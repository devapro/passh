package printweb

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
)

// TestMain keeps the tests away from the user's files: every location
// passh could use points into a temporary folder.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "passh-printweb-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, v := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
		"XDG_RUNTIME_DIR", "TMPDIR", "PASSH_CONFIG", "PASSWORD_STORE_DIR", "GNUPGHOME"} {
		p := filepath.Join(dir, strings.ToLower(v))
		if err := os.MkdirAll(p, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv(v, p)
	}
	allowLoopback = true
	minTTL = 10 * time.Millisecond
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var testDate = time.Date(2026, 11, 15, 14, 3, 0, 0, time.UTC)

func testSheet(t *testing.T) *print.Sheet {
	t.Helper()
	es := []model.Entry{
		{Path: paths.MustParse("work/github"), Password: "<script>alert(1)</script>", Username: `<img src=x onerror="alert(1)">`, URL: "https://github.com"},
		{Path: paths.MustParse("email"), Password: "Пароль\x1b]52;c;ZXZpbA==\x07", Username: "Иван"},
		{Path: paths.MustParse("bank/main"), Password: "a0O1lI b", URL: "javascript:alert(1)"},
	}
	s, err := print.NewSheet(es, print.Options{Date: testDate})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fakeInterfaces replaces the system's interfaces.
func fakeInterfaces(t *testing.T, m map[string][]string) {
	t.Helper()
	old := interfaceAddrs
	interfaceAddrs = func(name string) ([]netip.Prefix, error) {
		list, ok := m[name]
		if !ok {
			return nil, errors.New("no such network interface")
		}
		var out []netip.Prefix
		for _, s := range list {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out, nil
	}
	t.Cleanup(func() { interfaceAddrs = old })
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type testServer struct {
	*Server
	opts   Options
	cancel context.CancelFunc
	client *http.Client
}

// start starts a print page on 127.0.0.1 ("lo") with a fresh state folder.
func start(t *testing.T, mod func(*Options)) *testServer {
	t.Helper()
	fakeInterfaces(t, map[string][]string{"lo": {"127.0.0.1/8"}})
	opts := Options{
		Settings: config.PrintWeb{Enabled: true, Port: freePort(t), Interfaces: []string{"lo"}, TTL: time.Minute},
		StateDir: t.TempDir(),
		Doc:      testSheet(t),
	}
	if mod != nil {
		mod(&opts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, opts)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	ts := &testServer{Server: s, opts: opts, cancel: cancel}
	stateDir := opts.StateDir
	if stateDir == "" {
		if stateDir, err = config.StateDir(); err != nil {
			t.Fatal(err)
		}
	}
	ts.client = httpClient(t, stateDir, tls.VersionTLS13)
	t.Cleanup(func() {
		cancel()
		<-s.Done()
	})
	return ts
}

// httpClient trusts exactly the print page's stored certificate.
func httpClient(t *testing.T, stateDir string, maxVersion uint16) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(stateDir, certDirName, certFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("bad certificate PEM")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool, MaxVersion: maxVersion},
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
		},
	}
}

func (ts *testServer) get(t *testing.T, url, host string) (*http.Response, string, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body), nil
}

func (ts *testServer) base() string {
	return strings.TrimSuffix(ts.URLs[0], "/p/"+ts.token)
}

func waitResult(t *testing.T, s *Server) Result {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the server didn't stop")
	}
	return s.Wait()
}

func refused(t *testing.T, ts *testServer) {
	t.Helper()
	if resp, _, err := ts.get(t, ts.URLs[0], ""); err == nil {
		t.Fatalf("the stopped server answered: %s", resp.Status)
	}
}

func TestServedOnce(t *testing.T) {
	ts := start(t, nil)
	if len(ts.URLs) != 1 || !regexp.MustCompile(`^https://127\.0\.0\.1:\d+/p/[A-Za-z0-9_-]{22}$`).MatchString(ts.URLs[0]) {
		t.Fatalf("URLs = %q", ts.URLs)
	}
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(ts.Fingerprint) {
		t.Fatalf("fingerprint %q", ts.Fingerprint)
	}
	if ts.CertNotice == "" || !strings.Contains(ts.CertNotice, "first use") {
		t.Errorf("no notice for a new certificate: %q", ts.CertNotice)
	}
	if d := time.Until(ts.Expires); d < 50*time.Second || d > time.Minute {
		t.Errorf("Expires in %s", d)
	}

	resp, body, err := ts.get(t, ts.URLs[0], "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s", resp.Status)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 || resp.ProtoMajor != 1 {
		t.Errorf("not HTTP/1.1 over TLS 1.3: %+v %s", resp.TLS, resp.Proto)
	}
	if fp := Fingerprint(resp.TLS.PeerCertificates[0].Raw); fp != ts.Fingerprint {
		t.Errorf("the server's certificate has fingerprint %s, Server says %s", fp, ts.Fingerprint)
	}
	if !strings.HasSuffix(body, "</html>\n") {
		t.Errorf("the page is incomplete: …%q", body[max(0, len(body)-40):])
	}
	for _, want := range []string{"Иван", print.Confidential, "printed 2026-11-15 14:03", "github"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	res := waitResult(t, ts.Server)
	if res.Outcome != Served || res.Client != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(res.String(), "served to 127.0.0.1") {
		t.Errorf("message %q", res.String())
	}
	refused(t, ts)
}

func TestHeadersAndPage(t *testing.T) {
	ts := start(t, nil)
	resp, body, err := ts.get(t, ts.URLs[0], "")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(body, -1)
	if len(m) != 1 {
		t.Fatalf("%d style elements", len(m))
	}
	sum := sha256.Sum256([]byte(m[0][1]))
	wantCSP := "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	want := map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": wantCSP,
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"Content-Type":            "text/html; charset=utf-8",
	}
	for k, v := range want {
		if got := resp.Header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s: %q, want %q", k, got, v)
		}
	}

	// No script, no external resource, no link, no inline style or event
	// attribute: the only markup is ours.
	for _, re := range []string{
		`(?i)<script`, `(?i)<img`, `(?i)<link`, `(?i)<iframe`, `(?i)<object`, `(?i)<embed`, `(?i)<form`,
		`(?i)<a[\s>]`, `(?i)<[^>]*\s(src|href|srcset|action|style|on[a-z]+|xmlns(:\w+)?)\s*=`,
		`(?i)url\(`, `(?i)@import`,
	} {
		if loc := regexp.MustCompile(re).FindStringIndex(body); loc != nil {
			t.Errorf("page matches %s: %q", re, body[max(0, loc[0]-20):min(len(body), loc[1]+20)])
		}
	}
	// Entry content is text.
	for _, want := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&lt;img src=x onerror=&#34;alert(1)&#34;&gt;",
		`Пароль\x1b]52;c;ZXZpbA==\x07`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.ContainsRune(body, 0x1b) || strings.ContainsRune(body, 0x07) {
		t.Error("control characters in the page")
	}
	// Ambiguity marks and the legend.
	if !strings.Contains(body, "<b>D</b><b>U</b><b>D</b><b>L</b><b>U</b><b>S</b>") {
		t.Error("no ambiguity marks")
	}
	if !strings.Contains(body, "D digit, U capital letter") {
		t.Error("no legend")
	}
}

// TestPageRender checks the page without the network, including "already
// used" for a request that arrives after the token was taken.
func TestPageRender(t *testing.T) {
	s := &Server{
		token:   "tok",
		port:    8443,
		bound:   []netip.Addr{netip.MustParseAddr("192.168.1.10")},
		doc:     testSheet(t),
		served:  make(chan struct{}),
		tooMany: make(chan struct{}),
	}
	do := func(method, target, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Host = host
		r.RemoteAddr = "192.168.1.23:50000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := do("HEAD", "/p/tok", "192.168.1.10:8443"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: %d", w.Code)
	}
	if w := do("GET", "/p/tok", "192.168.1.10:8443"); w.Code != http.StatusOK {
		t.Fatalf("GET: %d", w.Code)
	}
	select {
	case <-s.served:
	default:
		t.Fatal("serving didn't signal")
	}
	w := do("GET", "/p/tok", "192.168.1.10")
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "already used") {
		t.Fatalf("second GET: %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Security-Policy") != contentSecurityPolicy || w.Header().Get("Cache-Control") != "no-store" {
		t.Error("error responses lack the headers")
	}
	if s.client != netip.MustParseAddr("192.168.1.23") {
		t.Errorf("client %s", s.client)
	}

	// After too many wrong tokens, the right one no longer works.
	s2 := &Server{token: "tok", port: 8443, bound: s.bound, doc: s.doc, served: make(chan struct{}), tooMany: make(chan struct{})}
	s = s2
	for range MaxWrongTokens {
		if w := do("GET", "/p/nope", "192.168.1.10"); w.Code != http.StatusNotFound {
			t.Fatalf("wrong token: %d", w.Code)
		}
	}
	select {
	case <-s2.tooMany:
	default:
		t.Fatal("too many wrong tokens didn't signal")
	}
	if w := do("GET", "/p/tok", "192.168.1.10"); w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "too many") {
		t.Fatalf("after too many wrong tokens: %d %q", w.Code, w.Body.String())
	}
}

func TestHostHeader(t *testing.T) {
	ts := start(t, func(o *Options) { o.Settings.Hostnames = []string{"pi.local"} })
	port := ts.opts.Settings.Port
	for _, host := range []string{"evil.example", fmt.Sprintf("evil.example:%d", port), "127.0.0.1:1", "127.0.0.2", "[::1]", "pi.local.evil"} {
		resp, _, err := ts.get(t, ts.URLs[0], host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %s", host, resp.Status)
		}
	}
	// A wrong Host doesn't consume the token: the page is still there.
	resp, _, err := ts.get(t, ts.URLs[0], fmt.Sprintf("PI.LOCAL:%d", port))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("hostname: %v %v", resp, err)
	}
	if res := waitResult(t, ts.Server); res.Outcome != Served {
		t.Fatalf("result %+v", res)
	}

	s := &Server{port: 8443, bound: []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fd00::1")}, hostnames: []string{"pi.local"}}
	for host, ok := range map[string]bool{
		"192.168.1.10": true, "192.168.1.10:8443": true, "192.168.1.10:443": false,
		"[fd00::1]": true, "[fd00::1]:8443": true, "fd00::1": true, "[fd00::1%eth0]:8443": false,
		"pi.local": true, "Pi.Local.": true, "pi.local:8443": true, "pi.local:80": false,
		"": false, "192.168.1.11": false, "localhost": false,
	} {
		if got := s.hostAllowed(host); got != ok {
			t.Errorf("hostAllowed(%q) = %v", host, got)
		}
	}
}

func TestAllowFromClosesBeforeTLS(t *testing.T) {
	ts := start(t, func(o *Options) { o.Settings.AllowFrom = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	addr := strings.TrimPrefix(ts.base(), "https://")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection wasn't closed: n=%d err=%v", n, err)
	}
	if _, _, err := ts.get(t, ts.URLs[0], ""); err == nil {
		t.Fatal("a client outside allow_from got an answer")
	}
	select {
	case <-ts.Done():
		t.Fatal("refused clients stopped the server")
	default:
	}

	// By default the bound address's subnet is allowed, and the server
	// waits for the TLS handshake instead of closing.
	ts2 := start(t, nil)
	c2, err := net.Dial("tcp", strings.TrimPrefix(ts2.base(), "https://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c2.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("an allowed client was closed: %v", err)
	}
}

func TestStopsAtTTL(t *testing.T) {
	ts := start(t, func(o *Options) { o.Settings.TTL = 300 * time.Millisecond })
	res := waitResult(t, ts.Server)
	if res.Outcome != Expired || res.Client.IsValid() {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(res.String(), "300ms") {
		t.Errorf("message %q", res.String())
	}
	refused(t, ts)
}

func TestStopsOnCancelAndStop(t *testing.T) {
	ts := start(t, nil)
	ts.cancel() // lock, exit
	if res := waitResult(t, ts.Server); res.Outcome != Cancelled {
		t.Fatalf("cancel: %+v", res)
	}
	refused(t, ts)

	ts = start(t, nil)
	ts.Stop() // Esc
	ts.Stop()
	if res := waitResult(t, ts.Server); res.Outcome != Cancelled || res.String() != "the print page was stopped" {
		t.Fatalf("Stop: %+v", res)
	}
	refused(t, ts)
}

func TestWrongTokens(t *testing.T) {
	ts := start(t, nil)
	alive := func() {
		t.Helper()
		select {
		case <-ts.Done():
			t.Fatal("the server stopped")
		default:
		}
	}
	for i := range 10 {
		for _, p := range []string{"/favicon.ico", "/", "/p", "/robots.txt"} {
			resp, _, err := ts.get(t, ts.base()+p, "")
			if err != nil || resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s #%d: %v %v", p, i, resp, err)
			}
		}
	}
	alive()
	for i := range MaxWrongTokens - 1 {
		resp, _, err := ts.get(t, ts.base()+"/p/wrong"+fmt.Sprint(i), "")
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("wrong token #%d: %v %v", i, resp, err)
		}
	}
	alive()
	ts.get(t, ts.base()+"/p/"+ts.token+"x", "")
	res := waitResult(t, ts.Server)
	if res.Outcome != TooManyWrongTokens {
		t.Fatalf("result %+v", res)
	}
	refused(t, ts)
}

func TestTLS12Refused(t *testing.T) {
	ts := start(t, nil)
	old := httpClient(t, ts.opts.StateDir, tls.VersionTLS12)
	req, _ := http.NewRequest(http.MethodGet, ts.URLs[0], nil)
	if resp, err := old.Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("a TLS 1.2 client got %s", resp.Status)
	}
	// Plain HTTP isn't offered either.
	plain := &http.Client{Timeout: 5 * time.Second}
	if resp, err := plain.Get(strings.Replace(ts.URLs[0], "https://", "http://", 1)); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("plain HTTP served the page")
		}
	}
	select {
	case <-ts.Done():
		t.Fatal("the server stopped")
	default:
	}
}

func TestRefusesPublicAndWildcard(t *testing.T) {
	for _, a := range []string{"0.0.0.0", "::", "8.8.8.8", "2001:db8::1", "172.32.0.1", "100.128.0.1", "169.254.1.1", "fe80::1", "::ffff:8.8.8.8"} {
		if err := checkBindable(netip.MustParseAddr(a)); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
	for _, a := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.10", "100.64.0.1", "100.127.255.254", "fd00::1", "fc00::1", "::ffff:192.168.1.10"} {
		if err := checkBindable(netip.MustParseAddr(a)); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	allowLoopback = false
	err := checkBindable(netip.MustParseAddr("127.0.0.1"))
	allowLoopback = true
	if err == nil {
		t.Error("loopback accepted without the test hook")
	}

	fakeInterfaces(t, map[string][]string{
		"pub":   {"203.0.113.5/24", "2001:db8::5/64"},
		"wild":  {"0.0.0.0/0", "::/0"},
		"mixed": {"2001:db8::7/64", "fe80::1/64", "192.168.1.10/24", "fd12:3456::1/64", "203.0.113.9/24"},
		"ts":    {"100.101.102.103/32", "fd7a:115c:a1e0::1/128"},
		"empty": {},
	})
	for _, ifs := range [][]string{{"pub"}, {"wild"}, {"nope"}, {"empty"}, {"pub", "wild", "nope"}, nil} {
		if b, _, err := resolveAddrs(ifs); err == nil {
			t.Errorf("%q: listening on %v", ifs, b)
		}
	}
	_, _, err = resolveAddrs([]string{"pub"})
	if err == nil || !strings.Contains(err.Error(), "203.0.113.5 is a public address") {
		t.Errorf("unclear error: %v", err)
	}
	_, _, err = resolveAddrs([]string{"wild"})
	if err == nil || !strings.Contains(err.Error(), "0.0.0.0 is the wildcard address") || strings.Contains(err.Error(), "public") {
		t.Errorf("wildcard: %v", err)
	}

	// Loopback is named as such, not as public.
	allowLoopback = false
	fakeInterfaces(t, map[string][]string{"lo": {"127.0.0.1/8", "::1/128"}, "mc": {"239.1.2.3/32"}})
	_, _, err = resolveAddrs([]string{"lo", "mc"})
	allowLoopback = true
	if err == nil {
		t.Fatal("listening on loopback without the test hook")
	}
	for _, want := range []string{"lo: 127.0.0.1 is a loopback address, not private", "lo: ::1 is a loopback address, not private", "mc: 239.1.2.3 is a multicast address"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "public") {
		t.Errorf("loopback called public: %v", err)
	}
	fakeInterfaces(t, map[string][]string{
		"pub":   {"203.0.113.5/24", "2001:db8::5/64"},
		"wild":  {"0.0.0.0/0", "::/0"},
		"mixed": {"2001:db8::7/64", "fe80::1/64", "192.168.1.10/24", "fd12:3456::1/64", "203.0.113.9/24"},
		"ts":    {"100.101.102.103/32", "fd7a:115c:a1e0::1/128"},
		"empty": {},
	})

	b, skipped, err := resolveAddrs([]string{"mixed", "ts", "nope", "mixed"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range b {
		got = append(got, x.addr.String()+" "+x.subnet.String())
	}
	want := []string{"192.168.1.10 192.168.1.0/24", "fd12:3456::1 fd12:3456::/64", "100.101.102.103 100.64.0.0/10", "fd7a:115c:a1e0::1 fc00::/7"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("bound %q, want %q", got, want)
	}
	joined := strings.Join(skipped, "\n")
	for _, s := range []string{"2001:db8::7 is a public address", "203.0.113.9 is a public address", "fe80::1 is link-local"} {
		if !strings.Contains(joined, s) {
			t.Errorf("skipped lacks %q: %q", s, skipped)
		}
	}

	// Start refuses too, and nothing listens.
	_, err = Start(context.Background(), Options{
		Settings: config.PrintWeb{Enabled: true, Port: freePort(t), Interfaces: []string{"pub", "wild"}, TTL: time.Minute},
		StateDir: t.TempDir(),
		Doc:      testSheet(t),
	})
	if err == nil {
		t.Fatal("Start listened on public or wildcard addresses")
	}
}

func TestStartValidation(t *testing.T) {
	fakeInterfaces(t, map[string][]string{"lo": {"127.0.0.1/8"}})
	base := Options{
		Settings: config.PrintWeb{Enabled: true, Port: freePort(t), Interfaces: []string{"lo"}, TTL: time.Minute},
		StateDir: t.TempDir(),
		Doc:      testSheet(t),
	}
	for name, mod := range map[string]func(*Options){
		"disabled":  func(o *Options) { o.Settings.Enabled = false },
		"no doc":    func(o *Options) { o.Doc = nil },
		"ttl 0":     func(o *Options) { o.Settings.TTL = 0 },
		"ttl 16m":   func(o *Options) { o.Settings.TTL = 16 * time.Minute },
		"port 0":    func(o *Options) { o.Settings.Port = 0 },
		"bad host":  func(o *Options) { o.Settings.Hostnames = []string{"a b"} },
		"no ifaces": func(o *Options) { o.Settings.Interfaces = nil },
	} {
		o := base
		mod(&o)
		s, err := Start(context.Background(), o)
		if err == nil {
			s.Stop()
			t.Errorf("%s: started", name)
		}
		if name == "disabled" && !errors.Is(err, ErrDisabled) {
			t.Errorf("disabled: %v", err)
		}
	}
	// A port in use is an error, not a silent fallback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	o := base
	o.Settings.Port = ln.Addr().(*net.TCPAddr).Port
	if s, err := Start(context.Background(), o); err == nil {
		s.Stop()
		t.Error("started on a port in use")
	}
}

func TestCertificate(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "passh", certDirName) // the state folder doesn't exist yet
	a1 := netip.MustParseAddr("192.168.1.10")
	a2 := netip.MustParseAddr("100.101.102.103")
	t0 := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

	c1, err := loadOrCreateCert(dir, []netip.Addr{a1, a2}, []string{"pi.local"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c1.notice, "first use") {
		t.Errorf("notice %q", c1.notice)
	}
	leaf := c1.leaf
	if leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.NotAfter.Sub(t0) != certValidity ||
		len(leaf.IPAddresses) != 2 || len(leaf.DNSNames) != 1 || leaf.IsCA {
		t.Errorf("certificate %v %v %v %v", leaf.PublicKeyAlgorithm, leaf.NotAfter, leaf.IPAddresses, leaf.DNSNames)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool(leaf), DNSName: "pi.local", CurrentTime: t0}); err != nil {
		t.Errorf("verify: %v", err)
	}
	for p, mode := range map[string]os.FileMode{dir: 0o700, filepath.Dir(dir): 0o700, filepath.Join(dir, keyFile): 0o600} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v %v, want %04o", p, fi.Mode(), err, mode)
		}
	}

	reuse := func(when time.Time, addrs []netip.Addr, hosts []string) *certInfo {
		t.Helper()
		c, err := loadOrCreateCert(dir, addrs, hosts, when)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// Same addresses, or fewer, and later in the year: reused.
	for _, c := range []*certInfo{
		reuse(t0.Add(time.Hour), []netip.Addr{a1, a2}, []string{"pi.local"}),
		reuse(t0.Add(300*24*time.Hour), []netip.Addr{a1}, []string{"PI.LOCAL"}),
		reuse(t0, nil, nil),
	} {
		if c.fingerprint != c1.fingerprint || c.notice != "" {
			t.Errorf("not reused: %s %q", c.fingerprint, c.notice)
		}
	}

	// A new address or hostname, expiry, a key readable by others, damage:
	// a new certificate, said so.
	steps := []struct {
		name   string
		prep   func()
		when   time.Time
		addrs  []netip.Addr
		hosts  []string
		reason string
	}{
		{"new address", nil, t0, []netip.Addr{a1, netip.MustParseAddr("10.0.0.5")}, []string{"pi.local"}, "doesn't cover 10.0.0.5"},
		{"new hostname", nil, t0, []netip.Addr{a1}, []string{"nas.local"}, "doesn't cover nas.local"},
		{"expired", nil, t0.Add(2 * certValidity), []netip.Addr{a1}, nil, "expired on"},
		{"expiring", nil, t0.Add(2*certValidity + certValidity - time.Hour), []netip.Addr{a1}, nil, "expires on"},
		{"key mode", func() { os.Chmod(filepath.Join(dir, keyFile), 0o644) }, t0.Add(3 * certValidity), []netip.Addr{a1}, nil, "readable by others"},
		{"damaged", func() { os.WriteFile(filepath.Join(dir, certFile), []byte("junk"), 0o600) }, t0.Add(3 * certValidity), []netip.Addr{a1}, nil, "can't be used"},
		{"missing key", func() { os.Remove(filepath.Join(dir, keyFile)) }, t0.Add(3 * certValidity), []netip.Addr{a1}, nil, "key can't be read"},
	}
	prev := c1.fingerprint
	for _, st := range steps {
		if st.prep != nil {
			st.prep()
		}
		c := reuse(st.when, st.addrs, st.hosts)
		if c.fingerprint == prev || !strings.Contains(c.notice, st.reason) {
			t.Errorf("%s: fingerprint %s (was %s), notice %q", st.name, c.fingerprint, prev, c.notice)
		}
		prev = c.fingerprint
		fi, err := os.Stat(filepath.Join(dir, keyFile))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: key file %v %v", st.name, fi, err)
		}
	}
	// No temporary files are left behind.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Errorf("files in %s: %v", dir, ents)
	}

	// A loosened folder mode is tightened again.
	os.Chmod(dir, 0o755)
	reuse(t0.Add(3*certValidity), []netip.Addr{a1}, nil)
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("folder mode %v", fi.Mode())
	}
}

func pool(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

func TestCertificateReusedByStart(t *testing.T) {
	ts := start(t, nil)
	first := ts.Fingerprint
	ts.Stop()
	waitResult(t, ts.Server)

	opts := ts.opts
	s, err := Start(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Stop(); <-s.Done() }()
	if s.Fingerprint != first || s.CertNotice != "" {
		t.Fatalf("second start: %s %q, first %s", s.Fingerprint, s.CertNotice, first)
	}
	s.Stop()
	<-s.Done()

	opts.Settings.Hostnames = []string{"pi.local"}
	s2, err := Start(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s2.Stop(); <-s2.Done() }()
	if s2.Fingerprint == first || !strings.Contains(s2.CertNotice, "pi.local") {
		t.Fatalf("new hostname: %s %q", s2.Fingerprint, s2.CertNotice)
	}
}

func TestRecoveryPage(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := print.NewRecoverySheet(id, "6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00", testDate)
	if err != nil {
		t.Fatal(err)
	}
	ts := start(t, func(o *Options) { o.Doc = rs })
	resp, body, err := ts.get(t, ts.URLs[0], "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%v %v", resp, err)
	}
	for _, want := range append(strings.Split(keys.FormatRecoveryKey(id), "\n"),
		"6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00", "<svg viewBox=", "<path fill=\"#000\" d=\"M", "passh recover",
		"tr -d &#39;\\r&#39; &lt; vault.passh") {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, bad := range []string{"age1", id.Recipient().String(), id.String()} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	if regexp.MustCompile(`(?i)<[^>]*\s(src|href|xmlns)\s*=`).MatchString(body) {
		t.Error("the SVG refers to something")
	}
	if res := waitResult(t, ts.Server); res.Outcome != Served {
		t.Fatalf("%+v", res)
	}
}

func TestTerminalQR(t *testing.T) {
	q, err := TerminalQR("https://192.168.1.10:8443/p/kq7ZabcdefghijklmnopqR")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(q, "\n"), "\n")
	if len(lines) < 10 || !strings.ContainsAny(q, "█▀▄") {
		t.Fatalf("QR:\n%s", q)
	}
	w := len([]rune(lines[0]))
	for _, l := range lines {
		if len([]rune(l)) != w {
			t.Fatal("ragged QR code")
		}
	}
}

func TestResultString(t *testing.T) {
	c := netip.MustParseAddr("192.168.1.23")
	for r, want := range map[Result]string{
		{Outcome: Served, Client: c}:             "the page was served to 192.168.1.23; if that wasn't you, start the print page again",
		{Outcome: Expired, TTL: 5 * time.Minute}: "the print page stopped after 5m0s without being opened",
		{Outcome: TooManyWrongTokens}:            "the print page stopped after 5 requests with a wrong address",
		{Outcome: Cancelled}:                     "the print page was stopped",
		{Outcome: Cancelled, Client: c}:          "the print page was stopped while it was sent to 192.168.1.23",
	} {
		if got := r.String(); got != want {
			t.Errorf("%+v: %q", r, got)
		}
	}
}

func TestSystemInterfaceAddrs(t *testing.T) {
	var name string
	for _, n := range []string{"lo", "lo0"} {
		if _, err := net.InterfaceByName(n); err == nil {
			name = n
		}
	}
	if name == "" {
		t.Skip("no loopback interface named lo or lo0")
	}
	ps, err := interfaceAddrs(name)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range ps {
		if p.Addr() == netip.MustParseAddr("127.0.0.1") && p.Bits() == 8 {
			found = true
		}
	}
	if !found {
		t.Errorf("%s: %v, want 127.0.0.1/8", name, ps)
	}
	if _, err := interfaceAddrs("passh-no-such-if0"); err == nil {
		t.Error("a missing interface has addresses")
	}
}

func TestStateDirDefaultAndErrors(t *testing.T) {
	// Without StateDir, the certificate goes to $XDG_STATE_HOME/passh/print-web.
	ts := start(t, func(o *Options) { o.StateDir = "" })
	state, err := config.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, certDirName, keyFile)); err != nil {
		t.Fatalf("certificate not in the state folder: %v", err)
	}
	ts.Stop()
	waitResult(t, ts.Server)

	// A file where the certificate folder should be.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, certDirName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateCert(filepath.Join(dir, certDirName), nil, nil, time.Now()); err == nil {
		t.Error("a file was used as the certificate folder")
	}
}
