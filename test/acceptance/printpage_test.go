package acceptance

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	printURLRe = regexp.MustCompile(`https://([0-9.]+):(\d+)/p/([A-Za-z0-9_-]+)`)
	fprRe      = regexp.MustCompile(`([0-9A-F]{2}(?::[0-9A-F]{2}){31})`)
)

func isPrivate4(ip net.IP) bool {
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// lanAddress finds an interface with an RFC 1918 address (preferring a real
// NIC over bridges), and another local private address outside its subnet.
func lanAddress() (ifname string, ip net.IP, subnet *net.IPNet, other net.IP) {
	ifs, _ := net.Interfaces()
	type cand struct {
		name string
		ip   net.IP
		n    *net.IPNet
	}
	var cands []cand
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && isPrivate4(ipn.IP) {
				cands = append(cands, cand{it.Name, ipn.IP.To4(), ipn})
			}
		}
	}
	virtual := func(n string) bool {
		for _, p := range []string{"docker", "br-", "veth", "virbr", "lxc", "tun", "wg", "tailscale"} {
			if strings.HasPrefix(n, p) {
				return true
			}
		}
		return false
	}
	for pass := 0; pass < 2 && ifname == ""; pass++ {
		for _, c := range cands {
			if pass == 0 && virtual(c.name) {
				continue
			}
			ifname, ip, subnet = c.name, c.ip, c.n
			break
		}
	}
	for _, c := range cands {
		if ifname != "" && !subnet.Contains(c.ip) {
			other = c.ip
			break
		}
	}
	return
}

func freePort(t *testing.T, ip net.IP) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// listeners lists the local addresses listening on TCP port.
func listeners(port int) []string {
	var out []string
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 4 || fs[3] != "0A" { // LISTEN
				continue
			}
			addr, p, _ := strings.Cut(fs[1], ":")
			pn, _ := strconv.ParseUint(p, 16, 32)
			if int(pn) != port {
				continue
			}
			raw, _ := hex.DecodeString(addr)
			ip := make(net.IP, len(raw))
			for i := 0; i < len(raw); i += 4 { // little-endian words
				for j := 0; j < 4; j++ {
					ip[i+j] = raw[i+3-j]
				}
			}
			out = append(out, ip.String())
		}
	}
	return out
}

type fetchResult struct {
	status  int
	header  http.Header
	body    string
	certFP  string
	version uint16
}

// fetch makes one HTTPS request to ip:port with the given Host header,
// optionally from a local address and with a TLS version cap.
func fetch(ip net.IP, port int, host, path string, from net.IP, maxTLS uint16) (fetchResult, error) {
	var res fetchResult
	d := &net.Dialer{Timeout: 5 * time.Second}
	if from != nil {
		d.LocalAddr = &net.TCPAddr{IP: from}
	}
	tr := &http.Transport{
		DialContext: d.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // the fingerprint is compared instead
			MaxVersion:         maxTLS,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) > 0 {
					sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
					res.certFP = colonHex(sum[:])
				}
				res.version = cs.Version
				return nil
			},
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://"+net.JoinHostPort(ip.String(), strconv.Itoa(port))+path, nil)
	if host != "" {
		req.Host = host
	}
	resp, err := cl.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	res.status, res.header, res.body = resp.StatusCode, resp.Header, string(b)
	return res, nil
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// tcpOpen reports whether something accepts TCP connections on ip:port.
func tcpOpen(ip net.IP, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func waitClosed(ip net.IP, port int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !tcpOpen(ip, port) {
			return true
		}
		time.Sleep(50 * time.Millisecond) // polling, with a deadline
	}
	return !tcpOpen(ip, port)
}

// canary counts requests to a local HTTP server that entries point to.
type canary struct {
	hits atomic.Int64
	url  string
	srv  *http.Server
}

func newCanary(t *testing.T) *canary {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &canary{url: "http://" + l.Addr().String()}
	c.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		w.WriteHeader(204)
	})}
	go c.srv.Serve(l)
	t.Cleanup(func() { c.srv.Close() })
	return c
}

// startPrintPage runs `passh print --web …` on a terminal (the agent gives
// the key) and returns the session, the URL's token and the fingerprint.
func (e *env) startPrintPage(args ...string) (*session, string, string) {
	e.t.Helper()
	s := e.start(sessOpts{}, append([]string{"print", "--web"}, args...)...)
	s.answer("to confirm:", "PRINT")
	if !s.expectWithin("Esc stops", 20*time.Second) {
		e.t.Fatalf("the print page didn't start; terminal:\n%s", s.output())
	}
	out := s.output()
	m := printURLRe.FindStringSubmatch(out)
	fp := fprRe.FindString(out)
	if m == nil || fp == "" {
		e.t.Fatalf("no URL or fingerprint shown:\n%s", out)
	}
	return s, m[3], fp
}

var (
	tagRe       = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
	badTags     = map[string]bool{"script": true, "img": true, "link": true, "iframe": true, "frame": true, "object": true, "embed": true, "form": true, "base": true, "audio": true, "video": true, "source": true, "svg": true, "image": true, "input": true, "button": true, "picture": true, "track": true, "portal": true}
	badAttrRe   = regexp.MustCompile(`(?i)\b(src|href|action|srcset|poster|formaction|background|ping|data|xlink:href|http-equiv)\s*=`)
	cssLoadRe   = regexp.MustCompile(`(?i)url\s*\(|@import|image-set\s*\(`)
	styleBlocks = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
)

// outgoing lists the markup in page that could load anything. Entry text
// is escaped (&lt;), so every "<" left in the page is markup of passh's.
func outgoing(page string) []string {
	var bad []string
	for _, m := range tagRe.FindAllStringSubmatch(page, -1) {
		if badTags[strings.ToLower(m[1])] || badAttrRe.MatchString(m[2]) {
			bad = append(bad, m[0])
		}
	}
	for _, st := range styleBlocks.FindAllStringSubmatch(page, -1) {
		if cssLoadRe.MatchString(st[1]) {
			bad = append(bad, "style: "+cssLoadRe.FindString(st[1]))
		}
	}
	return bad
}

// §13.1.7 and §13.2.7: the print page.
func TestF7S7_PrintPage(t *testing.T) {
	ifname, ip, subnet, other := lanAddress()
	if ip == nil {
		t.Skip("no interface with an RFC 1918 address: the print page can't be fetched here")
	}
	t.Logf("print page on %s %s (%s)", ifname, ip, subnet)
	_ = other // a second local source is NATed to the LAN address by Docker's rules here, so allow_from is tested with an explicit range
	can := newCanary(t)
	port, ttlPort := freePort(t, ip), freePort(t, ip)
	cfg := func(p int) string {
		return fmt.Sprintf("[print_web]\nenabled = true\nport = %d\ninterfaces = [%q, \"lo\"]\nhostnames = [\"pi.local\"]\nttl = \"1m\"\n", p, ifname)
	}
	e, _ := popEnv(t, cfg(port))
	e.unlock(fixPass)
	defer e.lock()
	xss := newEntry{
		path:     "web/xss",
		password: "pw<b>bold</b>&amp;",
		username: "<script>alert(1)</script>",
		url:      `https://x.example/"><img src=` + can.url + `/u.png>`,
		notes:    `<img src=` + can.url + `/n.png onerror=alert(1)>` + "\n" + `<style>body{background:url(` + can.url + `/c.png)}</style><link rel=stylesheet href=` + can.url + `/l.css>`,
	}
	e.add("", xss)

	// TTL run, on its own port, started first: it must stop after 1 min.
	e.writeConfig(cfg(ttlPort))
	ttlS, _, _ := e.startPrintPage()
	ttlStart := time.Now()
	e.writeConfig(cfg(port))

	// 1. Bind, TLS, Host, allow_from, wrong tokens, then the one load.
	s, token, fp := e.startPrintPage("--fields", "password,username,url,notes")
	out := s.output()
	if l := listeners(port); len(l) != 1 || l[0] != ip.String() {
		t.Errorf("the print page listens on %v, want only %s (private addresses only, never 0.0.0.0 or ::)", l, ip)
	}
	if !strings.Contains(out, "127.0.0.1 is a loopback address, not private") {
		t.Errorf("loopback in print_web.interfaces isn't reported as not private:\n%s", out)
	}
	if _, err := fetch(ip, port, "", "/p/"+token, nil, tls.VersionTLS12); err == nil {
		t.Errorf("TLS 1.2 was accepted (§7.4: TLS 1.3 only)")
	}
	if r, err := fetch(ip, port, "evil.example", "/p/"+token, nil, 0); err == nil && (r.status == 200 || strings.Contains(r.body, "s3cr3t")) {
		t.Errorf("a wrong Host header got the page (status %d)", r.status)
	}
	if r, err := fetch(ip, port, "", "/favicon.ico", nil, 0); err != nil || r.status != 404 {
		t.Errorf("/favicon.ico: want 404, got %v %v", r.status, err)
	}
	for i := 0; i < 2; i++ {
		if r, err := fetch(ip, port, "", "/p/AAAAAAAAAAAAAAAAAAAAAA", nil, 0); err == nil && r.status == 200 {
			t.Errorf("a wrong token got the page")
		}
	}
	r, err := fetch(ip, port, "", "/p/"+token, nil, 0)
	if err != nil {
		t.Fatalf("the page doesn't load: %v\n%s", err, s.output())
	}
	if r.status != 200 || r.version != tls.VersionTLS13 {
		t.Errorf("page: status %d, TLS version %#x", r.status, r.version)
	}
	if r.certFP != fp {
		t.Errorf("the served certificate's SHA-256 %s isn't the one shown, %s", r.certFP, fp)
	}
	for k, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := r.header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	csp := r.header.Get("Content-Security-Policy")
	cspRe := regexp.MustCompile(`^default-src 'none'; style-src 'sha256-([A-Za-z0-9+/=]+)'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'$`)
	if m := cspRe.FindStringSubmatch(csp); m == nil {
		t.Errorf("Content-Security-Policy = %q, not §7.4's", csp)
	} else {
		styles := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(r.body, -1)
		if len(styles) != 1 {
			t.Errorf("%d <style> elements, want 1", len(styles))
		} else if sum := sha256.Sum256([]byte(styles[0][1])); base64.StdEncoding.EncodeToString(sum[:]) != m[1] {
			t.Errorf("the CSP style hash doesn't match the page's <style>")
		}
	}
	for _, want := range []string{"github", "s3cr3t-P@ss", "arsenii", "&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=", "CONFIDENTIAL"} {
		if !strings.Contains(r.body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if m := outgoing(r.body); len(m) > 0 {
		t.Errorf("the page has elements or references that could load something: %q", m)
	}
	// Served once: the server stops after the response.
	if !waitClosed(ip, port, 5*time.Second) {
		t.Errorf("the server still runs after the page was served")
	}
	if res := s.wait(); res.code != 0 {
		t.Errorf("print --web after one load: %s", res)
	}
	if can.hits.Load() != 0 {
		t.Errorf("something requested the canary URLs from the entry")
	}
	// The certificate's key is kept 0600 and reused.
	keys, _ := filepath.Glob(filepath.Join(e.state, "print-web", "*key*"))
	if len(keys) == 0 {
		t.Errorf("no certificate key in %s", filepath.Join(e.state, "print-web"))
	}
	for _, k := range keys {
		if m := perm(t, k); m != 0o600 {
			t.Errorf("%s mode %o, want 0600", k, m)
		}
	}

	// 2. Five wrong tokens stop it; other paths don't count.
	s, token, fp2 := e.startPrintPage()
	if fp2 != fp {
		t.Errorf("the certificate changed between runs (%s, then %s); it must be reused", fp, fp2)
	}
	for i := 0; i < 4; i++ {
		fetch(ip, port, "", "/p/wrong"+strconv.Itoa(i), nil, 0)
		fetch(ip, port, "", "/favicon.ico", nil, 0)
	}
	if !tcpOpen(ip, port) {
		t.Errorf("the server stopped after 4 wrong tokens and 4 other paths (it stops at 5 wrong tokens)")
	}
	fetch(ip, port, "", "/p/wrong5", nil, 0)
	if !waitClosed(ip, port, 5*time.Second) {
		t.Errorf("the server keeps running after 5 wrong tokens")
	}
	s.wait()
	if r, err := fetch(ip, port, "", "/p/"+token, nil, 0); err == nil && r.status == 200 {
		t.Errorf("the page loads after the server stopped")
	}

	// 3. A client outside allow_from is closed before TLS (an explicit
	// range that excludes this machine's address).
	e.writeConfig(cfg(port) + "allow_from = [\"10.253.0.0/16\"]\n")
	s, token, _ = e.startPrintPage()
	if c, err := net.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port))); err == nil {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		n, rerr := c.Read(make([]byte, 1))
		if n != 0 || rerr == nil {
			t.Errorf("a connection from outside allow_from wasn't closed")
		}
		c.Close()
	}
	if r, err := fetch(ip, port, "", "/p/"+token, nil, 0); err == nil {
		t.Errorf("a client outside allow_from got status %d", r.status)
	}
	if !tcpOpen(ip, port) {
		t.Errorf("the server stopped after a refused client")
	}
	s.key("\x1b")
	s.wait()
	e.writeConfig(cfg(port))

	// 4. A headless browser loads it and makes no other request.
	t.Run("headless browser", func(t *testing.T) {
		e := e.with(t)
		chrome := ""
		for _, n := range []string{"google-chrome", "chromium", "chromium-browser", "google-chrome-stable"} {
			if p, err := exec.LookPath(n); err == nil {
				chrome = p
				break
			}
		}
		if chrome == "" {
			t.Skip("not testable: no headless Chrome/Chromium on this machine")
		}
		s, token, _ := e.startPrintPage("--fields", "password,username,url,notes")
		prof := filepath.Join(e.root, "chrome")
		netlog := filepath.Join(e.root, "netlog.json")
		_ = os.MkdirAll(prof, 0o700)
		url := fmt.Sprintf("https://%s:%d/p/%s", ip, port, token)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
			"--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-extensions",
			"--disable-default-apps", "--metrics-recording-only", "--user-data-dir="+prof, "--ignore-certificate-errors",
			"--log-net-log="+netlog, "--net-log-capture-mode=Default", "--virtual-time-budget=3000", "--dump-dom", url)
		c.Env = []string{"HOME=" + prof, "PATH=/usr/bin:/bin", "TMPDIR=" + e.tmp}
		dom, err := c.Output()
		if err != nil {
			t.Fatalf("chrome: %v", err)
		}
		if !strings.Contains(string(dom), "s3cr3t-P@ss") {
			t.Fatalf("the browser didn't get the page:\n%.2000s", dom)
		}
		if strings.Contains(string(dom), "<script>alert") || strings.Contains(string(dom), "<img src=") {
			t.Errorf("entry content became markup in the browser's DOM")
		}
		s.wait()
		if can.hits.Load() != 0 {
			t.Errorf("the browser requested %d canary URLs from the entry", can.hits.Load())
		}
		// §13.2.7 counts only requests the page caused: they carry its
		// site in the network isolation key; the browser's own background
		// requests don't.
		var nl struct {
			Constants struct {
				LogEventTypes map[string]int `json:"logEventTypes"`
			} `json:"constants"`
			Events []struct {
				Type   int            `json:"type"`
				Params map[string]any `json:"params"`
			} `json:"events"`
		}
		if err := json.Unmarshal(readFile(t, netlog), &nl); err != nil {
			t.Fatalf("net-log: %v", err)
		}
		start := nl.Constants.LogEventTypes["URL_REQUEST_START_JOB"]
		site := "https://" + ip.String()
		origin := fmt.Sprintf("https://%s:%d/", ip, port)
		pageRequests := 0
		for _, ev := range nl.Events {
			u, _ := ev.Params["url"].(string)
			nik, _ := ev.Params["network_isolation_key"].(string)
			if ev.Type != start || u == "" || !strings.Contains(nik, site) {
				continue
			}
			pageRequests++
			if !strings.HasPrefix(u, origin) {
				t.Errorf("the page made an outgoing request to %s", u)
			}
		}
		if pageRequests == 0 {
			t.Errorf("the net-log shows no request of the page: the check is broken")
		}
	})

	// 5. TTL: the first server stops after print_web.ttl (1 min).
	r2 := ttlS.wait()
	if d := time.Since(ttlStart); d < 50*time.Second || d > 80*time.Second {
		t.Errorf("print page with ttl 1m stopped after %v", d)
	}
	if tcpOpen(ip, ttlPort) {
		t.Errorf("the TTL server still accepts connections")
	}
	if r2.code == 0 {
		t.Logf("print page at TTL: %s", r2)
	}
}

// §13.2.7: a TUI lock stops the print page: L, and an idle lock.
func TestS7_PrintPageStopsOnTUILock(t *testing.T) {
	ifname, ip, _, _ := lanAddress()
	if ip == nil {
		t.Skip("no interface with an RFC 1918 address")
	}
	port := freePort(t, ip)
	e, _ := popEnv(t, fmt.Sprintf("[session]\nidle_ttl = \"5s\"\n[print_web]\nenabled = true\nport = %d\ninterfaces = [%q]\n", port, ifname))
	e.unlock(fixPass)
	defer e.lock()

	open := func(s *session) string {
		t.Helper()
		s.key("P")
		// The setup step (§9.2 of EXAMPLES): keep its choice, continue.
		if s.waitScreen(5*time.Second, "what to print") {
			s.key("\r")
		}
		s.mustScreen(5*time.Second, "Type PRINT")
		s.key("P", "R", "I", "N", "T", "\r")
		s.mustScreen(15*time.Second, "Print page", "https://")
		m := printURLRe.FindStringSubmatch(s.screen())
		if m == nil || !tcpOpen(ip, port) {
			t.Fatalf("the print page isn't running:\n%s", s.screen())
		}
		return m[3]
	}

	t.Run("idle lock", func(t *testing.T) {
		e := e.with(t)
		if len(agentProcs(e.root)) == 0 {
			e.unlock(fixPass)
		}
		s := e.startTUIAgent()
		token := open(s)
		if !s.waitScreen(12*time.Second, tuiLocked) {
			t.Errorf("no idle lock (session.idle_ttl 5s) while the print dialog is open")
		}
		if !waitClosed(ip, port, 5*time.Second) {
			t.Errorf("the print page keeps running after the TUI locked")
		}
		if r, err := fetch(ip, port, "", "/p/"+token, nil, 0); err == nil && r.status == 200 {
			t.Errorf("the page loads after the lock")
		}
		s.key("\x03")
		s.wait()
		e.unlock(fixPass) // the lock stopped the agent (stop_agent)
	})
	t.Run("setup step limits the page to the chosen folder", func(t *testing.T) {
		e := e.with(t)
		if len(agentProcs(e.root)) == 0 {
			e.unlock(fixPass)
		}
		s := e.startTUIAgent()
		s.key("P")
		s.mustScreen(5*time.Second, "what to print", "folder bank/")
		s.key("\r") // the folder under the cursor, bank/, is chosen
		s.mustScreen(5*time.Second, "Type PRINT")
		s.key("P", "R", "I", "N", "T", "\r")
		s.mustScreen(15*time.Second, "Print page", "https://")
		m := printURLRe.FindStringSubmatch(s.screen())
		if m == nil {
			t.Fatalf("no URL:\n%s", s.screen())
		}
		r, err := fetch(ip, port, "", "/p/"+m[3], nil, 0)
		if err != nil || r.status != 200 {
			t.Fatalf("page: %v %d", err, r.status)
		}
		mustContain(t, "page for folder bank/", r.body, "chase", "bob@example.com")
		mustNotContain(t, "page for folder bank/", r.body, "github", "arsenii", "s3cr3t-P@ss", "My Bank", "homelab")
		s.mustScreen(10*time.Second, "Print page stopped") // the outcome
		s.key("\r")                                        // any key closes it
		s.mustScreen(5*time.Second, "q quit")
		s.key("q")
		s.waitOK()
	})
	t.Run("hangup", func(t *testing.T) {
		e := e.with(t)
		if len(agentProcs(e.root)) == 0 {
			e.unlock(fixPass)
		}
		s := e.startTUIAgent()
		open(s)
		s.ptm.Close() // the SSH connection drops: SIGHUP
		if !waitClosed(ip, port, 5*time.Second) {
			t.Errorf("the print page keeps running after the terminal hung up")
		}
		s.wait()
		if len(passhProcs(e.root)) > len(agentProcs(e.root)) {
			t.Errorf("passh keeps running after the hangup")
		}
		e.unlock(fixPass)
	})
	t.Run("L", func(t *testing.T) {
		e := e.with(t)
		if len(agentProcs(e.root)) == 0 {
			e.unlock(fixPass)
		}
		s := e.startTUIAgent()
		open(s)
		s.key("L")
		locked := s.waitScreen(5*time.Second, tuiLocked)
		stopped := waitClosed(ip, port, 5*time.Second)
		s.key("\x1b")
		s.key("\x03")
		s.wait()
		if !locked {
			t.Errorf("L in the print dialog didn't lock the TUI (§5.2)")
		}
		if !stopped {
			t.Errorf("L in the print dialog didn't stop the print page (§7.4)")
		}
	})
}
