// Package printweb serves the print page (§7.4): a one-shot HTTPS page with
// a sheet from internal/print, inside the passh process.
//
// Start binds the private addresses of print_web.interfaces, makes or reuses
// the self-signed certificate, and serves the page once:
//
//   - only RFC 1918, 100.64.0.0/10 and fc00::/7 addresses are used; public
//     addresses are refused, and 0.0.0.0 or :: is never bound;
//   - connections from outside print_web.allow_from (default: the subnets
//     of the bound addresses) are closed before TLS;
//   - TLS 1.3 only, HTTP/1.1, no plain HTTP;
//   - the Host header must be a bound address or one of print_web.hostnames
//     (else 421), which defeats DNS rebinding;
//   - the page is at /p/<token>, a 128-bit random token. The first correct
//     GET consumes it; the server stops as soon as that response is written.
//     5 requests to /p/ with a wrong token stop it; other paths get 404 and
//     don't count;
//   - it also stops at print_web.ttl and when the context is cancelled (lock,
//     Esc, exit) or Stop is called.
//
// "Already used": the spec says a link preview can consume the token and the
// user then sees "already used". Since the server stops right after serving
// the page, a later request usually can't even connect; only a request that
// arrives while the page is still being written gets 410 "already used".
// Result.Client therefore tells the caller which address got the page, so
// it can print "page was served to 192.168.1.23 — if that wasn't you, start
// again".
package printweb

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"passh/internal/config"
	"passh/internal/print"
)

// MaxWrongTokens is how many requests with a wrong token stop the server.
const MaxWrongTokens = 5

// shutdownWait bounds the wait for the served response to be written.
const shutdownWait = 30 * time.Second

// minTTL is the shortest print_web.ttl. Tests lower it.
var minTTL = config.MinPrintWebTTL

// ErrDisabled: print_web.enabled is false.
var ErrDisabled = errors.New("the print page is off: set enabled = true in the [print_web] table of the config file")

// Options configures Start.
type Options struct {
	// Settings is the [print_web] table: interfaces, port, allow_from,
	// hostnames, ttl. Start fails with ErrDisabled unless Enabled is set.
	Settings config.PrintWeb
	// StateDir is passh's state folder; the certificate is kept in its
	// print-web subfolder. "" means config.StateDir().
	StateDir string
	// Doc is the sheet the page shows: a *print.Sheet or a
	// *print.RecoverySheet. It is rendered when the request arrives.
	Doc print.Document
}

// Outcome is how the server stopped.
type Outcome int

// Outcomes.
const (
	// Served: the page was sent to Result.Client.
	Served Outcome = iota + 1
	// Expired: print_web.ttl ran out.
	Expired
	// Cancelled: the context was cancelled or Stop was called.
	Cancelled
	// TooManyWrongTokens: MaxWrongTokens requests had a wrong token.
	TooManyWrongTokens
)

// Result is the outcome of a print page.
type Result struct {
	Outcome Outcome
	// Client is the address that got the page (consumed the token). It is
	// set for Served, and also when the server was stopped while it was
	// writing the page.
	Client netip.Addr
	// TTL is print_web.ttl, for the message.
	TTL time.Duration
}

// String describes the result for the user.
func (r Result) String() string {
	switch r.Outcome {
	case Served:
		return fmt.Sprintf("the page was served to %s; if that wasn't you, start the print page again", r.Client)
	case Expired:
		return fmt.Sprintf("the print page stopped after %s without being opened", r.TTL)
	case TooManyWrongTokens:
		return fmt.Sprintf("the print page stopped after %d requests with a wrong address", MaxWrongTokens)
	case Cancelled:
		if r.Client.IsValid() {
			return fmt.Sprintf("the print page was stopped while it was sent to %s", r.Client)
		}
		return "the print page was stopped"
	}
	return "the print page stopped"
}

// Server is a running print page.
type Server struct {
	// URLs are the page's addresses, https://<address>:<port>/p/<token>,
	// one per bound address.
	URLs []string
	// Fingerprint is the certificate's SHA-256 fingerprint as browsers
	// show it ("4F:A1:…:07:D2").
	Fingerprint string
	// CertNotice says why a new certificate was made (first use, the
	// addresses changed, it expired); "" when the stored one was reused.
	CertNotice string
	// Skipped lists addresses of the interfaces that are not used, and why
	// (public, link-local).
	Skipped []string
	// Expires is when the TTL runs out, for the countdown.
	Expires time.Time

	token     string
	port      int
	bound     []netip.Addr
	hostnames []string
	doc       print.Document
	ttl       time.Duration
	srv       *http.Server

	mu       sync.Mutex
	consumed bool
	client   netip.Addr
	wrong    int

	served   chan struct{} // closed when the token is consumed
	tooMany  chan struct{} // closed at MaxWrongTokens
	stop     chan struct{} // closed by Stop
	stopOnce sync.Once
	once     sync.Once // guards served and tooMany
	done     chan struct{}
	result   Result
}

// Start starts the print page and returns once it is listening. The
// server runs until it has served the page, the TTL runs out, ctx is
// cancelled, Stop is called or too many wrong tokens arrive; Wait or Done
// tell when.
func Start(ctx context.Context, opts Options) (*Server, error) {
	st := opts.Settings
	switch {
	case !st.Enabled:
		return nil, ErrDisabled
	case opts.Doc == nil:
		return nil, errors.New("print page: nothing to print")
	case st.TTL < minTTL || st.TTL > config.MaxPrintWebTTL:
		return nil, fmt.Errorf("print_web.ttl: %s is not between %s and %s", st.TTL, config.MinPrintWebTTL, config.MaxPrintWebTTL)
	case st.Port < 1 || st.Port > 65535:
		return nil, fmt.Errorf("print_web.port: %d is not between 1 and 65535", st.Port)
	}
	for _, h := range st.Hostnames {
		if h == "" || strings.ContainsAny(h, " \t\r\n/[]") {
			return nil, fmt.Errorf("print_web.hostnames: %q is not a hostname", h)
		}
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		d, err := config.StateDir()
		if err != nil {
			return nil, err
		}
		stateDir = d
	}

	bindings, skipped, err := resolveAddrs(st.Interfaces)
	if err != nil {
		return nil, err
	}
	allowed := slices.Clone(st.AllowFrom)
	var addrs []netip.Addr
	for _, b := range bindings {
		addrs = append(addrs, b.addr)
		if len(st.AllowFrom) == 0 && !slices.Contains(allowed, b.subnet) {
			allowed = append(allowed, b.subnet)
		}
	}

	cert, err := loadOrCreateCert(filepath.Join(stateDir, certDirName), addrs, st.Hostnames, time.Now())
	if err != nil {
		return nil, err
	}

	var tok [16]byte
	_, _ = rand.Read(tok[:]) // never fails (Go ≥ 1.24)
	s := &Server{
		Fingerprint: cert.fingerprint,
		CertNotice:  cert.notice,
		Skipped:     skipped,
		token:       base64.RawURLEncoding.EncodeToString(tok[:]),
		port:        st.Port,
		bound:       addrs,
		hostnames:   slices.Clone(st.Hostnames),
		doc:         opts.Doc,
		ttl:         st.TTL,
		served:      make(chan struct{}),
		tooMany:     make(chan struct{}),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}

	var listeners []net.Listener
	for _, a := range addrs {
		if err := checkBindable(a); err != nil { // never reached for resolved addresses
			closeAll(listeners)
			return nil, err
		}
		ap := netip.AddrPortFrom(a, uint16(st.Port))
		ln, err := net.Listen("tcp", ap.String())
		if err != nil {
			closeAll(listeners)
			return nil, fmt.Errorf("print page: %w", err)
		}
		listeners = append(listeners, ln)
		s.URLs = append(s.URLs, "https://"+ap.String()+"/p/"+s.token)
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert.pair},
		NextProtos:   []string{"http/1.1"},
	}
	s.srv = &http.Server{
		Handler:           s,
		TLSConfig:         tlsConf,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){}, // no HTTP/2
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       20 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0), // TLS errors would garble the TUI
	}
	s.Expires = time.Now().Add(st.TTL)
	for _, ln := range listeners {
		go func() {
			_ = s.srv.Serve(tls.NewListener(&allowListener{Listener: ln, allowed: allowed}, tlsConf))
		}()
	}
	go s.run(ctx)
	return s, nil
}

func closeAll(ls []net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}

// run waits for the first reason to stop, stops the server and records the
// result.
func (s *Server) run(ctx context.Context) {
	timer := time.NewTimer(time.Until(s.Expires))
	defer timer.Stop()
	res := Result{TTL: s.ttl}
	select {
	case <-s.served:
		res.Outcome = Served
	case <-s.tooMany:
		res.Outcome = TooManyWrongTokens
	case <-timer.C:
		res.Outcome = Expired
	case <-ctx.Done():
		res.Outcome = Cancelled
	case <-s.stop:
		res.Outcome = Cancelled
	}
	if res.Outcome == Served {
		// Stop listening now, and wait until the page has been written,
		// unless a stop comes first.
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownWait)
		go func() {
			select {
			case <-ctx.Done():
			case <-s.stop:
			case <-timer.C:
			case <-shCtx.Done():
			}
			cancel()
		}()
		if err := s.srv.Shutdown(shCtx); err != nil {
			s.srv.Close()
		}
		cancel()
	} else {
		s.srv.Close()
	}
	s.mu.Lock()
	res.Client = s.client
	s.result = res
	s.mu.Unlock()
	close(s.done)
}

// Stop stops the server now (Esc in the print dialog). The outcome is
// Cancelled unless the server had already stopped.
func (s *Server) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// Done is closed when the server has stopped.
func (s *Server) Done() <-chan struct{} { return s.done }

// Wait waits until the server has stopped and returns how.
func (s *Server) Wait() Result {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}

// ServeHTTP checks the Host header and the token, and serves the page once.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w.Header())
	if !s.hostAllowed(r.Host) {
		http.Error(w, "misdirected request: unknown host", http.StatusMisdirectedRequest)
		return
	}
	tok, ok := strings.CutPrefix(r.URL.Path, "/p/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
		s.wrongToken()
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if msg := s.consume(r.RemoteAddr); msg != "" {
		http.Error(w, msg, http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	_ = renderPage(w, s.doc) // a failed write can't be reported to the client
}

// consume takes the token for the client at remote. Only the first call
// succeeds, and tells run to stop the server; it fails too once too many
// wrong tokens have stopped the server. It returns "" on success, else the
// message for the client.
func (s *Server) consume(remote string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.consumed:
		return "already used: start the print page again in passh"
	case s.wrong >= MaxWrongTokens:
		return "stopped after too many wrong addresses: start the print page again in passh"
	}
	s.consumed = true
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		s.client = ap.Addr().Unmap().WithZone("")
	}
	s.once.Do(func() { close(s.served) })
	return ""
}

// wrongToken counts a request with a wrong token.
func (s *Server) wrongToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrong++
	if s.wrong >= MaxWrongTokens && !s.consumed {
		s.once.Do(func() { close(s.tooMany) })
	}
}

// hostAllowed reports whether the Host header names a bound address or one
// of the hostnames, with the right port or none.
func (s *Server) hostAllowed(host string) bool {
	if host == "" {
		return false
	}
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		h, port = host, ""
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
			h = h[1 : len(h)-1]
		}
	}
	if port != "" && port != strconv.Itoa(s.port) {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == "" && slices.Contains(s.bound, a.Unmap())
	}
	h = strings.TrimSuffix(h, ".")
	return slices.ContainsFunc(s.hostnames, func(n string) bool { return strings.EqualFold(n, h) })
}
