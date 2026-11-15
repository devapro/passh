package tui

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"passh/internal/clipboard"
	"passh/internal/print"
	"passh/internal/printweb"
)

// fakePage is a print page server that ends when the test says.
type fakePage struct {
	mu    sync.Mutex
	stops int
	done  chan struct{}
	once  sync.Once
	res   printweb.Result
}

func newFakePage() *fakePage { return &fakePage{done: make(chan struct{})} }

func (p *fakePage) Stop() {
	p.mu.Lock()
	p.stops++
	p.mu.Unlock()
	p.end(printweb.Result{Outcome: printweb.Cancelled, TTL: 5 * time.Minute})
}

func (p *fakePage) end(r printweb.Result) { p.once.Do(func() { p.res = r; close(p.done) }) }

func (p *fakePage) Done() <-chan struct{} { return p.done }

func (p *fakePage) Wait() printweb.Result { <-p.done; return p.res }

func (p *fakePage) stopCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stops
}

const (
	url1 = "https://192.168.1.20:8443/p/AAAAAAAAAAAAAAAAAAAAAA"
	url2 = "https://100.101.102.103:8443/p/AAAAAAAAAAAAAAAAAAAAAA"
	fp   = "4F:A1:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:07:D2"
)

// printHarness starts the TUI with a fake print page server; the page is
// started with P and PRINT.
func printHarness(t *testing.T, opts ...hopt) (*harness, *fakePage, *printweb.Options) {
	t.Helper()
	page := newFakePage()
	var got printweb.Options
	start := func(h *harness, d *deps) {
		h.cfg.PrintWeb.Enabled = true
		d.startPage = func(ctx context.Context, o printweb.Options) (pageInfo, pageServer, error) {
			got = o
			return pageInfo{
				URLs: []string{url1, url2}, Fingerprint: fp,
				CertNotice: "a new certificate was made: first use",
				Skipped:    []string{"203.0.113.5 (eth0): public"},
				Expires:    h.clock.Now().Add(5 * time.Minute),
			}, page, nil
		}
	}
	h := newHarness(t, sampleEntries(), append([]hopt{start}, opts...)...)
	h.selectPath("readme") // a top-level entry: the setup defaults to all entries
	h.press("P", "enter")
	h.typeText("PRINT")
	h.press("enter")
	if h.m.printDlg == nil {
		t.Fatalf("no print dialog:\n%s", h.plain())
	}
	return h, page, &got
}

func (h *harness) dialog() *printDialog { return h.m.printDlg.(*printDialog) }

func TestPrintDialog(t *testing.T) {
	h, page, opts := printHarness(t)
	sheet, ok := opts.Doc.(*print.Sheet)
	if !ok || sheet.Len() != 6 || !opts.Settings.Enabled {
		t.Fatalf("printweb options: %+v", opts)
	}
	h.contains("Print page", url1, "(1 of 2, Tab: next)", "Certificate fingerprint", fp[:40],
		"a new certificate was made", "Not used: 203.0.113.5 (eth0): public",
		"Stops in 5:00, after the page is loaded once, or with Esc.", "c copy URL")
	if !strings.ContainsAny(h.plain(), "▀▄█") {
		t.Fatalf("no QR code:\n%s", h.plain())
	}
	h.checkInert("print dialog")

	h.press("c")
	if copies, _, _ := h.clip.state(); len(copies) != 1 || copies[0].value != url1 {
		t.Fatalf("copies %+v", copies)
	}
	h.contains("URL copied · the clipboard clears in 30s")
	h.press("tab")
	h.contains(url2, "(2 of 2")
	h.press("c")
	if copies, _, _ := h.clip.state(); copies[1].value != url2 {
		t.Fatalf("copies %+v", copies)
	}
	h.press("shift+tab", "down", "down", "up", "pgdown", "home")
	h.contains(url1)

	// The countdown follows the clock.
	h.clock.Advance(61 * time.Second)
	h.send(printTickMsg{h.dialog().id})
	h.contains("Stops in 3:59")
	h.send(printTickMsg{999}) // another dialog's tick

	// The page is loaded: the outcome shows until a key.
	client := netip.MustParseAddr("192.168.1.23")
	page.end(printweb.Result{Outcome: printweb.Served, Client: client, TTL: 5 * time.Minute})
	h.send(printTickMsg{h.dialog().id})
	h.contains("Print page stopped", "The page was served to 192.168.1.23; if that wasn't you, start the print page again.", "any key closes")
	h.press("x")
	if h.m.printDlg != nil {
		t.Fatal("a key didn't close the dialog")
	}
	h.contains("Print page: The page was served to 192.168.1.23")
}

func TestPrintDialogEscStops(t *testing.T) {
	h, page, _ := printHarness(t)
	h.press("esc")
	if h.m.printDlg != nil || page.stopCount() == 0 {
		t.Fatal("Esc didn't stop and close")
	}
	h.contains("Print page: The print page was stopped.")
}

func TestPrintDialogOutcomes(t *testing.T) {
	for _, tc := range []struct {
		res  printweb.Result
		want string
	}{
		{printweb.Result{Outcome: printweb.Expired, TTL: 5 * time.Minute}, "stopped after 5m0s without being opened"},
		{printweb.Result{Outcome: printweb.TooManyWrongTokens}, "after 5 requests with a wrong address"},
	} {
		h, page, _ := printHarness(t)
		page.end(tc.res)
		h.send(printTickMsg{h.dialog().id})
		h.contains(tc.want)
		h.press("enter")
		h.contains("Print page: ")
	}
}

// Any lock stops the server (§7.4).
func TestPrintDialogStoppedByLock(t *testing.T) {
	h, page, _ := printHarness(t)
	h.clock.Advance(h.cfg.Session.IdleTTL)
	h.send(tickMsg{})
	if h.m.screen != screenLock || page.stopCount() == 0 {
		t.Fatal("the idle lock didn't stop the print page")
	}
	h, page, _ = printHarness(t)
	h.send(signalMsg{nil})
	if page.stopCount() == 0 {
		t.Fatal("a signal didn't stop the print page")
	}
}

func TestPrintDialogNoClipboard(t *testing.T) {
	h, _, _ := printHarness(t, func(h *harness, d *deps) {
		d.clip, d.clipErr = nil, &clipboard.NoClipboardError{Reason: "clipboard.osc52 is off and clipboard.command is empty"}
	})
	h.press("c")
	h.contains("Not copied: no clipboard (clipboard.osc52 is off", "scan the QR code")
}

func TestPrintDialogLayout(t *testing.T) {
	h, _, _ := printHarness(t)
	for _, size := range [][2]int{{80, 24}, {40, 20}, {20, 8}, {120, 50}} {
		h.resize(size[0], size[1])
		h.checkFits(size[0], size[1], "print dialog")
		h.checkInert("print dialog")
	}
	h.resize(30, 60)
	h.contains("(the window is too narrow for the QR code)")
	// Stacked (narrow): the address and fingerprint first, the QR code
	// below, reached by scrolling.
	h.resize(60, 24)
	h.contains(url1[:50], "Certificate", "↓ more")
	for range 40 {
		h.press("down")
	}
	h.checkFits(60, 24, "scrolled")
	if !strings.ContainsAny(h.plain(), "▀▄█") {
		t.Fatalf("no QR code after scrolling:\n%s", h.plain())
	}
	// Wide: the QR code beside the text, everything in view.
	h.resize(100, 30)
	h.press("home")
	h.contains("Certificate fingerprint", "Not used:")
	if !strings.ContainsAny(h.plain(), "▀▄█") {
		t.Fatalf("no QR code beside the text:\n%s", h.plain())
	}
}

func TestPrintPageErrors(t *testing.T) {
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) {
		h.cfg.PrintWeb.Enabled = true
		d.startPage = func(context.Context, printweb.Options) (pageInfo, pageServer, error) {
			return pageInfo{}, nil, errors.New("no private address on wg0, eth0")
		}
	})
	h.press("P", "enter")
	h.typeText("PRINT")
	h.press("enter")
	h.contains("Print page: no private address on wg0, eth0")

	h = newHarness(t, nil, func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true })
	h.press("P", "enter")
	h.contains("No entries to print there")
}

// privateInterface finds an interface with an RFC 1918 IPv4 address.
func privateInterface() (string, netip.Addr, bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", netip.Addr{}, false
	}
	rfc1918 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			for _, p := range rfc1918 {
				if p.Contains(ip.Unmap()) {
					return ifi.Name, ip.Unmap(), true
				}
			}
		}
	}
	return "", netip.Addr{}, false
}

// One real print page, on this machine's private address: the default
// PrintPage (printweb.Start), a browser stand-in loads the page, and the
// dialog reports who got it.
func TestPrintPageReal(t *testing.T) {
	name, addr, ok := privateInterface()
	if !ok {
		t.Skip("no RFC 1918 address on this machine")
	}
	ln, err := net.Listen("tcp", netip.AddrPortFrom(addr, 0).String())
	if err != nil {
		t.Skipf("can't listen on %s: %v", addr, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) {
		h.cfg.PrintWeb.Enabled = true
		h.cfg.PrintWeb.Interfaces = []string{name}
		h.cfg.PrintWeb.Port = port
		h.cfg.PrintWeb.TTL = time.Minute
	})
	h.selectPath("readme")
	h.press("P", "enter")
	h.typeText("PRINT")
	h.press("enter")
	if h.m.printDlg == nil {
		t.Fatalf("the print page didn't start:\n%s", h.plain())
	}
	dlg := h.dialog()
	defer dlg.Stop()
	url := dlg.info.URLs[0]
	if !strings.HasPrefix(url, "https://"+addr.String()+":"+strconv.Itoa(port)+"/p/") || len(dlg.info.Fingerprint) != 95 {
		t.Fatalf("info %+v", dlg.info)
	}
	h.contains(url, dlg.info.Fingerprint[:30])

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // the test compares nothing; a person compares the fingerprint
			MinVersion:         tls.VersionTLS13,
		}},
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "work/") {
		t.Fatalf("GET: %d\n%.300s", resp.StatusCode, body)
	}
	select {
	case <-dlg.srv.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the server didn't stop after serving the page")
	}
	h.send(printTickMsg{dlg.id})
	h.contains("The page was served to " + addr.String())
	h.press("enter")
	h.contains("Print page: The page was served to")
}
