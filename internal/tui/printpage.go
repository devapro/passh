package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/printweb"
	"github.com/devapro/passh/internal/sanitize"
)

// The print page of §7.4, started with P: the password sheet of the whole
// vault (print.DefaultFields: password, username, url) served once by
// internal/printweb, with this dialog showing the addresses, a QR code per
// address, the certificate fingerprint and a countdown.

// pageServer is a running print page: *printweb.Server, or a fake in
// tests.
type pageServer interface {
	Stop()
	Done() <-chan struct{}
	Wait() printweb.Result
}

// pageInfo is what the dialog shows of a started print page.
type pageInfo struct {
	URLs        []string
	Fingerprint string
	CertNotice  string
	Skipped     []string
	Expires     time.Time
}

// startPageFunc starts a print page.
type startPageFunc func(ctx context.Context, opts printweb.Options) (pageInfo, pageServer, error)

func startPrintweb(ctx context.Context, opts printweb.Options) (pageInfo, pageServer, error) {
	s, err := printweb.Start(ctx, opts)
	if err != nil {
		return pageInfo{}, nil, err
	}
	return pageInfo{URLs: s.URLs, Fingerprint: s.Fingerprint, CertNotice: s.CertNotice, Skipped: s.Skipped, Expires: s.Expires}, s, nil
}

// webPrintPage is the default PrintPage.
func webPrintPage(cfg *config.Config, start startPageFunc, now func() time.Time, after func(time.Duration, tea.Msg) tea.Cmd) PrintPage {
	return func(ctx context.Context, req PrintRequest) (PrintDialog, error) {
		o := req.Sheet
		o.Date = now()
		sheet, err := print.NewSheet(req.Data.List(), o)
		if errors.Is(err, print.ErrNoEntries) {
			return nil, errors.New("nothing to print: the vault has no entries")
		}
		if err != nil {
			return nil, err
		}
		info, srv, err := start(ctx, printweb.Options{Settings: cfg.PrintWeb, Doc: sheet})
		if err != nil {
			return nil, err
		}
		return newPrintDialog(info, srv, req.Copy, cfg.Clipboard.ClearAfter, now, after), nil
	}
}

var printDialogIDs atomic.Uint64

// Messages of the print dialog.
type (
	// printTickMsg updates the countdown and checks whether the server
	// stopped.
	printTickMsg struct{ id uint64 }
	// printCopiedMsg is the result of c (copy the URL).
	printCopiedMsg struct {
		id  uint64
		err error
	}
	// printResultMsg is how the server ended, after Esc stopped it.
	printResultMsg struct {
		id  uint64
		res printweb.Result
	}
)

// printDialog is the print page's dialog (§7.4 "Starting").
type printDialog struct {
	id         uint64
	info       pageInfo
	srv        pageServer
	copy       func(string) error
	clearAfter time.Duration
	now        func() time.Time
	after      func(time.Duration, tea.Msg) tea.Cmd

	qr      []string // per URL: the QR code, or "" when it can't be made
	sel     int      // the URL shown
	off     int      // scroll offset of the content
	note    string   // e.g. "URL copied"
	noteErr bool

	result   *printweb.Result // set once the server stopped
	stopping bool             // Esc stopped the server; its result is coming
	closed   bool
}

func newPrintDialog(info pageInfo, srv pageServer, copyFn func(string) error, clearAfter time.Duration, now func() time.Time, after func(time.Duration, tea.Msg) tea.Cmd) *printDialog {
	d := &printDialog{
		id: printDialogIDs.Add(1), info: info, srv: srv, copy: copyFn,
		clearAfter: clearAfter, now: now, after: after,
	}
	for _, u := range info.URLs {
		q, err := printweb.TerminalQR(u)
		if err != nil {
			q = ""
		}
		d.qr = append(d.qr, strings.TrimRight(q, "\n"))
	}
	return d
}

func (d *printDialog) Init() tea.Cmd { return d.after(time.Second, printTickMsg{d.id}) }

func (d *printDialog) Done() bool { return d.closed }

func (d *printDialog) Stop() { d.srv.Stop() }

// Outcome describes how the print page ended, for the TUI's status line.
func (d *printDialog) Outcome() string {
	if d.result == nil {
		return ""
	}
	return capitalize(d.result.String()) + "."
}

// finish records the server's result; the server has stopped.
func (d *printDialog) finish() {
	if d.result == nil {
		r := d.srv.Wait()
		d.result = &r
	}
}

func (d *printDialog) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case printTickMsg:
		if msg.id != d.id || d.result != nil {
			return nil
		}
		select {
		case <-d.srv.Done():
			d.finish() // doesn't wait: the server has stopped
			return nil
		default:
		}
		return d.after(time.Second, printTickMsg{d.id})
	case printCopiedMsg:
		if msg.id == d.id {
			d.copied(msg.err)
		}
	case printResultMsg:
		if msg.id == d.id && d.result == nil {
			d.result = &msg.res
			d.closed = d.stopping
		}
	case tea.KeyPressMsg:
		if d.result != nil { // the outcome is showing: any key closes
			d.closed = true
			return nil
		}
		if d.stopping {
			return nil
		}
		switch msg.String() {
		case "esc", "ctrl+c":
			// The server shuts down in the background; the dialog closes
			// with its result.
			d.srv.Stop()
			d.stopping = true
			srv, id := d.srv, d.id
			return func() tea.Msg { return printResultMsg{id: id, res: srv.Wait()} }
		case "c":
			return d.copyURL()
		case "tab", "n":
			if len(d.info.URLs) > 0 {
				d.sel = (d.sel + 1) % len(d.info.URLs)
				d.off = 0
			}
		case "shift+tab", "p":
			if len(d.info.URLs) > 0 {
				d.sel = (d.sel + len(d.info.URLs) - 1) % len(d.info.URLs)
				d.off = 0
			}
		case "up", "k":
			d.off = max(d.off-1, 0)
		case "down", "j":
			d.off++
		case "pgup":
			d.off = max(d.off-10, 0)
		case "pgdown", "space":
			d.off += 10
		case "home", "g":
			d.off = 0
		}
	}
	return nil
}

// copyURL copies the URL shown, in a command: the clipboard may run a
// tool.
func (d *printDialog) copyURL() tea.Cmd {
	if len(d.info.URLs) == 0 {
		return nil
	}
	cp, url, id := d.copy, d.info.URLs[d.sel], d.id
	d.note, d.noteErr = "Copying the URL…", false
	return func() tea.Msg { return printCopiedMsg{id: id, err: cp(url)} }
}

// copied shows how copying the URL went.
func (d *printDialog) copied(err error) {
	var nc *clipboard.NoClipboardError
	switch {
	case errors.As(err, &nc):
		d.note, d.noteErr = "Not copied: no clipboard ("+nc.Reason+"); type the address or scan the QR code.", true
	case err != nil:
		d.note, d.noteErr = "Not copied: "+err.Error(), true
	default:
		d.note, d.noteErr = fmt.Sprintf("URL copied · the clipboard clears in %s.", fmtDuration(d.clearAfter)), false
	}
}

// View renders the dialog in w×h cells: the content scrolls, the countdown
// and the keys stay at the bottom.
func (d *printDialog) View(w, h int) string {
	w = max(w, 1)
	wrap := func(s string) []string { return wrapText(sanitize.Line(s), max(w-2, 1)) }
	var body, foot []string
	add := func(lines []string, style func(string) string) {
		for _, l := range lines {
			if style != nil {
				l = style(l)
			}
			body = append(body, " "+l)
		}
	}

	if d.result != nil {
		add([]string{"Print page stopped"}, fn(styleTitle))
		add([]string{""}, nil)
		style := fn(styleWarn)
		if d.result.Outcome == printweb.Served {
			style = nil
		}
		add(wrap(capitalize(d.result.String())+"."), style)
		foot = append(foot, " "+styleFaint.Render(ansi.Truncate("any key closes", max(w-1, 1), "")))
		return d.frame(body, foot, h)
	}

	// The QR code goes beside the text when there is room, else below it:
	// the address and the fingerprint come first either way.
	qr := ""
	if d.sel < len(d.qr) {
		qr = d.qr[d.sel]
	}
	qrLines := strings.Split(qr, "\n")
	qrW := ansi.StringWidth(qrLines[0])
	side := qr != "" && w >= 40+qrW+3
	textW := w
	if side {
		textW = w - qrW - 2
	}
	wrapT := func(s string) []string { return wrapText(sanitize.Line(s), max(textW-2, 1)) }
	var text []string
	addT := func(lines []string, style func(string) string) {
		for _, l := range lines {
			if style != nil {
				l = style(l)
			}
			text = append(text, " "+l)
		}
	}
	addT([]string{"Print page"}, fn(styleTitle))
	addT(wrapT("Open this address in a browser on your LAN or VPN, compare the certificate fingerprint, then print:"), nil)
	addT([]string{""}, nil)
	if len(d.info.URLs) > 0 {
		addT(wrapT(d.info.URLs[d.sel]), fn(styleKey))
		if len(d.info.URLs) > 1 {
			addT(wrapT(fmt.Sprintf("(%d of %d, Tab: next)", d.sel+1, len(d.info.URLs))), fn(styleFaint))
		}
		addT([]string{""}, nil)
	}
	addT(wrapT("Certificate fingerprint (SHA-256); the browser must show the same:"), nil)
	addT(wrapT(d.info.Fingerprint), fn(styleKey))
	if d.info.CertNotice != "" {
		addT(wrapT(d.info.CertNotice), fn(styleWarn))
	}
	if len(d.info.Skipped) > 0 {
		addT(wrapT("Not used: "+strings.Join(d.info.Skipped, "; ")), fn(styleFaint))
	}
	switch {
	case side:
		for i := range max(len(text), len(qrLines)) {
			l, q := "", ""
			if i < len(text) {
				l = text[i]
			}
			if i < len(qrLines) {
				q = qrLines[i]
			}
			body = append(body, pad(l, textW)+" "+q)
		}
	case len(d.info.URLs) == 0:
		body = text
	case qr == "":
		body = append(text, "", " "+styleFaint.Render("(no QR code for this address)"))
	case qrW+1 > w:
		body = append(text, "")
		add(wrap("(the window is too narrow for the QR code)"), fn(styleFaint))
	default:
		body = append(text, "")
		for _, l := range qrLines {
			body = append(body, " "+l)
		}
	}

	left := max(d.info.Expires.Sub(d.now()), 0)
	for _, l := range wrap("Stops in " + fmtCountdown(left) + ", after the page is loaded once, or with Esc.") {
		foot = append(foot, " "+l)
	}
	if d.note != "" {
		style := fn(styleFaint)
		if d.noteErr {
			style = fn(styleError)
		}
		for _, l := range wrap(d.note) {
			foot = append(foot, " "+style(l))
		}
	}
	for _, l := range wrapItems([]string{"c copy URL", "Tab next URL", "↑↓ scroll", "Esc stop"}, max(w-1, 1)) {
		foot = append(foot, " "+styleFaint.Render(l))
	}
	return d.frame(body, foot, h)
}

// frame fits the scrolled body above the footer in h lines.
func (d *printDialog) frame(body, foot []string, h int) string {
	h = max(h, 1)
	if len(foot) > h {
		foot = foot[len(foot)-h:]
	}
	room := h - len(foot)
	d.off = max(min(d.off, len(body)-room), 0)
	end := min(d.off+room, len(body))
	lines := append([]string{}, body[d.off:end]...)
	if end < len(body) && room > 0 {
		lines[len(lines)-1] = " " + styleFaint.Render("↓ more (↓ scrolls)")
	}
	for len(lines) < room {
		lines = append(lines, "")
	}
	return strings.Join(append(lines, foot...), "\n")
}
