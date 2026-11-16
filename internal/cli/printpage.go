package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/printweb"
	"github.com/devapro/passh/internal/tty"
)

// servePrintPage runs the print page dialog (§7.4) on the terminal t: the
// URLs with QR codes, the certificate fingerprint and a countdown; c copies
// the URL, Esc (or q, or Ctrl-C) stops. SIGINT, SIGHUP and SIGTERM stop the
// server too. It reports how the page ended.
func (a *app) servePrintPage(ctx context.Context, t *tty.TTY, cfg *config.Config, doc print.Document) error {
	// The signals cancel ctx, which stops the server (CONC-6); stop ends
	// the watch.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	defer stop()

	srv, err := printweb.Start(ctx, printweb.Options{Settings: cfg.PrintWeb, Doc: doc, Printer: a.p})
	if err != nil {
		return err
	}
	var b strings.Builder
	if srv.CertNotice != "" {
		b.WriteString(line(srv.CertNotice) + "\n")
	}
	for _, s := range srv.Skipped {
		b.WriteString(a.T("not used: %s", line(s)) + "\n")
	}
	for _, u := range srv.URLs {
		if qr, err := printweb.TerminalQR(u); err == nil {
			b.WriteString(qr)
		}
		b.WriteString(u + "\n\n")
	}
	b.WriteString(a.T("certificate SHA-256  %s", srv.Fingerprint) + "\n")
	b.WriteString(a.T("Compare it with the fingerprint your browser shows before you accept the certificate.") + "\n")
	b.WriteString(a.T("c copies the URL · Esc stops") + "\n")
	a.termf(t, "%s", b.String())

	res := a.printPageKeys(ctx, t, cfg, srv)
	if res.Outcome == printweb.Served {
		a.statusf("Done: %s.", res)
		return nil
	}
	return i18n.Errorf("%v", res) // the Result, in the user's language when shown
}

// printPageKeys shows the countdown and handles keys until the server
// stops. The terminal is in raw mode meanwhile and restored afterwards.
func (a *app) printPageKeys(ctx context.Context, t *tty.TTY, cfg *config.Config, srv *printweb.Server) printweb.Result {
	f := t.File()
	if restore, err := makeRaw(f); err == nil {
		defer restore()
	}
	// Buffered (CONC-4): keys typed faster than the loop below takes them
	// are kept rather than lost, up to a few; more are dropped.
	keys := make(chan byte, 16)
	readerDone := make(chan struct{})
	// The reader ends when the terminal's read fails: the deadline set
	// below, once the dialog is over, or the end of the terminal. It is
	// waited for up to a second. Where /dev/tty has no read deadlines
	// (macOS), it stays blocked until the next key, which it eats; passh
	// exits right after the dialog, so that is harmless.
	go func() {
		defer close(readerDone)
		var k [1]byte
		for {
			n, err := f.Read(k[:])
			if n == 1 {
				select {
				case keys <- k[0]:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		// Unblock the reader, so it doesn't eat input after the dialog.
		if f.SetReadDeadline(time.Now()) == nil {
			select {
			case <-readerDone:
			case <-time.After(time.Second):
			}
			_ = f.SetReadDeadline(time.Time{})
		}
	}()

	// The status line is redrawn in place with a control sequence of
	// passh's own; its text is passh's messages and numbers.
	status := func(msg string) {
		left := max(time.Until(srv.Expires).Round(time.Second), 0)
		_, _ = fmt.Fprintf(t, "\r\x1b[K%s%s", msg, a.T("stops after one load or in %d:%02d", int(left/time.Minute), int(left%time.Minute/time.Second)))
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var copied string
	cb, cbErr := a.clipboard(cfg)
	if cb != nil {
		defer func() {
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer ccancel()
			_ = cb.ClearPending(cctx)
		}()
	}
	status("")
	for {
		select {
		case <-srv.Done():
			_, _ = t.Write([]byte("\r\x1b[K"))
			return srv.Wait()
		case <-tick.C:
			status(copied)
		case k := <-keys:
			switch k {
			case 'c', 'C':
				switch {
				case cbErr != nil:
					copied = a.T("no clipboard") + " · "
				default:
					if _, err := cb.CopyFor(ctx, srv.URLs[0], cfg.Clipboard.ClearAfter); err != nil {
						copied = a.T("copy failed") + " · "
					} else {
						copied = a.T("URL copied") + " · "
					}
				}
				status(copied)
			case 0x1b, 'q', 'Q', 0x03:
				srv.Stop()
			}
		}
	}
}

// makeRaw puts the terminal f into raw mode and returns the function that
// restores it. Unlike term.MakeRaw(int(f.Fd())), it leaves f in
// non-blocking mode, so read deadlines keep working on it.
func makeRaw(f *os.File) (restore func(), err error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		old    *term.State
		rawErr error
	)
	if err := rc.Control(func(fd uintptr) { old, rawErr = term.MakeRaw(int(fd)) }); err != nil {
		return nil, err
	}
	if rawErr != nil {
		return nil, rawErr
	}
	return func() {
		_ = rc.Control(func(fd uintptr) { _ = term.Restore(int(fd), old) })
	}, nil
}
