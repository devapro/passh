package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

func (a *app) cmdCopy() *cobra.Command {
	var field string
	c := &cobra.Command{
		Use:   "copy <path> [--field f]",
		Short: "Copy a field (default: the password) to the clipboard, cleared after a while",
		Long: "Copy the password, or another field, to the clipboard: through the terminal\n" +
			"(OSC 52, which works over SSH) or with clipboard.command. passh waits and clears\n" +
			"the clipboard after clipboard.clear_after; Ctrl-C clears it at once. The value\n" +
			"is never printed.",
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			// Choose the clipboard before unlocking: without one, say how
			// to copy instead and never ask for the passphrase.
			cb, err := a.clipboard(cfg)
			if err != nil {
				return clipboard.WithHint(err, p.String(), field)
			}
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			e, ok := v.Get(p)
			if !ok {
				err := notFound(v, p)
				v.Close()
				return err
			}
			val, ok := e.Field(field)
			// The key and the other values leave memory before the wait.
			v.Close()
			if !ok {
				return fmt.Errorf("%s has no field %q", p, field)
			}
			if val == "" {
				return fmt.Errorf("%s: the %s is empty; nothing was copied", p, field)
			}
			// Catch the signals before copying (S6): one that comes once
			// the value is on the clipboard ends the wait with a clear.
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			defer signal.Stop(sigs)
			wait := cfg.Clipboard.ClearAfter
			return a.copyAndWait(ctx, cb, val, wait, sigs, func() {
				a.statusf("Copied the %s of %s (%s); the clipboard clears in %s, Ctrl-C clears it now.",
					line(field), line(p.String()), cb, fmtDuration(wait))
			})
		},
	}
	c.Flags().StringVar(&field, "field", model.FieldPassword, "field to copy: password, username, url, tags, notes or a custom field")
	return c
}

// copyAndWait copies val, calls copied (which tells the user, "Ctrl-C
// clears it now"), waits d and clears, as clipboard.CopyAndWait does; but
// the caller caught the signals before the copy, so the message appears
// only once the value is on the clipboard and the signals are handled, and
// a signal that arrives from then on clears at once (S6).
func (a *app) copyAndWait(ctx context.Context, cb *clipboard.Clipboard, val string, d time.Duration, sigs <-chan os.Signal, copied func()) error {
	p, err := cb.CopyFor(ctx, val, d)
	if err != nil {
		return err
	}
	copied()
	var why string
	select {
	case <-p.Done():
		if err := p.Err(); err != nil {
			return fmt.Errorf("%v: %w", clipboard.ErrClearFailed, err)
		}
		a.statusf("Clipboard cleared.")
		return nil
	case <-ctx.Done():
		why = context.Cause(ctx).Error()
	case s := <-sigs:
		why = s.String()
	}
	// The clear must happen although ctx may be done (CONC-2).
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := p.ClearNow(cctx); err != nil {
		return fmt.Errorf("%w (%s), and %v: %w", clipboard.ErrInterrupted, why, clipboard.ErrClearFailed, err)
	}
	a.statusf("Clipboard cleared.")
	return nil
}

// clipboardCleared reports whether CopyAndWait's err means the clipboard
// was cleared: after the wait, or at once when interrupted (S6). It
// branches on the clipboard package's errors, never their text (ERR-4).
func clipboardCleared(err error) bool {
	return err == nil || errors.Is(err, clipboard.ErrInterrupted) && !errors.Is(err, clipboard.ErrClearFailed)
}

// clipboard opens the clipboard (§6.3): clipboard.command if set, else OSC
// 52 through the terminal, if there is one.
func (a *app) clipboard(cfg *config.Config) (*clipboard.Clipboard, error) {
	var term io.Writer // a nil *os.File would not be a nil io.Writer
	if t, err := a.tty(); err == nil {
		term = t.File()
	}
	return clipboard.New(cfg.Clipboard, term)
}
