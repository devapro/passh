package tui

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/vault"
)

// syncWriter is a terminal stand-in for OSC 52.
type syncWriter struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestClipboardAdapter(t *testing.T) {
	term := &syncWriter{}
	c, err := clipboard.New(config.Clipboard{OSC52: true}, term)
	if err != nil {
		t.Fatal(err)
	}
	cb := NewClipboard(c)
	if err := cb.CopyFor(context.Background(), "v", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := cb.ClearPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := term.String(), string(clipboard.OSC52("v"))+string(clipboard.OSC52("")); got != want {
		t.Fatalf("wrote %q, want %q", got, want)
	}
}

// reloadRollbackHarness: the file on disk goes back to an older revision
// while the TUI is open; R reloads it and asks the rollback question
// (§4.10) in the main view.
func reloadRollbackHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, sampleEntries())
	old, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	h.external(func(v *vault.Vault) {
		if _, err := v.Add(entry("new/one", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.WriteFile(h.path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	h.send(pollMsg{})
	h.press("R")
	if h.m.confirm == nil || h.m.confirm.kind != confirmRollback {
		t.Fatalf("no rollback question:\n%s", h.plain())
	}
	h.contains("older than one seen before", "Continue with this copy? [y/N]")
	return h
}

func TestReloadRollbackQuestion(t *testing.T) {
	h := reloadRollbackHarness(t)
	h.press("n")
	h.contains("Reload failed: stopped: this copy is older")
	h.press("R", "y")
	h.contains("Reloaded: revision 1, 6 entries.")
	if h.m.changedOnDisk {
		t.Fatal("still blocked after the reload")
	}
}

// A signal while the rollback question waits doesn't hang the lock.
func TestSignalDuringQuestion(t *testing.T) {
	h := reloadRollbackHarness(t)
	done := make(chan session.Report, 1)
	go func() {
		h.m.abortJobs() // what Run's signal handler does
		h.m.flights.close()()
		done <- lockSession(t.Context(), h.m.sess, session.ReasonSignal)
	}()
	select {
	case r := <-done:
		if !r.Locked {
			t.Fatal("not locked")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lock hung on the pending question")
	}
	h.run(nil) // the reload's result arrives and is dropped
	h.send(signalMsg{syscall.SIGTERM})
	if !h.quit {
		t.Fatal("didn't quit")
	}
	var se *SignalError
	if !errors.As(h.m.exitErr, &se) {
		t.Fatal(h.m.exitErr)
	}
}

// A lock while the rollback question waits drops the question, and leaves
// no answer behind: the next unlock asks again and waits for the user
// (§4.10; review TUI-001, where a stale "no" answered the next unlock's
// question and quit the TUI). ctrl+c at the question quits.
func TestLockDuringQuestion(t *testing.T) {
	for _, how := range []string{"L", "idle", "lock call"} {
		t.Run(how, func(t *testing.T) {
			h := reloadRollbackHarness(t)
			switch how {
			case "L":
				h.press("L")
			case "idle":
				h.clock.Advance(h.cfg.Session.IdleTTL)
				h.send(tickMsg{})
			case "lock call":
				h.run(h.m.lock(session.ReasonKey))
			}
			h.run(nil) // the cancelled reload's result arrives and is dropped
			if h.m.screen != screenLock || h.quit {
				t.Fatalf("not locked, or quit (%v):\n%s", h.m.exitErr, h.plain())
			}
			h.lacks("older than one seen before")
			// Unlock again (Enter uses the key source): the file is still the
			// older copy, so the question comes again, unanswered.
			h.press("enter")
			if h.quit {
				t.Fatalf("the next unlock was answered without the user: %v", h.m.exitErr)
			}
			if h.m.lk.ask == "" {
				t.Fatalf("the next unlock didn't ask the rollback question:\n%s", h.plain())
			}
			h.contains("older than one seen before", "Continue with this copy?")
			h.press("y")
			if h.quit {
				t.Fatalf("the question had been answered before the user's yes: %v", h.m.exitErr)
			}
			h.mustUnlocked()
		})
	}
	h := reloadRollbackHarness(t)
	h.press("ctrl+c")
	if !h.quit {
		t.Fatal("ctrl+c didn't quit")
	}
}

// Warnings from the vault (here: text around the vault file, §4.5) show
// in the status line.
func TestVaultWarningsShown(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("trailing junk\n")
	f.Close()
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
	h.contains("Unlocked: 6 entries", "Warning:")
}
