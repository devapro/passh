package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/tty"
)

// ptyOutput collects what the TUI writes to the pty.
type ptyOutput struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (o *ptyOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *ptyOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// ptyRun runs Run on a pseudo-terminal.
type ptyRun struct {
	t    *testing.T
	ptmx *os.File
	out  *ptyOutput
	done chan error
	mark int // waitFor looks at the output after this offset
}

func startRun(t *testing.T, ctx context.Context, opts Options) *ptyRun {
	t.Helper()
	ptmx, term, err := pty.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	r := &ptyRun{t: t, ptmx: ptmx, out: &ptyOutput{}, done: make(chan error, 1)}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(r.out, ptmx) // ends when the pty is closed
	}()
	t.Cleanup(func() {
		ptmx.Close()
		term.Close()
		select {
		case <-copied:
		case <-time.After(10 * time.Second):
			t.Error("the pty reader didn't end")
		}
	})
	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
		t.Fatal(err)
	}
	opts.TTY = term
	go func() { r.done <- Run(ctx, opts) }()
	return r
}

// waitFor waits until the screen output (without escape sequences) shows
// want, after the previous mark.
func (r *ptyRun) waitFor(want string) {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s := r.out.String()
		if i := strings.Index(ansi.Strip(s[r.mark:]), want); i >= 0 {
			r.mark = len(s)
			return
		}
		time.Sleep(10 * time.Millisecond) // polling, with the deadline above
	}
	r.t.Fatalf("the TUI never showed %q; output:\n%s", want, ansi.Strip(r.out.String()))
}

func (r *ptyRun) write(s string) {
	r.t.Helper()
	if _, err := r.ptmx.Write([]byte(s)); err != nil {
		r.t.Fatal(err)
	}
}

func (r *ptyRun) wait() error {
	r.t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(10 * time.Second):
		r.t.Fatal("Run didn't return")
	}
	return nil
}

// ptyVault writes a vault with the sample entries; it opens with testPass
// or the returned key.
func ptyVault(t *testing.T) (string, *config.Config, *age.X25519Identity) {
	t.Helper()
	k, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.passh")
	writeVault(t, path, k, sampleEntries()...)
	cfg := config.Default()
	cfg.Vault = path
	return path, cfg, k
}

// Run with an agent-less key source: unlock, browse, copy, quit. Quitting
// waits for the pending clear, as `passh copy` does. The clear comes when
// the test fires it, not after a wall-clock delay (TEST-7).
func TestRunWithKeySource(t *testing.T) {
	_, cfg, k := ptyVault(t)
	cfg.Clipboard.ClearAfter = time.Hour
	clip := &fakeClip{}
	r := startRun(t, context.Background(), Options{Config: cfg, Clipboard: clip, KeySource: keys.FromIdentity(k)})
	r.waitFor("Unlocked: 6 entries")
	r.write("j")
	r.write("j")
	r.write("\r") // open work
	r.waitFor("github")
	r.write("j")
	r.waitFor("arsenii")
	r.write("c")
	r.waitFor("Password copied")
	r.write("q")
	r.waitFor("Clipboard clears in")
	if _, clears, _ := clip.state(); clears != 0 {
		t.Fatal("cleared before the deadline")
	}
	clip.fire() // the clear is due
	if err := r.wait(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	r.waitFor("Clipboard cleared.")
	copies, clears, _ := clip.state()
	if len(copies) != 1 || copies[0].value != "s3cr3t-P@ss" || clears != 1 {
		t.Fatalf("clipboard: %+v, clears %d", copies, clears)
	}
	if strings.Contains(r.out.String(), "s3cr3t-P@ss") {
		t.Fatal("the password reached the terminal")
	}
}

// Run through the passphrase prompt, with the real agent client finding
// no agent: unlock, lock with L, quit with ctrl+c.
func TestRunWithPassphrase(t *testing.T) {
	_, cfg, _ := ptyVault(t)
	r := startRun(t, context.Background(), Options{Config: cfg, Clipboard: &fakeClip{}})
	r.waitFor("Passphrase")
	r.write("wrong\r")
	r.waitFor("Wrong passphrase")
	r.write(testPass + "\r")
	r.waitFor("Unlocked: 6 entries")
	r.write("L")
	r.waitFor("vault locked")
	r.write("\x03")
	if err := r.wait(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// While Run waits for the clear after q, Ctrl-C (SIGINT) clears at once and
// ends normally; SIGTERM clears at once and ends with a SignalError.
func TestRunQuitWaitInterrupted(t *testing.T) {
	for _, tc := range []struct {
		sig     syscall.Signal
		wantErr bool
	}{{syscall.SIGINT, false}, {syscall.SIGTERM, true}} {
		t.Run(tc.sig.String(), func(t *testing.T) {
			_, cfg, k := ptyVault(t)
			cfg.Clipboard.ClearAfter = time.Hour
			clip := &fakeClip{}
			r := startRun(t, context.Background(), Options{Config: cfg, Clipboard: clip, KeySource: keys.FromIdentity(k)})
			r.waitFor("Unlocked")
			r.write("u") // the cursor is on bank: nothing to copy
			r.write("j")
			r.write("j")
			r.write("j")
			r.write("\r")
			r.waitFor("readme")
			r.write("c")
			r.waitFor("Password copied")
			r.write("\x03") // ctrl+c quits the TUI like q
			r.waitFor("Clipboard clears in")
			start := time.Now()
			if err := syscall.Kill(os.Getpid(), tc.sig); err != nil {
				t.Fatal(err)
			}
			err := r.wait()
			if time.Since(start) > 5*time.Second {
				t.Fatal("the signal didn't end the wait")
			}
			var se *SignalError
			if got := errors.As(err, &se); got != tc.wantErr || (got && se.Signal != tc.sig) {
				t.Fatalf("Run: %v", err)
			}
			if _, clears, pending := clip.state(); clears != 1 || pending {
				t.Fatalf("clears %d, pending %v", clears, pending)
			}
		})
	}
}

// L clears at once, so quitting afterwards doesn't wait.
func TestRunLockClearsThenQuitDoesntWait(t *testing.T) {
	_, cfg, k := ptyVault(t)
	cfg.Clipboard.ClearAfter = time.Hour
	clip := &fakeClip{}
	r := startRun(t, context.Background(), Options{Config: cfg, Clipboard: clip, KeySource: keys.FromIdentity(k)})
	r.waitFor("Unlocked")
	r.write("jjj\r")
	r.waitFor("readme")
	r.write("c")
	r.waitFor("Password copied")
	r.write("L")
	r.waitFor("Clipboard cleared.")
	r.write("\x03")
	if err := r.wait(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ansi.Strip(r.out.String()), "Clipboard clears in") {
		t.Fatal("waited after the lock had cleared")
	}
	if _, clears, _ := clip.state(); clears != 1 {
		t.Fatalf("clears %d", clears)
	}
}

// SIGHUP (the SSH connection dropped) locks and ends Run.
// What the signal's lock couldn't do (clear the clipboard, stop the agent)
// is printed to Options.Stderr after the TUI (review TUI-004).
func TestRunSignal(t *testing.T) {
	_, cfg, k := ptyVault(t)
	cfg.Clipboard.ClearAfter = time.Hour
	stderr := &syncWriter{}
	clip := &fakeClip{clearErr: &clipboard.ClearError{Err: errors.New("clipboard command: xclip: exit status 1")}}
	ag := &fakeAgent{running: true, stopErr: errors.New("agent socket: connection refused")}
	r := startRun(t, context.Background(), Options{Config: cfg, Clipboard: clip, Agent: ag, KeySource: keys.FromIdentity(k), Stderr: stderr})
	r.waitFor("Unlocked")
	r.write("jjj\r")
	r.waitFor("readme")
	r.write("c")
	r.waitFor("Password copied")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	err := r.wait()
	var se *SignalError
	if !errors.As(err, &se) || se.Signal != syscall.SIGHUP {
		t.Fatalf("Run: %v", err)
	}
	got := stderr.String()
	for _, want := range []string{
		"passh: clearing the clipboard failed: clipboard command: xclip: exit status 1\n",
		"passh: stopping the agent failed: agent socket: connection refused\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(ansi.Strip(r.out.String()), "Clipboard cleared.") {
		t.Error("a failed clear was reported as done")
	}
}

func TestRunContextCancel(t *testing.T) {
	_, cfg, k := ptyVault(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := startRun(t, ctx, Options{Config: cfg, Clipboard: &fakeClip{}, KeySource: keys.FromIdentity(k)})
	r.waitFor("Unlocked")
	cancel()
	if err := r.wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunRefuses(t *testing.T) {
	cfg := config.Default()
	if err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("no config accepted")
	}
	f, err := os.CreateTemp(t.TempDir(), "notatty")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Run(context.Background(), Options{Config: cfg, TTY: f}); !errors.Is(err, tty.ErrNoTerminal) {
		t.Fatalf("a file as terminal: %v", err)
	}
	ptmx, term, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptmx.Close()
	defer term.Close()
	if err := Run(context.Background(), Options{Config: cfg, TTY: term}); err == nil || !strings.Contains(err.Error(), "no vault") {
		t.Fatalf("no vault: %v", err)
	}
	if err := Run(context.Background(), Options{Config: cfg, TTY: term, VaultPath: filepath.Join(t.TempDir(), "missing")}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing vault: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path, _, _ := ptyVault(t)
	if err := Run(ctx, Options{Config: cfg, TTY: term, VaultPath: path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}
