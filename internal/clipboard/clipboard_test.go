package clipboard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/devapro/passh/internal/config"
)

// The test binary doubles as the clipboard command: with helperEnv set it
// records what it got instead of running tests.
const (
	helperEnv = "PASSH_CLIPBOARD_HELPER"
	logEnv    = "PASSH_CLIPBOARD_LOG"
)

// record is what the fake clipboard command saw.
type record struct {
	Args    []string
	Stdin   string
	Cmdline string // /proc/self/cmdline
	Environ string // /proc/self/environ
}

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(isolated(m))
	case "record":
		in, _ := io.ReadAll(os.Stdin)
		r := record{Args: os.Args[1:], Stdin: string(in)}
		if b, err := os.ReadFile("/proc/self/cmdline"); err == nil {
			r.Cmdline = string(b)
		}
		if b, err := os.ReadFile("/proc/self/environ"); err == nil {
			r.Environ = string(b)
		}
		line, _ := json.Marshal(r)
		f, err := os.OpenFile(os.Getenv(logEnv), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			os.Exit(101)
		}
		_, _ = f.Write(append(line, '\n'))
		f.Close()
	case "fail":
		os.Exit(3)
	case "fail-empty":
		in, _ := io.ReadAll(os.Stdin)
		if len(in) == 0 {
			os.Exit(3)
		}
		f, err := os.OpenFile(os.Getenv(logEnv), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			os.Exit(101)
		}
		_, _ = f.Write([]byte("{}\n"))
		f.Close()
	default:
		os.Exit(100)
	}
	os.Exit(0)
}

// isolated runs the tests with every user folder pointing into a temporary
// directory (IMPLEMENTATION.md, test isolation).
func isolated(m *testing.M) int {
	root, err := os.MkdirTemp("", "passh-clipboard-test-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	for _, v := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
		"XDG_RUNTIME_DIR", "TMPDIR", "PASSH_CONFIG", "PASSWORD_STORE_DIR", "GNUPGHOME"} {
		d := filepath.Join(root, strings.ToLower(v))
		if err := os.Mkdir(d, 0o700); err != nil {
			panic(err)
		}
		os.Setenv(v, d)
	}
	return m.Run()
}

// syncBuffer is a terminal stand-in written from timer goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const clearSeq = "\x1b]52;c;\a"

func osc(t *testing.T) (*Clipboard, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	c, err := New(config.Clipboard{ClearAfter: time.Minute, OSC52: true}, buf)
	if err != nil {
		t.Fatal(err)
	}
	if c.Method() != MethodOSC52 {
		t.Fatalf("method = %v, want OSC 52", c.Method())
	}
	return c, buf
}

func waitDone(t *testing.T, p *Pending) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the clear didn't happen")
	}
}

func TestOSC52Bytes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"hunter2", "\x1b]52;c;aHVudGVyMg==\a"},
		{"пароль🔑", "\x1b]52;c;0L/QsNGA0L7Qu9GM8J+UkQ==\a"},
		// An escape sequence in the value is just data inside the base64.
		{"a\x1b]52;c;x\a", "\x1b]52;c;YRtdNTI7Yzt4Bw==\a"},
		{"", clearSeq},
	} {
		if got := string(OSC52(tc.in)); got != tc.want {
			t.Errorf("OSC52(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCopyAndClearOSC52(t *testing.T) {
	c, buf := osc(t)
	ctx := context.Background()
	if err := c.Copy(ctx, "пароль🔑"); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "\x1b]52;c;0L/QsNGA0L7Qu9GM8J+UkQ==\a"; got != want {
		t.Fatalf("after Copy the terminal got %q, want %q", got, want)
	}
	if err := c.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "\x1b]52;c;0L/QsNGA0L7Qu9GM8J+UkQ==\a"+clearSeq; got != want {
		t.Fatalf("after Clear the terminal got %q, want %q", got, want)
	}
	if c.String() != "OSC 52 through the terminal" || MethodOSC52.String() != "OSC 52" {
		t.Errorf("descriptions: %q, %q", c.String(), MethodOSC52.String())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, syscall.EIO }

func TestOSC52WriteError(t *testing.T) {
	c, err := New(config.Clipboard{OSC52: true}, failWriter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Copy(context.Background(), "x"); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Copy = %v, want EIO", err)
	}
}

func TestSelection(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	notTTY, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer notTTY.Close()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer master.Close()
	defer slave.Close()
	var nilFile *os.File

	for _, tc := range []struct {
		name    string
		cfg     config.Clipboard
		term    io.Writer
		want    Method
		noClip  bool // error matches ErrNoClipboard
		otherEr bool // some other error
	}{
		{name: "command wins over OSC 52", cfg: config.Clipboard{OSC52: true, Command: []string{exe}}, term: &syncBuffer{}, want: MethodCommand},
		{name: "command without a terminal", cfg: config.Clipboard{Command: []string{exe, "-x"}}, want: MethodCommand},
		{name: "OSC 52 on a pty", cfg: config.Clipboard{OSC52: true}, term: slave, want: MethodOSC52},
		{name: "OSC 52 on a writer", cfg: config.Clipboard{OSC52: true}, term: &syncBuffer{}, want: MethodOSC52},
		{name: "OSC 52 without a terminal", cfg: config.Clipboard{OSC52: true}, noClip: true},
		{name: "OSC 52 with a nil file", cfg: config.Clipboard{OSC52: true}, term: nilFile, noClip: true},
		{name: "OSC 52 on a regular file", cfg: config.Clipboard{OSC52: true}, term: notTTY, noClip: true},
		{name: "OSC 52 off", cfg: config.Clipboard{OSC52: false}, term: slave, noClip: true},
		{name: "missing program", cfg: config.Clipboard{OSC52: true, Command: []string{"passh-no-such-clipboard-tool"}}, term: slave, otherEr: true},
		{name: "empty program", cfg: config.Clipboard{Command: []string{" "}}, otherEr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.cfg, tc.term)
			switch {
			case tc.noClip:
				if !errors.Is(err, ErrNoClipboard) {
					t.Fatalf("New = %v, %v; want ErrNoClipboard", c, err)
				}
				if !strings.Contains(err.Error(), "passh show <path> --field password | pbcopy") {
					t.Errorf("error %q lacks the hint", err)
				}
			case tc.otherEr:
				if err == nil || errors.Is(err, ErrNoClipboard) {
					t.Fatalf("New = %v; want an error other than ErrNoClipboard", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if c.Method() != tc.want {
					t.Fatalf("method = %v, want %v", c.Method(), tc.want)
				}
			}
		})
	}
}

func TestHint(t *testing.T) {
	err := error(&NoClipboardError{Reason: "r"})
	if got, want := err.Error(), "no clipboard: r; copy with: passh show <path> --field password | pbcopy"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	err = WithHint(err, "bank/My Bank", "")
	if !errors.Is(err, ErrNoClipboard) {
		t.Fatal("WithHint lost ErrNoClipboard")
	}
	if !strings.HasSuffix(err.Error(), "passh show 'bank/My Bank' --field password | pbcopy") {
		t.Errorf("hint with path: %q", err)
	}
	if got, want := Hint("work/github", "username"), "passh show work/github --field username | pbcopy"; got != want {
		t.Errorf("Hint = %q, want %q", got, want)
	}
	if got, want := Hint("it's", "x y"), `passh show 'it'\''s' --field 'x y' | pbcopy`; got != want {
		t.Errorf("Hint = %q, want %q", got, want)
	}
	other := errors.New("other")
	if WithHint(other, "a", "b") != other { //nolint:errorlint // identity, not a match: the same error comes back
		t.Error("WithHint changed an unrelated error")
	}
}

// fakeCommand configures the test binary as clipboard.command and returns
// a function that reads what each run recorded.
func fakeCommand(t *testing.T, mode string, args ...string) (*Clipboard, func() []record) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "runs.jsonl")
	t.Setenv(helperEnv, mode)
	t.Setenv(logEnv, log)
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a -race child would wait 1 s on exit
	c, err := New(config.Clipboard{OSC52: true, Command: append([]string{exe}, args...)}, &syncBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	return c, func() []record {
		f, err := os.Open(log)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var runs []record
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var r record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			runs = append(runs, r)
		}
		return runs
	}
}

func TestCommandGetsValueOnStdin(t *testing.T) {
	const secret = "s3cr3t-P@ss пароль"
	c, runs := fakeCommand(t, "record", "-selection", "clipboard")
	ctx := context.Background()
	if err := c.Copy(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := c.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	got := runs()
	if len(got) != 2 {
		t.Fatalf("%d runs, want 2", len(got))
	}
	if got[0].Stdin != secret || got[1].Stdin != "" {
		t.Errorf("stdin = %q then %q; want the value, then empty", got[0].Stdin, got[1].Stdin)
	}
	for i, r := range got {
		if !slices.Equal(r.Args, []string{"-selection", "clipboard"}) {
			t.Errorf("run %d: args = %q, want exactly the configured ones", i, r.Args)
		}
		for _, where := range []string{strings.Join(r.Args, " "), r.Cmdline, r.Environ} {
			if strings.Contains(where, "s3cr3t") {
				t.Errorf("run %d: the secret is in the arguments or environment", i)
			}
		}
	}
	if !strings.HasPrefix(c.String(), "command ") || MethodCommand.String() != "clipboard command" {
		t.Errorf("descriptions: %q, %q", c.String(), MethodCommand.String())
	}
}

func TestCommandFailure(t *testing.T) {
	c, _ := fakeCommand(t, "fail")
	if err := c.Copy(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "clipboard command") {
		t.Fatalf("Copy = %v, want a clipboard command error", err)
	}
	if _, err := c.CopyFor(context.Background(), "x", time.Hour); err == nil {
		t.Fatal("CopyFor succeeded with a failing command")
	}
}

func TestCopyForClearsAfterDuration(t *testing.T) {
	c, buf := osc(t)
	start := time.Now()
	p, err := c.CopyFor(context.Background(), "hunter2", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != string(OSC52("hunter2")) {
		t.Fatalf("right after copying: %q", got)
	}
	if d := p.Deadline().Sub(start); d < 100*time.Millisecond || d > time.Second {
		t.Errorf("deadline in %v, want about 100ms", d)
	}
	waitDone(t, p)
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("cleared after %v, before the duration", elapsed)
	}
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	if got, want := buf.String(), string(OSC52("hunter2"))+clearSeq; got != want {
		t.Fatalf("terminal got %q, want %q", got, want)
	}
	// Nothing left to do afterwards.
	if p.Stop() {
		t.Error("Stop after the clear reported a scheduled clear")
	}
	if err := p.ClearNow(context.Background()); err != nil || buf.String() != string(OSC52("hunter2"))+clearSeq {
		t.Errorf("ClearNow after the clear wrote again or failed: %v", err)
	}
}

func TestCommandClearAfterDuration(t *testing.T) {
	c, runs := fakeCommand(t, "record")
	p, err := c.CopyFor(context.Background(), "v", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	got := runs()
	if len(got) != 2 || got[0].Stdin != "v" || got[1].Stdin != "" {
		t.Fatalf("runs = %+v; want a copy, then an empty value", got)
	}
}

func TestNewerCopyReplacesSchedule(t *testing.T) {
	c, buf := osc(t)
	ctx := context.Background()
	first, err := c.CopyFor(ctx, "a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.CopyFor(ctx, "b", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("the first schedule is still pending")
	}
	if first.Err() != nil {
		t.Fatal(first.Err())
	}
	waitDone(t, second)
	// The first ClearNow must not wipe anything now: it was replaced.
	if err := first.ClearNow(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), string(OSC52("a"))+string(OSC52("b"))+clearSeq; got != want {
		t.Fatalf("terminal got %q, want %q", got, want)
	}
}

func TestClearNowStopAndClearPending(t *testing.T) {
	ctx := context.Background()

	c, buf := osc(t)
	p, err := c.CopyFor(ctx, "x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ClearNow(ctx); err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if got := buf.String(); got != string(OSC52("x"))+clearSeq {
		t.Fatalf("after ClearNow: %q", got)
	}

	c, buf = osc(t)
	p, err = c.CopyFor(ctx, "x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Stop() || p.Stop() {
		t.Fatal("Stop should report true once, then false")
	}
	waitDone(t, p)
	if err := c.ClearPending(ctx); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != string(OSC52("x")) {
		t.Fatalf("after Stop: %q, want no clear", got)
	}

	c, buf = osc(t)
	p, err = c.CopyFor(ctx, "x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ClearPending(ctx); err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if err := c.ClearPending(ctx); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != string(OSC52("x"))+clearSeq {
		t.Fatalf("after ClearPending twice: %q, want one clear", got)
	}

	// Clear drops a scheduled clear too.
	c, buf = osc(t)
	p, err = c.CopyFor(ctx, "x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if err := p.ClearNow(ctx); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != string(OSC52("x"))+clearSeq {
		t.Fatalf("after Clear: %q, want one clear", got)
	}
}

func TestCopyAndWait(t *testing.T) {
	c, buf := osc(t)
	start := time.Now()
	if err := c.CopyAndWait(context.Background(), "hunter2", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("returned after %v, before the clear was due", elapsed)
	}
	if got, want := buf.String(), string(OSC52("hunter2"))+clearSeq; got != want {
		t.Fatalf("terminal got %q, want %q", got, want)
	}
}

// afterCopy runs f once cond holds, or after 10 s at the latest (the test
// then fails on what it checks). The goroutine ends after f.
func afterCopy(cond func() bool, f func()) {
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for !cond() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond) // polling, with the deadline above
		}
		f()
	}()
}

func TestCopyAndWaitCancelClearsAtOnce(t *testing.T) {
	c, buf := osc(t)
	ctx, cancel := context.WithCancel(context.Background())
	afterCopy(func() bool { return strings.Contains(buf.String(), "aHVudGVyMg==") }, cancel)
	start := time.Now()
	err := c.CopyAndWait(ctx, "hunter2", time.Hour)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("CopyAndWait = %v, want ErrInterrupted", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("waited for the full duration")
	}
	if got, want := buf.String(), string(OSC52("hunter2"))+clearSeq; got != want {
		t.Fatalf("terminal got %q, want %q", got, want)
	}
}

func TestCopyAndWaitSignalClearsAtOnce(t *testing.T) {
	c, buf := osc(t)
	// CopyAndWait has caught the signals once the copy is written.
	afterCopy(func() bool { return strings.Contains(buf.String(), "aHVudGVyMg==") },
		func() { _ = syscall.Kill(os.Getpid(), syscall.SIGINT) })
	err := c.CopyAndWait(context.Background(), "hunter2", time.Hour)
	if !errors.Is(err, ErrInterrupted) || errors.Is(err, ErrClearFailed) {
		t.Fatalf("CopyAndWait = %v, want ErrInterrupted after a clear", err)
	}
	if got, want := buf.String(), string(OSC52("hunter2"))+clearSeq; got != want {
		t.Fatalf("terminal got %q, want %q", got, want)
	}
}

func TestCopyAndWaitClearFailureIsReported(t *testing.T) {
	c, _ := fakeCommand(t, "fail-empty") // records the copy, fails the clear
	log := os.Getenv(logEnv)
	// Caught since before the copy started, and handled after it ends.
	afterCopy(func() bool { fi, err := os.Stat(log); return err == nil && fi.Size() > 0 },
		func() { _ = syscall.Kill(os.Getpid(), syscall.SIGHUP) })
	err := c.CopyAndWait(context.Background(), "v", time.Hour)
	var ce *ClearError
	if !errors.Is(err, ErrInterrupted) || !errors.Is(err, ErrClearFailed) || !errors.As(err, &ce) {
		t.Fatalf("CopyAndWait = %v, want ErrInterrupted and ErrClearFailed", err)
	}
	if !strings.Contains(err.Error(), "clearing the clipboard failed") {
		t.Errorf("message %q", err)
	}

	// The scheduled clear fails: ErrClearFailed without ErrInterrupted.
	err = c.CopyAndWait(context.Background(), "v", 0)
	if !errors.Is(err, ErrClearFailed) || errors.Is(err, ErrInterrupted) {
		t.Fatalf("CopyAndWait with a failing timed clear = %v", err)
	}
	if strings.Count(err.Error(), "clearing the clipboard failed") != 1 {
		t.Errorf("message %q", err)
	}
}

// TestClearErrors (CLI-002): every failed clear matches ErrClearFailed, and
// its message is the cause's (callers word it); a failed copy doesn't.
func TestClearErrors(t *testing.T) {
	c, _ := fakeCommand(t, "fail-empty")
	ctx := context.Background()
	p, err := c.CopyFor(ctx, "v", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	err = c.ClearPending(ctx)
	var ce *ClearError
	if !errors.Is(err, ErrClearFailed) || !errors.As(err, &ce) || ce.Unwrap() == nil {
		t.Fatalf("ClearPending = %v, want a *ClearError", err)
	}
	if strings.Contains(err.Error(), "clearing the clipboard failed") || !strings.Contains(err.Error(), "clipboard command") {
		t.Errorf("ClearPending message %q, want the cause only", err)
	}
	if !errors.Is(p.Err(), ErrClearFailed) {
		t.Errorf("Pending.Err = %v", p.Err())
	}
	if err := c.Clear(ctx); !errors.Is(err, ErrClearFailed) {
		t.Errorf("Clear = %v", err)
	}
	p, err = c.CopyFor(ctx, "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ClearNow(ctx); !errors.Is(err, ErrClearFailed) {
		t.Errorf("ClearNow = %v", err)
	}
	p, err = c.CopyFor(ctx, "x", 0) // the timer's clear
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if !errors.Is(p.Err(), ErrClearFailed) {
		t.Errorf("timed clear: Err = %v", p.Err())
	}

	f, _ := fakeCommand(t, "fail")
	if _, err := f.CopyFor(ctx, "v", time.Hour); err == nil || errors.Is(err, ErrClearFailed) {
		t.Errorf("failed copy = %v, want an error that isn't ErrClearFailed", err)
	}
}

func TestDoctorTest(t *testing.T) {
	c, buf := osc(t)
	if err := c.Test(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), string(OSC52(TestString))+clearSeq; got != want {
		t.Fatalf("terminal got %q, want %q", got, want)
	}
}

func TestEnvironmentNotes(t *testing.T) {
	env := map[string]string{"TMUX": "/tmp/tmux-1/default,1,0", "STY": "1.pts", "TERM_PROGRAM": "Apple_Terminal"}
	notes := EnvironmentNotes(func(k string) string { return env[k] })
	if len(notes) != 3 || !strings.Contains(notes[0], "set-clipboard on") {
		t.Fatalf("notes = %q", notes)
	}
	if n := EnvironmentNotes(func(string) string { return "" }); len(n) != 0 {
		t.Fatalf("notes for a plain environment: %q", n)
	}
}

func TestPending(t *testing.T) {
	c, _ := osc(t)
	ctx := context.Background()
	if _, ok := c.Pending(); ok {
		t.Fatal("pending before any copy")
	}
	before := time.Now()
	p, err := c.CopyFor(ctx, "x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := c.Pending()
	if !ok || d != p.Deadline() || d.Before(before.Add(time.Hour)) {
		t.Fatalf("Pending = %v, %v; deadline %v", d, ok, p.Deadline())
	}
	if err := c.ClearPending(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Pending(); ok {
		t.Fatal("pending after ClearPending")
	}

	// A clear that happened, or was stopped, is not pending.
	p, err = c.CopyFor(ctx, "y", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if _, ok := c.Pending(); ok {
		t.Fatal("pending after the timed clear")
	}
	p, err = c.CopyFor(ctx, "z", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()
	if _, ok := c.Pending(); ok {
		t.Fatal("pending after Stop")
	}
}

// retainWriter keeps the slice it was given, against io.Writer's contract,
// to see what happens to it afterwards.
type retainWriter struct{ got []byte }

func (w *retainWriter) Write(p []byte) (int, error) {
	w.got = p
	return len(p), nil
}

// TestOSC52BufferWiped (CLI-016): the sequence that carries the secret is
// wiped once it is written.
func TestOSC52BufferWiped(t *testing.T) {
	w := &retainWriter{}
	c, err := New(config.Clipboard{OSC52: true}, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Copy(context.Background(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	if len(w.got) == 0 || !bytes.Equal(w.got, make([]byte, len(w.got))) {
		t.Errorf("after the write the sequence holds %q, want zeros", w.got)
	}
}
