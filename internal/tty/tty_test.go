package tty

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const helperEnv = "PASSH_TTY_TEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "open":
		// No controlling terminal expected: report what Open says.
		_, err := Open()
		fmt.Print(errors.Is(err, ErrNoTerminal), err)
	case "passphrase", "passphrase-nodeadline":
		// The pty is the controlling terminal: prompt through /dev/tty.
		if os.Getenv(helperEnv) == "passphrase-nodeadline" {
			// As /dev/tty on macOS: a read deadline can't interrupt the read.
			canInterrupt = func(*os.File) bool { return false }
		}
		t, err := Open()
		if err != nil {
			fmt.Println("open failed:", err)
			os.Exit(1)
		}
		p, err := t.ReadPassphrase("Child passphrase: ")
		if err != nil {
			fmt.Println("read failed:", err)
			var se *SignalError
			if errors.As(err, &se) {
				os.Exit(128 + int(se.Signal.(syscall.Signal)))
			}
			os.Exit(1)
		}
		t.Printf("got:%s\n", hex.EncodeToString(p))
		t.Close()
	case "devname":
		t, err := Open()
		if err != nil {
			fmt.Println("open failed:", err)
			os.Exit(1)
		}
		t.Printf("device:%s.\n", t.DeviceName())
		t.Close()
	}
	os.Exit(0)
}

// console is the master side of a pseudo-terminal: it records everything
// the program writes to the terminal and types input.
type console struct {
	t      *testing.T
	master *os.File
	mu     sync.Mutex
	out    bytes.Buffer
	pos    int // how far expect has consumed out
}

func newConsole(t *testing.T) (*console, *os.File) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	c := &console{t: t, master: master}
	done := make(chan struct{})
	// The reader ends when the master is closed (cleanup); the cleanup
	// waits for it.
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, err := master.Read(buf)
			c.mu.Lock()
			c.out.Write(buf[:n])
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		slave.Close()
		master.Close()
		<-done
	})
	return c, slave
}

// expect waits until s appears in the output after the previous match and
// returns everything up to and including it.
func (c *console) expect(s string) string {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.mu.Lock()
		all := c.out.String()
		c.mu.Unlock()
		if i := strings.Index(all[c.pos:], s); i >= 0 {
			seen := all[c.pos : c.pos+i+len(s)]
			c.pos += i + len(s)
			return seen
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("timed out waiting for %q; output after last match: %q", s, all[c.pos:])
		}
		time.Sleep(5 * time.Millisecond) // polling, with the deadline above
	}
}

// rest returns the output after the last match up to now. The prompt under
// test has returned, so all it wrote is on its way: rest writes a marker to
// the terminal after it and waits for the marker, instead of waiting for
// the output to stop growing.
func (c *console) rest(tt *TTY) string {
	c.t.Helper()
	const marker = "\x00end-of-output\x00"
	if _, err := tt.Write([]byte(marker)); err != nil {
		c.t.Fatal(err)
	}
	return strings.TrimSuffix(c.expect(marker), marker)
}

// all returns everything written to the terminal so far.
func (c *console) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

func (c *console) send(s string) {
	c.t.Helper()
	if _, err := c.master.WriteString(s); err != nil {
		c.t.Fatal(err)
	}
}

type result[T any] struct {
	v   T
	err error
}

// run calls f in the background and returns a channel with its result.
// The goroutine ends when f returns; wait receives its result.
func run[T any](f func() (T, error)) <-chan result[T] {
	ch := make(chan result[T], 1)
	go func() {
		v, err := f()
		ch <- result[T]{v, err}
	}()
	return ch
}

func wait[T any](t *testing.T, ch <-chan result[T]) (T, error) {
	t.Helper()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("prompt didn't return")
		panic("unreachable")
	}
}

func newTTY(t *testing.T) (*TTY, *console) {
	t.Helper()
	c, slave := newConsole(t)
	tt, err := New(slave)
	if err != nil {
		t.Fatal(err)
	}
	return tt, c
}

// state returns the terminal state of f, without f.Fd (which would put f
// into blocking mode and stop read deadlines from working).
func state(t *testing.T, f *os.File) *term.State {
	t.Helper()
	var (
		st  *term.State
		err error
	)
	if cerr := control(f, func(fd int) { st, err = term.GetState(fd) }); cerr != nil || err != nil {
		t.Fatal(cerr, err)
	}
	return st
}

// echoOn reports whether the terminal f echoes input.
func echoOn(t *testing.T, f *os.File) bool {
	t.Helper()
	var (
		tio *unix.Termios
		err error
	)
	if cerr := control(f, func(fd int) { tio, err = unix.IoctlGetTermios(fd, ioctlGetTermios) }); cerr != nil || err != nil {
		t.Fatal(cerr, err)
	}
	return tio.Lflag&unix.ECHO != 0
}

func TestReadPassphraseEchoOff(t *testing.T) {
	tt, c := newTTY(t)
	before := state(t, tt.File())
	ch := run(func() ([]byte, error) { return tt.ReadPassphrase("Passphrase: ") })
	c.expect("Passphrase: ")
	if echoOn(t, tt.File()) {
		t.Error("echo is on at the passphrase prompt")
	}
	c.send("correct horse battery\r")
	got, err := wait(t, ch)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "correct horse battery" {
		t.Errorf("passphrase = %q", got)
	}
	if out := c.rest(tt); strings.Contains(out, "correct") || strings.Contains(out, "horse") {
		t.Errorf("passphrase was echoed: %q", out)
	}
	if !reflect.DeepEqual(before, state(t, tt.File())) {
		t.Error("terminal state not restored")
	}
}

func TestReadPassphraseEditing(t *testing.T) {
	tests := []struct{ name, typed, want string }{
		{"backspace", "abc\x7fd\r", "abd"},
		{"ctrl-h", "abc\x08\x08x\r", "ax"},
		{"backspace on empty", "\x7f\x7fok\r", "ok"},
		{"multibyte backspace", "пароль\x7f\x7fь\r", "пароь"},
		{"emoji backspace", "a🔐\x7fb\r", "ab"},
		{"ctrl-u", "wrong\x15right\n", "right"},
		{"ctrl-w", "one two  \x17three\r", "one three"},
		{"other controls ignored", "a\x01\x1bb\x04\r", "ab"},
		// CLI-017: arrow and function keys add nothing.
		{"arrow keys", "ab\x1b[A\x1b[Dc\r", "abc"},
		{"application cursor keys", "a\x1bOAb\x1bOPc\r", "abc"},
		{"function key with parameters", "x\x1b[15~y\x1b[1;5Cz\r", "xyz"},
		{"lone escape then enter", "pw\x1b\r", "pw"},
		{"double escape", "a\x1b\x1b[Bb\r", "ab"},
		{"ctrl-c inside a sequence", "a\x1b[1\x03", ""},
		{"empty", "\r", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tt, c := newTTY(t)
			ch := run(func() ([]byte, error) { return tt.ReadPassphrase("P: ") })
			c.expect("P: ")
			c.send(tc.typed)
			got, err := wait(t, ch)
			if strings.HasSuffix(tc.typed, "\x03") {
				if !errors.Is(err, ErrInterrupted) {
					t.Errorf("typed %q: err = %v, want ErrInterrupted", tc.typed, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("typed %q, got %q, want %q", tc.typed, got, tc.want)
			}
		})
	}
}

func TestReadPassphraseInterruptAndEOF(t *testing.T) {
	tt, c := newTTY(t)
	before := state(t, tt.File())

	ch := run(func() ([]byte, error) { return tt.ReadPassphrase("P: ") })
	c.expect("P: ")
	c.send("secret\x03")
	if _, err := wait(t, ch); !errors.Is(err, ErrInterrupted) {
		t.Errorf("Ctrl-C: err = %v, want ErrInterrupted", err)
	}
	if !reflect.DeepEqual(before, state(t, tt.File())) {
		t.Error("terminal state not restored after Ctrl-C")
	}

	ch = run(func() ([]byte, error) { return tt.ReadPassphrase("P2: ") })
	c.expect("P2: ")
	c.send("\x04")
	if _, err := wait(t, ch); !errors.Is(err, io.EOF) {
		t.Errorf("Ctrl-D: err = %v, want io.EOF", err)
	}
}

// TestPromptSignals (CLI-004): SIGTERM, SIGHUP and SIGINT at a prompt
// restore the terminal and return a *SignalError, for the raw passphrase
// prompt and for a line prompt. The signals go to the test process, which
// catches them while a prompt waits.
func TestPromptSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT} {
		for _, kind := range []string{"passphrase", "line", "masked"} {
			t.Run(sig.String()+"/"+kind, func(t *testing.T) {
				tt, c := newTTY(t)
				before := state(t, tt.File())
				ch := run(func() (string, error) {
					switch kind {
					case "passphrase":
						p, err := tt.ReadPassphrase("Prompt: ")
						return string(p), err
					case "masked":
						p, err := tt.ReadMaskedLines("Prompt: ")
						return string(p), err
					}
					return tt.ReadLine("Prompt: ")
				})
				c.expect("Prompt: ")
				c.send("typed")
				if kind != "line" {
					waitEcho(t, tt.File(), false) // raw mode
				}
				if err := syscall.Kill(os.Getpid(), sig); err != nil {
					t.Fatal(err)
				}
				_, err := wait(t, ch)
				var se *SignalError
				if !errors.As(err, &se) || se.Signal != sig || !errors.Is(err, ErrInterrupted) {
					t.Fatalf("err = %v, want a *SignalError for %v", err, sig)
				}
				if !reflect.DeepEqual(before, state(t, tt.File())) || !echoOn(t, tt.File()) {
					t.Error("terminal state not restored")
				}
			})
		}
	}
}

// waitEcho waits until the terminal's echo setting is on.
func waitEcho(t *testing.T, f *os.File, on bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for echoOn(t, f) != on {
		if time.Now().After(deadline) {
			t.Fatalf("echo still %v", !on)
		}
		time.Sleep(5 * time.Millisecond) // polling, with the deadline above
	}
}

// TestSignalAfterInput: a signal that arrives once the input is complete
// but before the prompt returns still ends the prompt; it is never
// swallowed.
func TestSignalAfterInput(t *testing.T) {
	tt, _ := newTTY(t)
	w := tt.watch(t.Context(), nil)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The signal is delivered asynchronously: wait until the watch has it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		w.mu.Lock()
		got := w.sig
		w.mu.Unlock()
		if got != nil || len(w.sigs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the signal didn't arrive")
		}
		time.Sleep(5 * time.Millisecond) // polling, with the deadline above
	}
	if sig := w.stop(); sig != syscall.SIGTERM {
		t.Errorf("stop = %v, want SIGTERM", sig)
	}
	if err := readErr(t.Context(), syscall.SIGTERM, nil); !errors.Is(err, ErrInterrupted) {
		t.Errorf("readErr = %v", err)
	}
}

// TestPromptContext: the …Context prompts return when their context ends,
// with the terminal restored.
func TestPromptContext(t *testing.T) {
	for _, kind := range []string{"passphrase", "line", "yesno", "confirm", "masked"} {
		t.Run(kind, func(t *testing.T) {
			tt, c := newTTY(t)
			before := state(t, tt.File())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ch := run(func() (struct{}, error) {
				var err error
				switch kind {
				case "passphrase":
					_, err = tt.ReadPassphraseContext(ctx, "Prompt: ")
				case "masked":
					_, err = tt.ReadMaskedLinesContext(ctx, "Prompt: ")
				case "line":
					_, err = tt.ReadLineContext(ctx, "Prompt: ")
				case "yesno":
					_, err = tt.YesNoContext(ctx, "Prompt:", false)
				case "confirm":
					err = tt.ConfirmContext(ctx, "Prompt:")
				}
				return struct{}{}, err
			})
			c.expect("Prompt:")
			cancel()
			if _, err := wait(t, ch); !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want context.Canceled", err)
			}
			if !reflect.DeepEqual(before, state(t, tt.File())) {
				t.Error("terminal state not restored")
			}
		})
	}
	// An ended context: no prompt at all.
	tt, c := newTTY(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := tt.ReadPassphraseContext(ctx, "Never: "); !errors.Is(err, context.Canceled) {
		t.Errorf("ended context: %v", err)
	}
	if _, err := tt.ReadLineContext(ctx, "Never: "); !errors.Is(err, context.Canceled) {
		t.Errorf("ended context: %v", err)
	}
	if out := c.rest(tt); strings.Contains(out, "Never") {
		t.Errorf("prompted with an ended context: %q", out)
	}
}

func TestReadMaskedLines(t *testing.T) {
	tests := []struct{ name, typed, want, shown string }{
		{"one line", "abcd efgh\r\r", "abcd efgh\n", "Key: **** ****"},
		{"leading empty lines", "\r  \rab\r\r", "ab\n", "Key: **"},
		{"two lines", "ab\rcd\r\r", "ab\ncd\n", "Key: **\r\nKey: **"},
		{"pasted with LF", "ab\ncd\n\n", "ab\ncd\n", "Key: **\r\nKey: **"},
		{"pasted with CRLF", "ab\r\ncd\r\n\r\n", "ab\ncd\n", "Key: **\r\nKey: **"},
		{"ctrl-d ends", "ab\r\x04", "ab\n", "Key: **"},
		{"editing", "abx\x7fc\x15de\x17fg\r\r", "fg\n", "Key: ***\b \b*"},
		{"arrow keys", "a\x1b[Cb\r\r", "ab\n", "Key: **"},
		{"multibyte", "ключ\r\r", "ключ\n", "Key: ****"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tt, c := newTTY(t)
			before := state(t, tt.File())
			ch := run(func() ([]byte, error) { return tt.ReadMaskedLines("Key: ") })
			c.expect("Key: ")
			c.send(tc.typed)
			got, err := wait(t, ch)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("typed %q, got %q, want %q", tc.typed, got, tc.want)
			}
			out := "Key: " + c.rest(tt)
			if !strings.Contains(out, tc.shown) {
				t.Errorf("typed %q: screen %q, want %q in it", tc.typed, out, tc.shown)
			}
			for _, secret := range []string{"ab", "cd", "fg", "ключ"} {
				if strings.Contains(out, secret) {
					t.Errorf("%q echoed: %q", secret, out)
				}
			}
			if !reflect.DeepEqual(before, state(t, tt.File())) {
				t.Error("terminal state not restored")
			}
		})
	}

	tt, c := newTTY(t)
	ch := run(func() ([]byte, error) { return tt.ReadMaskedLines("Key: ") })
	c.expect("Key: ")
	c.send("\x04")
	if _, err := wait(t, ch); !errors.Is(err, io.EOF) {
		t.Errorf("Ctrl-D at once: %v, want io.EOF", err)
	}
	ch = run(func() ([]byte, error) { return tt.ReadMaskedLines("Key: ") })
	c.expect("Key: ")
	c.send("ab\rcd\x03")
	if _, err := wait(t, ch); !errors.Is(err, ErrInterrupted) {
		t.Errorf("Ctrl-C: %v, want ErrInterrupted", err)
	}
}

func TestNewPassphrase(t *testing.T) {
	tt, c := newTTY(t)
	var checked []string
	check := func(p []byte) string {
		checked = append(checked, string(p))
		if len(p) < 8 {
			return "Warning: this passphrase is weak."
		}
		return ""
	}
	ch := run(func() ([]byte, error) { return tt.NewPassphrase(check) })
	c.expect("New passphrase: ")
	c.send("\r") // empty: asked again
	c.expect("must not be empty")
	c.expect("New passphrase: ")
	c.send("short\r")
	c.expect("weak")
	c.expect("Repeat passphrase: ")
	c.send("shorter\r")
	c.expect("don't match")
	c.expect("New passphrase: ")
	c.send("long enough words\r")
	c.expect("Repeat passphrase: ")
	c.send("long enough words\r")
	got, err := wait(t, ch)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "long enough words" {
		t.Errorf("passphrase = %q", got)
	}
	if !reflect.DeepEqual(checked, []string{"short", "long enough words"}) {
		t.Errorf("check called with %q", checked)
	}
	if out := c.rest(tt); strings.Contains(out, "long enough") {
		t.Errorf("passphrase echoed: %q", out)
	}
}

func TestNewPassphraseGivesUp(t *testing.T) {
	tt, c := newTTY(t)
	ch := run(func() ([]byte, error) { return tt.NewPassphrase(nil) })
	for i := range 3 {
		c.expect("New passphrase: ")
		c.send(fmt.Sprintf("a%d\r", i))
		c.expect("Repeat passphrase: ")
		c.send(fmt.Sprintf("b%d\r", i))
	}
	if _, err := wait(t, ch); !errors.Is(err, ErrMismatch) {
		t.Errorf("err = %v, want ErrMismatch", err)
	}
}

func TestReadLine(t *testing.T) {
	tt, c := newTTY(t)
	ch := run(func() (string, error) { return tt.ReadLine("Name: ") })
	c.expect("Name: ")
	c.send("hello world\n")
	got, err := wait(t, ch)
	if err != nil || got != "hello world" {
		t.Errorf("ReadLine = %q, %v", got, err)
	}
	c.expect("hello world") // echo is on for ordinary lines

	ch = run(func() (string, error) { return tt.ReadLine("Again: ") })
	c.expect("Again: ")
	c.send("\x04") // Ctrl-D on an empty line
	if _, err := wait(t, ch); !errors.Is(err, io.EOF) {
		t.Errorf("Ctrl-D: err = %v, want io.EOF", err)
	}
}

func TestYesNo(t *testing.T) {
	tests := []struct {
		def   bool
		typed []string
		want  bool
		err   error
	}{
		{true, []string{""}, true, nil},
		{false, []string{""}, false, nil},
		{false, []string{"y"}, true, nil},
		{false, []string{"YES"}, true, nil},
		{true, []string{" no "}, false, nil},
		{false, []string{"maybe", "y"}, true, nil},
		{true, []string{"a", "b", "c"}, false, ErrNotConfirmed},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.typed, ","), func(t *testing.T) {
			tt, c := newTTY(t)
			ch := run(func() (bool, error) { return tt.YesNo("Continue?", tc.def) })
			suffix := " [y/N] "
			if tc.def {
				suffix = " [Y/n] "
			}
			for _, s := range tc.typed {
				c.expect("Continue?" + suffix)
				c.send(s + "\n")
			}
			got, err := wait(t, ch)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Errorf("YesNo = %v, %v; want %v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		phrase, typed string
		ok            bool
	}{
		{PhrasePrintRecoveryKey, "PRINT RECOVERY KEY", true},
		{PhraseExportPlaintext, "  EXPORT PLAINTEXT  ", true},
		{PhrasePrint, "PRINT", true},
		{PhrasePrint, "print", false},
		{PhraseExportPlaintext, "EXPORT", false},
		{PhraseExportPlaintext, "y", false},
		{PhrasePrintRecoveryKey, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.phrase+"/"+tc.typed, func(t *testing.T) {
			tt, c := newTTY(t)
			ch := run(func() (struct{}, error) { return struct{}{}, tt.Confirm(tc.phrase) })
			c.expect("Type " + tc.phrase + " to confirm: ")
			c.send(tc.typed + "\n")
			_, err := wait(t, ch)
			if tc.ok && err != nil {
				t.Errorf("Confirm: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrNotConfirmed) {
				t.Errorf("Confirm = %v, want ErrNotConfirmed", err)
			}
		})
	}
}

func TestIsTerminalAndNew(t *testing.T) {
	_, slave := newConsole(t)
	if !IsTerminal(slave) {
		t.Error("IsTerminal(pty) = false")
	}
	if !canInterrupt(slave) {
		t.Error("IsTerminal put the pty into blocking mode")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Error("IsTerminal(regular file) = true")
	}
	if IsTerminal(nil) {
		t.Error("IsTerminal(nil) = true")
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if IsTerminal(w) {
		t.Error("IsTerminal(pipe) = true")
	}
	if _, err := New(f); !errors.Is(err, ErrNoTerminal) {
		t.Errorf("New(regular file) = %v, want ErrNoTerminal", err)
	}
	tt, err := New(slave)
	if err != nil {
		t.Fatal(err)
	}
	if err := tt.Close(); err != nil {
		t.Fatal(err)
	}
	if !IsTerminal(slave) {
		t.Error("Close closed an injected file")
	}
	if canInterrupt(f) {
		t.Error("a regular file counts as interruptible")
	}
}

// TestOpenWithoutTerminal runs Open in a child that has no controlling
// terminal (a new session), so the result doesn't depend on how the tests
// were started.
func TestOpenWithoutTerminal(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"=open")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	if !strings.HasPrefix(string(out), "true no terminal") {
		t.Errorf("Open without a terminal: %q, want an ErrNoTerminal error", out)
	}
}

// child is the test binary run as a helper with the pty as its controlling
// terminal.
type child struct {
	cmd    *exec.Cmd
	exited chan struct{} // closed when Wait has returned
	err    error         // Wait's error, once exited is closed
}

// startChild runs the test binary as helper with the pty as its
// controlling terminal. It is killed and reaped at the end of the test.
func startChild(t *testing.T, slave *os.File, helper string) *child {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+helper)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ch := &child{cmd: cmd, exited: make(chan struct{})}
	// Ends when the child exits; the cleanup kills it first if needed.
	go func() {
		ch.err = cmd.Wait()
		close(ch.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-ch.exited
	})
	return ch
}

// wait waits for the child to exit and returns Wait's error.
func (ch *child) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-ch.exited:
		return ch.err
	case <-time.After(10 * time.Second):
		t.Fatal("child didn't exit")
		return nil
	}
}

// TestOpenControllingTerminal makes a pty the controlling terminal of a
// child, which then prompts for a passphrase through /dev/tty.
func TestOpenControllingTerminal(t *testing.T) {
	c, slave := newConsole(t)
	ch := startChild(t, slave, "passphrase")
	c.expect("Child passphrase: ")
	c.send("over ssh\r")
	c.expect("got:" + hex.EncodeToString([]byte("over ssh")))
	if err := ch.wait(t); err != nil {
		t.Fatalf("child: %v; output %q", err, c.all())
	}
	if strings.Contains(c.all(), "over ssh") {
		t.Error("passphrase was echoed")
	}
}

// TestSIGTERMAtPrompt (CLI-004) is the reviewed failure: SIGTERM at a
// passphrase prompt on /dev/tty. The terminal gets its echo back, whether
// the read can be interrupted (the prompt returns a *SignalError and the
// process exits 128 + 15) or not (/dev/tty on macOS: the signal is raised
// again after the terminal is restored, and kills the process).
func TestSIGTERMAtPrompt(t *testing.T) {
	for _, helper := range []string{"passphrase", "passphrase-nodeadline"} {
		t.Run(helper, func(t *testing.T) {
			c, slave := newConsole(t)
			ch := startChild(t, slave, helper)
			c.expect("Child passphrase: ")
			waitEcho(t, slave, false) // raw mode, echo off
			c.send("half typed")
			if err := ch.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			err := ch.wait(t)
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("child: %v, want it ended by SIGTERM", err)
			}
			ws := ee.Sys().(syscall.WaitStatus)
			switch helper {
			case "passphrase":
				if ws.ExitStatus() != 128+int(syscall.SIGTERM) {
					t.Errorf("exit %v, want status 143; output %q", ws, c.all())
				}
				c.expect("read failed: interrupted (terminated)")
			default:
				if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
					t.Errorf("exit %v, want killed by SIGTERM; output %q", ws, c.all())
				}
			}
			if !echoOn(t, slave) {
				t.Error("the terminal was left without echo")
			}
			if strings.Contains(c.all(), "half typed") {
				t.Error("the passphrase was echoed")
			}
		})
	}
}

// TestDeviceName (CLI-019): the device behind a pty, and behind /dev/tty in
// a process whose controlling terminal the pty is.
func TestDeviceName(t *testing.T) {
	c, slave := newConsole(t)
	if got := DeviceName(slave); got != slave.Name() {
		t.Errorf("DeviceName(pty) = %q, want %q", got, slave.Name())
	}
	tt, err := New(slave)
	if err != nil {
		t.Fatal(err)
	}
	if got := tt.DeviceName(); got != slave.Name() {
		t.Errorf("TTY.DeviceName = %q, want %q", got, slave.Name())
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	if got := DeviceName(devNull); got != "" {
		t.Errorf("DeviceName(/dev/null) = %q", got)
	}
	if got := DeviceName(nil); got != "" {
		t.Errorf("DeviceName(nil) = %q", got)
	}

	ch := startChild(t, slave, "devname")
	c.expect("device:" + slave.Name() + ".")
	if err := ch.wait(t); err != nil {
		t.Fatalf("child: %v; output %q", err, c.all())
	}

	dev, ok := pathDevice(slave.Name())
	if !ok {
		t.Fatalf("pathDevice(%s) failed", slave.Name())
	}
	if got := findDevice(dev, "/nonexistent", filepath.Dir(slave.Name())); got != slave.Name() {
		t.Errorf("findDevice = %q, want %q", got, slave.Name())
	}
	if isDevicePath("/dev/tty") || !isDevicePath("/dev/pts/1") || isDevicePath("pts/1") {
		t.Error("isDevicePath")
	}
}

func TestWipeAndHelpers(t *testing.T) {
	b := []byte("secret")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Errorf("Wipe left %q", b)
	}
	if got := eraseWord([]byte("   ")); len(got) != 0 {
		t.Errorf("eraseWord(spaces) = %q", got)
	}
	if got := eraseRune(nil); len(got) != 0 {
		t.Errorf("eraseRune(nil) = %q", got)
	}
	if name(nil) != "<nil>" {
		t.Error("name(nil)")
	}
	err := error(&SignalError{Signal: syscall.SIGHUP})
	if !errors.Is(err, ErrInterrupted) || err.Error() != "interrupted (hangup)" {
		t.Errorf("SignalError = %q", err)
	}
}
