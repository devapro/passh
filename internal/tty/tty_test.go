package tty

import (
	"bytes"
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
	case "passphrase":
		// The pty is the controlling terminal: prompt through /dev/tty.
		t, err := Open()
		if err != nil {
			fmt.Println("open failed:", err)
			os.Exit(1)
		}
		p, err := t.ReadPassphrase("Child passphrase: ")
		if err != nil {
			fmt.Println("read failed:", err)
			os.Exit(1)
		}
		t.Printf("got:%s\n", hex.EncodeToString(p))
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
	go func() {
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
		time.Sleep(5 * time.Millisecond)
	}
}

// rest returns the output after the last match, once it stops growing.
func (c *console) rest() string {
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()[c.pos:]
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

func TestReadPassphraseEchoOff(t *testing.T) {
	tt, c := newTTY(t)
	before, err := term.GetState(int(tt.File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	ch := run(func() ([]byte, error) { return tt.ReadPassphrase("Passphrase: ") })
	c.expect("Passphrase: ")
	c.send("correct horse battery\r")
	got, err := wait(t, ch)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "correct horse battery" {
		t.Errorf("passphrase = %q", got)
	}
	if out := c.rest(); strings.Contains(out, "correct") || strings.Contains(out, "horse") {
		t.Errorf("passphrase was echoed: %q", out)
	}
	after, err := term.GetState(int(tt.File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
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
		{"empty", "\r", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tt, c := newTTY(t)
			ch := run(func() ([]byte, error) { return tt.ReadPassphrase("P: ") })
			c.expect("P: ")
			c.send(tc.typed)
			got, err := wait(t, ch)
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
	before, _ := term.GetState(int(tt.File().Fd()))

	ch := run(func() ([]byte, error) { return tt.ReadPassphrase("P: ") })
	c.expect("P: ")
	c.send("secret\x03")
	if _, err := wait(t, ch); !errors.Is(err, ErrInterrupted) {
		t.Errorf("Ctrl-C: err = %v, want ErrInterrupted", err)
	}
	after, _ := term.GetState(int(tt.File().Fd()))
	if !reflect.DeepEqual(before, after) {
		t.Error("terminal state not restored after Ctrl-C")
	}

	ch = run(func() ([]byte, error) { return tt.ReadPassphrase("P2: ") })
	c.expect("P2: ")
	c.send("\x04")
	if _, err := wait(t, ch); !errors.Is(err, io.EOF) {
		t.Errorf("Ctrl-D: err = %v, want io.EOF", err)
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
	if out := c.rest(); strings.Contains(out, "long enough") {
		t.Errorf("passphrase echoed: %q", out)
	}
}

func TestNewPassphraseGivesUp(t *testing.T) {
	tt, c := newTTY(t)
	ch := run(func() ([]byte, error) { return tt.NewPassphrase(nil) })
	for i := 0; i < 3; i++ {
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

// TestOpenControllingTerminal makes a pty the controlling terminal of a
// child, which then prompts for a passphrase through /dev/tty.
func TestOpenControllingTerminal(t *testing.T) {
	c, slave := newConsole(t)
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"=passphrase")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	c.expect("Child passphrase: ")
	c.send("over ssh\r")
	c.expect("got:" + hex.EncodeToString([]byte("over ssh")))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("child: %v; output %q", err, c.rest())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child didn't exit")
	}
	if strings.Contains(c.all(), "over ssh") {
		t.Error("passphrase was echoed")
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
}
