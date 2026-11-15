package editor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/tty"
)

// screen collects what a program writes to the pty.
type screen struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type runResult struct {
	e   model.Entry
	err error
}

// startRun runs the form on a new pty and returns the master side, the
// screen and the result channel.
func startRun(t *testing.T, ctx context.Context, e model.Entry) (*os.File, *screen, chan runResult) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() {
		master.Close()
		slave.Close()
	})
	if err := pty.Setsize(master, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
		t.Fatal(err)
	}
	scr := &screen{}
	go func() { _, _ = io.Copy(scr, master) }()
	done := make(chan runResult, 1)
	go func() {
		got, err := Run(ctx, slave, e, FormOptions{Title: "add work/gitlab"})
		done <- runResult{got, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(scr.String(), "add work/gitlab") {
		if time.Now().After(deadline) {
			t.Fatalf("the form didn't show; screen: %q", scr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return master, scr, done
}

func wait(t *testing.T, done chan runResult) runResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("Run didn't return")
	}
	return runResult{}
}

func TestRunSaves(t *testing.T) {
	master, scr, done := startRun(t, context.Background(), model.Entry{Username: "bob"})
	if _, err := master.Write([]byte("s3cr3t-pw")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := master.Write([]byte{0x13}); err != nil { // ctrl+s
		t.Fatal(err)
	}
	r := wait(t, done)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.e.Password != "s3cr3t-pw" || r.e.Username != "bob" {
		t.Fatalf("result %+v", r.e)
	}
	out := scr.String()
	if strings.Contains(out, "s3cr3t") {
		t.Error("the hidden password reached the terminal")
	}
	if !strings.Contains(out, "\x1b[?1049h") {
		t.Error("the form didn't use the alternate screen")
	}
}

func TestRunCancel(t *testing.T) {
	master, _, done := startRun(t, context.Background(), model.Entry{})
	if _, err := master.Write([]byte{0x03}); err != nil { // ctrl+c, nothing changed
		t.Fatal(err)
	}
	if r := wait(t, done); !errors.Is(r.err, ErrCancelled) {
		t.Fatalf("Run = %v, want ErrCancelled", r.err)
	}
}

func TestRunContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, done := startRun(t, ctx, model.Entry{})
	cancel()
	if r := wait(t, done); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", r.err)
	}
}

func TestRunNeedsTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Run(context.Background(), f, model.Entry{}, FormOptions{}); !errors.Is(err, tty.ErrNoTerminal) {
		t.Fatalf("Run = %v, want ErrNoTerminal", err)
	}
}
