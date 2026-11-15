package session

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fakeVault struct{ closed atomic.Int32 }

func (v *fakeVault) Close() { v.closed.Add(1) }

// world records what a lock did, in order.
type world struct {
	mu      sync.Mutex
	events  []string
	pending bool // a clipboard clear is pending
	agent   bool // an agent is running
	clipErr error
	agErr   error
}

func (w *world) log(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, s)
}

func (w *world) opts(clock *fakeClock, stopAgent bool) Options {
	return Options{
		IdleTTL:   5 * time.Minute,
		StopAgent: stopAgent,
		Now:       clock.Now,
		AgentStopper: func(ctx context.Context) (bool, error) {
			w.log("agent")
			w.mu.Lock()
			defer w.mu.Unlock()
			was := w.agent
			w.agent = false
			return was, w.agErr
		},
		ClipboardClearer: func(ctx context.Context) (bool, error) {
			w.log("clipboard")
			w.mu.Lock()
			defer w.mu.Unlock()
			was := w.pending
			w.pending = false
			return was, w.clipErr
		},
	}
}

func TestIdleTimer(t *testing.T) {
	clock := newClock()
	s := New(Options{IdleTTL: 5 * time.Minute, Now: clock.Now})
	if s.Unlocked() || s.IdleExpired() || s.Remaining() != 0 || !s.Deadline().IsZero() {
		t.Fatal("a new session is not plainly locked")
	}
	s.Touch() // ignored while locked
	v := &fakeVault{}
	s.Unlock(v)
	if !s.Unlocked() || s.Remaining() != 5*time.Minute {
		t.Fatalf("after unlock: unlocked %v, remaining %v", s.Unlocked(), s.Remaining())
	}
	clock.Advance(4*time.Minute + 59*time.Second)
	if s.IdleExpired() || s.Remaining() != time.Second {
		t.Fatalf("expired early: remaining %v", s.Remaining())
	}
	s.Touch() // a key resets the timer
	clock.Advance(4 * time.Minute)
	if s.IdleExpired() || s.Remaining() != time.Minute {
		t.Fatalf("Touch didn't restart the timer: remaining %v", s.Remaining())
	}
	clock.Advance(time.Minute)
	if !s.IdleExpired() || s.Remaining() != 0 {
		t.Fatalf("not expired after the TTL: remaining %v", s.Remaining())
	}
	if want := clock.Now(); !s.Deadline().Equal(want) {
		t.Fatalf("deadline %v, want %v", s.Deadline(), want)
	}
	r := s.Lock(context.Background(), ReasonIdle)
	if !r.Locked || r.Reason != ReasonIdle || v.closed.Load() != 1 {
		t.Fatalf("idle lock: %+v, closed %d", r, v.closed.Load())
	}
	if s.IdleExpired() || s.Unlocked() {
		t.Fatal("still unlocked or expired after the lock")
	}
}

func TestIdleOff(t *testing.T) {
	clock := newClock()
	s := New(Options{Now: clock.Now})
	s.Unlock(&fakeVault{})
	clock.Advance(1000 * time.Hour)
	if s.IdleExpired() || !s.Deadline().IsZero() {
		t.Fatal("idle lock with IdleTTL 0")
	}
}

func TestLockStopsAgentAndClearsClipboard(t *testing.T) {
	clock := newClock()
	w := &world{pending: true, agent: true}
	s := New(w.opts(clock, true))
	v := &fakeVault{}
	s.Unlock(v)
	var hookRan atomic.Int32
	s.OnLock(func() {
		if v.closed.Load() != 1 {
			t.Error("a lock hook ran before the vault was closed")
		}
		hookRan.Add(1)
		w.log("hook")
	})
	s.OnLock(nil) // ignored

	r := s.Lock(context.Background(), ReasonKey)
	want := Report{Reason: ReasonKey, Locked: true, ClipboardCleared: true, AgentStopped: true}
	if r != want {
		t.Fatalf("report %+v, want %+v", r, want)
	}
	if v.closed.Load() != 1 || hookRan.Load() != 1 {
		t.Fatalf("closed %d, hook %d", v.closed.Load(), hookRan.Load())
	}
	if got := w.events; len(got) != 3 || got[0] != "hook" || got[1] != "clipboard" || got[2] != "agent" {
		t.Fatalf("order %v, want hook, clipboard, agent", got)
	}

	// Idempotent: a second lock does nothing.
	r = s.Lock(context.Background(), ReasonExit)
	if r.Locked || v.closed.Load() != 1 || hookRan.Load() != 1 || len(w.events) != 3 {
		t.Fatalf("second lock acted: %+v, events %v", r, w.events)
	}

	// A new unlock: hooks were consumed; nothing pending, no agent.
	v2 := &fakeVault{}
	s.Unlock(v2)
	r = s.Lock(context.Background(), ReasonExit)
	if !r.Locked || r.ClipboardCleared || r.AgentStopped || v2.closed.Load() != 1 || hookRan.Load() != 1 {
		t.Fatalf("second session: %+v, hook %d", r, hookRan.Load())
	}
}

func TestLockKeepsAgentWithoutStopAgent(t *testing.T) {
	w := &world{agent: true}
	s := New(w.opts(newClock(), false))
	s.Unlock(&fakeVault{})
	r := s.Lock(context.Background(), ReasonIdle)
	if r.AgentStopped || !w.agent {
		t.Fatal("the agent was stopped although stop_agent is off")
	}
	for _, e := range w.events {
		if e == "agent" {
			t.Fatal("the agent stopper ran")
		}
	}
}

func TestKeepClipboardOnExit(t *testing.T) {
	w := &world{pending: true, agent: true}
	o := w.opts(newClock(), true)
	o.KeepClipboardOnExit = true
	s := New(o)
	s.Unlock(&fakeVault{})
	r := s.Lock(context.Background(), ReasonExit)
	if r.ClipboardCleared || !w.pending || !r.AgentStopped {
		t.Fatalf("exit: %+v, pending %v", r, w.pending)
	}
	// Every other reason clears at once.
	for _, reason := range []Reason{ReasonKey, ReasonIdle, ReasonSignal} {
		w.pending = true
		s.Unlock(&fakeVault{})
		if r := s.Lock(context.Background(), reason); !r.ClipboardCleared || w.pending {
			t.Fatalf("%v: %+v", reason, r)
		}
	}
}

func TestLockReportsErrors(t *testing.T) {
	w := &world{clipErr: errors.New("clip broken"), agErr: errors.New("agent broken")}
	s := New(w.opts(newClock(), true))
	v := &fakeVault{}
	s.Unlock(v)
	r := s.Lock(nil, ReasonSignal) //nolint:staticcheck // nil ctx is accepted
	if r.ClipboardErr == nil || r.AgentErr == nil || v.closed.Load() != 1 {
		t.Fatalf("errors not reported, or the vault not closed: %+v", r)
	}
}

func TestUnlockReplacesVault(t *testing.T) {
	s := New(Options{})
	a, b := &fakeVault{}, &fakeVault{}
	s.Unlock(a)
	s.Unlock(a)
	if a.closed.Load() != 0 {
		t.Fatal("re-unlocking with the same vault closed it")
	}
	s.Unlock(b)
	if a.closed.Load() != 1 {
		t.Fatal("the replaced vault wasn't closed")
	}
	s.Lock(context.Background(), ReasonExit)
	if b.closed.Load() != 1 {
		t.Fatal("the vault wasn't closed")
	}
}

// A second Lock waits until the first has finished, so a TUI exit never
// overtakes a signal's lock that is still stopping the agent.
func TestConcurrentLocksSerialize(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	var stopped atomic.Bool
	s := New(Options{
		StopAgent: true,
		AgentStopper: func(context.Context) (bool, error) {
			close(entered)
			<-release
			stopped.Store(true)
			return true, nil
		},
	})
	s.Unlock(&fakeVault{})
	go s.Lock(context.Background(), ReasonSignal)
	<-entered
	done := make(chan Report)
	go func() { done <- s.Lock(context.Background(), ReasonExit) }()
	select {
	case <-done:
		t.Fatal("the second Lock returned while the first was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	r := <-done
	if r.Locked || !stopped.Load() {
		t.Fatalf("second lock %+v, agent stopped %v", r, stopped.Load())
	}
}

func TestReasonString(t *testing.T) {
	for _, r := range []Reason{ReasonKey, ReasonExit, ReasonIdle, ReasonSignal, 0} {
		if r.String() == "" {
			t.Errorf("Reason(%d) has no text", r)
		}
	}
}

func TestNotify(t *testing.T) {
	got := make(chan os.Signal, 4)
	stop := Notify(func(s os.Signal) { got <- s })
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != syscall.SIGHUP {
			t.Fatalf("got %v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP not delivered")
	}
	stop()
	stop() // idempotent
	if len(Signals()) != 3 {
		t.Fatal("Signals should be SIGHUP, SIGTERM, SIGINT")
	}
}
