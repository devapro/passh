// Package session holds the TUI's lock state and its rules (spec §5.2).
//
// A Session is unlocked with the opened vault (Unlock) and locks when:
//
//   - the user presses L (ReasonKey);
//   - the TUI exits (ReasonExit);
//   - nothing was typed for session.idle_ttl (ReasonIdle; the TUI checks
//     IdleExpired on its clock tick, and every key calls Touch);
//   - passh receives SIGHUP, SIGTERM or SIGINT (ReasonSignal; see Notify).
//
// Locking (Lock) does, in this order:
//
//  1. drops the vault: its Close wipes the vault key and the decrypted data
//     (best effort, see vault.Vault.Close);
//  2. runs the functions registered with OnLock, e.g. stopping the print
//     page (§7.4: the server stops at a lock);
//  3. clears the clipboard at once if a clear is still pending: S6 promises
//     the clear "if the session is still alive", and a locked TUI drops the
//     session now. With KeepClipboardOnExit, ReasonExit leaves the clear to
//     the caller: the TUI quits like the non-TUI `passh copy`, which waits
//     for the clear (§6.3), so copy, quit, paste still works;
//  4. stops the agent if session.stop_agent is on (§5.2, §5.3), so the next
//     unlock asks for the passphrase again.
//
// The package doesn't know the vault, clipboard or agent types: the TUI
// passes small functions, so the rules are tested without a terminal, a
// clipboard or an agent, with an injected clock.
package session

import (
	"context"
	"sync"
	"time"
)

// Reason says why a session locked.
type Reason int

// The reasons of §5.2.
const (
	ReasonKey    Reason = iota + 1 // the user pressed L
	ReasonExit                     // the TUI exits
	ReasonIdle                     // session.idle_ttl without input
	ReasonSignal                   // SIGHUP, SIGTERM or SIGINT
)

func (r Reason) String() string {
	switch r {
	case ReasonKey:
		return "locked"
	case ReasonExit:
		return "locked on exit"
	case ReasonIdle:
		return "locked after inactivity"
	case ReasonSignal:
		return "locked by a signal"
	}
	return "locked"
}

// Closer is the opened vault: Close drops its key and data.
type Closer interface{ Close() }

// Options configure a Session.
type Options struct {
	// IdleTTL is session.idle_ttl. Zero or less turns the idle lock off
	// (the config never allows that; tests may).
	IdleTTL time.Duration
	// StopAgent is session.stop_agent: a lock also stops the agent.
	StopAgent bool
	// AgentStopper stops the vault's agent. It reports whether an agent was
	// running; no agent is (false, nil). nil means no agent can run.
	AgentStopper func(ctx context.Context) (stopped bool, err error)
	// ClipboardClearer clears the clipboard if a clear is still pending,
	// and reports whether it did. nil means no clipboard.
	ClipboardClearer func(ctx context.Context) (cleared bool, err error)
	// KeepClipboardOnExit: a lock with ReasonExit doesn't clear the
	// clipboard; the caller waits for the pending clear, then clears.
	KeepClipboardOnExit bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Report says what a Lock did.
type Report struct {
	Reason Reason
	// Locked is false when the session was already locked: nothing was
	// done.
	Locked bool
	// ClipboardCleared: a pending clear was done at once.
	ClipboardCleared bool
	ClipboardErr     error
	// AgentStopped: session.stop_agent is on and an agent was stopped.
	AgentStopped bool
	AgentErr     error
}

// Session is the TUI's lock state. Its methods are safe for concurrent use:
// a signal handler may lock while the TUI runs.
type Session struct {
	opts Options

	lockMu sync.Mutex // serializes Lock, so a second Lock waits for the first

	mu       sync.Mutex
	unlocked bool
	vault    Closer
	last     time.Time // last activity
	hooks    []func()
}

// New returns a locked session.
func New(opts Options) *Session {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Session{opts: opts}
}

// Unlock starts a session with the opened vault v and starts the idle
// timer. A session that is already unlocked closes its previous vault
// first, if it is a different one.
func (s *Session) Unlock(v Closer) {
	s.mu.Lock()
	old := s.vault
	s.unlocked, s.vault, s.last = true, v, s.opts.Now()
	s.mu.Unlock()
	if old != nil && old != v {
		old.Close()
	}
}

// Unlocked reports whether the session is unlocked.
func (s *Session) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlocked
}

// Touch records user activity (any key): the idle timer starts again.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unlocked {
		s.last = s.opts.Now()
	}
}

// IdleTTL returns session.idle_ttl.
func (s *Session) IdleTTL() time.Duration { return s.opts.IdleTTL }

// Deadline returns when the session locks for inactivity, the zero time
// when it is locked or the idle lock is off.
func (s *Session) Deadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.unlocked || s.opts.IdleTTL <= 0 {
		return time.Time{}
	}
	return s.last.Add(s.opts.IdleTTL)
}

// Remaining returns the time left before the idle lock: never negative,
// zero when locked, and IdleTTL when the idle lock is off.
func (s *Session) Remaining() time.Duration {
	d := s.Deadline()
	if d.IsZero() {
		if s.Unlocked() {
			return s.opts.IdleTTL
		}
		return 0
	}
	return max(d.Sub(s.opts.Now()), 0)
}

// IdleExpired reports whether the session is unlocked and has been idle
// for IdleTTL: the TUI then locks it with ReasonIdle.
func (s *Session) IdleExpired() bool {
	d := s.Deadline()
	return !d.IsZero() && !s.opts.Now().Before(d)
}

// OnLock registers fn to run once at the next lock, after the vault is
// dropped. Registered on a locked session, it runs at the next lock after
// the next unlock.
func (s *Session) OnLock(fn func()) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = append(s.hooks, fn)
}

// Lock locks the session (see the package documentation for what that
// does). It is idempotent: on a locked session it does nothing and reports
// Locked false. ctx bounds clearing the clipboard and stopping the agent.
func (s *Session) Lock(ctx context.Context, reason Reason) Report {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()

	s.mu.Lock()
	if !s.unlocked {
		s.mu.Unlock()
		return Report{Reason: reason}
	}
	v, hooks := s.vault, s.hooks
	s.unlocked, s.vault, s.hooks, s.last = false, nil, nil, time.Time{}
	s.mu.Unlock()

	r := Report{Reason: reason, Locked: true}
	if v != nil {
		v.Close()
	}
	for _, fn := range hooks {
		fn()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.opts.ClipboardClearer != nil && !(reason == ReasonExit && s.opts.KeepClipboardOnExit) {
		r.ClipboardCleared, r.ClipboardErr = s.opts.ClipboardClearer(ctx)
	}
	if s.opts.StopAgent && s.opts.AgentStopper != nil {
		r.AgentStopped, r.AgentErr = s.opts.AgentStopper(ctx)
	}
	return r
}
