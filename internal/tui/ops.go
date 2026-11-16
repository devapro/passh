package tui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/vault"
)

// Operations that do I/O run in commands, never in Update (review
// TUI-002): Update starts them and handles their result message, so keys,
// the countdown, L and the idle lock stay responsive while a save fsyncs,
// a clipboard tool runs or the print page binds its listeners.
//
// Update also never calls a method of the vault that takes the vault's
// lock (a save holds it for the whole save): the data it shows comes in the
// operations' result messages.
//
// A lock must not overtake a save or a copy started before it, nor let one
// start after it. flights tracks them; a lock waits for them before it
// closes the vault and clears the clipboard, so a copied value is cleared
// by the lock's clear. A save runs with the session's context, which the
// lock cancels first: a save still waiting for another passh process's
// lock stops at once, and the vault never stops a save once the new file
// is in place, so a save is either not done or complete when the lock goes
// on, and the lock screen (or, after quitting, the terminal) says which.

const (
	// lockTimeout bounds clearing the clipboard and stopping the agent at a
	// lock.
	lockTimeout = 5 * time.Second
	// copyTimeout bounds a copy (a clipboard command that hangs).
	copyTimeout = 15 * time.Second
	// agentCheckTimeout bounds the status request after a lock.
	agentCheckTimeout = 2 * time.Second
)

// Result messages of the operations.
type (
	savedMsg struct {
		op   *saveOp
		data *model.Data // the vault's data after the save; nil on error
	}
	copiedMsg struct {
		gen   int
		what  string // "password", "username"
		path  string
		due   time.Time // when the clear is due
		err   error
		clear bool // the clipboard reports the clear's result (ClearReporter)
	}
	lockedMsg struct {
		gen          int
		reason       session.Reason
		rep          session.Report
		agentRunning bool
		save         *saveOp // the save that was running when the lock came
	}
	changedMsg struct {
		v       Vault
		changed bool
		err     error
	}
	printStartedMsg struct {
		gen int
		dlg PrintDialog
		err error
	}
)

// errLocked: an operation was refused because the session is locking.
var errLocked = i18n.NewError("the session is locked")

// flights are the operations a lock must wait for: saves and copies. Safe
// for concurrent use; the signal handler waits for them too.
type flights struct {
	mu     sync.Mutex
	closed bool
	open   map[*flight]struct{}
}

type flight struct{ done chan struct{} }

// begin registers an operation; ok is false once a lock has begun.
func (f *flights) begin() (fl *flight, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, false
	}
	if f.open == nil {
		f.open = map[*flight]struct{}{}
	}
	fl = &flight{done: make(chan struct{})}
	f.open[fl] = struct{}{}
	return fl, true
}

// end marks fl finished.
func (f *flights) end(fl *flight) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.open, fl)
	close(fl.done)
}

// close refuses new operations and returns a function that waits for the
// running ones. The wait has no bound of its own: each operation is bounded
// (copyTimeout; a save by the vault's lock waits), and the vault's Close
// would wait for a running save anyway.
func (f *flights) close() (wait func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	var running []*flight
	for fl := range f.open {
		running = append(running, fl)
	}
	return func() {
		for _, fl := range running {
			<-fl.done
		}
	}
}

// reopen accepts operations again: a new session.
func (f *flights) reopen() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = false
}

// busy reports whether a job or a save runs: changes wait for it.
func (m *app) busy() bool { return m.job != nil || m.saving != nil }

func (m *app) setBusyStatus() {
	switch {
	case m.saving != nil:
		m.setStatus(m.d.p.T("Busy: wait for the save to finish."), true)
	case m.job != nil:
		m.setStatus(m.d.p.T("Busy: wait for the reload to finish."), true)
	default:
		m.setStatus(m.d.p.T("Busy: the print page is starting."), true)
	}
}

// Saves.

// saveOp is a change to the vault, saved in a command (§4.6: a lock, a
// change check, fsync, a read-back, a rename).
type saveOp struct {
	what string // the entry, for messages
	// run makes the change on the command's goroutine and returns the
	// message for success ("Saved work/github.").
	run func(ctx context.Context, v Vault) (string, error)
	// done handles the result in Update; the data is refreshed already.
	done func(m *app, text string, err error)
	// refused keeps the user's input when the vault changed on disk.
	refused func(m *app)

	// The result, set before the flight ends: the lock reads it when the
	// save ran into a lock.
	text string
	err  error
}

// lockReport is what the lock screen says about a save the lock waited
// for, in p's language: it was done, or it wasn't.
func (op *saveOp) lockReport(p i18n.Printer) string {
	switch {
	case op.err == nil:
		return op.text
	case errors.Is(op.err, context.Canceled):
		return p.T("Not saved (%s): the lock came before it was written.", op.what)
	case errors.Is(op.err, vault.ErrChanged):
		return p.T("Not saved (%s): the vault changed on disk.", op.what)
	}
	return p.T("Not saved (%s): %v", op.what, op.err)
}

// save runs op in a command, with the session's context (a lock or quit
// ends the save's waits for other passh processes). The vault file is
// checked first: if it changed on disk, nothing is saved and op.refused
// keeps the input (§6.2: saving is blocked until a reload).
func (m *app) save(op *saveOp) tea.Cmd {
	fl, ok := m.flights.begin()
	if !ok {
		return nil // locking: Update is on the lock screen by now
	}
	fls, v, ctx := m.flights, m.v, m.sessCtx
	m.saving = op
	m.setStatusSticky(m.d.p.T("Saving…"), false)
	return func() tea.Msg {
		defer fls.end(fl)
		msg := savedMsg{op: op}
		changed, err := v.Changed()
		switch {
		case err == nil && changed:
			op.err = vault.ErrChanged
		default:
			// A failed check (err != nil) is left to the save, which checks
			// the file again under its lock (§4.6 step 2).
			op.text, op.err = op.run(ctx, v)
		}
		if op.err == nil {
			msg.data = v.Snapshot()
		}
		return msg
	}
}

func (m *app) onSaved(msg savedMsg) tea.Cmd {
	op := msg.op
	if op != m.saving {
		return nil // a lock took it over and reports it
	}
	m.saving = nil
	m.st = status{}
	if msg.data != nil {
		m.refresh(msg.data)
	}
	if errors.Is(op.err, vault.ErrChanged) {
		m.changedOnDisk = true
		op.refused(m)
		return nil
	}
	op.done(m, op.text, op.err)
	return nil
}

// Copies.

// copyValue copies value in a command (§6.3); field and path are for the
// messages.
func (m *app) copyValue(value, field, path string) tea.Cmd {
	fl, ok := m.flights.begin()
	if !ok {
		return nil
	}
	m.copyGen++
	gen := m.copyGen
	fls, c, ctx, d := m.flights, m.clip.c, m.ctx, m.d.cfg.Clipboard.ClearAfter
	_, reports := c.(ClearReporter)
	m.st = status{text: m.d.p.T("Copying…")}
	return func() tea.Msg {
		defer fls.end(fl)
		cctx, cancel := context.WithTimeout(ctx, copyTimeout)
		defer cancel()
		msg := copiedMsg{gen: gen, what: field, path: path, clear: reports}
		if msg.err = c.CopyFor(cctx, value, d); msg.err == nil {
			msg.due, _ = c.Pending() // on this goroutine: Pending waits for the clipboard's lock
		}
		return msg
	}
}

func (m *app) onCopied(msg copiedMsg) tea.Cmd {
	if msg.gen != m.copyGen || m.screen != screenMain {
		return nil // a newer copy, or locked: the lock cleared it
	}
	if msg.err != nil {
		m.setStatusSticky(m.d.p.T("Not copied: %v", clipboard.WithHint(msg.err, msg.path, msg.what)), true)
		return nil
	}
	m.copied = copyState{what: msg.what, due: msg.due, reports: msg.clear}
	m.st = status{copied: true}
	return nil
}

// copyState is what was copied last, for the status line's countdown.
type copyState struct {
	what    string
	due     time.Time
	reports bool // the clipboard tells how its clear went
}

// clearText is the status line after a copy (S6): the countdown, then
// whether the clear worked. It never says "cleared" for a clear that failed
// or hasn't happened (review TUI-004).
func (m *app) clearText() (string, bool) {
	left := m.copied.due.Sub(m.now())
	var done bool
	var err error
	if cr, ok := m.clip.c.(ClearReporter); ok && m.copied.reports {
		done, err = cr.ClearResult()
	} else {
		done = left <= 0
	}
	p := m.d.p
	switch {
	case done && err != nil: // clipboard.ErrClearFailed from NewClipboard's; any error counts
		return p.T("Clearing the clipboard failed: %v", err), true
	case done:
		return p.T("Clipboard cleared."), false
	case left <= 0:
		return p.T("Clearing the clipboard…"), false
	}
	secs := int((left + time.Second - 1) / time.Second)
	switch m.copied.what {
	case model.FieldPassword:
		return p.T("Password copied · clears in %d s (L clears it now)", secs), false
	case model.FieldUsername:
		return p.T("Username copied · clears in %d s (L clears it now)", secs), false
	}
	return p.T("%s copied · clears in %d s (L clears it now)", capitalize(m.copied.what), secs), false
}

// The lock.

// lock locks the session (§5.2): L and the idle lock. The UI's copies are
// wiped at once and the lock screen shows; the vault's wipe, the clipboard
// clear and the agent stop run in a command after any save or copy that
// started before the lock (lockedMsg reports them).
func (m *app) lock(reason session.Reason) tea.Cmd {
	save := m.endSession()
	wait := m.flights.close()
	m.screen = screenLock
	m.lk = newLockScreen()
	m.lk.busy, m.lk.busyText = true, m.d.p.T("locking…")
	if save != nil {
		m.lk.busyText = m.d.p.T("locking: the change to %s is still being saved…", save.what)
	}
	m.lockGen++
	gen := m.lockGen
	ctx, sess, a := m.ctx, m.sess, m.d.agent
	checkAgent := a != nil && m.d.keySource == nil && (reason == session.ReasonKey || reason == session.ReasonIdle)
	return func() tea.Msg {
		wait()
		msg := lockedMsg{gen: gen, reason: reason, save: save}
		msg.rep = lockSession(ctx, sess, reason)
		if checkAgent {
			msg.agentRunning = agentRunning(ctx, a)
		}
		return msg
	}
}

func (m *app) onLocked(msg lockedMsg) tea.Cmd {
	if msg.gen != m.lockGen || m.screen != screenLock {
		return nil
	}
	m.lk.busy = false
	p := m.d.p
	var parts []string
	isErr := false
	if s := msg.save; s != nil {
		parts = append(parts, s.lockReport(p))
		isErr = s.err != nil
	}
	switch msg.reason {
	case session.ReasonIdle:
		parts = append(parts, p.T("Locked after %s without input.", fmtDuration(p, m.sess.IdleTTL())))
	default:
		parts = append(parts, p.T("Locked."))
	}
	rep := msg.rep
	if rep.ClipboardCleared {
		parts = append(parts, p.T("Clipboard cleared."))
	}
	if rep.ClipboardErr != nil {
		parts = append(parts, p.T("Clearing the clipboard failed: %v.", rep.ClipboardErr))
		isErr = true
	}
	if rep.AgentStopped {
		parts = append(parts, p.T("Agent stopped."))
	}
	if rep.AgentErr != nil {
		parts = append(parts, p.T("Stopping the agent failed: %v.", rep.AgentErr))
		isErr = true
	}
	m.lk.setMsg(strings.Join(parts, " "), isErr)
	if msg.reason == session.ReasonKey || msg.reason == session.ReasonIdle {
		m.lk.agentHint = m.d.keySource != nil || msg.agentRunning
	}
	return nil
}

// lockSession locks s. It may run because ctx ended (Run's context), and
// the clipboard must still be cleared and the agent stopped then: they get
// ctx without its cancellation, bounded by lockTimeout (CONC-2).
func lockSession(ctx context.Context, s *session.Session, r session.Reason) session.Report {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockTimeout)
	defer cancel()
	return s.Lock(ctx, r)
}

// agentRunning asks whether an agent runs (a status request).
func agentRunning(ctx context.Context, a Agent) bool {
	ctx, cancel := context.WithTimeout(ctx, agentCheckTimeout)
	defer cancel()
	return a.Running(ctx)
}

// The vault-file check (§6.2: "vault changed on disk").

// pollCmd checks whether the vault file changed on disk, in a command.
func (m *app) pollCmd() tea.Cmd {
	if m.screen != screenMain || m.v == nil || m.changedOnDisk || m.busy() || m.polling {
		return nil
	}
	m.polling = true
	v := m.v
	return func() tea.Msg {
		changed, err := v.Changed()
		return changedMsg{v: v, changed: changed, err: err}
	}
}

func (m *app) onChanged(msg changedMsg) tea.Cmd {
	if msg.v != m.v {
		return nil // locked meanwhile
	}
	m.polling = false
	switch {
	case msg.err == nil:
		m.pollErr = ""
		if msg.changed {
			m.changedOnDisk = true
		}
	case errors.Is(msg.err, vault.ErrClosed):
	default:
		// Shown once, not every 2 s. Saving isn't blocked: each save checks
		// the file again under its lock (§4.6 step 2) and refuses then.
		if text := m.d.p.T("Checking the vault file failed: %v", msg.err); text != m.pollErr {
			m.pollErr = text
			m.setStatus(text, true)
		}
	}
	return nil
}

// The print page (§7.4).

// startPrint starts the print page in a command: building the sheet,
// making or loading the certificate and binding the listeners.
func (m *app) startPrint(sheet print.Options) tea.Cmd {
	if m.v == nil || m.data == nil {
		return nil
	}
	m.printGen++
	gen := m.printGen
	m.printStarting = true
	req := PrintRequest{Data: m.data.Clone(), Sheet: sheet, Copy: m.printCopy()}
	ctx, start := m.sessCtx, m.d.print
	m.setStatusSticky(m.d.p.T("Starting the print page…"), false)
	return func() tea.Msg {
		dlg, err := start(ctx, req)
		return printStartedMsg{gen: gen, dlg: dlg, err: err}
	}
}

func (m *app) onPrintStarted(msg printStartedMsg) tea.Cmd {
	if msg.gen != m.printGen || m.screen != screenMain {
		if msg.dlg != nil {
			msg.dlg.Stop() // started for a session that has ended
		}
		return nil
	}
	m.printStarting = false
	if msg.err != nil {
		m.setStatusSticky(m.d.p.T("Print page: %v", msg.err), true)
		return nil
	}
	m.st = status{}
	m.printDlg = msg.dlg
	m.sess.OnLock(msg.dlg.Stop) // a lock from the signal handler stops it too
	return msg.dlg.Init()
}

// printCopy is PrintRequest.Copy: the dialog calls it from a command. It
// copies with the TUI's clipboard, cleared after clipboard.clear_after like
// a password, and is refused once a lock has begun.
func (m *app) printCopy() func(string) error {
	c, cerr, fls, ctx, d := m.clip.c, m.clip.err, m.flights, m.sessCtx, m.d.cfg.Clipboard.ClearAfter
	return func(value string) error {
		if c == nil {
			if cerr != nil {
				return cerr
			}
			return clipboard.ErrNoClipboard
		}
		fl, ok := fls.begin()
		if !ok {
			return errLocked
		}
		defer fls.end(fl)
		cctx, cancel := context.WithTimeout(ctx, copyTimeout)
		defer cancel()
		return c.CopyFor(cctx, value, d)
	}
}
