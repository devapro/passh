package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"filippo.io/age"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/vault"
)

// Timings.
const (
	tickEvery = time.Second     // header countdown, idle check, reveal and status expiry
	pollEvery = 2 * time.Second // "vault changed on disk" check (§6.2)
	statusTTL = 8 * time.Second // how long a message stays in the status line
)

// deps are the model's collaborators; Run fills them, tests inject fakes.
type deps struct {
	cfg       *config.Config
	vaultPath string
	open      opener
	agent     Agent
	keySource keys.KeySource
	clip      Clipboard
	clipErr   error         // why there is no clipboard
	print     PrintPage     // nil: the print page of internal/printweb
	startPage startPageFunc // for that default; nil: printweb.Start
	ctx       context.Context
	// now is the clock; nil means time.Now.
	now func() time.Time
	// after schedules msg after d; nil means tea.Tick. Tests record the
	// timers instead of waiting for them.
	after func(d time.Duration, msg tea.Msg) tea.Cmd
}

// Messages.
type (
	tickMsg    struct{}
	pollMsg    struct{}
	hideMsg    struct{ seq int }
	signalMsg  struct{ sig os.Signal }
	ctxDoneMsg struct{}
	askMsg     struct {
		job     *job
		warning string
	}
	unlockedMsg struct {
		gen   int
		v     Vault
		err   error
		via   string // "passphrase", "agent" or "key"
		asker *asker // asks v's questions from now on (reloads)
		data  *model.Data
		info  vault.Info
	}
	reloadedMsg struct {
		gen  int
		err  error
		data *model.Data
		info vault.Info
	}
)

type screen int

const (
	screenLock screen = iota
	screenMain
	screenBye // quitting: nothing is shown
)

type viewKind int

const (
	viewFolders viewKind = iota
	viewTags
	viewSearch // the list while a search is active
	numLists
)

// clipState is the clipboard. Its methods run off the UI goroutine.
type clipState struct {
	c   Clipboard
	err error // why there is no clipboard
	now func() time.Time
}

// clearPending is the session's ClipboardClearer: a value whose clear is
// still pending is cleared at once.
func (cs *clipState) clearPending(ctx context.Context) (bool, error) {
	if cs.c == nil {
		return false, nil
	}
	d, ok := cs.c.Pending()
	return ok && cs.now().Before(d), cs.c.ClearPending(ctx)
}

// status is the message line.
type status struct {
	text   string
	err    bool
	until  time.Time // zero: until replaced
	copied bool      // the clipboard countdown (text is computed)
}

// exitNotes are messages for the terminal after the TUI has ended: what a
// lock on exit couldn't do (review TUI-004). Safe for concurrent use: the
// signal handler adds to them.
type exitNotes struct {
	mu    sync.Mutex
	lines []string
}

func (n *exitNotes) add(s string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lines = append(n.lines, s)
}

// report adds the failures of a lock.
func (n *exitNotes) report(rep session.Report) {
	if rep.ClipboardErr != nil {
		n.add("clearing the clipboard failed: " + rep.ClipboardErr.Error())
	}
	if rep.AgentErr != nil {
		n.add("stopping the agent failed: " + rep.AgentErr.Error())
	}
}

func (n *exitNotes) take() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	l := n.lines
	n.lines = nil
	return l
}

// app is the whole TUI. It is used through a pointer: Update changes it
// in place.
type app struct {
	d     deps
	ctx   context.Context
	now   func() time.Time
	after func(time.Duration, tea.Msg) tea.Cmd
	sess  *session.Session
	clip  *clipState
	warns *warnings
	notes *exitNotes
	// flights are the saves and copies running; a lock waits for them.
	flights *flights
	// jobCtx is the parent of every job's context; abortJobs ends them all
	// from any goroutine (a signal: a reload asking the rollback question
	// holds the vault, which the lock must close).
	jobCtx    context.Context
	abortJobs context.CancelFunc

	w, h   int
	screen screen

	job      *job
	jobGen   int
	saving   *saveOp // the save in flight
	copyGen  int     // the latest copy; older results are dropped
	lockGen  int     // the lock the lock screen waits for
	printGen int     // the latest print page start
	// exitSave is a save that was still running when the TUI quit: Run
	// reports how it ended.
	exitSave *saveOp

	// Run's result: set when the TUI ends with an error.
	exitErr error
	// waitClip: the user quit; Run waits for a pending clipboard clear
	// before it returns, like `passh copy` (§6.3).
	waitClip bool

	lk lockScreen

	// Unlocked state. Everything below is dropped by wipe.
	v Vault
	// asker asks v's questions (a reload's rollback question).
	asker *asker
	// sessCtx ends when the session does (a lock, quitting, a signal):
	// saves stop waiting for other passh processes, a print page still
	// starting stops.
	sessCtx       context.Context
	sessCancel    context.CancelFunc
	data          *model.Data
	entries       []model.Entry  // sorted by path
	tree          *folder        // the Folders view's tree of entries
	byID          map[string]int // index into entries
	tags          []model.TagCount
	view          viewKind // folders or tags
	expanded      map[string]bool
	tagSel        map[string]bool
	search        searchState
	cur           [numLists]cursor
	detail        bool // full-width detail of detailID
	detailID      string
	detailOff     int
	reveal        reveal
	st            status
	copied        copyState
	changedOnDisk bool
	polling       bool   // a check of the vault file runs
	pollErr       string // the check's last failure, shown once
	kept          *kept
	help          bool
	helpOff       int
	form          *editor.Form
	fctx          formCtx
	prompt        *prompt
	confirm       *confirm
	printSetup    *printSetup
	printStarting bool // the print page is being started
	printDlg      PrintDialog
}

type cursor struct {
	key string // row key of the selected row
	idx int    // its index, used when the key is gone
	off int    // first visible row
}

type reveal struct {
	id    string
	until time.Time
	seq   int
}

// newModel makes the model. d.ctx must be set: Run's context, or the
// test's.
func newModel(d deps) *app {
	m := &app{
		d:       d,
		ctx:     d.ctx,
		now:     d.now,
		after:   d.after,
		warns:   &warnings{},
		notes:   &exitNotes{},
		flights: &flights{},
		w:       80,
		h:       24,
	}
	m.jobCtx, m.abortJobs = context.WithCancel(d.ctx)
	if m.now == nil {
		m.now = time.Now
	}
	if m.after == nil {
		m.after = func(dur time.Duration, msg tea.Msg) tea.Cmd {
			return tea.Tick(dur, func(time.Time) tea.Msg { return msg })
		}
	}
	m.clip = &clipState{c: d.clip, err: d.clipErr, now: m.now}
	so := session.Options{
		IdleTTL:          d.cfg.Session.IdleTTL,
		StopAgent:        d.cfg.Session.StopAgent,
		Now:              m.now,
		ClipboardClearer: m.clip.clearPending,
		// q leaves a pending clear to Run, which waits for it; L, idle and
		// signals clear at once.
		KeepClipboardOnExit: true,
	}
	if d.agent != nil {
		so.AgentStopper = d.agent.Stop
	}
	m.sess = session.New(so)
	m.lk = newLockScreen()
	if m.d.print == nil {
		start := d.startPage
		if start == nil {
			start = startPrintweb
		}
		m.d.print = webPrintPage(d.cfg, start, m.now, m.after)
	}
	return m
}

func (m *app) Init() tea.Cmd {
	cmds := []tea.Cmd{m.after(tickEvery, tickMsg{}), m.after(pollEvery, pollMsg{})}
	// Start-up: the key source or the agent, without a key press (§5.1).
	switch {
	case m.d.keySource != nil:
		cmds = append(cmds, m.startUnlock(m.d.keySource, "key"))
	case m.d.agent != nil:
		cmds = append(cmds, m.startUnlock(agentSource{m.d.agent}, "agent"))
	}
	return tea.Batch(cmds...)
}

// agentSource is a keys.KeySource backed by Agent. vault.Open passes the
// key block of the file it is opening, and the agent answers only for the
// key block `passh unlock` opened (agent.KeySource does the same).
type agentSource struct{ a Agent }

func (s agentSource) VaultKey(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	return s.a.KeyFor(ctx, keyBlock)
}

// ChecksKeyBlock implements keys.KeyBlockChecker: the agent gives the key
// only for the key block it was unlocked for, so a data block the key
// doesn't open is damaged, not newer.
func (agentSource) ChecksKeyBlock() bool { return true }

// errRekeyed: Reload needed the key source again because the file was
// rekeyed elsewhere; the typed passphrase is gone by then.
var errRekeyed = errors.New("the vault was rekeyed elsewhere: lock (L) and unlock with its current passphrase")

// onceKey unwraps the key block with a typed passphrase, once.
type onceKey struct {
	mu   sync.Mutex
	pass []byte
	used bool
}

// ChecksKeyBlock implements keys.KeyBlockChecker: the key comes from the
// key block itself.
func (*onceKey) ChecksKeyBlock() bool { return true }

func (o *onceKey) VaultKey(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.used {
		return nil, errRekeyed
	}
	o.used = true
	pass := o.pass
	o.pass = nil
	defer keys.Zero(pass)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return keys.UnwrapKey(keyBlock, pass)
}

// wipe drops a passphrase VaultKey never got to use (the job was cancelled
// first): SEC-1. A later VaultKey fails like a second use.
func (o *onceKey) wipe() {
	o.mu.Lock()
	defer o.mu.Unlock()
	keys.Zero(o.pass)
	o.pass, o.used = nil, true
}

// setStatus shows a message for statusTTL, with the vault's warnings
// (e.g. a backup that couldn't be rotated) after it.
func (m *app) setStatus(text string, isErr bool) {
	m.st = status{text: m.withWarnings(text), err: isErr, until: m.now().Add(statusTTL)}
}

// setStatusSticky shows a message until another replaces it.
func (m *app) setStatusSticky(text string, isErr bool) {
	m.st = status{text: m.withWarnings(text), err: isErr}
}

func (m *app) withWarnings(text string) string {
	if ws := m.warns.take(); len(ws) > 0 {
		return strings.TrimSpace(text + " Warning: " + strings.Join(ws, " "))
	}
	return text
}

// Update handles a message. It never waits for I/O: files, sockets,
// processes and the vault's lock are for commands (see ops.go).
func (m *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = max(msg.Width, 1), max(msg.Height, 1)
		m.sizeForm()
		return m, nil
	case tickMsg:
		return m, m.onTick()
	case pollMsg:
		return m, tea.Batch(m.after(pollEvery, pollMsg{}), m.pollCmd())
	case changedMsg:
		return m, m.onChanged(msg)
	case hideMsg:
		if msg.seq == m.reveal.seq {
			m.reveal = reveal{seq: m.reveal.seq}
		}
		return m, nil
	case signalMsg:
		m.exitErr = &SignalError{Signal: msg.sig}
		return m, m.quit()
	case ctxDoneMsg:
		return m, m.quit()
	case askMsg:
		return m, m.onAsk(msg)
	case unlockedMsg:
		return m, m.onUnlocked(msg)
	case reloadedMsg:
		return m, m.onReloaded(msg)
	case lockedMsg:
		return m, m.onLocked(msg)
	case savedMsg:
		return m, m.onSaved(msg)
	case copiedMsg:
		return m, m.onCopied(msg)
	case printStartedMsg:
		return m, m.onPrintStarted(msg)
	case tea.KeyPressMsg:
		m.sess.Touch()
		switch m.screen {
		case screenLock:
			return m, m.lockKey(msg)
		case screenMain:
			return m, m.mainKey(msg)
		}
		return m, nil
	case tea.PasteMsg:
		m.sess.Touch()
		switch m.screen {
		case screenLock:
			m.lockPaste(msg.Content)
		case screenMain:
			return m, m.mainPaste(msg)
		}
		return m, nil
	}
	// Anything else belongs to an open form or print dialog (their timers
	// and results).
	if m.screen == screenMain {
		switch {
		case m.form != nil:
			return m, m.formUpdate(msg)
		case m.printDlg != nil:
			return m, m.printUpdate(msg)
		}
	}
	return m, nil
}

func (m *app) onTick() tea.Cmd {
	next := m.after(tickEvery, tickMsg{})
	if m.screen != screenMain {
		return next
	}
	if m.sess.IdleExpired() {
		return tea.Batch(next, m.lock(session.ReasonIdle))
	}
	now := m.now()
	if m.reveal.id != "" && !now.Before(m.reveal.until) {
		m.reveal = reveal{seq: m.reveal.seq}
	}
	if !m.st.until.IsZero() && !now.Before(m.st.until) {
		m.st = status{}
	}
	return next
}

// unlocked switches to the main view with the opened vault; data and info
// were read from it by the job that opened it.
func (m *app) unlocked(v Vault, data *model.Data, info vault.Info) {
	m.sess.Unlock(v)
	m.flights.reopen()
	m.sessCtx, m.sessCancel = context.WithCancel(m.jobCtx) // abortJobs ends it too
	m.v = v
	m.screen = screenMain
	m.expanded = map[string]bool{}
	m.tagSel = map[string]bool{}
	m.cur = [numLists]cursor{}
	m.refresh(data)
	m.setStatus(fmt.Sprintf("Unlocked: %d entries, revision %d.", info.Entries, info.Revision), false)
}

// refresh replaces the model's copy of the data, after a save or reload.
func (m *app) refresh(data *model.Data) {
	if data == nil { // closed meanwhile (a signal's lock)
		data = model.NewData()
	}
	m.data = data
	m.entries = m.data.List()
	m.tree = buildTree(m.entries)
	m.byID = make(map[string]int, len(m.entries))
	for i, e := range m.entries {
		m.byID[e.ID] = i
	}
	m.tags = m.data.TagCounts()
	for t := range m.tagSel {
		if !m.hasTag(t) {
			delete(m.tagSel, t)
		}
	}
	if m.search.active {
		m.search.run(m.entries)
	}
	if m.detail {
		if _, ok := m.byID[m.detailID]; !ok {
			m.detail = false
		}
	}
}

func (m *app) hasTag(t string) bool {
	for _, tc := range m.tags {
		if tc.Tag == t {
			return true
		}
	}
	return false
}

func (m *app) entryByID(id string) (model.Entry, bool) {
	i, ok := m.byID[id]
	if !ok {
		return model.Entry{}, false
	}
	return m.entries[i], true
}

// userQuit is q or ctrl+c in the main view: lock and end the program;
// Run then waits for a pending clipboard clear.
func (m *app) userQuit() tea.Cmd {
	m.waitClip = true
	return m.quit()
}

// quit ends the program. The session is locked by Run once the program
// has ended (shutdown), or already by the signal handler.
func (m *app) quit() tea.Cmd {
	if s := m.endSession(); s != nil {
		m.exitSave = s
	}
	m.lk = newLockScreen()
	m.screen = screenBye
	return tea.Quit
}

// endSession ends the session on the UI's side: it stops the running job
// and the print page, cancels the session's context (a save in flight
// stops waiting for other passh processes), takes over that save
// (returned: the caller waits for it and reports it), and wipes what the
// UI holds (the decrypted data and what
// was typed: SEC-1, review TUI-003). Locking the session itself (the
// vault, the clipboard, the agent) is the caller's: lock's command, Run's
// shutdown or the signal handler.
func (m *app) endSession() (save *saveOp) {
	m.cancelJob()
	if m.printDlg != nil {
		m.printDlg.Stop()
	}
	if m.sessCancel != nil {
		m.sessCancel()
	}
	m.printGen++
	save, m.saving = m.saving, nil
	m.copyGen++
	m.lk.pass.Wipe()
	m.wipe()
	return save
}

// shutdown locks the session once the program has ended (§5.2: the TUI
// exits): it ends every job, waits for a save or copy still running,
// locks, and keeps what the user must know for the terminal (notes). Run
// calls it; it may run while a signal's lock is in progress (Lock
// serializes them).
func (m *app) shutdown() {
	m.abortJobs()
	m.flights.close()()
	if s := m.exitSave; s != nil {
		m.exitSave = nil
		m.notes.add(s.lockReport())
	}
	m.notes.report(lockSession(m.ctx, m.sess, session.ReasonExit))
}

// wipe drops the decrypted data and everything derived from it.
func (m *app) wipe() {
	m.v, m.asker = nil, nil
	m.sessCtx, m.sessCancel = nil, nil
	m.data, m.entries, m.tree, m.byID, m.tags = nil, nil, nil, nil, nil
	m.expanded, m.tagSel = nil, nil
	m.search.wipe()
	m.cur = [numLists]cursor{}
	m.detail, m.detailID, m.detailOff = false, "", 0
	m.reveal = reveal{seq: m.reveal.seq + 1}
	m.st = status{}
	m.copied = copyState{}
	m.changedOnDisk, m.polling, m.pollErr = false, false, ""
	m.kept = nil
	m.help, m.helpOff = false, 0
	m.form, m.fctx = nil, formCtx{}
	if m.prompt != nil {
		m.prompt.in.Wipe()
	}
	m.prompt, m.confirm, m.printDlg, m.printSetup = nil, nil, nil, nil
	m.printStarting = false
	m.view = viewFolders
}

// exitLines returns the notes for the terminal after the TUI, escaped
// (S4): an error may carry a path or a tool's message.
func (m *app) exitLines() []string {
	var out []string
	for _, n := range m.notes.take() {
		out = append(out, "passh: "+sanitize.Line(n))
	}
	return out
}

func fmtDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%d min", d/time.Minute)
	}
	return d.Round(time.Second).String()
}
