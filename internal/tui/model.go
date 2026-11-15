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

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
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
	tickMsg     struct{}
	pollMsg     struct{}
	hideMsg     struct{ seq int }
	signalMsg   struct{ sig os.Signal }
	ctxDoneMsg  struct{}
	askMsg      struct{ warning string }
	unlockedMsg struct {
		gen int
		v   Vault
		err error
		via string // "passphrase", "agent" or "key"
	}
	reloadedMsg struct {
		gen int
		err error
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

// job is a background operation that may ask the rollback question:
// opening (scrypt takes seconds) or reloading the vault.
type job struct {
	gen    int
	kind   string // "unlock" or "reload"
	cancel context.CancelFunc
}

// bridge carries the rollback question (§4.10) from a job's goroutine to
// the UI and the answer back. Jobs run one at a time.
type bridge struct {
	events  chan tea.Msg
	answers chan bool
	mu      sync.Mutex
	ctx     context.Context    // the running job's
	cancel  context.CancelFunc // cancels it
}

func newBridge() *bridge {
	return &bridge{events: make(chan tea.Msg, 8), answers: make(chan bool, 1), ctx: context.Background(), cancel: func() {}}
}

func (b *bridge) jobContext() context.Context {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ctx
}

func (b *bridge) setJob(ctx context.Context, cancel context.CancelFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ctx, b.cancel = ctx, cancel
}

// abort cancels the running job from any goroutine, so a pending question
// returns at once. A reload holds the vault busy while it asks; a lock from
// a signal handler would otherwise wait for an answer nobody gives.
func (b *bridge) abort() {
	b.mu.Lock()
	cancel := b.cancel
	b.mu.Unlock()
	cancel()
}

// prompt is vault.Options.Prompt: it runs on the job's goroutine.
func (b *bridge) prompt(warning string) (bool, error) {
	ctx := b.jobContext()
	select {
	case b.events <- askMsg{warning}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	select {
	case a := <-b.answers:
		return a, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// answer sends the user's answer, replacing a stale one.
func (b *bridge) answer(yes bool) {
	select {
	case <-b.answers:
	default:
	}
	b.answers <- yes
}

func (b *bridge) wait() tea.Msg { return <-b.events }

// warnings collects vault warnings from any goroutine.
type warnings struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnings) add(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, s)
}

func (w *warnings) take() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.msgs
	w.msgs = nil
	return m
}

// clipState is the clipboard and what was copied last.
type clipState struct {
	c   Clipboard
	err error // why there is no clipboard
	now func() time.Time

	mu   sync.Mutex
	what string // "password", "username" or "URL"
}

func (cs *clipState) copy(ctx context.Context, value, what string, d time.Duration) error {
	if err := cs.c.CopyFor(ctx, value, d); err != nil {
		return err
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.what = what
	return nil
}

// pending returns what was copied and the time left before its clear.
func (cs *clipState) pending() (what string, left time.Duration, ok bool) {
	if cs.c == nil {
		return "", 0, false
	}
	d, ok := cs.c.Pending()
	if !ok {
		return "", 0, false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.what, d.Sub(cs.now()), true
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

// app is the whole TUI. It is used through a pointer: Update changes it
// in place.
type app struct {
	d     deps
	ctx   context.Context
	now   func() time.Time
	after func(time.Duration, tea.Msg) tea.Cmd
	sess  *session.Session
	clip  *clipState
	br    *bridge
	warns *warnings

	w, h   int
	screen screen

	job    *job
	jobGen int

	// Run's result: set when the TUI ends with an error.
	exitErr error
	// waitClip: the user quit; Run waits for a pending clipboard clear
	// before it returns, like `passh copy` (§6.3).
	waitClip bool

	lk lockScreen

	// Unlocked state. Everything below is dropped by wipe.
	v             Vault
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
	changedOnDisk bool
	kept          *kept
	help          bool
	helpOff       int
	form          *editor.Form
	fctx          formCtx
	prompt        *prompt
	confirm       *confirm
	printSetup    *printSetup
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

func newModel(d deps) *app {
	if d.ctx == nil {
		d.ctx = context.Background()
	}
	m := &app{
		d:     d,
		ctx:   d.ctx,
		now:   d.now,
		after: d.after,
		br:    newBridge(),
		warns: &warnings{},
		w:     80,
		h:     24,
	}
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

// startJob runs fn in the background and returns the command that
// delivers its messages (a question, then its result).
func (m *app) startJob(kind string, fn func(ctx context.Context, gen int) tea.Msg) tea.Cmd {
	m.jobGen++
	gen := m.jobGen
	ctx, cancel := context.WithCancel(m.ctx)
	m.job = &job{gen: gen, kind: kind, cancel: cancel}
	m.br.setJob(ctx, cancel)
	events := m.br.events
	return func() tea.Msg {
		go func() { events <- fn(ctx, gen) }()
		return <-events
	}
}

// cancelJob stops waiting for a running job. Its result still arrives and
// is dropped (an opened vault is closed).
func (m *app) cancelJob() {
	if m.job == nil {
		return
	}
	m.job.cancel()
	m.br.answer(false)
}

func (m *app) startUnlock(ks keys.KeySource, via string) tea.Cmd {
	m.lk.busy = true
	m.lk.msg, m.lk.msgErr = "", false
	switch via {
	case "agent":
		m.lk.busyText = "asking the agent…"
	case "key":
		m.lk.busyText = "opening the vault…"
	default:
		m.lk.busyText = "unlocking… (this takes a few seconds on small devices)"
	}
	open, prompt, warn := m.d.open, m.br.prompt, m.warns.add
	return m.startJob("unlock", func(ctx context.Context, gen int) tea.Msg {
		v, err := open(ctx, ks, prompt, warn)
		if err == nil && ctx.Err() != nil {
			v.Close() // nobody waits for it any more
			v, err = nil, ctx.Err()
		}
		return unlockedMsg{gen: gen, v: v, err: err, via: via}
	})
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

// Update handles a message.
func (m *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = max(msg.Width, 1), max(msg.Height, 1)
		m.sizeForm()
		return m, nil
	case tickMsg:
		return m, m.onTick()
	case pollMsg:
		m.poll()
		return m, m.after(pollEvery, pollMsg{})
	case hideMsg:
		if msg.seq == m.reveal.seq {
			m.reveal = reveal{seq: m.reveal.seq}
		}
		return m, nil
	case signalMsg:
		m.exitErr = &SignalError{Signal: msg.sig}
		return m, m.quit(session.ReasonSignal)
	case ctxDoneMsg:
		return m, m.quit(session.ReasonExit)
	case askMsg:
		return m, m.onAsk(msg)
	case unlockedMsg:
		return m, m.onUnlocked(msg)
	case reloadedMsg:
		return m, m.onReloaded(msg)
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
	// Anything else belongs to an open form or print dialog (their timers).
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
		m.lock(session.ReasonIdle)
		return next
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

// poll checks whether the vault file changed on disk (§6.2).
func (m *app) poll() {
	if m.screen != screenMain || m.v == nil || m.changedOnDisk || m.job != nil {
		return
	}
	if changed, err := m.v.Changed(); err == nil && changed {
		m.changedOnDisk = true
	}
}

// blocked checks the file again before a save and reports whether saving
// is blocked until a reload.
func (m *app) blocked() bool {
	if m.changedOnDisk {
		return true
	}
	if changed, err := m.v.Changed(); err == nil && changed {
		m.changedOnDisk = true
	}
	return m.changedOnDisk
}

func (m *app) onAsk(msg askMsg) tea.Cmd {
	if m.job == nil {
		m.br.answer(false)
		return m.br.wait
	}
	switch m.screen {
	case screenLock:
		m.lk.ask = msg.warning
	case screenMain:
		m.confirm = &confirm{kind: confirmRollback, text: msg.warning}
	default:
		m.br.answer(false)
	}
	return m.br.wait
}

// answerAsk answers the rollback question. The command that delivers the
// job's result is already waiting (onAsk returned it), so none is needed.
func (m *app) answerAsk(yes bool) tea.Cmd {
	m.br.answer(yes)
	return nil
}

func (m *app) onUnlocked(msg unlockedMsg) tea.Cmd {
	if m.job == nil || msg.gen != m.job.gen {
		if msg.v != nil {
			msg.v.Close()
		}
		return nil
	}
	m.job = nil
	m.lk.busy, m.lk.ask = false, ""
	if m.screen != screenLock {
		if msg.v != nil {
			msg.v.Close()
		}
		return nil
	}
	err := msg.err
	switch {
	case err == nil:
		m.lk.pass.Wipe()
		m.unlocked(msg.v)
		return nil
	case errors.Is(err, vault.ErrRollbackDeclined):
		m.exitErr = err
		return m.quit(session.ReasonExit)
	case errors.Is(err, context.Canceled):
		return nil
	case errors.Is(err, vault.ErrDataDamaged) && !errors.Is(err, keys.ErrKeyMismatch):
		// The key fits the key block, the data block doesn't open: no
		// passphrase helps (§4.5). The message lists the backups.
		m.lk.damaged = true
		m.lk.setMsg(err.Error(), true)
		return nil
	case errors.Is(err, agent.ErrKeyBlockChanged):
		m.lk.agentHint = false
		m.lk.setMsg("The agent was unlocked for another key block (the passphrase was changed?): enter the passphrase.", false)
		return nil
	case errors.Is(err, agent.ErrNoAgent):
		m.lk.agentHint = false
		return nil
	case errors.Is(err, keys.ErrKeyMismatch):
		// A key from a source that doesn't check the key block (a paper
		// key given as Options.KeySource) for another or older vault key.
		m.lk.agentHint = false
		m.lk.setMsg("That key doesn't open this vault (rekeyed?): enter the passphrase.", true)
	case errors.Is(err, vault.ErrWrongPassphrase):
		m.lk.setMsg("Wrong passphrase, or the key block is damaged. Try again.", true)
	case msg.via == "agent":
		m.lk.agentHint = false
		m.lk.setMsg("The agent didn't give the key ("+err.Error()+"): enter the passphrase.", true)
	default:
		m.lk.setMsg(err.Error(), true)
	}
	return nil
}

// unlocked switches to the main view with the opened vault.
func (m *app) unlocked(v Vault) {
	m.sess.Unlock(v)
	m.v = v
	m.screen = screenMain
	m.expanded = map[string]bool{}
	m.tagSel = map[string]bool{}
	m.cur = [numLists]cursor{}
	m.refresh()
	info := v.Info()
	m.setStatus(fmt.Sprintf("Unlocked: %d entries, revision %d.", info.Entries, info.Revision), false)
}

// refresh reloads the model's copy of the data after a save or reload.
func (m *app) refresh() {
	m.data = m.v.Snapshot()
	if m.data == nil { // closed meanwhile (a signal's lock)
		m.data = model.NewData()
	}
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

// lock locks the session (§5.2) and wipes the UI's own copies.
func (m *app) lock(reason session.Reason) {
	m.cancelJob()
	if m.printDlg != nil {
		m.printDlg.Stop()
	}
	rep := lockSession(m.sess, reason)
	m.wipe()
	m.screen = screenLock
	m.lk = newLockScreen()
	var parts []string
	switch reason {
	case session.ReasonIdle:
		parts = append(parts, fmt.Sprintf("Locked after %s without input.", fmtDuration(m.sess.IdleTTL())))
	default:
		parts = append(parts, "Locked.")
	}
	if rep.ClipboardCleared {
		parts = append(parts, "Clipboard cleared.")
	}
	if rep.ClipboardErr != nil {
		parts = append(parts, "Clearing the clipboard failed: "+rep.ClipboardErr.Error()+".")
	}
	if rep.AgentStopped {
		parts = append(parts, "Agent stopped.")
	}
	if rep.AgentErr != nil {
		parts = append(parts, "Stopping the agent failed: "+rep.AgentErr.Error()+".")
	}
	m.lk.setMsg(strings.Join(parts, " "), false)
	if reason == session.ReasonKey || reason == session.ReasonIdle {
		m.lk.agentHint = m.d.keySource != nil || (m.d.agent != nil && m.agentRunning())
	}
}

func (m *app) agentRunning() bool {
	ctx, cancel := context.WithTimeout(m.ctx, 2*time.Second)
	defer cancel()
	return m.d.agent.Running(ctx)
}

// userQuit is q or ctrl+c in the main view: lock and end the program;
// Run then waits for a pending clipboard clear.
func (m *app) userQuit() tea.Cmd {
	m.waitClip = true
	return m.quit(session.ReasonExit)
}

// quit locks and ends the program.
func (m *app) quit(reason session.Reason) tea.Cmd {
	m.lock(reason)
	m.lk.pass.Wipe()
	m.screen = screenBye
	return tea.Quit
}

// wipe drops the decrypted data and everything derived from it.
func (m *app) wipe() {
	m.v = nil
	m.data, m.entries, m.tree, m.byID, m.tags = nil, nil, nil, nil, nil
	m.expanded, m.tagSel = nil, nil
	m.search.wipe()
	m.cur = [numLists]cursor{}
	m.detail, m.detailID, m.detailOff = false, "", 0
	m.reveal = reveal{seq: m.reveal.seq + 1}
	m.st = status{}
	m.changedOnDisk = false
	m.kept = nil
	m.help, m.helpOff = false, 0
	m.form, m.fctx = nil, formCtx{}
	if m.prompt != nil {
		m.prompt.in.Wipe()
	}
	m.prompt, m.confirm, m.printDlg, m.printSetup = nil, nil, nil, nil
	m.view = viewFolders
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
