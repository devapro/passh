// Package tui is passh's terminal user interface (spec §6.2): `passh` with
// no arguments.
//
// It starts on the lock screen, which takes the vault key from the agent
// if one runs for the vault, else asks for the passphrase (§5.1, §6.2). The
// main view browses the vault by folder or by tag, searches it, shows an
// entry with its secrets masked (S5), copies to the clipboard with a timed
// clear (§6.3, S6) and edits, adds, moves, tags and deletes entries, each
// change saved at once (§4.6). The TUI locks by the rules of §5.2; the lock
// itself is internal/session.
//
// Every value from the vault is rendered through internal/sanitize (S4):
// an escape sequence in an entry shows as text such as \x1b]52;…, it never
// reaches the terminal. View escapes the whole frame once more, keeping
// only the TUI's own styling, so a value that missed its sanitize call
// can't drive the terminal either.
//
// Update never blocks: saves, copies, the lock's clipboard clear and agent
// stop, the vault-file check and the print page's start run in commands
// whose results come back as messages (ops.go). The rollback question of
// an unlock or reload travels on channels of its own job (jobs.go).
//
// Secrets typed into the TUI (the passphrase) are wiped from the input
// widget when they are submitted, deleted, or the TUI locks or quits. That
// is the part the TUI owns. Bubble Tea delivers each key as a string, and
// the terminal reader's buffers are out of reach: those copies are left to
// the garbage collector (best effort, as ADR-4 says).
//
// The model talks to the vault, the clipboard, the agent and the print page
// through the small interfaces below, so tests drive it with a real vault
// in a temporary folder, a fake clipboard and a fake clock.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"filippo.io/age"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/tty"
	"github.com/devapro/passh/internal/vault"
)

// Vault is what the TUI needs of an opened vault. *vault.Vault implements
// it. The TUI calls the methods that read the file or save from commands,
// never from Update: a save holds the vault's lock while it runs.
type Vault interface {
	Snapshot() *model.Data
	Add(e model.Entry, overwrite bool) (model.Entry, error)
	Update(e model.Entry) (changed bool, err error)
	Move(src, dst paths.Path) error
	Remove(p paths.Path) error
	EditTags(p paths.Path, add, remove []string) (model.Entry, bool, error)
	// The …Context variants end their waits for another passh process's
	// locks when ctx ends; the TUI saves with them.
	AddContext(ctx context.Context, e model.Entry, overwrite bool) (model.Entry, error)
	UpdateContext(ctx context.Context, e model.Entry) (changed bool, err error)
	MoveContext(ctx context.Context, src, dst paths.Path) error
	RemoveContext(ctx context.Context, p paths.Path) error
	EditTagsContext(ctx context.Context, p paths.Path, add, remove []string) (model.Entry, bool, error)
	Changed() (bool, error)
	Reload(ctx context.Context) error
	Info() vault.Info
	Close()
}

var _ Vault = (*vault.Vault)(nil)

// Clipboard copies with a timed clear. NewClipboard adapts the
// internal/clipboard package; tests use a fake. The TUI calls its methods
// from commands, never from Update: a copy or clear may run a clipboard
// tool, and Pending may wait for it.
type Clipboard interface {
	// CopyFor copies value and schedules a clear after clearAfter. A later
	// copy replaces the schedule.
	CopyFor(ctx context.Context, value string, clearAfter time.Duration) error
	// ClearPending clears at once if a clear is scheduled.
	ClearPending(ctx context.Context) error
	// Pending returns when the scheduled clear is due; false when none is.
	Pending() (time.Time, bool)
}

// ClearReporter is implemented by a Clipboard that can tell how the timed
// clear of its last copy went; NewClipboard's does. Without it the TUI
// takes a clear as done when it is due.
type ClearReporter interface {
	// ClearResult reports whether the clear scheduled by the last CopyFor
	// has happened (done) and, if so, its error. It must not block: the
	// TUI calls it while drawing.
	ClearResult() (done bool, err error)
}

// NewClipboard adapts c to Clipboard; the result is a ClearReporter too.
func NewClipboard(c *clipboard.Clipboard) Clipboard { return &clipAdapter{c: c} }

type clipAdapter struct {
	c *clipboard.Clipboard

	mu   sync.Mutex
	last *clipboard.Pending // the last copy's scheduled clear
}

func (a *clipAdapter) CopyFor(ctx context.Context, v string, d time.Duration) error {
	p, err := a.c.CopyFor(ctx, v, d)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = p // nil after a failed copy: nothing is scheduled
	return err
}

func (a *clipAdapter) ClearPending(ctx context.Context) error { return a.c.ClearPending(ctx) }

func (a *clipAdapter) Pending() (time.Time, bool) { return a.c.Pending() }

// ClearResult implements ClearReporter from the last copy's
// clipboard.Pending, whose Done and Err don't wait for the clipboard.
func (a *clipAdapter) ClearResult() (bool, error) {
	a.mu.Lock()
	p := a.last
	a.mu.Unlock()
	if p == nil {
		return true, nil
	}
	select {
	case <-p.Done():
		return true, p.Err()
	default:
		return false, nil
	}
}

// Agent is the agent of the vault, as the TUI uses it. NewAgent adapts
// agent.Client; the TUI never starts an agent (§5.3).
type Agent interface {
	// KeyFor returns the vault key if the agent was unlocked for keyBlock,
	// the key block of the vault file as the TUI opens it. An agent
	// unlocked for another key block (a passwd elsewhere, a damaged or
	// replaced key block) answers agent.ErrKeyBlockChanged, and with no
	// agent it is agent.ErrNoAgent (ErrKeyBlockChanged matches that too):
	// the TUI then asks for the passphrase, which checks the key block
	// before any save copies it.
	KeyFor(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error)
	// Running reports whether an agent runs (a status request, which
	// doesn't count as use).
	Running(ctx context.Context) bool
	// Stop stops the agent and reports whether one was running.
	Stop(ctx context.Context) (stopped bool, err error)
}

// NewAgent adapts an agent client to Agent.
func NewAgent(c *agent.Client) Agent { return agentAdapter{c} }

type agentAdapter struct{ c *agent.Client }

func (a agentAdapter) KeyFor(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	return a.c.KeyFor(ctx, keyBlock)
}

func (a agentAdapter) Running(ctx context.Context) bool {
	_, err := a.c.Status(ctx)
	return err == nil
}

func (a agentAdapter) Stop(ctx context.Context) (bool, error) {
	_, err := a.c.Stop(ctx)
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// PrintPage starts the print page of §7.4 from the TUI's P key. The
// default (Options.PrintPage nil) serves the password sheet of the whole
// vault with internal/printweb; another PrintPage replaces it.
//
// The TUI checks print_web.enabled, lets the user choose the entries and
// fields (PrintRequest.Sheet) and type PRINT, then calls PrintPage with a
// snapshot of the vault. The dialog it returns
// (URLs, QR code, fingerprint, countdown; c copies the URL) is drawn full
// screen until Done; the TUI calls Stop when it locks or exits, which must
// stop the server (§7.4: "a lock" and "passh exiting").
type PrintPage func(ctx context.Context, req PrintRequest) (PrintDialog, error)

// PrintRequest is what the print page gets.
type PrintRequest struct {
	// Data is a deep copy of the vault; the dialog drops it when it stops.
	Data *model.Data
	// Sheet is what the user chose to print in the setup step: Folder or
	// Tags (or neither: every entry) and Fields. Date is left zero.
	Sheet print.Options
	// Copy copies a value (the URL) with the TUI's clipboard, cleared after
	// clipboard.clear_after like a password.
	Copy func(value string) error
}

// PrintDialog is the print page's dialog, hosted by the TUI. Its Update gets
// every key and every message the TUI doesn't handle itself while it is
// open; View renders it in the given size, already escaped (S4).
type PrintDialog interface {
	Init() tea.Cmd
	Update(msg tea.Msg) tea.Cmd
	View(width, height int) string
	// Done reports that the dialog is closed (Esc) or the server stopped.
	Done() bool
	// Stop stops the server at once; it is idempotent.
	Stop()
}

// Options configure Run.
type Options struct {
	// Config is the loaded config: session, clipboard, backup, rollback and
	// print_web settings. Required.
	Config *config.Config
	// VaultPath is the vault file; empty means Config.Vault.
	VaultPath string
	// TTY is the terminal (/dev/tty), used for input and output. Required.
	TTY *os.File
	// Clipboard is the clipboard; nil makes one from Config.Clipboard and
	// TTY (clipboard.New). If there is none, copying shows the hint of §6.3.
	Clipboard Clipboard
	// Agent is the vault's agent; nil uses the agent client of VaultPath.
	Agent Agent
	// KeySource, if set, is tried at start-up before the agent; after a
	// lock, Enter with an empty passphrase uses it again. For a paper key,
	// and for tests.
	KeySource keys.KeySource
	// PrintPage starts the print page; nil uses internal/printweb with the
	// password sheet of the whole vault (the usual case).
	PrintPage PrintPage
	// Stderr receives what Run prints after the TUI has left the screen
	// that the user must know: a save that ended after the user quit, a
	// clipboard clear or agent stop that failed at the lock on exit. nil
	// means TTY.
	Stderr io.Writer
	// Printer is the language of everything the TUI writes (§3.3): the
	// screens, key help, messages, the entry form, the print page. The zero
	// Printer is English. Values from the vault are never translated.
	Printer i18n.Printer
}

// SignalError is returned by Run when SIGHUP, SIGTERM or SIGINT ended the
// TUI. The session was locked first.
type SignalError struct{ Signal os.Signal }

func (e *SignalError) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language.
func (e *SignalError) Localize(p i18n.Printer) string {
	return p.T("locked and stopped: received %v", e.Signal)
}

// errNoVault: neither the config file nor --vault names a vault.
var errNoVault = i18n.NewError("no vault: set vault in the config file or pass --vault")

// Run runs the TUI on opts.TTY until the user quits, then locks (§5.2) and
// returns. It returns vault.ErrRollbackDeclined when the user declined the
// rollback warning (§4.10) and a *SignalError after a signal. A cancelled
// ctx locks and returns ctx's error. What the lock on exit couldn't do is
// printed to opts.Stderr, not returned: the TUI itself ended as asked.
func Run(ctx context.Context, opts Options) error {
	if opts.Config == nil {
		return errors.New("tui: no config")
	}
	if !tty.IsTerminal(opts.TTY) {
		return i18n.Errorf("the TUI needs a terminal (over SSH: ssh -t): %w", tty.ErrNoTerminal)
	}
	path := opts.VaultPath
	if path == "" {
		path = opts.Config.Vault
	}
	if path == "" {
		return errNoVault
	}
	if _, err := os.Stat(path); err != nil {
		return i18n.Errorf("opening the vault: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	d := deps{
		cfg:       opts.Config,
		vaultPath: path,
		agent:     opts.Agent,
		keySource: opts.KeySource,
		clip:      opts.Clipboard,
		print:     opts.PrintPage,
		ctx:       ctx,
		p:         opts.Printer,
	}
	if d.clip == nil {
		c, err := clipboard.New(opts.Config.Clipboard, opts.TTY)
		if err != nil {
			d.clipErr = err
		} else {
			d.clip = NewClipboard(c)
		}
	}
	if d.agent == nil {
		if c, err := agent.NewClient(path); err == nil {
			d.agent = NewAgent(c)
		}
	}
	d.open = vaultOpener(path, opts.Config, opts.Printer)

	m := newModel(d)
	p := tea.NewProgram(m,
		tea.WithInput(opts.TTY),
		tea.WithOutput(opts.TTY),
		tea.WithoutSignalHandler(),
	)
	stderr := opts.Stderr
	if stderr == nil {
		stderr = opts.TTY
	}
	sigs := make(chan os.Signal, 4) // for the wait for the clipboard
	stopSignals := session.Notify(func(sig os.Signal) {
		// Lock at once, even if the UI is busy: a pending question is
		// dropped, a save or copy that runs is finished first; then the UI
		// quits.
		m.abortJobs()
		m.flights.close()()
		m.notes.report(lockSession(ctx, m.sess, session.ReasonSignal))
		p.Send(signalMsg{sig})
		select {
		case sigs <- sig:
		default:
		}
	})
	defer stopSignals()
	ctxDone := make(chan struct{})
	defer close(ctxDone)
	// Ends when ctx ends or Run returns.
	go func() {
		select {
		case <-ctx.Done():
			p.Send(ctxDoneMsg{})
		case <-ctxDone:
		}
	}()

	_, err := p.Run()
	// Lock on exit, whatever ended the program (§5.2).
	m.shutdown()
	// The user quit: wait for a pending clear like `passh copy` does.
	// Every other way out clears at once.
	if m.waitClip && err == nil && m.exitErr == nil && ctx.Err() == nil {
		m.exitErr = waitForClear(ctx, opts.Printer, opts.TTY, m.clip, sigs)
	}
	// The last chance for a pending clear; it must happen even when ctx
	// ended, bounded (CONC-2).
	clearCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockTimeout)
	if _, cerr := m.clip.clearPending(clearCtx); cerr != nil {
		m.notes.add(opts.Printer.T("clearing the clipboard failed: %v", cerr))
	}
	cancel()
	for _, l := range m.exitLines() {
		fmt.Fprintln(stderr, l)
	}
	switch {
	case m.exitErr != nil:
		return m.exitErr
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

// waitForClear waits, after the TUI has left the alternate screen, until
// the pending clipboard clear is due, then clears (§6.3: like `passh
// copy`). SIGINT (Ctrl-C) clears at once; SIGHUP and SIGTERM clear at once
// and end with a *SignalError; a cancelled ctx clears at once. It writes in
// p's language.
func waitForClear(ctx context.Context, p i18n.Printer, term io.Writer, cs *clipState, sigs <-chan os.Signal) error {
	if cs.c == nil {
		return nil
	}
	deadline, ok := cs.c.Pending()
	if !ok || !time.Now().Before(deadline) {
		return nil
	}
	show := func() {
		left := (time.Until(deadline) + time.Second - 1) / time.Second
		fmt.Fprint(term, "\r\x1b[K"+p.T("Clipboard clears in %d s — Ctrl-C clears now", max(left, 1)))
	}
	result := func(err error) {
		if err != nil {
			fmt.Fprint(term, "\r\x1b[K"+p.T("Clearing the clipboard failed: %v", sanitize.Line(p.Error(err)))+"\n")
			return
		}
		fmt.Fprint(term, "\r\x1b[K"+p.T("Clipboard cleared.")+"\n")
	}
	clearNow := func() {
		// Must happen even when ctx ended, bounded (CONC-2).
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockTimeout)
		defer cancel()
		result(cs.c.ClearPending(cctx))
	}
	show()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-timer.C:
			clearNow()
			return nil
		case <-tick.C:
			if _, ok := cs.c.Pending(); !ok { // the timed clear ran meanwhile
				var err error
				if cr, ok := cs.c.(ClearReporter); ok {
					_, err = cr.ClearResult()
				}
				result(err)
				return nil
			}
			show()
		case sig := <-sigs:
			clearNow()
			if sig == os.Interrupt {
				return nil
			}
			return &SignalError{Signal: sig}
		case <-ctx.Done():
			clearNow()
			return ctx.Err()
		}
	}
}

// opener opens the vault with ks; prompt asks the rollback question
// (§4.10) and warn receives warnings.
type opener func(ctx context.Context, ks keys.KeySource, prompt func(string) (bool, error), warn func(string)) (Vault, error)

// vaultCallbacks adapts the TUI's prompt and warn to vault.Options.Prompt
// and Warn, rendering the vault's messages in p's language. nil stays nil.
func vaultCallbacks(p i18n.Printer, prompt func(string) (bool, error), warn func(string)) (func(i18n.Message) (bool, error), func(i18n.Message)) {
	var vp func(i18n.Message) (bool, error)
	if prompt != nil {
		vp = func(w i18n.Message) (bool, error) { return prompt(w.Localize(p)) }
	}
	var vw func(i18n.Message)
	if warn != nil {
		vw = func(w i18n.Message) { warn(w.Localize(p)) }
	}
	return vp, vw
}

// vaultOpener is the opener of the vault file path. The vault's questions
// and warnings reach prompt and warn in p's language.
func vaultOpener(path string, cfg *config.Config, p i18n.Printer) opener {
	return func(ctx context.Context, ks keys.KeySource, prompt func(string) (bool, error), warn func(string)) (Vault, error) {
		o := vault.Options{
			BackupKeep:   cfg.Backup.Keep,
			RollbackWarn: cfg.Rollback.Warn,
		}
		o.Prompt, o.Warn = vaultCallbacks(p, prompt, warn)
		v, err := vault.Open(ctx, path, ks, o)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
}
