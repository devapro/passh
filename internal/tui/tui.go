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
// reaches the terminal.
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
	"time"

	tea "charm.land/bubbletea/v2"
	"filippo.io/age"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
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
// it.
type Vault interface {
	Snapshot() *model.Data
	Add(e model.Entry, overwrite bool) (model.Entry, error)
	Update(e model.Entry) (changed bool, err error)
	Move(src, dst paths.Path) error
	Remove(p paths.Path) error
	EditTags(p paths.Path, add, remove []string) (model.Entry, bool, error)
	Changed() (bool, error)
	Reload(ctx context.Context) error
	Info() vault.Info
	Close()
}

var _ Vault = (*vault.Vault)(nil)

// Clipboard copies with a timed clear. NewClipboard adapts the
// internal/clipboard package; tests use a fake.
type Clipboard interface {
	// CopyFor copies value and schedules a clear after clearAfter. A later
	// copy replaces the schedule.
	CopyFor(ctx context.Context, value string, clearAfter time.Duration) error
	// ClearPending clears at once if a clear is scheduled.
	ClearPending(ctx context.Context) error
	// Pending returns when the scheduled clear is due; false when none is.
	Pending() (time.Time, bool)
}

// NewClipboard adapts c to Clipboard.
func NewClipboard(c *clipboard.Clipboard) Clipboard { return clipAdapter{c} }

type clipAdapter struct{ c *clipboard.Clipboard }

func (a clipAdapter) CopyFor(ctx context.Context, v string, d time.Duration) error {
	_, err := a.c.CopyFor(ctx, v, d)
	return err
}

func (a clipAdapter) ClearPending(ctx context.Context) error { return a.c.ClearPending(ctx) }

func (a clipAdapter) Pending() (time.Time, bool) { return a.c.Pending() }

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
}

// SignalError is returned by Run when SIGHUP, SIGTERM or SIGINT ended the
// TUI. The session was locked first.
type SignalError struct{ Signal os.Signal }

func (e *SignalError) Error() string {
	return fmt.Sprintf("locked and stopped: received %v", e.Signal)
}

// Run runs the TUI on opts.TTY until the user quits, then locks (§5.2) and
// returns. It returns vault.ErrRollbackDeclined when the user declined the
// rollback warning (§4.10) and a *SignalError after a signal. A cancelled
// ctx locks and returns ctx's error.
func Run(ctx context.Context, opts Options) error {
	if opts.Config == nil {
		return errors.New("tui: no config")
	}
	if !tty.IsTerminal(opts.TTY) {
		return fmt.Errorf("the TUI needs a terminal (over SSH: ssh -t): %w", tty.ErrNoTerminal)
	}
	path := opts.VaultPath
	if path == "" {
		path = opts.Config.Vault
	}
	if path == "" {
		return errors.New("no vault: set vault in the config file or pass --vault")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("opening the vault: %w", err)
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
	d.open = vaultOpener(path, opts.Config)

	m := newModel(d)
	p := tea.NewProgram(m,
		tea.WithInput(opts.TTY),
		tea.WithOutput(opts.TTY),
		tea.WithoutSignalHandler(),
	)
	sigs := make(chan os.Signal, 4) // for the wait for the clipboard
	stopSignals := session.Notify(func(sig os.Signal) {
		// Lock at once, even if the UI is busy (a pending question is
		// dropped first); then let the UI quit.
		m.br.abort()
		lockSession(m.sess, session.ReasonSignal)
		p.Send(signalMsg{sig})
		select {
		case sigs <- sig:
		default:
		}
	})
	defer stopSignals()
	ctxDone := make(chan struct{})
	defer close(ctxDone)
	go func() {
		select {
		case <-ctx.Done():
			p.Send(ctxDoneMsg{})
		case <-ctxDone:
		}
	}()

	_, err := p.Run()
	// Lock on exit, whatever ended the program (§5.2).
	m.br.abort()
	lockSession(m.sess, session.ReasonExit)
	// The user quit: wait for a pending clear like `passh copy` does.
	// Every other way out clears at once.
	if m.waitClip && err == nil && m.exitErr == nil && ctx.Err() == nil {
		m.exitErr = waitForClear(ctx, opts.TTY, m.clip, sigs)
	}
	clearCtx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	_, _ = m.clip.clearPending(clearCtx)
	cancel()
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
// and end with a *SignalError; a cancelled ctx clears at once.
func waitForClear(ctx context.Context, term io.Writer, cs *clipState, sigs <-chan os.Signal) error {
	if cs.c == nil {
		return nil
	}
	deadline, ok := cs.c.Pending()
	if !ok || !time.Now().Before(deadline) {
		return nil
	}
	show := func() {
		left := (time.Until(deadline) + time.Second - 1) / time.Second
		fmt.Fprintf(term, "\r\x1b[KClipboard clears in %d s — Ctrl-C clears now", max(left, 1))
	}
	clearNow := func() {
		cctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
		defer cancel()
		if err := cs.c.ClearPending(cctx); err != nil {
			fmt.Fprintf(term, "\r\x1b[KClearing the clipboard failed: %s\n", sanitize.Line(err.Error()))
			return
		}
		fmt.Fprint(term, "\r\x1b[KClipboard cleared.\n")
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
			if _, ok := cs.c.Pending(); !ok { // cleared meanwhile
				fmt.Fprint(term, "\r\x1b[KClipboard cleared.\n")
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

// lockTimeout bounds clearing the clipboard and stopping the agent at a
// lock.
const lockTimeout = 5 * time.Second

// lockSession locks s with a bounded context that a cancelled Run context
// doesn't cut short: the clipboard and the agent are handled even then.
func lockSession(s *session.Session, r session.Reason) session.Report {
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	return s.Lock(ctx, r)
}

// opener opens the vault with ks; prompt asks the rollback question
// (§4.10) and warn receives warnings.
type opener func(ctx context.Context, ks keys.KeySource, prompt func(string) (bool, error), warn func(string)) (Vault, error)

func vaultOpener(path string, cfg *config.Config) opener {
	return func(ctx context.Context, ks keys.KeySource, prompt func(string) (bool, error), warn func(string)) (Vault, error) {
		v, err := vault.Open(ctx, path, ks, vault.Options{
			BackupKeep:   cfg.Backup.Keep,
			RollbackWarn: cfg.Rollback.Warn,
			Prompt:       prompt,
			Warn:         warn,
		})
		if err != nil {
			return nil, err
		}
		return v, nil
	}
}
