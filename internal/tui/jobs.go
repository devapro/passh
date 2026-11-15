package tui

import (
	"context"
	"errors"
	"fmt"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/vault"
)

// Background jobs that may ask the rollback question (§4.10): opening the
// vault (scrypt takes seconds) and reloading it. This is the only part of
// the model that waits for the user on another goroutine.
//
// Each job has its own channels: its question and result travel on
// job.events, the user's answer on job.answers. An answer can therefore
// only reach the job whose question it answers; a lock cancels the job's
// context, which ends a pending question without an answer, and drops the
// job with its channels (review TUI-001: a shared answer channel let a
// stale "no" answer the next unlock's question).

// job is a background operation that may ask the rollback question.
type job struct {
	gen  int
	kind string // "unlock" or "reload"
	// ctx is the job's context: a job is one operation, and its question
	// (asked through an asker, which has no context of its own) must end
	// when the job is cancelled.
	ctx    context.Context
	cancel context.CancelFunc
	// events carries the job's question, then its result. It holds both,
	// so the job never blocks on a UI that stopped listening.
	events chan tea.Msg
	// answers carries the answer to this job's question; one at most.
	answers chan bool
}

// ask sends the rollback question to the UI and waits for the user's
// answer, or for the job's end. It runs on the job's goroutine.
func (j *job) ask(warning string) (bool, error) {
	select {
	case j.events <- askMsg{job: j, warning: warning}:
	case <-j.ctx.Done():
		return false, j.ctx.Err()
	}
	select {
	case a := <-j.answers:
		return a, nil
	case <-j.ctx.Done():
		return false, j.ctx.Err()
	}
}

// wait is the command that delivers the job's next message.
func (j *job) wait() tea.Msg { return <-j.events }

// errNoJob: the vault asked a question while no job of the TUI was using
// it. It doesn't happen: the vault asks only while it opens or reloads.
var errNoJob = errors.New("no question can be asked now")

// asker is a vault's vault.Options.Prompt: it hands the question to the
// job that uses the vault now (its unlock, later a reload). Each opened
// vault has its own, so a question can't reach a job that works on another
// vault. Safe for concurrent use.
type asker struct {
	mu  sync.Mutex
	job *job
}

func (a *asker) use(j *job) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.job = j
}

func (a *asker) prompt(warning string) (bool, error) {
	a.mu.Lock()
	j := a.job
	a.mu.Unlock()
	if j == nil {
		return false, errNoJob
	}
	return j.ask(warning)
}

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

// startJob runs fn in the background for the vault that a serves, and
// returns the command that delivers the job's messages (a question, then
// its result). The job's context ends when the job is cancelled (a lock),
// when every job is aborted (a signal, Run's end) or when Run's context
// ends.
func (m *app) startJob(kind string, a *asker, fn func(ctx context.Context, gen int) tea.Msg) tea.Cmd {
	m.jobGen++
	gen := m.jobGen
	ctx, cancel := context.WithCancel(m.jobCtx)
	j := &job{gen: gen, kind: kind, ctx: ctx, cancel: cancel, events: make(chan tea.Msg, 2), answers: make(chan bool, 1)}
	a.use(j)
	m.job = j
	return func() tea.Msg {
		// Ends when fn returns: fn honours ctx, so a cancel ends a question.
		go func() {
			msg := fn(ctx, gen)
			a.use(nil)
			cancel()
			j.events <- msg // never blocks: events holds the question and the result
		}()
		return j.wait()
	}
}

// cancelJob drops the running job: its context ends, so a pending question
// returns without an answer and the vault stops. Its result still arrives
// and is dropped (an opened vault is closed).
func (m *app) cancelJob() {
	if m.job == nil {
		return
	}
	m.job.cancel()
	m.job = nil
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
	a := &asker{}
	open, warn := m.d.open, m.warns.add
	return m.startJob("unlock", a, func(ctx context.Context, gen int) tea.Msg {
		if w, ok := ks.(interface{ wipe() }); ok {
			defer w.wipe() // a typed passphrase the vault didn't use (SEC-1)
		}
		v, err := open(ctx, ks, a.prompt, warn)
		if err == nil && ctx.Err() != nil {
			v.Close() // nobody waits for it any more
			v, err = nil, ctx.Err()
		}
		msg := unlockedMsg{gen: gen, v: v, err: err, via: via, asker: a}
		if v != nil {
			msg.data, msg.info = v.Snapshot(), v.Info()
		}
		return msg
	})
}

// reload reads the vault file again (R) in the background.
func (m *app) reload() tea.Cmd {
	if m.v == nil {
		return nil
	}
	if m.busy() {
		m.setBusyStatus()
		return nil
	}
	v := m.v
	m.setStatusSticky("Reloading…", false)
	return m.startJob("reload", m.asker, func(ctx context.Context, gen int) tea.Msg {
		msg := reloadedMsg{gen: gen, err: v.Reload(ctx)}
		if msg.err == nil {
			msg.data, msg.info = v.Snapshot(), v.Info()
		}
		return msg
	})
}

func (m *app) onAsk(msg askMsg) tea.Cmd {
	if msg.job != m.job {
		// A cancelled job's question: its context has ended, so nobody
		// waits for an answer. Its result still comes; keep listening.
		return msg.job.wait
	}
	switch m.screen {
	case screenLock:
		m.lk.ask = msg.warning
	case screenMain:
		m.confirm = &confirm{kind: confirmRollback, text: msg.warning}
	}
	return msg.job.wait
}

// answerAsk answers the running job's rollback question. The command that
// delivers the job's result is already waiting (onAsk returned it), so none
// is needed.
func (m *app) answerAsk(yes bool) tea.Cmd {
	if m.job != nil {
		select {
		case m.job.answers <- yes:
		default: // already answered
		}
	}
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
		m.asker = msg.asker
		m.unlocked(msg.v, msg.data, msg.info)
		return nil
	case errors.Is(err, vault.ErrRollbackDeclined):
		m.exitErr = err
		return m.quit()
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
	case errors.Is(err, vault.ErrWorkFactor):
		// Refused before scrypt runs (INV-10); no passphrase gets past it.
		m.lk.setMsg("The vault file's key block asks for more scrypt work than passh ever uses: "+
			"the file is damaged or wasn't made by passh. Restore a backup (passh backups lists them), then unlock again.", true)
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

func (m *app) onReloaded(msg reloadedMsg) tea.Cmd {
	if m.job == nil || msg.gen != m.job.gen {
		return nil
	}
	m.job = nil
	if m.confirm != nil && m.confirm.kind == confirmRollback {
		m.confirm = nil
	}
	if m.screen != screenMain || m.v == nil {
		return nil
	}
	if err := msg.err; err != nil {
		if !errors.Is(err, context.Canceled) {
			m.setStatusSticky("Reload failed: "+err.Error(), true)
		}
		return nil
	}
	m.changedOnDisk = false
	m.refresh(msg.data)
	m.setStatus(fmt.Sprintf("Reloaded: revision %d, %d entries.", msg.info.Revision, msg.info.Entries), false)
	if k := m.kept; k != nil {
		m.kept = nil
		k.reopen(m)
	}
	return nil
}
