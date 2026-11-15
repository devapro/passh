package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/printweb"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/vault"
)

// Update never waits for I/O (review TUI-002): saves, copies, the
// vault-file check and the print page's start run in commands, and a lock
// waits for a save or copy that started before it.

// gatedVault holds its saves (and, if changedGate is set, its file checks)
// until the test opens the gate: before the save, or once it is done
// (afterSave).
type gatedVault struct {
	*vault.Vault
	gate        chan struct{} // closed by the test: saves go on
	entered     chan struct{} // a save waits at the gate
	afterSave   bool          // the gate is after the save, not before
	changedGate chan struct{} // nil: Changed doesn't wait
	changedErr  error
}

func newGatedVault(v *vault.Vault) *gatedVault {
	return &gatedVault{Vault: v, gate: make(chan struct{}), entered: make(chan struct{}, 4)}
}

func (g *gatedVault) wait() {
	g.entered <- struct{}{}
	<-g.gate
}

func (g *gatedVault) UpdateContext(ctx context.Context, e model.Entry) (bool, error) {
	if !g.afterSave {
		g.wait()
		return g.Vault.UpdateContext(ctx, e)
	}
	defer g.wait()
	return g.Vault.UpdateContext(ctx, e)
}

func (g *gatedVault) Changed() (bool, error) {
	if g.changedGate != nil {
		g.entered <- struct{}{}
		<-g.changedGate
	}
	if g.changedErr != nil {
		return false, g.changedErr
	}
	return g.Vault.Changed()
}

// withGatedVault makes every vault the TUI opens a gatedVault, returned
// through *gv.
func withGatedVault(gv **gatedVault) hopt {
	return func(h *harness, d *deps) {
		h.wrap = func(v *vault.Vault) Vault {
			*gv = newGatedVault(v)
			return *gv
		}
	}
}

// update calls Update and returns its command without running it.
func (h *harness) update(msg tea.Msg) tea.Cmd {
	h.t.Helper()
	var cmd tea.Cmd
	promptly(h.t, "Update", func() { _, cmd = h.m.Update(msg) })
	return cmd
}

// promptly fails if fn doesn't return soon: Update must not wait for I/O.
func promptly(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked", what)
	}
}

// async runs cmd on its own goroutine, as Bubble Tea does.
func async(cmd tea.Cmd) <-chan tea.Msg {
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	return ch
}

// receive waits for a command's message.
func receive(t *testing.T, ch <-chan tea.Msg) tea.Msg {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(10 * time.Second):
		t.Fatal("a command didn't finish")
	}
	return nil
}

// editUsername opens the form on work/github and types a new username.
func editUsername(h *harness, name string) {
	h.t.Helper()
	h.selectPath("work/github")
	h.press("e", "tab", "ctrl+u")
	h.typeText(name)
}

// A save runs in a command: keys and L work while it runs. The lock ends
// the session's context, which a save not yet written stops on, and waits
// for the save: it is either done or not, and the lock screen says which
// (CORE-003: the context never stops a save after its rename).
func TestSaveInFlightThenLock(t *testing.T) {
	for _, tc := range []struct {
		name      string
		afterSave bool   // the save is written before the lock comes
		report    string // what the lock screen says about it
		username  string // on disk afterwards
	}{
		{"not written yet", false, "Not saved (work/github): the lock came before it was written.", "arsenii"},
		{"written", true, "Saved work/github.", "bob"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gv *gatedVault
			h := newHarness(t, sampleEntries(), withGatedVault(&gv))
			gv.afterSave = tc.afterSave
			v := gv.Vault
			editUsername(h, "bob")
			saved := async(h.update(key(t, "ctrl+s")))
			<-gv.entered // the save waits at the gate
			h.contains("Saving…")
			h.update(key(t, "down")) // keys are handled meanwhile
			h.update(key(t, "e"))
			h.contains("Busy: wait for the save to finish.")

			lockCmd := h.update(key(t, "L"))
			if h.m.screen != screenLock {
				t.Fatalf("L didn't lock at once:\n%s", h.plain())
			}
			h.lacks("arsenii", "bob")
			h.contains("still being saved")
			locked := async(lockCmd)
			// Time passing under test (TEST-7): a lock that doesn't wait for
			// the save would close the vault and report now.
			time.Sleep(50 * time.Millisecond)
			close(gv.gate)
			h.send(receive(t, saved)) // taken over by the lock
			h.send(receive(t, locked))
			h.contains(tc.report, "Locked.")
			if e, _ := h.diskEntry("work/github"); e.Username != tc.username {
				t.Fatalf("username %q on disk, want %q", e.Username, tc.username)
			}
			if v.Snapshot() != nil || h.m.sess.Unlocked() {
				t.Fatal("the lock didn't close the vault")
			}
			// The next unlock works as usual.
			h.press("enter")
			h.mustUnlocked()
		})
	}
}

// A save refused while the lock waits is reported on the lock screen.
func TestSaveRefusedWhileLocking(t *testing.T) {
	var gv *gatedVault
	h := newHarness(t, sampleEntries(), withGatedVault(&gv))
	gv.changedGate = make(chan struct{})
	editUsername(h, "bob")
	saved := async(h.update(key(t, "ctrl+s")))
	<-gv.entered                      // the save checks the vault file
	h.external(func(v *vault.Vault) { // changed on disk meanwhile
		if _, err := v.Add(entry("other/one", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	locked := async(h.update(key(t, "L")))
	close(gv.changedGate)
	h.send(receive(t, saved))
	h.send(receive(t, locked))
	h.contains("Not saved (work/github): the vault changed on disk.", "Locked.")
	if e, _ := h.diskEntry("work/github"); e.Username != "arsenii" {
		t.Fatalf("saved over a changed vault: %q", e.Username)
	}
}

// Quitting while a save runs: Run's shutdown waits for it and says how it
// ended on the terminal.
func TestQuitDuringSave(t *testing.T) {
	var gv *gatedVault
	h := newHarness(t, sampleEntries(), withGatedVault(&gv))
	gv.afterSave = true // written before the quit; the shutdown still waits
	editUsername(h, "bob")
	saved := async(h.update(key(t, "ctrl+s")))
	<-gv.entered
	if cmd := h.update(key(t, "q")); cmd == nil || h.m.screen != screenBye {
		t.Fatal("q didn't quit")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.m.shutdown()
	}()
	close(gv.gate)
	<-done
	<-saved // dropped: the program has ended
	if got := strings.Join(h.m.exitLines(), "\n"); got != "passh: Saved work/github." {
		t.Fatalf("exit lines %q", got)
	}
	if e, _ := h.diskEntry("work/github"); e.Username != "bob" {
		t.Fatalf("the save was lost: %q", e.Username)
	}
	if h.m.sess.Unlocked() {
		t.Fatal("not locked")
	}
}

// A copy runs in a command; a lock waits for it and clears what it copied.
func TestCopyInFlightThenLock(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.cfg.Clipboard.ClearAfter = time.Hour
	h.clip.gate, h.clip.entered = make(chan struct{}), make(chan struct{}, 1)
	h.selectPath("work/github")
	copied := async(h.update(key(t, "c")))
	<-h.clip.entered // the clipboard tool runs
	h.contains("Copying…")
	locked := async(h.update(key(t, "L")))
	// Time passing under test (TEST-7): a lock that doesn't wait would
	// clear now, before the copy, and leave the password behind.
	time.Sleep(50 * time.Millisecond)
	close(h.clip.gate)
	h.send(receive(t, copied))
	h.send(receive(t, locked))
	copies, clears, pending := h.clip.state()
	if len(copies) != 1 || clears != 1 || pending {
		t.Fatalf("copies %d, clears %d, pending %v: the lock didn't clear the copy", len(copies), clears, pending)
	}
	h.contains("Locked.", "Clipboard cleared.")
}

// The vault-file check runs in a command, and its failure shows once
// (review TUI-013).
func TestPollInCommand(t *testing.T) {
	var gv *gatedVault
	h := newHarness(t, sampleEntries(), withGatedVault(&gv))
	gv.changedGate = make(chan struct{})
	cmd := h.update(pollMsg{})
	if cmd == nil {
		t.Fatal("no check started")
	}
	close(gv.changedGate)
	h.run(cmd)
	gv.changedErr = errors.New("read vault.passh: input/output error")
	h.send(pollMsg{})
	h.contains("Checking the vault file failed: read vault.passh: input/output error")
	h.m.st = status{}
	h.send(pollMsg{})
	h.lacks("Checking the vault file failed")
	if h.m.changedOnDisk {
		t.Fatal("a failed check blocked saving")
	}
}

// The print page starts in a command (it binds listeners, may write a
// certificate).
func TestPrintStartInCommand(t *testing.T) {
	gate := make(chan struct{})
	page := newFakePage()
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) {
		h.cfg.PrintWeb.Enabled = true
		d.startPage = func(ctx context.Context, o printweb.Options) (pageInfo, pageServer, error) {
			<-gate
			return pageInfo{URLs: []string{url1}, Fingerprint: fp, Expires: h.clock.Now().Add(5 * time.Minute)}, page, nil
		}
	})
	h.press("P", "enter")
	h.typeText("PRINT")
	started := async(h.update(key(t, "enter")))
	h.contains("Starting the print page…")
	close(gate)
	h.send(receive(t, started))
	if h.m.printDlg == nil {
		t.Fatalf("no dialog:\n%s", h.plain())
	}

	// A start that ends after a lock is stopped, not shown.
	gate = make(chan struct{})
	page2 := newFakePage()
	page = page2
	h.press("esc")
	h.run(nil)
	h.press("P", "enter")
	h.typeText("PRINT")
	started = async(h.update(key(t, "enter")))
	h.press("L")
	close(gate)
	h.send(receive(t, started))
	if page2.stopCount() == 0 || h.m.printDlg != nil {
		t.Fatal("a print page started for an ended session still runs")
	}
}

// A question that arrives after the lock dropped its job is ignored, and
// nothing can answer it (review TUI-001, second path).
func TestLateQuestionIgnored(t *testing.T) {
	h := newHarness(t, sampleEntries())
	a := &asker{}
	cmd := h.m.startJob("reload", a, func(ctx context.Context, gen int) tea.Msg {
		_, err := a.prompt("late question")
		return reloadedMsg{gen: gen, err: err}
	})
	j := h.m.job
	late := receive(t, async(cmd)) // the question, not delivered yet
	if _, ok := late.(askMsg); !ok {
		t.Fatalf("got %T, want the question", late)
	}
	h.press("L") // drops the job; its question returns unanswered
	h.send(late) // the question arrives after the lock
	if h.m.lk.ask != "" || h.m.confirm != nil {
		t.Fatal("a dropped job's question is shown")
	}
	h.lacks("late question")
	h.press("y") // typed into the passphrase field: there is no question
	if len(j.answers) != 0 {
		t.Fatal("an answer was left for a dropped job")
	}
	h.press("esc", "enter") // clear the field; Enter uses the key source
	h.mustUnlocked()
}

// What was typed on the lock screen is wiped when the TUI quits from it
// (SEC-1; review TUI-003). Bubble Tea's own copies of the keys are out of
// reach (see the package doc).
func TestQuitWipesTypedPassphrase(t *testing.T) {
	for _, k := range []string{"ctrl+c", "ctrl+d"} {
		h := newHarness(t, nil, withPassphrase())
		h.typeText("hunter2-secret")
		typed := h.m.lk.pass // shares the input's memory
		h.press(k)
		if !h.quit {
			t.Fatalf("%s didn't quit", k)
		}
		if got := strings.Trim(typed.String(), "\x00"); got != "" {
			t.Errorf("after %s the passphrase input still holds %q", k, got)
		}
	}
}

// A passphrase the vault never used (the unlock was cancelled first) is
// wiped when its job ends.
func TestOnceKeyWipe(t *testing.T) {
	pass := []byte("hunter2-secret")
	k := &onceKey{pass: pass}
	k.wipe()
	if strings.Trim(string(pass), "\x00") != "" {
		t.Fatalf("the passphrase survived: %q", pass)
	}
	if _, err := k.VaultKey(t.Context(), nil); !errors.Is(err, errRekeyed) {
		t.Fatalf("VaultKey after wipe: %v", err)
	}
}

// What the lock on exit couldn't do is told on the terminal after the TUI
// (review TUI-004).
func TestExitLockFailuresReported(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent(), func(h *harness, d *deps) {
		h.agent.stopErr = errors.New("agent socket: connection refused")
	})
	h.press("q")
	if got := strings.Join(h.m.exitLines(), "\n"); got != "passh: stopping the agent failed: agent socket: connection refused" {
		t.Fatalf("exit lines %q", got)
	}
	// The lock screen reports a failed agent stop too.
	h = newHarness(t, sampleEntries(), withAgent(), func(h *harness, d *deps) {
		h.agent.stopErr = errors.New("agent socket: connection refused")
	})
	h.press("L")
	h.contains("Locked.", "Stopping the agent failed: agent socket: connection refused.")
	h.lacks("Agent stopped.")
}

// The signal handler's lock reports into the same notes.
func TestExitNotesFromReport(t *testing.T) {
	var n exitNotes
	n.report(session.Report{ClipboardErr: errors.New("xclip: \x1b]52;c;x\x07"), AgentErr: errors.New("gone")})
	m := &app{notes: &n}
	got := strings.Join(m.exitLines(), "\n")
	want := "passh: clearing the clipboard failed: xclip: \\x1b]52;c;x\\x07\npassh: stopping the agent failed: gone"
	if got != want {
		t.Fatalf("exit lines %q, want %q", got, want)
	}
}
