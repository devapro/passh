package tui

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"passh/internal/keys"
	"passh/internal/vault"
)

func TestUnlockWithKeySource(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.mustUnlocked()
	h.contains("bank", "(2)", "work", "homelab", "readme", "unlocked · locks in 5:00", "Unlocked: 6 entries")
	if !h.m.sess.Unlocked() {
		t.Fatal("the session isn't unlocked")
	}
}

func TestUnlockWithPassphrase(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	if h.m.screen != screenLock {
		t.Fatal("started unlocked without a key")
	}
	h.contains("vault locked", "Passphrase")
	// Typing is masked with a fixed-length mask.
	h.typeText("wrong")
	h.lacks("wrong")
	h.contains("••••••••")
	h.press("enter")
	if h.m.screen != screenLock {
		t.Fatal("unlocked with a wrong passphrase")
	}
	h.contains("Wrong passphrase")
	if !h.m.lk.pass.Empty() {
		t.Fatal("the wrong passphrase stayed in the input")
	}
	// Enter on an empty input with no agent only asks to type.
	h.press("enter")
	h.contains("Type the passphrase")
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
	h.contains("work")
}

func TestUnlockWithAgent(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent())
	h.mustUnlocked()
	if h.agent.keyReqs != 1 {
		t.Fatalf("asked the agent %d times", h.agent.keyReqs)
	}
}

func TestNoAgentFallsBackToPassphrase(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent(), func(h *harness, d *deps) { h.agent.running = false })
	if h.m.screen != screenLock || h.agent.keyReqs != 1 {
		t.Fatalf("screen %v, agent asked %d times", h.m.screen, h.agent.keyReqs)
	}
	h.lacks("agent")
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
}

// The agent answers only for the key block it was unlocked for, so a key
// that doesn't open the data block under that key block means the data
// block is damaged or replaced (keys.KeyBlockChecker). A stale agent after
// a passwd or rekey elsewhere is refused by the key block check instead:
// see TestAgentRefusedForChangedKeyBlock.
func TestAgentKeyNotOpeningDataIsDamage(t *testing.T) {
	other, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, sampleEntries(), withAgent(), func(h *harness, d *deps) { h.agent.key = other })
	if h.m.screen != screenLock || !h.m.lk.damaged {
		t.Fatalf("not reported as damaged:\n%s", h.plain())
	}
	h.contains("data is damaged; restore a backup", "Enter try again")
	h.lacks("Passphrase")
}

// A key source that doesn't check the key block (a paper key) and doesn't
// fit: the lock screen asks for the passphrase.
func TestWrongPaperKeyAsksPassphrase(t *testing.T) {
	other, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) { d.keySource = keys.FromIdentity(other) })
	if h.m.screen != screenLock || h.m.lk.damaged {
		t.Fatalf("screen %v, damaged %v", h.m.screen, h.m.lk.damaged)
	}
	h.contains("doesn't open this vault", "Passphrase")
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
}

func TestRollbackDeclinedQuits(t *testing.T) {
	h := rollbackHarness(t)
	h.contains("older than one seen before", "Continue with this copy?")
	h.press("n")
	if !h.quit || !errors.Is(h.m.exitErr, vault.ErrRollbackDeclined) {
		t.Fatalf("quit %v, err %v", h.quit, h.m.exitErr)
	}
}

func TestRollbackAccepted(t *testing.T) {
	h := rollbackHarness(t)
	h.press("y")
	h.mustUnlocked()
	if h.quit {
		t.Fatal("quit after yes")
	}
}

// rollbackHarness opens a vault older than one this machine has seen:
// the lock screen asks the rollback question (§4.10).
func rollbackHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, sampleEntries(), withPassphrase())
	old, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	h.external(func(v *vault.Vault) { // revision 2 is recorded
		if _, err := v.Add(entry("new/one", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.WriteFile(h.path, old, 0o600); err != nil { // back to revision 1
		t.Fatal(err)
	}
	h.typeText(testPass)
	h.press("enter")
	if h.m.lk.ask == "" {
		t.Fatalf("no rollback question:\n%s", h.plain())
	}
	return h
}

func TestIdleLock(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent(), func(h *harness, d *deps) {
		// Longer than the idle TTL, so the clear is still pending at the lock.
		h.cfg.Clipboard.ClearAfter = time.Hour
	})
	h.mustUnlocked()
	h.selectPath("work/github")
	h.press("c")
	if len(h.clip.copies) != 1 {
		t.Fatal("not copied")
	}
	h.clock.Advance(4 * time.Minute)
	h.send(tickMsg{})
	h.contains("locks in 1:00")
	h.press("down") // any key resets the idle timer
	h.clock.Advance(4 * time.Minute)
	h.send(tickMsg{})
	h.mustUnlocked()
	h.clock.Advance(time.Minute)
	h.send(tickMsg{})
	if h.m.screen != screenLock {
		t.Fatalf("not locked after the idle TTL:\n%s", h.plain())
	}
	h.contains("Locked after 5 min without input.", "Clipboard cleared.", "Agent stopped.")
	if h.agent.stops != 1 || h.clip.clears != 1 {
		t.Fatalf("agent stops %d, clipboard clears %d", h.agent.stops, h.clip.clears)
	}
	// Functional criterion 3: after the idle lock it asks again.
	h.contains("Passphrase")
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
}

// Safety test 6 (TUI bullet): a TUI lock with session.stop_agent stops the
// agent, and the lock wipes the decrypted state.
func TestLockStopsAgentAndWipes(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent())
	h.mustUnlocked()
	v := h.m.v
	h.selectPath("work/github")
	h.press("r", "e") // reveal, then open the form
	if h.m.form == nil {
		t.Fatal("no form")
	}
	h.press("esc")
	h.press("/")
	h.typeText("git")
	h.press("enter")
	h.press("L")
	if h.m.screen != screenLock {
		t.Fatal("L didn't lock")
	}
	if h.agent.stops != 1 {
		t.Fatalf("agent stopped %d times", h.agent.stops)
	}
	if v.Snapshot() != nil || v.Info().Entries != 0 {
		t.Fatal("the vault still holds data after the lock")
	}
	m := h.m
	if m.v != nil || m.data != nil || m.entries != nil || m.byID != nil || m.tags != nil ||
		m.form != nil || m.search.active || m.search.in.String() != "" || m.reveal.id != "" ||
		m.detail || m.prompt != nil || m.confirm != nil || m.kept != nil {
		t.Fatalf("UI state survived the lock: %+v", m.search)
	}
	h.lacks("github", "arsenii", "bank")
	h.contains("Locked.", "Agent stopped.")
	// An agent is gone now: no hint to use it.
	h.lacks("An agent is running")

	// Unlocking again works with the passphrase.
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
}

func TestLockKeepsAgentWithoutStopAgent(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent(), func(h *harness, d *deps) { h.cfg.Session.StopAgent = false })
	h.press("L")
	if h.agent.stops != 0 {
		t.Fatal("the agent was stopped with stop_agent off")
	}
	// The agent still runs: Enter with an empty passphrase uses it.
	h.contains("An agent is running")
	h.press("enter")
	h.mustUnlocked()
	if h.agent.keyReqs != 2 {
		t.Fatalf("agent asked %d times", h.agent.keyReqs)
	}
}

func TestQuitLocks(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent())
	v := h.m.v
	h.selectPath("bank/chase")
	h.press("u")
	h.press("q")
	if !h.quit {
		t.Fatal("q didn't quit")
	}
	if h.agent.stops != 1 || v.Snapshot() != nil || h.m.sess.Unlocked() {
		t.Fatalf("quit didn't lock: stops %d", h.agent.stops)
	}
	// The pending clear is left to Run, which waits for it (§6.3).
	if _, clears, pending := h.clip.state(); clears != 0 || !pending || !h.m.waitClip {
		t.Fatalf("clears %d, pending %v, wait %v", clears, pending, h.m.waitClip)
	}
	if h.view() != "" {
		t.Fatalf("something is shown after quitting: %q", h.view())
	}
}

func TestSignalLocksAndQuits(t *testing.T) {
	h := newHarness(t, sampleEntries(), withAgent())
	h.send(signalMsg{syscall.SIGHUP})
	if !h.quit || h.agent.stops != 1 || h.m.sess.Unlocked() {
		t.Fatalf("quit %v, stops %d", h.quit, h.agent.stops)
	}
	var se *SignalError
	if !errors.As(h.m.exitErr, &se) || se.Signal != syscall.SIGHUP || !strings.Contains(se.Error(), "hangup") {
		t.Fatalf("exit error %v", h.m.exitErr)
	}
}

func TestQuitFromLockScreen(t *testing.T) {
	h := newHarness(t, nil, withPassphrase())
	h.press("esc")
	if !h.quit {
		t.Fatal("esc on an empty passphrase didn't quit")
	}
	h = newHarness(t, nil, withPassphrase())
	h.typeText("abc")
	h.press("esc")
	if h.quit || !h.m.lk.pass.Empty() {
		t.Fatal("esc with input should clear it")
	}
	h.press("ctrl+c")
	if !h.quit {
		t.Fatal("ctrl+c didn't quit")
	}
}

func TestContextCancelQuits(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.send(ctxDoneMsg{})
	if !h.quit || h.m.sess.Unlocked() || h.m.waitClip {
		t.Fatal("a cancelled context didn't lock and quit, or would wait")
	}
}

// A job's result that arrives after a lock is dropped and its vault
// closed.
func TestStaleUnlockResultClosed(t *testing.T) {
	h := newHarness(t, nil, withPassphrase())
	v := h.diskVault()
	h.send(unlockedMsg{gen: 99, v: v})
	if v.Snapshot() != nil {
		t.Fatal("a stale vault wasn't closed")
	}
	if h.m.screen != screenLock {
		t.Fatal("a stale result unlocked")
	}
}

func TestOnceKeyRefusesSecondUse(t *testing.T) {
	k := &onceKey{pass: []byte("x")}
	if _, err := k.VaultKey(context.Background(), nil); err == nil {
		t.Fatal("garbage key block opened")
	}
	if _, err := k.VaultKey(context.Background(), nil); !errors.Is(err, errRekeyed) {
		t.Fatalf("second use: %v", err)
	}
}

func TestLockScreenPaste(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	h.send(tea.PasteMsg{Content: testPass + "\n"})
	h.press("enter")
	h.mustUnlocked()

	h = newHarness(t, sampleEntries(), withPassphrase())
	h.send(tea.PasteMsg{Content: "a\nb"})
	h.contains("Paste refused")
}
