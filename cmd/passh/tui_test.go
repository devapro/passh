package main

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"passh/internal/model"
	"passh/internal/paths"
)

// TestTUI (§6.2): `passh` alone opens the TUI on the lock screen; the
// passphrase unlocks it and shows the tree; an entry added in the TUI is
// in the vault after quitting; without a terminal it says to use ssh -t.
func TestTUI(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("bank/card"), Password: "1234"})

	r := e.fail(1)
	mustContain(t, "passh without a terminal", r.stderr, "the TUI needs a terminal", "ssh -t")

	s := e.start(sessOpts{}, "--vault", e.vault)
	s.expect("vault locked")
	s.expect("Passphrase")
	s.send(fixturePass + "\r")
	s.expect("Unlocked:")
	mustContain(t, "TUI", s.output(), "▸ bank")

	// Add an entry: a, its path, the form, ctrl+s.
	s.send("a")
	s.expect("New entry's path:")
	s.send("\x15work/gitlab\r") // ctrl+u clears the proposed folder
	s.expect("add work/gitlab")
	s.send("gl-p@ss")
	time.Sleep(100 * time.Millisecond)
	s.send("\x13") // ctrl+s
	s.expect("Added work/gitlab.")
	s.send("q")
	r = s.waitOK()
	mustNotContain(t, "TUI", r.out, fixturePass, "gl-p@ss")

	s = e.start(sessOpts{pipeStdout: true}, "show", "work/gitlab", "--field", "password")
	s.answer("Passphrase:", fixturePass)
	if r = s.waitOK(); r.stdout != "gl-p@ss" {
		t.Errorf("entry added in the TUI: %q", r.stdout)
	}
}

// TestTUIAgent: with an agent running the TUI opens without the
// passphrase; with session.stop_agent (the default), L locks and stops the
// agent; SIGHUP locks, stops the agent and exits.
func TestTUIAgent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("work/github"), Password: "pw"})

	e.unlock(fixturePass)
	s := e.start(sessOpts{})
	s.expect("Unlocked:")
	mustContain(t, "TUI with the agent", s.output(), "▸ work")
	if strings.Contains(s.output(), "Passphrase") {
		t.Error("the TUI asked for the passphrase while the agent runs")
	}
	if len(agentPIDs(e.root)) != 1 {
		t.Fatalf("want the agent running, have %v", agentPIDs(e.root))
	}
	s.send("L")
	s.expect("Agent stopped.")
	if pids := agentPIDs(e.root); len(pids) > 0 {
		t.Errorf("agent still running after L: %v", pids)
	}
	s.send("\x03") // ctrl+c on the lock screen quits
	s.waitOK()

	// SIGHUP: lock, stop the agent, exit with 128 + 1.
	e.unlock(fixturePass)
	s = e.start(sessOpts{})
	s.expect("Unlocked:")
	if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	r := s.wait()
	if r.code != 129 || !strings.Contains(r.out, "locked and stopped: received hangup") {
		t.Errorf("SIGHUP: %s", r)
	}
	if pids := agentPIDs(e.root); len(pids) > 0 {
		t.Errorf("agent still running after SIGHUP: %v", pids)
	}
}
