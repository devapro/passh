package acceptance

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const (
	tuiLocked   = "vault locked"
	tuiUnlocked = "unlocked"
)

// startTUI starts `passh` (the TUI) on a 100x30 terminal and waits for the
// lock screen.
func (e *env) startTUI(args ...string) *session {
	e.t.Helper()
	s := e.start(sessOpts{cols: 100, rows: 30}, args...)
	s.mustScreen(15*time.Second, tuiLocked, "Passphrase")
	return s
}

// startTUIAgent starts the TUI while an agent runs: it takes the key from
// the agent without asking (§6.2).
func (e *env) startTUIAgent() *session {
	e.t.Helper()
	s := e.start(sessOpts{cols: 100, rows: 30})
	s.mustScreen(15*time.Second, tuiUnlocked)
	return s
}

// tuiUnlock types the passphrase (or Enter alone to use the agent) and
// waits for the unlocked header.
func (s *session) tuiUnlock(pass string) {
	s.t.Helper()
	time.Sleep(50 * time.Millisecond)
	s.send(pass + "\r")
	s.mustScreen(15*time.Second, tuiUnlocked)
}

// key sends keys and lets the TUI redraw.
func (s *session) key(keys ...string) {
	for _, k := range keys {
		s.send(k)
		time.Sleep(120 * time.Millisecond)
	}
}

// tuiQuit quits and waits for exit 0.
func (s *session) tuiQuit() result {
	s.t.Helper()
	s.key("\x1b", "\x1b")
	s.send("q")
	return s.waitOK()
}

// §13.1.3: the TUI asks for the passphrase once per session; after
// session.idle_ttl without input it locks and asks again.
func TestF3_TUIPassphraseOncePerSession(t *testing.T) {
	e, _ := popEnv(t, "[session]\nidle_ttl = \"3s\"\n")
	s := e.startTUI()
	s.tuiUnlock(fixPass)
	mustContain(t, "unlocked TUI", s.screen(), "bank", "work", "Unlocked: 7 entries")

	// Busy for 6 s (longer than idle_ttl), opening folders, entries and
	// the search: no second passphrase prompt.
	keys := []string{"G", "\r", "j", "\r", "\x1b", "/", "git", "\r", "\x1b", "\t", "\t", "k", "j"}
	start := time.Now()
	for i := 0; time.Since(start) < 6*time.Second; i++ {
		s.send(keys[i%len(keys)])
		time.Sleep(400 * time.Millisecond)
		if sc := s.screen(); strings.Contains(sc, tuiLocked) {
			t.Fatalf("the TUI locked after %v although input came every 0.4 s:\n%s", time.Since(start), sc)
		}
	}
	// Idle: it locks after about 3 s and asks again.
	s.send("\x1b")
	idleFrom := time.Now()
	if !s.waitScreen(8*time.Second, tuiLocked, "Passphrase") {
		t.Fatalf("no lock after %v idle (session.idle_ttl 3s):\n%s", time.Since(idleFrom), s.screen())
	}
	if d := time.Since(idleFrom); d < 2*time.Second {
		t.Errorf("locked %v after the last input, before idle_ttl", d)
	}
	mustContain(t, "idle lock screen", s.screen(), "without input")
	mustNotContain(t, "idle lock screen", s.screen(), "github", "arsenii")
	s.tuiUnlock(fixPass)
	s.tuiQuit()
}

// §13.2.6: a TUI lock with session.stop_agent (default on) stops the agent;
// with it off the agent keeps running. The TUI never starts an agent.
func TestS6_TUILockStopsAgent(t *testing.T) {
	e, _ := popEnv(t, "")
	s := e.startTUI()
	s.tuiUnlock(fixPass)
	if n := len(agentProcs(e.root)); n != 0 {
		t.Errorf("the TUI started %d agents", n)
	}
	s.tuiQuit()

	pid := e.unlock(fixPass)
	s = e.startTUIAgent()
	s.key("L")
	s.mustScreen(5*time.Second, tuiLocked)
	if !waitGone(pid, 5*time.Second) {
		t.Errorf("a TUI lock with session.stop_agent = true left the agent running")
	}
	s.send("\x03")
	s.wait()

	// stop_agent = false: L locks the TUI only.
	e.writeConfig("[session]\nstop_agent = false\n")
	pid = e.unlock(fixPass)
	s = e.startTUIAgent()
	s.key("L")
	s.mustScreen(5*time.Second, tuiLocked)
	time.Sleep(500 * time.Millisecond)
	if !alive(pid) {
		t.Errorf("a TUI lock with session.stop_agent = false stopped the agent")
	}
	s.send("\x03")
	s.wait()
	e.lock()
}

// §13.2.3 (TUI): escape sequences in entries render inert on the screen.
// The bytes the TUI writes must not contain any sequence that came from
// entry content; the TUI's own styling is ignored.
func TestS3_TUIEscapesInert(t *testing.T) {
	g := makeGPGStoreWith(t, map[string]string{
		"evil/osc52":   evilEntry,
		"evil/x\u202e": "bidi\n",
	}, false)
	f := fixtures(t)
	e := newEnv(t)
	e.installVault(f.empty, "")
	e.gnupg = g.home
	e.path = binDir + ":/usr/bin:/bin"
	e.unlock(fixPass)
	e.ok("import", "pass", g.store)
	e.lock()
	e.path = binDir

	s := e.startTUI()
	s.tuiUnlock(fixPass)
	s.key("/", "o", "s", "c", "\r", "\r") // search, open the entry
	s.mustScreen(5*time.Second, "username", "notes")
	s.key("r") // reveal the password
	s.mustScreen(5*time.Second, "SGVsbG8=")
	sc := s.screen()
	s.key("j", "j", "j", "k", "\x1b", "\t", "\r", "\t")
	s.tuiQuit()

	raw := string(s.raw())
	for _, bad := range []string{
		"\x1b]52;c;SGVsbG8", // the entry's clipboard write
		"\x1b]0;pwned",      // window title
		"\x1b]8;;http://evil",
		"\x1bP+q",
		"\u009b31m",
		"\x07tail", "\x07bell", "\x07 and",
		"\x1b[2J\x1b[Hname",
		"\x1b[31mred",
		"\rcarriage",
	} {
		if strings.Contains(raw, bad) {
			t.Errorf("the TUI wrote the entry's sequence %q to the terminal", bad)
		}
	}
	// The value is shown, escaped, as text.
	mustContain(t, "revealed evil entry", sc, "52;c;SGVsbG8=", "tail")
}

// §13.1.5 (TUI): c copies the password through OSC 52 with its exact bytes
// and clears it after clipboard.clear_after.
func TestF5_TUICopy(t *testing.T) {
	e, _ := popEnv(t, "[clipboard]\nclear_after = \"2s\"\n")
	s := e.startTUI()
	s.tuiUnlock(fixPass)
	s.key("/", "g", "i", "t", "h", "u", "b", "\r", "\r")
	s.mustScreen(5*time.Second, "arsenii")
	s.key("c")
	want := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte("s3cr3t-P@ss")) + "\x07"
	if !s.expectWithin(want, 5*time.Second) {
		t.Fatalf("no OSC 52 with the exact password after c")
	}
	copied := time.Now()
	if !s.expectWithin("\x1b]52;c;\x07", 6*time.Second) {
		t.Errorf("the clipboard wasn't cleared within 6 s (clear_after 2s)")
	} else if d := time.Since(copied); d < 1500*time.Millisecond {
		t.Errorf("cleared after %v, before clear_after", d)
	}
	s.tuiQuit()
	if strings.Contains(s.output(), "s3cr3t-P@ss") {
		t.Errorf("the TUI printed the password while copying")
	}
}
