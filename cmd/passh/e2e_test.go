package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vault"
)

// TestEndToEnd: init → unlock → add → show/ls/find/tags/tag → generate →
// mv → rm → lock → passwd → rekey → recover, with real scrypt.
func TestEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const (
		pass1 = "violet granite pepper harbor glacier sonnet"
		pass2 = "copper willow thunder basket meadow quiver"
		pass3 = "lantern ribbon falcon pebble orchard nimbus"
		pass4 = "saffron tundra beacon marble cricket vellum"
	)

	// init: passphrase twice, vault and config written, recovery key hint.
	s := e.start(sessOpts{}, "init")
	s.answer("New passphrase:", pass1)
	s.answer("Repeat passphrase:", pass1)
	s.answer("Print the recovery key now? [Y/n]", "n")
	r := s.waitOK()
	mustContain(t, "init", r.out, "Created the vault ~/.local/share/passh/vault.passh", "Wrote the config file", "passh recovery-key print")
	mustNotContain(t, "init", r.out, pass1, "weak passphrase")
	if m := fileMode(t, e.vault); m != 0o600 {
		t.Errorf("vault mode %o, want 600", m)
	}
	cfg, err := os.ReadFile(e.config)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "config", string(cfg), `vault    = "~/.local/share/passh/vault.passh"`, `language = "en"`)
	r = e.fail(1, "init")
	mustContain(t, "init again", r.stderr, "already exists")

	// Functional criterion 1: doctor reports no errors after init.
	r = e.ok("doctor")
	mustContain(t, "doctor", r.stdout, "0 errors", "ok     vault ", "vault mode    0600")

	// Without an agent and without a terminal, commands are locked.
	r = e.fail(1, "ls")
	if r.stderr != "passh: "+lockedMsg+"\n" {
		t.Errorf("locked: stderr %q", r.stderr)
	}

	paper1 := paperKey(t, e.vault, pass1)

	// unlock; a second unlock reports the running agent.
	r = e.unlock(pass1)
	mustContain(t, "unlock", r.out, "if unused", "at the latest", "passh lock")
	// It restarts the idle time and reports what is left after that
	// (CLI-011); --ttl can't change a running agent, and says so.
	r = e.ok("unlock")
	mustStatus(t, "unlock again", r, "Already unlocked", "exits in 15m if unused")
	r = e.ok("unlock", "--ttl", "30m")
	mustStatus(t, "unlock --ttl again", r, "Already unlocked", "--ttl was not applied", "passh lock")

	// add: hidden password asked twice, then username, url, tags, notes.
	s = e.start(sessOpts{}, "add", "work/github")
	s.answer("Password (empty to generate):", "s3cr3t-P@ss")
	s.answer("Repeat password:", "s3cr3t-P@ss")
	s.answer("Username:", "arsenii")
	s.answer("URL:", "https://github.com")
	s.answer("Tags (comma-separated):", "work, dev, 2fa")
	s.expect("Notes (end with an empty line):")
	s.send("Recovery codes in notes\rsecond line\r\r")
	r = s.waitOK()
	mustContain(t, "add", r.out, "Saved work/github.")
	mustNotContain(t, "add (echo off)", r.out, "s3cr3t-P@ss", "Passphrase:")

	// add with an empty password generates one.
	s = e.start(sessOpts{}, "add", "work/jira")
	s.answer("Password (empty to generate):", "")
	s.answer("Username:", "")
	s.answer("URL:", "")
	s.answer("Tags (comma-separated):", "work")
	s.expect("Notes (end with an empty line):")
	s.send("\r")
	r = s.waitOK()
	mustContain(t, "add generated", r.out, "Generated a 24-character password.", "Saved work/jira.")
	if pw := e.ok("show", "work/jira", "--field", "password").stdout; len(pw) != 24 {
		t.Errorf("generated password %q, want 24 characters", pw)
	}

	// add of an existing path needs --force; add needs a terminal.
	s = e.start(sessOpts{}, "add", "work/github")
	r = s.wait()
	if r.code != 1 || !strings.Contains(r.out, "already exists: use --force") {
		t.Errorf("add existing: %s", r)
	}
	r = e.fail(1, "add", "x/y")
	mustContain(t, "add without terminal", r.stderr, "needs a terminal")

	// show: the text form (§4.3); --field piped is exact, without newline.
	r = e.ok("show", "work/github")
	want := "s3cr3t-P@ss\nusername: arsenii\nurl: https://github.com\ntags: work, dev, 2fa\n---\nRecovery codes in notes\nsecond line\n"
	if r.stdout != want {
		t.Errorf("show:\n%q\nwant\n%q", r.stdout, want)
	}
	if r = e.ok("show", "work/github", "--field", "password"); r.stdout != "s3cr3t-P@ss" {
		t.Errorf("show --field password piped: %q", r.stdout)
	}
	if r = e.ok("show", "work/github", "--field", "notes"); r.stdout != "Recovery codes in notes\nsecond line" {
		t.Errorf("show --field notes: %q", r.stdout)
	}
	r = e.fail(1, "show", "work/github", "--field", "nope")
	mustContain(t, "show missing field", r.stderr, `has no field "nope"`)
	r = e.fail(1, "show", "work")
	mustContain(t, "show folder", r.stderr, "is a folder")
	// On a terminal, --field ends with a newline.
	s = e.start(sessOpts{}, "show", "work/github", "--field", "username")
	if r = s.waitOK(); r.out != "arsenii\n" {
		t.Errorf("show --field on a terminal: %q", r.out)
	}

	// generate: a new entry; an existing one needs --force, which replaces
	// only the password.
	r = e.ok("generate", "work/new-site", "32", "--symbols")
	mustStatus(t, "generate", r, "Stored work/new-site: a new 32-character password (letters, digits and symbols", "passh show work/new-site --field password")
	pw := e.ok("show", "work/new-site", "--field", "password").stdout
	if len(pw) != 32 || strings.Contains(r.stderr, pw) {
		t.Errorf("generated %q; output %q", pw, r.stderr)
	}
	r = e.fail(1, "generate", "work/new-site")
	mustContain(t, "generate existing", r.stderr, "already exists", "--force")
	r = e.ok("generate", "work/github", "--force")
	mustStatus(t, "generate --force", r, "Replaced the password of work/github")
	if pw := e.ok("show", "work/github", "--field", "password").stdout; pw == "s3cr3t-P@ss" || len(pw) != 24 {
		t.Errorf("password after generate --force: %q", pw)
	}
	if u := e.ok("show", "work/github", "--field", "username").stdout; u != "arsenii" {
		t.Errorf("username after generate --force: %q", u)
	}
	e.fail(2, "generate", "work/x", "abc")

	// ls, find, tags, tag.
	r = e.ok("ls")
	wantTree := "~/.local/share/passh/vault.passh\n└── work/\n    ├── github\n    ├── jira\n    └── new-site\n"
	if r.stdout != wantTree {
		t.Errorf("ls:\n%s\nwant:\n%s", r.stdout, wantTree)
	}
	r = e.ok("find", "gthb")
	if first, _, _ := strings.Cut(r.stdout, "\n"); first != "work/github" {
		t.Errorf("find gthb: %q", r.stdout)
	}
	r = e.ok("find", "2fa")
	mustContain(t, "find tag", r.stdout, "work/github  (tag 2fa)")
	e.fail(1, "find", "qqqqqq")
	r = e.ok("tags")
	if r.stdout != "2fa   1\ndev   1\nwork  2\n" {
		t.Errorf("tags: %q", r.stdout)
	}
	r = e.ok("tag", "work/github", "--add", "rotate-soon", "--remove", "dev")
	mustStatus(t, "tag", r, "work/github: tags work, 2fa, rotate-soon")
	r = e.ok("ls", "--tag", "rotate-soon")
	mustContain(t, "ls --tag", r.stdout, "(tag rotate-soon)", "github")
	mustNotContain(t, "ls --tag", r.stdout, "jira")
	e.fail(2, "tag", "work/github")

	// mv: an entry, then a folder into another folder.
	r = e.ok("mv", "work/jira", "work/atlassian/jira")
	mustStatus(t, "mv", r, "Moved work/jira to work/atlassian/jira.")
	r = e.ok("ls", "work")
	mustContain(t, "ls work", r.stdout, "work/\n├── atlassian/\n│   └── jira\n├── github\n")
	r = e.ok("mv", "work/atlassian", "archive/")
	mustStatus(t, "mv folder", r, "Moved the folder work/atlassian/ to archive/atlassian/ (1 entry).")
	e.ok("show", "archive/atlassian/jira")
	r = e.fail(1, "mv", "work/github", "work/new-site")
	mustContain(t, "mv onto existing", r.stderr, "already exists")

	// rm: confirmation on the terminal, or --force.
	r = e.fail(1, "rm", "work/new-site")
	mustContain(t, "rm without terminal", r.stderr, "asks for confirmation", "--force")
	s = e.start(sessOpts{}, "rm", "work/new-site")
	s.answer("Delete work/new-site? [y/N]", "n")
	if r = s.wait(); r.code != 1 || !strings.Contains(r.out, "not deleted") {
		t.Errorf("rm declined: %s", r)
	}
	s = e.start(sessOpts{}, "rm", "work/new-site")
	s.answer("Delete work/new-site? [y/N]", "y")
	mustContain(t, "rm", s.waitOK().out, "Deleted work/new-site.")
	e.ok("rm", "--force", "archive/atlassian/jira")
	r = e.fail(1, "show", "work/new-site")
	mustContain(t, "show deleted", r.stderr, "work/new-site: not found")

	// Every save made an automatic backup.
	r = e.ok("backups")
	if n := strings.Count(r.stdout, "\n"); n < 5 {
		t.Errorf("backups: %d lines:\n%s", n, r.stdout)
	}

	// lock: the agent stops; commands without a terminal are locked again.
	r = e.ok("lock")
	mustStatus(t, "lock", r, "Locked: the agent (pid")
	r = e.ok("lock")
	mustStatus(t, "lock again", r, "No agent is running")
	r = e.fail(1, "show", "work/github")
	if r.stderr != "passh: "+lockedMsg+"\n" {
		t.Errorf("after lock: stderr %q", r.stderr)
	}
	if pids := agentPIDs(e.root); len(pids) > 0 {
		t.Errorf("agent still running after lock: %v", pids)
	}

	// passwd: current passphrase, new one twice; the data stays.
	s = e.start(sessOpts{}, "passwd")
	s.answer("Current passphrase:", pass1)
	s.answer("New passphrase:", pass2)
	s.answer("Repeat passphrase:", pass2)
	mustContain(t, "passwd", s.waitOK().out, "Passphrase changed. The paper recovery key stays valid.")

	// rekey with an agent running: the current passphrase is still asked
	// for (CLI-018), and the agent, which holds the old key, is stopped.
	e.unlock(pass2)
	s = e.start(sessOpts{}, "rekey")
	s.answer("Current passphrase:", pass2)
	s.answer("New passphrase:", pass3)
	s.answer("Repeat passphrase:", pass3)
	r = s.waitOK()
	mustContain(t, "rekey", r.out, "The vault has a new key", "passh recovery-key print", "The agent held the old key and was stopped")
	if pids := agentPIDs(e.root); len(pids) > 0 {
		t.Errorf("agent still running after rekey: %v", pids)
	}

	// recover: the paper key from before the rekey no longer opens it.
	s = e.start(sessOpts{}, "recover")
	s.expectSecretPrompt("> ")
	s.send(strings.ReplaceAll(paper1, "\n", "\r") + "\r\r")
	r = s.wait()
	if r.code != 1 || !strings.Contains(r.out, "this recovery key doesn't open") {
		t.Errorf("recover with the old key: %s", r)
	}
	// The current paper key, typed in lower case over several lines with
	// a typo first: the checksum catches it and it is asked again.
	paper := paperKey(t, e.vault, pass3)
	typo := []byte(paper)
	for i := len(typo) - 1; i > 0; i-- {
		if typo[i] != ' ' && typo[i] != '\n' {
			typo[i] = map[bool]byte{true: 'Q', false: 'P'}[typo[i] != 'Q']
			break
		}
	}
	s = e.start(sessOpts{}, "recover")
	s.expectSecretPrompt("> ")
	s.send(strings.ReplaceAll(string(typo), "\n", "\r") + "\r\r")
	s.expect("Type it again.")
	s.expectSecretPrompt("> ")
	s.send(strings.ToLower(strings.ReplaceAll(paper, "\n", "\r")) + "\r\r")
	s.answer("New passphrase:", pass4)
	s.answer("Repeat passphrase:", pass4)
	r = s.waitOK()
	mustContain(t, "recover", r.out, "typo", "The recovery key opens the vault.", "New passphrase set")

	// The new passphrase opens it; a wrong one is asked again. stdout is a
	// pipe: the prompt goes to the terminal, the value to stdout, exactly.
	s = e.start(sessOpts{pipeStdout: true}, "show", "work/github", "--field", "username")
	s.answer("Passphrase:", "not the passphrase")
	s.expect("Wrong passphrase. Try again.")
	s.answer("Passphrase:", pass4)
	r = s.waitOK()
	if r.stdout != "arsenii" {
		t.Errorf("show after recover: stdout %q", r.stdout)
	}
	mustNotContain(t, "terminal", r.out, pass4, "arsenii")

	// Safety test 2: no plaintext anywhere on disk: the vault, its backups,
	// the state folder and everything else hold none of the values.
	secrets := []string{"s3cr3t-P@ss", "arsenii", "Recovery codes in notes", "rotate-soon", "work/github", pw}
	err = filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, s := range secrets {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("plaintext %q found in %s", s, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAgentWithoutTerminal: commands without a terminal use the agent until
// it exits at its max TTL (functional criterion 4); then they are locked.
func TestAgentWithoutTerminal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	r := e.fail(1, "ls")
	if r.stderr != "passh: "+lockedMsg+"\n" {
		t.Errorf("locked: %q", r.stderr)
	}
	e.fail(1, "unlock") // needs a terminal
	start := time.Now()
	r = e.unlock(fixturePass, "--ttl", "3s")
	mustContain(t, "unlock --ttl", r.out, "exits in ")
	mustNotContain(t, "unlock --ttl", r.out, "if unused")
	e.ok("generate", "site", "--symbols")
	if pw := e.ok("show", "site", "--field", "password").stdout; len(pw) != 24 {
		t.Errorf("password %q", pw)
	}
	if len(agentPIDs(e.root)) != 1 {
		t.Errorf("want one agent, have %v", agentPIDs(e.root))
	}
	// The agent exits at --ttl; then the command fails with the hint.
	time.Sleep(time.Until(start.Add(4 * time.Second))) // time passing under test: the TTL
	deadline := time.Now().Add(10 * time.Second)
	for len(agentPIDs(e.root)) > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond) // polling, with the deadline above
	}
	if pids := agentPIDs(e.root); len(pids) > 0 {
		t.Fatalf("agent still running after its TTL: %v", pids)
	}
	r = e.fail(1, "show", "site")
	if r.stderr != "passh: "+lockedMsg+"\n" {
		t.Errorf("after the TTL: %q", r.stderr)
	}
	e.ok("lock")
}

// TestUsage: exit status 2 for usage errors, and `passh` alone.
func TestUsage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, args := range [][]string{
		{"bogus"},
		{"show"},
		{"show", "a", "b"},
		{"ls", "--nope"},
		{"generate", "x", "0"},
		{"generate", "x", "many"},
		{"unlock", "--ttl", "soon"},
		{"export"},
		{"export", "--format", "xml"},
		{"export", "--format", "json", "--age", "age1x", "--confirm-plaintext"},
		{"export", "--format", "json", "--spreadsheet-safe"},
		{"tag", "a/b"},
		{"import"},
	} {
		r := e.run(args...)
		if r.code != 2 {
			t.Errorf("passh %v: want exit 2, got %s", args, r)
		}
	}
	r := e.fail(1, "ls")
	mustContain(t, "no config", r.stderr, "no config file", "passh init")
	r = e.fail(1, "--vault", e.root+"/none.passh", "ls")
	mustContain(t, "no vault", r.stderr, "no vault at", "passh init")
	// The hidden agent command refuses to run by hand.
	if r = e.run("__agent", "--vault=/x"); r.code != 2 {
		t.Errorf("__agent by hand: %s", r)
	}
}

// TestInitVaultFlag: init --vault with a weak passphrase warns but doesn't
// refuse, and writes a config naming that vault.
func TestInitVaultFlag(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	path := e.root + "/elsewhere/my.passh"
	s := e.start(sessOpts{}, "init", "--vault", path)
	s.answer("New passphrase:", "password")
	s.expect("weak passphrase")
	s.expect("6 or more random words")
	s.answer("Repeat passphrase:", "password")
	// init offers to print the recovery key (§5.4).
	sheet := e.root + "/sheet.txt"
	s.answer("Print the recovery key now? [Y/n]", "")
	s.answer("Write the text sheet to [", sheet)
	s.answer("Type PRINT RECOVERY KEY to confirm:", "PRINT RECOVERY KEY")
	r := s.waitOK()
	mustContain(t, "init", r.out, "Created the vault", "Wrote the paper recovery key to "+sheet, "passh recovery-key print --web")
	// The status line, then the note about it, then the QR code version.
	wrote, note := strings.Index(r.out, "Wrote the paper recovery key to"), strings.Index(r.out, "print it, keep the sheet offline")
	if qr := strings.Index(r.out, "For a version with the key as a QR code"); wrote > note || note > qr {
		t.Errorf("init: the recovery sheet lines are out of order:\n%s", r.out)
	}
	if m := fileMode(t, sheet); m != 0o600 {
		t.Errorf("sheet mode %o", m)
	}
	text, _ := os.ReadFile(sheet)
	mustContain(t, "sheet", string(text), "passh paper recovery key", "AGE-SECRET-KEY-1")
	mustNotContain(t, "sheet", string(text), "age1")
	cfg, err := os.ReadFile(e.config)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "config", string(cfg), path)
	r = e.ok("verify")
	mustContain(t, "verify", r.stdout, "my.passh: OK")
	// Without a config, --vault is enough.
	os.Remove(e.config)
	r = e.ok("--vault", path, "verify")
	mustContain(t, "verify --vault", r.stdout, ": OK")
}

// TestPasswdWithAgent: passwd and rekey never take the key from the agent
// (CLI-018, owner decision): without a terminal they fail, a wrong current
// passphrase changes nothing, and the right one works and stops the agent
// (it unlocked the old key block). An agent whose key block was replaced
// behind its back (a passwd elsewhere) isn't used: the command falls back
// to the passphrase, and without a terminal it is locked.
func TestPasswdWithAgent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	const pass2 = "harbor quiver nimbus copper falcon sonnet"
	e.unlock(fixturePass)
	before, err := os.ReadFile(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func(what string) {
		t.Helper()
		if now, _ := os.ReadFile(e.vault); !bytes.Equal(now, before) {
			t.Errorf("%s changed the vault", what)
		}
		if pids := agentPIDs(e.root); len(pids) != 1 {
			t.Errorf("%s: agents running %v, want the one", what, pids)
		}
	}
	for _, cmd := range []string{"passwd", "rekey"} {
		r := e.fail(1, cmd)
		mustContain(t, cmd+" without a terminal", r.stderr, "needs the current passphrase", "the agent's key isn't enough")
		unchanged(cmd + " without a terminal")

		s := e.start(sessOpts{}, cmd)
		for range 3 {
			s.answer("Current passphrase:", "not the passphrase")
		}
		r = s.wait()
		if r.code != 1 || !strings.Contains(r.out, "wrong passphrase, or the key block is damaged") || strings.Contains(r.out, "New passphrase:") {
			t.Errorf("%s with a wrong current passphrase: %s", cmd, r)
		}
		unchanged(cmd + " with a wrong current passphrase")
	}
	s := e.start(sessOpts{}, "passwd")
	s.answer("Current passphrase:", fixturePass)
	s.answer("New passphrase:", pass2)
	s.answer("Repeat passphrase:", pass2)
	r := s.waitOK()
	mustContain(t, "passwd", r.out, "Passphrase changed.", "The agent was unlocked with the old key block and was stopped")
	if pids := agentPIDs(e.root); len(pids) > 0 {
		t.Errorf("agent still running after passwd: %v", pids)
	}

	e.unlock(pass2)
	e.ok("ls")
	// passwd elsewhere: the key block changes, the vault key doesn't.
	v, err := vault.Open(context.Background(), e.vault, keys.FromIdentity(fixtureKey), vault.Options{StateDir: e.state})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Passwd([]byte(fixturePass)); err != nil {
		t.Fatal(err)
	}
	v.Close()
	r = e.fail(1, "ls")
	mustContain(t, "ls after passwd elsewhere", r.stderr, "key block", "passh: "+lockedMsg+"\n")
	// With a terminal, the passphrase is asked for instead.
	s = e.start(sessOpts{}, "ls")
	s.answer("Passphrase:", fixturePass)
	s.waitOK()
	// unlock replaces the stale agent instead of reporting it.
	r = e.unlock(fixturePass)
	mustContain(t, "unlock over a stale agent", r.out, "replacing it")
	e.ok("ls")
	if pids := agentPIDs(e.root); len(pids) != 1 {
		t.Errorf("agents after replacing: %v", pids)
	}
	e.ok("lock")
}

// TestRollback (§4.10, safety test 11 at the CLI): an older copy put back
// warns on stderr without a terminal and leaves the record; with a
// terminal, no stops without changes and yes stops the warning repeating;
// verify --full only reports.
func TestRollback(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("a"), Password: "1"})
	old, err := os.ReadFile(e.vault) // r2
	if err != nil {
		t.Fatal(err)
	}
	e.addEntries(model.Entry{Path: paths.MustParse("b"), Password: "2"}) // r3 recorded
	e.unlock(fixturePass)
	if err := os.WriteFile(e.vault, old, 0o600); err != nil {
		t.Fatal(err)
	}
	const warning = "this copy is older than one seen before on this machine (r2 of "
	r := e.ok("ls")
	mustContain(t, "ls without a terminal", r.stderr, "passh: warning: "+warning, "seen r3 of")
	r = e.ok("verify", "--full")
	mustContain(t, "verify --full", r.stdout, "rollback  OLDER than seen before on this machine (seen r3")

	s := e.start(sessOpts{}, "ls")
	s.answer("Continue with this copy? [y/N]", "n")
	r = s.wait()
	if r.code != 1 || !strings.Contains(r.out, warning) || !strings.Contains(r.out, "nothing was changed") {
		t.Errorf("rollback declined: %s", r)
	}
	if r = e.ok("ls"); !strings.Contains(r.stderr, warning) {
		t.Errorf("the record changed after no:\n%s", r)
	}
	s = e.start(sessOpts{}, "ls")
	s.answer("Continue with this copy? [y/N]", "y")
	mustContain(t, "rollback accepted", s.waitOK().out, "└── a")
	if r = e.ok("ls"); r.stderr != "" {
		t.Errorf("warning repeats after yes: %q", r.stderr)
	}
	e.ok("lock")
}

// TestRecoverDamagedKeyBlock: with the key block damaged, commands fail and
// point to recover; recover opens the data with the paper key
// (vault.Options.Recovery) and writes a new key block.
func TestRecoverDamagedKeyBlock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("a"), Password: "pw-a"})
	data, err := os.ReadFile(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte("-----BEGIN AGE ENCRYPTED FILE-----\n")) + 40
	data[i] = '*'
	if err := os.WriteFile(e.vault, data, 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.fail(1, "ls")
	mustContain(t, "ls with a damaged key block", r.stderr, "file is damaged (block 1)", "passh recover")
	r = e.fail(1, "verify")
	mustContain(t, "verify", r.stderr, "file is damaged (block 1)")

	const pass = "nimbus orchard pebble ribbon falcon lantern"
	s := e.start(sessOpts{}, "recover")
	s.expectSecretPrompt("> ")
	s.send(strings.ReplaceAll(keys.FormatRecoveryKey(fixtureKey), "\n", "\r") + "\r\r")
	s.answer("New passphrase:", pass)
	s.answer("Repeat passphrase:", pass)
	r = s.waitOK()
	mustContain(t, "recover", r.out, "the key block is damaged; setting a new passphrase rewrites it", "New passphrase set")
	e.ok("verify")
	s = e.start(sessOpts{pipeStdout: true}, "show", "a", "--field", "password")
	s.answer("Passphrase:", pass)
	if r = s.waitOK(); r.stdout != "pw-a" {
		t.Errorf("after recover: %q", r.stdout)
	}
}
