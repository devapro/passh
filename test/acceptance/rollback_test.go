package acceptance

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var rollbackRe = regexp.MustCompile(`this copy is older than one seen before on this machine \(r(\d+) of \d{4}-\d{2}-\d{2}; seen r(\d+) of \d{4}-\d{2}-\d{2}\)\. If you didn't restore it on purpose, the file may have been replaced\.`)

const continuePrompt = "Continue with this copy?"

// §13.2.11: the rollback warning (§4.10).
func TestS11_RollbackWarning(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	P := f.popRev
	old := readFile(t, e.vault)
	e.ok("generate", "rb/new")
	revFile := filepath.Join(e.state, "revisions.json")
	rec := readFile(t, revFile)

	// The record holds only ids, revision numbers and times.
	var anyRec any
	if err := json.Unmarshal(rec, &anyRec); err != nil {
		t.Errorf("revisions.json isn't JSON: %v", err)
	}
	mustNotContain(t, "revisions.json", string(rec), "rb/new", "github", "s3cr3t", "arsenii")
	mustContain(t, "revisions.json", string(rec), f.popData.VaultID, strconv.Itoa(P+1))

	writeFile(t, e.vault, old, 0o600) // put back an older valid copy

	checkWarn := func(what, out string) {
		t.Helper()
		m := rollbackRe.FindStringSubmatch(out)
		if m == nil {
			t.Errorf("%s: no rollback warning in:\n%s", what, out)
			return
		}
		if m[1] != strconv.Itoa(P) || m[2] != strconv.Itoa(P+1) {
			t.Errorf("%s: warning names r%s/seen r%s, want r%d/seen r%d", what, m[1], m[2], P, P+1)
		}
	}

	// Without a terminal: a warning on stderr, the command continues, the
	// record stays unchanged (so the warning repeats).
	for i := 0; i < 2; i++ {
		r := e.ok("ls")
		checkWarn("no terminal", r.stderr)
		mustContain(t, "ls after the warning", r.stdout, "github")
		if !bytes.Equal(rec, readFile(t, revFile)) {
			t.Errorf("without a terminal, the record changed")
		}
	}

	// With a terminal, declining exits without changes.
	s := e.start(sessOpts{pipeStdout: true}, "ls")
	s.answer(continuePrompt, "n")
	r := s.wait()
	checkWarn("terminal", r.term)
	if r.stdout != "" {
		t.Errorf("declined: ls still printed %q", r.stdout)
	}
	s = e.start(sessOpts{pipeStdout: true}, "generate", "rb/declined")
	s.answer(continuePrompt, "n")
	r = s.wait()
	if r.code == 0 {
		t.Errorf("declined generate exited 0")
	}
	if !bytes.Equal(old, readFile(t, e.vault)) || !bytes.Equal(rec, readFile(t, revFile)) {
		t.Errorf("declining changed the vault or the record")
	}

	// Accepting continues, and the warning doesn't repeat.
	s = e.start(sessOpts{pipeStdout: true}, "ls")
	s.answer(continuePrompt, "y")
	r = s.waitOK()
	mustContain(t, "accepted ls", r.stdout, "github")
	s = e.start(sessOpts{pipeStdout: true}, "ls")
	if s.expectWithin(continuePrompt, 3*time.Second) {
		t.Errorf("the prompt repeats after accepting")
		s.send("y\r")
	}
	r = s.waitOK()
	if strings.Contains(r.term, "older than") {
		t.Errorf("the warning repeats after accepting: %s", r.term)
	}
	if r := e.ok("ls"); strings.Contains(r.stderr, "older than") {
		t.Errorf("the warning repeats without a terminal after accepting: %s", r.stderr)
	}

	// Files in the automatic backups folder never prompt.
	e.ok("generate", "rb/after") // now at P+1 again; a backup of r P exists
	bks, _ := filepath.Glob(filepath.Join(e.state, "backups", f.popData.VaultID, "*.passh"))
	var bk string
	for _, b := range bks {
		if strings.HasSuffix(b, "-r"+strconv.Itoa(P)+".passh") {
			bk = b
		}
	}
	if bk == "" {
		t.Fatalf("no automatic backup of r%d among %v", P, bks)
	}
	s = e.start(sessOpts{pipeStdout: true}, "--vault", bk, "ls")
	for {
		w := s.expectAny(20*time.Second, "Passphrase:", continuePrompt)
		if w == "" {
			break
		}
		if w == continuePrompt {
			t.Errorf("a file in the backups folder prompts")
			s.send("y\r")
			continue
		}
		time.Sleep(20 * time.Millisecond)
		s.send(fixPass + "\r")
	}
	if r := s.wait(); r.code != 0 || !strings.Contains(r.stdout, "github") {
		t.Errorf("--vault <backup> ls: %s", r)
	}

	// verify --full of an older copy never prompts; it reports.
	oldCopy := filepath.Join(e.root, "old.passh")
	writeFile(t, oldCopy, old, 0o600)
	s = e.start(sessOpts{pipeStdout: true}, "verify", "--full", oldCopy)
	for {
		w := s.expectAny(20*time.Second, "Passphrase:", continuePrompt)
		if w == "" {
			break
		}
		if w == continuePrompt {
			t.Errorf("verify --full prompts")
			s.send("y\r")
			continue
		}
		time.Sleep(20 * time.Millisecond)
		s.send(fixPass + "\r")
	}
	r = s.wait()
	if r.code != 0 || !strings.Contains(r.stdout, "revision  "+strconv.Itoa(P)) {
		t.Errorf("verify --full of an older copy: %s", r)
	}
	if !strings.Contains(strings.ToLower(r.stdout+r.term), "older") {
		t.Errorf("verify --full doesn't report the comparison: %s", r)
	}
}

// §13.2.11: with rollback.warn = false nothing warns or prompts.
func TestS11_RollbackWarnOff(t *testing.T) {
	e, _ := popEnv(t, "[rollback]\nwarn = false\n")
	e.unlock(fixPass)
	defer e.lock()
	old := readFile(t, e.vault)
	e.ok("generate", "rb/new")
	writeFile(t, e.vault, old, 0o600)
	if r := e.ok("ls"); strings.Contains(r.stderr, "older than") {
		t.Errorf("rollback.warn = false, no terminal: %s", r.stderr)
	}
	s := e.start(sessOpts{pipeStdout: true}, "ls")
	if s.expectWithin(continuePrompt, 3*time.Second) {
		t.Errorf("rollback.warn = false still prompts")
		s.send("y\r")
	}
	if r := s.waitOK(); strings.Contains(r.term, "older than") {
		t.Errorf("rollback.warn = false, terminal: %s", r.term)
	}
}
