package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"passh/internal/clipboard"
	"passh/internal/model"
	"passh/internal/paths"
)

// selfBin is the test binary, which passh runs as a helper program.
func selfBin(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// readLog reads a helper's log: one %q-quoted string per line.
func readLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		s, err := strconv.Unquote(l)
		if err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		out = append(out, s)
	}
	return out
}

// TestCopy (§6.3, functional criterion 5): OSC 52 through the terminal,
// cleared after clear_after or at once on Ctrl-C; clipboard.command with
// the value on stdin; the hint when there is no clipboard; doctor's test.
func TestCopy(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	const pw = "s3cr3t-P@ss"
	e.addEntries(model.Entry{Path: paths.MustParse("work/github"), Password: pw, Username: "arsenii"})
	e.writeConfig("[clipboard]\nclear_after = \"1s\"\n")

	// No clipboard: the hint, and no passphrase prompt or secret.
	r := e.fail(1, "copy", "work/github")
	mustContain(t, "copy without a terminal", r.stderr,
		"no clipboard: OSC 52 needs a terminal", "copy with: passh show work/github --field password | pbcopy")
	s := e.start(sessOpts{}, "--config", writeFile(t, e.root+"/nocb.toml",
		fmt.Sprintf("vault = %q\n[clipboard]\nosc52 = false\n", e.vault)), "copy", "work/github", "--field", "url")
	r = s.wait()
	if r.code != 1 || !strings.Contains(r.out, "clipboard.osc52 is off") || !strings.Contains(r.out, "--field url | pbcopy") {
		t.Errorf("copy with osc52 off: %s", r)
	}

	e.unlock(fixturePass)
	// OSC 52: the exact sequence, then the empty one that clears.
	s = e.start(sessOpts{}, "copy", "work/github")
	r = s.waitOK()
	set, clr := string(clipboard.OSC52(pw)), string(clipboard.OSC52(""))
	if i, j := strings.Index(r.out, set), strings.LastIndex(r.out, clr); i < 0 || j < i {
		t.Errorf("copy: want %q then %q in:\n%q", set, clr, r.out)
	}
	mustContain(t, "copy", r.out, "Copied the password of work/github (OSC 52 through the terminal); the clipboard clears in 1s", "Clipboard cleared.")
	if strings.Contains(strings.ReplaceAll(r.out, set, ""), pw) {
		t.Error("the password was printed")
	}
	r = e.start(sessOpts{}, "copy", "work/github", "--field", "username").waitOK()
	mustContain(t, "copy --field", r.out, string(clipboard.OSC52("arsenii")))
	r = e.start(sessOpts{}, "copy", "work/github", "--field", "nope").wait()
	if r.code != 1 || !strings.Contains(r.out, `has no field "nope"`) {
		t.Errorf("copy --field nope: %s", r)
	}

	// Ctrl-C clears at once.
	e.writeConfig("[clipboard]\nclear_after = \"5m\"\n")
	s = e.start(sessOpts{}, "copy", "work/github")
	s.expect("Ctrl-C clears it now.")
	s.send("\x03")
	r = s.waitOK()
	mustContain(t, "copy, Ctrl-C", r.out, clr, "Clipboard cleared.")

	// clipboard.command: the value on stdin, then an empty value; no
	// terminal needed (ssh host passh copy …).
	clipLog := filepath.Join(e.root, "clip.log")
	e.setenv(helperEnv, "clipboard")
	e.setenv(clipLogEnv, clipLog)
	e.writeConfig(fmt.Sprintf("[clipboard]\nclear_after = \"1s\"\ncommand = [%q, \"--flag\"]\n", selfBin(t)))
	r = e.ok("copy", "work/github")
	mustContain(t, "copy with a command", r.stdout, "(command ", "Clipboard cleared.")
	if got := readLog(t, clipLog); len(got) != 2 || got[0] != pw || got[1] != "" {
		t.Errorf("clipboard command got %q", got)
	}

	// doctor: a test string, then the clear (with a terminal only).
	os.Remove(clipLog)
	r = e.start(sessOpts{}, "doctor").waitOK()
	mustContain(t, "doctor", r.out, "Testing the clipboard", "ok     clipboard")
	if got := readLog(t, clipLog); len(got) != 2 || got[0] != clipboard.TestString || got[1] != "" {
		t.Errorf("doctor's clipboard test sent %q", got)
	}
	r = e.ok("doctor")
	mustContain(t, "doctor without a terminal", r.stdout, "skip   clipboard", "not tested without a terminal")
	e.ok("lock")
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestEditForm: the built-in form on the terminal saves the edit; cancel
// saves nothing.
func TestEditForm(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("work/github"), Password: "s3cr3t-P@ss", Username: "arsenii"})
	e.unlock(fixturePass)

	s := e.start(sessOpts{}, "edit", "work/github")
	s.expect("edit work/github")
	s.send("\t")     // to username
	s.send("\x15")   // ctrl+u: erase it
	s.send("newbie") // type the new one
	s.expect("newbie")
	s.send("\x13") // ctrl+s
	r := s.waitOK()
	mustContain(t, "edit", r.out, "Saved work/github.")
	mustNotContain(t, "edit", r.out, "s3cr3t-P@ss")
	if u := e.ok("show", "work/github", "--field", "username").stdout; u != "newbie" {
		t.Errorf("username after edit: %q", u)
	}
	if p := e.ok("show", "work/github", "--field", "password").stdout; p != "s3cr3t-P@ss" {
		t.Errorf("password after edit: %q", p)
	}

	s = e.start(sessOpts{}, "edit", "work/github")
	s.expect("edit work/github")
	s.send("\x03") // ctrl+c, nothing changed
	if r = s.wait(); r.code != 1 || !strings.Contains(r.out, "cancelled; nothing was saved") {
		t.Errorf("edit cancelled: %s", r)
	}
	e.fail(1, "edit", "work/github") // needs a terminal
	e.ok("lock")
}

// tmpfsRuntime points $XDG_RUNTIME_DIR at a new folder on /dev/shm, so
// `edit --editor` has a tmpfs of the test's own; it skips the test where
// there is none.
func (e *env) tmpfsRuntime() string {
	e.t.Helper()
	if !onTmpfs(e.t, "/dev/shm/x") {
		e.t.Skip("/dev/shm is not tmpfs")
	}
	dir, err := os.MkdirTemp("/dev/shm", "pcli")
	if err != nil {
		e.t.Skip("can't use /dev/shm:", err)
	}
	e.t.Cleanup(func() { os.RemoveAll(dir) })
	e.setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

// TestEditExternal (§5.6): $EDITOR on a temporary file on tmpfs that is
// wiped afterwards; a parse error offers to edit again; "vault changed on
// disk" offers to reload and apply the edit again to the same entry.
func TestEditExternal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	runtime := e.tmpfsRuntime()
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("work/github"), Password: "pw", Username: "arsenii",
		Fields: []model.Field{{Key: "recovery-email", Value: "me@example.com"}}})
	editLog := filepath.Join(e.root, "edit.log")
	e.setenv("EDITOR", selfBin(t))
	e.setenv(helperEnv, "editor")
	e.setenv(editLogEnv, editLog)
	e.setenv(binEnv, passhBin)
	e.unlock(fixturePass)

	editWith := func(texts []string, run []string) *session {
		t.Helper()
		os.Remove(editLog)
		e.setenv(editTextsEnv, strings.Join(texts, textSep))
		e.setenv(editRunEnv, strings.Join(run, textSep))
		return e.start(sessOpts{}, "edit", "--editor", "work/github")
	}
	noLeftovers := func() {
		t.Helper()
		if left, _ := filepath.Glob(filepath.Join(runtime, "passh-edit-*")); len(left) > 0 {
			t.Errorf("temporary folders left: %v", left)
		}
	}

	// A change is saved; the editor got the text form.
	r := editWith([]string{"pw2\nusername: arsenii\nrecovery-email: me@example.com\n---\nnew notes\n"}, nil).waitOK()
	mustContain(t, "edit --editor", r.out, "warning: passh can't control backup", "Saved work/github.")
	if got := readLog(t, editLog); len(got) != 1 || got[0] != "pw\nusername: arsenii\nrecovery-email: me@example.com\n" {
		t.Errorf("the editor got %q", got)
	}
	if got := e.ok("show", "work/github").stdout; got != "pw2\nusername: arsenii\nrecovery-email: me@example.com\n---\nnew notes\n" {
		t.Errorf("after edit: %q", got)
	}
	noLeftovers()

	// Unchanged: no save.
	r = editWith(nil, nil).waitOK()
	mustContain(t, "edit unchanged", r.out, "No change.")

	// A parse error offers to edit again; the second text is saved.
	s := editWith([]string{"pw3\nusername: a\nusername: b\n", "pw3\nusername: b\n"}, nil)
	s.answer("Edit it again? [Y/n]", "y")
	r = s.waitOK()
	mustContain(t, "edit after a parse error", r.out, "line 3: username appears twice", "Saved work/github.")
	if got := readLog(t, editLog); len(got) != 2 || got[1] != "pw3\nusername: a\nusername: b\n" {
		t.Errorf("second run got %q", got)
	}
	if u := e.ok("show", "work/github", "--field", "username").stdout; u != "b" {
		t.Errorf("username %q", u)
	}
	noLeftovers()

	// The vault changes while the editor runs: reload and apply again.
	s = editWith([]string{"pw4\nusername: b\n"}, []string{"generate", "other/new"})
	s.answer("reload and apply your edit again? [y/N]", "y")
	r = s.waitOK()
	mustContain(t, "edit after a change on disk", r.out, "Saved work/github.")
	if p := e.ok("show", "work/github", "--field", "password").stdout; p != "pw4" {
		t.Errorf("password %q", p)
	}
	e.ok("show", "other/new") // the other change is kept

	// No: nothing is saved.
	s = editWith([]string{"pw5\nusername: b\n"}, []string{"generate", "other/newer"})
	s.answer("reload and apply your edit again? [y/N]", "n")
	if r = s.wait(); r.code != 1 || !strings.Contains(r.out, "not saved: the vault changed on disk") {
		t.Errorf("edit, declined reload: %s", r)
	}
	if p := e.ok("show", "work/github", "--field", "password").stdout; p != "pw4" {
		t.Errorf("password after a declined reload %q", p)
	}

	// The entry was deleted meanwhile: refused.
	s = editWith([]string{"pw6\nusername: b\n"}, []string{"rm", "--force", "work/github"})
	s.answer("reload and apply your edit again? [y/N]", "y")
	if r = s.wait(); r.code != 1 || !strings.Contains(r.out, "was deleted or replaced") {
		t.Errorf("edit of a deleted entry: %s", r)
	}
	e.fail(1, "show", "work/github")
	noLeftovers()
	e.ok("lock")
}
