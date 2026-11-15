package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeEditor writes an editor script named name that logs its arguments and
// the file's location, file system and modes (never the content), then
// replaces the password line with newPass.
func fakeEditor(t *testing.T, dir, name, log, newPass string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := `#!/bin/sh
eval f=\${$#}
{
  printf 'ARGS:'; for a in "$@"; do printf ' [%s]' "$a"; done; echo
  echo "FILE: $f"
  echo "FSTYPE: $(stat -f -c %T "$f")"
  echo "MODE: $(stat -c %a "$f")"
  echo "DIRMODE: $(stat -c %a "$(dirname "$f")")"
} >> ` + log + `
rest=$(tail -n +2 "$f")
printf '%s\n%s\n' '` + newPass + `' "$rest" > "$f"
`
	writeFile(t, p, []byte(script), 0o755)
	return p
}

func logField(log, key string) string {
	for _, l := range strings.Split(log, "\n") {
		if v, ok := strings.CutPrefix(l, key+": "); ok {
			return v
		}
	}
	return ""
}

func shmEntries(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	ents, _ := os.ReadDir(dir)
	for _, x := range ents {
		out[x.Name()] = true
	}
	return out
}

// S1, §5.6: `edit --editor` puts the entry's text in a 0600 file in a 0700
// folder on tmpfs ($XDG_RUNTIME_DIR if it is tmpfs, else /dev/shm), passes
// the leak-safe flags of known editors, and leaves nothing behind.
func TestS1_EditorTmpfsOnly(t *testing.T) {
	e, _ := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	edDir := filepath.Join(e.root, "ed")
	log := filepath.Join(e.root, "editor.log")

	run := func(name, wantDir string, wantFlags []string, wantWarn bool) {
		t.Helper()
		_ = os.Remove(log)
		pass := "edited-by-" + name
		fakeEditor(t, edDir, name, log, pass)
		e.extra = []string{"EDITOR=" + name}
		e.path = edDir + ":" + binDir + ":/usr/bin:/bin"
		shmBefore := shmEntries(t, "/dev/shm")
		runBefore := shmEntries(t, wantDir)
		s := e.start(sessOpts{}, "edit", "--editor", "work/github")
		r := s.wait()
		if r.code != 0 {
			t.Fatalf("edit --editor with %s: %s", name, r)
		}
		lg := string(readFile(t, log))
		file := logField(lg, "FILE")
		if fs := logField(lg, "FSTYPE"); fs != "tmpfs" {
			t.Errorf("%s: the temporary file is on %q, not tmpfs (S1)", name, fs)
		}
		if !strings.HasPrefix(file, wantDir+"/") {
			t.Errorf("%s: the temporary file %s isn't in %s", name, file, wantDir)
		}
		if m := logField(lg, "MODE"); m != "600" {
			t.Errorf("%s: temporary file mode %s, want 600", name, m)
		}
		if m := logField(lg, "DIRMODE"); m != "700" {
			t.Errorf("%s: temporary folder mode %s, want 700", name, m)
		}
		args := strings.TrimPrefix(lg[strings.Index(lg, "ARGS:")+5:], " ")
		args, _, _ = strings.Cut(args, "\n")
		for _, fl := range wantFlags {
			if !strings.Contains(args, fl) {
				t.Errorf("%s: arguments %s lack %s (§5.6)", name, args, fl)
			}
		}
		// S8: "--" before paths for programs known to accept it (vim,
		// neovim, nano); others get the absolute path only.
		if wantFlags != nil && !strings.HasSuffix(args, "[--] ["+file+"]") {
			t.Errorf("%s: arguments %s don't end with -- and the file (S8)", name, args)
		}
		if !filepath.IsAbs(file) || !strings.HasSuffix(args, "["+file+"]") {
			t.Errorf("%s: the file %q isn't the last argument as an absolute path", name, file)
		}
		if got := strings.Contains(strings.ToLower(r.term), "warning"); got != wantWarn {
			t.Errorf("%s: warning shown %v, want %v:\n%s", name, got, wantWarn, r.term)
		}
		if _, err := os.Stat(file); err == nil {
			t.Errorf("%s: the temporary file is still there", name)
		}
		for n := range shmEntries(t, "/dev/shm") {
			if !shmBefore[n] && strings.HasPrefix(n, "passh") {
				t.Errorf("%s: left /dev/shm/%s", name, n)
			}
		}
		for n := range shmEntries(t, wantDir) {
			if !runBefore[n] {
				t.Errorf("%s: left %s/%s", name, wantDir, n)
			}
		}
		e.extra = nil
		e.path = binDir + ":/usr/bin:/bin"
		if got := e.ok("show", "work/github", "--field", "password").stdout; got != pass {
			t.Errorf("%s: password after the edit = %q, want %q", name, got, pass)
		}
		if got := e.ok("show", "work/github", "--field", "username").stdout; got != "arsenii" {
			t.Errorf("%s: username changed to %q", name, got)
		}
	}

	vimFlags := []string{"[-n] [-u] [NONE] [-i] [NONE] [-c] [set nobackup nowritebackup noundofile noswapfile]"}
	// $XDG_RUNTIME_DIR here is on ext4, so /dev/shm is used.
	run("vim", "/dev/shm", vimFlags, false)
	run("nvim", "/dev/shm", []string{"[-n] [--clean] [-i] [NONE] [-c] [set nobackup nowritebackup noundofile noswapfile]"}, false)
	run("nano", "/dev/shm", []string{"[--ignorercfiles] [--nohelp]"}, false)
	run("myedit", "/dev/shm", nil, true) // unknown editor: a warning

	// $XDG_RUNTIME_DIR on tmpfs: it is used, and left as it was.
	rt, err := os.MkdirTemp("/dev/shm", "passh-acc-rt-")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	defer os.RemoveAll(rt)
	e.runtime = rt
	run("vim", rt, vimFlags, false)
	time.Sleep(10 * time.Millisecond)
}
