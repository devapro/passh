package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

// writeStore makes a pass store: files maps store paths to contents.
func writeStore(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestImportPassDryRun: what would be imported and the conflicts, with
// every store-derived name escaped; nothing is decrypted (the files aren't
// even encrypted) and nothing is saved.
func TestImportPassDryRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("work/github"), Password: "kept"})
	store := filepath.Join(e.root, "store")
	writeStore(t, store, map[string][]byte{
		"work/github.gpg":       []byte("x"),
		"work/gitlab.gpg":       []byte("x"),
		"bank/my bank.gpg":      []byte("x"),
		"bad/-dash.gpg":         []byte("x"),
		"evil\x1b]52;c;x\a.gpg": []byte("x"),
		".git/objects/a.gpg":    []byte("x"),
		".gpg-id":               []byte("ABC\n"),
		"notes.txt":             []byte("x"),
	})
	if err := os.Symlink("/etc/passwd", filepath.Join(store, "outside.gpg")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(e.vault)
	e.unlock(fixturePass)
	r := e.ok("import", "pass", store, "--dry-run")
	mustContain(t, "dry run", r.stdout,
		"Dry run: nothing was decrypted or saved.",
		"Would import 2 entries:", "  bank/my bank\n", "  work/gitlab\n",
		"Would skip 4:", "2 invalid path", "1 already in the vault", "1 symlink leads outside the store",
		"work/github.gpg — already in the vault: use --overwrite to replace it",
		`evil\x1b]52;c;x\x07.gpg — invalid path`)
	mustNotContain(t, "dry run", r.stdout, "\x1b", "\a", ".git", "notes.txt")
	r = e.ok("import", "pass", store, "--dry-run", "--overwrite")
	mustContain(t, "dry run --overwrite", r.stdout, "Would import 3 entries", "work/github  (replaces the entry in the vault)")
	if after, _ := os.ReadFile(e.vault); !bytes.Equal(before, after) {
		t.Error("a dry run changed the vault")
	}
	r = e.fail(1, "import", "pass", filepath.Join(e.root, "nostore"), "--dry-run")
	mustContain(t, "import without a store", r.stderr, "pass store")
	e.ok("lock")
}

// TestImportPassGPG imports a real pass store with gpg (skipped without
// gpg): folders, tags, fields and otp; one save; conflicts skipped.
func TestImportPassGPG(t *testing.T) {
	t.Parallel()
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed")
	}
	e := newEnv(t)
	e.withVault()
	e.addEntries(model.Entry{Path: paths.MustParse("work/github"), Password: "kept"})
	gnupg := filepath.Join(e.root, "g")
	gpgRun := func(stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(gpg, append([]string{"--homedir", gnupg, "--batch"}, args...)...)
		cmd.Env = e.vars
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg %v: %v: %s", args, err, stderr.Bytes())
		}
		return out
	}
	t.Cleanup(func() {
		for _, args := range [][]string{{"--kill", "all"}, {"--remove-socketdir"}} {
			cmd := exec.Command("gpgconf", args...)
			cmd.Env = e.vars
			_ = cmd.Run()
		}
	})
	const uid = "passh test <passh-test@example.invalid>"
	gpgRun(nil, "--passphrase", "", "--quick-gen-key", uid, "future-default", "default", "never")
	enc := func(plain string) []byte {
		return gpgRun([]byte(plain), "--yes", "--trust-model", "always", "--encrypt", "--recipient", uid)
	}
	store := filepath.Join(e.root, "h", ".password-store") // $PASSWORD_STORE_DIR
	writeStore(t, store, map[string][]byte{
		".gpg-id":          []byte(uid + "\n"),
		"work/github.gpg":  enc("other\n"),
		"work/gitlab.gpg":  enc("gl-pass\nlogin: arsenii\nurl: https://gitlab.com\ntags: work, dev\nrecovery-email: me@example.com\notpauth://totp/x?secret=ABC\nnotes here\n"),
		"bank/my bank.gpg": enc("b@nk\n"),
		"broken/entry.gpg": []byte("not encrypted"),
	})
	e.unlock(fixturePass)
	r := e.ok("import", "pass")
	mustContain(t, "import", r.stdout, "Imported 2 entries from", "Skipped 2:", "1 already in the vault", "1 decryption failed")
	want := "gl-pass\nusername: arsenii\nurl: https://gitlab.com\ntags: work, dev\nrecovery-email: me@example.com\notp: otpauth://totp/x?secret=ABC\n---\nnotes here\n"
	if got := e.ok("show", "work/gitlab").stdout; got != want {
		t.Errorf("imported entry:\n%q\nwant\n%q", got, want)
	}
	if got := e.ok("show", "work/github", "--field", "password").stdout; got != "kept" {
		t.Errorf("conflict was overwritten: %q", got)
	}
	if got := e.ok("show", "bank/my bank", "--field", "password").stdout; got != "b@nk" {
		t.Errorf("bank/my bank: %q", got)
	}
	// One save: one automatic backup since the fixture entries were added.
	if r := e.ok("backups"); strings.Count(r.stdout, "\n") != 2 {
		t.Errorf("backups after one import (want 2: the fixture's add and the import):\n%s", r.stdout)
	}
	r = e.ok("import", "pass", "--overwrite")
	mustContain(t, "import --overwrite", r.stdout, "Imported 3 entries (3 replacing entries already in the vault)")
	if got := e.ok("show", "work/github", "--field", "password").stdout; got != "other" {
		t.Errorf("--overwrite: %q", got)
	}
	e.ok("lock")
}
