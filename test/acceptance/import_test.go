package acceptance

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// gpgStore is a real pass store encrypted with a throw-away gpg key in a
// short temporary GNUPGHOME.
type gpgStore struct {
	home    string // GNUPGHOME
	store   string // the pass store
	outside string // a folder next to it that symlinks point to
	wrapDir string // holds a logging gpg wrapper
	log     string // the wrapper's log of gpg invocations
}

func gpgCmd(t *testing.T, home string, stdin string, args ...string) string {
	t.Helper()
	c := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--yes", "--quiet"}, args...)...)
	c.Env = []string{"GNUPGHOME=" + home, "PATH=/usr/bin:/bin", "HOME=" + home, "LANG=C"}
	c.Stdin = strings.NewReader(stdin)
	out, err := c.Output()
	if err != nil {
		var se string
		if ee, ok := err.(*exec.ExitError); ok {
			se = string(ee.Stderr)
		}
		t.Fatalf("gpg %v: %v\n%s", args, err, se)
	}
	return string(out)
}

// passEntries are the store's files (path without .gpg → plaintext).
var passEntries = map[string]string{
	"work/github":                "gh-pass-123\nusername: octo\nurl: https://github.com\ntags: work, dev\nrecovery-email: me@example.com\nrecovery-email: alt@example.com\n---\nfree notes\nmore notes",
	"bank/chase":                 "ch@se!\nlogin: bob\nurl: https://chase.com\n",
	"mail/fastmail":              "fm-pw\nuser: alice\notpauth://totp/Fastmail:alice?secret=JBSWY3DPEHPK3PXP&issuer=Fastmail\npin: 1234\n",
	"mail/twootp":                "two-pw\notp: otpauth://totp/A?secret=AAAAAAAA\notpauth://totp/B?secret=BBBBBBBB\n",
	"deep/a/b/c/leaf":            "leafpw\n",
	"folder with space/the name": "sp-pw\nnot a key value line\nusername: late\n",
	".git/objects/x":             "in-git\n",
	".hidden":                    "hidden\n",
	".extensions/ext":            "ext\n",
	"-dash":                      "dash\n",
	"bad\x1b[31mname":            "bad\n",
}

func makeGPGStore(t *testing.T) *gpgStore {
	t.Helper()
	return makeGPGStoreWith(t, passEntries, true)
}

// makeGPGStoreWith makes a pass store holding entries (path → plaintext),
// and, if links, symlinks that lead out of the store.
func makeGPGStoreWith(t *testing.T, entries map[string]string, links bool) *gpgStore {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	home, err := os.MkdirTemp("/tmp", "pg")
	if err != nil {
		t.Fatal(err)
	}
	g := &gpgStore{home: home}
	t.Cleanup(func() {
		for _, a := range [][]string{{"--kill", "all"}, {"--remove-socketdir"}} {
			c := exec.Command("gpgconf", a...)
			c.Env = []string{"GNUPGHOME=" + home, "PATH=/usr/bin:/bin", "HOME=" + home}
			_ = c.Run()
		}
		_ = os.RemoveAll(home)
	})
	gpgCmd(t, home, "", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", "passh test <test@example.invalid>", "future-default", "default", "never")
	var fpr string
	for _, l := range strings.Split(gpgCmd(t, home, "", "--with-colons", "--list-keys"), "\n") {
		if strings.HasPrefix(l, "fpr:") {
			fpr = strings.Split(l, ":")[9]
			break
		}
	}
	if fpr == "" {
		t.Fatal("no gpg fingerprint")
	}
	root := filepath.Join(home, "x")
	g.store = filepath.Join(root, "store")
	g.outside = filepath.Join(root, "outside")
	writeFile(t, filepath.Join(g.store, ".gpg-id"), []byte(fpr+"\n"), 0o600)
	writeFile(t, filepath.Join(g.store, "README.md"), []byte("not an entry\n"), 0o600)
	enc := func(file, plain string) {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		gpgCmd(t, home, plain, "--trust-model", "always", "-r", fpr, "-e", "-o", file)
	}
	for p, plain := range entries {
		enc(filepath.Join(g.store, p+".gpg"), plain)
	}
	if links {
		// Outside the store, reached only through symlinks (§4.9, §13.2.1).
		enc(filepath.Join(g.outside, "secret.gpg"), "OUTSIDE-SECRET\n")
		enc(filepath.Join(g.outside, "sub", "deep.gpg"), "OUTSIDE-DEEP\n")
		for link, target := range map[string]string{
			"evil.gpg":      "../outside/secret.gpg",
			"abs.gpg":       filepath.Join(g.outside, "secret.gpg"),
			"linkdir":       "../outside",
			"work/up.gpg":   "../../outside/secret.gpg",
			"work/linkdir2": filepath.Join(g.outside, "sub"),
		} {
			if err := os.Symlink(target, filepath.Join(g.store, link)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A gpg wrapper that logs its arguments (S8 check) and runs the real one.
	g.wrapDir = filepath.Join(root, "wrap")
	g.log = filepath.Join(root, "gpg.log")
	writeFile(t, filepath.Join(g.wrapDir, "gpg"), []byte("#!/bin/sh\nprintf '%s\\n' \"ARGS: $*\" >> "+g.log+"\nexec /usr/bin/gpg \"$@\"\n"), 0o755)
	return g
}

// treeSum hashes every file and link of a folder.
func treeSum(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[p] = "link:" + l
		case info.Mode().IsRegular():
			b, _ := os.ReadFile(p)
			out[p] = fmt.Sprintf("%x %o", sha256.Sum256(b), info.Mode().Perm())
		default:
			out[p] = fmt.Sprintf("dir %o", info.Mode().Perm())
		}
		return nil
	})
	return out
}

// §13.1.2 and §13.2.1 (symlinks): a real pass store imports with folders,
// tags, extra fields and otpauth://; symlinks out of the store are not
// followed; afterwards passh works without gpg.
func TestF2_ImportPass(t *testing.T) {
	g := makeGPGStore(t)
	f := fixtures(t)
	e := newEnv(t)
	e.installVault(f.empty, "")
	e.gnupg = g.home
	e.path = g.wrapDir + ":" + binDir + ":/usr/bin:/bin"
	e.pstore = g.store
	before := treeSum(t, g.store)
	outsideBefore := treeSum(t, g.outside)

	e.unlock(fixPass)
	defer e.lock()
	e.ok("generate", "bank/chase", "12") // a conflict

	// --dry-run decrypts nothing, uses $PASSWORD_STORE_DIR, shows conflicts.
	r := e.ok("import", "pass", "--dry-run")
	if b, _ := os.ReadFile(g.log); strings.Contains(string(b), "--decrypt") {
		t.Errorf("--dry-run ran gpg --decrypt:\n%s", b)
	}
	mustContain(t, "dry run", r.stdout, "work/github", "deep/a/b/c/leaf", "bank/chase")
	mustNotContain(t, "dry run", r.all(), "gh-pass-123", "OUTSIDE")

	r = e.ok("import", "pass", g.store)
	out := r.all()
	mustNotContain(t, "import report", out, "\x1b", "OUTSIDE")
	mustContain(t, "import report (skipped and why, §4.9)", out, "-dash", "bank/chase")

	// S8: gpg runs with --status-fd and --decrypt; the store isn't changed.
	logb, _ := os.ReadFile(g.log)
	if !strings.Contains(string(logb), "--status-fd") || !strings.Contains(string(logb), "--decrypt") {
		t.Errorf("gpg invocations without --status-fd/--decrypt:\n%s", logb)
	}
	if after := treeSum(t, g.store); !mapsEqual(before, after) || !mapsEqual(outsideBefore, treeSum(t, g.outside)) {
		t.Errorf("import pass changed the pass store")
	}

	// §13.2.2: the decrypted values went through pipes, not files.
	for p, b := range walkFiles(e.root) {
		if strings.HasPrefix(p, g.home) {
			continue
		}
		for _, v := range []string{"gh-pass-123", "JBSWY3DPEHPK3PXP", "free notes", "ch@se!"} {
			if strings.Contains(string(b), v) {
				t.Errorf("after import pass, %s holds the imported value %q", p, v)
			}
		}
	}

	// Now without gpg on PATH.
	e.path = binDir
	r = e.ok("export", "--format", "json", "--confirm-plaintext")
	var d vData
	if err := json.Unmarshal([]byte(r.stdout), &d); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, en := range d.Entries {
		got = append(got, en.Path)
	}
	sort.Strings(got)
	want := []string{"bank/chase", "deep/a/b/c/leaf", "folder with space/the name", "mail/fastmail", "mail/twootp", "work/github"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("imported paths = %q, want %q (dot-folders, invalid paths and symlinks out of the store skipped)", got, want)
	}
	for _, en := range d.Entries {
		if strings.Contains(en.Password, "OUTSIDE") {
			t.Errorf("an entry from outside the store was imported through a symlink: %s", en.Path)
		}
	}
	gh, _ := d.entry("work/github")
	if gh.Password != "gh-pass-123" || gh.Username != "octo" || gh.URL != "https://github.com" ||
		strings.Join(gh.Tags, ",") != "work,dev" || gh.Notes != "free notes\nmore notes" ||
		len(gh.Fields) != 2 || gh.Fields[0] != (vField{"recovery-email", "me@example.com"}) || gh.Fields[1] != (vField{"recovery-email", "alt@example.com"}) {
		t.Errorf("work/github imported as %+v", gh)
	}
	ch, _ := d.entry("bank/chase")
	if ch.Password == "ch@se!" {
		t.Errorf("bank/chase was overwritten without --overwrite")
	}
	fm, _ := d.entry("mail/fastmail")
	otp := ""
	pin := ""
	for _, fl := range fm.Fields {
		switch fl.Key {
		case "otp":
			otp = fl.Value
		case "pin":
			pin = fl.Value
		}
	}
	if fm.Username != "alice" || !strings.HasPrefix(otp, "otpauth://totp/Fastmail:alice") || pin != "1234" {
		t.Errorf("mail/fastmail imported as %+v (want user: → username, otpauth:// → otp field)", fm)
	}
	sp, _ := d.entry("folder with space/the name")
	if sp.Username != "" || sp.Notes != "not a key value line\nusername: late" {
		t.Errorf("metadata must end at the first non key: value line (§4.3): %+v", sp)
	}
	// §7.1 mapping: Bitwarden gets the first otp as login.totp, other
	// fields as custom fields (hidden when secret), tags as "tags"; CSV
	// leaves custom fields out with a warning.
	r = e.ok("export", "--format", "bitwarden-json", "--confirm-plaintext")
	checkBitwarden(t, []byte(r.stdout), &d)
	var bw struct {
		Folders []struct{ ID, Name string }
		Items   []struct {
			Name     string
			FolderID *string `json:"folderId"`
			Login    struct {
				TOTP *string `json:"totp"`
			}
			Fields []struct {
				Name, Value string
				Type        int
			}
		}
	}
	if err := json.Unmarshal([]byte(r.stdout), &bw); err != nil {
		t.Fatal(err)
	}
	folders := map[string]string{}
	for _, fo := range bw.Folders {
		folders[fo.ID] = fo.Name
	}
	for _, it := range bw.Items {
		path := it.Name
		if it.FolderID != nil {
			path = folders[*it.FolderID] + "/" + it.Name
		}
		fields := map[string][]string{}
		types := map[string][]int{}
		for _, f := range it.Fields {
			fields[f.Name] = append(fields[f.Name], f.Value)
			types[f.Name] = append(types[f.Name], f.Type)
		}
		switch path {
		case "deep/a/b/c/leaf":
			if folders[*it.FolderID] != "deep/a/b/c" {
				t.Errorf("Bitwarden folder of %s = %q, want the path deep/a/b/c", path, folders[*it.FolderID])
			}
		case "mail/fastmail":
			if it.Login.TOTP == nil || !strings.HasPrefix(*it.Login.TOTP, "otpauth://totp/Fastmail") || len(fields["otp"]) != 0 {
				t.Errorf("Bitwarden %s: totp %v, otp fields %q", path, it.Login.TOTP, fields["otp"])
			}
			if strings.Join(fields["pin"], ",") != "1234" || types["pin"][0] != 0 {
				t.Errorf("Bitwarden %s: pin field %q types %v", path, fields["pin"], types["pin"])
			}
		case "mail/twootp":
			if it.Login.TOTP == nil || *it.Login.TOTP != "otpauth://totp/A?secret=AAAAAAAA" {
				t.Errorf("Bitwarden %s: the first otp field must be login.totp, got %v", path, it.Login.TOTP)
			}
			if len(fields["otp"]) != 1 || fields["otp"][0] != "otpauth://totp/B?secret=BBBBBBBB" || types["otp"][0] != 1 {
				t.Errorf("Bitwarden %s: the second otp must be a hidden custom field: %q %v", path, fields["otp"], types["otp"])
			}
		case "work/github":
			if strings.Join(fields["recovery-email"], ",") != "me@example.com,alt@example.com" || strings.Join(fields["tags"], "") != "work, dev" {
				t.Errorf("Bitwarden %s: fields %v", path, fields)
			}
		}
	}
	r = e.ok("export", "--format", "csv", "--confirm-plaintext")
	if !strings.Contains(r.stderr, "field") {
		t.Errorf("CSV export of entries with custom fields: no warning that they are left out: %q", r.stderr)
	}

	r = e.ok("show", "mail/fastmail", "--field", "otp")
	if !strings.HasPrefix(r.stdout, "otpauth://") {
		t.Errorf("show --field otp without gpg: %s", r)
	}
	r = e.ok("ls")
	mustContain(t, "ls without gpg", r.stdout, "deep/", "leaf", "the name")
	r = e.ok("ls", "--tag", "dev")
	mustContain(t, "ls --tag without gpg", r.stdout, "github")

	// --overwrite replaces the conflicting entry (gpg back on PATH).
	e.path = g.wrapDir + ":" + binDir + ":/usr/bin:/bin"
	e.ok("import", "pass", g.store, "--overwrite")
	e.path = binDir
	if r := e.ok("show", "bank/chase", "--field", "password"); r.stdout != "ch@se!" {
		t.Errorf("--overwrite didn't replace bank/chase: %q", r.stdout)
	}
	if r := e.ok("show", "bank/chase", "--field", "username"); r.stdout != "bob" {
		t.Errorf("login: must become username: %q", r.stdout)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
