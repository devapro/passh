package importpass

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

const outsideSecret = "OUTSIDE-SECRET-must-never-be-imported"

// testGPG makes sure gpg never waits for a terminal in the tests.
var testGPG = GPG{Program: "gpg", Args: []string{"--batch"}}

type storeFile struct {
	name      string
	plaintext string // encrypted with the test key
	raw       []byte // written as is
	link      string // a symlink with this target
	fifo      bool
}

func writeStore(t *testing.T, dir string, files []storeFile) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f.name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		var err error
		switch {
		case f.link != "":
			err = os.Symlink(f.link, p)
		case f.fifo:
			err = syscall.Mkfifo(p, 0o600)
		case f.raw != nil:
			err = os.WriteFile(p, f.raw, 0o600)
		default:
			err = os.WriteFile(p, encrypt(t, f.plaintext), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// snapshot describes every file under dir without following symlinks or
// opening anything but regular files.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		desc := fmt.Sprintf("%v %d %d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			desc += " -> " + target
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			desc += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		m[p] = desc
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func itemPaths(r *Result) []string {
	var out []string
	for _, it := range r.Items {
		out = append(out, it.Path.String())
	}
	return out
}

func skipsOf(r *Result) map[string]Reason {
	m := map[string]Reason{}
	for _, s := range r.Skipped {
		m[s.File] = s.Reason
	}
	return m
}

// fullStore is a pass store with everything import must handle. The
// folder "outside" next to the store holds a valid entry that symlinks in
// the store point to.
func fullStore(t *testing.T) (store, outside string) {
	t.Helper()
	base := t.TempDir()
	store = filepath.Join(base, "store")
	outside = filepath.Join(base, "outside")
	writeStore(t, outside, []storeFile{
		{name: "secret.gpg", plaintext: outsideSecret + "\nuser: mallory\n"},
		{name: "dir/other.gpg", plaintext: outsideSecret + "\n"},
	})
	tampered := encrypt(t, "tampered-pw\n")
	tampered[len(tampered)-10] ^= 0x55
	writeStore(t, store, []storeFile{
		{name: ".gpg-id", raw: []byte(testUID + "\n")},
		{name: ".git/config", raw: []byte("[core]\n")},
		{name: ".git/objects/x.gpg", plaintext: "git-object\n"},
		{name: ".hidden.gpg", plaintext: "hidden\n"},
		{name: ".extensions/otp.bash", raw: []byte("#!/bin/bash\n")},
		{name: "email/personal.gpg", plaintext: "pw1\nuser: alice\nurl: https://mail.test\ntags: mail, personal\nrecovery: r@x.test\n---\nnote line\n"},
		{name: "work/dev/github.gpg", plaintext: "pw2\nlogin: bob\notpauth://totp/GH:bob?secret=JBSWY3DPEHPK3PXP\npin: 1234\nSome notes\nmore notes\n\n"},
		{name: "top.gpg", plaintext: "toppw\n"},
		{name: "existing.gpg", plaintext: "existing-pw\n"},
		{name: "café/ünïcode.gpg", plaintext: "unicode-pw\n"},
		{name: "README.md", raw: []byte("not an entry\n")},
		{name: "notes.txt.gpg.bak", raw: []byte("backup\n")},
		{name: "-oops.gpg", plaintext: "oops\n"},
		{name: "bad/-x/y.gpg", plaintext: "bad\n"},
		{name: "corrupt.gpg", raw: []byte("this is not OpenPGP data\n")},
		{name: "truncated.gpg", raw: encrypt(t, "truncated\n")[:40]},
		{name: "tampered.gpg", raw: tampered},
		{name: "binary.gpg", plaintext: "\xff\xfe binary \x00 data"},
		{name: "fifo.gpg", fifo: true},
		// symlinks
		{name: "alias.gpg", link: "email/personal.gpg"},               // inside: allowed
		{name: "work/alias2.gpg", link: "../top.gpg"},                 // inside via ..: allowed
		{name: "outside.gpg", link: "../outside/secret.gpg"},          // relative, leads outside
		{name: "abs.gpg", link: filepath.Join(outside, "secret.gpg")}, // absolute
		{name: "sneaky/deep.gpg", link: "../../outside/secret.gpg"},   // from a subfolder
		{name: "chain.gpg", link: "work/outlink.gpg"},                 // inside, then outside
		{name: "work/outlink.gpg", link: "../../outside/secret.gpg"},  // leads outside
		{name: "outdir", link: "../outside/dir"},                      // a folder outside
		{name: "indir", link: "work"},                                 // a folder inside
		{name: "dangling.gpg", link: "nothing-here.gpg"},              // broken
		{name: "fifolink.gpg", link: "fifo.gpg"},                      // to a FIFO
		{name: "readme-link", link: "README.md"},                      // not .gpg, inside: ignored
		{name: ".dotlink.gpg", link: "../outside/secret.gpg"},         // dot-file: ignored
	})
	return store, outside
}

func TestImportFullStore(t *testing.T) {
	needGPG(t)
	store, outside := fullStore(t)
	before, beforeOutside := snapshot(t, store), snapshot(t, outside)

	var progress []string
	res, err := Run(t.Context(), Options{
		Dir:      store,
		Exists:   func(p paths.Path) bool { return p.String() == "existing" },
		Progress: func(n, total int, file string) { progress = append(progress, fmt.Sprintf("%d/%d %s", n, total, file)) },
		GPG:      testGPG,
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Dir != store || res.DryRun {
		t.Errorf("result header: %q %v", res.Dir, res.DryRun)
	}
	wantPaths := []string{"alias", "café/ünïcode", "email/personal", "top", "work/alias2", "work/dev/github"}
	if got := itemPaths(res); !slices.Equal(got, wantPaths) {
		t.Errorf("imported %q,\nwant %q", got, wantPaths)
	}
	wantSkips := map[string]Reason{
		"-oops.gpg":        InvalidPath,
		"bad/-x/y.gpg":     InvalidPath,
		"existing.gpg":     Conflict,
		"outside.gpg":      SymlinkOutside,
		"abs.gpg":          SymlinkOutside,
		"sneaky/deep.gpg":  SymlinkOutside,
		"chain.gpg":        SymlinkOutside,
		"work/outlink.gpg": SymlinkOutside,
		"outdir":           SymlinkOutside,
		"indir":            SymlinkFolder,
		"dangling.gpg":     BrokenSymlink,
		"fifo.gpg":         NotRegular,
		"fifolink.gpg":     NotRegular,
		"corrupt.gpg":      DecryptFailed,
		"truncated.gpg":    DecryptFailed,
		"tampered.gpg":     DecryptFailed,
		"binary.gpg":       NotAnEntry,
	}
	if got := skipsOf(res); !reflect.DeepEqual(got, wantSkips) {
		t.Errorf("skipped:\n%v\nwant\n%v", got, wantSkips)
	}
	if !slices.IsSortedFunc(res.Skipped, func(a, b Skip) int { return strings.Compare(a.File, b.File) }) {
		t.Error("skips are not sorted")
	}
	for _, s := range res.Skipped {
		if s.Reason == InvalidPath && s.Detail != paths.ErrDashSegment.Error() {
			t.Errorf("%s: detail %q", s.File, s.Detail)
		}
		if s.Reason == SymlinkOutside && s.Detail != "not followed" {
			t.Errorf("%s: detail %q", s.File, s.Detail)
		}
	}
	if got := res.SkippedBy(); got[SymlinkOutside] != 6 || got[DecryptFailed] != 3 || got[InvalidPath] != 2 {
		t.Errorf("SkippedBy = %v", got)
	}

	// Only files in the store were decrypted: never one behind a symlink
	// leading outside (§13.2 test 1), never a dot-file.
	for _, p := range progress {
		if strings.Contains(p, "outside") || strings.Contains(p, "abs") || strings.Contains(p, "deep") ||
			strings.Contains(p, "chain") || strings.Contains(p, "outlink") || strings.Contains(p, "/.") || strings.Contains(p, " .") {
			t.Errorf("decrypted %s", p)
		}
	}
	if len(progress) != 10 || progress[0] != "1/10 alias.gpg" || progress[9] != "10/10 work/dev/github.gpg" {
		t.Errorf("progress = %q", progress)
	}

	entries := res.Entries()
	for _, e := range entries {
		if strings.Contains(fmt.Sprintf("%+v", e), "OUTSIDE") {
			t.Errorf("%s holds the outside secret", e.Path)
		}
	}
	byPath := map[string]model.Entry{}
	for _, e := range entries {
		byPath[e.Path.String()] = e
	}
	personal := byPath["email/personal"]
	if personal.Password != "pw1" || personal.Username != "alice" || personal.URL != "https://mail.test" ||
		!slices.Equal(personal.Tags, []string{"mail", "personal"}) ||
		!reflect.DeepEqual(fieldPairs(personal), [][2]string{{"recovery", "r@x.test"}}) ||
		personal.Notes != "note line" {
		t.Errorf("email/personal = %+v", personal)
	}
	if a := byPath["alias"]; a.Password != "pw1" || a.Username != "alice" {
		t.Errorf("alias = %+v", a)
	}
	if a := byPath["work/alias2"]; a.Password != "toppw" {
		t.Errorf("work/alias2 = %+v", a)
	}
	gh := byPath["work/dev/github"]
	if gh.Password != "pw2" || gh.Username != "bob" ||
		!reflect.DeepEqual(fieldPairs(gh), [][2]string{{"otp", "otpauth://totp/GH:bob?secret=JBSWY3DPEHPK3PXP"}, {"pin", "1234"}}) ||
		gh.Notes != "Some notes\nmore notes" {
		t.Errorf("work/dev/github = %+v", gh)
	}
	if u := byPath["café/ünïcode"]; u.Password != "unicode-pw" {
		t.Errorf("unicode entry = %+v", u)
	}
	for _, e := range entries {
		if e.ID != "" || !e.CreatedAt.IsZero() {
			t.Errorf("%s: id or time set", e.Path)
		}
	}

	// The entries go into the vault in one go.
	d := model.NewData()
	for _, e := range entries {
		if _, err := d.Add(e, testNow, false); err != nil {
			t.Fatalf("Add(%s): %v", e.Path, err)
		}
	}

	if after := snapshot(t, store); !reflect.DeepEqual(before, after) {
		t.Error("the store changed")
	}
	if after := snapshot(t, outside); !reflect.DeepEqual(beforeOutside, after) {
		t.Error("the folder outside changed")
	}
}

func fieldPairs(e model.Entry) [][2]string {
	var out [][2]string
	for _, f := range e.Fields {
		out = append(out, [2]string{f.Key, f.Value})
	}
	return out
}

func TestImportOverwrite(t *testing.T) {
	needGPG(t)
	store := t.TempDir()
	writeStore(t, store, []storeFile{
		{name: "a.gpg", plaintext: "new-a\n"},
		{name: "b.gpg", plaintext: "new-b\n"},
	})
	exists := func(p paths.Path) bool { return p.String() == "a" }

	res, err := Run(t.Context(), Options{Dir: store, Exists: exists, GPG: testGPG})
	if err != nil {
		t.Fatal(err)
	}
	if got := itemPaths(res); !slices.Equal(got, []string{"b"}) {
		t.Errorf("without --overwrite: %q", got)
	}
	if s := res.Skipped[0]; s.File != "a.gpg" || s.Reason != Conflict || s.Detail != "use --overwrite to replace it" {
		t.Errorf("skipped = %+v", res.Skipped)
	}

	res, err = Run(t.Context(), Options{Dir: store, Exists: exists, Overwrite: true, GPG: testGPG})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 2 || !res.Items[0].Replace || res.Items[1].Replace || len(res.Skipped) != 0 {
		t.Fatalf("with --overwrite: %+v", res)
	}
	if res.Items[0].Entry.Password != "new-a" {
		t.Errorf("a = %+v", res.Items[0].Entry)
	}
}

func TestDryRunStartsNoGPG(t *testing.T) {
	needGPG(t)
	store, _ := fullStore(t)
	before := snapshot(t, store)
	marker := filepath.Join(t.TempDir(), "gpg-ran")
	fake := writeScript(t, "#!/bin/sh\ntouch '"+marker+"'\nexit 1\n")

	for _, program := range []string{"/nonexistent/gpg", fake} {
		var calls int
		res, err := Run(t.Context(), Options{
			Dir:      store,
			DryRun:   true,
			Exists:   func(p paths.Path) bool { return p.String() == "existing" },
			Progress: func(int, int, string) { calls++ },
			GPG:      GPG{Program: program},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.DryRun || calls != 0 {
			t.Errorf("DryRun %v, progress calls %d", res.DryRun, calls)
		}
		// Without decrypting, damaged files can't be told apart.
		want := []string{"alias", "binary", "café/ünïcode", "corrupt", "email/personal", "tampered", "top", "truncated", "work/alias2", "work/dev/github"}
		if got := itemPaths(res); !slices.Equal(got, want) {
			t.Errorf("would import %q", got)
		}
		for _, it := range res.Items {
			if it.Entry.Password != "" || !it.Entry.Path.IsZero() {
				t.Errorf("%s: dry run has content", it.Path)
			}
		}
		if res.Entries() != nil {
			t.Error("Entries() in a dry run")
		}
		skips := skipsOf(res)
		if skips["existing.gpg"] != Conflict || skips["outside.gpg"] != SymlinkOutside || skips["-oops.gpg"] != InvalidPath {
			t.Errorf("skips = %v", skips)
		}
		for _, r := range skips {
			if r == DecryptFailed || r == NotAnEntry {
				t.Errorf("a dry run reports %v", r)
			}
		}
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a dry run started gpg")
	}
	if after := snapshot(t, store); !reflect.DeepEqual(before, after) {
		t.Error("the store changed")
	}
}

func TestNoGPG(t *testing.T) {
	store := t.TempDir()
	writeStore(t, store, []storeFile{{name: "a.gpg", raw: []byte("x")}})
	_, err := Run(t.Context(), Options{Dir: store, GPG: GPG{Program: "/nonexistent/gpg"}})
	if !errors.Is(err, ErrNoGPG) {
		t.Errorf("error = %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := Run(t.Context(), Options{Dir: store}); !errors.Is(err, ErrNoGPG) {
		t.Errorf("error = %v", err)
	}
	// Nothing to decrypt: gpg isn't needed.
	empty := t.TempDir()
	writeStore(t, empty, []storeFile{{name: ".gpg-id", raw: []byte("x\n")}, {name: "README", raw: []byte("x")}})
	res, err := Run(t.Context(), Options{Dir: empty})
	if err != nil || len(res.Items) != 0 || len(res.Skipped) != 0 {
		t.Errorf("empty store: %+v, %v", res, err)
	}
}

func TestStoreMissing(t *testing.T) {
	_, err := Run(t.Context(), Options{Dir: filepath.Join(t.TempDir(), "nope")})
	if err == nil || !strings.Contains(err.Error(), "pass store") {
		t.Errorf("error = %v", err)
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := Run(t.Context(), Options{Dir: f}); err == nil {
		t.Error("a file as the store")
	}
}

func TestStoreDir(t *testing.T) {
	home := os.Getenv("HOME")
	t.Setenv(EnvStoreDir, "")
	if d, err := StoreDir(""); err != nil || d != filepath.Join(home, ".password-store") {
		t.Errorf("default = %q, %v", d, err)
	}
	t.Setenv(EnvStoreDir, "~/elsewhere")
	if d, err := StoreDir(""); err != nil || d != filepath.Join(home, "elsewhere") {
		t.Errorf("env = %q, %v", d, err)
	}
	if d, err := StoreDir("/abs/store/"); err != nil || d != "/abs/store" {
		t.Errorf("arg = %q, %v", d, err)
	}
	wd, _ := os.Getwd()
	if d, err := StoreDir("rel"); err != nil || d != filepath.Join(wd, "rel") {
		t.Errorf("relative arg = %q, %v", d, err)
	}
	t.Setenv("HOME", "")
	t.Setenv(EnvStoreDir, "")
	if _, err := StoreDir(""); err == nil {
		t.Error("no $HOME: no error")
	}
}

// TestDefaultStoreDir imports from $PASSWORD_STORE_DIR with gpg's default
// options (no --batch).
func TestDefaultStoreDir(t *testing.T) {
	needGPG(t)
	store := t.TempDir()
	writeStore(t, store, []storeFile{{name: "x/y.gpg", plaintext: "pw\ntags: a\n"}})
	t.Setenv(EnvStoreDir, store)
	res, err := Run(t.Context(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].Entry.Password != "pw" || !slices.Equal(res.Items[0].Entry.Tags, []string{"a"}) {
		t.Errorf("result = %+v", res)
	}
}

func TestDuplicatePath(t *testing.T) {
	store := t.TempDir()
	// The same name in NFC and NFD gives one path.
	writeStore(t, store, []storeFile{
		{name: "café.gpg", raw: []byte("x")},
		{name: "café.gpg", raw: []byte("x")},
	})
	if _, err := os.Stat(filepath.Join(store, "café.gpg")); err != nil {
		t.Skip("the file system normalizes names")
	}
	ents, _ := os.ReadDir(store)
	if len(ents) != 2 {
		t.Skip("the file system normalizes names")
	}
	res, err := Run(t.Context(), Options{Dir: store, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || len(res.Skipped) != 1 || res.Skipped[0].Reason != DuplicatePath ||
		!strings.HasPrefix(res.Skipped[0].Detail, "same path as ") {
		t.Errorf("result = %+v", res)
	}
}

func TestUnreadableFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	store := t.TempDir()
	writeStore(t, store, []storeFile{
		{name: "ok.gpg", raw: []byte("x")},
		{name: "locked/a.gpg", raw: []byte("x")},
		{name: "noperm.gpg", raw: []byte("x")},
	})
	locked := filepath.Join(store, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	noperm := filepath.Join(store, "noperm.gpg")
	if err := os.Chmod(noperm, 0); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{Dir: store, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := skipsOf(res); got["locked"] != Unreadable {
		t.Errorf("skips = %v", got)
	}

	// A file that can't be read is skipped when it is read.
	fake := writeScript(t, "#!/bin/sh\ncat >/dev/null\nprintf 'pw\\n'\necho '[GNUPG:] DECRYPTION_OKAY' >&3\n")
	res, err = Run(t.Context(), Options{Dir: store, GPG: GPG{Program: fake}})
	if err != nil {
		t.Fatal(err)
	}
	if got := skipsOf(res); got["noperm.gpg"] != Unreadable || got["locked"] != Unreadable {
		t.Errorf("skips = %v", got)
	}
	if got := itemPaths(res); !slices.Equal(got, []string{"ok"}) {
		t.Errorf("items = %q", got)
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	big, err := os.Create(filepath.Join(dir, "big"))
	if err != nil {
		t.Fatal(err)
	}
	big.Truncate(maxCiphertext + 1)
	big.Close()
	os.WriteFile(filepath.Join(dir, "ok"), []byte("data"), 0o600)
	os.Symlink("../escape", filepath.Join(dir, "escape"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// A FIFO doesn't block the open.
	if _, r, _ := readFile(root, "fifo"); r != NotRegular {
		t.Errorf("fifo: %v", r)
	}
	if _, r, _ := readFile(root, "big"); r != TooLarge {
		t.Errorf("big: %v", r)
	}
	if _, r, d := readFile(root, "escape"); r != Unreadable || !strings.Contains(d.String(), "escapes") {
		t.Errorf("escape: %v %q", r, d)
	}
	if b, r, _ := readFile(root, "ok"); r != 0 || string(b) != "data" {
		t.Errorf("ok: %q %v", b, r)
	}
}

func TestReasonString(t *testing.T) {
	for r := InvalidPath; r <= NotAnEntry; r++ {
		if s := r.String(); s == "" || strings.HasPrefix(s, "Reason(") {
			t.Errorf("%d has no name", r)
		}
	}
	if Reason(99).String() != "Reason(99)" {
		t.Error(Reason(99).String())
	}
}
