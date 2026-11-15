package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vaultfile"
)

func TestCreateAndOpen(t *testing.T) {
	e := newEnv(t)
	if m := mode(t, e.path); m != 0o600 {
		t.Errorf("vault mode %o, want 600", m)
	}
	if m := mode(t, e.dir); m != 0o700 {
		t.Errorf("created vault folder mode %o, want 700", m)
	}
	v := e.open()
	info := v.Info()
	if info.Revision != FirstRevision || info.Entries != 0 || info.VaultID == "" {
		t.Fatalf("new vault info %+v", info)
	}
	if !info.SavedAt.Equal(clockStart.Add(time.Minute)) {
		t.Errorf("saved_at %v", info.SavedAt)
	}
	sum := sha256.Sum256(e.read())
	if info.SHA256 != hex.EncodeToString(sum[:]) || !info.Canonical || len(info.Warnings) != 0 {
		t.Errorf("info %+v", info)
	}
	if info.RealPath != e.path || info.Path != e.path {
		t.Errorf("paths %q %q", info.Path, info.RealPath)
	}
	// The file is canonical and its key block is the one given.
	f, err := vaultfile.Parse(e.read())
	if err != nil || !f.Canonical || !bytes.Equal(f.KeyBlock, e.keyBlock) {
		t.Fatalf("parse: %v canonical=%v", err, f != nil && f.Canonical)
	}
	// Nothing else in the vault's folder.
	if ents, _ := os.ReadDir(e.dir); len(ents) != 1 {
		t.Errorf("vault folder holds %d files", len(ents))
	}
	// The rollback record knows revision 1.
	rec, err := readRecord(e.state)
	if err != nil || rec.Vaults[info.VaultID].Revision != 1 {
		t.Errorf("record %+v, %v", rec, err)
	}

	// Create refuses an existing file, and a dangling symlink, without
	// running scrypt.
	start := time.Now()
	if _, err := Create(e.path, []byte(testPass), e.opts()); !errors.Is(err, ErrExists) {
		t.Errorf("Create over a vault: %v", err)
	}
	link := filepath.Join(e.dir, "dangling.passh")
	if err := os.Symlink(filepath.Join(e.dir, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(link, []byte(testPass), e.opts()); !errors.Is(err, ErrExists) {
		t.Errorf("Create over a symlink: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("refusing took %v: scrypt ran", d)
	}
}

func TestOpenMissing(t *testing.T) {
	_, err := Open(context.Background(), filepath.Join(t.TempDir(), "none.passh"), keys.FromIdentity(nil), Options{StateDir: t.TempDir()})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := Open(context.Background(), t.TempDir(), keys.FromIdentity(nil), Options{StateDir: t.TempDir()}); !errors.Is(err, ErrNotVault) {
		t.Fatalf("a folder: %v", err)
	}
}

func TestMutations(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	gh := mustAdd(t, v, "work/github", "pw1")
	mustAdd(t, v, "bank/visa", "pw2")
	if v.Info().Revision != 3 {
		t.Fatalf("revision %d after two adds", v.Info().Revision)
	}
	if got := entryPaths(v.Entries()); !slices.Equal(got, []string{"bank/visa", "work/github"}) {
		t.Fatalf("entries %v", got)
	}

	// Add refuses a taken path; nothing is saved.
	if _, err := v.Add(testEntry("work/github", "other"), false); !errors.Is(err, model.ErrExists) {
		t.Fatalf("add over: %v", err)
	}
	// Overwrite keeps the id.
	ow, err := v.Add(testEntry("work/github", "pw3"), true)
	if err != nil || ow.ID != gh.ID || ow.Password != "pw3" {
		t.Fatalf("overwrite: %+v %v", ow, err)
	}
	// The same content again changes nothing and saves nothing.
	rev := v.Info().Revision
	if _, err := v.Add(testEntry("work/github", "pw3"), true); err != nil || v.Info().Revision != rev {
		t.Fatalf("no-op overwrite: rev %d → %d, %v", rev, v.Info().Revision, err)
	}

	// Put: no id adds, an id updates (and moves).
	if err := v.Put(testEntry("work/jira", "pw4")); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(testEntry("work/jira", "pw5")); !errors.Is(err, model.ErrExists) {
		t.Fatalf("put without id over a taken path: %v", err)
	}
	cur, _ := v.Get(paths.MustParse("work/github"))
	cur.Path = paths.MustParse("dev/github")
	cur.Notes = "moved"
	if err := v.Put(cur); err != nil {
		t.Fatal(err)
	}
	if got, ok := v.GetByID(gh.ID); !ok || got.Path.String() != "dev/github" || got.Notes != "moved" {
		t.Fatalf("after put: %+v", got)
	}
	// Update without a change saves nothing.
	rev = v.Info().Revision
	if changed, err := v.Update(cur); err != nil || changed || v.Info().Revision != rev {
		t.Fatalf("no-op update: %v %v", changed, err)
	}

	if err := v.Move(paths.MustParse("dev/github"), paths.MustParse("work/github")); err != nil {
		t.Fatal(err)
	}
	if err := v.Move(paths.MustParse("nope"), paths.MustParse("x")); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("move missing: %v", err)
	}
	if err := v.Remove(paths.MustParse("bank/visa")); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove(paths.MustParse("bank/visa")); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}
	snap := v.Snapshot()
	if len(snap.Deleted) != 1 {
		t.Fatalf("tombstones %+v", snap.Deleted)
	}

	// Tags.
	te, changed, err := v.EditTags(paths.MustParse("work/github"), []string{" dev ", "2fa"}, []string{"t-pw3"})
	if err != nil || !changed || !slices.Equal(te.Tags, []string{"dev", "2fa"}) {
		t.Fatalf("tags: %v %v %v", te.Tags, changed, err)
	}
	rev = v.Info().Revision
	if _, changed, err := v.EditTags(paths.MustParse("work/github"), nil, []string{"absent"}); err != nil || changed || v.Info().Revision != rev {
		t.Fatalf("no-op tags: %v %v", changed, err)
	}
	if _, _, err := v.EditTags(paths.MustParse("work/github"), []string{"a,b"}, nil); !errors.Is(err, model.ErrInvalidTag) {
		t.Fatalf("bad tag: %v", err)
	}
	if _, _, err := v.EditTags(paths.MustParse("nope"), []string{"x"}, nil); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("tags of a missing entry: %v", err)
	}

	// Apply: one revision for many changes; an error saves nothing.
	rev = v.Info().Revision
	err = v.Apply(func(d *model.Data, now time.Time) (bool, error) {
		for _, p := range []string{"imp/a", "imp/b", "imp/c"} {
			if _, err := d.Add(testEntry(p, "x"), now, false); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err != nil || v.Info().Revision != rev+1 || v.Info().Entries != 5 {
		t.Fatalf("apply: %v rev %d entries %d", err, v.Info().Revision, v.Info().Entries)
	}
	boom := errors.New("boom")
	if err := v.Apply(func(d *model.Data, now time.Time) (bool, error) {
		d.Entries = nil
		return true, boom
	}); err != boom || v.Info().Entries != 5 { //nolint:errorlint // asserts that fn's error comes back unwrapped
		t.Fatalf("failed apply: %v, %d entries", err, v.Info().Entries)
	}

	// Everything is on disk: a fresh open sees the same data.
	w := e.open()
	if !slices.EqualFunc(w.Entries(), v.Entries(), model.Entry.Equal) || w.Info().Revision != v.Info().Revision {
		t.Fatal("reopened vault differs")
	}
	// Times come from the clock.
	if got, _ := w.Get(paths.MustParse("imp/a")); !got.CreatedAt.After(clockStart) {
		t.Errorf("created_at %v", got.CreatedAt)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	s := v.Snapshot()
	s.Entries[0].Password = "changed"
	s.Entries = nil
	if got, _ := v.Get(paths.MustParse("a")); got.Password != "pw" {
		t.Fatal("Snapshot shares memory with the vault")
	}
	list := v.Entries()
	list[0].Tags[0] = "changed"
	if got, _ := v.Get(paths.MustParse("a")); got.Tags[0] != "t-pw" {
		t.Fatal("Entries shares memory with the vault")
	}
}

// Unknown keys written by a newer passh survive a save (§4.2).
func TestUnknownKeysKept(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	plain := `{"format":"passh-vault-data","version":1,"vault_id":"` + v.Info().VaultID + `","revision":7,` +
		`"saved_at":"2026-11-15T12:00:00Z","future":{"x":[1,2]},"entries":[{"id":"e1","path":"a","password":"p","later":true}],"deleted":[]}`
	db, err := keys.EncryptData(e.key, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(e.keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	e.write(file)
	v = e.open()
	mustAdd(t, v, "b", "pw")
	f, _ := vaultfile.Parse(e.read())
	got, err := keys.DecryptData(e.key, f.DataBlock)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"future": {`, `"later": true`, `"revision": 8`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("saved data lacks %s:\n%s", want, got)
		}
	}
}

func TestNewerDataVersion(t *testing.T) {
	e := newEnv(t)
	db, err := keys.EncryptData(e.key, []byte(`{"format":"passh-vault-data","version":2}`))
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(e.keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	e.write(file)
	_, err = Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	var oe *OpenError
	if !errors.As(err, &oe) || !errors.Is(err, ErrNewer) || !strings.Contains(err.Error(), "made by a newer passh; upgrade passh") {
		t.Fatalf("newer data: %v", err)
	}
}

// Opening never writes the vault file, even a non-canonical copy, and
// passes the parser's warnings on.
func TestOpenDoesNotWrite(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	crlf := append([]byte("From: someone\r\n\r\n"), bytes.ReplaceAll(e.read(), []byte("\n"), []byte("\r\n"))...)
	e.write(crlf)
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(e.path, old, old); err != nil {
		t.Fatal(err)
	}
	e.take()
	w := e.open()
	if w.Info().Canonical || len(w.Info().Warnings) != 1 {
		t.Errorf("info %+v", w.Info())
	}
	if warns, _ := e.take(); len(warns) != 1 || !strings.Contains(warns[0], "ignored 1 line of text before") {
		t.Errorf("warnings %q", warns)
	}
	if err := w.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ch, err := w.Changed(); err != nil || ch {
		t.Fatalf("Changed after open: %v %v", ch, err)
	}
	st, _ := os.Stat(e.path)
	if !bytes.Equal(e.read(), crlf) || !st.ModTime().Equal(old) {
		t.Fatal("open changed the vault file")
	}
	if ents, _ := os.ReadDir(e.dir); len(ents) != 1 {
		t.Fatalf("open left %d files in the vault folder", len(ents))
	}
	// The first save writes the canonical form.
	mustAdd(t, w, "b", "pw")
	if f, err := vaultfile.Parse(e.read()); err != nil || !f.Canonical || len(f.Warnings) != 0 {
		t.Fatalf("after save: %v", err)
	}
	if !w.Info().Canonical {
		t.Error("Info after save not canonical")
	}
}

func TestChangedAndReload(t *testing.T) {
	e := newEnv(t)
	a, b := e.open(), e.open()
	mustAdd(t, a, "from/a", "pa")
	if ch, err := b.Changed(); err != nil || !ch {
		t.Fatalf("Changed: %v %v", ch, err)
	}
	if ch, err := a.Changed(); err != nil || ch {
		t.Fatalf("Changed of the saver: %v %v", ch, err)
	}
	// b's change is refused, b keeps its state, the file keeps a's change.
	before := e.read()
	if _, err := b.Add(testEntry("from/b", "pb"), false); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale save: %v", err)
	}
	if !bytes.Equal(e.read(), before) {
		t.Fatal("stale save changed the file")
	}
	if len(b.Entries()) != 0 || b.Info().Revision != 1 {
		t.Fatal("refused save changed the in-memory state")
	}
	if err := b.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ch, _ := b.Changed(); ch {
		t.Fatal("Changed after Reload")
	}
	mustAdd(t, b, "from/b", "pb")
	if got := entryPaths(e.open().Entries()); !slices.Equal(got, []string{"from/a", "from/b"}) {
		t.Fatalf("entries %v: a change was lost", got)
	}
	// A removed file is a change, too.
	if err := os.Rename(e.path, e.path+".moved"); err != nil {
		t.Fatal(err)
	}
	if ch, err := b.Changed(); err != nil || !ch {
		t.Fatalf("Changed of a removed file: %v %v", ch, err)
	}
	if _, err := b.Add(testEntry("x", "x"), false); !errors.Is(err, ErrChanged) {
		t.Fatalf("save to a removed file: %v", err)
	}
	if _, err := os.Stat(e.path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("save recreated a removed vault")
	}
}

// Reload after another process rekeyed the file asks the key source.
func TestReloadAfterRekeyAsksAgain(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	// Simulate a rekey elsewhere: same data, a new key (low work factor).
	other := e.open()
	newKey, _ := keys.NewVaultKey()
	other.mu.Lock()
	err := other.commit(t.Context(), other.data.Clone(), lowKeyBlock(t, newKey, "second pass"), newKey)
	other.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// v's key source is FromIdentity(old key): it can't open the new file.
	if err := v.Reload(context.Background()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("reload with the old key: %v", err)
	}
	if v.Info().Revision != 1 {
		t.Fatal("failed reload changed the state")
	}
	w, err := Open(context.Background(), e.path, passSource("second pass", nil), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClose(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	v.Close()
	if v.Key() != nil || v.Entries() != nil || v.Snapshot() != nil {
		t.Fatal("Close kept the key or the data")
	}
	if _, ok := v.Get(paths.MustParse("a")); ok {
		t.Fatal("Get after Close")
	}
	if _, err := v.Add(testEntry("b", "pw"), false); !errors.Is(err, ErrClosed) {
		t.Fatalf("Add after Close: %v", err)
	}
	if err := v.Passwd([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Passwd after Close: %v", err)
	}
	if _, err := v.Rekey([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Rekey after Close: %v", err)
	}
	if err := v.Reload(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Reload after Close: %v", err)
	}
	if _, err := v.Changed(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Changed after Close: %v", err)
	}
	if _, err := v.Backups(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Backups after Close: %v", err)
	}
	if _, ok := v.GetByID("x"); ok || v.Info().VaultID != "" {
		t.Fatal("data after Close")
	}
}

// A symlinked vault is written to its target; the link stays.
func TestSymlinkedVault(t *testing.T) {
	e := newEnv(t)
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "vault.passh")
	if err := os.Symlink(e.path, link); err != nil {
		t.Fatal(err)
	}
	v := e.openFile(link)
	if v.Info().RealPath != e.path || v.Info().Path != link {
		t.Fatalf("info %+v", v.Info())
	}
	mustAdd(t, v, "a", "pw")
	if st, err := os.Lstat(link); err != nil || st.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced")
	}
	if target, _ := os.Readlink(link); target != e.path {
		t.Fatalf("link points to %s", target)
	}
	if got := entryPaths(e.open().Entries()); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("target holds %v", got)
	}
	if ents, _ := os.ReadDir(linkDir); len(ents) != 1 {
		t.Fatal("files were written next to the link")
	}
	if m := mode(t, e.path); m != 0o600 {
		t.Fatalf("target mode %o", m)
	}
	// The link pointed elsewhere after open: the save is refused.
	other := filepath.Join(e.dir, "other.passh")
	if err := os.WriteFile(other, e.read(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if ch, _ := v.Changed(); !ch {
		t.Error("Changed after the link moved")
	}
	if _, err := v.Add(testEntry("b", "pw"), false); !errors.Is(err, ErrChanged) {
		t.Fatalf("save after the link moved: %v", err)
	}
}

// Modes: the vault and backups 0600, state folders 0700, whatever the
// vault's mode was before and whatever the umask.
func TestModes(t *testing.T) {
	e := newEnv(t)
	if err := os.Chmod(e.path, 0o644); err != nil {
		t.Fatal(err)
	}
	// State folders and files are made from scratch under a strict umask.
	if err := os.RemoveAll(e.state); err != nil {
		t.Fatal(err)
	}
	defer syscall.Umask(syscall.Umask(0o277))
	v := e.open()
	mustAdd(t, v, "a", "pw")
	if m := mode(t, e.path); m != 0o600 {
		t.Errorf("vault mode %o after save", m)
	}
	for _, d := range []string{e.state, filepath.Join(e.state, "locks"), backupsRoot(e.state), BackupDir(e.state, v.Info().VaultID)} {
		if m := mode(t, d); m != 0o700 {
			t.Errorf("%s: mode %o, want 700", d, m)
		}
	}
	files := filesUnder(t, e.state)
	if len(files) < 4 { // a lock, the record, its lock, a backup
		t.Fatalf("state files %v", files)
	}
	for _, f := range files {
		if m := mode(t, f); m != 0o600 {
			t.Errorf("%s: mode %o, want 600", f, m)
		}
	}
}

// Data that decrypts but isn't valid vault data is damage, with the detail.
func TestInvalidData(t *testing.T) {
	e := newEnv(t)
	for _, plain := range []string{
		`not json`,
		`{"format":"other","version":1}`,
		`{"format":"passh-vault-data","version":1,"vault_id":"x","revision":1,` +
			`"entries":[{"id":"a","path":"p"},{"id":"b","path":"p"}]}`,
	} {
		db, err := keys.EncryptData(e.key, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		file, err := vaultfile.Encode(e.keyBlock, db)
		if err != nil {
			t.Fatal(err)
		}
		e.write(file)
		_, err = Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
		var oe *OpenError
		if !errors.As(err, &oe) || !errors.Is(err, ErrDataDamaged) ||
			!strings.HasPrefix(err.Error(), e.path+": data is damaged; restore a backup (invalid vault data") {
			t.Fatalf("%s: %v", plain, err)
		}
	}
}
