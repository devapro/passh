package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"passh/internal/keys"
	"passh/internal/vaultfile"
)

func TestBackupRotation(t *testing.T) {
	e := newEnv(t)
	e.keep = 3
	v := e.open()
	var files [][]byte // files[r] is revision r+1 as it was on disk
	files = append(files, e.read())
	for i := range 6 {
		mustAdd(t, v, "e/"+string(rune('a'+i)), "pw")
		files = append(files, e.read())
	}
	// Saves 1–6 backed up r1–r6; the newest three are kept.
	list, err := v.Backups()
	if err != nil {
		t.Fatal(err)
	}
	var revs []uint64
	for _, b := range list {
		revs = append(revs, b.Revision)
	}
	if !slices.Equal(revs, []uint64{6, 5, 4}) {
		t.Fatalf("kept revisions %v", revs)
	}
	name := regexp.MustCompile(`^20261115T12\d{4}Z-r\d+\.passh$`)
	for i, b := range list {
		if !name.MatchString(filepath.Base(b.Path)) || filepath.Dir(b.Path) != BackupDir(e.state, v.Info().VaultID) {
			t.Errorf("backup path %s", b.Path)
		}
		if i > 0 && !b.Time.Before(list[i-1].Time) {
			t.Errorf("not newest first: %v", list)
		}
		// Each backup is the vault file byte for byte, and opens.
		got, _ := os.ReadFile(b.Path)
		if !bytes.Equal(got, files[b.Revision-1]) {
			t.Errorf("backup r%d differs from the file it copied", b.Revision)
		}
		if m := mode(t, b.Path); m != 0o600 {
			t.Errorf("backup mode %o", m)
		}
		if bv := e.openFile(b.Path); bv.Info().Revision != b.Revision {
			t.Errorf("backup r%d opens as r%d", b.Revision, bv.Info().Revision)
		}
	}
	if s := list[0].String(); !regexp.MustCompile(`^2026-11-15 12:\d\d:00  r6  /.*\.passh$`).MatchString(s) {
		t.Errorf("String() = %q", s)
	}
	// A smaller keep trims on the next save.
	e.keep = 1
	w := e.open()
	mustAdd(t, w, "e/z", "pw")
	if list, _ := w.Backups(); len(list) != 1 || list[0].Revision != 7 {
		t.Fatalf("after keep=1: %v", list)
	}
}

func TestBackupsOff(t *testing.T) {
	e := newEnv(t)
	e.keep = 0
	v := e.open()
	mustAdd(t, v, "a", "pw")
	if _, err := os.Stat(backupsRoot(e.state)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backups folder with keep=0: %v", err)
	}
	if list, err := v.Backups(); err != nil || len(list) != 0 {
		t.Fatalf("Backups: %v %v", list, err)
	}
	// Turning backups off leaves earlier ones alone.
	e.keep = 2
	mustAdd(t, e.open(), "b", "pw")
	e.keep = 0
	mustAdd(t, e.open(), "c", "pw")
	if n := len(listBackups(t, e.state)); n != 1 {
		t.Fatalf("%d backups", n)
	}
}

func TestBackupNames(t *testing.T) {
	state := t.TempDir()
	now := time.Date(2026, 11, 15, 12, 0, 31, 0, time.UTC)
	for range 3 {
		if _, _, err := writeBackup(state, "0f6c-id", 42, []byte("x"), now, 10, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := writeBackup(state, "0f6c-id", 41, []byte("x"), now.Add(-time.Minute), 10, ""); err != nil {
		t.Fatal(err)
	}
	dir := BackupDir(state, "0f6c-id")
	for _, junk := range []string{"README", "20261115T120031Z-r42.txt", ".backup.tmp-1"} {
		os.WriteFile(filepath.Join(dir, junk), nil, 0o600)
	}
	list, err := ListBackups(state, "0f6c-id")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range list {
		names = append(names, filepath.Base(b.Path))
	}
	want := []string{"20261115T120031Z-r42-3.passh", "20261115T120031Z-r42-2.passh", "20261115T120031Z-r42.passh", "20261115T115931Z-r41.passh"}
	if !slices.Equal(names, want) {
		t.Fatalf("names %v", names)
	}
	if list[0].Time != now || list[0].Revision != 42 || list[0].VaultID != "0f6c-id" {
		t.Fatalf("parsed %+v", list[0])
	}
	// An id that isn't a safe file name gets a digest folder, inside backups.
	if d := BackupDir(state, "../../etc"); filepath.Dir(d) != backupsRoot(state) || strings.Contains(filepath.Base(d), ".") {
		t.Fatalf("unsafe id folder %s", d)
	}
	// The next backup removes the leftover temporary file.
	writeBackup(state, "0f6c-id", 43, []byte("x"), now.Add(time.Minute), 10, "")
	if _, err := os.Stat(filepath.Join(dir, ".backup.tmp-1")); err == nil {
		t.Fatal("leftover backup temporary file survived")
	}
	if all, _ := ListBackups(state, ""); len(all) != 5 {
		t.Fatalf("all backups: %d", len(all))
	}
	if none, err := ListBackups(t.TempDir(), ""); err != nil || len(none) != 0 {
		t.Fatalf("no backups folder: %v %v", none, err)
	}
}

// "data is damaged" lists this vault's automatic backups (§4.5, §4.7).
func TestDamagedDataListsBackups(t *testing.T) {
	// Another vault's backups must not be listed.
	other := newEnv(t)
	e := newEnv(t)
	e.state = other.state
	ov := other.open()
	mustAdd(t, ov, "o", "pw")

	v := e.open()
	mustAdd(t, v, "a", "pw")
	mustAdd(t, v, "b", "pw")
	mine, _ := v.Backups()
	if len(mine) != 2 {
		t.Fatalf("backups %v", mine)
	}

	f, _ := vaultfile.Parse(e.read())
	db := bytes.Clone(f.DataBlock)
	db[len(db)-5] ^= 1 // in the payload: authentication fails
	file, _ := vaultfile.Encode(f.KeyBlock, db)
	e.write(file)
	_, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	var oe *OpenError
	if !errors.As(err, &oe) || !errors.Is(err, ErrDataDamaged) || errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("damaged data: %v", err)
	}
	if !oe.BackupsMatched || !slices.EqualFunc(oe.Backups, mine, func(a, b Backup) bool { return a.Path == b.Path }) {
		t.Fatalf("listed %v, want %v", oe.Backups, mine)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, e.path+": data is damaged; restore a backup") ||
		!strings.Contains(msg, "automatic backups of this vault, newest first:\n  "+mine[0].String()) {
		t.Fatalf("message:\n%s", msg)
	}

	// After a key block change (passwd) without a save since, the vault key
	// still finds the backups.
	newKB := lowKeyBlock(t, e.key, "another passphrase")
	file, _ = vaultfile.Encode(newKB, db)
	e.write(file)
	_, err = Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	if !errors.As(err, &oe) || !oe.BackupsMatched || len(oe.Backups) != 2 {
		t.Fatalf("after a key block change: %v", err)
	}

	// FindBackups (passh backups, no key) matches by key block.
	e.write(mustRead(t, mine[0].Path))
	list, matched, err := FindBackups(e.state, e.path)
	if err != nil || !matched || len(list) != 2 {
		t.Fatalf("FindBackups: %v %v %v", list, matched, err)
	}
	// Unrecognized: every backup on the machine.
	os.WriteFile(e.path, []byte("garbage"), 0o600)
	list, matched, err = FindBackups(e.state, e.path)
	if err != nil || matched || len(list) != 3 {
		t.Fatalf("FindBackups of garbage: %v %v %v", list, matched, err)
	}
	if _, _, err := FindBackups(e.state, filepath.Join(e.dir, "missing")); err == nil {
		t.Fatal("FindBackups of a missing file")
	}

	// Without any backup, the message says so.
	e2 := newEnv(t)
	f2, _ := vaultfile.Parse(e2.read())
	db2 := bytes.Clone(f2.DataBlock)
	db2[len(db2)-5] ^= 1
	file2, _ := vaultfile.Encode(f2.KeyBlock, db2)
	e2.write(file2)
	_, err = Open(context.Background(), e2.path, keys.FromIdentity(e2.key), e2.opts())
	if err == nil || !strings.Contains(err.Error(), "no automatic backups of this vault were found") {
		t.Fatalf("no backups: %v", err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
