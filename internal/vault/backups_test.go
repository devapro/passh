package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/vaultfile"
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
	name := regexp.MustCompile(`^0000000[4-6]-20261115T12\d{4}Z-r[4-6]\.passh$`)
	for i, b := range list {
		if !name.MatchString(filepath.Base(b.Path)) || filepath.Dir(b.Path) != BackupDir(e.state, v.Info().VaultID) {
			t.Errorf("backup path %s", b.Path)
		}
		if b.seq != b.Revision { // one save per revision since r1
			t.Errorf("backup %s has number %d", b.Path, b.seq)
		}
		if i > 0 && (!b.Time.Before(list[i-1].Time) || b.seq >= list[i-1].seq) {
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
		if _, _, err := writeBackup(t.Context(), state, "0f6c-id", 42, []byte("x"), now, 10, ""); err != nil {
			t.Fatal(err)
		}
	}
	// The clock went back a minute: still the newest.
	if _, _, err := writeBackup(t.Context(), state, "0f6c-id", 41, []byte("x"), now.Add(-time.Minute), 10, ""); err != nil {
		t.Fatal(err)
	}
	dir := BackupDir(state, "0f6c-id")
	for _, junk := range []string{
		"README", "00000009-20261115T120031Z-r42.txt", ".backup.tmp-1",
		"0-20261115T120031Z-r1.passh",                    // number 0: not made by passh
		"x1-20261115T120031Z-r1.passh",                   // not a number
		"00000009-20261115T120031Z-r1-2.passh",           // a suffix only old names have
		"5000000000000000000-20261115T120031Z-r1.passh",  // above maxBackupSeq
		"99999999999999999999-20261115T120031Z-r1.passh", // above uint64
	} {
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
	want := []string{
		"00000004-20261115T115931Z-r41.passh",
		"00000003-20261115T120031Z-r42.passh",
		"00000002-20261115T120031Z-r42.passh",
		"00000001-20261115T120031Z-r42.passh",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("names %v, want %v", names, want)
	}
	if b := list[0]; !b.Time.Equal(now.Add(-time.Minute)) || b.Revision != 41 || b.VaultID != "0f6c-id" || b.seq != 4 {
		t.Fatalf("parsed %+v", b)
	}
	// An id that isn't a safe file name gets a digest folder, inside backups.
	if d := BackupDir(state, "../../etc"); filepath.Dir(d) != backupsRoot(state) || strings.Contains(filepath.Base(d), ".") {
		t.Fatalf("unsafe id folder %s", d)
	}
	// The next backup removes the leftover temporary file.
	p, _, err := writeBackup(t.Context(), state, "0f6c-id", 43, []byte("x"), now.Add(time.Minute), 10, "")
	if err != nil || filepath.Base(p) != "00000005-20261115T120131Z-r43.passh" {
		t.Fatalf("next backup %s: %v", p, err)
	}
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

// Backups named before sequence numbers existed (20261115T120000Z-r9.passh)
// are listed and rotated as older than every numbered one; among
// themselves the time in the name decides, then revision, then the -2, -3
// suffix.
func TestBackupsOldNames(t *testing.T) {
	state := t.TempDir()
	dir := BackupDir(state, "id")
	if err := mkdirs(dir); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{
		"20261115T120000Z-r9.passh",
		"20261115T120000Z-r9-2.passh",
		"20261115T110000Z-r12.passh", // higher revision, earlier time
		"20300101T000000Z-r3.passh",  // made while the clock was ahead
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := func() []string {
		t.Helper()
		list, err := ListBackups(state, "id")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, b := range list {
			out = append(out, filepath.Base(b.Path))
		}
		return out
	}
	want := []string{"20300101T000000Z-r3.passh", "20261115T120000Z-r9-2.passh", "20261115T120000Z-r9.passh", "20261115T110000Z-r12.passh"}
	if got := names(); !slices.Equal(got, want) {
		t.Fatalf("old names listed as %v, want %v", got, want)
	}

	// The first numbered backup is number 1 and the newest, whatever its
	// time; rotation removes old names first, oldest first.
	at := time.Date(2026, 11, 15, 13, 0, 0, 0, time.UTC)
	for i, keep := range []int{4, 3, 3, 3} {
		if _, _, err := writeBackup(t.Context(), state, "id", uint64(13+i), []byte("new"), at.Add(time.Duration(i)*time.Minute), keep, ""); err != nil {
			t.Fatal(err)
		}
	}
	want = []string{
		"00000004-20261115T130300Z-r16.passh",
		"00000003-20261115T130200Z-r15.passh",
		"00000002-20261115T130100Z-r14.passh",
	}
	if got := names(); !slices.Equal(got, want) {
		t.Fatalf("after four backups: %v, want %v", got, want)
	}
}

// CORE-001 regression: after the vault went back to a lower revision (a
// backup restored as §4.7 says), rotation keeps the backups of the new
// work, the newest backup.keep made, and drops the stale higher-revision
// ones. Before sequence numbers, each new backup was removed by the next
// save and the stale ones stayed on top.
func TestBackupsAfterRestore(t *testing.T) {
	e := newEnv(t)
	e.keep = 3
	e.noPrompt = true // the rollback warning goes to Warn
	v := e.open()
	mustAdd(t, v, "old/0", "pw")
	r2 := e.read()
	for i := 1; i <= 10; i++ {
		mustAdd(t, v, "old/"+strconv.Itoa(i), "pw")
	}
	if revs := backupRevisions(t, e.state); !slices.Equal(revs, []uint64{11, 10, 9}) || v.Info().Revision != 12 {
		t.Fatalf("before the restore: backups %v at r%d", revs, v.Info().Revision)
	}

	e.write(r2) // restore an older copy over the vault
	w := e.open()
	saved := map[uint64][]byte{2: r2}
	for i := range 4 {
		mustAdd(t, w, "new/"+strconv.Itoa(i), "pw")
		saved[w.Info().Revision] = e.read()
		list := listBackups(t, e.state)
		// The backup just made, of the revision before this save, is first.
		if list[0].Revision != w.Info().Revision-1 {
			t.Fatalf("save %d: newest backup is r%d, want r%d (%v)", i+1, list[0].Revision, w.Info().Revision-1, list)
		}
		if len(list) != e.keep {
			t.Fatalf("save %d: %d backups, keep = %d", i+1, len(list), e.keep)
		}
	}
	// Saves 2–4 backed up r3–r5 (save 1 backed up r2).
	list := listBackups(t, e.state)
	if revs := backupRevisions(t, e.state); !slices.Equal(revs, []uint64{5, 4, 3}) {
		t.Fatalf("after the restore and four saves: backups %v, want [5 4 3]", revs)
	}
	for _, b := range list {
		if !bytes.Equal(mustRead(t, b.Path), saved[b.Revision]) {
			t.Errorf("backup r%d isn't the file that was replaced", b.Revision)
		}
	}
}

func backupRevisions(t *testing.T, state string) []uint64 {
	t.Helper()
	var revs []uint64
	for _, b := range listBackups(t, state) {
		revs = append(revs, b.Revision)
	}
	return revs
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
