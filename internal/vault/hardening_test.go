package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vaultfile"
)

// otherVersion makes another valid version of e's vault, as another
// machine would (a copy edited elsewhere), and returns its bytes. e's vault
// and state are untouched.
func otherVersion(t *testing.T, e *env) []byte {
	t.Helper()
	cp := filepath.Join(t.TempDir(), "copy.passh")
	if err := os.WriteFile(cp, e.read(), 0o600); err != nil {
		t.Fatal(err)
	}
	o := e.opts()
	o.StateDir = t.TempDir()
	x, err := Open(context.Background(), cp, keys.FromIdentity(e.key), o)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, x, "remote/change", "remote-pw")
	return mustRead(t, cp)
}

// putInPlace replaces the vault the way a sync tool does: a new file
// renamed over it.
func putInPlace(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp := path + ".synctmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Error(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Error(err)
	}
}

// A copy put in place while a save is under way, after the first check
// (during the read-back, the backup or just before the rename), is never
// overwritten: the save fails with ErrChanged and the other version stays.
// With a plain rename (no exchange), the second check right before the
// backup still catches it up to that point.
func TestReplacedDuringSave(t *testing.T) {
	for _, plain := range []bool{false, true} {
		points := []string{hookTempSynced, hookVerified}
		if !plain {
			points = append(points, hookRechecked, hookBackupWritten, hookBackupDone, hookBeforeRename)
		}
		for _, point := range points {
			name := point
			if plain {
				name = "plain-rename/" + point
			}
			t.Run(name, func(t *testing.T) {
				if plain {
					noExchange(t)
				}
				e := newEnv(t)
				v := e.open()
				mustAdd(t, v, "local/first", "pw")
				other := otherVersion(t, e)
				setHook(t, func(p, _ string) {
					if p == point {
						putInPlace(t, e.path, other)
					}
				})
				_, err := v.Add(testEntry("local/second", "pw"), false)
				testHook = nil
				if !errors.Is(err, ErrChanged) {
					t.Fatalf("save while the file was replaced: %v", err)
				}
				if !bytes.Equal(e.read(), other) {
					t.Fatal("the other version was overwritten")
				}
				if left := temps(t, e.dir); len(left) != 0 {
					t.Fatalf("left %v", left)
				}
				if got := entryPaths(v.Entries()); !slices.Equal(got, []string{"local/first"}) {
					t.Fatalf("in-memory state changed: %v", got)
				}
				// Reload, repeat: nothing is lost.
				if err := v.Reload(context.Background()); err != nil {
					t.Fatal(err)
				}
				mustAdd(t, v, "local/second", "pw")
				want := []string{"local/first", "local/second", "remote/change"}
				if got := entryPaths(e.open().Entries()); !slices.Equal(got, want) {
					t.Fatalf("entries %v, want %v", got, want)
				}
			})
		}
	}
}

// If the exchange can't be undone, the other version is kept beside the
// vault under a visible name, never lost.
func TestReplacedAndExchangeFails(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	other := otherVersion(t, e)
	calls := 0
	setExchange(t, func(a, b string) error {
		calls++
		if calls > 1 {
			return syscall.EIO
		}
		return exchange(a, b)
	})
	setHook(t, func(p, _ string) {
		if p == hookBeforeRename {
			putInPlace(t, e.path, other)
		}
	})
	_, err := v.Add(testEntry("local", "pw"), false)
	testHook = nil
	if !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), ".conflict-") {
		t.Fatalf("save: %v", err)
	}
	kept, _ := filepath.Glob(filepath.Join(e.dir, "vault.conflict-*.passh"))
	if len(kept) != 1 || !bytes.Equal(mustRead(t, kept[0]), other) {
		t.Fatalf("the other version wasn't kept: %v", kept)
	}
}

// Step 1 doesn't remove the temporary file of a save in progress (one that
// serializes on another lock file, e.g. with another state folder); its
// writer holds it locked. Stale ones go.
func TestLockedTempKept(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	busy, err := writeTemp(e.dir, "vault.passh", []byte("a save in progress"), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.discard()
	stale := filepath.Join(e.dir, ".vault.passh.tmp-stale")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustAdd(t, v, "a", "pw")
	if _, err := os.Stat(busy.path); err != nil {
		t.Fatalf("the busy temporary file was removed: %v", err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("the stale temporary file survived")
	}
	// Two saves with different state folders, at once: both temporary
	// files survive each other's cleanup.
	o := e.opts()
	o.StateDir = t.TempDir()
	w, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o)
	if err != nil {
		t.Fatal(err)
	}
	setHook(t, func(p, _ string) {
		if p == hookTempSynced {
			testHook = nil // once: w's own save passes here too
			// w's cleanup runs while v's temporary file exists.
			if _, err := w.Add(testEntry("w", "pw"), false); err != nil {
				t.Errorf("w: %v", err)
			}
		}
	})
	_, err = v.Add(testEntry("v", "pw"), false)
	if !errors.Is(err, ErrChanged) { // w saved first
		t.Fatalf("v: %v", err)
	}
	if got := entryPaths(e.open().Entries()); !slices.Equal(got, []string{"a", "w"}) {
		t.Fatalf("entries %v", got)
	}
}

// Reload doesn't reuse the in-memory key for a changed key block: it goes
// through the key source again (which checks the key block, as the agent's
// does).
func TestReloadChangedKeyBlock(t *testing.T) {
	e := newEnv(t)
	var asked atomic.Int32
	ks := countingSource{keys.FromIdentity(e.key), &asked}
	v, err := Open(context.Background(), e.path, ks, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	other := e.open()
	mustAdd(t, other, "a", "pw")
	if err := v.Reload(context.Background()); err != nil || asked.Load() != 1 {
		t.Fatalf("reload, same key block: %v, asked %d", err, asked.Load())
	}
	// A passwd elsewhere: same key, another key block.
	other.mu.Lock()
	err = other.commit(t.Context(), other.data.Clone(), lowKeyBlock(t, e.key, "new pass"), e.key)
	other.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Reload(context.Background()); err != nil || asked.Load() != 2 {
		t.Fatalf("reload, new key block: %v, asked %d", err, asked.Load())
	}
	if !bytes.Equal(v.KeyBlock(), keyBlockOf(t, e.read())) {
		t.Fatal("KeyBlock isn't the new one")
	}
	// A Vault without a key source (made by Create) refuses.
	c := &Vault{display: e.path, path: e.path, opts: v.opts, real: v.real, sum: v.sum, keyBlock: e.keyBlock, key: e.key, data: v.data}
	if err := c.Reload(context.Background()); !errors.Is(err, ErrKeyBlockChanged) {
		t.Fatalf("reload without a key source: %v", err)
	}
}

type countingSource struct {
	keys.KeySource
	n *atomic.Int32
}

func (c countingSource) VaultKey(ctx context.Context, kb []byte) (*age.X25519Identity, error) {
	c.n.Add(1)
	return c.KeySource.VaultKey(ctx, kb)
}

func keyBlockOf(t *testing.T, file []byte) []byte {
	t.Helper()
	f, err := vaultfile.Parse(file)
	if err != nil {
		t.Fatal(err)
	}
	return f.KeyBlock
}

// A vault inside the automatic backups folder opens, but isn't saved:
// rotation would remove it.
func TestSaveInBackupsFolder(t *testing.T) {
	e := newEnv(t)
	e.keep = 3
	v := e.open()
	for i := range 4 {
		mustAdd(t, v, "x/"+string(rune('a'+i)), "pw")
	}
	list := listBackups(t, e.state)
	oldest := list[len(list)-1].Path
	before := mustRead(t, oldest)
	b := e.openFile(oldest)
	if _, err := b.Add(testEntry("in/backup", "pw"), false); !errors.Is(err, ErrBackupFile) {
		t.Fatalf("save in the backups folder: %v", err)
	}
	if !bytes.Equal(mustRead(t, oldest), before) {
		t.Fatal("the backup changed")
	}
	// Also through a symlink, and for Create.
	link := filepath.Join(t.TempDir(), "link.passh")
	os.Symlink(oldest, link)
	if _, err := e.openFile(link).Add(testEntry("in/backup", "pw"), false); !errors.Is(err, ErrBackupFile) {
		t.Fatalf("save through a symlink: %v", err)
	}
	c, _ := newVault(filepath.Join(BackupDir(e.state, v.Info().VaultID), "new.passh"), e.opts())
	if err := c.create(t.Context(), e.key, e.keyBlock); !errors.Is(err, ErrBackupFile) {
		t.Fatalf("create in the backups folder: %v", err)
	}
	// Rotation never removes a protected path, nor the file just written.
	dir := filepath.Dir(oldest)
	if err := rotate(dir, 0, oldest); err != nil {
		t.Fatal(err)
	}
	if left, _ := listDir(dir, ""); len(left) != 1 || left[0].Path != oldest {
		t.Fatalf("after rotate: %v", left)
	}
}

// After the clock went back, rotation keeps the backups made last, not the
// files with the latest times in their names, and lists them first.
func TestRotationClockSkew(t *testing.T) {
	e := newEnv(t)
	e.keep = 3
	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	o := e.opts()
	n := 0
	o.Now = func() time.Time { n++; return future.Add(time.Duration(n) * time.Minute) }
	v, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		mustAdd(t, v, "f/"+string(rune('a'+i)), "pw")
	}
	w := e.open() // the clock is right again
	for i := range 3 {
		mustAdd(t, w, "g/"+string(rune('a'+i)), "pw")
	}
	list := listBackups(t, e.state)
	if revs := backupRevisions(t, e.state); !slices.Equal(revs, []uint64{6, 5, 4}) {
		t.Fatalf("kept revisions %v, want [6 5 4]", revs)
	}
	if list[len(list)-1].Time.After(future) || !list[0].Time.Before(future) {
		t.Fatalf("the kept backups aren't the ones made after the clock was fixed: %v", list)
	}
}

// Every file is fsynced before it is renamed into place, the folder after
// the rename, and each new folder's parent after the folder is made.
func TestSyncOrder(t *testing.T) {
	var log []string
	setSyncFile(t, func(f *os.File) error {
		log = append(log, "sync "+f.Name())
		return f.Sync()
	})
	setHook(t, func(p, file string) { log = append(log, p+" "+file) })

	// A new vault in new folders.
	root := t.TempDir()
	state := filepath.Join(root, "state")
	path := filepath.Join(root, "a", "b", "vault.passh")
	key, _ := keys.NewVaultKey()
	c, err := newVault(path, Options{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.create(t.Context(), key, lowKeyBlock(t, key, testPass)); err != nil {
		t.Fatal(err)
	}
	tmp := find(t, log, hookTempCreated+" ")
	dirB := filepath.Join(root, "a", "b")
	order(t, log, "sync "+root+"$", "sync "+filepath.Join(root, "a")+"$") // folders a and b
	order(t, log, "sync "+tmp+"$", hookRenamed+" ")
	order(t, log, hookRenamed+" ", "sync "+dirB+"$")
	order(t, log, "sync "+dirB+"$", "sync "+state+"$") // state, then state/locks

	// A save with the first backup: backups/ and backups/<id> are new.
	log = nil
	v, err := Open(context.Background(), path, keys.FromIdentity(key), Options{StateDir: state, BackupKeep: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add(testEntry("a", "pw"), false); err != nil {
		t.Fatal(err)
	}
	tmp = find(t, log, hookTempCreated+" ")
	backupTmp := find(t, log, hookBackupWritten+" ")
	backupDir := BackupDir(state, v.Info().VaultID)
	order(t, log, "sync "+tmp+"$", hookRenamed+" ")
	order(t, log, "sync "+backupTmp+"$", hookBackupRenamed+" ")
	order(t, log, hookBackupRenamed+" ", "sync "+backupDir+"$")
	order(t, log, "sync "+backupDir+"$", hookBeforeRename+" ")
	order(t, log, "sync "+state+"$", "sync "+backupsRoot(state)+"$") // backups, then backups/<id>
	order(t, log, "sync "+backupsRoot(state)+"$", hookBackupWritten+" ")
	order(t, log, hookRenamed+" ", "sync "+dirB+"$")
	order(t, log, "sync "+dirB+"$", hookDirSynced+" ")
	// The rollback record too.
	recTmp := find(t, log, "sync "+filepath.Join(state, ".revisions.json.tmp-"))
	order(t, log, "sync "+recTmp+"$", hookRecordWritten+" ")
	order(t, log, hookRecordWritten+" ", "sync "+state+"$")
	order(t, log, "sync "+state+"$", hookRecorded+" ")
}

// find returns the first log line starting with prefix, without its
// first word ("temp-created /x/.v.tmp-1" gives "/x/.v.tmp-1").
func find(t *testing.T, log []string, prefix string) string {
	t.Helper()
	i := at(log, prefix)
	if i < 0 {
		t.Fatalf("no %q in\n%s", prefix, strings.Join(log, "\n"))
	}
	_, rest, _ := strings.Cut(log[i], " ")
	return rest
}

// at returns the index of the first line matching pat: a prefix, or the
// whole line if pat ends in "$".
func at(log []string, pat string) int {
	return slices.IndexFunc(log, func(l string) bool { return match(l, pat) })
}

func match(l, pat string) bool {
	if exact, ok := strings.CutSuffix(pat, "$"); ok {
		return l == exact
	}
	return strings.HasPrefix(l, pat)
}

// order checks that a line matching first comes before a later line
// matching then.
func order(t *testing.T, log []string, first, then string) {
	t.Helper()
	i := at(log, first)
	if i < 0 {
		t.Fatalf("no %q in\n%s", first, strings.Join(log, "\n"))
	}
	if !slices.ContainsFunc(log[i+1:], func(l string) bool { return match(l, then) }) {
		t.Fatalf("no %q after %q in\n%s", then, first, strings.Join(log, "\n"))
	}
}

// damageKeyBlockHeader breaks the first base64 line of the key block, so
// the file no longer parses ("file is damaged (block 1)").
func damageKeyBlockHeader(t *testing.T, file []byte) []byte {
	t.Helper()
	lines := strings.Split(string(file), "\n")
	if !strings.HasPrefix(lines[2], "YWdl") { // "age-encryption.org/v1"
		t.Fatalf("unexpected line %q", lines[2])
	}
	lines[2] = "ZWdl" + lines[2][4:]
	return []byte(strings.Join(lines, "\n"))
}

// recover with a damaged key block: Options.Recovery opens the data block
// with the paper key; only a new key block (Passwd, Rekey) may be saved.
func TestRecoveryWithDamagedKeyBlock(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	e.write(damageKeyBlockHeader(t, e.read()))
	before := e.read()

	_, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	var de *vaultfile.DamagedError
	if !errors.As(err, &de) || de.Block != 1 {
		t.Fatalf("without Recovery: %v", err)
	}
	o := e.opts()
	o.Recovery = true
	// The wrong paper key still fails, and names the damaged key block.
	stranger, _ := keys.NewVaultKey()
	if _, err := Open(context.Background(), e.path, keys.FromIdentity(stranger), o); !errors.As(err, &de) {
		t.Fatalf("recovery with another key: %v", err)
	}
	r, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyBlock() != nil || len(r.Info().Warnings) != 1 || !slices.Equal(entryPaths(r.Entries()), []string{"a"}) {
		t.Fatalf("recovered %+v", r.Info())
	}
	if _, err := r.Add(testEntry("b", "pw"), false); !errors.Is(err, ErrKeyBlockDamaged) {
		t.Fatalf("save without a new key block: %v", err)
	}
	if !bytes.Equal(e.read(), before) {
		t.Fatal("the vault changed")
	}
	// What Passwd does, with a cheap key block.
	r.mu.Lock()
	err = r.commit(t.Context(), r.data.Clone(), lowKeyBlock(t, e.key, "fresh pass"), r.key)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), e.path, passSource("fresh pass", nil), e.opts()); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	// The damaged file is among the backups.
	found := false
	for _, b := range listBackups(t, e.state) {
		found = found || bytes.Equal(mustRead(t, b.Path), before)
	}
	if !found {
		t.Fatal("the damaged file wasn't backed up")
	}
}

// The rollback record is replaced only when it is damaged; a newer or
// unreadable one is left alone, so no other vault's entry is lost.
func TestRecordLeftAlone(t *testing.T) {
	e := newEnv(t)
	newer := []byte(`{"version": 2, "vaults": {"someone-else": {"revision": 9}}, "more": true}` + "\n")
	if err := os.WriteFile(recordPath(e.state), newer, 0o600); err != nil {
		t.Fatal(err)
	}
	v := e.open()
	mustAdd(t, v, "a", "pw")
	if !bytes.Equal(mustRead(t, recordPath(e.state)), newer) {
		t.Fatal("a newer record was replaced")
	}
	if warns, _ := e.take(); len(warns) == 0 || !strings.Contains(warns[0], "newer passh") {
		t.Fatalf("warnings %q", warns)
	}

	if os.Getuid() != 0 {
		valid := []byte(`{"version": 1, "vaults": {"someone-else": {"revision": 9, "saved_at": "2026-11-15T12:00:00Z", "seen_at": "2026-11-15T12:00:00Z"}}}`)
		if err := os.WriteFile(recordPath(e.state), valid, 0o000); err != nil {
			t.Fatal(err)
		}
		os.Chmod(recordPath(e.state), 0o000)
		v := e.open()
		mustAdd(t, v, "b", "pw")
		os.Chmod(recordPath(e.state), 0o600)
		if !bytes.Equal(mustRead(t, recordPath(e.state)), valid) {
			t.Fatal("an unreadable record was replaced")
		}
		if warns, _ := e.take(); len(warns) < 2 {
			t.Fatalf("warnings %q", warns)
		}
	}

	// A damaged one (not JSON, or no version) is started again.
	for _, bad := range []string{"{not json", `{"vaults": {}}`} {
		os.WriteFile(recordPath(e.state), []byte(bad), 0o600)
		e.open()
		if r := recorded(t, e); r == 0 {
			t.Fatalf("%s: record not restarted", bad)
		}
	}
}

// Create never renames over a file that appeared after its check, with the
// no-replace rename or its link fallback.
func TestCreateDoesNotClobber(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%v", fallback), func(t *testing.T) {
			if fallback {
				noRenameNoReplace(t)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "vault.passh")
			setHook(t, func(p, _ string) {
				if p == hookBeforeRename {
					if err := os.WriteFile(path, []byte("someone else's file"), 0o600); err != nil {
						t.Error(err)
					}
				}
			})
			key, _ := keys.NewVaultKey()
			c, _ := newVault(path, Options{StateDir: filepath.Join(dir, "state")})
			err := c.create(t.Context(), key, lowKeyBlock(t, key, testPass))
			testHook = nil
			if !errors.Is(err, ErrExists) {
				t.Fatalf("create: %v", err)
			}
			if string(mustRead(t, path)) != "someone else's file" {
				t.Fatal("the file was replaced")
			}
			if left := temps(t, dir); len(left) != 0 {
				t.Fatalf("left %v", left)
			}
		})
	}
}

// Tags and other saves still work after all of the above (a smoke test of
// the exchange path with a symlinked vault).
func TestExchangeThroughSymlink(t *testing.T) {
	e := newEnv(t)
	link := filepath.Join(t.TempDir(), "v.passh")
	os.Symlink(e.path, link)
	v := e.openFile(link)
	mustAdd(t, v, "a", "pw")
	if _, _, err := v.EditTags(paths.MustParse("a"), []string{"x"}, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
	if left := temps(t, e.dir); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

// CORE-002 regression: a close error after the new file was renamed into
// place doesn't turn the finished save into a failure: the save is
// reported as done (with a warning), the in-memory state follows the file,
// and the next save works. Also for a new key block (Passwd, Rekey) and for
// Create.
func TestCloseErrorAfterRename(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("plain-rename=%v", plain), func(t *testing.T) {
			if plain {
				noExchange(t)
			}
			e := newEnv(t)
			v := e.open()
			closeErr := errors.New("close failed")
			setCloseFile(t, func(f *os.File) error {
				_ = f.Close()
				return closeErr
			})
			e.take()
			if _, err := v.Add(testEntry("a", "pw"), false); err != nil {
				t.Fatalf("save with a failing close: %v", err)
			}
			if w, _ := e.take(); len(w) != 1 || !strings.Contains(w[0], "was saved, but closing it failed: close failed") {
				t.Fatalf("warnings %q", w)
			}
			if v.Info().Revision != 2 || !slices.Equal(entryPaths(v.Entries()), []string{"a"}) {
				t.Fatalf("in-memory state: %+v", v.Info())
			}
			if changed, err := v.Changed(); err != nil || changed {
				t.Fatalf("Changed after the save: %v %v", changed, err)
			}
			kb := lowKeyBlock(t, e.key, "new pass")
			v.mu.Lock()
			err := v.commit(t.Context(), v.data.Clone(), kb, e.key)
			v.mu.Unlock()
			if err != nil || !bytes.Equal(v.KeyBlock(), kb) || !bytes.Equal(keyBlockOf(t, e.read()), kb) {
				t.Fatalf("key block change with a failing close: %v", err)
			}
			mustAdd(t, v, "b", "pw")
			if r := e.open().Info().Revision; r != 4 {
				t.Fatalf("the file holds r%d, want r4", r)
			}
			if left := temps(t, e.dir); len(left) != 0 {
				t.Fatalf("left %v", left)
			}

			path := filepath.Join(t.TempDir(), "new.passh")
			c, _ := newVault(path, e.opts())
			if err := c.create(t.Context(), e.key, e.keyBlock); err != nil {
				t.Fatalf("create with a failing close: %v", err)
			}
		})
	}
}

// CORE-002: when the other version of the vault can't be moved aside after
// a failed undo, it stays at its temporary name, the error says so, and the
// save doesn't remove it.
func TestReplacedAndKeepAsideFails(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	other := otherVersion(t, e)
	calls := 0
	setExchange(t, func(a, b string) error {
		calls++
		if calls > 1 {
			return syscall.EIO
		}
		return exchange(a, b)
	})
	old := renameNoReplaceFn
	t.Cleanup(func() { renameNoReplaceFn = old })
	setHook(t, func(p, _ string) {
		if p == hookBeforeRename {
			putInPlace(t, e.path, other)
			// From here (after the backup) every move aside fails.
			renameNoReplaceFn = func(string, string) error { return syscall.EIO }
		}
	})
	_, err := v.Add(testEntry("local", "pw"), false)
	if !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "a temporary name") {
		t.Fatalf("save: %v", err)
	}
	left := temps(t, e.dir)
	if len(left) != 1 || !bytes.Equal(mustRead(t, filepath.Join(e.dir, left[0])), other) {
		t.Fatalf("the other version wasn't kept: %v", left)
	}
	if !strings.Contains(err.Error(), left[0]) {
		t.Fatalf("the error doesn't name %s: %v", left[0], err)
	}
}

// CORE-002: an exchanged-out file that can't be read is not compared with
// the opened one, so it is kept aside, not removed. The save stands.
func TestReplacedFileUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads files without permission")
	}
	e := newEnv(t)
	v := e.open()
	before := e.read()
	var tmp string
	setHook(t, func(p, file string) {
		switch p {
		case hookTempCreated:
			tmp = file
		case hookRenamed:
			// tmp holds the old vault now.
			if err := os.Chmod(tmp, 0); err != nil {
				t.Error(err)
			}
		}
	})
	e.take()
	if _, err := v.Add(testEntry("a", "pw"), false); err != nil {
		t.Fatalf("save: %v", err)
	}
	w, _ := e.take()
	if len(w) != 1 || !strings.Contains(w[0], "couldn't be checked") || !strings.Contains(w[0], ".conflict-") {
		t.Fatalf("warnings %q", w)
	}
	kept, _ := filepath.Glob(filepath.Join(e.dir, "vault.conflict-*.passh"))
	if len(kept) != 1 {
		t.Fatalf("kept %v", kept)
	}
	if err := os.Chmod(kept[0], 0o600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, kept[0]), before) {
		t.Fatal("the kept file isn't the replaced vault")
	}
	if r := e.open().Info().Revision; r != 2 {
		t.Fatalf("the vault holds r%d", r)
	}
}

// CORE-007 regression: a temporary file that can't be locked is removed,
// and the error says what failed.
func TestWriteTempLockFails(t *testing.T) {
	dir := t.TempDir()
	setFlock(t, func(int, int) error { return syscall.ENOLCK })
	if _, err := writeTemp(dir, "vault.passh", []byte("x"), "", "", ""); err == nil ||
		!errors.Is(err, syscall.ENOLCK) || !strings.Contains(err.Error(), "locking the temporary file") {
		t.Fatalf("writeTemp: %v", err)
	}
	if left := temps(t, dir); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}
