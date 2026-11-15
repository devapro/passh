package vault

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/paths"
)

// savePoints runs one save with backups and a rollback record update and
// returns the hook points it passed, in order.
func savePoints(t *testing.T) []string {
	t.Helper()
	e := newEnv(t)
	v := e.open()
	var points []string
	testHook = func(p, _ string) { points = append(points, p) }
	defer func() { testHook = nil }()
	mustAdd(t, v, "a", "pw")
	return points
}

func TestSavePoints(t *testing.T) {
	want := []string{
		hookLocked, hookChecked, hookTempCreated, hookTempWritten, hookTempSynced, hookVerified, hookRechecked,
		hookBackupWritten, hookBackupSynced, hookBackupRenamed, hookBackupDone, hookBeforeRename, hookRenamed,
		hookOldRemoved, hookDirSynced, hookRecordWritten, hookRecorded,
	}
	if got := savePoints(t); !slices.Equal(got, want) {
		t.Fatalf("save steps\n got %v\nwant %v", got, want)
	}
}

// Safety test 9: a save killed (SIGKILL) at every step of §4.6 — before and
// after each fsync and the rename — leaves a vault that opens, at the old
// or the new revision. The next save removes the leftover temporary files.
func TestCrashAtEveryStep(t *testing.T) {
	t.Run("exchange", func(t *testing.T) { crashAtEveryStep(t, false) })
	t.Run("plain-rename", func(t *testing.T) { crashAtEveryStep(t, true) })
}

func crashAtEveryStep(t *testing.T, plain bool) {
	if plain {
		noExchange(t)
	}
	points := savePoints(t)
	renamedAt := slices.Index(points, hookRenamed)
	oldRemovedAt := slices.Index(points, hookOldRemoved)
	if oldRemovedAt < 0 {
		oldRemovedAt = renamedAt
	}
	for i, point := range points {
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			e.keep = 3
			v := e.open()
			mustAdd(t, v, "old/entry", "old-secret") // revision 2, one backup
			oldRev := v.Info().Revision

			out := runCrashChild(t, e, point, "crash/new", plain)

			// The vault opens, complete, at the old or the new revision.
			w := e.open()
			got := entryPaths(w.Entries())
			wantRev, want := oldRev, []string{"old/entry"}
			if i >= renamedAt {
				wantRev, want = oldRev+1, []string{"crash/new", "old/entry"}
			}
			if w.Info().Revision != wantRev || !slices.Equal(got, want) {
				t.Fatalf("after a crash at %s: revision %d, entries %v; want %d, %v (child: %s)",
					point, w.Info().Revision, got, wantRev, want, out)
			}
			if w.Rollback().Older() {
				t.Fatalf("crash at %s looks like a rollback: %+v", point, w.Rollback())
			}
			// A crash after the temporary file was created and before the
			// rename leaves it behind (the case the next save cleans up).
			left := temps(t, e.dir)
			if created := slices.Index(points, hookTempCreated); i >= created && i < renamedAt && len(left) != 1 {
				t.Fatalf("crash at %s left %v in the vault folder", point, left)
			}
			// Between the exchange and the removal of the old file, the
			// old file is the one temporary file.
			if i >= renamedAt && i < oldRemovedAt && len(left) != 1 {
				t.Fatalf("crash at %s left %v; want the exchanged-out file", point, left)
			}
			if i >= oldRemovedAt && len(left) != 0 {
				t.Fatalf("crash at %s left %v after the rename", point, left)
			}
			// Leftovers hold no plaintext (S1, safety test 2).
			checkNoPlaintext(t, []string{"old-secret", "child-password", "crash/new", "old/entry"}, e.dir, e.state)

			// Every backup is complete and opens.
			bdir := BackupDir(e.state, w.Info().VaultID)
			for _, b := range listBackups(t, e.state) {
				if bv, err := Open(context.Background(), b.Path, keys.FromIdentity(e.key), e.opts()); err != nil {
					t.Fatalf("backup %s: %v", b.Path, err)
				} else if bv.Info().Revision != b.Revision {
					t.Fatalf("backup %s holds r%d", b.Path, bv.Info().Revision)
				}
			}

			// The next save works and removes every leftover.
			mustAdd(t, w, "next/entry", "next-secret")
			if left := temps(t, e.dir); len(left) != 0 {
				t.Fatalf("after the next save: %v in the vault folder", left)
			}
			if left := temps(t, bdir); len(left) != 0 {
				t.Fatalf("after the next save: %v in the backups folder", left)
			}
			if left := temps(t, e.state); len(left) != 0 {
				t.Fatalf("after the next save: %v in the state folder", left)
			}
			if r := e.open().Info().Revision; r != wantRev+1 {
				t.Fatalf("after the next save: revision %d", r)
			}
		})
	}
}

// runCrashChild runs a child that opens the vault and adds entry, killing
// itself at point. It returns the child's output.
func runCrashChild(t *testing.T, e *env, point, entry string, plain bool) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = os.Environ()
	if plain {
		cmd.Env = append(cmd.Env, childPlainRename+"=1")
	}
	cmd.Env = append(cmd.Env,
		childEnv+"=crash",
		childPathEnv+"="+e.path,
		childStateEnv+"="+e.state,
		childCrashEnv+"="+point,
		childEntryEnv+"="+entry,
	)
	cmd.Stdin = strings.NewReader(e.key.String() + "\n")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v, output %q", err, out)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child wasn't killed at %s: %v, output %q", point, err, out)
	}
	return string(out)
}

// Safety test 9: of two passh processes saving changes to the same vault,
// the second is refused, and no change is lost silently.
func TestTwoProcessesSave(t *testing.T) {
	e := newEnv(t)
	type child struct {
		cmd   *exec.Cmd
		in    io.WriteCloser
		out   *bufio.Reader
		entry string
	}
	var kids []*child
	for _, name := range []string{"proc/one", "proc/two"} {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(),
			childEnv+"=concurrent",
			childPathEnv+"="+e.path,
			childStateEnv+"="+e.state,
			childEntryEnv+"="+name,
		)
		cmd.Stderr = os.Stderr
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		c := &child{cmd: cmd, in: in, out: bufio.NewReader(out), entry: name}
		kids = append(kids, c)
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		if _, err := io.WriteString(in, e.key.String()+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	// Both have opened revision 1 before either saves.
	for _, c := range kids {
		if l, err := c.out.ReadString('\n'); err != nil || l != "opened\n" {
			t.Fatalf("child %s: %q %v", c.entry, l, err)
		}
	}
	for _, c := range kids {
		io.WriteString(c.in, "go\n")
	}
	results := map[string]string{}
	for _, c := range kids {
		l, err := c.out.ReadString('\n')
		if err != nil {
			t.Fatalf("child %s: %v", c.entry, err)
		}
		results[c.entry] = strings.TrimSpace(l)
		if err := c.cmd.Wait(); err != nil {
			t.Fatalf("child %s: %v", c.entry, err)
		}
	}
	var winner string
	var oks, refused int
	for name, r := range results {
		switch r {
		case "ok":
			oks++
			winner = name
		case "changed":
			refused++
		default:
			t.Fatalf("child %s: %s", name, r)
		}
	}
	if oks != 1 || refused != 1 {
		t.Fatalf("results %v: want one saved and one refused", results)
	}
	v := e.open()
	if got := entryPaths(v.Entries()); !slices.Equal(got, []string{winner}) || v.Info().Revision != 2 {
		t.Fatalf("vault holds %v at r%d; the saved change was %s", got, v.Info().Revision, winner)
	}
}

// Two Vaults in one process behave like two processes.
func TestTwoInstancesSave(t *testing.T) {
	e := newEnv(t)
	a, b := e.open(), e.open()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, v := range []*Vault{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = v.Add(testEntry("inst/"+string(rune('a'+i)), "pw"), false)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrChanged):
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("errors %v: want exactly one save", errs)
	}
	if n := e.open().Info().Entries; n != 1 {
		t.Fatalf("vault holds %d entries", n)
	}
}

// A save waits for the lock, and gives up with ErrLocked after lockWait.
func TestSaveLock(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	lock, err := lockFile(vaultLockPath(e.state, e.path))
	if err != nil {
		t.Fatal(err)
	}
	defer func(d time.Duration) { lockWait = d }(lockWait)
	lockWait = 100 * time.Millisecond
	before := e.read()
	if _, err := v.Add(testEntry("a", "pw"), false); !errors.Is(err, ErrLocked) {
		t.Fatalf("save while locked: %v", err)
	}
	if !bytes.Equal(e.read(), before) || len(v.Entries()) != 0 {
		t.Fatal("refused save changed something")
	}

	// A waiting save goes ahead once the lock is released.
	lockWait = 10 * time.Second
	done := make(chan error, 1)
	go func() {
		_, err := v.Add(testEntry("a", "pw"), false)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("save didn't wait for the lock: %v", err)
	default:
	}
	lock.unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The lock is keyed by the real path: a symlink shares it.
	link := filepath.Join(t.TempDir(), "link.passh")
	os.Symlink(e.path, link)
	if vaultLockPath(e.state, mustReal(t, link)) != vaultLockPath(e.state, e.path) {
		t.Fatal("a symlink has its own lock")
	}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := realPath(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Leftover temporary files are removed by the next save; other files stay.
func TestLeftoverTempsRemoved(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	stale := []string{".vault.passh.tmp-123", ".vault.passh.tmp-abc"}
	keep := []string{".vault.passh.tmpx", ".other.passh.tmp-1", "vault.passh.tmp-1", "notes.txt"}
	for _, n := range append(slices.Clone(stale), keep...) {
		if err := os.WriteFile(filepath.Join(e.dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := TempFiles(e.path); err != nil || len(got) != len(stale) {
		t.Fatalf("TempFiles: %v %v", got, err)
	}
	mustAdd(t, v, "a", "pw")
	if got, err := TempFiles(e.path); err != nil || len(got) != 0 {
		t.Fatalf("TempFiles after save: %v %v", got, err)
	}
	for _, n := range stale {
		if _, err := os.Stat(filepath.Join(e.dir, n)); err == nil {
			t.Errorf("%s survived the save", n)
		}
	}
	for _, n := range keep {
		if _, err := os.Stat(filepath.Join(e.dir, n)); err != nil {
			t.Errorf("%s was removed: %v", n, err)
		}
	}
}

// Step 5: a temporary file that doesn't read back as written is deleted,
// and the vault, the backups and the in-memory state stay as they were.
func TestReadBackMismatch(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	before := e.read()
	nBackups := len(listBackups(t, e.state))
	for _, damage := range []func([]byte) []byte{
		func(b []byte) []byte { b[len(b)/2] ^= 1; return b },           // flipped bit
		func(b []byte) []byte { return b[:len(b)-10] },                 // short write
		func(b []byte) []byte { return append(b, "trailing\n"...) },    // extra text
		func(b []byte) []byte { return bytes.ToUpper(b) },              // anything else
		func(b []byte) []byte { return append([]byte("x\n"), b...) },   // text before
		func(b []byte) []byte { return bytes.ReplaceAll(b, nl, crlf) }, // same content, other bytes
	} {
		testHook = func(p, file string) {
			if p == hookTempSynced {
				b, _ := os.ReadFile(file)
				os.WriteFile(file, damage(b), 0o600)
			}
		}
		_, err := v.Add(testEntry("b", "pw"), false)
		testHook = nil
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("damaged temporary file: %v", err)
		}
		if !bytes.Equal(e.read(), before) {
			t.Fatal("the vault changed")
		}
		if left := temps(t, e.dir); len(left) != 0 {
			t.Fatalf("temporary file kept: %v", left)
		}
		if len(v.Entries()) != 1 || v.Info().Revision != 2 {
			t.Fatal("in-memory state changed")
		}
		if n := len(listBackups(t, e.state)); n != nBackups {
			t.Fatal("a backup was made for a failed save")
		}
	}
	mustAdd(t, v, "b", "pw")
}

var nl, crlf = []byte("\n"), []byte("\r\n")

// A failed backup fails the save; the vault is unchanged.
func TestBackupFailureStopsSave(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores folder permissions")
	}
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	bdir := BackupDir(e.state, v.Info().VaultID)
	if err := os.Chmod(bdir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(bdir, 0o700)
	before := e.read()
	_, err := v.Add(testEntry("b", "pw"), false)
	if err == nil || !strings.Contains(err.Error(), "making the automatic backup") {
		t.Fatalf("save with a read-only backups folder: %v", err)
	}
	if !bytes.Equal(e.read(), before) || len(temps(t, e.dir)) != 0 || len(v.Entries()) != 1 {
		t.Fatal("failed save left changes")
	}
	os.Chmod(bdir, 0o700)
	mustAdd(t, v, "b", "pw")
}

// A save that can't write its temporary file changes nothing.
func TestUnwritableFolder(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores folder permissions")
	}
	e := newEnv(t)
	v := e.open()
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.dir, 0o700)
	if _, err := v.Add(testEntry("a", "pw"), false); err == nil || !strings.Contains(err.Error(), "the vault is unchanged") {
		t.Fatalf("save to a read-only folder: %v", err)
	}
	if len(v.Entries()) != 0 {
		t.Fatal("in-memory state changed")
	}
}

func TestMoveAndRemoveSave(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a/b", "pw")
	if err := v.Move(paths.MustParse("a/b"), paths.MustParse("c/d")); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove(paths.MustParse("c/d")); err != nil {
		t.Fatal(err)
	}
	w := e.open()
	if w.Info().Entries != 0 || len(w.Snapshot().Deleted) != 1 || w.Info().Revision != 4 {
		t.Fatalf("after move and remove: %+v", w.Info())
	}
}
