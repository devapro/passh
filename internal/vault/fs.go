package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// maxFileSize bounds what Open reads, so a wrong path (a disk image, a
// device) fails fast instead of filling memory.
const maxFileSize = 64 << 20

// readVaultFile reads a vault file: a regular file of at most maxFileSize
// bytes. A missing file gives an error matching fs.ErrNotExist.
func readVaultFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, errTooLarge
	}
	return data, nil
}

// realPath resolves symlinks in path (which must be absolute). The vault is
// written to the target of a symlink, and the link is kept (§4.6).
func realPath(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

// syncFile is the only way this package fsyncs a file or a folder, so the
// tests can check that every write is synced, and in which order.
var syncFile = (*os.File).Sync

// closeFile closes a temporary file after its rename, and flock takes the
// locks on files; they are variables so the tests can make them fail.
var (
	closeFile = (*os.File).Close
	flock     = unix.Flock
)

// syncDir fsyncs a folder so that a rename or a new entry in it is durable.
// File systems that can't sync folders (some network and FUSE file
// systems) are tolerated.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := syncFile(d); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) ||
			errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.ENOTTY) {
			return nil
		}
		return err
	}
	return nil
}

// mkdirs creates dir and its missing parents with mode 0700 (exactly, not
// reduced by the umask), and fsyncs the parent of each folder it creates.
// Existing folders are left as they are.
func mkdirs(dir string) error {
	if st, err := os.Stat(dir); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("%s is not a folder", dir)
		}
		return nil
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirs(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return syncDir(parent)
}

// tempPrefix is the name prefix of the temporary files of a file named
// name: ".<name>.tmp-" (§3.2).
func tempPrefix(name string) string { return "." + name + ".tmp-" }

// A temporary file is flocked by its writer from its creation until it is
// renamed into place or removed. removeTemps skips temporary files it can't
// lock, so a cleaner never deletes the file of a save in progress, even one
// that serializes on another lock file (another state folder, a
// case-insensitive or bind-mounted path).

// tempFile is a temporary file being written, locked by its writer.
type tempFile struct {
	f    *os.File
	path string
	// kept means the file at path must survive discard: after a failed
	// exchange it holds another version of the vault that couldn't be
	// moved aside, and an error message names it (§4.6: nothing is lost).
	kept bool
}

// writeTemp writes content to a new temporary file ".<name>.tmp-<random>"
// in dir with mode 0600 and fsyncs it. The file stays open and locked until
// close or discard. The hook points name the steps: created, written
// (before fsync) and synced. On error the file is removed.
func writeTemp(dir, name string, content []byte, created, written, synced string) (*tempFile, error) {
	var t *tempFile
	for attempt := 0; t == nil; attempt++ {
		f, err := os.CreateTemp(dir, tempPrefix(name)+"*")
		if err != nil {
			return nil, err
		}
		if err := flockNB(f); err != nil {
			// FILE-5: the file is empty and ours; nothing else may stay.
			_ = f.Close()
			_ = os.Remove(f.Name())
			return nil, fmt.Errorf("locking the temporary file: %w", err)
		}
		// A cleaner may have removed the file between its creation and
		// the lock; then start again with a new one.
		if !samePath(f, f.Name()) {
			_ = f.Close() // empty, and no longer at its name: nothing to lose
			if attempt == 2 {
				return nil, errors.New("temporary files keep disappearing")
			}
			continue
		}
		t = &tempFile{f: f, path: f.Name()}
	}
	if err := t.write(content, created, written, synced); err != nil {
		t.discard()
		return nil, err
	}
	return t, nil
}

func (t *tempFile) write(content []byte, created, written, synced string) error {
	// CreateTemp made the file 0600 (the umask can only narrow that);
	// file systems without Unix modes (FAT, exFAT: a backup on a USB
	// stick) refuse the chmod, which then changes nothing.
	if err := t.f.Chmod(0o600); err != nil && !noModes(err) {
		return err
	}
	hook(created, t.path)
	if _, err := t.f.Write(content); err != nil {
		return err
	}
	hook(written, t.path)
	if err := syncFile(t.f); err != nil {
		return err
	}
	hook(synced, t.path)
	return nil
}

// noModes reports whether a chmod error means the file system has no Unix
// modes to set.
func noModes(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}

// close releases the file (and its lock) after it was renamed into place.
// The file was fsynced before the rename (FILE-3), so a close error can't
// mean lost data, and it can't be undone either: callers that can warn
// pass it on as a warning, never as a failed write.
func (t *tempFile) close() error { return closeFile(t.f) }

// discard removes the file, still locked, then releases it. A kept file
// is only released.
func (t *tempFile) discard() {
	if !t.kept {
		_ = os.Remove(t.path) // best effort: the next save's removeTemps retries
	}
	_ = t.f.Close() // the file is gone or kept as it is; nothing was promised about it
}

// flockNB takes an exclusive flock on f without waiting.
func flockNB(f *os.File) error {
	for {
		err := flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// samePath reports whether path still names the open file f.
func samePath(f *os.File, path string) bool {
	a, err := f.Stat()
	if err != nil {
		return false
	}
	b, err := os.Lstat(path)
	return err == nil && os.SameFile(a, b)
}

// removeTemps removes the temporary files that interrupted writes of
// dir/name left behind. A temporary file that another writer holds locked
// is in use and stays. It reports how many it removed.
func removeTemps(dir, name string) (int, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	prefix := tempPrefix(name)
	n := 0
	var firstErr error
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), prefix) || !e.Type().IsRegular() {
			continue
		}
		removed, err := removeTemp(filepath.Join(dir, e.Name()))
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if removed {
			n++
		}
	}
	return n, firstErr
}

// removeTemp removes one leftover temporary file unless its writer still
// holds it locked.
func removeTemp(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := flockNB(f); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil // a save in progress
		}
		return false, err
	}
	if !samePath(f, path) {
		return false, nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}

// TempFiles lists the temporary files that interrupted saves left next to
// the vault file at path (or its symlink target), for `passh doctor`. The
// next save removes them.
func TempFiles(path string) ([]string, error) {
	real, err := realPath(path)
	if err != nil {
		return nil, err
	}
	dir, name := filepath.Split(real)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tempPrefix(name)) && e.Type().IsRegular() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// writeAtomic replaces path with content: a temporary file in the same
// folder (mode 0600, fsynced), renamed over path, then the folder fsynced.
// Leftover temporary files of path are removed first; the caller holds the
// lock that serializes writers of path.
func writeAtomic(path string, content []byte, synced string) error {
	dir, name := filepath.Split(path)
	dir = filepath.Clean(dir)
	if _, err := removeTemps(dir, name); err != nil {
		return err
	}
	t, err := writeTemp(dir, name, content, "", "", synced)
	if err != nil {
		return err
	}
	if err := os.Rename(t.path, path); err != nil {
		t.discard()
		return err
	}
	// Renamed and fsynced already: closing only releases the descriptor
	// and its lock (see tempFile.close).
	_ = t.close()
	return syncDir(dir)
}

// errNoAtomicRename means the file system (or OS) has no exchanging or
// no-replace rename; the callers fall back.
var errNoAtomicRename = errors.New("atomic rename not supported")

// The renames this package needs beyond rename(2). They are variables so
// the tests can take the fallbacks.
var (
	// exchangeFiles swaps the files at a and b atomically (Linux:
	// renameat2 RENAME_EXCHANGE; macOS: renamex_np RENAME_SWAP).
	exchangeFiles = exchange
	// renameNoReplaceFn renames old to new unless new exists (Linux:
	// RENAME_NOREPLACE; macOS: RENAME_EXCL).
	renameNoReplaceFn = renameNoReplaceOS
	// linkFile is the hard link renameNoReplace falls back to.
	linkFile = os.Link
)

// unsupportedRename reports whether a rename error means the operation
// isn't available here, rather than that it failed.
func unsupportedRename(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}

// renameNoReplace renames old to new, failing with an error matching
// fs.ErrExist if new exists. Without a no-replace rename it links new to
// old and removes old; where hard links don't work either (FAT), it checks
// that new doesn't exist and renames, which leaves a tiny window.
func renameNoReplace(old, new string) error {
	err := renameNoReplaceFn(old, new)
	if !errors.Is(err, errNoAtomicRename) {
		return err
	}
	if err := linkFile(old, new); err == nil {
		return os.Remove(old)
	} else if errors.Is(err, fs.ErrExist) {
		return err
	}
	if _, err := os.Lstat(new); err == nil {
		return &os.LinkError{Op: "rename", Old: old, New: new, Err: fs.ErrExist}
	}
	return os.Rename(old, new)
}

// fileLock is an exclusive flock on a lock file.
type fileLock struct{ f *os.File }

// lockPoll is how often a waiting lock retries; lockWait is how long it
// waits in total. Tests shorten them (restored with t.Cleanup).
var (
	lockPoll = 20 * time.Millisecond
	lockWait = 15 * time.Second
)

// lockFile takes an exclusive flock on path, creating it with mode 0600 if
// needed. flock is per open file, so two Vaults in one process exclude each
// other as two processes do, and the lock goes away with the process. It
// waits up to lockWait, then fails with ErrLocked. A cancelled ctx ends
// the wait at once (CONC-1) with an error wrapping ctx.Err(); a lock that
// is free is taken even then, since that doesn't wait.
func lockFile(ctx context.Context, path string) (*fileLock, error) {
	// Read-only is enough for flock, and works even if a strict umask
	// left the file without write permission.
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the lock file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close() // read-only, not locked: nothing to lose
		return nil, fmt.Errorf("opening the lock file: %w", err)
	}
	// The timers start when the lock is first found busy.
	var deadline, poll *time.Timer
	defer func() {
		if deadline != nil {
			deadline.Stop()
			poll.Stop()
		}
	}()
	for {
		err := flockNB(f)
		switch {
		case err == nil:
			return &fileLock{f: f}, nil
		case !errors.Is(err, unix.EWOULDBLOCK):
			_ = f.Close() // read-only, not locked
			return nil, fmt.Errorf("locking %s: %w", path, err)
		}
		if deadline == nil {
			hook(hookLockBusy, path)
			deadline, poll = time.NewTimer(lockWait), time.NewTimer(lockPoll)
		} else {
			poll.Reset(lockPoll)
		}
		select {
		case <-ctx.Done():
			_ = f.Close() // read-only, not locked
			return nil, fmt.Errorf("stopped waiting for another passh process: %w", ctx.Err())
		case <-deadline.C:
			_ = f.Close() // read-only, not locked
			return nil, ErrLocked
		case <-poll.C:
		}
	}
}

func (l *fileLock) unlock() {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
}

// hashName is a file-name-safe digest of s: 32 hex characters.
func hashName(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:16])
}

// isWithin reports whether path lies inside dir (both cleaned, absolute).
func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}
