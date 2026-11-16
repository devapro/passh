package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/tty"
)

// output is where a plaintext document goes (§7.1, §7.2): a new file (-o)
// or stdout, never a terminal.
type output struct {
	path string // "" means stdout
}

// prepareOutput checks the destination before anything is unlocked: -o
// must not exist; without -o, stdout must not be a terminal. what names
// the data in the refusal ("export data", "the sheet").
func (a *app) prepareOutput(o, what string) (output, error) {
	if o == "" {
		if tty.IsTerminal(a.stdout) {
			return output{}, fmt.Errorf("refusing to write %s to a terminal: add -o file or redirect stdout", what)
		}
		return output{}, nil
	}
	p, err := config.ExpandPath(o)
	if err != nil {
		return output{}, err
	}
	if _, err := os.Lstat(p); err == nil {
		return output{}, fmt.Errorf("%s already exists; passh doesn't overwrite files", config.ContractHome(p))
	}
	return output{path: p}, nil
}

// write writes data to the destination and returns its name for messages.
// A new file gets mode 0600; if it isn't on tmpfs and holds plaintext,
// passh warns (§7.1).
func (a *app) write(out output, data []byte, plaintext bool) (string, error) {
	if out.path == "" {
		_, err := a.stdout.Write(data)
		return "stdout", err
	}
	if err := writeNew(out.path, data); err != nil {
		return "", err
	}
	dest := displayPath(out.path)
	if plaintext && !onTmpfs(filepath.Dir(out.path)) {
		a.warnf("%s isn't on tmpfs: the plaintext is on persistent disk. Delete it when you're done", dest)
	}
	return dest, nil
}

// Test hooks; the production values are the os package's.
var (
	syncFile   = (*os.File).Sync
	removeFile = os.Remove
)

// writeNew creates path, which must not exist, with mode 0600 (never
// through a symlink, never overwriting: O_EXCL), writes data and fsyncs the
// file and its folder: the -o files of export, print and recovery-key
// print (§7.1, §7.2). (`backup <dest>` goes through vault.CopyChecked.)
//
// On any failure the new file is removed, and the error says whether that
// worked: a partial file holds plaintext (an export, a sheet, the recovery
// key), so a removal that fails is reported, never dropped (FILE-5,
// CLI-006).
func writeNew(path string, data []byte) (err error) {
	show := config.ContractHome(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; passh doesn't overwrite files", show)
	}
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if err == nil {
			return
		}
		if !closed {
			_ = f.Close() // the earlier error is the one reported
		}
		if rerr := removeFile(path); rerr != nil {
			err = fmt.Errorf("%w; the partial file %s could not be removed (%v): delete it", err, show, rerr)
			return
		}
		err = fmt.Errorf("%w; the partial file was removed", err)
	}()
	// The umask can only narrow 0600; some file systems (FAT) have no
	// modes, so a failed chmod there is no reason to fail.
	_ = f.Chmod(0o600)
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing %s: %w", show, err)
	}
	if err := syncFile(f); err != nil {
		return fmt.Errorf("writing %s: %w", show, err)
	}
	closed = true
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", show, err)
	}
	syncDirBestEffort(filepath.Dir(path))
	return nil
}
