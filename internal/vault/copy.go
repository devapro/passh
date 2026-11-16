package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/vaultfile"
)

// ErrCopyVerify means a checked copy didn't read back as written. Nothing
// was left under the copy's name.
var ErrCopyVerify = i18n.NewError("the copy didn't read back as written; nothing was written under its name")

// CopyResult describes a copy made by CopyChecked.
type CopyResult struct {
	// SHA256 is the copy's SHA-256, as read back.
	SHA256 [sha256.Size]byte
	// Size is the copy's size in bytes.
	Size int
	// Canonical reports whether the source was in canonical form: the copy
	// is then byte for byte the source. Otherwise the copy is the source
	// re-encoded in canonical form (§4.8), and its SHA-256 differs.
	Canonical bool
}

// CopyChecked makes a checked copy of the vault file src at dst, for
// `passh backup <dest>` (§4.8). No passphrase is needed: src must pass the
// structure check (vaultfile.Parse), and a copy that isn't in canonical
// form (line endings or wrapping changed in copying) is written in
// canonical form.
//
// The copy is complete or absent (FILE-2, INV-11): it is written to a
// temporary file ".<name>.tmp-…" in dst's folder (mode 0600), fsynced,
// read back and compared, then renamed to dst without replacing anything,
// and the folder is fsynced. On a file system without a no-replace rename
// or hard links (FAT, exFAT) the rename falls back as the vault's backups
// do (renameNoReplace). On any failure the temporary file is removed and
// nothing is left under dst; one left by a crash is removed by the next
// copy to the same name.
//
// An existing dst is refused with an error matching ErrExists; a copy that
// reads back differently with ErrCopyVerify. ctx is checked between the
// steps.
func CopyChecked(ctx context.Context, src, dst string) (CopyResult, error) {
	var res CopyResult
	data, err := readVaultFile(src)
	if errors.Is(err, errTooLarge) || errors.Is(err, errNotRegular) {
		return res, i18n.Errorf("%s: %w", src, err)
	}
	if err != nil {
		return res, err
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		return res, i18n.Errorf("%s doesn't pass the structure check, so it isn't copied: %w", src, err)
	}
	content := data
	if !f.Canonical {
		if content, err = vaultfile.Encode(f.KeyBlock, f.DataBlock); err != nil {
			return res, err
		}
	}
	want := sha256.Sum256(content)

	exists := func() error {
		return i18n.Errorf("%s: %w; passh doesn't overwrite files", dst, ErrExists)
	}
	if _, err := os.Lstat(dst); err == nil {
		return res, exists()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	dir, name := filepath.Split(dst)
	dir = filepath.Clean(dir)
	// Leftovers of an interrupted copy to the same name. Best effort: one
	// that can't be removed is no reason not to make this copy.
	_, _ = removeTemps(dir, name)
	if err := ctx.Err(); err != nil {
		return res, err
	}

	t, err := writeTemp(dir, name, content, hookCopyCreated, hookCopyWritten, hookCopySynced)
	if err != nil {
		return res, i18n.Errorf("writing %s: %w", dst, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			t.discard() // FILE-5: nothing stays behind on a failure
		}
	}()
	back, err := readBack(t.path, len(content))
	if err != nil {
		return res, i18n.Errorf("reading back the copy of %s: %w", dst, err)
	}
	got := sha256.Sum256(back)
	if got != want || !bytes.Equal(back, content) {
		return res, i18n.Errorf("%s (SHA-256 %x, expected %x): %w", dst, got, want, ErrCopyVerify)
	}
	hook(hookCopyVerified, t.path)
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if err := renameNoReplace(t.path, dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return res, exists()
		}
		return res, i18n.Errorf("writing %s: %w", dst, err)
	}
	renamed = true
	// Renamed and fsynced already: closing only releases the descriptor
	// and its lock (see tempFile.close).
	_ = t.close()
	hook(hookCopyRenamed, dst)
	if err := syncDir(dir); err != nil {
		return res, i18n.Errorf("%s is written, but its folder couldn't be synced: %w", dst, err)
	}
	res.SHA256, res.Size, res.Canonical = got, len(content), f.Canonical
	return res, nil
}

// readBack reads the file at path, which should hold size bytes; a longer
// file is read only as far as needed to tell.
func readBack(path string, size int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // read-only
	return io.ReadAll(io.LimitReader(f, int64(size)+1))
}
