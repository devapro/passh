package vault

import (
	"golang.org/x/sys/unix"
)

// exchange swaps the files at a and b atomically: renamex_np with
// RENAME_SWAP (macOS 10.12+, APFS and HFS+). Where the file system lacks
// it, the caller falls back to a plain rename (see commit).
func exchange(a, b string) error {
	err := unix.RenamexNp(a, b, unix.RENAME_SWAP)
	if err != nil && unsupportedRename(err) {
		return errNoAtomicRename
	}
	return err
}

// renameNoReplaceOS is renamex_np with RENAME_EXCL.
func renameNoReplaceOS(old, new string) error {
	err := unix.RenamexNp(old, new, unix.RENAME_EXCL)
	if err != nil && unsupportedRename(err) {
		return errNoAtomicRename
	}
	return err
}
