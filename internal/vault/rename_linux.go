package vault

import (
	"golang.org/x/sys/unix"
)

// exchange swaps the files at a and b atomically: renameat2 with
// RENAME_EXCHANGE (Linux 3.15+; ext4, xfs, btrfs, tmpfs and others).
func exchange(a, b string) error {
	err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
	if err != nil && unsupportedRename(err) {
		return errNoAtomicRename
	}
	return err
}

// renameNoReplaceOS is renameat2 with RENAME_NOREPLACE.
func renameNoReplaceOS(old, new string) error {
	err := unix.Renameat2(unix.AT_FDCWD, old, unix.AT_FDCWD, new, unix.RENAME_NOREPLACE)
	if err != nil && unsupportedRename(err) {
		return errNoAtomicRename
	}
	return err
}
