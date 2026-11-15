//go:build !linux && !darwin

package vault

// exchange is not available: the caller falls back to a plain rename.
func exchange(a, b string) error { return errNoAtomicRename }

// renameNoReplaceOS is not available: renameNoReplace falls back to link.
func renameNoReplaceOS(old, new string) error { return errNoAtomicRename }
