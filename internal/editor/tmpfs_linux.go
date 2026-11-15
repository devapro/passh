//go:build linux

package editor

import "golang.org/x/sys/unix"

// onTmpfs reports whether dir is on a RAM-backed file system: tmpfs, or
// ramfs (which is never even swapped out).
func onTmpfs(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	// The magic numbers are 32 bits; Statfs_t.Type is int32 on 32-bit ARM
	// (where RAMFS_MAGIC overflows it), int64 or uint32 elsewhere.
	t := uint32(st.Type)
	return t == unix.TMPFS_MAGIC || t == unix.RAMFS_MAGIC
}
