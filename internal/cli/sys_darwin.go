//go:build darwin

package cli

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// memoryCheck on macOS reads the total memory (hw.memsize). macOS has no
// cheap "available memory" figure like Linux's MemAvailable (it needs Mach
// host statistics, i.e. cgo), and it compresses and swaps memory freely,
// so only the total is judged.
func memoryCheck() (level, string) {
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return levelSkip, fmt.Sprintf("can't read the memory size: %v", err)
	}
	l, msg := memoryVerdict(total, "in total")
	return l, msg + "; available memory isn't checked on macOS"
}

// swapCheck reads vm.swapusage (struct xsw_usage: total, avail, used as
// uint64, page size as uint32, encrypted as boolean_t). macOS swaps
// dynamically and encrypts swap by default.
func swapCheck() (level, string) {
	raw, err := unix.SysctlRaw("vm.swapusage")
	if err != nil || len(raw) < 32 {
		return levelSkip, fmt.Sprintf("can't read vm.swapusage: %v", err)
	}
	total := binary.LittleEndian.Uint64(raw[0:8])
	used := binary.LittleEndian.Uint64(raw[16:24])
	encrypted := binary.LittleEndian.Uint32(raw[28:32]) != 0
	switch {
	case total == 0:
		return levelOK, "no swap is in use"
	case encrypted:
		return levelInfo, fmt.Sprintf("swap is active (%s used) and encrypted by macOS", formatBytes(used))
	}
	return levelWarn, fmt.Sprintf("swap is active (%s used) and not encrypted: process memory, decrypted secrets included, may be written to disk", formatBytes(used))
}

// onTmpfs reports whether dir is on a memory file system. macOS has no
// tmpfs by default, so a plaintext export is almost always on disk.
func onTmpfs(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	name := st.Fstypename[:]
	for i, c := range name {
		if c == 0 {
			name = name[:i]
			break
		}
	}
	return string(name) == "tmpfs"
}
