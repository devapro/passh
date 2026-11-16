//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/devapro/passh/internal/i18n"
)

// memoryCheck reads MemAvailable from /proc/meminfo: the memory a new
// process can use without swapping.
func memoryCheck(p i18n.Printer) (level, string) {
	kb, err := meminfoField("/proc/meminfo", "MemAvailable")
	if err != nil {
		return levelSkip, p.T("can't read the available memory: %v", err)
	}
	return memoryVerdict(p, kb<<10, false)
}

// meminfoField returns a field of a /proc/meminfo-style file, in KiB.
func meminfoField(path, name string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || key != name {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			break
		}
		return strconv.ParseUint(fields[0], 10, 64)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s has no %s line", path, name)
}

// swapCheck reads /proc/swaps: any active swap area is a warning, because
// process memory, decrypted secrets included, may be written to disk
// (§5.5; passh doesn't lock memory, by design).
func swapCheck(p i18n.Printer) (level, string) {
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return levelSkip, p.T("can't read /proc/swaps: %v", err)
	}
	var areas int
	var total uint64
	for i, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 3 {
			continue // header
		}
		areas++
		if kb, err := strconv.ParseUint(f[2], 10, 64); err == nil {
			total += kb << 10
		}
	}
	if areas == 0 {
		return levelOK, p.T("no swap is active")
	}
	return levelWarn, p.N(areas,
		"%d swap area is active (%s): process memory, decrypted secrets included, may be written to disk. "+
			"passh doesn't change this; turn swap off or encrypt it if that matters to you",
		"%d swap areas are active (%s): process memory, decrypted secrets included, may be written to disk. "+
			"passh doesn't change this; turn swap off or encrypt it if that matters to you",
		areas, formatBytes(p, total))
}

// onTmpfs reports whether dir is on a memory file system (tmpfs or ramfs),
// where a plaintext export doesn't reach persistent disk (§7.1).
func onTmpfs(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	// Type is int32 on 32-bit systems, where RAMFS_MAGIC is negative.
	t := uint32(st.Type) //nolint:gosec // a magic number, not a size
	return t == unix.TMPFS_MAGIC || t == unix.RAMFS_MAGIC
}
