package importpass

import (
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"passh/internal/tty"
)

// terminalName returns the device path (such as /dev/pts/3 or
// /dev/ttys004) of the first of files that is a terminal, or "". gpg passes
// it to pinentry as GPG_TTY, as `export GPG_TTY=$(tty)` does for pass:
// gpg's stdin is a pipe here, so gpg can't find the terminal by itself.
func terminalName(files ...*os.File) string {
	for _, f := range files {
		if !tty.IsTerminal(f) {
			continue
		}
		if n := ttyName(f); n != "" {
			return n
		}
	}
	return ""
}

// ttyName returns the device path of the terminal f, or "". On Linux it
// reads /proc/self/fd; elsewhere it looks in /dev for the character device
// with f's device number, as ttyname(3) does.
func ttyName(f *os.File) string {
	if n, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd()))); err == nil && isTTYPath(n) {
		return n
	}
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return findDevice(st, "/dev/pts", "/dev")
}

// isTTYPath accepts a device path, but not /dev/tty: that names the
// controlling terminal of whoever opens it, and pinentry (started by
// gpg-agent) has none.
func isTTYPath(p string) bool {
	return strings.HasPrefix(p, "/dev/") && p != "/dev/tty"
}

// findDevice returns the path of the character device in dirs whose device
// number is want's, or "".
func findDevice(want *syscall.Stat_t, dirs ...string) string {
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.Type()&fs.ModeCharDevice == 0 {
				continue
			}
			p := dir + "/" + e.Name()
			if !isTTYPath(p) {
				continue
			}
			fi, err := os.Stat(p)
			if err != nil {
				continue
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Rdev == want.Rdev {
				return p
			}
		}
	}
	return ""
}
