package tty

import (
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// DeviceName returns the path of the terminal device f is open on, such as
// /dev/pts/3 or /dev/ttys004, or "" if f isn't a terminal or the device
// can't be found. For /dev/tty it returns the controlling terminal's own
// device: gpg's pinentry needs that as GPG_TTY (§4.9), because /dev/tty
// names the controlling terminal of whoever opens it, and pinentry, started
// by gpg-agent, has none.
func DeviceName(f *os.File) string {
	if !IsTerminal(f) {
		return ""
	}
	var (
		name string
		dev  uint64
		ok   bool
	)
	_ = control(f, func(fd int) {
		// Linux names the device of an open file in /proc.
		if n, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil && isDevicePath(n) {
			name = n
			return
		}
		dev, ok = fileDevice(fd)
		if ttyDev, isTTY := pathDevice("/dev/tty"); ok && isTTY && dev == ttyDev {
			dev, ok = controllingDevice(fd)
		}
	})
	if name != "" || !ok {
		return name
	}
	return findDevice(dev, "/dev/pts", "/dev")
}

// DeviceName is DeviceName(t.File()).
func (t *TTY) DeviceName() string { return DeviceName(t.f) }

// isDevicePath accepts a terminal device path, but not /dev/tty (see
// DeviceName).
func isDevicePath(p string) bool {
	return strings.HasPrefix(p, "/dev/") && p != "/dev/tty"
}

// findDevice returns the path of the character device in dirs whose device
// number is dev, or "", as ttyname(3) does.
func findDevice(dev uint64, dirs ...string) string {
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
			if !isDevicePath(p) {
				continue
			}
			if d, ok := pathDevice(p); ok && d == dev {
				return p
			}
		}
	}
	return ""
}
