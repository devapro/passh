package tty

import "golang.org/x/sys/unix"

// fileDevice returns the device number of the character device open as fd.
func fileDevice(fd int) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return 0, false
	}
	return uint64(uint32(st.Rdev)), true //nolint:gosec // dev_t is 32 bits; keep its bits
}

// pathDevice returns the device number of the character device at path.
func pathDevice(path string) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return 0, false
	}
	return uint64(uint32(st.Rdev)), true //nolint:gosec // dev_t is 32 bits; keep its bits
}

// controllingDevice returns the device number of the controlling terminal
// of this process (fd is open on /dev/tty, whose fstat names /dev/tty
// itself), from the process table.
func controllingDevice(int) (uint64, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", unix.Getpid())
	if err != nil || kp.Eproc.Tdev == -1 { // NODEV: no controlling terminal
		return 0, false
	}
	return uint64(uint32(kp.Eproc.Tdev)), true //nolint:gosec // dev_t is 32 bits; keep its bits
}
