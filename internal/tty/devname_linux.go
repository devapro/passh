package tty

import "golang.org/x/sys/unix"

// fileDevice returns the device number of the character device open as fd.
func fileDevice(fd int) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return 0, false
	}
	return st.Rdev, true
}

// pathDevice returns the device number of the character device at path.
func pathDevice(path string) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return 0, false
	}
	return st.Rdev, true
}

// controllingDevice returns the device number of the terminal behind fd,
// which is open on /dev/tty: TIOCGDEV, in the encoding stat uses.
func controllingDevice(fd int) (uint64, bool) {
	d, err := unix.IoctlGetUint32(fd, unix.TIOCGDEV)
	if err != nil {
		return 0, false
	}
	return uint64(d), true
}
