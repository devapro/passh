package tty

import "golang.org/x/sys/unix"

// flushInput discards input the terminal fd has received but nobody has
// read (TIOCFLUSH with FREAD): typed ahead at a prompt that didn't end with
// an answer.
func flushInput(fd int) error {
	const fread = 1 // FREAD of <sys/fcntl.h>
	return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fread)
}
