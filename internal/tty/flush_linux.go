package tty

import "golang.org/x/sys/unix"

// flushInput discards input the terminal fd has received but nobody has
// read (TCIFLUSH): typed ahead at a prompt that didn't end with an answer.
func flushInput(fd int) error { return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) }
