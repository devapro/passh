package tty

import "golang.org/x/sys/unix"

// ioctlGetTermios reads the terminal attributes.
const ioctlGetTermios = unix.TIOCGETA

// ioctlInputPending reads how many input bytes wait to be read (FIONREAD).
const ioctlInputPending = 0x4004667f
