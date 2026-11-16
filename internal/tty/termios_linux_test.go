package tty

import "golang.org/x/sys/unix"

// ioctlGetTermios reads the terminal attributes.
const ioctlGetTermios = unix.TCGETS

// ioctlInputPending reads how many input bytes wait to be read.
const ioctlInputPending = unix.TIOCINQ
