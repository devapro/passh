package acceptance

import "golang.org/x/sys/unix"

// ioctlGetTermios reads the terminal attributes.
const ioctlGetTermios = unix.TCGETS
