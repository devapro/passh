package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// socketPeerUID reads the peer's uid with SO_PEERCRED: the credentials the
// kernel recorded when the peer connected (or, for a client, when the
// server called listen), so the peer can't fake them.
func socketPeerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
