//go:build !linux && !darwin

package agent

import (
	"errors"
	"net"
)

// socketPeerUID: passh supports peer credentials on Linux and macOS only.
// Elsewhere every peer is refused.
func socketPeerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("peer credentials are not supported on this system")
}
