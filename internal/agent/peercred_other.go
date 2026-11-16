//go:build !linux && !darwin

package agent

import (
	"net"

	"github.com/devapro/passh/internal/i18n"
)

// socketPeerUID: passh supports peer credentials on Linux and macOS only.
// Elsewhere every peer is refused.
func socketPeerUID(*net.UnixConn) (int, error) {
	return -1, i18n.NewError("peer credentials are not supported on this system")
}
