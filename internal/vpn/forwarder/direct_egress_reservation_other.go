//go:build !linux

package forwarder

import (
	"fmt"
	"io"
)

// reserveHostPort fails closed on platforms without the Linux host-socket
// ownership primitives. Direct WAN egress itself is Linux-only (the production
// WAN device is unavailable elsewhere), so refusing is the safe answer: a
// reservation that cannot be proven must never be assumed.
func reserveHostPort(proto uint8, port uint16) (io.Closer, error) {
	return nil, fmt.Errorf("%w: port %d: host tuple reservation requires Linux sockets",
		ErrHostTupleOwnershipUnavailable, port)
}
