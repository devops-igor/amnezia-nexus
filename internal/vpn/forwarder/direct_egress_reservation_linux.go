//go:build linux

package forwarder

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// protoTCP and protoUDP are the IP protocol numbers direct egress handles.
const (
	protoTCP = 6
	protoUDP = 17
)

// rejectAllFilter drops every datagram the kernel delivers to the reservation
// socket, so an owned tuple can never accumulate a receive queue. It is a single
// unconditional-return instruction. The array form keeps its length a
// compile-time constant, so the program header below carries an exact constant
// rather than a narrowing conversion of a runtime slice length.
var rejectAllFilter = [...]unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}

// reserveHostPort takes exclusive kernel ownership of the host tuple
// (wildcard address, port) for the IP protocol and returns the socket that holds
// it.
//
// Direct-NAT replies are read from AF_PACKET, which sees packets before kernel
// protocol processing and is not filtered by INPUT/OUTPUT firewall policy. The
// userspace port maps alone therefore cannot prove that a reply belongs to the
// VPN binding: an unrelated local socket can own the same (address, port) tuple
// (the panel's own resolver is one example) and its reply would be attributed to
// the VPN flow and delivered to the peer. Binding our own socket to the tuple
// removes that ambiguity for the entire binding lifetime:
//
//   - the bind is wildcard and never sets SO_REUSEADDR or SO_REUSEPORT, so no
//     later local bind of that port can succeed, whether it asks for the exact
//     WAN address, the wildcard address, or asks for reuse. Linux refuses the
//     later bind with EADDRINUSE in both orderings.
//   - the same strictness makes a bind fail here when the port is already owned,
//     which is how a host-first collision is detected instead of taken over.
//   - the socket is never listened on, connected, read or written. A TCP socket
//     that is bound but not listening is absent from the kernel's established and
//     listen tables, so direct-WAN TCP replies are not delivered to it and the
//     WAN device's INPUT DROP rule keeps suppressing the resets and ICMP errors
//     the kernel would otherwise emit. UDP duplicates that the INPUT socket
//     exemption lets through are discarded by the reject-all filter.
//
// The reservation is a bounded local socket/bind sequence: no name resolution,
// file or network I/O, and no packet is sent or received.
func reserveHostPort(proto uint8, port uint16) (io.Closer, error) {
	sockType := unix.SOCK_DGRAM
	if proto == protoTCP {
		sockType = unix.SOCK_STREAM
	}
	fd, err := unix.Socket(unix.AF_INET, sockType|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: port %d: create socket: %w", ErrHostTupleOwnershipUnavailable, port, err)
	}

	// Filtering is defense in depth for the UDP duplicate path only; the kernel
	// refuses a filter on an unprivileged TCP socket (EPERM), so a failure is not
	// treated as a reservation failure.
	prog := unix.SockFprog{Len: uint16(len(rejectAllFilter)), Filter: &rejectAllFilter[0]}
	_ = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)

	sockaddr := &unix.SockaddrInet4{Port: int(port)}
	if err := unix.Bind(fd, sockaddr); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, fmt.Errorf("%w: port %d", errHostTupleInUse, port)
		}
		return nil, fmt.Errorf("%w: port %d: bind: %w", ErrHostTupleOwnershipUnavailable, port, err)
	}
	return &hostPortSocket{fd: fd}, nil
}

// hostPortSocket is the kernel socket that holds one host tuple.
type hostPortSocket struct {
	fd int
}

// Close releases the tuple. It is idempotent and never blocks.
func (s *hostPortSocket) Close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	fd := s.fd
	s.fd = -1
	return unix.Close(fd)
}
