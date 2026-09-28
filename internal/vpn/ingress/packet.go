package ingress

import (
	"errors"
	"fmt"
	"net/netip"
)

// DropReason is a stable identifier for why the router discarded a packet.
// Values double as the documented metric counter names.
type DropReason string

const (
	// ReasonMalformed marks packets shorter than an IPv4 header or without
	// an IPv4 version nibble.
	ReasonMalformed DropReason = "malformed_packet_drops"
	// ReasonUnmappedSource marks packets whose parsed source IP has no
	// durable owner in the resolver.
	ReasonUnmappedSource DropReason = "unmapped_source_ip_drops"
	// ReasonOwnershipMismatch marks packets whose source IP is durably owned
	// by a different peer than the one admission authenticated.
	ReasonOwnershipMismatch DropReason = "ownership_mismatch_drops"
)

// Sentinel errors wrap every HandlePacket drop, letting callers and tests
// classify outcomes with errors.Is instead of string matching.
var (
	// ErrDropMalformed wraps malformed packet rejections.
	ErrDropMalformed = errors.New("ingress: malformed packet")
	// ErrDropUnmapped wraps unmapped-source rejections.
	ErrDropUnmapped = errors.New("ingress: unmapped source IP")
	// ErrDropMismatch wraps ownership mismatch rejections.
	ErrDropMismatch = errors.New("ingress: source IP ownership mismatch")
	// ErrAdmissionRejected wraps peer rejection by the admission callback
	// (unknown peer, disabled or expired user, traffic limit, no healthy
	// backend). Data-plane backpressure, not a programming error.
	ErrAdmissionRejected = errors.New("ingress: admission rejected peer")
	// ErrAdmissionContract wraps admission results violating the Admission
	// contract (nil handle on success).
	ErrAdmissionContract = errors.New("ingress: admission contract violation")
)

// ipv4HeaderLen is the minimum IHL=5 IPv4 header length.
const ipv4HeaderLen = 20

// ParseIPv4Source extracts the source address of one plaintext IPv4 packet.
// It is bounded and panic-free: packets shorter than the fixed IPv4 header
// (IHL options are never read) and non-IPv4 version nibbles are rejected.
// Packets with IHL > 20 are accepted: the fixed offsets of the source field
// are identical for every IHL, and the upstream engine already bounded the
// datagram to the TUN MTU. The returned address is always a 4-byte netip.Addr.
func ParseIPv4Source(packet []byte) (netip.Addr, bool) {
	if len(packet) < ipv4HeaderLen {
		return netip.Addr{}, false
	}
	if packet[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}), true
}

// dropError builds one classified drop error.
func dropError(sentinel error, reason DropReason) error {
	return fmt.Errorf("%w: %s", sentinel, reason)
}
