package ingress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// DropReason is a stable identifier for why the router discarded a packet.
// Values double as the documented metric counter names.
type DropReason string

const (
	// ReasonMalformed marks packets rejected by the strict structural IPv4
	// parse: shorter than a minimum header, wrong version nibble, IHL
	// below 5, header length beyond the received bytes, or a total-length
	// field inconsistent with the header or the received bytes.
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
// It is bounded and panic-free, and structurally strict: a packet is
// rejected unless
//
//   - it carries at least one full header,
//   - the version nibble is 4,
//   - IHL is at least 5,
//   - the IHL-derived header length fits inside the received bytes,
//   - the total-length field is at least the header length, and
//   - the total-length field does not exceed the received length.
//
// A datagram whose self-declared length disagrees with the bytes actually
// received is malformed, not routable — the source field of such a packet
// is never trusted. IHL > 5 stays accepted: the fixed offsets of the source
// field are identical for every IHL, and the upstream engine already
// bounded the datagram to the TUN MTU. No checksum validation happens here;
// the engine has already authenticated the peer. The returned address is
// always a 4-byte netip.Addr.
func ParseIPv4Source(packet []byte) (netip.Addr, bool) {
	if len(packet) < ipv4HeaderLen {
		return netip.Addr{}, false
	}
	if packet[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	ihl := int(packet[0] & 0x0f)
	if ihl < 5 {
		return netip.Addr{}, false
	}
	headerLen := ihl * 4
	if headerLen > len(packet) {
		return netip.Addr{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < headerLen || totalLen > len(packet) {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}), true
}

// dropError builds one classified drop error.
func dropError(sentinel error, reason DropReason) error {
	return fmt.Errorf("%w: %s", sentinel, reason)
}
