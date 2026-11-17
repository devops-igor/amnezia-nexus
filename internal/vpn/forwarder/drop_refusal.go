package forwarder

import (
	"errors"
	"net/netip"
)

// recordDirectRefusal publishes the no-flow refusals of the direct egress path into the
// bounded per-client ledger.
//
// Three of these leave nothing behind for a later read to find:
//
//   - the flow table is full, so no entry was created at all;
//   - a NAT port could not be allocated, so the entry that was created is removed again;
//   - the direct egress is unavailable before any entry exists.
//
// Without this hook the client sees its packet disappear while the global drop counter
// only says that something was dropped. The refusal is recorded with the tuple the packet
// actually carried, through the same publication fence the other producers use, so a
// producer that resumes after the session ended still stores nothing.
//
// Classification is by the error the packet path already returned: no policy is
// re-evaluated here and the forwarding decision is unchanged. An error this build has no
// reason for is left to the existing counters rather than labeled with a guess.
func (f *Forwarder) recordDirectRefusal(peerKey string, route *sessionRoute, packet []byte, pktLen int64, err error) {
	reason := ""
	switch {
	case errors.Is(err, ErrFlowTableFull):
		reason = DropReasonFlowTableFull
	case errors.Is(err, ErrNATPortExhaustion):
		reason = DropReasonNATPortExhaustion
	case errors.Is(err, ErrDirectEgressUnavailable):
		reason = DropReasonEgressUnavailable
	default:
		return
	}

	// The packet reached this point through ParseAndValidateClientIPv4, but re-deriving the
	// tuple from the packet is cheap and keeps the hook independent of every caller's
	// variable layout. A packet that no longer parses is recorded without a tuple rather
	// than with one this code cannot confirm.
	key, keyErr := flowKeyForPacket(peerKey, packet)
	if keyErr != nil {
		f.recordClientDrop(peerKey, route, reason, 0, netip.Addr{}, 0, false, pktLen)
		return
	}
	f.recordClientDrop(peerKey, route, reason, key.Protocol, netip.AddrFrom4(key.DstIP), key.DstPort, true, pktLen)
}
