package forwarder

import (
	"errors"
	"net/netip"
)

// refusalOrigin says which step refused the packet. It decides whether the per-client DROP
// ledger owns the outcome, and it is known by the caller that took the step rather than
// inferred later from whatever flow happens to own the tuple.
type refusalOrigin int

const (
	// refusalAtDecisionInstall: the decision record could not be installed, so no flow exists.
	refusalAtDecisionInstall refusalOrigin = iota
	// refusalBeforeDispatch: there is no direct-egress manager, so nothing was dispatched and
	// no flow exists.
	refusalBeforeDispatch
	// refusalAtDispatch: the dispatch itself refused the packet.
	refusalAtDispatch
)

// recordDirectRefusal publishes a no-flow refusal into the bounded per-client ledger, but only
// when no flow record retains the outcome.
//
// Ownership is decided by the step that failed, not by a later lookup:
//
//   - a decision install or pre-dispatch refusal leaves no flow behind, so the ledger is the
//     only place the client's refusal can appear;
//   - a dispatch refusal for a full table or an exhausted port pool also leaves no flow (the
//     manager removes the entry it created), so it belongs here too;
//   - a dispatch refusal because the WAN write failed happens AFTER the flow entry exists and
//     has already recorded that failure on the flow itself. Publishing it here as well would
//     report one refusal twice, so this helper declines it.
//
// Classification uses the error the packet path already returned: no policy is re-evaluated and
// the forwarding decision is unchanged. An error this build has no reason for is left to the
// existing counters rather than labeled with a guess.
func (f *Forwarder) recordDirectRefusal(peerKey string, route *sessionRoute, packet []byte, pktLen int64, err error, origin refusalOrigin) {
	reason := ""
	switch {
	case errors.Is(err, ErrFlowTableFull):
		reason = DropReasonFlowTableFull
	case errors.Is(err, ErrNATPortExhaustion):
		reason = DropReasonNATPortExhaustion
	case errors.Is(err, ErrDirectEgressUnavailable):
		if origin == refusalAtDispatch {
			// The flow entry exists and its evidence already holds this failure. One refusal,
			// one owner.
			return
		}
		reason = DropReasonEgressUnavailable
	default:
		return
	}

	// The packet reached this point through ParseAndValidateClientIPv4, but re-deriving the
	// tuple from the packet is cheap and keeps the hook independent of every caller's variable
	// layout. A packet that no longer parses is recorded without a tuple rather than with one
	// this code cannot confirm.
	key, keyErr := flowKeyForPacket(peerKey, packet)
	if keyErr != nil {
		f.recordClientDrop(peerKey, route, reason, 0, netip.Addr{}, 0, false, pktLen)
		return
	}
	f.recordClientDrop(peerKey, route, reason, key.Protocol, netip.AddrFrom4(key.DstIP), key.DstPort, true, pktLen)
}
