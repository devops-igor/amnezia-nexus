package forwarder

import (
	"net/netip"
	"time"
)

// recordClientDrop publishes one pre-flow refusal, but only if the incarnation that
// refused the packet is still the live route.
//
// The producer decides to refuse while holding no lock, so it can be paused between that
// decision and this call. Retirement removes the session's records, and without a final
// ownership check the resumed producer would write them back: content for a session that
// no longer exists, published as current evidence.
//
// The check is therefore done HERE, in one critical section with the record itself, under
// the same forwarder lock that retirement takes to remove the route. Two orderings are
// possible and both are correct:
//
//   - this section runs first: the record is stored, and the retirement that follows
//     removes it with the session;
//   - retirement runs first: the route is gone, this call stores nothing.
//
// The ledger's own mutex is a leaf: it takes no forwarder lock, performs no I/O and is
// never held across the forwarder lock in the other direction.
func (f *Forwarder) recordClientDrop(peerKey string, route *sessionRoute, reason string, protocol uint8, dst netip.Addr, dstPort uint16, hasTuple bool, pktLen int64) {
	if f == nil || route == nil {
		return
	}
	now := time.Now()
	f.mu.RLock()
	current, ok := f.routesByPeer[peerKey]
	if !ok || current != route || route.stopped {
		f.mu.RUnlock()
		// The incarnation that refused this packet is gone. Its refusal is no longer
		// evidence about any live client, so nothing is published.
		return
	}
	sessionID, generation := route.sessionID, route.generation
	f.clientDrops.Record(sessionID, generation, reason, protocol, dst, dstPort, hasTuple, pktLen, now)
	f.mu.RUnlock()
}
