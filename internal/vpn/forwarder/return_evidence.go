package forwarder

import (
	"encoding/binary"
	"net/netip"
)

// Per-flow PROXY return evidence (issue #861).
//
// A backend return arrives at RouteBackendToClient with the client's assigned IP and the
// reply packet only. The reply's own header, reversed, names the flow: the admitted flow
// sent clientIP:clientPort to remoteIP:remotePort, so the reply's source is the remote
// side and its destination port is the client's port. Reversing it yields the exact
// FlowKey of the admitting flow, which is a single map lookup in the existing flow table.
//
// Nothing here scans the table, allocates history or keeps a second index: the flow table
// is already the authority, and a retired flow leaves nothing behind to match.

// Return failure tokens. Each names a place the reply actually stopped, so an operator
// can tell a full client queue from a closed engine writer.
const (
	FlowReturnQueueFull   = "client_queue_full"
	FlowReturnRateLimited = "client_rate_limited"
	FlowReturnOversized   = "packet_too_large"
	FlowReturnPathClosed  = "return_path_closed"
	FlowReturnWriteFailed = "client_write_failed"
	FlowReturnShortWrite  = "client_short_write"
	FlowReturnNotFound    = "no_recorded_flow"
)

// returnFlowKey reverses a reply packet into the FlowKey of the flow that sent it.
//
// The reply must be a well-formed IPv4 TCP or UDP packet whose destination is the client
// IP the router resolved. Anything else is not attributable and reports false rather than
// producing a key that could match an unrelated flow.
func returnFlowKey(peerKey string, packet []byte, clientIP netip.Addr) (FlowKey, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return FlowKey{}, false
	}
	header := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || header > len(packet) || total < header || total > len(packet) {
		return FlowKey{}, false
	}
	protocol := packet[9]
	if protocol != 6 && protocol != 17 {
		return FlowKey{}, false
	}
	if len(packet) < header+4 {
		return FlowKey{}, false
	}
	remoteIP := [4]byte{packet[12], packet[13], packet[14], packet[15]}
	destination := [4]byte{packet[16], packet[17], packet[18], packet[19]}
	if !clientIP.Is4() || clientIP.As4() != destination {
		return FlowKey{}, false
	}
	remotePort := binary.BigEndian.Uint16(packet[header : header+2])
	clientPort := binary.BigEndian.Uint16(packet[header+2 : header+4])
	// The flow was keyed client -> remote, so the reply supplies the remote side as the
	// destination and the client's own port as the source.
	return FlowKey{
		PeerKey:  peerKey,
		Protocol: protocol,
		SrcIP:    destination,
		DstIP:    remoteIP,
		SrcPort:  clientPort,
		DstPort:  remotePort,
	}, true
}

// proxyReturnEvidence matches a backend reply to the flow that admitted the request.
//
// The match requires the same peer (the route's), the same session and the same route
// generation, so a reply can never be credited to a successor that reused the tuple. The
// flow table read is the existing locked lookup; the caller is outside the forwarder
// lock, which is the documented Forwarder -> DirectEgress order.
func (f *Forwarder) proxyReturnEvidence(route *sessionRoute, packet []byte, clientIP netip.Addr) (*flowStats, bool) {
	if f.directEgress == nil || route == nil {
		return nil, false
	}
	key, ok := returnFlowKey(route.peerKey, packet, clientIP)
	if !ok {
		return nil, false
	}
	entry := f.directEgress.flowEntryForReturn(key)
	if entry == nil || entry.evidence == nil {
		return nil, false
	}
	if entry.sessionID != route.sessionID || entry.generation != route.generation {
		return nil, false
	}
	return entry.evidence, true
}

// flowEntryForReturn is the read-only flow lookup used by the return path. It does not
// refresh lastSeen or retire anything: observing a reply must not change what the packet
// path decides next.
func (m *DirectEgressManager) flowEntryForReturn(key FlowKey) *flowEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.flows[key]
}
