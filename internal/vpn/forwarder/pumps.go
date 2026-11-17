package forwarder

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// RouteClientToBackend routes a packet from a client peer toward their assigned backend tunnel.
func (f *Forwarder) RouteClientToBackend(peerKey string, packet []byte) error {
	return f.routeClientToBackend(peerKey, packet, nil)
}

// RouteClientToBackendWithReturnPath fences submissions to one engine owner.
func (f *Forwarder) RouteClientToBackendWithReturnPath(peerKey string, packet []byte, path *ReturnPath) error {
	if path == nil || path.Closed() {
		return ErrReturnPathClosed
	}
	return f.routeClientToBackend(peerKey, packet, path)
}

func (f *Forwarder) routeClientToBackend(peerKey string, packet []byte, path *ReturnPath) error {
	var srcIP string
	if len(packet) >= 20 && (packet[0]>>4) == 4 {
		srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15]).String()
	}

	f.mu.RLock()
	route, ok := f.routesByPeer[peerKey]
	if !ok || (path != nil && route.returnPath != path) {
		f.mu.RUnlock()
		return ErrSessionNotRegistered
	}

	if srcIP != "" && srcIP != "0.0.0.0" && route.assignedIP != srcIP {
		f.spoofedRebinds.Add(1)
		f.mu.RUnlock()
		return ErrSpoofedSourceIP
	}

	tbUp := route.tbUp
	f.mu.RUnlock()

	pktLen := int64(len(packet))
	if tbUp != nil && !tbUp.Allow(pktLen) {
		f.clientDropsRateLimited.Add(1)
		f.clientDropsTotal.Add(1)
		return ErrRateLimitExceeded
	}

	if !f.pbrEnabled.Load() {
		// Configurations issued while policy routing was active name the
		// gateway address as their only resolver. A gateway-address-only
		// responder keeps serving them after disablement, while external
		// port 53 keeps its previous routing.
		if handled, err := f.handleLegacyGatewayDNS(route, peerKey, packet); handled {
			return err
		}
		return f.routeClientLegacy(route, packet, pktLen)
	}

	return f.routeClientPBR(route, peerKey, packet, pktLen)
}

// handleLegacyGatewayDNS submits a gateway-addressed port-53 packet to the
// installed DNS handler while policy routing is inactive. Only the designated
// gateway address is matched, so external port-53 traffic keeps its previous
// routing; anything else falls through to the legacy path unchanged. The check
// is deliberately cheap because this is the default path for every client
// packet when policy routing is off; the handler and the gateway perform the
// full validation of an admitted packet.
func (f *Forwarder) handleLegacyGatewayDNS(route *sessionRoute, peerKey string, packet []byte) (bool, error) {
	f.mu.RLock()
	handler := f.dnsHandler
	gwDNS := f.gatewayDNSIP
	f.mu.RUnlock()
	if handler == nil || !gwDNS.IsValid() {
		return false, nil
	}
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return false, nil
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return false, nil
	}
	if proto := packet[9]; proto != 6 && proto != 17 {
		return false, nil
	}
	if binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) != 53 {
		return false, nil
	}
	if netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}) != gwDNS {
		return false, nil
	}
	return handler.HandleDNSPacket(route.sessionID, peerKey, route.assignedIP, route.returnPath, packet)
}

func (f *Forwarder) routeClientLegacy(route *sessionRoute, packet []byte, pktLen int64) error {
	f.mu.RLock()
	beQueue, ok := f.backendQueues[route.backendTunnelID]
	if !ok {
		f.clientDropsNoBackend.Add(1)
		f.clientDropsTotal.Add(1)
		f.mu.RUnlock()
		return ErrBackendNotFound
	}
	sID := route.sessionID
	cID := route.connectionID
	backendTraffic := f.backendTraffic[route.backendTunnelID]
	f.mu.RUnlock()

	return f.sendToBackendQueue(beQueue, route, backendTraffic, sID, cID, packet, pktLen)
}

func (f *Forwarder) routeClientPBR(route *sessionRoute, peerKey string, packet []byte, pktLen int64) error {
	f.mu.RLock()
	backend := proxyBackend{tunnelID: route.backendTunnelID, queue: f.backendQueues[route.backendTunnelID]}
	sID := route.sessionID
	cID := route.connectionID
	backendTraffic := f.backendTraffic[route.backendTunnelID]
	directEgress := f.directEgress
	routeCache := f.routeCache
	policyMatcher := f.policyMatcher
	gwDNS := f.gatewayDNSIP
	dnsHandler := f.dnsHandler
	f.mu.RUnlock()

	parsed, err := ParseAndValidateClientIPv4(packet, route.assignedIP)
	if err != nil {
		f.directDrops.Add(1)
		// The packet is refused before a flow exists. Its destination and ports are not
		// trusted, so the record carries the length only and states that it has no tuple.
		f.recordClientDrop(peerKey, route, DropReasonInvalidPacket, 0, netip.Addr{}, 0, false, pktLen)
		return err
	}
	dstIP := parsed.DstIP

	// Flow Stickiness: Active 5-tuple flow decisions remain stable across TTL or list refresh.
	if handled, err := f.handleStickyFlow(directEgress, route, peerKey, packet, pktLen, backend, backendTraffic, sID, cID); handled {
		return err
	}

	// Step 1 — DROP: Prohibited destinations (loopback, link-local, RFC1918, CGNAT, multicast, metadata).
	// Explicit exception: traffic to designated gateway DNS on port 53 strictly.
	if err := ValidateDirectDestination(dstIP, parsed.DstPort, gwDNS); err != nil {
		f.directDrops.Add(1)
		// The destination is prohibited, so no flow is created. The packet IS a well-formed
		// client packet, so its protocol and destination are recorded as observed facts.
		f.recordClientDrop(peerKey, route, DropReasonProhibitedDestination,
			parsed.Protocol, dstIP, parsed.DstPort, true, pktLen)
		return err
	}

	// Step 1b — PROXY FALLBACK: Non-TCP/UDP protocols (such as ICMP ping) cannot be NAT'd via direct egress.
	// Route them safely through the proxy backend, preserving connectivity.
	if parsed.Protocol != 6 && parsed.Protocol != 17 {
		return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
	}

	// Ingress DNS interception: while policy routing is active every plain
	// DNS packet on UDP or TCP port 53 is submitted to the policy resolver,
	// whatever its destination, so the client's own answers become routing
	// evidence. The gateway rewrites the reply to appear from the queried
	// address, so an unmodified client accepts it. Prohibited destinations
	// keep the drop decided above; this never becomes an egress path.
	if dnsHandler != nil && parsed.DstPort == 53 {
		handled, err := dnsHandler.HandleDNSPacket(sID, peerKey, route.assignedIP, route.returnPath, packet)
		if handled {
			return err
		}
	}

	// The decision's policy snapshot is read ONCE, and the same immutable snapshot
	// supplies both the rule match and the generation recorded on the flow. A
	// publish between two separate reads would let the record claim a generation
	// that did not make the decision.
	policySnapshot := currentPolicySnapshot(policyMatcher)
	policyGeneration := policyGenerationOf(policySnapshot)
	backendTunnel := backend.tunnelID

	// Step 2 — PROXY: Policy snapshot CIDR or route cache Proxy match (including shared-IP conflict).
	if matched, reason := f.matchesProxyPolicy(dstIP, sID, policySnapshot, routeCache); matched {
		if directEgress != nil {
			_ = directEgress.RecordFlowDecision(peerKey, sID, route.generation, packet, EgressChoiceProxy, FlowDecision{
				Reason:           reason,
				PolicyGeneration: policyGeneration,
				DecidedAt:        time.Now(),
				BackendTunnelID:  backendTunnel,
			})
		}
		return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
	}

	// Step 3 — DIRECT: Client-scoped DNS evidence observed public destination without proxy match.
	if routeCache != nil && routeCache.Lookup(sID, dstIP) == policy.Direct {
		return f.routeDirectDecision(directEgress, route, peerKey, packet, pktLen, backend, backendTraffic, sID, cID, FlowDecision{
			Reason:           EgressReasonEvidenceDirect,
			PolicyGeneration: policyGeneration,
			DecidedAt:        time.Now(),
		})
	}

	// Step 4 — PROXY (Safe Default): Missing, expired, or evicted DNS evidence (policy.Unknown).
	if directEgress != nil {
		_ = directEgress.RecordFlowDecision(peerKey, sID, route.generation, packet, EgressChoiceProxy, FlowDecision{
			Reason:           EgressReasonNoTrustedEvidence,
			PolicyGeneration: policyGeneration,
			DecidedAt:        time.Now(),
			BackendTunnelID:  backendTunnel,
		})
	}
	return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
}

// currentPolicySnapshot reads the published snapshot once. Everything a decision
// records about "the policy" comes from the snapshot this returns, never from a
// second read that a concurrent publish could move.
func currentPolicySnapshot(matcher *policy.Matcher) *policy.Snapshot {
	if matcher == nil {
		return nil
	}
	return matcher.Current()
}

// policyGenerationOf reports the generation of the snapshot the decision was
// taken against, or "" when no snapshot is published.
func policyGenerationOf(snapshot *policy.Snapshot) string {
	if snapshot == nil {
		return ""
	}
	return snapshot.Generation()
}

func (f *Forwarder) handleStickyFlow(directEgress *DirectEgressManager, route *sessionRoute, peerKey string, packet []byte, pktLen int64, backend proxyBackend, backendTraffic *trafficCounters, sID, cID string) (bool, error) {
	if directEgress == nil {
		return false, nil
	}
	choice, found := directEgress.LookupFlow(peerKey, packet)
	if !found {
		return false, nil
	}
	if choice == EgressChoiceDirect {
		if route.retired.Load() || (route.generation != 0 && f.PeerRegistration(peerKey) != route.generation) {
			return true, f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
		}
		return true, f.sendToDirectEgress(directEgress, route, peerKey, packet, pktLen, sID, cID)
	}
	return true, f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
}

func (f *Forwarder) routeDirectDecision(directEgress *DirectEgressManager, route *sessionRoute, peerKey string, packet []byte, pktLen int64, backend proxyBackend, backendTraffic *trafficCounters, sID, cID string, decision FlowDecision) error {
	if route.retired.Load() || (route.generation != 0 && f.PeerRegistration(peerKey) != route.generation) {
		// The route this evidence belonged to is gone. The packet still has to go
		// somewhere, so it takes the proxy path, but no DIRECT flow record is
		// installed for it: there is no live incarnation to attribute it to.
		return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
	}
	if directEgress != nil {
		if err := directEgress.RecordFlowDecision(peerKey, sID, route.generation, packet, EgressChoiceDirect, decision); err != nil {
			f.directDrops.Add(1)
			return err
		}
		return f.sendToDirectEgress(directEgress, route, peerKey, packet, pktLen, sID, cID)
	}
	f.directDrops.Add(1)
	return ErrDirectEgressUnavailable
}

// matchesProxyPolicy reports whether the policy puts this destination on the
// proxy, and WHICH branch matched. The caller records the branch as the flow's
// decision reason (issue #861), so the reason is the branch that actually ran
// rather than a second evaluation of the same rules.
//
// It takes the published snapshot rather than the matcher on purpose: the caller
// takes one snapshot at the decision and uses it for both this match and the
// generation it records, so the two can never disagree.
func (f *Forwarder) matchesProxyPolicy(dstIP netip.Addr, sID string, snapshot *policy.Snapshot, routeCache RouteCache) (bool, EgressReason) {
	if snapshot != nil && snapshot.MatchIPv4(dstIP) {
		return true, EgressReasonProxyCIDRRule
	}
	if routeCache != nil && routeCache.Lookup(sID, dstIP) == policy.Proxy {
		return true, EgressReasonProxyCachedEvidence
	}
	return false, ""
}

func (f *Forwarder) sendToDirectEgress(directEgress *DirectEgressManager, route *sessionRoute, peerKey string, packet []byte, pktLen int64, sID, cID string) error {
	// Re-check route not retired and generation matches before installing new flow state or transmitting to WAN
	if route == nil || route.retired.Load() {
		f.directDrops.Add(1)
		return ErrSessionNotRegistered
	}
	activeGen, activeSID, active := f.ActivePeerGeneration(peerKey)
	if !active || (route.generation != 0 && activeGen != route.generation) || (sID != "" && activeSID != sID) {
		f.directDrops.Add(1)
		return ErrSessionNotRegistered
	}

	// Call RouteDirect FIRST
	err := directEgress.RouteDirect(peerKey, route.assignedIP, sID, route.generation, packet, route.returnPath)
	if err != nil {
		f.directDrops.Add(1)
		return err
	}

	// Only increment metrics and accounting after successful transmission
	f.directBytes.Add(pktLen)
	f.totalRxBytes.Add(pktLen)
	f.totalRxPackets.Add(1)
	route.traffic.AddRx(pktLen)
	if f.accountant != nil {
		f.accountant.RecordRx(sID, cID, pktLen)
	}
	return nil
}

// proxyBackend is the egress target resolved for one proxy-required packet
// while the routing decision is made under Forwarder.mu. Carrying the tunnel ID
// alongside the queue lets the enqueue re-check that exact tunnel's
// availability instead of whatever the route points at by then.
type proxyBackend struct {
	tunnelID int64
	queue    chan BackendPacket
}

// sendToProxyBackend enqueues one proxy-required packet toward the route's
// assigned backend.
//
// The availability check and the enqueue share a single Forwarder.mu read-lock
// hold, so DetachBackendDevice — which marks the backend detached and drains
// its queue under the write lock — cannot interleave between them and leave a
// packet parked in a queue that nothing drains. A packet the proxy path cannot
// hand to a live backend is dropped and counted (issue #677 "drop and count");
// it is never re-decided as DIRECT.
func (f *Forwarder) sendToProxyBackend(backend proxyBackend, route *sessionRoute, backendTraffic *trafficCounters, sID, cID string, packet []byte, pktLen int64) error {
	// ONE evidence lookup for this packet, taken before the enqueue: the same
	// pointer is credited with the admission outcome here and travels with the
	// queued work so the device write credits the same incarnation.
	stats := f.proxyDispatchEvidence(route, packet)

	if backend.queue == nil {
		stats.recordForward(0, errProxyBackendUnavailable, FlowFailureBackendUnavailable)
		return f.dropProxyPacket()
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	f.mu.RLock()
	if _, detached := f.detachedBackends[backend.tunnelID]; detached {
		f.mu.RUnlock()
		stats.recordForward(0, errProxyBackendDetached, FlowFailureBackendDetached)
		return f.dropProxyPacket()
	}
	select {
	case backend.queue <- newBackendPacket(pktCopy, stats, sID, route.generation):
		f.mu.RUnlock()
		f.recordProxyAdmission(route, backendTraffic, sID, cID, pktLen)
		stats.recordForward(0, nil, "")
		return nil
	default:
		f.mu.RUnlock()
		f.clientDropsQueueFull.Add(1)
		f.clientDropsTotal.Add(1)
		stats.recordForward(0, errProxyQueueFull, FlowFailureQueueFull)
		return ErrQueueFull
	}
}

var (
	errProxyBackendUnavailable = errors.New("proxy backend unavailable")
	errProxyBackendDetached    = errors.New("proxy backend detached")
	errProxyQueueFull          = errors.New("proxy backend queue full")
)

// dropProxyPacket counts a proxy-required packet the proxy path refused and
// returns the fail-closed error the caller propagates.
func (f *Forwarder) dropProxyPacket() error {
	f.proxyDrops.Add(1)
	f.clientDropsNoBackend.Add(1)
	f.clientDropsTotal.Add(1)
	return ErrBackendNotFound
}

// recordProxyAdmission books a proxy packet that actually entered the backend queue.
// Admission is recorded at enqueue time (see the dataplane ownership contract,
// client-to-backend traversal), so a later writer failure is reported as a drop
// without retroactively un-booking these counters.
func (f *Forwarder) recordProxyAdmission(route *sessionRoute, backendTraffic *trafficCounters, sID, cID string, pktLen int64) {
	f.totalRxBytes.Add(pktLen)
	f.totalRxPackets.Add(1)
	f.proxiedBytes.Add(pktLen)
	route.traffic.record(pktLen, true)
	if backendTraffic != nil {
		backendTraffic.record(pktLen, true)
	}
	if f.accountant != nil {
		f.accountant.RecordRx(sID, cID, pktLen)
	}
}

// proxyDispatchEvidence returns the evidence block of the flow that admitted this
// packet, or nil when no flow is attributable. It applies the same incarnation
// guard the dispatch outcome used: a packet arriving on a route whose session or
// generation no longer owns the tuple is not credited to whoever owns it now.
func (f *Forwarder) proxyDispatchEvidence(route *sessionRoute, packet []byte) *flowStats {
	if f == nil || f.directEgress == nil || route == nil {
		return nil
	}
	f.mu.RLock()
	dem := f.directEgress
	peerKey := route.peerKey
	sessionID := route.sessionID
	generation := route.generation
	f.mu.RUnlock()
	if dem == nil || peerKey == "" {
		return nil
	}
	return dem.dispatchEvidence(peerKey, sessionID, generation, packet)
}

func (f *Forwarder) sendToBackendQueue(beQueue chan BackendPacket, route *sessionRoute, backendTraffic *trafficCounters, sID, cID string, packet []byte, pktLen int64) error {
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	// The legacy (non-policy) path records no flow, so the queued work carries no
	// owner. A nil owner is the honest value: nothing is credited later.
	select {
	case beQueue <- newBackendPacket(pktCopy, nil, sID, 0):
		f.totalRxBytes.Add(pktLen)
		f.totalRxPackets.Add(1)
		route.traffic.record(pktLen, true)
		if backendTraffic != nil {
			backendTraffic.record(pktLen, true)
		}
		if f.accountant != nil {
			f.accountant.RecordRx(sID, cID, pktLen)
		}
		return nil
	default:
		f.clientDropsQueueFull.Add(1)
		f.clientDropsTotal.Add(1)
		return ErrQueueFull
	}
}

// RouteBackendToClient routes a packet arriving from a backend tunnel to the destination client peer.
func (f *Forwarder) RouteBackendToClient(backendTunnelID int64, packet []byte, destIP string) error {
	f.mu.RLock()
	route, ok := f.routesByIP[destIP]
	if !ok {
		f.mu.RUnlock()
		// Production rejection site (issue #389 rework 2): the packet is
		// dropped here, BEFORE any route or ReturnPath writer exists, so
		// the engine's write callback can never classify it — count the
		// UnmappedDrops equivalent here (single owner of this reason).
		f.dropsNoRoute.Add(1)
		f.dropsTotal.Add(1)
		f.classifyReturnReject(ReturnRejectedUnrouted)
		return ErrSessionNotRegistered
	}
	if route.returnPath != nil {
		if backendTunnelID != route.backendTunnelID {
			f.mu.RUnlock()
			// Production rejection site (issue #389 rework 2): the reply
			// arrived on a backend the route does not own. The engine's
			// write callback never runs for it — count the
			// OwnershipMismatchDrops equivalent here (single owner).
			f.dropsNoRoute.Add(1)
			f.dropsTotal.Add(1)
			f.classifyReturnReject(ReturnRejectedMismatch)
			return ErrReturnRouteMismatch
		}
		if !validReturnDestination(packet, destIP) {
			f.mu.RUnlock()
			// Production rejection site (issue #389 rework 2): a malformed
			// reply is rejected by the shape filter before the engine's
			// write callback runs, so the callback cannot classify it —
			// count the MalformedDrops equivalent here (single owner; no
			// double-count with the write callback).
			f.dropsNoRoute.Add(1)
			f.dropsTotal.Add(1)
			f.classifyReturnReject(ReturnRejectedMalformed)
			return ErrReturnRouteMismatch
		}
	}
	sID := route.sessionID
	cID := route.connectionID
	tbDown := route.tbDown
	backendTraffic := f.backendTraffic[backendTunnelID]
	f.mu.RUnlock()

	// Reverse the reply into the admitting flow BEFORE any refusal, so a reply that is
	// dropped for size or rate still says where it stopped instead of vanishing. A reply
	// that reverses to no flow, or to another incarnation, stays unattributed: it is
	// counted as such and never credited to a flow it cannot be shown to belong to.
	clientIP, err := netip.ParseAddr(destIP)
	if err != nil {
		clientIP = netip.Addr{}
	}
	returnEvidence, returnMatched := f.proxyReturnEvidence(route, packet, clientIP)
	// Arrival is recorded BEFORE the size, rate and queue decisions, so the counters
	// conserve: every matched reply is either admitted or dropped, and the observed label
	// describes what was actually measured rather than what survived the filters.
	if returnMatched {
		returnEvidence.recordReturnMatch()
	} else {
		f.proxyReturnsUnmatched.Add(1)
	}

	pktLen := int64(len(packet))
	if len(packet) > MaxClientQueuePacketBytes {
		f.recordOversizedReturn(&f.oversizedBackendReturns, len(packet))
		returnEvidence.recordReturnRefused(FlowReturnOversized)
		return ErrPacketTooLarge
	}
	if tbDown != nil && !tbDown.Allow(pktLen) {
		returnEvidence.recordReturnRefused(FlowReturnRateLimited)
		return ErrRateLimitExceeded
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)
	// The matched flow travels with the packet. The writer runs asynchronously and the
	// flow can be retired or replaced in between, so the identity is fixed here and never
	// re-resolved later.
	queued := ClientPacket{packet: pktCopy, evidence: returnEvidence}

	f.mu.RLock()
	currentRoute, current := f.routesByIP[destIP]
	if !current || currentRoute != route {
		f.mu.RUnlock()
		f.dropsNoRoute.Add(1)
		f.dropsTotal.Add(1)
		f.classifyReturnReject(ReturnRejectedUnrouted)
		returnEvidence.recordReturnRefused(FlowReturnRouteReplaced)
		return ErrSessionNotRegistered
	}
	clientQueue := route.clientQueue
	f.aggregateQueueMu.Lock()
	f.reconcileBeforeQueueMutationLocked(route)
	select {
	case clientQueue <- queued:
		f.reconcileQueueOccupancyLocked(route)
		routeOccupancy := uint64(len(clientQueue))
		for current := route.queueHighWater.Load(); routeOccupancy > current; {
			if route.queueHighWater.CompareAndSwap(current, routeOccupancy) {
				break
			}
			current = route.queueHighWater.Load()
		}
		aggregateOccupancy := uint64(f.aggregateQueueOccupancy) // #nosec G115 -- maintained sum of non-negative queue lengths.
		for current := f.aggregateQueueHighWater.Load(); aggregateOccupancy > current; {
			if f.aggregateQueueHighWater.CompareAndSwap(current, aggregateOccupancy) {
				break
			}
			current = f.aggregateQueueHighWater.Load()
		}
		select {
		case route.queueReady <- struct{}{}:
		default:
		}
		f.aggregateQueueMu.Unlock()
		f.mu.RUnlock()
		returnEvidence.recordReturnAdmitted()
		f.totalTxBytes.Add(pktLen)
		f.totalTxPackets.Add(1)
		route.traffic.record(pktLen, false)
		backendTraffic.record(pktLen, false)
		if f.accountant != nil {
			f.accountant.RecordTx(sID, cID, pktLen)
		}
		return nil
	default:
		f.aggregateQueueMu.Unlock()
		f.mu.RUnlock()
		// Bounded backpressure: the packet is dropped, but every drop is
		// counted so the stats API can surface a stalled downstream path
		// (issue #39) instead of only a log line.
		route.queueFullDrops.Add(1)
		f.dropsQueueFull.Add(1)
		f.dropsTotal.Add(1)
		returnEvidence.recordReturnRefused(FlowReturnQueueFull)
		return ErrQueueFull
	}
}

// AttachBackendDevice attaches a backend tunnel packet device.
func (f *Forwarder) AttachBackendDevice(backendTunnelID int64, dev PacketDevice) {
	f.mu.Lock()
	oldStopCh, oldDoneCh := f.takeBackendPumpLocked(backendTunnelID)
	f.mu.Unlock()

	stopBackendPump(oldStopCh, oldDoneCh)

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.backendQueues[backendTunnelID]; !ok {
		f.backendQueues[backendTunnelID] = make(chan BackendPacket, f.backendBufSize)
		f.ensureBackendTrafficLocked(backendTunnelID)
	}
	if dev != nil {
		f.backendDevices[backendTunnelID] = dev
		f.ensureBackendTrafficLocked(backendTunnelID)
		f.backendTraffic[backendTunnelID] = &trafficCounters{}
		// A live device makes this backend an available proxy egress again.
		delete(f.detachedBackends, backendTunnelID)
	} else {
		delete(f.backendDevices, backendTunnelID)
		delete(f.backendTraffic, backendTunnelID)
		// No device means no egress path: proxy-required packets must refuse
		// and count instead of parking in a queue nothing drains.
		f.detachedBackends[backendTunnelID] = struct{}{}
	}

	if f.pumpsRunning && dev != nil {
		pumpStopCh := make(chan struct{})
		pumpDoneCh := make(chan struct{})
		f.backendPumpStops[backendTunnelID] = pumpStopCh
		f.backendPumpDones[backendTunnelID] = pumpDoneCh
		f.pumpsWg.Add(1)
		go f.pumpBackendQueue(f.pumpsStopCh, pumpStopCh, pumpDoneCh, backendTunnelID, f.backendQueues[backendTunnelID], dev)
	}
}

// DetachBackendDevice detaches a backend tunnel packet device and terminates its pump goroutine.
func (f *Forwarder) DetachBackendDevice(backendTunnelID int64) {
	f.mu.Lock()
	// Record the retirement of this backend's egress path first. The marker is
	// what makes a later proxy-required packet refuse and count instead of
	// being admitted into a queue nothing drains, and unlike the queue itself it
	// survives the re-creation that session registration and
	// UpdateSessionBackend perform for this tunnel ID.
	f.detachedBackends[backendTunnelID] = struct{}{}
	f.drainAbandonedProxyQueueLocked(backendTunnelID)
	delete(f.backendDevices, backendTunnelID)
	delete(f.backendTraffic, backendTunnelID)
	oldStopCh, oldDoneCh := f.takeBackendPumpLocked(backendTunnelID)
	f.mu.Unlock()

	stopBackendPump(oldStopCh, oldDoneCh)
}

// takeBackendPumpLocked removes one backend's pump bookkeeping and returns the
// channels the caller must signal and wait on after releasing f.mu.
func (f *Forwarder) takeBackendPumpLocked(backendTunnelID int64) (stopCh, doneCh chan struct{}) {
	stopCh, exists := f.backendPumpStops[backendTunnelID]
	if !exists {
		return nil, nil
	}
	doneCh = f.backendPumpDones[backendTunnelID]
	delete(f.backendPumpStops, backendTunnelID)
	delete(f.backendPumpDones, backendTunnelID)
	return stopCh, doneCh
}

// stopBackendPump signals a taken pump to exit and waits a bounded time for it
// to finish. Callers must not hold f.mu: a pump can be blocked in a device
// write, and waiting under the routing-table lock would stall every routing
// decision for the whole timeout.
func stopBackendPump(stopCh, doneCh chan struct{}) {
	if stopCh == nil {
		return
	}
	close(stopCh)
	if doneCh != nil {
		select {
		case <-doneCh:
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// drainAbandonedProxyQueueLocked discards the packets still queued toward a
// backend that has just been detached and counts them as proxy drops.
//
// Those packets were admitted for a backend that is now gone: they can never be
// delivered, and leaving them in the preserved queue would hand a stale packet
// to whatever device a later re-attach installs. Only the policy-routed proxy
// path owns them — the legacy path keeps its documented buffer-across-detach
// behavior and is deliberately left untouched. The caller must hold f.mu.
func (f *Forwarder) drainAbandonedProxyQueueLocked(backendTunnelID int64) {
	queue, ok := f.backendQueues[backendTunnelID]
	if !ok || !f.pbrEnabled.Load() {
		return
	}
	// Bound the drain by the occupancy observed under the lock; the legacy
	// sender does not hold f.mu across its enqueue, so a packet can still
	// arrive and must not turn this into an unbounded loop.
	for pending := len(queue); pending > 0; pending-- {
		select {
		case <-queue:
			f.proxyDrops.Add(1)
			f.clientDropsTotal.Add(1)
		default:
			return
		}
	}
}

// StartPumps launches background packet pumps connecting forwarder queues to attached packet devices.
func (f *Forwarder) StartPumps(ctx context.Context) {
	f.mu.Lock()
	if f.pumpsRunning {
		f.mu.Unlock()
		return
	}
	f.pumpsRunning = true
	f.pumpsStopCh = make(chan struct{})
	stopCh := f.pumpsStopCh

	// Start pump for each backend device
	for beID, dev := range f.backendDevices {
		if q, ok := f.backendQueues[beID]; ok && dev != nil {
			pumpStopCh := make(chan struct{})
			pumpDoneCh := make(chan struct{})
			f.backendPumpStops[beID] = pumpStopCh
			f.backendPumpDones[beID] = pumpDoneCh
			f.pumpsWg.Add(1)
			go f.pumpBackendQueue(stopCh, pumpStopCh, pumpDoneCh, beID, q, dev)
		}
	}

	// Start pump for each client route; self-heal pumpless routes. A route
	// registered while pumps were not running (or whose pump was stopped by
	// a StopPumps/StartPumps cycle) is adopted here so no route can stay
	// permanently pumpless — the issue #39 failure mode where a queue sat
	// full for hours with the route registered.
	for _, route := range f.routesByPeer {
		if route.pumpStarted {
			continue
		}
		route.pumpStarted = true
		f.pumpsWg.Add(1)
		go f.pumpClientQueue(stopCh, route)
	}
	f.mu.Unlock()
}

// StopPumps terminates background packet pump routines.
func (f *Forwarder) StopPumps() {
	f.stopPumpsSignalOnly()
	f.pumpsWg.Wait()
}

func (f *Forwarder) pumpBackendQueue(globalStopCh <-chan struct{}, perPumpStopCh <-chan struct{}, doneCh chan struct{}, backendTunnelID int64, queue chan BackendPacket, dev PacketDevice) {
	defer f.pumpsWg.Done()
	if doneCh != nil {
		defer close(doneCh)
	}
	for {
		select {
		case <-globalStopCh:
			return
		case <-perPumpStopCh:
			return
		case work, ok := <-queue:
			if !ok {
				return
			}
			if pumpStopped(globalStopCh, perPumpStopCh) {
				return
			}
			f.writeBackendPacket(dev, work)
		}
	}
}

// pumpStopped reports whether either stop signal has been closed while the
// queue was ready.
func pumpStopped(globalStopCh, perPumpStopCh <-chan struct{}) bool {
	select {
	case <-globalStopCh:
		return true
	case <-perPumpStopCh:
		return true
	default:
		return false
	}
}

// writeBackendPacket hands one dequeued packet to the attached backend device
// and counts the loss when the write fails on a policy-routed forwarder.
//
// With policy routing enabled every client-to-backend packet is a proxy
// decision, so a failed write is a proxy drop. Its bytes stay in admitted
// throughput because admission is booked at enqueue time (see
// recordProxyAdmission); the legacy path keeps its existing silent-error
// behavior.
func (f *Forwarder) writeBackendPacket(dev PacketDevice, work BackendPacket) {
	if dev == nil {
		// No device means the packet was never written: no completion and no failure
		// is recorded, because inventing either would misstate what happened.
		return
	}
	packet := work.Bytes()
	n, err := dev.Write(packet)
	if err != nil && f.pbrEnabled.Load() {
		f.proxyDrops.Add(1)
		f.clientDropsTotal.Add(1)
	}
	// The admitting flow learns what the DEVICE did, through the ownership captured
	// at enqueue. Admitted bytes stay booked: completion is additional observation,
	// not a correction of throughput.
	work.owner.recordBackendWrite(n, len(packet), err)
}

func (f *Forwarder) pumpClientQueue(stopCh <-chan struct{}, route *sessionRoute) {
	defer f.pumpsWg.Done()
	// routeStopCh: route.stopCh is created at registration and only closed
	// (never nil-ed or replaced) by UnregisterSession under f.mu, so reading
	// it here is race-free and a pump started after teardown still observes
	// the closed channel and exits immediately.
	routeStopCh := route.stopCh

	for {
		var pkt ClientPacket
		select {
		case <-stopCh:
			return
		case <-routeStopCh:
			return
		default:
		}
		// Never receive outside the accounting lock: even a receive followed
		// immediately by a lock can make an enqueue miss its actual peak.
		f.aggregateQueueMu.Lock()
		f.reconcileBeforeQueueMutationLocked(route)
		select {
		case pkt = <-route.clientQueue:
			f.reconcileQueueOccupancyLocked(route)
		default:
			f.aggregateQueueMu.Unlock()
			select {
			case <-stopCh:
				return
			case <-routeStopCh:
				return
			case <-route.queueReady:
			}
			continue
		}
		f.aggregateQueueMu.Unlock()
		f.mu.RLock()
		currentRoute, current := f.routesByPeer[route.peerKey]
		if !current || currentRoute != route || route.stopped {
			f.mu.RUnlock()
			// The route was replaced or stopped before the handoff. The reply never
			// reaches a client, and the flow that admitted it records where it stopped
			// instead of looking queued forever.
			pkt.evidenceOrNil().recordReturnRefused(FlowReturnRouteReplaced)
			continue
		}
		var dev packetWriter
		if route.returnPath != nil {
			dev = routeWriter{path: route.returnPath, peerKey: route.peerKey, assignedIP: route.assignedIP}
		}
		f.mu.RUnlock()
		if dev == nil {
			// No engine writer for this route: the reply cannot be handed off, and the
			// matched flow records the refusal instead of looking delivered.
			pkt.evidenceOrNil().recordReturnRefused(FlowReturnPathClosed)
			continue
		}
		f.writeClientPacket(route, dev, pkt.packet, pkt.evidenceOrNil())
	}
}
