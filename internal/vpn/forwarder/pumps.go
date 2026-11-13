package forwarder

import (
	"context"
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
		return f.routeClientLegacy(route, packet, pktLen)
	}

	return f.routeClientPBR(route, peerKey, packet, pktLen)
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
		return err
	}

	// Step 1b — PROXY FALLBACK: Non-TCP/UDP protocols (such as ICMP ping) cannot be NAT'd via direct egress.
	// Route them safely through the proxy backend, preserving connectivity.
	if parsed.Protocol != 6 && parsed.Protocol != 17 {
		return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
	}

	// Ingress DNS interception: if addressed to gateway DNS on port 53, submit to DNS handler.
	if dnsHandler != nil && gwDNS.IsValid() && dstIP == gwDNS && parsed.DstPort == 53 {
		handled, err := dnsHandler.HandleDNSPacket(sID, peerKey, route.assignedIP, route.returnPath, packet)
		if handled {
			return err
		}
	}

	// Step 2 — PROXY: Policy snapshot CIDR or route cache Proxy match (including shared-IP conflict).
	if f.matchesProxyPolicy(dstIP, sID, policyMatcher, routeCache) {
		if directEgress != nil {
			_ = directEgress.RecordFlow(peerKey, sID, route.generation, packet, EgressChoiceProxy)
		}
		return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
	}

	// Step 3 — DIRECT: Client-scoped DNS evidence observed public destination without proxy match.
	if routeCache != nil && routeCache.Lookup(sID, dstIP) == policy.Direct {
		return f.routeDirectDecision(directEgress, route, peerKey, packet, pktLen, backend, backendTraffic, sID, cID)
	}

	// Step 4 — PROXY (Safe Default): Missing, expired, or evicted DNS evidence (policy.Unknown).
	if directEgress != nil {
		_ = directEgress.RecordFlow(peerKey, sID, route.generation, packet, EgressChoiceProxy)
	}
	return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
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

func (f *Forwarder) routeDirectDecision(directEgress *DirectEgressManager, route *sessionRoute, peerKey string, packet []byte, pktLen int64, backend proxyBackend, backendTraffic *trafficCounters, sID, cID string) error {
	if route.retired.Load() || (route.generation != 0 && f.PeerRegistration(peerKey) != route.generation) {
		return f.sendToProxyBackend(backend, route, backendTraffic, sID, cID, packet, pktLen)
	}
	if directEgress != nil {
		if err := directEgress.RecordFlow(peerKey, sID, route.generation, packet, EgressChoiceDirect); err != nil {
			f.directDrops.Add(1)
			return err
		}
		return f.sendToDirectEgress(directEgress, route, peerKey, packet, pktLen, sID, cID)
	}
	f.directDrops.Add(1)
	return ErrDirectEgressUnavailable
}

func (f *Forwarder) matchesProxyPolicy(dstIP netip.Addr, sID string, policyMatcher *policy.Matcher, routeCache RouteCache) bool {
	if policyMatcher != nil {
		if snap := policyMatcher.Current(); snap != nil && snap.MatchIPv4(dstIP) {
			return true
		}
	}
	if routeCache != nil && routeCache.Lookup(sID, dstIP) == policy.Proxy {
		return true
	}
	return false
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
	queue    chan []byte
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
	if backend.queue == nil {
		return f.dropProxyPacket()
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	f.mu.RLock()
	if _, detached := f.detachedBackends[backend.tunnelID]; detached {
		f.mu.RUnlock()
		return f.dropProxyPacket()
	}
	select {
	case backend.queue <- pktCopy:
		f.mu.RUnlock()
		f.recordProxyAdmission(route, backendTraffic, sID, cID, pktLen)
		return nil
	default:
		f.mu.RUnlock()
		f.clientDropsQueueFull.Add(1)
		f.clientDropsTotal.Add(1)
		return ErrQueueFull
	}
}

// dropProxyPacket counts a proxy-required packet the proxy path refused and
// returns the fail-closed error the caller propagates.
func (f *Forwarder) dropProxyPacket() error {
	f.proxyDrops.Add(1)
	f.clientDropsNoBackend.Add(1)
	f.clientDropsTotal.Add(1)
	return ErrBackendNotFound
}

// recordProxyAdmission books a proxy packet that actually entered the backend
// queue. Admission is recorded at enqueue time (see the dataplane ownership
// contract, client-to-backend traversal), so a later writer failure is reported
// as a drop without retroactively un-booking these counters.
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

func (f *Forwarder) sendToBackendQueue(beQueue chan []byte, route *sessionRoute, backendTraffic *trafficCounters, sID, cID string, packet []byte, pktLen int64) error {
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	select {
	case beQueue <- pktCopy:
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

	pktLen := int64(len(packet))
	if len(packet) > MaxClientQueuePacketBytes {
		f.dropsPacketTooLarge.Add(1)
		f.dropsTotal.Add(1)
		return ErrPacketTooLarge
	}
	if tbDown != nil && !tbDown.Allow(pktLen) {
		return ErrRateLimitExceeded
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	f.mu.RLock()
	currentRoute, current := f.routesByIP[destIP]
	if !current || currentRoute != route {
		f.mu.RUnlock()
		f.dropsNoRoute.Add(1)
		f.dropsTotal.Add(1)
		f.classifyReturnReject(ReturnRejectedUnrouted)
		return ErrSessionNotRegistered
	}
	clientQueue := route.clientQueue
	f.aggregateQueueMu.Lock()
	f.reconcileBeforeQueueMutationLocked(route)
	select {
	case clientQueue <- pktCopy:
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
		f.backendQueues[backendTunnelID] = make(chan []byte, f.backendBufSize)
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

func (f *Forwarder) pumpBackendQueue(globalStopCh <-chan struct{}, perPumpStopCh <-chan struct{}, doneCh chan struct{}, backendTunnelID int64, queue chan []byte, dev PacketDevice) {
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
		case pkt, ok := <-queue:
			if !ok {
				return
			}
			if pumpStopped(globalStopCh, perPumpStopCh) {
				return
			}
			f.writeBackendPacket(dev, pkt)
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
func (f *Forwarder) writeBackendPacket(dev PacketDevice, pkt []byte) {
	if dev == nil {
		return
	}
	if _, err := dev.Write(pkt); err != nil && f.pbrEnabled.Load() {
		f.proxyDrops.Add(1)
		f.clientDropsTotal.Add(1)
	}
}

func (f *Forwarder) pumpClientQueue(stopCh <-chan struct{}, route *sessionRoute) {
	defer f.pumpsWg.Done()
	// routeStopCh: route.stopCh is created at registration and only closed
	// (never nil-ed or replaced) by UnregisterSession under f.mu, so reading
	// it here is race-free and a pump started after teardown still observes
	// the closed channel and exits immediately.
	routeStopCh := route.stopCh

	for {
		var pkt []byte
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
			continue
		}
		var dev packetWriter
		if route.returnPath != nil {
			dev = routeWriter{path: route.returnPath, peerKey: route.peerKey, assignedIP: route.assignedIP}
		}
		f.mu.RUnlock()
		if dev != nil {
			f.writeClientPacket(route, dev, pkt)
		}
	}
}
