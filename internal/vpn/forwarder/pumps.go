package forwarder

import (
	"context"
	"net"
	"time"
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

	beQueue, ok := f.backendQueues[route.backendTunnelID]
	if !ok {
		f.clientDropsNoBackend.Add(1)
		f.clientDropsTotal.Add(1)
		f.mu.RUnlock()
		return ErrBackendNotFound
	}
	sID := route.sessionID
	cID := route.connectionID
	tbUp := route.tbUp
	backendTraffic := f.backendTraffic[route.backendTunnelID]
	f.mu.RUnlock()

	pktLen := int64(len(packet))
	if tbUp != nil && !tbUp.Allow(pktLen) {
		f.clientDropsRateLimited.Add(1)
		f.clientDropsTotal.Add(1)
		return ErrRateLimitExceeded
	}

	// The packet copy happens before the send attempt, so the drop path costs
	// the same allocation it always did; only the ACCOUNTING placement is
	// under review here (issue #424 round 3, finding 2).
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	// Throughput accounting records ADMITTED traffic: bytes the backend
	// actually received. It therefore runs only once the packet is on the
	// backend queue. It used to run before the send, so a packet refused by
	// a full queue was counted as backend RX AND as a queue-full drop at the
	// same time — diagnostics could report +1500 bytes of backend throughput
	// alongside queue-full +1 for one packet the backend never accepted,
	// which is the opposite of what per-backend traffic is for (#432).
	//
	// Rejected traffic is still visible: it is counted by
	// clientDropsQueueFull/clientDropsTotal below and reported as the
	// client_backend_queue_full reason, so no packet is lost from the
	// accounting — it simply stops being reported as carried throughput.
	select {
	case beQueue <- pktCopy:
		f.totalRxBytes.Add(pktLen)
		f.totalRxPackets.Add(1)
		// route.traffic also advances the route's last-traffic age (#433),
		// so a refused packet must not reset "last seen" for a route that
		// carried nothing.
		route.traffic.record(pktLen, true)
		backendTraffic.record(pktLen, true)
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
	var oldStopCh chan struct{}
	var oldDoneCh chan struct{}
	if stopCh, exists := f.backendPumpStops[backendTunnelID]; exists {
		oldStopCh = stopCh
		oldDoneCh = f.backendPumpDones[backendTunnelID]
		delete(f.backendPumpStops, backendTunnelID)
		delete(f.backendPumpDones, backendTunnelID)
	}
	f.mu.Unlock()

	if oldStopCh != nil {
		close(oldStopCh)
		if oldDoneCh != nil {
			select {
			case <-oldDoneCh:
			case <-time.After(500 * time.Millisecond):
			}
		}
	}

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
	} else {
		delete(f.backendDevices, backendTunnelID)
		delete(f.backendTraffic, backendTunnelID)
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
	delete(f.backendDevices, backendTunnelID)
	delete(f.backendTraffic, backendTunnelID)
	var oldStopCh chan struct{}
	var oldDoneCh chan struct{}
	if stopCh, exists := f.backendPumpStops[backendTunnelID]; exists {
		oldStopCh = stopCh
		oldDoneCh = f.backendPumpDones[backendTunnelID]
		delete(f.backendPumpStops, backendTunnelID)
		delete(f.backendPumpDones, backendTunnelID)
	}
	f.mu.Unlock()

	if oldStopCh != nil {
		close(oldStopCh)
		if oldDoneCh != nil {
			select {
			case <-oldDoneCh:
			case <-time.After(500 * time.Millisecond):
			}
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
			// Verify this pump was not stopped while queue was ready
			select {
			case <-globalStopCh:
				return
			case <-perPumpStopCh:
				return
			default:
			}
			if dev != nil {
				_, _ = dev.Write(pkt)
			}
		}
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

// HasBackendDevice returns whether an active packet device is attached for the backend tunnel.
func (f *Forwarder) HasBackendDevice(backendTunnelID int64) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.backendDevices[backendTunnelID] != nil
}
