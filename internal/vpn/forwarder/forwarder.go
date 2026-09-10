package forwarder

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrSessionNotRegistered = errors.New("session route not registered")
	ErrBackendNotFound      = errors.New("backend queue not found")
	ErrQueueFull            = errors.New("packet queue is full")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
)

// PacketDevice abstracts physical Linux TUN / network interfaces and in-memory test devices.
type PacketDevice interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

// TokenBucket implements a token bucket rate limiter for per-peer bandwidth throttling.
type TokenBucket struct {
	rate       float64 // bytes per second
	capacity   float64 // burst capacity in bytes
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket with rate in bytes per second.
func NewTokenBucket(rateBps int64, capacity ...int64) *TokenBucket {
	if rateBps <= 0 {
		return nil
	}
	capVal := float64(rateBps)
	if len(capacity) > 0 && capacity[0] > 0 {
		capVal = float64(capacity[0])
	}
	if capVal < float64(rateBps) {
		capVal = float64(rateBps)
	}
	return &TokenBucket{
		rate:       float64(rateBps),
		capacity:   capVal,
		tokens:     capVal,
		lastUpdate: time.Now(),
	}
}

// Allow returns true if n bytes can be consumed from the bucket, and deducts the tokens.
func (tb *TokenBucket) Allow(n int64) bool {
	if tb == nil {
		return true
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

type sessionRoute struct {
	sessionID       string
	connectionID    string
	peerKey         string
	assignedIP      string
	backendTunnelID int64
	clientQueue     chan []byte
	// stopCh terminates this route's pumpClientQueue goroutine on session
	// teardown; stopped guards exactly-once close. The client queue itself is
	// deliberately NOT closed because RouteBackendToClient sends to it after
	// releasing the read lock — closing it would race into a
	// send-on-closed-channel panic.
	stopCh       chan struct{}
	stopped      bool
	limitDownBps int64
	limitUpBps   int64
	tbDown       *TokenBucket
	tbUp         *TokenBucket
	// pumpStarted records that a pumpClientQueue goroutine owns this route's
	// queue. StartPumps uses it (under f.mu) to give pumpless routes a pump;
	// the flag prevents a double start for the same route generation.
	pumpStarted bool
}

// Forwarder manages packet routing and bidirectional relay between peer sessions and backend tunnels.
type Forwarder struct {
	mu               sync.RWMutex
	accountant       *TrafficAccountant
	routesByPeer     map[string]*sessionRoute // peerKey -> route
	routesByIP       map[string]*sessionRoute // assignedIP -> route
	backendQueues    map[int64]chan []byte    // backendTunnelID -> queue
	clientDevices    map[string]PacketDevice  // peerKey -> device
	backendDevices   map[int64]PacketDevice   // backendTunnelID -> device
	backendPumpStops map[int64]chan struct{}  // backendTunnelID -> pump stop channel
	backendPumpDones map[int64]chan struct{}  // backendTunnelID -> pump done channel
	defaultClientDev PacketDevice             // default client packet device
	bufSize          int
	totalRxBytes     atomic.Int64
	totalTxBytes     atomic.Int64
	dropsQueueFull   atomic.Uint64 // return packets dropped: per-route queue full
	dropsTotal       atomic.Uint64 // return-path drops counted so far (queue full)
	running          bool
	stopCh           chan struct{}
	pumpsRunning     bool
	pumpsStopCh      chan struct{}
	pumpsWg          sync.WaitGroup
	// Generation accounting for teardown races (issue #39): each
	// registration for a peer key earns one teardown; an UnregisterSession
	// that arrives while a NEWER registration holds the route (late reaper /
	// API teardown of a superseded rekey generation) is consumed as stale
	// instead of killing the live route. Guarded by mu.
	peerRegs   map[string]uint64 // peerKey -> registrations seen
	peerUnregs map[string]uint64 // peerKey -> stale teardown requests consumed
}

// NewForwarder creates a new Forwarder.
func NewForwarder(accountant *TrafficAccountant, bufSize ...int) *Forwarder {
	qSize := 256
	if len(bufSize) > 0 && bufSize[0] > 0 {
		qSize = bufSize[0]
	}
	return &Forwarder{
		accountant:       accountant,
		routesByPeer:     make(map[string]*sessionRoute),
		routesByIP:       make(map[string]*sessionRoute),
		backendQueues:    make(map[int64]chan []byte),
		clientDevices:    make(map[string]PacketDevice),
		backendDevices:   make(map[int64]PacketDevice),
		backendPumpStops: make(map[int64]chan struct{}),
		backendPumpDones: make(map[int64]chan struct{}),
		peerRegs:         make(map[string]uint64),
		peerUnregs:       make(map[string]uint64),
		bufSize:          qSize,
		stopCh:           make(chan struct{}),
	}
}

// RegisterSession registers a peer session route with unlimited bandwidth.
func (f *Forwarder) RegisterSession(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64) {
	f.RegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, 0, 0)
}

// RegisterSessionWithLimit registers a peer session route and configures initial rate limits (in bytes/sec).
func (f *Forwarder) RegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, limitDownBps, limitUpBps int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Ensure backend queue exists
	if _, ok := f.backendQueues[backendTunnelID]; !ok {
		f.backendQueues[backendTunnelID] = make(chan []byte, f.bufSize)
	}

	var tbDown, tbUp *TokenBucket
	if limitDownBps > 0 {
		tbDown = NewTokenBucket(limitDownBps)
	}
	if limitUpBps > 0 {
		tbUp = NewTokenBucket(limitUpBps)
	}

	route := &sessionRoute{
		sessionID:       sessionID,
		connectionID:    connectionID,
		peerKey:         peerKey,
		assignedIP:      assignedIP,
		backendTunnelID: backendTunnelID,
		clientQueue:     make(chan []byte, f.bufSize),
		stopCh:          make(chan struct{}),
		limitDownBps:    limitDownBps,
		limitUpBps:      limitUpBps,
		tbDown:          tbDown,
		tbUp:            tbUp,
	}

	// A re-registration for the same peer replaces an existing route: stop
	// the old route's pump before the maps are overwritten so it cannot leak.
	if old, ok := f.routesByPeer[peerKey]; ok && old != nil {
		f.stopRoutePumpLocked(old)
	}
	// Each registration earns exactly one teardown (generation accounting,
	// issue #39): if a teardown for a SUPERSEDED registration of this peer
	// arrives before this one, it was consumed as stale against the older
	// balance — see UnregisterSession.
	f.peerRegs[peerKey]++

	f.routesByPeer[peerKey] = route
	if assignedIP != "" {
		f.routesByIP[assignedIP] = route
	}

	if f.pumpsRunning {
		route.pumpStarted = true
		f.pumpsWg.Add(1)
		go f.pumpClientQueue(f.pumpsStopCh, route)
	}
}

// stopRoutePumpLocked closes the route's per-session stop channel exactly
// once. The channel is never nil-ed after close: a pump goroutine that starts
// after teardown must still be able to observe the closed channel and exit.
// Caller must hold f.mu (write).
func (f *Forwarder) stopRoutePumpLocked(route *sessionRoute) {
	if route != nil && route.stopCh != nil && !route.stopped {
		close(route.stopCh)
		route.stopped = true
		route.pumpStarted = false
	}
}

// SetPeerRateLimit sets per-peer bandwidth throttling limits in bytes per second.
func (f *Forwarder) SetPeerRateLimit(peerKey string, limitDownBps, limitUpBps int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	route, ok := f.routesByPeer[peerKey]
	if !ok {
		return ErrSessionNotRegistered
	}

	route.limitDownBps = limitDownBps
	route.limitUpBps = limitUpBps
	if limitDownBps > 0 {
		route.tbDown = NewTokenBucket(limitDownBps)
	} else {
		route.tbDown = nil
	}
	if limitUpBps > 0 {
		route.tbUp = NewTokenBucket(limitUpBps)
	} else {
		route.tbUp = nil
	}

	return nil
}

// GetPeerRateLimit returns the configured rate limits for a peer in bytes per second.
func (f *Forwarder) GetPeerRateLimit(peerKey string) (limitDownBps, limitUpBps int64, err error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	route, ok := f.routesByPeer[peerKey]
	if !ok {
		return 0, 0, ErrSessionNotRegistered
	}

	return route.limitDownBps, route.limitUpBps, nil
}

// UnregisterSession removes a peer session route, stops its pump goroutine,
// and drains its queue so in-flight senders cannot block.
//
// A teardown request is matched against the per-peer registration balance
// (issue #39): each RegisterSession earns exactly one teardown. When the
// route currently in the maps is a NEWER generation than the teardown
// (rekey/reconnect re-registration happened first, then the OLD session's
// reaper/API teardown arrived late), the request is consumed as stale and
// the live route survives. Route state is only torn down when a currently
// held teardown credit is spent on it.
func (f *Forwarder) UnregisterSession(peerKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.peerUnregs == nil {
		f.peerUnregs = make(map[string]uint64)
	}
	if f.peerRegs == nil {
		f.peerRegs = make(map[string]uint64)
	}
	// Teardown requests are served strictly in registration order: the
	// k-th request for a peer belongs to the k-th registration. Three
	// cases (issue #39):
	//   unregs+1 > regs: no such generation (unknown peer, or the balance
	//     was already exhausted) — pure no-op, never counts against a
	//     future registration.
	//   unregs+1 < regs: the route was re-registered in the meantime
	//     (client rekey/reconnect registers the NEW session before the
	//     OLD session's reaper/API teardown arrives) — the request
	//     targets a superseded generation: consume as stale so it can
	//     never kill the live route.
	//   unregs+1 == regs: request for the current generation — tear down.
	switch n := f.peerUnregs[peerKey] + 1; {
	case n > f.peerRegs[peerKey]:
		return
	case n < f.peerRegs[peerKey]:
		f.peerUnregs[peerKey]++
		return
	default:
		f.peerUnregs[peerKey]++
	}

	if route, ok := f.routesByPeer[peerKey]; ok {
		// Generation-bounded delete: only remove the routesByIP entry if it
		// still points at THIS route. A late unregister of an OLD session
		// (reaper/API race after a client rekey or reconnect re-registered
		// the same peer/IP) must not delete the NEW route — before this
		// guard it did, and the session then showed CONNECTED while every
		// return packet got ErrSessionNotRegistered forever (issue #39).
		if cur, ok := f.routesByIP[route.assignedIP]; ok && cur == route {
			delete(f.routesByIP, route.assignedIP)
		}
		delete(f.routesByPeer, peerKey)
		delete(f.clientDevices, peerKey)
		// Terminate the per-session pump exactly once. The queue is NOT
		// closed: RouteBackendToClient sends to it after releasing the lock,
		// and closing would race into a send-on-closed panic. Instead the
		// pump stops via stopCh and the buffered queue is drained here —
		// late senders just fill the abandoned buffer and hit ErrQueueFull.
		f.stopRoutePumpLocked(route)
	drain:
		for {
			select {
			case <-route.clientQueue:
			default:
				break drain
			}
		}
	}
}

// UpdateSessionBackend updates the assigned backend tunnel for a session (e.g. during failover).
func (f *Forwarder) UpdateSessionBackend(peerKey string, newBackendTunnelID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	route, ok := f.routesByPeer[peerKey]
	if !ok {
		return ErrSessionNotRegistered
	}

	if _, ok := f.backendQueues[newBackendTunnelID]; !ok {
		f.backendQueues[newBackendTunnelID] = make(chan []byte, f.bufSize)
	}

	route.backendTunnelID = newBackendTunnelID
	return nil
}

// RouteClientToBackend routes a packet from a client peer toward their assigned backend tunnel.
func (f *Forwarder) RouteClientToBackend(peerKey string, packet []byte) error {
	var srcIP string
	if len(packet) >= 20 && (packet[0]>>4) == 4 {
		srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15]).String()
	}

	f.mu.RLock()
	route, ok := f.routesByPeer[peerKey]
	if !ok {
		f.mu.RUnlock()
		return ErrSessionNotRegistered
	}

	var (
		beQueue chan []byte
		sID     string
		cID     string
		tbUp    *TokenBucket
	)

	if srcIP != "" && srcIP != "0.0.0.0" && route.assignedIP != srcIP {
		f.mu.RUnlock()
		f.mu.Lock()
		route, ok = f.routesByPeer[peerKey]
		if !ok {
			f.mu.Unlock()
			return ErrSessionNotRegistered
		}
		if route.assignedIP != srcIP {
			if route.assignedIP != "" {
				delete(f.routesByIP, route.assignedIP)
			}
			f.routesByIP[srcIP] = route
			route.assignedIP = srcIP
		}
		beQueue, ok = f.backendQueues[route.backendTunnelID]
		if !ok {
			f.mu.Unlock()
			return ErrBackendNotFound
		}
		sID = route.sessionID
		cID = route.connectionID
		tbUp = route.tbUp
		f.mu.Unlock()
	} else {
		beQueue, ok = f.backendQueues[route.backendTunnelID]
		if !ok {
			f.mu.RUnlock()
			return ErrBackendNotFound
		}
		sID = route.sessionID
		cID = route.connectionID
		tbUp = route.tbUp
		f.mu.RUnlock()
	}

	pktLen := int64(len(packet))
	if tbUp != nil && !tbUp.Allow(pktLen) {
		return ErrRateLimitExceeded
	}

	f.totalRxBytes.Add(pktLen)
	if f.accountant != nil {
		f.accountant.RecordRx(sID, cID, pktLen)
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	select {
	case beQueue <- pktCopy:
		return nil
	default:
		return ErrQueueFull
	}
}

// RouteBackendToClient routes a packet arriving from a backend tunnel to the destination client peer.
func (f *Forwarder) RouteBackendToClient(backendTunnelID int64, packet []byte, destIP string) error {
	f.mu.RLock()
	route, ok := f.routesByIP[destIP]
	if !ok {
		f.mu.RUnlock()
		return ErrSessionNotRegistered
	}
	clientQueue := route.clientQueue
	sID := route.sessionID
	cID := route.connectionID
	tbDown := route.tbDown
	f.mu.RUnlock()

	pktLen := int64(len(packet))
	if tbDown != nil && !tbDown.Allow(pktLen) {
		return ErrRateLimitExceeded
	}

	f.totalTxBytes.Add(pktLen)
	if f.accountant != nil {
		f.accountant.RecordTx(sID, cID, pktLen)
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	select {
	case clientQueue <- pktCopy:
		return nil
	default:
		// Bounded backpressure: the packet is dropped, but every drop is
		// counted so the stats API can surface a stalled downstream path
		// (issue #39) instead of only a log line.
		f.dropsQueueFull.Add(1)
		f.dropsTotal.Add(1)
		return ErrQueueFull
	}
}

// GetClientPacketChannel returns the outbound packet channel for a client peer.
func (f *Forwarder) GetClientPacketChannel(peerKey string) (<-chan []byte, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	route, ok := f.routesByPeer[peerKey]
	if !ok {
		return nil, false
	}
	return route.clientQueue, true
}

// GetBackendPacketChannel returns the packet channel for a backend tunnel.
func (f *Forwarder) GetBackendPacketChannel(backendTunnelID int64) (<-chan []byte, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ch, ok := f.backendQueues[backendTunnelID]
	return ch, ok
}

// AttachClientDevice attaches a default client-facing packet device (e.g. TUN interface).
func (f *Forwarder) AttachClientDevice(dev PacketDevice) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defaultClientDev = dev
}

// AttachPeerDevice attaches a peer-specific packet device.
func (f *Forwarder) AttachPeerDevice(peerKey string, dev PacketDevice) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if dev != nil {
		f.clientDevices[peerKey] = dev
	} else {
		delete(f.clientDevices, peerKey)
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
		f.backendQueues[backendTunnelID] = make(chan []byte, f.bufSize)
	}
	if dev != nil {
		f.backendDevices[backendTunnelID] = dev
	} else {
		delete(f.backendDevices, backendTunnelID)
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

// DropStats returns the number of return packets dropped because a route's
// client queue was full, and the total number of return-path drops. Both are
// exposed via the stats API so a stalled downstream path is visible without
// tailing logs (issue #39).
func (f *Forwarder) DropStats() (queueFull, total uint64) {
	return f.dropsQueueFull.Load(), f.dropsTotal.Load()
}

// StopPumps terminates background packet pump routines.
func (f *Forwarder) StopPumps() {
	f.mu.Lock()
	if !f.pumpsRunning {
		f.mu.Unlock()
		return
	}
	f.pumpsRunning = false
	close(f.pumpsStopCh)
	for beID, stopCh := range f.backendPumpStops {
		close(stopCh)
		delete(f.backendPumpStops, beID)
		delete(f.backendPumpDones, beID)
	}
	// Every client-route pump exits via the closed global stop channel;
	// clear their ownership flags so a subsequent StartPumps adopts all
	// routes again (the operator-visible Stop/Start recovery path for a
	// stalled downstream data plane, issue #39).
	for _, route := range f.routesByPeer {
		route.pumpStarted = false
	}
	f.mu.Unlock()

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
		select {
		case <-stopCh:
			return
		case <-routeStopCh:
			return
		case pkt, ok := <-route.clientQueue:
			if !ok {
				return
			}
			f.mu.RLock()
			dev, ok := f.clientDevices[route.peerKey]
			if !ok || dev == nil {
				dev = f.defaultClientDev
			}
			f.mu.RUnlock()

			if dev != nil {
				_, _ = dev.Write(pkt)
			}
		}
	}
}

// GetStats returns current aggregated traffic and active route counts.
func (f *Forwarder) GetStats() (rx int64, tx int64, activeRoutes int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rx = f.totalRxBytes.Load()
	tx = f.totalTxBytes.Load()
	activeRoutes = len(f.routesByPeer)
	return
}

// Start marks the forwarder active.
func (f *Forwarder) Start(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = true
	if f.accountant != nil {
		f.accountant.Start(ctx)
	}
}

// Stop terminates the forwarder, pumps, and flushes accountant.
func (f *Forwarder) Stop() error {
	f.StopPumps()

	f.mu.Lock()
	f.running = false
	f.mu.Unlock()

	if f.accountant != nil {
		return f.accountant.Stop()
	}
	return nil
}

// IsRunning returns true if the forwarder is active.
func (f *Forwarder) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}
