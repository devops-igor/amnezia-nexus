package forwarder

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrSessionNotRegistered = errors.New("session route not registered")
	ErrBackendNotFound      = errors.New("backend queue not found")
	ErrQueueFull            = errors.New("packet queue is full")
	// ErrPacketTooLarge rejects packets that cannot fit within the payload-size
	// assumption used by the aggregate client queue memory budget.
	ErrPacketTooLarge    = errors.New("packet exceeds maximum queued payload size")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	// ErrSpoofedSourceIP is returned by RouteClientToBackend when the inner
	// packet's claimed source IP fails the rebind ownership guard (issue
	// #89): outside the portal subnet, currently assigned to another route,
	// or otherwise not a legitimate self-heal target. The packet is dropped
	// and the spoofedRebinds counter is incremented; callers (the endpoint
	// router) treat it as a drop, not a protocol error.
	ErrSpoofedSourceIP = errors.New("spoofed inner source IP: rebind rejected")
)

// PacketDevice abstracts physical Linux TUN / network interfaces and in-memory test devices.
type PacketDevice interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

// TokenBucket implements a token bucket rate limiter for per-peer bandwidth throttling.
//
// Rate-vs-burst semantics (issue #94): `rate` is the SUSTAINED throughput in
// bytes per second — the long-run average the bucket refills at. `capacity`
// is the BURST budget: the maximum number of bytes that can be consumed
// instantaneously, bounded by the tokens accumulated in the bucket. The two
// are independent: a bucket configured at 1 MB/s with a 4 MB capacity can
// deliver a 4 MB burst immediately and then sustain 1 MB/s; a bucket at
// 1 MB/s with capacity 128 KB can only ever burst 128 KB before waiting for
// refills. `limitBps` alone is therefore NOT a hard per-second ceiling —
// short windows may exceed it by up to the burst capacity.
//
// With no explicit capacity, NewTokenBucket defaults capacity to the rate,
// i.e. the bucket starts full and permits an initial burst of up to one
// full second of configured bandwidth (a configured 1 MB/s limit permits a
// ~1 MB initial burst). Any supplied capacity is clamped to at least the
// rate (see NewTokenBucket). Tokens refill continuously at the rate while
// idle and cap at capacity.
//
// The bucket is mutex-guarded: Allow is safe for concurrent use from
// multiple goroutines (per-peer limit buckets are shared by concurrent
// packet pumps — see sessionRoute.tbDown/tbUp and RouteClientToBackend /
// RouteBackendToClient).
type TokenBucket struct {
	rate       float64 // bytes per second (sustained refill rate)
	capacity   float64 // burst capacity in bytes (max instantaneous burst)
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket with rate in bytes per second.
//
// rateBps is the sustained refill rate in bytes/second; an optional second
// argument overrides the burst capacity in bytes. Defaults and clamping:
//   - capacity defaults to rateBps, so the bucket starts full and permits an
//     initial burst of up to one second's worth of configured bandwidth
//     (1 MB/s ⇒ ~1 MB initial burst — issue #94).
//   - a capacity below rateBps is clamped UP to rateBps; the sustained rate
//     always remains achievable.
//   - tokens start at capacity (full bucket).
//
// A non-positive rate returns nil; callers treat a nil *TokenBucket as
// "unlimited" (Allow on a nil receiver always returns true).
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

type RouteQueueStats struct {
	Occupancy      int    `json:"occupancy"`
	Capacity       int    `json:"capacity"`
	HighWater      int    `json:"high_water"`
	QueueFullDrops uint64 `json:"queue_full_drops"`
}

type sessionRoute struct {
	sessionID       string
	connectionID    string
	peerKey         string
	assignedIP      string
	backendTunnelID int64
	clientQueue     chan []byte
	queueReady      chan struct{} // coalesced notification; dequeue holds aggregateQueueMu
	queueHighWater  atomic.Uint64
	queueFullDrops  atomic.Uint64
	retired         atomic.Bool
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
	backendBufSize   int
	maxActiveRoutes  int
	// portalSubnet is the VPN's own client address pool (same CIDR the IPAM
	// allocates from). It bounds the srcIP self-heal rebind in
	// RouteClientToBackend (issue #89): only IPs INSIDE this subnet can ever
	// trigger a rebind, and only while unassigned. A claimed srcIP outside
	// the subnet (or unparseable) is always treated as spoofed and dropped —
	// an inner packet source outside the portal pool can only be a spoof.
	portalSubnet        *net.IPNet
	totalRxBytes        atomic.Int64
	totalTxBytes        atomic.Int64
	dropsQueueFull      atomic.Uint64 // return packets dropped: per-route queue full
	dropsNoRoute        atomic.Uint64 // return packets dropped: unroutable / no session registered (issue #151)
	dropsPacketTooLarge atomic.Uint64 // return packets dropped because they exceed the queued payload bound
	dropsTotal          atomic.Uint64 // return-path drops counted so far
	// spoofedRebinds counts client→backend packets whose claimed inner
	// source IP failed the rebind ownership guard (issue #89): outside the
	// portal subnet or already assigned to another route. Such packets are
	// dropped (never forwarded, never rebound). Exposed via SpoofedRebinds.
	spoofedRebinds atomic.Uint64
	// writeErrLogUntil throttles return-path device Write-error log lines to
	// at most one per second (issue #43: a failed dev.Write on the client
	// queue -> client device leg, e.g. "no transport keys for peer", used to
	// vanish silently). CAS-based on a monotonic deadline, same pattern as
	// the endpoint listener's rejectLogUntil; safe under concurrent pumps.
	writeErrLogUntil         atomic.Int64
	deviceWriteErrors        atomic.Uint64
	deviceWriteDurationNS    atomic.Uint64
	deviceWriteMaxDurationNS atomic.Uint64
	aggregateQueueHighWater  atomic.Uint64
	// aggregateQueueMu serializes managed queue operations so aggregate
	// high-water is sampled at the same linearization point as enqueue/dequeue.
	aggregateQueueMu sync.Mutex
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

// DefaultClientQueueSize is the default capacity of each per-client downstream packet channel.
// Sized to absorb downstream microbursts without drops while keeping memory bounded
// (2048 packets ~ 2.8 MB @ MTU 1420, issue #151).
const DefaultClientQueueSize = 2048

// DefaultBackendQueueSize is the default capacity of each backend packet queue.
// It is intentionally independent from DefaultClientQueueSize so client queue
// tuning does not silently change backend queue memory allocation.
const DefaultBackendQueueSize = 2048

// MaxSupportedActiveRoutes is the supported upper bound used when budgeting
// queued client packet memory. It is deliberately independent of the runtime
// load-balancer configuration so old configurations remain valid.
const MaxSupportedActiveRoutes = 1000

// MaxClientQueuePacketBytes is the conservative payload size reserved for one
// queued packet (the VPN MTU is 1420 bytes).
const MaxClientQueuePacketBytes = 1500

// MaxClientQueueMemoryBytes is the explicit aggregate queued-payload budget
// for all supported active routes. Per-route queue capacity is derived from
// this budget and MaxSupportedActiveRoutes, then bounded by this package's
// public queue limit.
const MaxClientQueueMemoryBytes = 8 << 30

// MaxClientQueuePacketsForRoutes returns the largest per-route queue capacity
// that keeps the configured active-route population within the aggregate
// queued-payload memory budget. It always permits at least one queued packet.
func MaxClientQueuePacketsForRoutes(activeRoutes int) int {
	if activeRoutes <= 0 {
		activeRoutes = MaxSupportedActiveRoutes
	}
	maxBudgetPackets := MaxClientQueueMemoryBytes / MaxClientQueuePacketBytes
	if activeRoutes >= maxBudgetPackets {
		return 1
	}
	maxPackets := maxBudgetPackets / activeRoutes
	if maxPackets < 1 {
		return 1
	}
	return maxPackets
}

// MaxClientQueuePackets is the hard upper bound for a per-route queue when the
// default maximum of MaxSupportedActiveRoutes routes is configured.
const MaxClientQueuePackets = MaxClientQueueMemoryBytes / (MaxSupportedActiveRoutes * MaxClientQueuePacketBytes)

// NewForwarder creates a new Forwarder.
//
// portalSubnetCIDR is the VPN client pool CIDR (the same source IPAM is
// constructed from, e.g. VPNConfig.SubnetCIDR). It gates the srcIP rebind
// self-heal (issue #89): rebinds are only accepted for IPs inside this
// subnet that are currently unassigned. An empty or invalid CIDR disables
// ALL rebinds (fail-closed) — self-heal silently stops working but the
// hijack primitive stays closed.
func NewForwarder(accountant *TrafficAccountant, portalSubnetCIDR string, bufSize ...int) *Forwarder {
	qSize := DefaultClientQueueSize
	if len(bufSize) > 0 && bufSize[0] > 0 {
		qSize = bufSize[0]
	}
	return NewForwarderWithLimits(accountant, portalSubnetCIDR, qSize, MaxSupportedActiveRoutes)
}

// NewForwarderWithLimits creates a forwarder with an explicit client-queue size
// and maximum active-route count. The queue size is bounded from the same
// aggregate payload-memory budget as the route limit, keeping the configured
// session capacity and the data-plane memory budget aligned.
func NewForwarderWithLimits(accountant *TrafficAccountant, portalSubnetCIDR string, queueSize, maxActiveRoutes int) *Forwarder {
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = MaxSupportedActiveRoutes
	}
	maxQueue := MaxClientQueuePacketsForRoutes(maxActiveRoutes)
	if queueSize <= 0 {
		queueSize = DefaultClientQueueSize
	}
	if queueSize > maxQueue {
		queueSize = maxQueue
	}
	var portalSubnet *net.IPNet
	if portalSubnetCIDR != "" {
		if _, ipNet, err := net.ParseCIDR(portalSubnetCIDR); err == nil {
			portalSubnet = ipNet
		} else {
			log.Printf("[vpn/forwarder] invalid portal subnet CIDR %q: srcIP rebind self-heal disabled", portalSubnetCIDR)
		}
	}
	return &Forwarder{
		accountant:       accountant,
		portalSubnet:     portalSubnet,
		routesByPeer:     make(map[string]*sessionRoute),
		routesByIP:       make(map[string]*sessionRoute),
		backendQueues:    make(map[int64]chan []byte),
		clientDevices:    make(map[string]PacketDevice),
		backendDevices:   make(map[int64]PacketDevice),
		backendPumpStops: make(map[int64]chan struct{}),
		backendPumpDones: make(map[int64]chan struct{}),
		peerRegs:         make(map[string]uint64),
		peerUnregs:       make(map[string]uint64),
		bufSize:          queueSize,
		backendBufSize:   DefaultBackendQueueSize,
		maxActiveRoutes:  maxActiveRoutes,
		stopCh:           make(chan struct{}),
	}
}

// RegisterSession registers a peer session route with unlimited bandwidth.
func (f *Forwarder) RegisterSession(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64) {
	f.RegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, 0, 0)
}

// RegisterSessionWithLimit registers a peer session route and configures initial rate limits (in bytes/sec).
//
// Rate-limit wiring (issue #94): limitDownBps/limitUpBps are SUSTAINED
// rates in bytes/second; each creates a TokenBucket whose burst capacity
// defaults to the rate (see NewTokenBucket — a configured 1 MB/s limit
// permits an initial ~1 MB burst before sustained limiting settles in).
// The per-direction buckets (tbDown for backend→client, tbUp for
// client→backend) are consumed per packet in RouteBackendToClient /
// RouteClientToBackend and are shared by concurrent pumps; they are
// mutex-guarded and safe for concurrent use.
func (f *Forwarder) RegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, limitDownBps, limitUpBps int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Registration is intentionally void for API compatibility. A new peer is
	// rejected when the configured active-route budget is full; callers observe
	// the rejection through the usual absent-route behavior. Re-registration of
	// an existing peer is allowed so reconnect/rekey lifecycle semantics remain
	// unchanged and does not increase the active route count.
	maxActiveRoutes := f.maxActiveRoutes
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = MaxSupportedActiveRoutes
	}
	if _, exists := f.routesByPeer[peerKey]; !exists && len(f.routesByPeer) >= maxActiveRoutes {
		return
	}

	// Ensure backend queue exists
	if _, ok := f.backendQueues[backendTunnelID]; !ok {
		f.backendQueues[backendTunnelID] = make(chan []byte, f.backendBufSize)
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
		queueReady:      make(chan struct{}, 1),
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
		f.drainRouteQueueLocked(old)
		if old.assignedIP != "" {
			if current, exists := f.routesByIP[old.assignedIP]; exists && current == old {
				delete(f.routesByIP, old.assignedIP)
			}
		}
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
		// Retirement is intentionally non-blocking. A client PacketDevice.Write
		// may be slow or permanently blocked, and this function is called while
		// holding f.mu. Waiting for the write here would serialize the entire
		// forwarder behind one stalled route.
		route.retired.Store(true)
		close(route.stopCh)
		route.stopped = true
		route.pumpStarted = false
	}
}

// drainRouteQueueLocked removes buffered packets. Caller must hold f.mu (write).
func (f *Forwarder) drainRouteQueueLocked(route *sessionRoute) {
	if route == nil {
		return
	}
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()
	for {
		select {
		case <-route.clientQueue:
		default:
			return
		}
	}
}

// SetPeerRateLimit sets per-peer bandwidth throttling limits in bytes per second.
//
// Rate-limit wiring (issue #94): the limits are SUSTAINED rates in
// bytes/second (see TokenBucket); each replaces the peer's per-direction
// bucket with a fresh one at burst capacity = rate. Passing 0 for a
// direction removes that direction's bucket (unlimited).
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
		f.drainRouteQueueLocked(route)
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
		f.backendQueues[newBackendTunnelID] = make(chan []byte, f.backendBufSize)
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
			// Issue #89: the claimed srcIP comes from the INNER packet and
			// is attacker-controlled. Only accept the rebind when BOTH hold:
			//   1. srcIP is inside the portal client subnet (an inner source
			//      outside the pool can only be a spoof), AND
			//   2. srcIP is currently UNASSIGNED — checking under THIS write
			//      lock (routesByIP is only mutated under f.mu, so the
			//      check-and-insert here is atomic with respect to every
			//      other registration/unregister/rebind).
			// Anything else — including another peer's live assigned IP — is
			// a spoofed rebind attempt: drop the packet and count it. Before
			// this guard, a peer could claim a victim's (guessable,
			// sequentially allocated) IP and hijack the victim's downstream
			// traffic by stealing its routesByIP entry.
			spoofed := !f.inPortalSubnet(srcIP) || f.routesByIP[srcIP] != nil
			if spoofed {
				f.spoofedRebinds.Add(1)
				f.mu.Unlock()
				return ErrSpoofedSourceIP
			}
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
		f.dropsNoRoute.Add(1)
		f.dropsTotal.Add(1)
		return ErrSessionNotRegistered
	}
	sID := route.sessionID
	cID := route.connectionID
	tbDown := route.tbDown
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
		return ErrSessionNotRegistered
	}
	clientQueue := route.clientQueue
	f.aggregateQueueMu.Lock()
	select {
	case clientQueue <- pktCopy:
		routeOccupancy := uint64(len(clientQueue))
		for current := route.queueHighWater.Load(); routeOccupancy > current; {
			if route.queueHighWater.CompareAndSwap(current, routeOccupancy) {
				break
			}
			current = route.queueHighWater.Load()
		}
		aggregateOccupancy := uint64(0)
		for _, queuedRoute := range f.routesByPeer {
			if queuedRoute != nil {
				aggregateOccupancy += uint64(len(queuedRoute.clientQueue))
			}
		}
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

// GetClientPacketChannel returns the outbound packet channel for a client peer.
// Consumers must use this channel only as an observation/compatibility handle;
// direct receives bypass queue accounting. Production consumers should leave
// draining to StartPumps so occupancy and high-water metrics remain meaningful.
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
		f.backendQueues[backendTunnelID] = make(chan []byte, f.backendBufSize)
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

// ReconfigureClientQueueConfig changes the capacity used for subsequently
// registered client routes. Existing route channels cannot be resized safely;
// reject changes while any route is active so persisted configuration cannot
// diverge from the running data plane.
func (f *Forwarder) ReconfigureClientQueueConfig(size, maxActiveRoutes int) error {
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = MaxSupportedActiveRoutes
	}
	maxQueue := MaxClientQueuePacketsForRoutes(maxActiveRoutes)
	if size <= 0 {
		size = DefaultClientQueueSize
	}
	if size > maxQueue {
		size = maxQueue
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.routesByPeer) > 0 {
		return errors.New("client queue configuration cannot change while sessions are active")
	}
	f.bufSize = size
	f.maxActiveRoutes = maxActiveRoutes
	return nil
}

func (f *Forwarder) ReconfigureClientQueueSize(size int) error {
	f.mu.RLock()
	maxActiveRoutes := f.maxActiveRoutes
	f.mu.RUnlock()
	return f.ReconfigureClientQueueConfig(size, maxActiveRoutes)
}

// RouteQueueStats returns a point-in-time snapshot of one peer's downstream
// queue, including its high-water mark and queue-full drops.
func (f *Forwarder) RouteQueueStats(peerKey string) (RouteQueueStats, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()
	route, ok := f.routesByPeer[peerKey]
	if !ok || route == nil {
		return RouteQueueStats{}, false
	}
	return RouteQueueStats{
		Occupancy:      len(route.clientQueue),
		Capacity:       cap(route.clientQueue),
		HighWater:      int(route.queueHighWater.Load()), // #nosec G115 -- queue high-water is bounded by the configured channel capacity.
		QueueFullDrops: route.queueFullDrops.Load(),
	}, true
}

// AllRouteQueueStats returns point-in-time snapshots for all active peers.
func (f *Forwarder) AllRouteQueueStats() map[string]RouteQueueStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()
	stats := make(map[string]RouteQueueStats, len(f.routesByPeer))
	for peerKey, route := range f.routesByPeer {
		if route == nil {
			continue
		}
		stats[peerKey] = RouteQueueStats{
			Occupancy:      len(route.clientQueue),
			Capacity:       cap(route.clientQueue),
			HighWater:      int(route.queueHighWater.Load()), // #nosec G115 -- queue high-water is bounded by the configured channel capacity.
			QueueFullDrops: route.queueFullDrops.Load(),
		}
	}
	return stats
}

// AggregateQueueStats returns current and high-water occupancy across all
// active peer queues. The per-route snapshot remains available through
// AllRouteQueueStats for diagnosis of an individual stalled consumer.
func (f *Forwarder) AggregateQueueStats() (occupancy, capacity, highWater int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()
	occupancy = 0
	highWater = int(f.aggregateQueueHighWater.Load()) // #nosec G115 -- aggregate queue high-water is bounded by active queue capacities.
	for _, route := range f.routesByPeer {
		if route == nil {
			continue
		}
		occupancy += len(route.clientQueue)
		capacity += cap(route.clientQueue)
	}
	return
}

// DeviceWriteStats returns client-device write failures, total write duration,
// and the slowest observed write.
func (f *Forwarder) DeviceWriteStats() (errors uint64, total, max time.Duration) {
	return f.deviceWriteErrors.Load(),
		time.Duration(f.deviceWriteDurationNS.Load()), // #nosec G115 -- accumulated monotonic durations are non-negative.
		time.Duration(f.deviceWriteMaxDurationNS.Load()) // #nosec G115 -- accumulated monotonic durations are non-negative.
}

// DropStats returns the number of return packets dropped because a route's
// client queue was full, the number of return packets dropped because no
// registered session route matched the destination IP, and the total number
// of return-path drops, including oversized packets. Both are exposed via
// the stats API so a stalled
// downstream path and unroutable sessions are visible without tailing logs
// (issues #39, #151).
func (f *Forwarder) DropStats() (queueFull, noRoute, total uint64) {
	return f.dropsQueueFull.Load(), f.dropsNoRoute.Load(), f.dropsTotal.Load()
}

// DropsNoRoute returns the number of return packets dropped because no
// registered session route matched the packet's destination IP (issue #151).
func (f *Forwarder) DropsNoRoute() uint64 {
	return f.dropsNoRoute.Load()
}

// DropsQueueFull returns the number of return packets dropped because a
// route's client queue was full (issue #151).
func (f *Forwarder) DropsQueueFull() uint64 {
	return f.dropsQueueFull.Load()
}

// DropsPacketTooLarge returns the number of return packets dropped because
// they exceed the payload size that can be safely budgeted in client queues.
func (f *Forwarder) DropsPacketTooLarge() uint64 {
	return f.dropsPacketTooLarge.Load()
}

// inPortalSubnet reports whether ip belongs to the portal client pool.
// Unparseable IPs and an unknown subnet both answer false (fail-closed).
// Callers must hold f.mu (write) or accept a racy-but-constant read: the
// field is set once at construction and never mutated.
func (f *Forwarder) inPortalSubnet(ip string) bool {
	if f.portalSubnet == nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return f.portalSubnet.Contains(parsed)
}

// SpoofedRebinds returns the number of client→backend packets whose claimed
// inner source IP failed the rebind ownership guard (issue #89) and were
// dropped: source outside the portal subnet, or currently assigned to
// another route. Nonzero values are a strong signal of tenant-isolation
// abuse (or severe NAT misconfiguration) and are safe to alert on.
func (f *Forwarder) SpoofedRebinds() uint64 {
	return f.spoofedRebinds.Load()
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
		select {
		case pkt = <-route.clientQueue:
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
		dev, ok := f.clientDevices[route.peerKey]
		if !ok || dev == nil {
			dev = f.defaultClientDev
		}
		f.mu.RUnlock()
		if route.retired.Load() {
			continue
		}

		if dev != nil {
			started := time.Now()
			_, err := dev.Write(pkt)
			duration := time.Since(started)
			f.deviceWriteDurationNS.Add(uint64(duration))                                   // #nosec G115 -- time.Since returns a non-negative duration.
			for current := f.deviceWriteMaxDurationNS.Load(); uint64(duration) > current; { // #nosec G115 -- time.Since returns a non-negative duration.
				if f.deviceWriteMaxDurationNS.CompareAndSwap(current, uint64(duration)) { // #nosec G115 -- time.Since returns a non-negative duration.
					break
				}
				current = f.deviceWriteMaxDurationNS.Load()
			}
			if err != nil {
				f.deviceWriteErrors.Add(1)
				// Issue #43: a failing return-leg device write (e.g.
				// "no transport keys for peer") must surface somewhere.
				// Throttle to ~1 line/second like the queue-full drop
				// counters; the packet itself is dropped either way.
				now := time.Now().Unix()
				if f.writeErrLogUntil.Load() <= now {
					f.writeErrLogUntil.Store(now + 1)
					log.Printf("[vpn/forwarder] return-path device write error (throttled 1/s): peer=%s session=%s: %v",
						route.peerKey, route.sessionID, err)
				}
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
