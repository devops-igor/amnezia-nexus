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
	// ErrRouteCapacityExhausted is returned by TryRegisterSessionWithLimit
	// when a NEW route cannot be admitted because the configured
	// active-route budget is full (issue #388: checked registration —
	// admission callers must observe the refusal and roll back, instead of
	// inferring it from an absent route). Re-registering an existing peer
	// never returns it: replacement does not increase the route count.
	ErrRouteCapacityExhausted = errors.New("forwarder: active route limit reached")
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
	Occupancy          int    `json:"occupancy"`
	Capacity           int    `json:"capacity"`
	HighWater          int    `json:"high_water"`
	QueueFullDrops     uint64 `json:"queue_full_drops"`
	WriteCount         uint64 `json:"write_count"`
	WriteErrors        uint64 `json:"write_errors"`
	WriteStalls        uint64 `json:"write_stalls"`
	WritesInFlight     int    `json:"writes_in_flight"`
	OldestWriteMS      int64  `json:"oldest_write_ms"`
	MaxWriteDurationMS int64  `json:"max_write_duration_ms"`
	P95WriteSamples    int    `json:"p95_write_samples"`
	P95WriteMS         int64  `json:"p95_write_ms"`

	// PeerKeyDisplay is the REDACTED, human-readable rendering of the peer
	// this stats block belongs to (issue #424 round 6, finding 2).
	//
	// It exists because these stats are served as a MAP whose key must be a
	// unique, collision-resistant identifier, and the redaction convention
	// (a truncated key prefix) is not unique. The map key is therefore the
	// opaque ingress.PeerKeyFingerprint, and this field carries the display
	// form so a reader of the map still sees something recognizable instead
	// of a digest.
	//
	// It is populated at the API boundary by the caller that owns both the
	// raw key and the redaction convention; the forwarder itself does not
	// redact and leaves it empty. Additive and omitempty: a caller that does
	// not set it keeps the previous payload exactly.
	PeerKeyDisplay string `json:"peer_key_display,omitempty"`

	// The *Recent fields are the RECENT-change counterparts of the three
	// lifetime failure counters above, measured over the sampling window
	// described in route_pressure.go (issue #424 round 6, finding 3). They
	// are additive and drive the current-pressure decision; the lifetime
	// fields above are untouched and stay visible as history.
	QueueFullDropsRecent uint64 `json:"queue_full_drops_recent"`
	WriteErrorsRecent    uint64 `json:"write_errors_recent"`
	WriteStallsRecent    uint64 `json:"write_stalls_recent"`
}

type sessionRoute struct {
	sessionID       string
	connectionID    string
	peerKey         string
	assignedIP      string
	backendTunnelID int64
	returnPath      *ReturnPath // immutable owner for this route generation; nil means legacy
	clientQueue     chan []byte
	queueReady      chan struct{} // coalesced notification; dequeue holds aggregateQueueMu
	queueHighWater  atomic.Uint64
	queueFullDrops  atomic.Uint64
	queueOccupancy  int // guarded by aggregateQueueMu; reconciles compatibility drains
	// pressure windows the route's monotonic failure counters so HasPressure
	// can mean "degraded now" instead of "degraded at some point since the
	// route was created" (issue #424 round 6, finding 3). It has its own mutex
	// and is never touched on the packet path.
	pressure       routePressureWindow
	writeMu        sync.Mutex // admission and completion; never acquired under f.mu
	retired        atomic.Bool
	createdAt      time.Time
	traffic        trafficCounters
	writeMetrics   DeviceWriteTelemetry  // guarded by Forwarder.writeMetricsMu
	writeLatencies routeLatencyReservoir // guarded by Forwarder.writeMetricsMu
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
	backendTraffic   map[int64]*trafficCounters
	backendQueues    map[int64]chan []byte   // backendTunnelID -> queue
	backendDevices   map[int64]PacketDevice  // backendTunnelID -> device
	backendPumpStops map[int64]chan struct{} // backendTunnelID -> pump stop channel
	backendPumpDones map[int64]chan struct{} // backendTunnelID -> pump done channel
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
	totalRxPackets      atomic.Uint64
	totalTxPackets      atomic.Uint64
	dropsQueueFull      atomic.Uint64 // return packets dropped: per-route queue full
	dropsNoRoute        atomic.Uint64 // return packets dropped: unroutable / no session registered (issue #151)
	dropsPacketTooLarge atomic.Uint64 // return packets dropped because they exceed the queued payload bound
	dropsTotal          atomic.Uint64 // return-path drops counted so far

	clientDropsQueueFull   atomic.Uint64 // client packets dropped: backend queue full
	clientDropsRateLimited atomic.Uint64 // client packets dropped: upstream token bucket exhausted
	clientDropsNoBackend   atomic.Uint64 // client packets dropped: backend queue not registered/found
	clientDropsTotal       atomic.Uint64 // monotonic total of client->backend drops in forwarder
	// spoofedRebinds counts client→backend packets whose claimed inner
	// source IP failed the rebind ownership guard (issue #89): outside the
	// portal subnet or already assigned to another route. Such packets are
	// dropped (never forwarded, never rebound). Exposed via SpoofedRebinds.
	spoofedRebinds atomic.Uint64
	// returnRejectClassifier, when non-nil, receives one call for every
	// return packet rejected by RouteBackendToClient BEFORE any per-route
	// handling, together with the reason the filter fired (unrouted,
	// malformed, or backend mismatch). The ingress engine registers one
	// classifier for its lifetime and folds these rejections into the
	// engine-level MalformedDrops/UnmappedDrops/OwnershipMismatchDrops
	// counters, which would otherwise stay at zero in production because
	// the filter rejects the packet before the engine's write callback
	// ever sees it (issue #389 rework 2).
	//
	// Single-owner rule per drop reason (both sites enforced HERE, in the
	// forwarder — the ONLY production rejection sites):
	//   - UnmappedDrops: unrouted replies are rejected at the routesByIP
	//     lookup, where no route exists — so no ReturnPath writer exists
	//     either. Only the service-level classifier counts them; the
	//     engine's write callback never observes an unmapped packet.
	//   - MalformedDrops / OwnershipMismatchDrops: those replies are
	//     rejected at the route.returnPath shape filter, which returns
	//     before calling the writer. Exactly one of (filter, writer) counts
	//     a given packet.
	// The write callback must never classify the same packet as the
	// filter: validReturnDestination is checked before path.write.
	returnRejectClassifier func(reason ReturnRejectReason) // guarded by mu; set via SetReturnRejectClassifier
	// writeErrLogUntil throttles return-path device Write-error log lines to
	// at most one per second (issue #43: a failed dev.Write on the client
	// queue -> client device leg, e.g. "no transport keys for peer", used to
	// vanish silently). CAS-based on a monotonic deadline, same pattern as
	// the endpoint listener's rejectLogUntil; safe under concurrent pumps.
	writeErrLogUntil   atomic.Int64
	writeMetricsMu     sync.Mutex
	writeMetrics       DeviceWriteTelemetry
	writeHistogram     writeDurationHistogram
	writeLatencies     latencyReservoir
	writesInFlight     map[*sessionRoute]time.Time
	rateTracker        *RateTracker
	historyRateTracker *RateTracker
	// genEpoch is the forwarder's generation counter (issue #429 review
	// blocker 1). It advances only in Start, so every Start after Stop is an
	// explicit new generation: the rate trackers and the per-backend traffic
	// history baselines are reset/re-primed instead of a restart being
	// inferred from counters that moved backwards.
	genEpoch atomic.Uint64
	// backendTrafficGeneration is the generation the per-backend traffic
	// HISTORY baselines are tagged with. It mirrors genEpoch.
	backendTrafficGeneration atomic.Uint64
	aggregateQueueOccupancy  int               // guarded by aggregateQueueMu
	aggregateQueueCapacity   int               // guarded by aggregateQueueMu
	queueDwell               queueDwellTracker // guarded by aggregateQueueMu
	aggregateQueueHighWater  atomic.Uint64
	// aggregateQueueMu serializes managed queue operations so aggregate
	// high-water is sampled at the same linearization point as enqueue/dequeue.
	aggregateQueueMu sync.Mutex
	running          bool
	stopCh           chan struct{}
	pumpsRunning     bool
	pumpsStopCh      chan struct{}
	pumpsWg          sync.WaitGroup
	// Diagnostic registration count. Teardown ownership is determined by
	// sessionRoute.sessionID, never inferred from this counter.
	peerRegs    map[string]uint64 // peerKey -> registrations seen
	stopTimeout time.Duration
}

// DefaultClientQueueSize is the default capacity of each per-client downstream packet channel.
// Sized to absorb downstream microbursts without drops while keeping memory bounded
// (2048 packets ~ 2.8 MB @ MTU 1420, issue #151).
const DefaultClientQueueSize = 2048

// DefaultBackendQueueSize is the default capacity of each backend packet queue.
// It is intentionally independent from DefaultClientQueueSize so client queue
// tuning does not silently change backend queue memory allocation.
const DefaultBackendQueueSize = 2048

// MaxSupportedActiveRoutes is the default route population and the limit on
// per-route status diagnostics. Explicit populations use MaxBudgetedActiveRoutes
// as their memory-budget bound.
const MaxSupportedActiveRoutes = 1000

// MaxClientQueuePacketBytes is the conservative payload size reserved for one
// queued packet (the VPN MTU is 1420 bytes).
const MaxClientQueuePacketBytes = 1500

// MaxClientQueueMemoryBytes is the explicit aggregate queued-payload budget
// for all supported active routes. Per-route queue capacity is derived from
// this budget and the configured maximum active-route population.
const MaxClientQueueMemoryBytes = 8 << 30

// MaxBudgetedActiveRoutes is the largest population that can reserve even one
// maximum-sized packet per client inside the aggregate payload budget.
const MaxBudgetedActiveRoutes = MaxClientQueueMemoryBytes / MaxClientQueuePacketBytes

// ValidateClientRouteLimit rejects populations that cannot fit the payload
// budget. Non-positive values select the default route limit.
func ValidateClientRouteLimit(activeRoutes int) error {
	if activeRoutes > MaxBudgetedActiveRoutes {
		return errors.New("maximum active routes exceeds the client queue memory budget")
	}
	return nil
}

// MaxClientQueuePacketsForRoutes returns the largest per-route queue capacity
// that keeps the configured active-route population within the aggregate
// queued-payload memory budget. Zero means the population cannot fit even one
// packet per route and must be rejected.
func MaxClientQueuePacketsForRoutes(activeRoutes int) int {
	if activeRoutes <= 0 {
		activeRoutes = MaxSupportedActiveRoutes
	}
	maxBudgetPackets := MaxClientQueueMemoryBytes / MaxClientQueuePacketBytes
	if activeRoutes > maxBudgetPackets {
		return 0
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
	f, _ := NewForwarderWithLimits(accountant, portalSubnetCIDR, qSize, MaxSupportedActiveRoutes) // Default route limit always fits the budget.
	return f
}

// NewForwarderWithLimits creates a forwarder with an explicit client-queue size
// and maximum active-route count. The queue size is bounded from the same
// aggregate payload-memory budget as the route limit, keeping the configured
// session capacity and the data-plane memory budget aligned. Populations that
// cannot reserve even one packet per route are rejected.
func NewForwarderWithLimits(accountant *TrafficAccountant, portalSubnetCIDR string, queueSize, maxActiveRoutes int) (*Forwarder, error) {
	if err := ValidateClientRouteLimit(maxActiveRoutes); err != nil {
		return nil, err
	}
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
	fwd := &Forwarder{
		accountant:         accountant,
		portalSubnet:       portalSubnet,
		routesByPeer:       make(map[string]*sessionRoute),
		routesByIP:         make(map[string]*sessionRoute),
		backendQueues:      make(map[int64]chan []byte),
		backendDevices:     make(map[int64]PacketDevice),
		writesInFlight:     make(map[*sessionRoute]time.Time),
		backendPumpStops:   make(map[int64]chan struct{}),
		backendPumpDones:   make(map[int64]chan struct{}),
		peerRegs:           make(map[string]uint64),
		bufSize:            queueSize,
		backendBufSize:     DefaultBackendQueueSize,
		maxActiveRoutes:    maxActiveRoutes,
		rateTracker:        NewRateTracker(),
		historyRateTracker: NewRateTracker(),
		stopCh:             make(chan struct{}),
	}
	// The constructor-time incarnation is generation 0 and is already live:
	// adopt its baselines explicitly so a reused Forwarder value always has
	// exactly one accepted generation (issue #429 review blocker 1).
	fwd.backendTrafficGeneration.Store(0)
	fwd.resetRateTrackersForGeneration(0)
	return fwd, nil
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
	f.BeginRegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, limitDownBps, limitUpBps).Wait()
}

// BeginRegisterSessionWithLimit installs the new route and stops admission on
// the old generation without waiting for device I/O. Call Wait on the returned
// retirement only after releasing caller locks (including Service.mu).
//
// Void registration for API compatibility: a route-capacity refusal is
// silent here and observable only through the usual absent-route behavior.
// Callers that must distinguish capacity exhaustion (the ingress admission
// path, issue #388) use TryRegisterSessionWithLimit instead.
func (f *Forwarder) BeginRegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, limitDownBps, limitUpBps int64) (retirement Retirement) {
	retirement, _ = f.TryRegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, limitDownBps, limitUpBps)
	return retirement
}

// TryRegisterSessionWithLimit is BeginRegisterSessionWithLimit with an
// inspectable success/failure contract (issue #388): it returns the
// retirement of any replaced route and reports ErrRouteCapacityExhausted
// — without installing anything — when a new peer's route does not fit the
// configured active-route budget. Re-registration of an existing peer is
// allowed (replacement, not growth) and never reports capacity exhaustion.
//
// Call Wait on the retirement only after releasing caller locks; on error
// the returned retirement is always the zero value.
func (f *Forwarder) TryRegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, limitDownBps, limitUpBps int64) (retirement Retirement, err error) {
	return f.TryRegisterSessionWithReturnPath(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, limitDownBps, limitUpBps, nil)
}

// TryRegisterSessionWithReturnPath installs a route-bound plaintext writer.
// A nonnil path always takes precedence over legacy devices, including when closed.
func (f *Forwarder) TryRegisterSessionWithReturnPath(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID, limitDownBps, limitUpBps int64, path *ReturnPath) (Retirement, error) {
	if path != nil && path.Closed() {
		return Retirement{}, ErrReturnPathClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registerSessionLocked(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, limitDownBps, limitUpBps, path)
}

func (f *Forwarder) registerSessionLocked(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID, limitDownBps, limitUpBps int64, path *ReturnPath) (retirement Retirement, err error) {
	if path != nil && path.Closed() {
		return Retirement{}, ErrReturnPathClosed
	}

	// A new peer is rejected when the configured active-route budget is
	// full. Re-registration of an existing peer is allowed so
	// reconnect/rekey lifecycle semantics remain unchanged and does not
	// increase the active route count.
	maxActiveRoutes := f.maxActiveRoutes
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = MaxSupportedActiveRoutes
	}
	if _, exists := f.routesByPeer[peerKey]; !exists && len(f.routesByPeer) >= maxActiveRoutes {
		return Retirement{}, ErrRouteCapacityExhausted
	}

	// Ensure backend queue exists
	if _, ok := f.backendQueues[backendTunnelID]; !ok {
		f.backendQueues[backendTunnelID] = make(chan []byte, f.backendBufSize)
		f.ensureBackendTrafficLocked(backendTunnelID)
	}

	var tbDown, tbUp *TokenBucket
	if limitDownBps > 0 {
		tbDown = NewTokenBucket(limitDownBps)
	}
	if limitUpBps > 0 {
		tbUp = NewTokenBucket(limitUpBps)
	}

	route := &sessionRoute{
		createdAt:       time.Now(),
		returnPath:      path,
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
		retirement.route = old
		f.stopRoutePumpLocked(old)
		f.drainRouteQueueLocked(old)
		f.changeQueueCapacityLocked(-cap(old.clientQueue))
		if old.assignedIP != "" {
			if current, exists := f.routesByIP[old.assignedIP]; exists && current == old {
				delete(f.routesByIP, old.assignedIP)
			}
		}
	}
	// Keep the registration count for diagnostics. Route retirement itself
	// uses the session ID, because rekeys replace routes without a matching
	// unregister call for each replaced session.
	f.peerRegs[peerKey]++

	f.routesByPeer[peerKey] = route
	f.changeQueueCapacityLocked(cap(route.clientQueue))
	if assignedIP != "" {
		f.routesByIP[assignedIP] = route
	}

	if f.pumpsRunning {
		route.pumpStarted = true
		f.pumpsWg.Add(1)
		go f.pumpClientQueue(f.pumpsStopCh, route)
	}
	return retirement, nil
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
	f.reconcileBeforeQueueMutationLocked(route)
	for {
		select {
		case <-route.clientQueue:
			f.reconcileQueueOccupancyLocked(route)
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

// PeerRegistration returns the registration generation seen for a peer.
func (f *Forwarder) PeerRegistration(peerKey string) uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.peerRegs == nil {
		return 0
	}
	return f.peerRegs[peerKey]
}

// RouteSessionID returns the active session ID for a peer's route, or "" if no route exists.
func (f *Forwarder) RouteSessionID(peerKey string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if route, ok := f.routesByPeer[peerKey]; ok && route != nil {
		return route.sessionID
	}
	return ""
}

// HasSessionRoute checks that the live route still belongs to the session and
// its assigned IP/backend. A stale or missing route needs normal admission.
func (f *Forwarder) HasSessionRoute(peerKey, sessionID, connectionID, assignedIP string, backendTunnelID int64) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	route := f.routesByPeer[peerKey]
	return route != nil && !route.retired.Load() && route.sessionID == sessionID && route.connectionID == connectionID &&
		route.assignedIP == assignedIP && route.backendTunnelID == backendTunnelID &&
		f.routesByIP[assignedIP] == route
}

// UnregisterSession removes a peer session route, stops its pump goroutine,
// and drains its queue so in-flight senders cannot block.
//
// This unconditional method is for callers intentionally removing whichever
// route is currently associated with the peer. Session lifecycle callers
// must use BeginUnregisterSession with the session ID instead.
func (f *Forwarder) UnregisterSession(peerKey string) {
	f.beginUnregisterSession(peerKey, "").Wait()
}

// BeginUnregisterSession retires the route only if it still belongs to sessionID.
// A delayed teardown for an old session cannot remove its replacement. Call
// Wait after releasing caller locks to finish any admitted device writes.
func (f *Forwarder) BeginUnregisterSession(peerKey, sessionID string) Retirement {
	if sessionID == "" {
		return Retirement{}
	}
	return f.beginUnregisterSession(peerKey, sessionID)
}

func (f *Forwarder) beginUnregisterSession(peerKey, sessionID string) (retirement Retirement) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if route, ok := f.routesByPeer[peerKey]; ok && route != nil && (sessionID == "" || route.sessionID == sessionID) {
		retirement.route = route
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
		// Terminate the per-session pump exactly once. The queue is NOT
		// closed: RouteBackendToClient sends to it after releasing the lock,
		// and closing would race into a send-on-closed panic. Instead the
		// pump stops via stopCh and the buffered queue is drained here —
		// late senders just fill the abandoned buffer and hit ErrQueueFull.
		f.stopRoutePumpLocked(route)
		f.drainRouteQueueLocked(route)
		f.changeQueueCapacityLocked(-cap(route.clientQueue))
	}
	return retirement
}

func (f *Forwarder) retireRoutesMatchingLocked(predicate func(*sessionRoute) bool) []Retirement {
	var matches []*sessionRoute
	for _, route := range f.routesByPeer {
		if route != nil && (predicate == nil || predicate(route)) {
			matches = append(matches, route)
		}
	}
	retirements := make([]Retirement, 0, len(matches))
	for _, route := range matches {
		retirements = append(retirements, Retirement{route: route})
		if cur, ok := f.routesByIP[route.assignedIP]; ok && cur == route {
			delete(f.routesByIP, route.assignedIP)
		}
		delete(f.routesByPeer, route.peerKey)
		f.stopRoutePumpLocked(route)
		f.drainRouteQueueLocked(route)
		f.changeQueueCapacityLocked(-cap(route.clientQueue))
	}
	return retirements
}

// RetireAllRoutes stops pumps, drains queues, removes all routes from forwarder
// routing tables, and returns a wait function that callers execute outside forwarder
// locks to join in-flight writes with a bounded context.
func (f *Forwarder) RetireAllRoutes() (wait func(ctx context.Context) error) {
	if f == nil {
		return func(ctx context.Context) error { return nil }
	}
	f.mu.Lock()
	retirements := f.retireRoutesMatchingLocked(nil)
	clear(f.routesByPeer)
	clear(f.routesByIP)
	f.aggregateQueueMu.Lock()
	f.aggregateQueueOccupancy = 0
	f.aggregateQueueCapacity = 0
	f.queueDwell.observe(time.Now(), 0, 0)
	f.aggregateQueueMu.Unlock()
	f.mu.Unlock()

	return func(ctx context.Context) error {
		if ctx == nil {
			ctx = context.Background()
		}
		for _, ret := range retirements {
			if err := ret.WaitContext(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// RetireRoutesByReturnPath stops pumps, drains queues, and removes routes associated
// with the specified ReturnPath. Routes belonging to other engines remain untouched.
// Returns a wait function that callers execute outside forwarder locks to join in-flight writes.
func (f *Forwarder) RetireRoutesByReturnPath(path *ReturnPath) (wait func(ctx context.Context) error) {
	if f == nil {
		return func(ctx context.Context) error { return nil }
	}
	f.mu.Lock()
	retirements := f.retireRoutesMatchingLocked(func(route *sessionRoute) bool {
		return route.returnPath == path
	})
	f.mu.Unlock()

	return func(ctx context.Context) error {
		if ctx == nil {
			ctx = context.Background()
		}
		for _, ret := range retirements {
			if err := ret.WaitContext(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// RetireUnmanagedRoutes stops pumps, drains queues, and removes unmanaged routes
// (routes where returnPath == nil).
// Returns a wait function that callers execute outside forwarder locks to join in-flight writes.
func (f *Forwarder) RetireUnmanagedRoutes() (wait func(ctx context.Context) error) {
	return f.RetireRoutesByReturnPath(nil)
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
		f.ensureBackendTrafficLocked(newBackendTunnelID)
	}

	route.backendTunnelID = newBackendTunnelID
	return nil
}

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

// RegisterSessionWithReturnPath registers a peer session route with a dedicated ReturnPath.
func (f *Forwarder) RegisterSessionWithReturnPath(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, path *ReturnPath) {
	retirement, _ := f.TryRegisterSessionWithReturnPath(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, 0, 0, path)
	retirement.Wait()
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

// ReconfigureClientQueueConfig changes the capacity used for subsequently
// registered client routes. A route-limit change is safe with live sessions
// when it accommodates them and the existing queue size fits the new budget.
// Resizing live channels still requires all sessions to disconnect first.
func (f *Forwarder) ReconfigureClientQueueConfig(size, maxActiveRoutes int) error {
	if err := ValidateClientRouteLimit(maxActiveRoutes); err != nil {
		return err
	}
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
	if len(f.routesByPeer) > 0 && size != f.bufSize {
		return errors.New("client queue size cannot change while sessions are active")
	}
	if len(f.routesByPeer) > maxActiveRoutes {
		return errors.New("client route limit cannot be lower than the active route count")
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
	return f.routeQueueStatsLocked(route), true
}

// AllRouteQueueStats returns point-in-time snapshots for all active peers.
func (f *Forwarder) AllRouteQueueStats() map[string]RouteQueueStats {
	type rawItem struct {
		peerKey        string
		route          *sessionRoute
		writes         DeviceWriteTelemetry
		latencies      routeLatencyReservoir
		occupancy      int
		capacity       int
		highWater      int
		queueFullDrops uint64
	}

	f.mu.RLock()
	f.aggregateQueueMu.Lock()
	f.writeMetricsMu.Lock()

	raw := make([]rawItem, 0, len(f.routesByPeer))
	for peerKey, route := range f.routesByPeer {
		if route == nil {
			continue
		}
		writes := route.writeMetrics
		if started, ok := f.writesInFlight[route]; ok {
			writes.InFlight = 1
			writes.OldestInFlight = time.Since(started)
			if writes.OldestInFlight >= DeviceWriteStallThreshold {
				writes.Stalls++
			}
		}
		raw = append(raw, rawItem{
			peerKey:        peerKey,
			route:          route,
			writes:         writes,
			latencies:      route.writeLatencies,
			occupancy:      len(route.clientQueue),
			capacity:       cap(route.clientQueue),
			highWater:      int(route.queueHighWater.Load()), // #nosec G115 -- bounded by channel capacity.
			queueFullDrops: route.queueFullDrops.Load(),
		})
	}

	f.writeMetricsMu.Unlock()
	f.aggregateQueueMu.Unlock()
	f.mu.RUnlock()

	now := time.Now()
	stats := make(map[string]RouteQueueStats, len(raw))
	for _, item := range raw {
		p95 := item.latencies.p95()
		recent := item.route.pressure.sample(now, item.queueFullDrops, item.writes.Errors, item.writes.Stalls)
		stats[item.peerKey] = RouteQueueStats{
			Occupancy:            item.occupancy,
			Capacity:             item.capacity,
			HighWater:            item.highWater,
			QueueFullDrops:       item.queueFullDrops,
			WriteCount:           item.writes.Count,
			WriteErrors:          item.writes.Errors,
			WriteStalls:          item.writes.Stalls,
			WritesInFlight:       item.writes.InFlight,
			OldestWriteMS:        item.writes.OldestInFlight.Milliseconds(),
			MaxWriteDurationMS:   item.writes.MaxDuration.Milliseconds(),
			P95WriteMS:           p95.Milliseconds(),
			P95WriteSamples:      item.latencies.count,
			QueueFullDropsRecent: recent.QueueFullDropsRecent,
			WriteErrorsRecent:    recent.WriteErrorsRecent,
			WriteStallsRecent:    recent.WriteStallsRecent,
		}
	}
	return stats
}

// AggregateQueueStats returns current and high-water occupancy across all
// active peer queues. The per-route snapshot remains available through
// AllRouteQueueStats for diagnosis of an individual stalled consumer.
func (f *Forwarder) AggregateQueueStats() (occupancy, capacity, highWater int) {
	occupancy, capacity, highWater, _ = f.aggregateQueueSnapshot()
	return
}

// aggregateQueueSnapshot reconciles legacy handles and reads dwell coherently.
// Managed mutations update dwell at their transition; compatibility drains can
// only reset the unobserved run at this snapshot, never supply a past drain time.
func (f *Forwarder) aggregateQueueSnapshot() (occupancy, capacity, highWater int, dwell queueDwellSnapshot) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()
	highWater = int(f.aggregateQueueHighWater.Load()) // #nosec G115 -- bounded by active queue capacities.
	reconciled := false
	for _, route := range f.routesByPeer {
		if route == nil {
			continue
		}
		current := len(route.clientQueue)
		reconciled = reconciled || current != route.queueOccupancy
		route.queueOccupancy = current
		occupancy += current
		capacity += cap(route.clientQueue)
	}
	f.aggregateQueueOccupancy, f.aggregateQueueCapacity = occupancy, capacity
	now := time.Now()
	if reconciled {
		f.queueDwell.reconcile(now, occupancy, capacity)
	} else {
		f.queueDwell.observe(now, occupancy, capacity)
	}
	return occupancy, capacity, highWater, f.queueDwell.snapshot(now)
}

// DeviceWriteStats returns client-device write failures, total write duration,
// and the slowest observed write.
func (f *Forwarder) DeviceWriteStats() (errors uint64, total, max time.Duration) {
	stats := f.DeviceWriteSnapshot()
	return stats.Errors, stats.TotalDuration, stats.MaxDuration
}

// DropStats returns the number of return packets dropped because a route's
// client queue was full, the number of return packets dropped because no
// registered session route matched the destination IP, and the total number
// of return-path drops, including oversized packets, since the current startup epoch.
// Both are exposed via the stats API so a stalled downstream path and unroutable
// sessions are visible without tailing logs (issues #39, #151).
func (f *Forwarder) DropStats() (queueFull, noRoute, total uint64) {
	if f == nil {
		return 0, 0, 0
	}
	return f.dropsQueueFull.Load(), f.dropsNoRoute.Load(), f.dropsTotal.Load()
}

// DropsNoRoute returns the number of return packets dropped because no
// registered session route matched the packet's destination IP since startup (issue #151).
func (f *Forwarder) DropsNoRoute() uint64 {
	if f == nil {
		return 0
	}
	return f.dropsNoRoute.Load()
}

// DropsQueueFull returns the number of return packets dropped because a
// route's client queue was full since startup (issue #151).
func (f *Forwarder) DropsQueueFull() uint64 {
	if f == nil {
		return 0
	}
	return f.dropsQueueFull.Load()
}

// DropsPacketTooLarge returns the number of return packets dropped because
// they exceed the payload size that can be safely budgeted in client queues since startup.
func (f *Forwarder) DropsPacketTooLarge() uint64 {
	if f == nil {
		return 0
	}
	return f.dropsPacketTooLarge.Load()
}

// ClientDropStats returns the number of client-to-backend packets dropped because
// the backend queue was full, rate limited, or no backend was found, along with
// the monotonic total of client-to-backend drops in the forwarder since startup.
func (f *Forwarder) ClientDropStats() (queueFull, rateLimited, noBackend, total uint64) {
	if f == nil {
		return 0, 0, 0, 0
	}
	return f.clientDropsQueueFull.Load(),
		f.clientDropsRateLimited.Load(),
		f.clientDropsNoBackend.Load(),
		f.clientDropsTotal.Load()
}

// ClientDropStatsSinceStartup returns client-to-backend drop counts since the current Start() epoch.
func (f *Forwarder) ClientDropStatsSinceStartup() (queueFull, rateLimited, noBackend, total uint64) {
	return f.ClientDropStats()
}

// DropsQueueFullSinceStartup returns return queue-full drops since the current Start() epoch.
func (f *Forwarder) DropsQueueFullSinceStartup() uint64 {
	return f.DropsQueueFull()
}

// DropsPacketTooLargeSinceStartup returns oversized packet drops since the current Start() epoch.
func (f *Forwarder) DropsPacketTooLargeSinceStartup() uint64 {
	return f.DropsPacketTooLarge()
}

// RawDropStats returns lifetime return drop counters without startup baseline subtraction.
func (f *Forwarder) RawDropStats() (queueFull, noRoute, total uint64) {
	if f == nil {
		return 0, 0, 0
	}
	return f.dropsQueueFull.Load(), f.dropsNoRoute.Load(), f.dropsTotal.Load()
}

// RawClientDropStats returns lifetime client drop counters without startup baseline subtraction.
func (f *Forwarder) RawClientDropStats() (queueFull, rateLimited, noBackend, total uint64) {
	if f == nil {
		return 0, 0, 0, 0
	}
	return f.clientDropsQueueFull.Load(), f.clientDropsRateLimited.Load(), f.clientDropsNoBackend.Load(), f.clientDropsTotal.Load()
}

// SeedDropsForTest increments the raw monotonic drop counters for testing baseline behavior.
func (f *Forwarder) SeedDropsForTest(queueFull, noRoute, tooLarge, clientQueueFull, clientRateLimited, clientNoBackend uint64) {
	if f == nil {
		return
	}
	f.dropsQueueFull.Add(queueFull)
	f.dropsNoRoute.Add(noRoute)
	f.dropsPacketTooLarge.Add(tooLarge)
	f.dropsTotal.Add(queueFull + noRoute + tooLarge)
	f.clientDropsQueueFull.Add(clientQueueFull)
	f.clientDropsRateLimited.Add(clientRateLimited)
	f.clientDropsNoBackend.Add(clientNoBackend)
	f.clientDropsTotal.Add(clientQueueFull + clientRateLimited + clientNoBackend)
}

// ResetDropCounters resets monotonic drop counters to zero.
func (f *Forwarder) ResetDropCounters() {
	if f == nil {
		return
	}
	f.resetDropCounters()
}

// InPortalSubnet reports whether ip belongs to the portal client pool.
// Unparseable IPs and an unknown subnet both answer false (fail-closed).
func (f *Forwarder) InPortalSubnet(ip string) bool {
	if f == nil || f.portalSubnet == nil {
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

// PacketStats returns monotonic totals of received and transmitted packets.
func (f *Forwarder) PacketStats() (rxPackets, txPackets uint64) {
	if f == nil {
		return 0, 0
	}
	return f.totalRxPackets.Load(), f.totalTxPackets.Load()
}

// Rates updates and returns recent throughput and packet rates.
func (f *Forwarder) Rates() TrafficRates {
	if f == nil {
		return TrafficRates{}
	}
	// The generation is captured BEFORE the counter snapshot (review round
	// 6): a Start() between capture and read leaves this observation tagged
	// old, so the tracker conservatively rejects it instead of mislabeling
	// pre-restart counters with the new generation.
	gen := f.currentGeneration()
	rxBytes, txBytes, _ := f.GetStats()
	rxPackets := f.totalRxPackets.Load()
	txPackets := f.totalTxPackets.Load()
	queueDrops, _, totalDrops := f.DropStats()
	if f.rateTracker != nil {
		f.rateTracker.Sample(gen, time.Now(), rxBytes, txBytes, rxPackets, txPackets, totalDrops, queueDrops)
		return f.rateTracker.Snapshot(rxPackets, txPackets)
	}
	return TrafficRates{TotalRxPackets: rxPackets, TotalTxPackets: txPackets}
}

// QueuePressure updates and returns queue pressure duration and utilization.
func (f *Forwarder) QueuePressure() QueuePressureStats {
	if f == nil {
		return QueuePressureStats{}
	}
	// Generation before counters: same ordering contract as Rates.
	gen := f.currentGeneration()
	rxBytes, txBytes, _ := f.GetStats()
	rxPackets := f.totalRxPackets.Load()
	txPackets := f.totalTxPackets.Load()
	queueDrops, _, totalDrops := f.DropStats()
	occ, cap, hw, dwell := f.aggregateQueueSnapshot()
	f.rateTracker.Sample(gen, time.Now(), rxBytes, txBytes, rxPackets, txPackets, totalDrops, queueDrops)
	stats := f.rateTracker.PressureSnapshot(occ, cap, hw, queueDrops)
	stats.SecondsAbove50Pct, stats.SecondsAbove80Pct = dwell.total50, dwell.total80
	stats.ConsecutiveAbove50Sec, stats.ConsecutiveAbove80Sec = dwell.consecutive50, dwell.consecutive80
	return stats
}

// HistoryRates updates and returns history throughput and packet rates
// against an independent history baseline.
func (f *Forwarder) HistoryRates(now time.Time) TrafficRates {
	if f == nil {
		return TrafficRates{}
	}
	// Generation before counters: same ordering contract as Rates.
	gen := f.currentGeneration()
	rxBytes, txBytes, _ := f.GetStats()
	rxPackets := f.totalRxPackets.Load()
	txPackets := f.totalTxPackets.Load()
	queueDrops, _, totalDrops := f.DropStats()
	if f.historyRateTracker != nil {
		f.historyRateTracker.Sample(gen, now, rxBytes, txBytes, rxPackets, txPackets, totalDrops, queueDrops)
		return f.historyRateTracker.Snapshot(rxPackets, txPackets)
	}
	return TrafficRates{TotalRxPackets: rxPackets, TotalTxPackets: txPackets}
}

// PrimeHistoryRates primes the independent history rate tracker baseline.
func (f *Forwarder) PrimeHistoryRates(now time.Time) {
	if f == nil || f.historyRateTracker == nil {
		return
	}
	// Generation before counters: same ordering contract as Rates.
	gen := f.currentGeneration()
	rxBytes, txBytes, _ := f.GetStats()
	rxPackets := f.totalRxPackets.Load()
	txPackets := f.totalTxPackets.Load()
	queueDrops, _, totalDrops := f.DropStats()
	f.historyRateTracker.Sample(gen, now, rxBytes, txBytes, rxPackets, txPackets, totalDrops, queueDrops)
}

// ActiveRoutesCount returns the number of currently registered routes.
func (f *Forwarder) ActiveRoutesCount() int {
	if f == nil {
		return 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.routesByPeer)
}

func (f *Forwarder) stopPumpsSignalOnly() {
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

// GetStats returns current aggregated traffic and active route counts.
func (f *Forwarder) GetStats() (rx int64, tx int64, activeRoutes int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rx = f.totalRxBytes.Load()
	tx = f.totalTxBytes.Load()
	activeRoutes = len(f.routesByPeer)
	return
}

// ReturnRouteOwner returns the return route owner ("upstream" or "none")
// based on currently registered active routes in the forwarder. If at least one active,
// non-stopped route has an open return path, "upstream" is returned. Otherwise, "none" is returned.
func (f *Forwarder) ReturnRouteOwner() string {
	if f == nil {
		return "none"
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.routesByPeer) == 0 {
		return "none"
	}
	for _, route := range f.routesByPeer {
		if route.stopped {
			continue
		}
		if route.returnPath != nil && !route.returnPath.Closed() {
			return "upstream"
		}
	}
	return "none"
}

// currentGeneration returns the forwarder's accepted generation.
func (f *Forwarder) currentGeneration() Generation {
	return Generation(f.genEpoch.Load())
}

// resetRateTrackersForGeneration adopts gen as the accepted generation for
// the aggregate and history rate trackers. Called from the constructor with
// the initial generation and from Start with the bumped one.
func (f *Forwarder) resetRateTrackersForGeneration(gen Generation) {
	f.rateTracker.Reset(gen)
	f.historyRateTracker.Reset(gen)
}

// resetBackendTrafficHistoryForGeneration re-primes every current per-backend
// traffic history baseline so a restarted forwarder measures only post-restart
// traffic into its history windows.
//
// Concurrency contract (issue #424 round 8, blocker 3): f.backendTraffic is
// snapshotted under f.mu.RLock so iteration cannot race with concurrent
// AttachBackendDevice or DetachBackendDevice map writes. The per-counter
// resetHistoryForGeneration calls then run outside f.mu, preventing lock-order
// inversion with RouteBackendToClient.
func (f *Forwarder) resetBackendTrafficHistoryForGeneration(gen Generation, now time.Time) {
	f.mu.RLock()
	snapshot := make([]*trafficCounters, 0, len(f.backendTraffic))
	for _, counters := range f.backendTraffic {
		snapshot = append(snapshot, counters)
	}
	f.mu.RUnlock()

	for _, counters := range snapshot {
		counters.resetHistoryForGeneration(gen, now)
	}
}

func (f *Forwarder) resetDropCounters() {
	f.dropsQueueFull.Store(0)
	f.dropsNoRoute.Store(0)
	f.dropsPacketTooLarge.Store(0)
	f.dropsTotal.Store(0)
	f.clientDropsQueueFull.Store(0)
	f.clientDropsRateLimited.Store(0)
	f.clientDropsNoBackend.Store(0)
	f.clientDropsTotal.Store(0)
}

// Start marks the forwarder active and establishes a new diagnostics
// generation: every cumulative telemetry baseline owned here is reset and
// re-primes on its next sample (issue #429 review blocker 1).
func (f *Forwarder) Start(ctx context.Context) {
	// Every Start after Stop is an explicit new generation. Bumping before
	// any sample can be tagged with it guarantees stale in-flight samples
	// from the previous generation are ignored rather than mixed in. The
	// per-backend history baselines re-prime for backends that exist now;
	// backends registered later prime lazily in their first history read.
	f.mu.Lock()
	f.running = true
	f.genEpoch.Add(1)
	f.backendTrafficGeneration.Store(f.genEpoch.Load())
	gen := Generation(f.genEpoch.Load())
	f.resetRateTrackersForGeneration(gen)
	f.resetDropCounters()
	f.mu.Unlock()

	// The baseline re-prime reads live counters (c.mu per counter), so it
	// must not run under f.mu: RouteBackendToClient holds f.mu while
	// sampling backend traffic, and blocking it here risks lock-order
	// inversion.
	f.resetBackendTrafficHistoryForGeneration(gen, time.Now())

	if f.accountant != nil {
		f.accountant.Start(ctx)
	}
}

// HasRoutesForReturnPath reports whether any active route in the forwarder references path.
func (f *Forwarder) HasRoutesForReturnPath(path *ReturnPath) bool {
	if f == nil || path == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, route := range f.routesByPeer {
		if route != nil && route.returnPath == path {
			return true
		}
	}
	return false
}

// SetStopTimeoutForTest sets the quiescence wait timeout for route retirement during Stop.
func (f *Forwarder) SetStopTimeoutForTest(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopTimeout = d
}

// SetBackendQueueForTest sets or deletes a backend queue for testing drop behavior.
func (f *Forwarder) SetBackendQueueForTest(backendTunnelID int64, ch chan []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ch == nil {
		delete(f.backendQueues, backendTunnelID)
	} else {
		f.backendQueues[backendTunnelID] = ch
		f.ensureBackendTrafficLocked(backendTunnelID)
	}
}

func (f *Forwarder) getStopTimeout() time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.stopTimeout > 0 {
		return f.stopTimeout
	}
	return 5 * time.Second
}

// Stop terminates the forwarder, retires and drains all routes, joins in-flight
// writes, stops pumps, and flushes the accountant.
func (f *Forwarder) Stop() error {
	if f == nil {
		return nil
	}
	var retireErr error
	if wait := f.RetireAllRoutes(); wait != nil {
		ctx, cancel := context.WithTimeout(context.Background(), f.getStopTimeout())
		retireErr = wait(ctx)
		cancel()
	}
	if retireErr != nil {
		f.stopPumpsSignalOnly()
		f.mu.Lock()
		f.running = false
		f.mu.Unlock()
		if f.accountant != nil {
			_ = f.accountant.Stop()
		}
		return retireErr
	}
	f.StopPumps()

	f.mu.Lock()
	f.running = false
	f.mu.Unlock()

	var accountantErr error
	if f.accountant != nil {
		accountantErr = f.accountant.Stop()
	}
	return accountantErr
}

// IsRunning returns true if the forwarder is active.
func (f *Forwarder) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}
