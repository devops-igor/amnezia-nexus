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
