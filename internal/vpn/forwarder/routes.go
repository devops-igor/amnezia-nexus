package forwarder

import (
	"context"
	"sort"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
)

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

// RegisterSessionWithReturnPath registers a peer session route with a dedicated ReturnPath.
func (f *Forwarder) RegisterSessionWithReturnPath(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, path *ReturnPath) {
	retirement, _ := f.TryRegisterSessionWithReturnPath(sessionID, connectionID, peerKey, assignedIP, backendTunnelID, 0, 0, path)
	retirement.Wait()
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

// ActiveRoutesCount returns the number of currently registered routes.
func (f *Forwarder) ActiveRoutesCount() int {
	if f == nil {
		return 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.routesByPeer)
}

// RouteInfo holds structural and performance state for an active forwarder route.
type RouteInfo struct {
	PeerKey           string          `json:"peer_key"`
	AssignedIP        string          `json:"assigned_ip"`
	SessionID         string          `json:"session_id"`
	ConnectionID      string          `json:"connection_id"`
	BackendTunnelID   int64           `json:"backend_tunnel_id"`
	HasReturnPath     bool            `json:"has_return_path"`
	ReturnPathClosed  bool            `json:"return_path_closed"`
	Stats             RouteQueueStats `json:"stats"`
	SessionAgeSec     int64           `json:"session_age_sec"`
	LastTrafficAgeSec int64           `json:"last_traffic_age_sec"`
	Traffic           TrafficSnapshot `json:"traffic"`
	HasPressure       bool            `json:"has_pressure"`
}

// InspectRoutes returns a point-in-time inventory of all currently registered routes.
func (f *Forwarder) InspectRoutes() []RouteInfo {
	type rawRoute struct {
		peerKey          string
		assignedIP       string
		sessionID        string
		connectionID     string
		backendTunnelID  int64
		route            *sessionRoute
		writes           DeviceWriteTelemetry
		latencies        routeLatencyReservoir
		occupancy        int
		capacity         int
		highWater        int
		queueFullDrops   uint64
		hasReturnPath    bool
		returnPathClosed bool
		createdAt        time.Time
	}

	f.mu.RLock()
	f.aggregateQueueMu.Lock()
	f.writeMetricsMu.Lock()

	raw := make([]rawRoute, 0, len(f.routesByPeer))
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
		hasReturnPath := route.returnPath != nil
		returnPathClosed := hasReturnPath && route.returnPath.Closed()
		raw = append(raw, rawRoute{
			peerKey:          peerKey,
			assignedIP:       route.assignedIP,
			sessionID:        route.sessionID,
			connectionID:     route.connectionID,
			backendTunnelID:  route.backendTunnelID,
			route:            route,
			writes:           writes,
			latencies:        route.writeLatencies,
			occupancy:        len(route.clientQueue),
			capacity:         cap(route.clientQueue),
			highWater:        int(route.queueHighWater.Load()), // #nosec G115 -- bounded by channel capacity.
			queueFullDrops:   route.queueFullDrops.Load(),
			hasReturnPath:    hasReturnPath,
			returnPathClosed: returnPathClosed,
			createdAt:        route.createdAt,
		})
	}

	f.writeMetricsMu.Unlock()
	f.aggregateQueueMu.Unlock()
	f.mu.RUnlock()

	now := time.Now()
	routes := make([]RouteInfo, 0, len(raw))
	for _, item := range raw {
		p95 := item.latencies.p95()
		recent := item.route.pressure.sample(now, item.queueFullDrops, item.writes.Errors, item.writes.Stalls)
		stats := RouteQueueStats{
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
			QueueFullDropRatePPS: recent.DropRatePPS,
			WriteErrorsRecent:    recent.WriteErrorsRecent,
			WriteStallsRecent:    recent.WriteStallsRecent,
		}

		// HasPressure means DEGRADED NOW, not "degraded at some point since
		// this route was created" (issue #424 round 6, finding 3).
		hasPressure := (stats.Capacity > 0 && routeUtilization(stats) >= thresholds.RoutePressureUtilization()) ||
			stats.OldestWriteMS >= 100 ||
			stats.QueueFullDropsRecent > 0 ||
			stats.WriteErrorsRecent > 0 ||
			stats.WriteStallsRecent > 0

		routes = append(routes, RouteInfo{
			PeerKey:           item.peerKey,
			AssignedIP:        item.assignedIP,
			SessionID:         item.sessionID,
			ConnectionID:      item.connectionID,
			BackendTunnelID:   item.backendTunnelID,
			HasReturnPath:     item.hasReturnPath,
			ReturnPathClosed:  item.returnPathClosed,
			Stats:             stats,
			SessionAgeSec:     int64(now.Sub(item.createdAt) / time.Second),
			LastTrafficAgeSec: item.route.traffic.lastTrafficAge(now),
			Traffic:           item.route.traffic.snapshot(now),
			HasPressure:       hasPressure,
		})
	}
	return routes
}

// ProblemRoutes returns active routes ranked by current/recent pressure.
func (f *Forwarder) ProblemRoutes(limit int) []RouteInfo {
	return ProblemRoutesFromSnapshot(f.InspectRoutes(), limit)
}

// ProblemRoutesFromSnapshot filters and ranks a caller-owned route snapshot.
//
// The snapshot form exists so one higher-level status collection can inspect
// route pressure exactly once and reuse that same observation for routing
// consistency, the legacy route-queue map, all_routes and problem_routes.
// Sampling the monotonic counters independently in each consumer can otherwise
// advance the recency window between reads and make one response disagree with
// itself.
//
// Ranking follows issue #424's current-degradation-first rule. Lifetime totals
// remain visible as history and are only late tie-breakers after all current
// pressure signals are equal.
func ProblemRoutesFromSnapshot(allRoutes []RouteInfo, limit int) []RouteInfo {
	routes := make([]RouteInfo, 0, len(allRoutes))
	for _, r := range allRoutes {
		if r.HasPressure {
			routes = append(routes, r)
		}
	}
	if len(routes) == 0 {
		return []RouteInfo{}
	}

	sort.Slice(routes, func(i, j int) bool {
		rA := routes[i]
		rB := routes[j]

		// 1. Fresh packet loss is the strongest current signal.
		if rA.Stats.QueueFullDropsRecent != rB.Stats.QueueFullDropsRecent {
			return rA.Stats.QueueFullDropsRecent > rB.Stats.QueueFullDropsRecent
		}

		// 2. Then current queue saturation.
		utilA := routeUtilization(rA.Stats)
		utilB := routeUtilization(rB.Stats)
		if utilA != utilB {
			return utilA > utilB
		}

		// 3. Then fresh write failures/stalls.
		if rA.Stats.WriteErrorsRecent != rB.Stats.WriteErrorsRecent {
			return rA.Stats.WriteErrorsRecent > rB.Stats.WriteErrorsRecent
		}
		if rA.Stats.WriteStallsRecent != rB.Stats.WriteStallsRecent {
			return rA.Stats.WriteStallsRecent > rB.Stats.WriteStallsRecent
		}

		// 4. Live blocked-write age and recent latency context.
		if rA.Stats.OldestWriteMS != rB.Stats.OldestWriteMS {
			return rA.Stats.OldestWriteMS > rB.Stats.OldestWriteMS
		}
		if rA.Stats.P95WriteMS != rB.Stats.P95WriteMS {
			return rA.Stats.P95WriteMS > rB.Stats.P95WriteMS
		}

		// 5. Historical totals may break an otherwise-current-state tie, but
		// they never outrank an active signal above.
		if rA.Stats.QueueFullDrops != rB.Stats.QueueFullDrops {
			return rA.Stats.QueueFullDrops > rB.Stats.QueueFullDrops
		}
		if rA.Stats.WriteErrors != rB.Stats.WriteErrors {
			return rA.Stats.WriteErrors > rB.Stats.WriteErrors
		}
		if rA.Stats.WriteStalls != rB.Stats.WriteStalls {
			return rA.Stats.WriteStalls > rB.Stats.WriteStalls
		}

		return rA.PeerKey < rB.PeerKey
	})

	if limit > 0 && len(routes) > limit {
		return routes[:limit]
	}
	return routes
}

func routeUtilization(stats RouteQueueStats) float64 {
	if stats.Capacity <= 0 {
		return 0
	}
	return float64(stats.Occupancy) / float64(stats.Capacity)
}
