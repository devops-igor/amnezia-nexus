package forwarder

import (
	"math"
	"sort"
)

// RouteInfo holds structural and performance state for an active forwarder route.
type RouteInfo struct {
	PeerKey          string          `json:"peer_key"`
	AssignedIP       string          `json:"assigned_ip"`
	SessionID        string          `json:"session_id"`
	ConnectionID     string          `json:"connection_id"`
	BackendTunnelID  int64           `json:"backend_tunnel_id"`
	HasReturnPath    bool            `json:"has_return_path"`
	ReturnPathClosed bool            `json:"return_path_closed"`
	Stats            RouteQueueStats `json:"stats"`
	HasPressure      bool            `json:"has_pressure"`
}

// InspectRoutes returns a point-in-time inventory of all currently registered routes.
func (f *Forwarder) InspectRoutes() []RouteInfo {
	f.mu.RLock()
	defer f.mu.RUnlock()
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()

	routes := make([]RouteInfo, 0, len(f.routesByPeer))
	for peerKey, route := range f.routesByPeer {
		if route == nil {
			continue
		}
		stats := f.routeQueueStatsLocked(route)
		hasReturnPath := route.returnPath != nil
		returnPathClosed := hasReturnPath && route.returnPath.Closed()
		// HasPressure means DEGRADED NOW, not "degraded at some point since
		// this route was created" (issue #424 round 6, finding 3).
		//
		// Occupancy and OldestWriteMS are already current-state readings: they
		// describe the queue as it is right now and fall back on their own
		// when a drain or a completed write clears them. The three failure
		// counters are NOT: queueFullDrops, WriteErrors and WriteStalls are
		// monotonic for the lifetime of the route and production never resets
		// them anywhere, so "> 0" meant "this route has ever had a problem".
		// One historical drop therefore kept the route in the CURRENT
		// problem-routes list until the sessionRoute was destroyed, which
		// contradicted the principle round 2 established at the aggregate
		// level.
		//
		// They are therefore read through their per-route recency window
		// (route_pressure.go): a nonzero RECENT delta is a live incident, and
		// a route whose traffic went quiet goes quiet here too, so a route
		// with no traffic cannot accumulate pressure it never had. The
		// lifetime values remain on the payload as history; they simply no
		// longer decide.
		hasPressure := (stats.Capacity > 0 && stats.Occupancy >= stats.Capacity*8/10) ||
			stats.OldestWriteMS >= 100 ||
			stats.QueueFullDropsRecent > 0 ||
			stats.WriteErrorsRecent > 0 ||
			stats.WriteStallsRecent > 0

		routes = append(routes, RouteInfo{
			PeerKey:          peerKey,
			AssignedIP:       route.assignedIP,
			SessionID:        route.sessionID,
			ConnectionID:     route.connectionID,
			BackendTunnelID:  route.backendTunnelID,
			HasReturnPath:    hasReturnPath,
			ReturnPathClosed: returnPathClosed,
			Stats:            stats,
			HasPressure:      hasPressure,
		})
	}
	return routes
}

// ProblemRoutes returns active routes ranked problem-first (highest drops, highest queue occupancy, write stalls).
// Only routes with active pressure (HasPressure == true) are returned. If no routes have pressure,
// an empty slice is returned.
func (f *Forwarder) ProblemRoutes(limit int) []RouteInfo {
	allRoutes := f.InspectRoutes()
	routes := make([]RouteInfo, 0, len(allRoutes))
	for _, r := range allRoutes {
		if r.HasPressure {
			routes = append(routes, r)
		}
	}
	if len(routes) == 0 {
		return []RouteInfo{}
	}

	// Problem-first sort
	sort.Slice(routes, func(i, j int) bool {
		rA := routes[i]
		rB := routes[j]

		// 1. Any drops?
		if (rA.Stats.QueueFullDrops > 0) != (rB.Stats.QueueFullDrops > 0) {
			return rA.Stats.QueueFullDrops > 0
		}
		if rA.Stats.QueueFullDrops != rB.Stats.QueueFullDrops {
			return rA.Stats.QueueFullDrops > rB.Stats.QueueFullDrops
		}

		// 2. High occupancy ratio
		utilA := float64(0)
		if rA.Stats.Capacity > 0 {
			utilA = float64(rA.Stats.Occupancy) / float64(rA.Stats.Capacity)
		}
		utilB := float64(0)
		if rB.Stats.Capacity > 0 {
			utilB = float64(rB.Stats.Occupancy) / float64(rB.Stats.Capacity)
		}
		if math.Abs(utilA-utilB) > 0.05 {
			return utilA > utilB
		}

		// 3. Write errors or stalls
		if (rA.Stats.WriteErrors > 0) != (rB.Stats.WriteErrors > 0) {
			return rA.Stats.WriteErrors > 0
		}
		if (rA.Stats.WriteStalls > 0) != (rB.Stats.WriteStalls > 0) {
			return rA.Stats.WriteStalls > 0
		}
		if rA.Stats.OldestWriteMS != rB.Stats.OldestWriteMS {
			return rA.Stats.OldestWriteMS > rB.Stats.OldestWriteMS
		}
		if rA.Stats.MaxWriteDurationMS != rB.Stats.MaxWriteDurationMS {
			return rA.Stats.MaxWriteDurationMS > rB.Stats.MaxWriteDurationMS
		}

		// 4. Stable tie-breaker
		return rA.PeerKey < rB.PeerKey
	})

	if limit > 0 && len(routes) > limit {
		return routes[:limit]
	}
	return routes
}
