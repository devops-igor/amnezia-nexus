package forwarder

import "sort"

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
		hasPressure := (stats.Capacity > 0 && routeUtilization(stats) >= 0.8) ||
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
