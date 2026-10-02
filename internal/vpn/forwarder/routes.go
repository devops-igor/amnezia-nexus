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
		hasPressure := stats.QueueFullDrops > 0 || (stats.Capacity > 0 && stats.Occupancy >= stats.Capacity*8/10) || stats.WriteErrors > 0 || stats.WriteStalls > 0 || stats.OldestWriteMS >= 100

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
func (f *Forwarder) ProblemRoutes(limit int) []RouteInfo {
	routes := f.InspectRoutes()

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
