package forwarder

import (
	"sort"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
)

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
