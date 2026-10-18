package forwarder

import (
	"time"
)

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
	QueueFullDropsRecent uint64  `json:"queue_full_drops_recent"`
	QueueFullDropRatePPS float64 `json:"queue_full_drop_rate_pps,omitempty"`
	WriteErrorsRecent    uint64  `json:"write_errors_recent"`
	WriteStallsRecent    uint64  `json:"write_stalls_recent"`
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
	if f == nil {
		return 0, 0, 0
	}
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

// RawDropStats returns return drop counters for the current forwarder instance.
// Note that drop counters are reset to zero upon Start(), so these values reflect
// drops accumulated since the current Start() epoch rather than whole process lifetime.
func (f *Forwarder) RawDropStats() (queueFull, noRoute, total uint64) {
	if f == nil {
		return 0, 0, 0
	}
	return f.dropsQueueFull.Load(), f.dropsNoRoute.Load(), f.dropsTotal.Load()
}

// RawClientDropStats returns client-to-backend drop counters for the current forwarder instance.
// Note that drop counters are reset to zero upon Start(), so these values reflect
// drops accumulated since the current Start() epoch rather than whole process lifetime.
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

// GetStats returns current aggregated traffic and active route counts.
func (f *Forwarder) GetStats() (rx int64, tx int64, activeRoutes int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rx = f.totalRxBytes.Load()
	tx = f.totalTxBytes.Load()
	activeRoutes = len(f.routesByPeer)
	return
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
