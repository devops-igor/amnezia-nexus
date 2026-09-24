package forwarder

import (
	"log"
	"time"
)

// Retirement joins writes admitted by a retired route generation. Its zero
// value is safe. Wait must be called only after releasing all caller locks.
type Retirement struct {
	route *sessionRoute
}

// Wait completes retirement; no write from this generation can begin afterward.
func (r Retirement) Wait() { r.route.waitForWrite() }

// DeviceWriteStallThreshold defines a slow client-device write. Stalls count
// each write once, including writes still blocked when telemetry is queried.
const DeviceWriteStallThreshold = 100 * time.Millisecond

// DeviceWriteTelemetry includes admitted writes, completed outcomes, and live
// stall diagnostics. Count includes in-flight writes; durations cover completed
// writes. OldestInFlight is the age of the oldest admitted, unfinished write.
type DeviceWriteTelemetry struct {
	Count          uint64
	Errors         uint64
	Stalls         uint64
	InFlight       int
	OldestInFlight time.Duration
	TotalDuration  time.Duration
	MaxDuration    time.Duration
}

// DeviceWriteSnapshot also includes retired routes whose writes have not yet
// returned, so a stalled teardown cannot disappear from operational telemetry.
func (f *Forwarder) DeviceWriteSnapshot() DeviceWriteTelemetry {
	f.writeMetricsMu.Lock()
	defer f.writeMetricsMu.Unlock()
	stats := f.writeMetrics
	stats.InFlight = len(f.writesInFlight)
	for _, started := range f.writesInFlight {
		age := time.Since(started)
		if age > stats.OldestInFlight {
			stats.OldestInFlight = age
		}
		if age >= DeviceWriteStallThreshold {
			stats.Stalls++
		}
	}
	return stats
}

// waitForWrite completes retirement after any admitted write returns. Callers
// MUST release f.mu first: a stuck device must not block unrelated routes.
func (route *sessionRoute) waitForWrite() {
	if route != nil {
		route.writeMu.Lock()
		route.writeMu.Unlock() //nolint:staticcheck // The empty critical section joins any admitted write before retirement returns.
	}
}

// writeClientPacket serializes admission with retirement completion. A pump
// that selected a device before retirement but reaches admission afterward is
// rejected. If retirement races an admitted write, retirement waits outside
// f.mu; once it returns, this generation can no longer call dev.Write.
func (f *Forwarder) writeClientPacket(route *sessionRoute, dev PacketDevice, packet []byte) {
	route.writeMu.Lock()
	defer route.writeMu.Unlock()
	if route.retired.Load() {
		return
	}
	started := time.Now()
	f.writeMetricsMu.Lock()
	f.writeMetrics.Count++
	route.writeMetrics.Count++
	f.writesInFlight[route] = started
	f.writeMetricsMu.Unlock()

	_, err := dev.Write(packet)
	duration := time.Since(started)
	f.writeMetricsMu.Lock()
	delete(f.writesInFlight, route)
	f.writeMetrics.TotalDuration += duration
	route.writeMetrics.TotalDuration += duration
	if duration > route.writeMetrics.MaxDuration {
		route.writeMetrics.MaxDuration = duration
	}
	if duration > f.writeMetrics.MaxDuration {
		f.writeMetrics.MaxDuration = duration
	}
	if duration >= DeviceWriteStallThreshold {
		f.writeMetrics.Stalls++
		route.writeMetrics.Stalls++
	}
	if err != nil {
		f.writeMetrics.Errors++
		route.writeMetrics.Errors++
	}
	f.writeMetricsMu.Unlock()
	if err != nil {
		now := time.Now().Unix()
		if f.writeErrLogUntil.Load() <= now {
			f.writeErrLogUntil.Store(now + 1)
			log.Printf("[vpn/forwarder] return-path device write error (throttled 1/s): peer=%s session=%s: %v",
				route.peerKey, route.sessionID, err)
		}
	}
}

// routeQueueStatsLocked attributes queue loss and write stalls to the same
// route generation. The caller holds f.mu and aggregateQueueMu.
func (f *Forwarder) routeQueueStatsLocked(route *sessionRoute) RouteQueueStats {
	f.writeMetricsMu.Lock()
	defer f.writeMetricsMu.Unlock()
	writes := route.writeMetrics
	if started, ok := f.writesInFlight[route]; ok {
		writes.InFlight = 1
		writes.OldestInFlight = time.Since(started)
		if writes.OldestInFlight >= DeviceWriteStallThreshold {
			writes.Stalls++
		}
	}
	return RouteQueueStats{
		Occupancy:          len(route.clientQueue),
		Capacity:           cap(route.clientQueue),
		HighWater:          int(route.queueHighWater.Load()), // #nosec G115 -- bounded by channel capacity.
		QueueFullDrops:     route.queueFullDrops.Load(),
		WriteCount:         writes.Count,
		WriteErrors:        writes.Errors,
		WriteStalls:        writes.Stalls,
		WritesInFlight:     writes.InFlight,
		OldestWriteMS:      writes.OldestInFlight.Milliseconds(),
		MaxWriteDurationMS: writes.MaxDuration.Milliseconds(),
	}
}

// reconcileQueueOccupancyLocked updates aggregate occupancy in O(1). Managed
// enqueue/dequeue/drain operations call it under aggregateQueueMu. Reading the
// channel length also reconciles legacy direct drains of this route; aggregate
// snapshots reconcile all such compatibility handles outside the packet path.
func (f *Forwarder) reconcileQueueOccupancyLocked(route *sessionRoute) {
	occupancy := len(route.clientQueue)
	f.aggregateQueueOccupancy += occupancy - route.queueOccupancy
	route.queueOccupancy = occupancy
}
