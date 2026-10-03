package forwarder

import (
	"context"
	"errors"
	"log"
	"sort"
	"time"
)

// ErrRetirementTimeout is returned when waiting for in-flight writes to complete exceeds the deadline.
var ErrRetirementTimeout = errors.New("forwarder: retirement wait timed out joining in-flight writes")

// Retirement joins writes admitted by a retired route generation. Its zero
// value is safe. Wait or WaitContext must be called only after releasing all caller locks.
type Retirement struct {
	route *sessionRoute
}

// WaitContext waits for admitted writes of this route generation to complete,
// or until ctx is done.
func (r Retirement) WaitContext(ctx context.Context) error {
	if r.route == nil {
		return nil
	}
	return r.route.waitForWriteContext(ctx)
}

// Wait completes retirement; no write from this generation can begin afterward.
func (r Retirement) Wait() {
	_ = r.WaitContext(context.Background())
}

// DeviceWriteStallThreshold defines a slow client-device write. Stalls count
// each write once, including writes still blocked when telemetry is queried.
const DeviceWriteStallThreshold = 100 * time.Millisecond

const latencyReservoirSize = 1024

// latencyHealthWindow bounds how far back a forward-write duration may be and
// still count toward CURRENT health (issue #424 round 8, finding 4).
//
// The reservoir below never forgets: it keeps the last 1024 durations with no
// expiry, so on a low-volume or idle server a single burst of slow writes kept
// p95 above the threshold until 1024 new writes displaced them, which is
// arbitrarily long. Health now reads a time-bounded slice instead. The reservoir
// itself remains as descriptive telemetry, so operators keep the historical
// percentiles.
const latencyHealthWindow = 60 * time.Second

type latencyReservoir struct {
	samples [latencyReservoirSize]time.Duration
	stamps  [latencyReservoirSize]time.Time
	head    int
	count   int
}

func (r *latencyReservoir) record(d time.Duration) {
	r.recordAt(d, time.Now())
}

func (r *latencyReservoir) recordAt(d time.Duration, at time.Time) {
	r.samples[r.head] = d
	r.stamps[r.head] = at
	r.head = (r.head + 1) % latencyReservoirSize
	if r.count < latencyReservoirSize {
		r.count++
	}
}

func (r *latencyReservoir) percentiles() (p50, p95, p99 time.Duration) {
	n := r.count
	if n == 0 {
		return 0, 0, 0
	}
	buf := make([]time.Duration, n)
	copy(buf, r.samples[:n])
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	p50 = buf[n*50/100]
	p95 = buf[n*95/100]
	p99 = buf[n*99/100]
	return p50, p95, p99
}

// healthP95 returns the p95 over the samples recorded within latencyHealthWindow
// of now, plus how many samples that slice contains. A zero sample count means
// nothing recent was observed, and the caller must then treat latency as
// UNKNOWN rather than BAD: an idle server has no recent evidence of slowness and
// must not be held DEGRADED on history (issue #424 round 8, finding 4).
func (r *latencyReservoir) healthP95(now time.Time) (time.Duration, int) {
	n := r.count
	if n == 0 {
		return 0, 0
	}
	cutoff := now.Add(-latencyHealthWindow)
	buf := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		if r.stamps[i].Before(cutoff) {
			continue
		}
		buf = append(buf, r.samples[i])
	}
	if len(buf) == 0 {
		return 0, 0
	}
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	return buf[len(buf)*95/100], len(buf)
}

type routeLatencyReservoir struct {
	samples [128]time.Duration
	head    int
	count   int
}

func (r *routeLatencyReservoir) record(d time.Duration) {
	r.samples[r.head] = d
	r.head = (r.head + 1) % 128
	if r.count < 128 {
		r.count++
	}
}

func (r *routeLatencyReservoir) p95() time.Duration {
	n := r.count
	if n == 0 {
		return 0
	}
	buf := make([]time.Duration, n)
	copy(buf, r.samples[:n])
	sort.Slice(buf, func(i, j int) bool { return buf[i] < buf[j] })
	return buf[n*95/100]
}

// DeviceWriteTelemetry includes admitted writes, completed outcomes, and live
// stall diagnostics. Count includes in-flight writes; durations cover completed
// writes. OldestInFlight is the age of the oldest admitted, unfinished write.
//
// P50Duration/P95Duration/P99Duration are DESCRIPTIVE: they describe the last
// latencyReservoirSize completed writes and deliberately never expire.
// P95HealthDuration/P95HealthSamples are the CURRENT-health view: the p95 over
// writes completed within latencyHealthWindow, and how many writes that window
// holds. P95HealthSamples == 0 means no recent write was observed, so latency is
// UNKNOWN and must not gate health (issue #424 round 8, finding 4).
type DeviceWriteTelemetry struct {
	Count          uint64
	Errors         uint64
	Stalls         uint64
	InFlight       int
	OldestInFlight time.Duration
	TotalDuration  time.Duration
	MaxDuration    time.Duration
	P50Duration    time.Duration
	P95Duration    time.Duration
	P99Duration    time.Duration

	P95HealthDuration time.Duration
	P95HealthSamples  int
	HealthWindow      time.Duration
}

// DeviceWriteSnapshot also includes retired routes whose writes have not yet
// returned, so a stalled teardown cannot disappear from operational telemetry.
func (f *Forwarder) DeviceWriteSnapshot() DeviceWriteTelemetry {
	f.writeMetricsMu.Lock()
	defer f.writeMetricsMu.Unlock()
	stats := f.writeMetrics
	now := time.Now()
	stats.P50Duration, stats.P95Duration, stats.P99Duration = f.writeLatencies.percentiles()
	stats.P95HealthDuration, stats.P95HealthSamples = f.writeLatencies.healthP95(now)
	stats.HealthWindow = latencyHealthWindow
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

// waitForWriteContext completes retirement after any admitted write returns,
// or when ctx expires. Callers MUST release f.mu first: a stuck device must not
// block unrelated routes.
func (route *sessionRoute) waitForWriteContext(ctx context.Context) error {
	if route == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ErrRetirementTimeout
	}
	done := make(chan struct{})
	go func() {
		route.writeMu.Lock()
		route.writeMu.Unlock() //nolint:staticcheck // The empty critical section joins any admitted write before retirement returns.
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ErrRetirementTimeout
	}
}

// writeClientPacket serializes admission with retirement completion. A pump
// that selected a device before retirement but reaches admission afterward is
// rejected. If retirement races an admitted write, retirement waits outside
// f.mu; once it returns, this generation can no longer call dev.Write.
func (f *Forwarder) writeClientPacket(route *sessionRoute, dev packetWriter, packet []byte) {
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
	f.writeLatencies.record(duration)
	f.writeHistogram.observe(duration)
	route.writeLatencies.record(duration)
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
	p95 := route.writeLatencies.p95()
	// Sample the per-route recency window AFTER the in-flight stall adjustment
	// above, so a write that is stalled RIGHT NOW shows up as recent pressure
	// and not only as a lifetime total (issue #424 round 6, finding 3).
	recent := route.pressure.sample(time.Now(), route.queueFullDrops.Load(), writes.Errors, writes.Stalls)
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
		P95WriteMS:         p95.Milliseconds(),
		P95WriteSamples:    route.writeLatencies.count,

		QueueFullDropsRecent: recent.QueueFullDropsRecent,
		WriteErrorsRecent:    recent.WriteErrorsRecent,
		WriteStallsRecent:    recent.WriteStallsRecent,
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
	f.queueDwell.observe(time.Now(), f.aggregateQueueOccupancy, f.aggregateQueueCapacity)
}
