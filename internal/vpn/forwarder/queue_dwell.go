package forwarder

import "time"

// queueDwellTracker measures threshold dwell from serialized queue transitions.
// Forwarder.aggregateQueueMu owns all fields; it adds no locks or goroutines.
type queueDwellTracker struct {
	lastAt           time.Time
	above50, above80 bool
	since50, since80 time.Time
	total50, total80 time.Duration
}

type queueDwellSnapshot struct {
	total50, total80             int64
	consecutive50, consecutive80 int64
}

func (d *queueDwellTracker) observe(now time.Time, occupancy, capacity int) {
	if !d.lastAt.IsZero() {
		elapsed := now.Sub(d.lastAt)
		if elapsed < 0 {
			return
		}
		if d.above50 {
			d.total50 += elapsed
		}
		if d.above80 {
			d.total80 += elapsed
		}
	}
	util := 0.0
	if capacity > 0 {
		util = float64(occupancy) / float64(capacity)
	}
	above50, above80 := capacity > 0 && util >= 0.5, capacity > 0 && util >= 0.8
	if above50 && !d.above50 {
		d.since50 = now
	}
	if above80 && !d.above80 {
		d.since80 = now
	}
	if !above50 {
		d.since50 = time.Time{}
	}
	if !above80 {
		d.since80 = time.Time{}
	}
	d.above50, d.above80 = above50, above80
	d.lastAt = now
}

// reconcile handles legacy channel drains with unknown transition times.
// Discard the unobserved interval rather than inventing an exact drain time.
func (d *queueDwellTracker) reconcile(now time.Time, occupancy, capacity int) {
	d.lastAt = now
	d.above50, d.above80 = false, false
	d.since50, d.since80 = time.Time{}, time.Time{}
	d.observe(now, occupancy, capacity)
}

func (d *queueDwellTracker) snapshot(now time.Time) queueDwellSnapshot {
	result := queueDwellSnapshot{total50: int64(d.total50 / time.Second), total80: int64(d.total80 / time.Second)}
	if d.above50 {
		result.consecutive50 = int64(now.Sub(d.since50) / time.Second)
	}
	if d.above80 {
		result.consecutive80 = int64(now.Sub(d.since80) / time.Second)
	}
	return result
}

// changeQueueCapacityLocked is called under f.mu when a route is added/removed.
func (f *Forwarder) changeQueueCapacityLocked(delta int) {
	f.aggregateQueueMu.Lock()
	defer f.aggregateQueueMu.Unlock()
	f.aggregateQueueCapacity += delta
	f.queueDwell.observe(time.Now(), f.aggregateQueueOccupancy, f.aggregateQueueCapacity)
}

// reconcileBeforeQueueMutationLocked detects drains through a legacy handle
// before accounting a known managed mutation. The caller holds aggregateQueueMu.
func (f *Forwarder) reconcileBeforeQueueMutationLocked(route *sessionRoute) {
	occupancy := len(route.clientQueue)
	if occupancy == route.queueOccupancy {
		return
	}
	f.aggregateQueueOccupancy += occupancy - route.queueOccupancy
	route.queueOccupancy = occupancy
	f.queueDwell.reconcile(time.Now(), f.aggregateQueueOccupancy, f.aggregateQueueCapacity)
}
