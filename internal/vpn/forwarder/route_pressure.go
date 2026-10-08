package forwarder

import (
	"sync"
	"time"
)

// routePressureSampleInterval is the minimum spacing between two accepted
// samples of one route's lifetime counters (issue #424 round 6, finding 3).
//
// It matches the 200ms floor the diagnostics layer already uses for its
// windowed counters (diagDeltaTracker), and it exists for a concrete reason
// rather than as smoothing: a single diagnostics collection reads each route's
// stats MORE THAN ONCE (the routing-invariant pass and the problem-routes pass
// each take a snapshot), so without a floor the first read would consume the
// delta and the second, a few microseconds later, would report zero and hide
// the very incident the collection exists to surface. Inside the floor the
// previous delta is returned unchanged, so both reads of one collection agree.
const routePressureSampleInterval = 200 * time.Millisecond

// routePressureWindow tracks RECENT change in one route's lifetime failure
// counters, so current pressure can be distinguished from history.
//
// The counters themselves (queueFullDrops, writeMetrics.Errors, writeMetrics
// .Stalls) are monotonic for the lifetime of a route and production NEVER
// resets them, so "> 0" on any of them means "this route has ever had a
// problem", not "this route has a problem now". Gating HasPressure on them
// pinned every route that ever dropped a packet into the CURRENT problem-routes
// list until its sessionRoute was destroyed.
//
// The lifetime values stay on the payload, untouched, because an admin still
// needs "this route dropped 4 packets since it was created". Only the
// decision to call a route a problem moved onto these deltas.
type routePressureWindow struct {
	mu           sync.Mutex
	primed       bool
	lastDrops    uint64
	lastErrors   uint64
	lastStalls   uint64
	lastSampleAt time.Time
	dropsDelta   uint64
	errorsDelta  uint64
	stallsDelta  uint64
	dropRatePPS  float64
	elapsedSec   float64
}

// pressureSnapshot is one route's recent-change view of its lifetime counters.
type pressureSnapshot struct {
	QueueFullDropsRecent uint64
	WriteErrorsRecent    uint64
	WriteStallsRecent    uint64
	DropRatePPS          float64
	ElapsedSec           float64
}

// sample records the cumulative counters and returns the increase since the
// previous accepted sample.
//
// Lifecycle, mirroring diagDeltaTracker:
//   - the first sample only primes a baseline and reports zero, so a counter
//     that has been rising since the route was created is never reported as a
//     fresh incident;
//   - a sample inside routePressureSampleInterval of the last accepted one
//     returns the previous delta unchanged, so repeated reads within one
//     collection cannot swallow an incident;
//   - a counter that DECREASED (a route generation replaced under the same
//     peer key) contributes no new loss this window.
func (w *routePressureWindow) sample(now time.Time, drops, writeErrors, writeStalls uint64) pressureSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.primed {
		w.primed = true
		w.lastDrops, w.lastErrors, w.lastStalls = drops, writeErrors, writeStalls
		w.lastSampleAt = now
		w.dropsDelta, w.errorsDelta, w.stallsDelta = 0, 0, 0
		w.dropRatePPS, w.elapsedSec = 0, 0
		return pressureSnapshot{}
	}

	if now.Sub(w.lastSampleAt) < routePressureSampleInterval {
		return pressureSnapshot{
			QueueFullDropsRecent: w.dropsDelta,
			WriteErrorsRecent:    w.errorsDelta,
			WriteStallsRecent:    w.stallsDelta,
			DropRatePPS:          w.dropRatePPS,
			ElapsedSec:           w.elapsedSec,
		}
	}

	elapsedSec := now.Sub(w.lastSampleAt).Seconds()
	if drops >= w.lastDrops {
		w.dropsDelta = drops - w.lastDrops
	} else {
		w.dropsDelta = 0
	}
	if writeErrors >= w.lastErrors {
		w.errorsDelta = writeErrors - w.lastErrors
	} else {
		w.errorsDelta = 0
	}
	if writeStalls >= w.lastStalls {
		w.stallsDelta = writeStalls - w.lastStalls
	} else {
		w.stallsDelta = 0
	}
	w.lastDrops, w.lastErrors, w.lastStalls = drops, writeErrors, writeStalls
	w.lastSampleAt = now

	var dropRate float64
	if w.dropsDelta > 0 && elapsedSec > 0 {
		dropRate = float64(w.dropsDelta) / elapsedSec
	}
	w.dropRatePPS = dropRate
	w.elapsedSec = elapsedSec

	return pressureSnapshot{
		QueueFullDropsRecent: w.dropsDelta,
		WriteErrorsRecent:    w.errorsDelta,
		WriteStallsRecent:    w.stallsDelta,
		DropRatePPS:          dropRate,
		ElapsedSec:           elapsedSec,
	}
}
