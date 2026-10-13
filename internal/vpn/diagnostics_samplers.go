package vpn

import (
	"sync"
	"time"
)

// diagRatesTracker provides thread-safe sampling and independent rate computation
// for device write errors, client drops, return drops, and overall dataplane drops.
//
// Its baseline bookkeeping delegates to the ONE reusable generation-aware
// window primitive (generationWindow, issue #429 review blocker 1): within a
// generation an accepted baseline is monotonic — a stale LOWER observation
// reports zero deltas and never replaces the baseline — and a lifecycle reset
// re-primes instead of inferring a restart from counters that moved backwards.
type diagRatesTracker struct {
	mu sync.Mutex
	// window is generation-aware; priming semantics are unchanged (issue
	// #424 round 8, finding 2): the first sample captures lastSampleTime AND
	// every counter baseline and reports zero rates. primed stays a tracker
	// field on purpose — the round-8 audit pins an unprimed constructor via
	// tk.primed, and it must never be derived from lastSampleTime being zero.
	// The generation travels with the observation (issue #429 review round
	// 4, blocker 1): Sample takes it explicitly instead of reading a
	// tracker-current field, so a snapshot captured before a lifecycle reset
	// can never be sampled against the new generation.
	gen            diagGeneration
	primed         bool
	window         generationWindow[float64]
	lastSampleTime time.Time

	clientDropRate float64
	returnDropRate float64
	totalDropRate  float64
	writeErrorRate float64

	reasonRates    map[string]float64
	ratesAvailable bool
}

// newDiagRatesTracker returns an UNPRIMED tracker. lastSampleTime and every
// counter baseline are captured by the first Sample call, so a counter that has
// been accumulating since process start is never reported as a fresh incident
// (issue #424 round 8, finding 2). Seeding the timestamp here would make the
// priming branch in Sample dead code.
func newDiagRatesTracker() *diagRatesTracker {
	return &diagRatesTracker{}
}

// SampleWithAcceptance records the cumulative drop counters, reports the per-second
// rates of the newly accepted window, and reports whether the observation was accepted
// (issue #457 Rework Round 7). Callers use acceptance to publish aggregate and reason
// loss rates coherently.
func (t *diagRatesTracker) SampleWithAcceptance(gen diagGeneration, now time.Time, clientDrops, returnDrops, totalDrops, writeErrors uint64) (clientDropRate, returnDropRate, totalDropRate, writeErrorRate float64, accepted bool) {
	if t == nil {
		return 0, 0, 0, 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// R7-H2: Old-generation observations are strict no-ops.
	// Do NOT mutate wrapper priming, timestamp, or published rates.
	if gen < t.gen {
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, false
	}

	if t.primed && t.reasonRates != nil {
		// Tracker is established for whole-vector sampling; alternating vector
		// widths must not silently re-prime an established accepted vector.
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, false
	}

	if gen > t.gen || !t.primed {
		// First sample: prime time AND every counter baseline, report zero.
		t.gen = gen
		t.primed = true
		t.lastSampleTime = now
		t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate = 0, 0, 0, 0
		t.window.reset(gen)
		t.window.sample(gen, now, []uint64{clientDrops, returnDrops, totalDrops, writeErrors})
		return 0, 0, 0, 0, false
	}
	if accepted := t.window.sample(gen, now, []uint64{clientDrops, returnDrops, totalDrops, writeErrors}); !accepted {
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, false
	}
	deltas, elapsed, _ := t.window.last()

	t.clientDropRate = deltas[0] / elapsed
	t.returnDropRate = deltas[1] / elapsed
	// deltas[2] is the TotalDrops counter (issue #429 review round 4,
	// blocker 2): the total rate must come from the total counter, not the
	// client+return sum — the direction-neutral backend_device_unattributed
	// bucket is in TotalDrops but in neither directional total, so the sum
	// under-reported the conserved total.
	t.totalDropRate = deltas[2] / elapsed
	// deltas[3] is the writeErrors counter.
	t.writeErrorRate = deltas[3] / elapsed
	t.lastSampleTime = now

	return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, true
}

func (t *diagRatesTracker) publishRetainedLocked(drops *DropCategoryBreakdown) {
	drops.ClientDropRatePps = t.clientDropRate
	drops.ReturnDropRatePps = t.returnDropRate
	drops.TotalDropRatePps = t.totalDropRate
	drops.ReasonRates = cloneReasonRates(t.reasonRates)
	drops.RatesAvailable = t.ratesAvailable
}

// SampleLossVector records the complete loss-counter vector (aggregates and disjoint reasons),
// reports rates computed from the single accepted window, and preserves all parts of the last
// accepted publication together on rejection (issue #457 Rework Round 8, Round 9).
func (t *diagRatesTracker) SampleLossVector(gen diagGeneration, now time.Time, drops *DropCategoryBreakdown, writeErrors uint64) (writeErrorRate float64, accepted bool) {
	if t == nil || drops == nil {
		return 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if gen < t.gen {
		t.publishRetainedLocked(drops)
		return t.writeErrorRate, false
	}

	// Use the existing whole-vector window, not a second acceptance engine.
	totals := dropReasonTotals(*drops)
	values := make([]uint64, 4+len(knownDropReasonKeys))
	values[0], values[1], values[2], values[3] = drops.ClientTotalDrops, drops.ReturnTotalDrops, drops.TotalDrops, writeErrors
	for i, key := range knownDropReasonKeys {
		values[4+i] = totals[key]
	}
	if gen > t.gen || !t.primed || t.reasonRates == nil {
		t.gen, t.primed, t.lastSampleTime = gen, true, now
		t.window.reset(gen)
		t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate = 0, 0, 0, 0
		t.reasonRates = make(map[string]float64, len(totals))
		t.ratesAvailable = false
	}
	if !t.window.sample(gen, now, values) {
		t.publishRetainedLocked(drops)
		return t.writeErrorRate, false
	}

	deltas, elapsed, _ := t.window.last()
	t.lastSampleTime = now
	t.clientDropRate, t.returnDropRate = deltas[0]/elapsed, deltas[1]/elapsed
	t.totalDropRate, t.writeErrorRate = deltas[2]/elapsed, deltas[3]/elapsed
	rates := make(map[string]float64, len(totals))
	for i, key := range knownDropReasonKeys {
		rates[key] = deltas[4+i] / elapsed
	}
	t.reasonRates, t.ratesAvailable = rates, true
	t.publishRetainedLocked(drops)
	return t.writeErrorRate, true
}

// Sample records the cumulative drop counters and reports the per-second rates
// of the newly accepted window. The generation travels with the observation
// (issue #429 review round 4, blocker 1): callers pass the generation the
// snapshot was captured under, never a tracker-current value. Only
// observations >= the accepted baseline advance it; an older/lower observation
// reports the previous window and leaves the baseline unchanged (issue #429
// review blocker 1).
func (t *diagRatesTracker) Sample(gen diagGeneration, now time.Time, clientDrops, returnDrops, totalDrops, writeErrors uint64) (clientDropRate, returnDropRate, totalDropRate, writeErrorRate float64) {
	clientDropRate, returnDropRate, totalDropRate, writeErrorRate, _ = t.SampleWithAcceptance(gen, now, clientDrops, returnDrops, totalDrops, writeErrors)
	return
}

// reset re-primes the tracker for a new diagnostics generation: subsequent
// samples are tagged with the generation their snapshot captured, and the
// window re-primes on its next call (issue #429 review blocker 1). A
// generation lower than the accepted one is ignored.
func (t *diagRatesTracker) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if gen < t.gen {
		return
	}
	if gen > t.gen {
		t.gen = gen
	}
	if !t.window.reset(gen) {
		return
	}
	t.primed = false
	t.lastSampleTime = time.Time{}
	t.clientDropRate, t.returnDropRate = 0, 0
	t.totalDropRate, t.writeErrorRate = 0, 0
	t.reasonRates = nil
	t.ratesAvailable = false
}

// diagDeltaTracker measures the increase of a single lifetime counter over
// the last sampling window, so a cumulative failure counter can stay visible as
// history without permanently degrading current health (issue #424 round 2,
// finding 5).
//
// Its baseline bookkeeping delegates to the ONE reusable generation-aware
// window primitive (generationWindow, issue #429 review blocker 1): within a
// generation the accepted baseline is monotonic — a stale LOWER observation
// reports zero and never rewinds the baseline — and Reset re-primes on an
// explicit new generation instead of inferring a restart from current<previous.
type diagDeltaTracker struct {
	mu sync.Mutex
	// window owns its own locking; mu guards only the WRAPPER state below
	// (the published snapshot), which Sample reads and reset clears
	// without any other synchronization (issue #429 review round 3,
	// blocker 1 — the "each has its own mutex" claim was false for the
	// wrapper fields). The generation travels with the observation (issue
	// #429 review round 4, blocker 1): Sample takes it explicitly instead
	// of reading a tracker-current field.
	window        generationWindow[uint64]
	delta         uint64
	windowSeconds float64
}

// deltaSnapshot is an immutable read of the tracker's last computed delta.
type deltaSnapshot struct {
	delta         uint64
	windowSeconds float64
}

// Sample records cumulative and returns the increase since the previous
// accepted sample. The generation travels with the observation (issue #429
// review round 4, blocker 1): callers pass the generation the snapshot was
// captured under, never a tracker-current value. The first sample only primes
// the baseline and reports zero, so a counter that has been rising since
// process start is never reported as a fresh incident. Resampling sooner than
// 200ms reuses the previous delta rather than dividing by a near-zero window.
// A stale LOWER observation reports no new loss AND leaves the accepted
// baseline unchanged, so later activity up to the previously accepted value
// can never be replayed as a fresh delta (issue #429 review blocker 1).
func (t *diagDeltaTracker) Sample(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	snap, _ := t.sample(gen, now, cumulative)
	return snap
}

func (t *diagDeltaTracker) sample(gen diagGeneration, now time.Time, cumulative uint64) (deltaSnapshot, bool) {
	if t == nil {
		return deltaSnapshot{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if accepted := t.window.sample(gen, now, []uint64{cumulative}); !accepted {
		return deltaSnapshot{delta: t.delta, windowSeconds: t.windowSeconds}, false
	}
	deltas, elapsed, _ := t.window.last()
	t.delta = deltas[0]
	t.windowSeconds = elapsed
	return deltaSnapshot{delta: t.delta, windowSeconds: t.windowSeconds}, true
}

// reset re-primes the tracker for a new diagnostics generation: subsequent
// samples are tagged with the generation their snapshot captured, and the
// window re-primes on its next call (issue #429 review blocker 1). A
// generation lower than the accepted one is ignored.
func (t *diagDeltaTracker) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.reset(gen) {
		return
	}
	t.delta = 0
	t.windowSeconds = 0
}

// returnOwnershipSnapshot is an immutable atomic read of the return-direction
// ownership mismatch delta, sampling window, and consecutive high-rate streak
// (issue #457).
type returnOwnershipSnapshot struct {
	deltaSnapshot
	consecutiveHighRateWindows int
}

// returnOwnershipTracker tracks return-direction ownership mismatch drops across
// sampling windows and maintains generation-scoped persistence for sustained
// high-rate detection. A single mutex synchronizes generation gates, window
// baseline tracking, and streak counting to eliminate split-lock races (issue #457).
type returnOwnershipTracker struct {
	mu                     sync.Mutex
	gen                    diagGeneration
	primed                 bool
	window                 generationWindow[uint64]
	delta                  uint64
	windowSeconds          float64
	consecutiveHighWindows int
}

// Sample records cumulative and returns the coherent delta, window length, and
// consecutive high-rate window streak. If the sample belongs to an older generation,
// it is rejected wholesale without mutating baseline, window, or streak.
// Resampling sooner than 200ms returns the previous accepted snapshot.
func (t *returnOwnershipTracker) Sample(gen diagGeneration, now time.Time, cumulative uint64) returnOwnershipSnapshot {
	if t == nil {
		return returnOwnershipSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// If sample is from a stale generation, reject it: leave baseline, window,
	// and streak completely untouched and return current published snapshot.
	if gen < t.gen {
		return returnOwnershipSnapshot{
			deltaSnapshot: deltaSnapshot{
				delta:         t.delta,
				windowSeconds: t.windowSeconds,
			},
			consecutiveHighRateWindows: t.consecutiveHighWindows,
		}
	}

	// If advancing to a newer generation or not yet primed: re-prime into gen.
	if gen > t.gen || !t.primed {
		t.gen = gen
		t.primed = true
		t.delta = 0
		t.windowSeconds = 0
		t.consecutiveHighWindows = 0
		// Re-prime the baseline; window.sample always returns false on re-prime.
		t.window.sample(gen, now, []uint64{cumulative})
		return returnOwnershipSnapshot{}
	}

	accepted := t.window.sample(gen, now, []uint64{cumulative})
	if accepted {
		deltas, elapsed, _ := t.window.last()
		t.delta = deltas[0]
		t.windowSeconds = elapsed

		th := defaultHealthThresholds()
		var rate float64
		if t.windowSeconds > 0 {
			rate = float64(t.delta) / t.windowSeconds
		}
		if rate >= th.ReturnOwnershipMismatchDegradedRatePPS {
			t.consecutiveHighWindows++
		} else {
			t.consecutiveHighWindows = 0
		}
	}
	// A throttled (<200ms) or monotonic-stale rejected sample leaves
	// delta, windowSeconds, and consecutiveHighRateWindows untouched.
	return returnOwnershipSnapshot{
		deltaSnapshot: deltaSnapshot{
			delta:         t.delta,
			windowSeconds: t.windowSeconds,
		},
		consecutiveHighRateWindows: t.consecutiveHighWindows,
	}
}

// reset re-primes the tracker for a new diagnostics generation.
// A generation lower than the accepted one is ignored (no-op, leaving published
// delta and consecutive streak untouched).
func (t *returnOwnershipTracker) reset(gen diagGeneration) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.reset(gen) {
		return false
	}
	t.gen = gen
	t.primed = false
	t.delta = 0
	t.windowSeconds = 0
	t.consecutiveHighWindows = 0
	return true
}

func (t *returnOwnershipTracker) consecutiveHighRateWindows() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.consecutiveHighWindows
}

// diagDeltaTrackers groups the per-counter windowed delta trackers. Each has
// its own mutex (both the wrapper state and the embedded window are
// synchronized), so a caller needs no outer lock.
type diagDeltaTrackers struct {
	ownershipMismatch returnOwnershipTracker
	// clientOwnershipMismatch tracks the CLIENT-direction counterpart. It is a
	// separate tracker, not a second field on the return one, because the two
	// counters rise independently: sharing a tracker would let a burst in one
	// direction mask a quiet window in the other, which is the invisibility
	// blocker 3 exists to remove (issue #424 review round 9).
	clientOwnershipMismatch diagDeltaTracker
	syncFailures            diagDeltaTracker
	enqueueFailures         diagDeltaTracker
	writeStalls             diagDeltaTracker
}

func (t *diagDeltaTrackers) sampleOwnershipMismatch(gen diagGeneration, now time.Time, cumulative uint64) returnOwnershipSnapshot {
	if t == nil {
		return returnOwnershipSnapshot{}
	}
	return t.ownershipMismatch.Sample(gen, now, cumulative)
}

func (t *diagDeltaTrackers) consecutiveHighRateWindows() int {
	if t == nil {
		return 0
	}
	return t.ownershipMismatch.consecutiveHighRateWindows()
}

func (t *diagDeltaTrackers) sampleClientOwnershipMismatch(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	return t.clientOwnershipMismatch.Sample(gen, now, cumulative)
}

func (t *diagDeltaTrackers) sampleSyncFailures(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	return t.syncFailures.Sample(gen, now, cumulative)
}

func (t *diagDeltaTrackers) sampleEnqueueFailures(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	return t.enqueueFailures.Sample(gen, now, cumulative)
}

// reset re-primes every sub-tracker — ownership mismatch (both directions),
// peer-sync failures, enqueue failures, and write stalls — for a new
// diagnostics generation (issue #429 review blocker 1).
func (t *diagDeltaTrackers) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.ownershipMismatch.reset(gen)
	t.clientOwnershipMismatch.reset(gen)
	t.syncFailures.reset(gen)
	t.enqueueFailures.reset(gen)
	t.writeStalls.reset(gen)
}
