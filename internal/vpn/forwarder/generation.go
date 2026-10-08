package forwarder

import (
	"sync"
	"time"
)

// Generation identifies the lifetime incarnation of the dataplane component
// that owns a cumulative counter (issue #429 review blocker 1).
//
// A generation advances ONLY when the owning component explicitly starts a new
// one (Service.Start after Stop, Forwarder.Start). Within one generation the
// accepted baselines of cumulative counters are monotonic: a stale, lower or
// out-of-order observation may report no new delta, but it must never replace
// the accepted baseline — otherwise later activity up to the previously
// accepted value is replayed as a fresh delta and can resurface recovered
// incidents as current health findings.
type Generation uint64

// GenerationSampleMinInterval is the minimum spacing between two accepted
// samples of one cumulative window. It matches the 200ms floor the diagnostics
// trackers and routePressureWindow already use: a single diagnostics collection
// reads some counters more than once, and inside the floor the previous window
// must stay intact so the second read cannot swallow the incident.
const GenerationSampleMinInterval = 200 * time.Millisecond

// GenerationSampler is the reusable generation-aware cumulative sampler.
//
// Every cumulative telemetry tracker in the dataplane delegates its baseline
// bookkeeping here so reset and ordering semantics exist exactly once:
//   - a sample tagged with a generation older than the accepted one is stale
//     (an in-flight read crossing a lifecycle reset): it is ignored entirely;
//   - the first sample of a generation (after construction or Reset) only
//     primes the baseline and reports no accepted window;
//   - a sample inside GenerationSampleMinInterval of the accepted one leaves
//     the window untouched, so repeated reads within one collection agree;
//   - within one generation, the sampler enforces whole-vector monotonicity
//     (issue #429 review round 7): if ANY counter observation is lower than
//     its accepted baseline, the entire observation is rejected wholesale
//     (accepted=false and NOTHING is mutated — baseline, anchor or window);
//     only observations where ALL counters are >= baseline advance the window;
//   - Reset(generation) explicitly starts a new generation, clearing the
//     baselines so the next sample re-primes into it.
//
// The zero value is usable and unprimed.
type GenerationSampler struct {
	mu     sync.Mutex
	gen    Generation
	primed bool
	at     time.Time
	values []uint64
}

// NewGenerationSampler returns a sampler tracking the given number of
// cumulative counters. The count may also be left implicit by using the zero
// value; the width is (re-)adopted from the first observation.
func NewGenerationSampler(counters int) *GenerationSampler {
	if counters < 0 {
		counters = 0
	}
	return &GenerationSampler{values: make([]uint64, counters)}
}

// Sample applies the generation gate, the throttle floor and the
// whole-vector monotonic-baseline rule to one cumulative observation of
// len(values) counters.
//
// accepted reports whether this observation opened a new measurement window;
// only then are deltas and elapsed meaningful and the baselines advanced.
// The returned slice is freshly allocated.
//
// Staleness contract (issue #429 review round 4 finding 3, round 7 — same
// documented rule as internal/vpn/generationWindow): classification happens
// BEFORE any mutation. Whole-vector monotonicity is enforced: if ANY counter
// in values is lower than its accepted baseline (value < w.values[i]), the
// observation is rejected wholesale: accepted=false, returning nil, 0, false,
// and NOTHING is mutated — not the baselines, not the accepted sampling
// anchor (at), so the next valid window keeps its true denominator.
// An observation where all counters are equal (idle period) is accepted after
// minInterval yielding zero deltas, and advancing observations (some greater,
// remainder equal) advance baselines and the shared anchor.
func (w *GenerationSampler) Sample(gen Generation, now time.Time, minInterval time.Duration, values []uint64) (deltas []uint64, elapsed float64, accepted bool) {
	if len(values) == 0 {
		return nil, 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.values) != len(values) {
		// Width change: the observation layout differs from the accepted
		// baseline, so nothing comparable survives — re-prime.
		w.values = make([]uint64, len(values))
		w.primed = false
	}

	if gen < w.gen {
		// Stale generation: an in-flight observation crossing a lifecycle
		// reset. It may neither describe nor advance the current baseline.
		return nil, 0, false
	}
	if gen > w.gen || !w.primed {
		// First sample of a new generation: prime only, no window yet.
		w.gen = gen
		w.primed = true
		w.at = now
		copy(w.values, values)
		return nil, 0, false
	}

	elapsed = now.Sub(w.at).Seconds()
	if elapsed < minInterval.Seconds() {
		return nil, 0, false
	}

	// Whole-vector monotonicity (issue #429 review round 7): classify
	// WITHOUT mutating. If ANY counter in values is lower than its accepted
	// baseline, the observation is stale or incoherent and must be rejected
	// wholesale without mutating baselines, anchor, or window.
	for i, value := range values {
		if value < w.values[i] {
			return nil, 0, false
		}
	}

	deltas = make([]uint64, len(values))
	for i, value := range values {
		deltas[i] = value - w.values[i]
		w.values[i] = value
	}
	w.at = now
	return deltas, elapsed, true
}

// SampleCounter is the allocation-free single-counter form of Sample and
// follows the same classify-before-mutation staleness contract (issue #429
// review round 4, finding 3): an observation below the accepted baseline is
// rejected with accepted=false and zero mutation — the baseline, the sampling
// anchor and the window are untouched, so the next valid window keeps its
// true denominator.
func (w *GenerationSampler) SampleCounter(gen Generation, now time.Time, minInterval time.Duration, value uint64) (delta uint64, elapsed float64, accepted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if gen < w.gen {
		return 0, 0, false
	}
	if gen > w.gen || !w.primed || len(w.values) != 1 {
		w.gen = gen
		w.primed = true
		w.at = now
		if len(w.values) != 1 {
			w.values = make([]uint64, 1)
		}
		w.values[0] = value
		return 0, 0, false
	}

	elapsed = now.Sub(w.at).Seconds()
	if elapsed < minInterval.Seconds() {
		return 0, 0, false
	}
	if value < w.values[0] {
		return 0, 0, false
	}
	delta = value - w.values[0]
	w.values[0] = value
	w.at = now
	return delta, elapsed, true
}

// Reset explicitly starts a new generation: baselines are cleared so the next
// sample re-primes into it. A generation lower than the accepted one is
// ignored (generations only move forward).
func (w *GenerationSampler) Reset(gen Generation) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if gen < w.gen {
		return
	}
	if gen > w.gen {
		w.gen = gen
	}
	w.primed = false
	w.at = time.Time{}
	w.values = nil
}

// Baseline reports the accepted baseline of counter i: its value, the time it
// was sampled at, and whether a baseline has been accepted at all.
func (w *GenerationSampler) Baseline(i int) (value uint64, at time.Time, primed bool, gen Generation) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if i < 0 || i >= len(w.values) {
		return 0, time.Time{}, w.primed, w.gen
	}
	return w.values[i], w.at, w.primed, w.gen
}

// counterUint64 converts a signed cumulative byte counter into the unsigned
// domain of the generation-aware samplers, clamping a negative observation to
// 0 (gosec G115, CWE-190): a negative lifetime must never convert to a
// two-complement uint64 burst. Clamped values still compare lower than any
// accepted baseline, so the monotonic-baseline rule keeps reporting a zero
// delta for a counter that moved backwards.
func counterUint64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}
