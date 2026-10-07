package vpn

import (
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// diagGeneration identifies the lifetime incarnation of the dataplane the
// diagnostics trackers sample (issue #429 review blocker 1). It advances ONLY
// when Service.Start explicitly starts a new generation after Stop; within one
// generation the accepted baselines of cumulative counters are monotonic: a
// stale, lower or out-of-order observation may report no new delta, but it
// must never replace the accepted baseline.
type diagGeneration = forwarder.Generation

// diagEpochSampleFloor is the minimum spacing between two accepted samples of
// one cumulative diagnostics window. It preserves the 200ms throttle the
// trackers already used: a single diagnostics collection reads some counters
// more than once, and inside the floor the previous window must stay intact
// so the second read cannot swallow the incident.
const diagEpochSampleFloor = forwarder.GenerationSampleMinInterval

// generationWindow is ONE reusable generation-aware cumulative window over a
// fixed set of counters (issue #429 review blocker 1):
//   - a sample tagged with a generation older than the accepted one is stale
//     (an in-flight read crossing a lifecycle reset): it is ignored entirely;
//   - the first sample of a generation only primes the baseline and reports
//     no accepted window;
//   - a sample inside diagEpochSampleFloor of the accepted one leaves the
//     window untouched, so repeated reads within one collection agree;
//   - within one generation, the sampler enforces whole-vector monotonicity
//     (issue #429 review round 7): if ANY counter observation is lower than
//     its accepted baseline, the entire observation is rejected wholesale
//     (accepted=false and NOTHING is mutated — baselines, timestamp, or
//     deltas); only observations where ALL counters are >= baseline advance
//     the window;
//   - Reset(gen) explicitly starts a new generation, clearing the baseline so
//     the next sample re-primes into it.
type generationWindow[N numericDelta] struct {
	mu       sync.Mutex
	gen      diagGeneration
	primed   bool
	at       time.Time
	baseline []uint64
	delta    []N
	window   float64
}

// numericDelta is satisfied by every windowed output this package needs
// today (float64 rates, uint64 deltas); the primitive stays reusable without
// duplicating its reset/order semantics per tracker.
type numericDelta interface {
	~float64 | ~uint64
}

// sample applies the generation gate, the throttle floor and the
// whole-vector monotonic-baseline rule to one cumulative observation.
// accepted reports whether this observation opened a new measurement window.
//
// Staleness contract (issue #429 review round 3 blocker 2, round 7):
//   - whole-vector monotonicity: classification happens BEFORE any mutation.
//     If ANY counter in values is lower than its accepted baseline
//     (value < w.baseline[i]), the observation is rejected wholesale:
//     accepted=false and NOTHING is mutated — not the accepted baselines,
//     not the published deltas, not the accepted sampling timestamp (at),
//     and not the published window. A stale read therefore cannot corrupt
//     the denominator of the next valid window, and callers keep the previous
//     accepted snapshot unchanged;
//   - an observation where all counters equal their baselines (idle period)
//     is accepted after the sample floor (elapsed >= diagEpochSampleFloor),
//     producing zero deltas so idle rates legitimately drop to 0;
//   - an observation where some counters advance and the remainder are equal
//     is accepted normally: advancing counters move their baselines and deltas,
//     equal counters report zero deltas, and the shared timestamp advances.
func (w *generationWindow[N]) sample(gen diagGeneration, now time.Time, values []uint64) (accepted bool) {
	if len(values) == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.baseline) != len(values) {
		// Width change: nothing comparable survives — re-prime.
		w.baseline = make([]uint64, len(values))
		w.delta = make([]N, len(values))
		w.primed = false
	}
	if gen < w.gen {
		return false
	}
	if gen > w.gen || !w.primed {
		w.gen = gen
		w.primed = true
		w.at = now
		copy(w.baseline, values)
		for i := range w.delta {
			var zero N
			w.delta[i] = zero
		}
		w.window = 0
		return false
	}
	elapsed := now.Sub(w.at).Seconds()
	if elapsed < diagEpochSampleFloor.Seconds() {
		return false
	}
	// Whole-vector monotonicity (issue #429 review round 7): classify
	// WITHOUT mutating. If ANY counter in values is lower than its accepted
	// baseline, the observation is stale or incoherent and must be rejected
	// wholesale without mutating baselines, timestamp, window, or deltas.
	for i, value := range values {
		if value < w.baseline[i] {
			return false
		}
	}
	// All counters are >= baseline. Compute deltas, advance baselines and clock.
	for i, value := range values {
		w.delta[i] = N(value - w.baseline[i])
		w.baseline[i] = value
	}
	w.window = elapsed
	w.at = now
	return true
}

// reset explicitly starts a new generation: the baseline is cleared so the
// next sample re-primes into it. Older generations are ignored.
func (w *generationWindow[N]) reset(gen diagGeneration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if gen > w.gen {
		w.gen = gen
	}
	w.primed = false
	w.at = time.Time{}
	w.baseline = nil
	w.delta = nil
	w.window = 0
}

// last returns the last computed window: deltas, its length in seconds, and
// whether any window has been accepted at all.
func (w *generationWindow[N]) last() (deltas []N, windowSec float64, primed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.primed || w.window <= 0 || len(w.delta) == 0 {
		return nil, 0, false
	}
	return w.delta, w.window, true
}

// diagCounterWindows is the keyed counter window set used by trackers whose
// counter keys are data-driven (drop reasons).
type diagCounterWindows struct {
	mu      sync.Mutex
	windows map[string]*generationWindow[float64]
	alive   map[string]bool
	at      time.Time
	primed  bool
	gen     diagGeneration
}

func newDiagCounterWindows() *diagCounterWindows {
	return &diagCounterWindows{windows: make(map[string]*generationWindow[float64]), alive: make(map[string]bool)}
}

// sample applies the same generation/throttle/monotonic rules per counter key
// and reports whether any window was accepted this call.
func (d *diagCounterWindows) sample(gen diagGeneration, now time.Time, totals map[string]uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if gen < d.gen {
		return false
	}
	if gen > d.gen || !d.primed {
		d.gen = gen
		d.primed = true
		d.at = now
		for key, total := range totals {
			w, ok := d.windows[key]
			if !ok {
				w = &generationWindow[float64]{}
				d.windows[key] = w
			}
			w.reset(d.gen)
			w.sample(d.gen, now, []uint64{total})
		}
		return false
	}
	elapsed := now.Sub(d.at).Seconds()
	if elapsed < diagEpochSampleFloor.Seconds() {
		return false
	}
	acceptedAny := false
	for key, total := range totals {
		w, ok := d.windows[key]
		if !ok {
			w = &generationWindow[float64]{}
			d.windows[key] = w
		}
		if w.sample(d.gen, now, []uint64{total}) {
			acceptedAny = true
		}
	}
	for key := range d.windows {
		if _, live := totals[key]; !live {
			d.alive[key] = false
		} else {
			d.alive[key] = true
		}
	}
	if acceptedAny {
		d.at = now
	}
	return acceptedAny
}

// rate returns the per-key windowed rates plus the window length; available
// reports whether any accepted window exists in the current generation.
func (d *diagCounterWindows) rate(key string) (float64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.alive[key] {
		return 0, false
	}
	w, ok := d.windows[key]
	if !ok || w == nil {
		return 0, false
	}
	deltas, windowSec, primed := w.last()
	if !primed || len(deltas) != 1 || windowSec <= 0 {
		return 0, false
	}
	return deltas[0] / windowSec, true
}

// reset starts a new generation for the whole keyed set.
func (d *diagCounterWindows) reset(gen diagGeneration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if gen > d.gen {
		d.gen = gen
	}
	d.primed = false
	d.at = time.Time{}
	for _, w := range d.windows {
		w.reset(d.gen)
	}
}
