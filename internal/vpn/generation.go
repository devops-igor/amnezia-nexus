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
//   - a counter observation lower than its accepted baseline reports a zero
//     delta AND leaves that baseline unchanged; only observations >= the
//     baseline advance it;
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
// monotonic-baseline rule to one cumulative observation. accepted reports
// whether this observation opened a new measurement window.
//
// Staleness contract (issue #429 review round 3, blocker 2):
//   - a counter below its accepted baseline is a stale observation: in an
//     accepted window it contributes no delta (its published delta is zeroed
//     for that window) and leaves its baseline untouched;
//   - an observation in which EVERY counter is below its baseline is rejected
//     wholesale: accepted=false and NOTHING is mutated — not the accepted
//     baselines, not the published deltas, not the accepted sampling
//     timestamp (at) and not the published window. A stale read therefore
//     cannot corrupt the denominator of the next valid window, and callers
//     keep the previous accepted snapshot unchanged;
//   - a PARTIALLY stale observation (some counters >= baseline, some below)
//     is accepted: the advancing counters move their baselines and deltas,
//     the stale counters report a zero delta for this window, and the shared
//     timestamp/window advance because at least one counter genuinely
//     advanced.
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
	// First pass: classify WITHOUT mutating. An observation in which every
	// counter is below its baseline is fully stale and must change nothing
	// (issue #429 review round 3, blocker 2) — zeroing deltas or advancing
	// the anchor here would erase the last accepted window and corrupt the
	// next valid denominator.
	anyAdvanced := false
	for i, value := range values {
		if value >= w.baseline[i] {
			anyAdvanced = true
			break
		}
	}
	if !anyAdvanced {
		return false
	}
	// Second pass: apply the accepted window. Stale counters report a zero
	// delta for this window and keep their baselines; advancing counters
	// move both.
	for i, value := range values {
		var zero N
		if value < w.baseline[i] {
			w.delta[i] = zero
			continue
		}
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
	mu       sync.Mutex
	windows  map[string]*generationWindow[float64]
	alive    map[string]bool
	at       time.Time
	window   float64
	accepted bool
	primed   bool
	gen      diagGeneration
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
		d.window = 0
		d.accepted = false
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
		d.window = elapsed
		d.accepted = true
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
	d.accepted = false
	d.window = 0
	d.at = time.Time{}
	for _, w := range d.windows {
		w.reset(d.gen)
	}
}
