package forwarder

import (
	"testing"
	"time"
)

// Issue #424 round 8, finding 3: the tracker used to attribute the WHOLE
// inter-sample interval using only the occupancy observed at the END of it, so
// three momentary 81% readings accumulated ~30s of claimed sustained pressure
// and diagnostics surfaced "stayed above 80% utilization for 30s" (DEGRADED).
//
// The model is now a linear interpolation between the previous and the current
// reading. It can under-count an excursion contained inside one interval but it
// must never over-count one.
func TestRateTracker_SaturationDurationIsNotBackfilledFromEndingSnapshot(t *testing.T) {
	// Brief spike: three samples each just over 80%, spaced 10s apart. The
	// pre-change code credited 10s each, claiming 30s of sustained pressure.
	rt := NewRateTracker()
	t0 := time.Now()

	// Priming sample: baseline only, credits nothing.
	rt.Sample(t0, 0, 0, 0, 0, 0, 0, 10, 1000)

	// Each interval rises from empty to just over 80% only at its end, so the
	// interpolated fraction above the threshold is tiny, not the whole 10s.
	for i := 1; i <= 3; i++ {
		rt.Sample(t0.Add(time.Duration(i)*10*time.Second), 0, 0, 0, 0, 0, 0, 810, 1000)
	}

	p := rt.PressureSnapshot(810, 1000, 810, 0)
	if p.ConsecutiveAbove80Sec >= 30 {
		t.Fatalf("three momentary 81%% readings must not accumulate 30s of claimed sustained pressure, got %ds",
			p.ConsecutiveAbove80Sec)
	}
	if p.ConsecutiveAbove80Sec == 0 {
		t.Fatalf("a real 81%% reading must still register some saturation, got %ds", p.ConsecutiveAbove80Sec)
	}
	if p.SecondsAbove80Pct >= 30 {
		t.Fatalf("total above-80 duration must not be backfilled to 30s, got %ds", p.SecondsAbove80Pct)
	}
}

// The inverse of the brief spike: a queue saturated for most of a long interval
// that drains just before the sample. The pre-change code recorded nothing at
// all because the ENDING reading was below the threshold, so genuine sustained
// saturation was invisible.
func TestRateTracker_SaturatedThenDrainedIsNotForgotten(t *testing.T) {
	rt := NewRateTracker()
	t0 := time.Now()

	rt.Sample(t0, 0, 0, 0, 0, 0, 0, 900, 1000)
	// Saturate: an interval that starts and ends above 80% is credited whole.
	rt.Sample(t0.Add(10*time.Second), 0, 0, 0, 0, 0, 0, 900, 1000)
	p := rt.PressureSnapshot(900, 1000, 900, 0)
	if p.SecondsAbove80Pct < 9 {
		t.Fatalf("an interval observed above 80%% at both ends must be credited, got %ds", p.SecondsAbove80Pct)
	}

	// Now drain: the queue falls from 90% to empty across this interval. The
	// pre-change code zeroed the consecutive counter and added nothing to the
	// total, losing the part of the interval that really was saturated.
	before := p.SecondsAbove80Pct
	rt.Sample(t0.Add(20*time.Second), 0, 0, 0, 0, 0, 0, 0, 1000)
	p = rt.PressureSnapshot(0, 1000, 900, 0)
	if p.SecondsAbove80Pct <= before {
		t.Fatalf("draining from saturated must still credit the saturated part of the interval, total stayed at %ds",
			p.SecondsAbove80Pct)
	}
	if p.ConsecutiveAbove80Sec != 0 {
		t.Fatalf("the consecutive run is over once the queue drains, got %ds", p.ConsecutiveAbove80Sec)
	}
}

// Occupancy changing immediately BEFORE and immediately AFTER a long interval:
// the credited duration must reflect the transition, not the ending value.
func TestRateTracker_TransitionInsideLongInterval(t *testing.T) {
	rt := NewRateTracker()
	t0 := time.Now()

	rt.Sample(t0, 0, 0, 0, 0, 0, 0, 0, 1000)

	// Occupancy jumps to full immediately BEFORE the second sample, then the
	// long interval is measured from an empty reading to a saturated one.
	// Linear interpolation credits the fraction on the saturated side, which
	// for 0 -> 100% over 10s and an 80% threshold is 2s, not 10s.
	rt.Sample(t0.Add(10*time.Second), 0, 0, 0, 0, 0, 0, 1000, 1000)
	p := rt.PressureSnapshot(1000, 1000, 1000, 0)
	if p.SecondsAbove80Pct > 3 {
		t.Fatalf("a rise from empty to saturated across 10s must credit only the post-threshold fraction, got %ds",
			p.SecondsAbove80Pct)
	}
	if p.SecondsAbove80Pct < 1 {
		t.Fatalf("the post-threshold fraction must still be credited, got %ds", p.SecondsAbove80Pct)
	}

	// Occupancy drops immediately AFTER: the next interval starts saturated and
	// ends empty, and its credited fraction must again be the saturated part.
	before := p.SecondsAbove80Pct
	rt.Sample(t0.Add(20*time.Second), 0, 0, 0, 0, 0, 0, 0, 1000)
	p = rt.PressureSnapshot(0, 1000, 1000, 0)
	added := p.SecondsAbove80Pct - before
	if added > 3 {
		t.Fatalf("a fall from saturated to empty across 10s must credit only the pre-threshold fraction, added %ds", added)
	}
	if p.ConsecutiveAbove80Sec != 0 {
		t.Fatalf("consecutive must be zero once the queue is empty, got %ds", p.ConsecutiveAbove80Sec)
	}
}

func TestCreditAbove_Interpolation(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur float64
		threshold float64
		elapsed   float64
		want      float64
	}{
		{"both below", 0.1, 0.2, 0.8, 10, 0},
		{"both above", 0.9, 0.95, 0.8, 10, 10},
		{"rising through", 0.0, 1.0, 0.8, 10, 2},
		{"falling through", 1.0, 0.0, 0.8, 10, 2},
		{"no movement", 0.85, 0.85, 0.8, 10, 10},
		{"zero elapsed", 0.9, 0.9, 0.8, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := creditAbove(tc.prev, tc.cur, tc.threshold, tc.elapsed)
			if got < 0 || got > tc.elapsed+1e-9 {
				t.Fatalf("credit must stay within [0, elapsed], got %v for elapsed %v", got, tc.elapsed)
			}
			if diff := got - tc.want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("creditAbove(%v, %v, %v, %v) = %v, want %v",
					tc.prev, tc.cur, tc.threshold, tc.elapsed, got, tc.want)
			}
		})
	}
}
