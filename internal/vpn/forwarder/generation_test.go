package forwarder

import (
	"context"
	"math"
	"testing"
	"time"
)

// This file pins issue #429 review blocker 1 on the forwarder side, mirroring
// internal/vpn/diagnostics_generation_test.go: the cumulative telemetry
// trackers are generation-aware. Every Start after Stop is an explicit new
// generation; within a generation the accepted baselines are monotonic, so an
// out-of-order observation can never rewind them, and a lifecycle reset
// re-primes instead of inferring a restart from counters that moved backwards.

// TestGenerationSampler_OutOfOrderNeverRewindsBaselines drives the shared
// primitive through the canonical out-of-order scenario: rising counters, one
// LOWER observation (the pre-restart epoch replaying), then the return to the
// higher value. A fully lower observation must be rejected wholesale —
// accepted=false with zero mutation (round 4 finding 3: it used to open a
// window and advance the anchor); a stale-generation observation must be
// ignored entirely.
func TestGenerationSampler_OutOfOrderNeverRewindsBaselines(t *testing.T) {
	w := NewGenerationSampler(2)
	base := time.Now()

	// First sample of generation 0: primes the baseline only.
	deltas, _, accepted := w.Sample(0, base, GenerationSampleMinInterval, []uint64{100, 1000})
	if accepted || deltas != nil {
		t.Fatalf("first sample must only prime the baseline, got accepted=%v deltas=%v", accepted, deltas)
	}

	// Window 1: 100 -> 110 and 1000 -> 1100 over 1s.
	deltas, _, accepted = w.Sample(0, base.Add(1*time.Second), GenerationSampleMinInterval, []uint64{110, 1100})
	if !accepted || deltas[0] != 10 || deltas[1] != 100 {
		t.Fatalf("window 1: want accepted deltas [10 100], got accepted=%v deltas=%v", accepted, deltas)
	}

	// Out-of-order: the pre-restart observations (100, 900) replay AFTER the
	// higher ones were accepted. The observation is fully stale, so it must
	// be rejected wholesale: accepted=false and nothing mutates.
	deltas, _, accepted = w.Sample(0, base.Add(2*time.Second), GenerationSampleMinInterval, []uint64{100, 900})
	if accepted || deltas != nil {
		t.Fatalf("a fully stale observation must be rejected with no deltas, got accepted=%v deltas=%v", accepted, deltas)
	}

	// The counters return to the previously accepted values: still zero —
	// the baselines were never rewound, so nothing replays as fresh delta.
	deltas, _, accepted = w.Sample(0, base.Add(3*time.Second), GenerationSampleMinInterval, []uint64{110, 1100})
	if !accepted {
		t.Fatal("an observation outside the sample floor must open a window")
	}
	if deltas[0] != 0 || deltas[1] != 0 {
		t.Fatalf("activity up to the accepted baseline must not replay as fresh delta, got %v", deltas)
	}
	if v, _, primed, _ := w.Baseline(0); !primed || v != 110 {
		t.Fatalf("counter 0 baseline must remain the accepted 110, got value=%d primed=%v", v, primed)
	}
	if v, _, primed, _ := w.Baseline(1); !primed || v != 1100 {
		t.Fatalf("counter 1 baseline must remain the accepted 1100, got value=%d primed=%v", v, primed)
	}

	// Lifecycle reset: generation 1 re-primes from the restarted counters.
	w.Reset(1)
	deltas, _, accepted = w.Sample(1, base.Add(4*time.Second), GenerationSampleMinInterval, []uint64{0, 0})
	if accepted || deltas != nil {
		t.Fatalf("first sample after Reset must only re-prime, got accepted=%v deltas=%v", accepted, deltas)
	}

	// A stale in-flight observation from generation 0 crossing the reset must
	// be ignored entirely: it may neither describe nor advance the baseline.
	deltas, _, accepted = w.Sample(0, base.Add(5*time.Second), GenerationSampleMinInterval, []uint64{1 << 40, 1 << 40})
	if accepted || deltas != nil {
		t.Fatalf("stale-generation observation must be ignored, got accepted=%v deltas=%v", accepted, deltas)
	}
	if v, _, primed, gen := w.Baseline(0); !primed || gen != 1 || v != 0 {
		t.Fatalf("stale observation must not touch the generation-1 baseline, got value=%d primed=%v gen=%d", v, primed, gen)
	}
}

// TestGenerationSampler_FullyStaleNeverAdvancesClock pins review round 4,
// finding 3 with the review's exact numbers: accepted 110@t1, fully stale
// 100@t10 rejected with accepted=false and zero mutation, valid 120@t10.2
// keeps its true denominator (9.2s). Pre-fix the stale observation returned
// accepted=true and advanced w.at, corrupting the denominator to 0.2s.
func TestGenerationSampler_FullyStaleNeverAdvancesClock(t *testing.T) {
	t.Run("multi_counter_sample", func(t *testing.T) {
		w := NewGenerationSampler(1)
		base := time.Now()
		w.Sample(0, base, GenerationSampleMinInterval, []uint64{100}) // prime
		deltas, elapsed, accepted := w.Sample(0, base.Add(1*time.Second), GenerationSampleMinInterval, []uint64{110})
		if !accepted || deltas[0] != 10 || elapsed != 1 {
			t.Fatalf("window 1: want accepted delta 10 over 1s, got accepted=%v deltas=%v elapsed=%v", accepted, deltas, elapsed)
		}

		// Fully stale: every counter below baseline. Must classify before
		// mutation: accepted=false, nil deltas, zero elapsed, NOTHING moves.
		deltas, elapsed, accepted = w.Sample(0, base.Add(10*time.Second), GenerationSampleMinInterval, []uint64{100})
		if accepted || deltas != nil || elapsed != 0 {
			t.Fatalf("fully stale observation must be rejected with zero mutation, got accepted=%v deltas=%v elapsed=%v", accepted, deltas, elapsed)
		}

		// The valid observation keeps its true denominator: 10.2s - 1s = 9.2s.
		deltas, elapsed, accepted = w.Sample(0, base.Add(10200*time.Millisecond), GenerationSampleMinInterval, []uint64{120})
		if !accepted || deltas[0] != 10 {
			t.Fatalf("valid observation must be accepted with delta 10, got accepted=%v deltas=%v", accepted, deltas)
		}
		if math.Abs(elapsed-9.2) > 1e-9 {
			t.Fatalf("elapsed=%v, want 9.2: the stale observation must not consume the denominator", elapsed)
		}
	})

	t.Run("partial_stale_advances", func(t *testing.T) {
		// Documented contract: SOME counters below baseline with at least one
		// advancing is still an accepted window (the advancing counters moved
		// genuinely); the stale counters report zero for that window.
		w := NewGenerationSampler(2)
		base := time.Now()
		w.Sample(0, base, GenerationSampleMinInterval, []uint64{100, 200}) // prime
		if d, _, accepted := w.Sample(0, base.Add(1*time.Second), GenerationSampleMinInterval, []uint64{110, 210}); !accepted || d[0] != 10 || d[1] != 10 {
			t.Fatalf("window 1: want accepted deltas [10 10], got accepted=%v deltas=%v", accepted, d)
		}
		// counter[1] replays stale while counter[0] genuinely advanced.
		d, elapsed, accepted := w.Sample(0, base.Add(2*time.Second), GenerationSampleMinInterval, []uint64{130, 200})
		if !accepted || d[0] != 20 || d[1] != 0 {
			t.Fatalf("partially stale observation must be accepted when one counter advanced, got accepted=%v deltas=%v", accepted, d)
		}
		if math.Abs(elapsed-1.0) > 1e-9 {
			t.Fatalf("elapsed=%v, want 1.0: the shared window advances with the genuine counter", elapsed)
		}
	})

	t.Run("sample_counter_same_contract", func(t *testing.T) {
		w := NewGenerationSampler(1)
		base := time.Now()
		if _, _, accepted := w.SampleCounter(0, base, GenerationSampleMinInterval, 100); accepted {
			t.Fatal("first sample must only prime")
		}
		if delta, _, accepted := w.SampleCounter(0, base.Add(1*time.Second), GenerationSampleMinInterval, 110); !accepted || delta != 10 {
			t.Fatalf("window 1: want accepted delta 10, got delta=%d accepted=%v", delta, accepted)
		}
		// Fully stale single counter: the same classify-before-mutation
		// contract (already correct at head; pinned explicitly).
		if delta, elapsed, accepted := w.SampleCounter(0, base.Add(10*time.Second), GenerationSampleMinInterval, 100); accepted || delta != 0 || elapsed != 0 {
			t.Fatalf("fully stale SampleCounter must be rejected with zero mutation, got delta=%d elapsed=%v accepted=%v", delta, elapsed, accepted)
		}
		// Denominator preserved for the next valid window.
		if delta, elapsed, accepted := w.SampleCounter(0, base.Add(10200*time.Millisecond), GenerationSampleMinInterval, 120); !accepted || delta != 10 {
			t.Fatalf("valid observation must be accepted with delta 10, got delta=%d accepted=%v", delta, accepted)
		} else if math.Abs(elapsed-9.2) > 1e-9 {
			t.Fatalf("elapsed=%v, want 9.2", elapsed)
		}
	})
}

// TestGenerationSampler_SampleFloorKeepsWindowIntact pins the throttle half of
// the contract: a repeated read inside GenerationSampleMinInterval of the
// accepted one leaves the previous window untouched, so a single collection
// that reads a counter twice cannot swallow the incident.
func TestGenerationSampler_SampleFloorKeepsWindowIntact(t *testing.T) {
	w := NewGenerationSampler(1)
	base := time.Now()

	w.Sample(0, base, GenerationSampleMinInterval, []uint64{100})
	deltas, elapsed, accepted := w.Sample(0, base.Add(1*time.Second), GenerationSampleMinInterval, []uint64{110})
	if !accepted || deltas[0] != 10 || elapsed != 1 {
		t.Fatalf("window 1: want accepted delta 10 over 1s, got accepted=%v deltas=%v elapsed=%v", accepted, deltas, elapsed)
	}

	// Same-timestamp repeat read (diagnostics collections do this): inside the
	// floor, so the 10-delta window must stay intact and no new one may open.
	deltas, elapsed, accepted = w.Sample(0, base.Add(1*time.Second), GenerationSampleMinInterval, []uint64{110})
	if accepted || deltas != nil || elapsed != 0 {
		t.Fatalf("sample inside the floor must leave the window untouched, got accepted=%v deltas=%v elapsed=%v", accepted, deltas, elapsed)
	}
	deltas, _, accepted = w.Sample(0, base.Add(1*time.Second), GenerationSampleMinInterval, []uint64{113})
	if accepted || deltas != nil {
		t.Fatalf("sample inside the floor must be ignored even with new activity, got accepted=%v deltas=%v", accepted, deltas)
	}

	// Outside the floor the fresh activity is measured exactly once.
	deltas, _, accepted = w.Sample(0, base.Add(2*time.Second), GenerationSampleMinInterval, []uint64{113})
	if !accepted || deltas[0] != 3 {
		t.Fatalf("post-floor sample must measure the pending delta once, got accepted=%v deltas=%v", accepted, deltas)
	}
}

// TestGenerationSampler_SampleCounterNeverRewinds pins the single-counter
// allocation-free form to the same monotonic rule.
func TestGenerationSampler_SampleCounterNeverRewinds(t *testing.T) {
	w := NewGenerationSampler(1)
	base := time.Now()

	if _, _, accepted := w.SampleCounter(0, base, GenerationSampleMinInterval, 100); accepted {
		t.Fatal("first sample must only prime")
	}
	delta, _, accepted := w.SampleCounter(0, base.Add(1*time.Second), GenerationSampleMinInterval, 110)
	if !accepted || delta != 10 {
		t.Fatalf("window 1: want accepted delta 10, got delta=%d accepted=%v", delta, accepted)
	}

	// Lower observation: zero delta, baseline untouched...
	delta, _, _ = w.SampleCounter(0, base.Add(2*time.Second), GenerationSampleMinInterval, 100)
	if delta != 0 {
		t.Fatalf("lower observation must report zero delta, got %d", delta)
	}
	// ...and the return to 110 must not replay as fresh delta.
	delta, _, accepted = w.SampleCounter(0, base.Add(3*time.Second), GenerationSampleMinInterval, 110)
	if accepted && delta != 0 {
		t.Fatalf("activity up to the accepted baseline must not replay, got delta=%d accepted=%v", delta, accepted)
	}
	if v, _, primed, _ := w.Baseline(0); !primed || v != 110 {
		t.Fatalf("baseline must remain the accepted 110, got value=%d primed=%v", v, primed)
	}
}

// TestRateTracker_OutOfOrderNeverRewindsBaselines drives the aggregate
// RateTracker (the sampler's production consumer) through the same scenario:
// the lower replay must produce zero rates, and the return to the higher
// counters must not resurface as a fresh loss burst.
func TestRateTracker_OutOfOrderNeverRewindsBaselines(t *testing.T) {
	rt := NewRateTracker()
	base := time.Now()

	// Prime, then window 1: +1000 rx bytes, +100 rx pkts, +10 drops over 1s.
	rt.Sample(0, base, 1000, 2000, 100, 200, 50, 5)
	rt.Sample(0, base.Add(1*time.Second), 2000, 4000, 200, 400, 60, 6)

	rates := rt.Snapshot(0, 0)
	if !rates.Available || rates.RxBps != 8000 || rates.RxPps != 100 || rates.TxPps != 200 || rates.DropRatePps != 10 {
		t.Fatalf("window 1: want rx=8000Bps/100pps tx=200pps drops=10pps, got %+v", rates)
	}

	// Out-of-order: the pre-restart counters replay after the higher window.
	// Fully stale, so the sample is rejected wholesale and the PREVIOUS
	// window's rates stay published (pre-fix this returned true with zero
	// deltas, zeroing the published rates for 200ms of wall time).
	rt.Sample(0, base.Add(2*time.Second), 1000, 2000, 100, 200, 50, 5)
	rates = rt.Snapshot(0, 0)
	if !rates.Available || rates.RxBps != 8000 || rates.RxPps != 100 || rates.TxPps != 200 || rates.DropRatePps != 10 {
		t.Fatalf("lower replay must keep the last accepted rates, got %+v", rates)
	}

	// Return to the higher counters: still zero — the baselines never moved,
	// so the pre-restart totals cannot resurface as a fresh loss burst.
	rt.Sample(0, base.Add(3*time.Second), 2000, 4000, 200, 400, 60, 6)
	rates = rt.Snapshot(0, 0)
	if !rates.Available || rates.RxBps != 0 || rates.RxPps != 0 || rates.TxPps != 0 || rates.DropRatePps != 0 {
		t.Fatalf("activity up to the accepted baseline must not replay as fresh rates, got %+v", rates)
	}

	// Only genuinely-new activity above the baselines is measured.
	rt.Sample(0, base.Add(4*time.Second), 3000, 4000, 250, 400, 63, 6)
	rates = rt.Snapshot(0, 0)
	if !rates.Available || rates.RxBps != 8000 || rates.RxPps != 50 || rates.DropRatePps != 3 {
		t.Fatalf("post-replay delta must measure only new activity (rx 8000Bps/50pps, drops 3pps), got %+v", rates)
	}
}

// TestForwarder_StartResetsGenerationAndReprimesRates is the forwarder
// counterpart of the diagnostics lifecycle regression: after Stop->Start the
// history rates recorded through the production entry point must be computed
// only from post-start generations — never from pre-start totals (either
// direction: inflated by them, or a cross-restart baseline rewinding so the
// pre-start totals divide the post-restart window).
func TestForwarder_StartResetsGenerationAndReprimesRates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 256, 16)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits failed: %v", err)
	}

	// --- Generation 0 (the constructor incarnation): baselines live. ---
	now := time.Now()
	fwd.HistoryRates(now) // prime generation 0 from zero
	fwd.totalRxPackets.Store(100)
	fwd.totalTxPackets.Store(200)
	fwd.dropsTotal.Store(10)
	pre := fwd.HistoryRates(now.Add(1 * time.Second)) // +100 pkts over 1s
	if !pre.Available || pre.RxPps != 100 || pre.TxPps != 200 || pre.DropRatePps != 10 {
		t.Fatalf("generation 0 history window: want 100/200pps drops 10pps, got %+v", pre)
	}

	// --- Stop->Start: the production lifecycle reset. ---
	fwd.Start(ctx)
	if got := fwd.currentGeneration(); got != 1 {
		t.Fatalf("Start must advance the generation to 1, got %d", got)
	}

	// --- Generation 1: the counters restarted from zero. ---
	fwd.totalRxPackets.Store(0)
	fwd.totalTxPackets.Store(0)
	fwd.dropsTotal.Store(0)
	post := time.Now()
	fwd.HistoryRates(post) // lazily re-prime into generation 1
	r := fwd.HistoryRates(post.Add(1 * time.Second))
	if !r.Available {
		t.Fatal("post-start history window must be available")
	}
	// Zero across the board: the pre-start totals (100/200/10) must neither
	// inflate this window nor be replayed against the post-start baseline.
	if r.RxPps != 0 || r.TxPps != 0 || r.DropRatePps != 0 {
		t.Fatalf("post-start history rates must come only from post-start counters, got %+v", r)
	}

	// Post-start traffic is measured from the fresh baseline only.
	fwd.totalRxPackets.Store(50)
	fwd.totalTxPackets.Store(80)
	fwd.dropsTotal.Store(2)
	r = fwd.HistoryRates(post.Add(2 * time.Second))
	if !r.Available || r.RxPps != 50 || r.TxPps != 80 || r.DropRatePps != 2 {
		t.Fatalf("post-start rates must measure only post-start activity, got %+v", r)
	}

	// The fresh baseline is primed at the post-start value in generation 1 —
	// no pre-start value (100 rx packets) survives anywhere in the accepted
	// state (slot 2 is the rx-packets baseline, last accepted at 50).
	if v, _, primed, gen := fwd.historyRateTracker.sampler.Baseline(2); !primed || gen != 1 || v != 50 {
		t.Fatalf("history rx-packets baseline must be primed at the post-start value in generation 1, got value=%d primed=%v gen=%d", v, primed, gen)
	}
}
