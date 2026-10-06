package vpn

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Concurrency regressions for issue #429 review round 3, blocker 1: the
// generationWindow wrappers kept separately mutable state OUTSIDE any lock
// (diagDeltaTracker had none at all), so a concurrent Sample/reset pair raced
// on the wrapper gen/delta/windowSeconds while the inner window stayed
// consistent. Run with -race: these tests fail on the pre-fix code with
// detected data races, and pass after the wrapper state became synchronized.

// TestDiagDeltaTrackerConcurrentSampleReset hammers ONE diagDeltaTracker from
// concurrent Sample and reset callers. Every operation must complete and the
// tracker must stay internally consistent (no torn snapshots, no panics).
func TestDiagDeltaTrackerConcurrentSampleReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tk diagDeltaTracker
		base := time.Now()
		const workers = 8
		const iters = 200

		var wg sync.WaitGroup
		wg.Add(workers + 1)

		// Samplers: monotonically increasing cumulative observations, all
		// tagged with generation 0 until the resetter advances it.
		for w := range workers {
			go func(w int) {
				defer wg.Done()
				for i := 1; i <= iters; i++ {
					tk.Sample(base.Add(time.Duration(i)*time.Second), uint64(w*iters+i))
				}
			}(w)
		}

		// Resetter: walks the generation forward while samplers run.
		go func() {
			defer wg.Done()
			for gen := diagGeneration(1); gen <= 50; gen++ {
				tk.reset(gen)
				time.Sleep(2 * time.Second)
			}
		}()

		wg.Wait()

		// Post-hammer consistency: a fresh sample in the final generation must
		// behave exactly like a priming sample (the reset cleared the
		// baseline) and return a coherent snapshot.
		snap := tk.Sample(base.Add(500*time.Second), 42)
		if snap.delta != 0 || snap.windowSeconds != 0 {
			t.Fatalf("sample after reset must report the priming zero snapshot, got %+v", snap)
		}
	})
}

// TestDiagDeltaTrackersConcurrentResetAll exercises the aggregate reset path
// (every sub-tracker plus the per-reason windows) against concurrent per-tracker
// samplers — the production resetDiagnosticsGeneration shape.
func TestDiagDeltaTrackersConcurrentResetAll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var dts diagDeltaTrackers
		base := time.Now()

		var wg sync.WaitGroup
		wg.Add(6)
		for i := range 5 {
			go func(i int) {
				defer wg.Done()
				for j := 1; j <= 100; j++ {
					at := base.Add(time.Duration(j) * time.Second)
					dts.ownershipMismatch.Sample(at, uint64(j))
					dts.syncFailures.Sample(at, uint64(j))
					dts.writeStalls.Sample(at, uint64(j))
					if i == 0 {
						dts.reasons.sample(at, map[string]uint64{"client_malformed": uint64(j)})
					}
				}
			}(i)
		}
		go func() {
			defer wg.Done()
			for gen := diagGeneration(1); gen <= 20; gen++ {
				dts.reset(gen)
				time.Sleep(5 * time.Second)
			}
		}()
		wg.Wait()
	})
}

// TestDiagGeneration_ConcurrentStaleSnapshotVersusReset is the deterministic
// interleaving the review described: an in-flight cross-generation Sample
// completing AFTER a reset on the same tracker. The generation gate (now
// synchronized on the wrapper too) must confine the stale call to a no-op.
func TestDiagGeneration_ConcurrentStaleSnapshotVersusReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tk diagDeltaTracker
		base := time.Now()

		tk.Sample(base, 100)
		tk.Sample(base.Add(1*time.Second), 110)

		// The in-flight generation-0 request captured its tag before the
		// lifecycle reset.
		capturedGen := tk.gen
		tk.reset(1)
		tk.Sample(base.Add(2*time.Second), 0) // prime gen 1
		snap := tk.Sample(base.Add(3*time.Second), 3)
		if snap.delta != 3 {
			t.Fatalf("generation 1 must be primed from post-start counters, got %+v", snap)
		}

		// The stale generation-0 request completes now. It must be rejected
		// wholesale and leave the new-generation snapshot untouched.
		if tk.window.sample(capturedGen, base.Add(10*time.Second), []uint64{110}) {
			t.Fatal("stale cross-generation completion must be rejected")
		}
		if tk.gen != 1 {
			t.Fatalf("wrapper generation=%d, want 1: a stale completion must never demote it", tk.gen)
		}
		// And the accepted generation-1 baseline must still be 3.
		next := tk.Sample(base.Add(4*time.Second), 5)
		if next.delta != 2 {
			t.Fatalf("post-stale delta=%d, want 2 (5-3): the stale request must not re-baseline", next.delta)
		}
	})
}
