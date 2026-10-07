package vpn

import (
	"math"
	"testing"
	"testing/synctest"
	"time"
)

// Issue #429 review round 4 regressions: the generation an observation was
// captured under travels WITH the observation (blocker 1), and the total drop
// rate comes from the TotalDrops counter so the direction-neutral bucket is
// conserved (blocker 2).

// TestDiagGeneration_R1_ProductionStaleSnapshotAfterRestart is the
// production-level cross-generation regression (review round 4, regression 1):
// a diagnosticsInputs snapshot captured at generation N through the production
// capture path, with its sampling completed AFTER the service lifecycle reset
// (the diagnostics part of Stop->Start) and after the new generation has
// primed, must leave every N+1 baseline/window/rate unchanged. It drives the
// production entry points only — no direct tracker/window calls.
func TestDiagGeneration_R1_ProductionStaleSnapshotAfterRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := &Service{rollingHistory: NewRollingHistory()}

		// --- Generation 0: the old request captures its snapshot through
		// the production capture path and begins sampling. ---
		base := time.Now()
		oldInputs := svc.captureDiagnosticsInputs()
		if oldInputs.generation != 0 {
			t.Fatalf("fresh service must capture generation 0, got %d", oldInputs.generation)
		}
		oldDrops := oldInputs.collectDropCategories()
		// The pre-restart counters the in-flight request observed (higher
		// than anything generation 1 ever sees: equal values would advance a
		// new-generation window, higher values poison its baseline).
		oldDrops.ClientMalformed = 1000
		oldDrops.ClientTotalDrops = 1000
		oldDrops.TotalDrops = 1000
		svc.sampleDropRates(0, base, &oldDrops, 0) // prime generation 0

		// --- Stop->Start: the production lifecycle reset (gen N+1), then
		// the new generation primes and settles through the production
		// path. ---
		svc.resetDiagnosticsGeneration()
		if got := svc.currentDiagGeneration(); got != 1 {
			t.Fatalf("restart must advance the generation to 1, got %d", got)
		}
		post := time.Now()
		fresh := svc.captureDiagnosticsInputs()
		if fresh.generation != 1 {
			t.Fatalf("post-restart capture must carry generation 1, got %d", fresh.generation)
		}
		primeDrops := fresh.collectDropCategories()
		svc.sampleDropRates(fresh.generation, post, &primeDrops, 0) // prime gen 1
		settled := svc.captureDiagnosticsInputs().collectDropCategories()
		svc.sampleDropRates(1, post.Add(time.Second), &settled, 0)
		if !settled.RatesAvailable || settled.TotalDropRatePps != 0 || settled.ClientDropRatePps != 0 {
			t.Fatalf("generation 1 must be settled at zero before the stale completion, got %+v", settled)
		}

		// --- The old request completes now, through the production
		// sampling functions, tagged with ITS captured generation. ---
		svc.sampleDropRates(oldInputs.generation, base.Add(10*time.Second), &oldDrops, 0)

		// Every generation-1 published rate must be unchanged: the stale
		// completion advanced nothing (pre-fix it sampled against the
		// tracker-current generation and poisoned the baseline with +1000).
		after := svc.captureDiagnosticsInputs().collectDropCategories()
		svc.sampleDropRates(1, post.Add(2*time.Second), &after, 0)
		if after.ClientDropRatePps != 0 || after.TotalDropRatePps != 0 {
			t.Fatalf("completed pre-restart request polluted the new generation: client=%v total=%v, want 0/0",
				after.ClientDropRatePps, after.TotalDropRatePps)
		}
		if rate := after.ReasonRates["client_malformed"]; rate != 0 {
			t.Fatalf("completed pre-restart request polluted the new-generation reason rate: %v, want 0", rate)
		}
	})
}

// TestDropRateConservation_TotalMatchesDisjointReasons pins review round 4,
// blocker 2: total_drop_rate_pps comes from the TotalDrops counter delta, so
// it equals the sum of the disjoint per-reason rates — including the fixture
// where ONLY backend_device_unattributed changes (client=0, return=0). The
// pre-fix client+return sum reported 0 for a 10 pps neutral loss.
func TestDropRateConservation_TotalMatchesDisjointReasons(t *testing.T) {
	t.Run("neutral_only_fixture", func(t *testing.T) {
		svc := &Service{}
		base := time.Now()

		prime := DropCategoryBreakdown{BackendDeviceUnattributed: 5, TotalDrops: 5}
		svc.sampleDropRates(0, base, &prime, 0)

		drops := DropCategoryBreakdown{BackendDeviceUnattributed: 15, TotalDrops: 15}
		svc.sampleDropRates(0, base.Add(time.Second), &drops, 0)

		if !drops.RatesAvailable {
			t.Fatal("window must be available")
		}
		if math.Abs(drops.TotalDropRatePps-10) > 1e-9 {
			t.Fatalf("total_drop_rate_pps=%v, want 10: the neutral-only loss must be conserved in the total", drops.TotalDropRatePps)
		}
		sum := 0.0
		for _, rate := range drops.ReasonRates {
			sum += rate
		}
		if math.Abs(sum-drops.TotalDropRatePps) > 1e-9 {
			t.Fatalf("conservation violated: reason sum %v != total %v", sum, drops.TotalDropRatePps)
		}
		if drops.ClientDropRatePps != 0 || drops.ReturnDropRatePps != 0 {
			t.Fatalf("directional rates must stay zero, got client=%v return=%v", drops.ClientDropRatePps, drops.ReturnDropRatePps)
		}
	})

	t.Run("mixed_directional_and_neutral", func(t *testing.T) {
		svc := &Service{}
		base := time.Now()

		svc.sampleDropRates(0, base, &DropCategoryBreakdown{}, 0)
		drops := DropCategoryBreakdown{
			ClientMalformed:           30,
			ClientTotalDrops:          30,
			ReturnQueueFull:           20,
			ReturnTotalDrops:          20,
			BackendDeviceUnattributed: 5,
			TotalDrops:                55,
		}
		svc.sampleDropRates(0, base.Add(time.Second), &drops, 0)

		if math.Abs(drops.TotalDropRatePps-55) > 1e-9 {
			t.Fatalf("total_drop_rate_pps=%v, want 55", drops.TotalDropRatePps)
		}
		sum := 0.0
		for _, rate := range drops.ReasonRates {
			sum += rate
		}
		if math.Abs(sum-drops.TotalDropRatePps) > 1e-9 {
			t.Fatalf("conservation violated: reason sum %v != total %v", sum, drops.TotalDropRatePps)
		}
	})
}

// TestDropRateConservation_HeadlineMirrorsCorrectedTotal audits the headline
// consumer through the PRODUCTION status assembly: status.Rates.DropRatePps
// must mirror the corrected drop_categories total (which now includes the
// direction-neutral bucket), not the pre-fix client+return sum. Inside the
// bubble the status collection lands inside the 200ms sample floor, so it
// publishes exactly the rates the seeded production sample left behind.
func TestDropRateConservation_HeadlineMirrorsCorrectedTotal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := &Service{}
		base := time.Now()

		prime := DropCategoryBreakdown{BackendDeviceUnattributed: 5, TotalDrops: 5}
		svc.sampleDropRates(0, base, &prime, 0)
		drops := DropCategoryBreakdown{BackendDeviceUnattributed: 15, TotalDrops: 15}
		svc.sampleDropRates(0, base.Add(time.Second), &drops, 0)
		if math.Abs(drops.TotalDropRatePps-10) > 1e-9 {
			t.Fatalf("seed total=%v, want 10", drops.TotalDropRatePps)
		}

		var status Status
		svc.populateOperationalDiagnostics(&status)
		if math.Abs(status.DropCategories.TotalDropRatePps-10) > 1e-9 {
			t.Fatalf("drop_categories.total_drop_rate_pps=%v, want 10 (conserved neutral loss)", status.DropCategories.TotalDropRatePps)
		}
		if math.Abs(status.Rates.DropRatePps-10) > 1e-9 {
			t.Fatalf("headline Rates.DropRatePps=%v, want 10: the headline must draw from the corrected total", status.Rates.DropRatePps)
		}
	})
}
