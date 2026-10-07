package vpn

import (
	"math"
	"testing"
	"testing/synctest"
	"time"
)

// Issue #429 review round 5 regression: primeHistoryFromDrops must reject a
// stale-generation observation BEFORE any mutation — the history baselines,
// the per-generation primed-mark, and the forwarder history priming alike.
// The pre-fix order primed and marked first (with the tracker-current
// generation substituted for the observation's) and only then ran the stale
// guard, so a stale pre-restart snapshot resuming between the lifecycle reset
// and the new generation's first genuine collection re-baselined the new
// generation's history from its old high totals and suppressed the genuine
// re-prime; real post-restart counters then read as stale/lower until they
// caught up.

// r5SeedRetiredLosses gives the service a large retired-loss population the
// way a long-lived epoch accumulates engine losses before a restart. The
// totals ride into diagnosticsInputs snapshots BY VALUE, so a snapshot
// captured now keeps them even after the service field is reset for the new
// epoch — the "much larger totals" the stale completion carries.
func r5SeedRetiredLosses(t *testing.T, svc *Service) {
	t.Helper()
	svc.mu.Lock()
	svc.retiredIngressLosses.router.MalformedPacketDrops = 10_000
	svc.retiredIngressLosses.returns.MalformedDrops = 10_000
	svc.mu.Unlock()
}

// r5ResetRetiredLosses models the new epoch starting from small/current
// counters: far below anything the old snapshot carries.
func r5ResetRetiredLosses(t *testing.T, svc *Service) {
	t.Helper()
	svc.mu.Lock()
	svc.retiredIngressLosses = ingressLossTotals{}
	svc.mu.Unlock()
}

func r5HistoryPrimedState(t *testing.T, svc *Service) (primed bool, gen diagGeneration) {
	t.Helper()
	svc.diagRatesMu.Lock()
	defer svc.diagRatesMu.Unlock()
	return svc.historyPrimed, svc.historyPrimedGen
}

func r5LastHistoryPoint(t *testing.T, svc *Service) HistoryPoint {
	t.Helper()
	windows := svc.rollingHistory.Snapshot().Window15m
	if len(windows) == 0 {
		t.Fatal("no rolling history points recorded")
	}
	return windows[len(windows)-1]
}

// TestDiagGeneration_R5_StaleCompletionCannotPrimeNewGenerationHistory drives
// the production collection path only (captureDiagnosticsInputs,
// populateOperationalDiagnosticsFromInputs, resetDiagnosticsGeneration,
// sampleRollingHistory) — never the trackers or the priming primitive.
func TestDiagGeneration_R5_StaleCompletionCannotPrimeNewGenerationHistory(t *testing.T) {
	t.Run("before_first_genuine_collection", func(t *testing.T) {
		// The corruption window: the lifecycle reset re-primed the new
		// generation's baselines from small post-start counters but the
		// primed-mark is not yet set (the new generation's first genuine
		// collection sets it). A stale completion landing here must be
		// rejected before ANY mutation.
		synctest.Test(t, func(t *testing.T) {
			svc := &Service{rollingHistory: NewRollingHistory()}

			// Generation N: the old request captures its snapshot through
			// the production capture path while the dying epoch still
			// reports large cumulative losses.
			r5SeedRetiredLosses(t, svc)
			oldInputs := svc.captureDiagnosticsInputs()
			if oldInputs.generation != 0 {
				t.Fatalf("fresh service must capture generation 0, got %d", oldInputs.generation)
			}

			// Stop->Start (the diagnostics part): generation N+1, history
			// baselines re-primed from the small post-start counters,
			// primed-mark NOT set.
			r5ResetRetiredLosses(t, svc)
			svc.resetDiagnosticsGeneration()
			if got := svc.currentDiagGeneration(); got != 1 {
				t.Fatalf("restart must advance the generation to 1, got %d", got)
			}

			// The old request resumes inside the window and completes
			// through the production collection path with its much larger
			// pre-restart totals.
			beforePrimed, beforeGen := r5HistoryPrimedState(t, svc)
			var staleStatus Status
			svc.populateOperationalDiagnosticsFromInputs(&staleStatus, nil, oldInputs)

			// The stale completion must be rejected before any mutation: no
			// priming and no primed-mark for the new generation. Exact state
			// equality, so a polluting mark with the wrong generation cannot
			// slip through either.
			if afterPrimed, afterGen := r5HistoryPrimedState(t, svc); afterPrimed != beforePrimed || afterGen != beforeGen {
				t.Fatalf("stale completion moved the priming state: primed %v->%v, historyPrimedGen %d->%d",
					beforePrimed, afterPrimed, beforeGen, afterGen)
			}

			// The new generation's first genuine collection primes normally
			// from the current small counters.
			time.Sleep(250 * time.Millisecond)
			svc.sampleRollingHistory()
			if primed, gen := r5HistoryPrimedState(t, svc); !primed || gen != 1 {
				t.Fatalf("genuine first collection must prime generation 1: primed=%v historyPrimedGen=%d", primed, gen)
			}

			// A genuine post-restart loss must measure normally. It is far
			// BELOW the stale totals, so a poisoned baseline would classify
			// the observation fully stale and report no window at all.
			time.Sleep(1 * time.Second)
			svc.mu.Lock()
			svc.retiredIngressLosses.router.MalformedPacketDrops += 50
			svc.mu.Unlock()
			svc.sampleRollingHistory()

			point := r5LastHistoryPoint(t, svc)
			if !point.DropRatesAvailable {
				t.Fatal("genuine generation-1 loss produced no history window (baseline poisoned by the stale completion?)")
			}
			if math.Abs(point.TotalDropRate-50) > 1e-9 {
				t.Fatalf("history total_drop_rate=%v, want 50 (50 drops / 1s window): the stale completion re-baselined the new generation", point.TotalDropRate)
			}
			if math.Abs(point.DropReasonRates["client_malformed"]-50) > 1e-9 {
				t.Fatalf("history client_malformed rate=%v, want 50: the stale completion poisoned the reason baseline", point.DropReasonRates["client_malformed"])
			}
		})
	})

	t.Run("after_first_genuine_collection", func(t *testing.T) {
		// The reviewer's literal sequence: the new generation primes
		// genuinely first; the stale completion arrives after, past the
		// sample floor. It must leave baseline, window, reason baseline and
		// priming state exactly as the genuine sampler left them.
		synctest.Test(t, func(t *testing.T) {
			svc := &Service{rollingHistory: NewRollingHistory()}

			r5SeedRetiredLosses(t, svc)
			oldInputs := svc.captureDiagnosticsInputs()

			r5ResetRetiredLosses(t, svc)
			svc.resetDiagnosticsGeneration()
			if got := svc.currentDiagGeneration(); got != 1 {
				t.Fatalf("restart must advance the generation to 1, got %d", got)
			}

			// First genuine N+1 collection primes from small/current
			// counters.
			time.Sleep(250 * time.Millisecond)
			svc.sampleRollingHistory()
			if primed, gen := r5HistoryPrimedState(t, svc); !primed || gen != 1 {
				t.Fatalf("genuine first collection must prime generation 1: primed=%v historyPrimedGen=%d", primed, gen)
			}

			// Advance past the sample floor, then complete the old snapshot
			// with much larger totals through the production path.
			time.Sleep(1 * time.Second)
			var staleStatus Status
			svc.populateOperationalDiagnosticsFromInputs(&staleStatus, nil, oldInputs)

			// historyPrimedGen remains N+1.
			if primed, gen := r5HistoryPrimedState(t, svc); !primed || gen != 1 {
				t.Fatalf("stale completion disturbed the priming state: primed=%v historyPrimedGen=%d", primed, gen)
			}

			// The next genuine N+1 delta measures normally: 50 drops over
			// the 2s since the last accepted window — a moved anchor or
			// baseline would change the rate.
			time.Sleep(1 * time.Second)
			svc.mu.Lock()
			svc.retiredIngressLosses.router.MalformedPacketDrops += 50
			svc.mu.Unlock()
			svc.sampleRollingHistory()

			point := r5LastHistoryPoint(t, svc)
			if !point.DropRatesAvailable {
				t.Fatal("genuine generation-1 loss produced no history window")
			}
			if math.Abs(point.TotalDropRate-25) > 1e-9 {
				t.Fatalf("history total_drop_rate=%v, want 25 (50 drops / 2s window): the stale completion moved the window anchor or baseline", point.TotalDropRate)
			}
			if math.Abs(point.DropReasonRates["client_malformed"]-25) > 1e-9 {
				t.Fatalf("history client_malformed rate=%v, want 25: the stale completion disturbed the reason window", point.DropReasonRates["client_malformed"])
			}
		})
	})

	t.Run("stale_completion_primes_no_forwarder_history", func(t *testing.T) {
		// The forwarder priming calls are part of the same priming contract
		// and sit behind the same generation decision: a stale snapshot must
		// not prime the forwarder's aggregate or per-backend history either.
		// With a live forwarder the bug is observable through the public API:
		// after the lifecycle reset the first genuine forwarder-history read
		// may only PRIME (rates unavailable); if the stale completion
		// consumed the priming slot, that genuine read instead ACCEPTS a
		// window and reports rates.
		synctest.Test(t, func(t *testing.T) {
			svc, fwd, _ := newTestHistoryService(t)

			oldInputs := svc.captureDiagnosticsInputs()
			if oldInputs.generation != 0 {
				t.Fatalf("fresh fixture must capture generation 0, got %d", oldInputs.generation)
			}

			// Stop->Start (the diagnostics part of it). The forwarder value
			// survives the snapshot — exactly the aliasing an in-flight
			// request carries across the reset.
			svc.resetDiagnosticsGeneration()
			if got := svc.currentDiagGeneration(); got != 1 {
				t.Fatalf("restart must advance the generation to 1, got %d", got)
			}

			// The stale completion runs through the production collection
			// path with the live forwarder inside the snapshot.
			var staleStatus Status
			svc.populateOperationalDiagnosticsFromInputs(&staleStatus, nil, oldInputs)

			// First genuine forwarder-history read after the reset: past the
			// sample floor so a consumed priming slot would show. It must
			// find the forwarder history UNPRIMED — the stale completion may
			// not prime it.
			time.Sleep(250 * time.Millisecond)
			rates := fwd.HistoryRates(time.Now())
			if rates.Available {
				t.Fatal("stale completion primed the forwarder aggregate history: the first genuine post-restart read accepted a window instead of priming")
			}
			traffic := fwd.BackendTrafficHistorySnapshot(time.Now())
			if len(traffic) != 1 {
				t.Fatalf("fixture must expose one backend, got %d", len(traffic))
			}
			for id, snap := range traffic {
				if snap.Available {
					t.Fatalf("stale completion primed backend %d traffic history: the first genuine post-restart read accepted a window instead of priming", id)
				}
			}
		})
	})
}
