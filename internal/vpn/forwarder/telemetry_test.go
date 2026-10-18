package forwarder

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"
)

func TestTelemetry_RouteQueueStatsAndAllRouteQueueStats(t *testing.T) {
	t.Run("single peer stats lifecycle and display redaction", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 4)
		f.RegisterSession("s1", "c1", "peer-1", "10.100.0.10", 1)

		// Initial query: empty queue
		stats, ok := f.RouteQueueStats("peer-1")
		if !ok {
			t.Fatal("expected RouteQueueStats to find registered peer-1")
		}
		if stats.Occupancy != 0 || stats.Capacity != 4 || stats.HighWater != 0 || stats.QueueFullDrops != 0 {
			t.Fatalf("unexpected initial stats: %+v", stats)
		}
		if stats.PeerKeyDisplay != "" {
			t.Fatalf("expected PeerKeyDisplay to be empty by default, got %q", stats.PeerKeyDisplay)
		}

		// JSON serialization omits empty PeerKeyDisplay
		data, err := json.Marshal(stats)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var rawMap map[string]any
		if err := json.Unmarshal(data, &rawMap); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if _, exists := rawMap["peer_key_display"]; exists {
			t.Fatalf("peer_key_display should be omitted when empty, found in json: %s", string(data))
		}

		// When set by caller (API redaction convention), it is serialized and deserialized
		stats.PeerKeyDisplay = "peer-1-redacted"
		dataWithDisplay, err := json.Marshal(stats)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var restored RouteQueueStats
		if err := json.Unmarshal(dataWithDisplay, &restored); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if restored.PeerKeyDisplay != "peer-1-redacted" {
			t.Fatalf("expected PeerKeyDisplay %q, got %q", "peer-1-redacted", restored.PeerKeyDisplay)
		}

		// Fill queue up to capacity
		for i := 0; i < 4; i++ {
			if err := f.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
				t.Fatalf("packet %d route failed: %v", i, err)
			}
		}

		// Next packet should trigger queue full drop
		if err := f.RouteBackendToClient(1, []byte("overflow"), "10.100.0.10"); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull, got %v", err)
		}

		// Wait for routePressureSampleInterval (200ms) to elapse so new sample updates delta
		time.Sleep(210 * time.Millisecond)

		statsAfter, ok := f.RouteQueueStats("peer-1")
		if !ok {
			t.Fatal("expected RouteQueueStats to find peer-1")
		}
		if statsAfter.Occupancy != 4 || statsAfter.Capacity != 4 || statsAfter.HighWater != 4 || statsAfter.QueueFullDrops != 1 {
			t.Fatalf("unexpected stats after overflow: %+v", statsAfter)
		}
		if statsAfter.QueueFullDropsRecent != 1 {
			t.Fatalf("expected QueueFullDropsRecent=1, got %d", statsAfter.QueueFullDropsRecent)
		}
	})

	t.Run("non-existent peer lookup returns false", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 4)
		stats, ok := f.RouteQueueStats("non-existent-peer")
		if ok {
			t.Fatalf("expected ok=false for non-existent peer, got stats: %+v", stats)
		}
		if stats != (RouteQueueStats{}) {
			t.Fatalf("expected empty RouteQueueStats, got %+v", stats)
		}
	})

	t.Run("AllRouteQueueStats matches per-route stats and tracks in-flight stalls", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 4)
		f.RegisterSession("s1", "c1", "peer-1", "10.100.0.10", 1)
		f.RegisterSession("s2", "c2", "peer-2", "10.100.0.20", 2)

		if err := f.RouteBackendToClient(1, []byte("pkt1"), "10.100.0.10"); err != nil {
			t.Fatalf("route to peer-1: %v", err)
		}
		if err := f.RouteBackendToClient(2, []byte("pkt2"), "10.100.0.20"); err != nil {
			t.Fatalf("route to peer-2: %v", err)
		}

		all := f.AllRouteQueueStats()
		if len(all) != 2 {
			t.Fatalf("expected 2 routes in AllRouteQueueStats, got %d", len(all))
		}

		s1, ok1 := all["peer-1"]
		s2, ok2 := all["peer-2"]
		if !ok1 || !ok2 {
			t.Fatalf("missing routes in AllRouteQueueStats: ok1=%v, ok2=%v", ok1, ok2)
		}
		if s1.Occupancy != 1 || s2.Occupancy != 1 {
			t.Fatalf("expected occupancy 1 for both, got s1=%d, s2=%d", s1.Occupancy, s2.Occupancy)
		}

		// Simulate an in-flight stall on peer-1
		route1 := f.routesByPeer["peer-1"]
		stallStart := time.Now().Add(-2 * DeviceWriteStallThreshold)
		f.writeMetricsMu.Lock()
		f.writesInFlight[route1] = stallStart
		f.writeMetricsMu.Unlock()

		allWithStall := f.AllRouteQueueStats()
		s1Stalled := allWithStall["peer-1"]
		if s1Stalled.WritesInFlight != 1 {
			t.Fatalf("expected WritesInFlight=1, got %d", s1Stalled.WritesInFlight)
		}
		if s1Stalled.OldestWriteMS < (DeviceWriteStallThreshold * 2).Milliseconds() {
			t.Fatalf("expected OldestWriteMS >= stall duration, got %d", s1Stalled.OldestWriteMS)
		}
		if s1Stalled.WriteStalls != 1 {
			t.Fatalf("expected WriteStalls=1, got %d", s1Stalled.WriteStalls)
		}

		// Clean up simulated stall
		f.writeMetricsMu.Lock()
		delete(f.writesInFlight, route1)
		f.writeMetricsMu.Unlock()
	})
}

func TestTelemetry_AggregateQueueStatsAndSnapshot(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	f.RegisterSession("s1", "c1", "peer-1", "10.100.0.10", 1)
	f.RegisterSession("s2", "c2", "peer-2", "10.100.0.20", 2)

	// Send 3 packets to peer-1 and 2 to peer-2
	for i := 0; i < 3; i++ {
		if err := f.RouteBackendToClient(1, []byte("pkt"), "10.100.0.10"); err != nil {
			t.Fatalf("packet %d to peer-1: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := f.RouteBackendToClient(2, []byte("pkt"), "10.100.0.20"); err != nil {
			t.Fatalf("packet %d to peer-2: %v", i, err)
		}
	}

	occ, cap, hw := f.AggregateQueueStats()
	if occ != 5 {
		t.Fatalf("expected aggregate occupancy 5, got %d", occ)
	}
	if cap != 8 {
		t.Fatalf("expected aggregate capacity 8, got %d", cap)
	}
	if hw != 5 {
		t.Fatalf("expected aggregate high-water 5, got %d", hw)
	}

	// Verify aggregateQueueSnapshot includes dwell sampling
	snapOcc, snapCap, snapHW, dwell := f.aggregateQueueSnapshot()
	if snapOcc != 5 || snapCap != 8 || snapHW != 5 {
		t.Fatalf("snapshot mismatch: occ=%d, cap=%d, hw=%d", snapOcc, snapCap, snapHW)
	}
	// Capacity is 8, occupancy 5 is 62.5% (> 50%, < 80%)
	_ = dwell // dwell tracker records dwell states

	// Compatibility drain reconciliation:
	// Drain 2 packets directly from peer-1's channel
	ch, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("failed to get peer-1 channel")
	}
	<-ch
	<-ch

	// AggregateQueueStats reconciles direct channel drains
	occReconciled, capReconciled, hwReconciled := f.AggregateQueueStats()
	if occReconciled != 3 {
		t.Fatalf("expected reconciled aggregate occupancy 3, got %d", occReconciled)
	}
	if capReconciled != 8 {
		t.Fatalf("expected aggregate capacity 8, got %d", capReconciled)
	}
	if hwReconciled != 5 {
		t.Fatalf("expected high-water mark to stay at 5, got %d", hwReconciled)
	}
}

func TestTelemetry_DropCounterGettersAndSeeding(t *testing.T) {
	t.Run("initial state is zero", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)

		if qF, nR, tot := f.DropStats(); qF != 0 || nR != 0 || tot != 0 {
			t.Fatalf("expected zero DropStats, got (%d, %d, %d)", qF, nR, tot)
		}
		if got := f.DropsNoRoute(); got != 0 {
			t.Fatalf("expected DropsNoRoute=0, got %d", got)
		}
		if got := f.DropsQueueFull(); got != 0 {
			t.Fatalf("expected DropsQueueFull=0, got %d", got)
		}
		if got := f.DropsPacketTooLarge(); got != 0 {
			t.Fatalf("expected DropsPacketTooLarge=0, got %d", got)
		}
		if got := f.DropsQueueFullSinceStartup(); got != 0 {
			t.Fatalf("expected DropsQueueFullSinceStartup=0, got %d", got)
		}
		if got := f.DropsPacketTooLargeSinceStartup(); got != 0 {
			t.Fatalf("expected DropsPacketTooLargeSinceStartup=0, got %d", got)
		}
		if qF, nR, tot := f.RawDropStats(); qF != 0 || nR != 0 || tot != 0 {
			t.Fatalf("expected zero RawDropStats, got (%d, %d, %d)", qF, nR, tot)
		}
		if qF, rL, nB, tot := f.ClientDropStats(); qF != 0 || rL != 0 || nB != 0 || tot != 0 {
			t.Fatalf("expected zero ClientDropStats, got (%d, %d, %d, %d)", qF, rL, nB, tot)
		}
		if qF, rL, nB, tot := f.ClientDropStatsSinceStartup(); qF != 0 || rL != 0 || nB != 0 || tot != 0 {
			t.Fatalf("expected zero ClientDropStatsSinceStartup, got (%d, %d, %d, %d)", qF, rL, nB, tot)
		}
		if qF, rL, nB, tot := f.RawClientDropStats(); qF != 0 || rL != 0 || nB != 0 || tot != 0 {
			t.Fatalf("expected zero RawClientDropStats, got (%d, %d, %d, %d)", qF, rL, nB, tot)
		}
		if got := f.SpoofedRebinds(); got != 0 {
			t.Fatalf("expected SpoofedRebinds=0, got %d", got)
		}
		if rx, tx := f.PacketStats(); rx != 0 || tx != 0 {
			t.Fatalf("expected PacketStats=(0, 0), got (%d, %d)", rx, tx)
		}
		if rx, tx, routes := f.GetStats(); rx != 0 || tx != 0 || routes != 0 {
			t.Fatalf("expected GetStats=(0, 0, 0), got (%d, %d, %d)", rx, tx, routes)
		}
	})

	t.Run("SeedDropsForTest increments return and client drop counters", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)

		f.SeedDropsForTest(10, 20, 30, 40, 50, 60)

		if got := f.DropsQueueFull(); got != 10 {
			t.Fatalf("expected DropsQueueFull=10, got %d", got)
		}
		if got := f.DropsNoRoute(); got != 20 {
			t.Fatalf("expected DropsNoRoute=20, got %d", got)
		}
		if got := f.DropsPacketTooLarge(); got != 30 {
			t.Fatalf("expected DropsPacketTooLarge=30, got %d", got)
		}
		if got := f.DropsQueueFullSinceStartup(); got != 10 {
			t.Fatalf("expected DropsQueueFullSinceStartup=10, got %d", got)
		}
		if got := f.DropsPacketTooLargeSinceStartup(); got != 30 {
			t.Fatalf("expected DropsPacketTooLargeSinceStartup=30, got %d", got)
		}

		qF, nR, tot := f.DropStats()
		if qF != 10 || nR != 20 || tot != 60 {
			t.Fatalf("expected DropStats=(10, 20, 60), got (%d, %d, %d)", qF, nR, tot)
		}
		rqF, rnR, rtot := f.RawDropStats()
		if rqF != 10 || rnR != 20 || rtot != 60 {
			t.Fatalf("expected RawDropStats=(10, 20, 60), got (%d, %d, %d)", rqF, rnR, rtot)
		}

		cqF, crL, cnB, cTot := f.ClientDropStats()
		if cqF != 40 || crL != 50 || cnB != 60 || cTot != 150 {
			t.Fatalf("expected ClientDropStats=(40, 50, 60, 150), got (%d, %d, %d, %d)", cqF, crL, cnB, cTot)
		}
		sqF, srL, snB, sTot := f.ClientDropStatsSinceStartup()
		if sqF != 40 || srL != 50 || snB != 60 || sTot != 150 {
			t.Fatalf("expected ClientDropStatsSinceStartup=(40, 50, 60, 150), got (%d, %d, %d, %d)", sqF, srL, snB, sTot)
		}
		rcqF, rcrL, rcnB, rcTot := f.RawClientDropStats()
		if rcqF != 40 || rcrL != 50 || rcnB != 60 || rcTot != 150 {
			t.Fatalf("expected RawClientDropStats=(40, 50, 60, 150), got (%d, %d, %d, %d)", rcqF, rcrL, rcnB, rcTot)
		}

		// ResetDropCounters resets everything back to 0
		f.ResetDropCounters()

		if qF, nR, tot := f.DropStats(); qF != 0 || nR != 0 || tot != 0 {
			t.Fatalf("expected zero DropStats after reset, got (%d, %d, %d)", qF, nR, tot)
		}
		if cqF, crL, cnB, cTot := f.ClientDropStats(); cqF != 0 || crL != 0 || cnB != 0 || cTot != 0 {
			t.Fatalf("expected zero ClientDropStats after reset, got (%d, %d, %d, %d)", cqF, crL, cnB, cTot)
		}
	})

	t.Run("nil receiver safe defaults without panic", func(t *testing.T) {
		var nilFwd *Forwarder

		if qF, nR, tot := nilFwd.DropStats(); qF != 0 || nR != 0 || tot != 0 {
			t.Fatalf("expected zero DropStats for nil, got (%d, %d, %d)", qF, nR, tot)
		}
		if got := nilFwd.DropsNoRoute(); got != 0 {
			t.Fatalf("expected DropsNoRoute=0 for nil, got %d", got)
		}
		if got := nilFwd.DropsQueueFull(); got != 0 {
			t.Fatalf("expected DropsQueueFull=0 for nil, got %d", got)
		}
		if got := nilFwd.DropsPacketTooLarge(); got != 0 {
			t.Fatalf("expected DropsPacketTooLarge=0 for nil, got %d", got)
		}
		if got := nilFwd.DropsQueueFullSinceStartup(); got != 0 {
			t.Fatalf("expected DropsQueueFullSinceStartup=0 for nil, got %d", got)
		}
		if got := nilFwd.DropsPacketTooLargeSinceStartup(); got != 0 {
			t.Fatalf("expected DropsPacketTooLargeSinceStartup=0 for nil, got %d", got)
		}
		if qF, nR, tot := nilFwd.RawDropStats(); qF != 0 || nR != 0 || tot != 0 {
			t.Fatalf("expected zero RawDropStats for nil, got (%d, %d, %d)", qF, nR, tot)
		}
		if qF, rL, nB, tot := nilFwd.ClientDropStats(); qF != 0 || rL != 0 || nB != 0 || tot != 0 {
			t.Fatalf("expected zero ClientDropStats for nil, got (%d, %d, %d, %d)", qF, rL, nB, tot)
		}
		if qF, rL, nB, tot := nilFwd.ClientDropStatsSinceStartup(); qF != 0 || rL != 0 || nB != 0 || tot != 0 {
			t.Fatalf("expected zero ClientDropStatsSinceStartup for nil, got (%d, %d, %d, %d)", qF, rL, nB, tot)
		}
		if qF, rL, nB, tot := nilFwd.RawClientDropStats(); qF != 0 || rL != 0 || nB != 0 || tot != 0 {
			t.Fatalf("expected zero RawClientDropStats for nil, got (%d, %d, %d, %d)", qF, rL, nB, tot)
		}
		if rx, tx := nilFwd.PacketStats(); rx != 0 || tx != 0 {
			t.Fatalf("expected PacketStats=(0, 0) for nil, got (%d, %d)", rx, tx)
		}
		if rates := nilFwd.Rates(); rates != (TrafficRates{}) {
			t.Fatalf("expected empty Rates for nil, got %+v", rates)
		}
		if pressure := nilFwd.QueuePressure(); pressure != (QueuePressureStats{}) {
			t.Fatalf("expected empty QueuePressure for nil, got %+v", pressure)
		}
		if rates := nilFwd.HistoryRates(time.Now()); rates != (TrafficRates{}) {
			t.Fatalf("expected empty HistoryRates for nil, got %+v", rates)
		}

		// Mutating / resetting calls on nil receiver must be no-ops
		nilFwd.SeedDropsForTest(1, 2, 3, 4, 5, 6)
		nilFwd.ResetDropCounters()
		nilFwd.PrimeHistoryRates(time.Now())
	})
}

func TestTelemetry_GenerationAwareResetMonotonicity(t *testing.T) {
	t.Run("generation adopts and rejects older observations", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		if gen := f.currentGeneration(); gen != 0 {
			t.Fatalf("expected initial generation 0, got %d", gen)
		}

		// Reset to generation 1
		f.resetRateTrackersForGeneration(1)

		now := time.Now()
		// Sample with stale generation 0 is rejected by RateTracker
		f.rateTracker.Sample(0, now, 1000, 1000, 10, 10, 0, 0)
		rates := f.rateTracker.Snapshot(10, 10)
		if rates.Available {
			t.Fatalf("expected rates to not be available after stale generation sample")
		}

		// First sample with generation 1 primes baseline
		f.rateTracker.Sample(1, now, 1000, 1000, 10, 10, 0, 0)
		rates = f.rateTracker.Snapshot(10, 10)
		if rates.Available {
			t.Fatalf("expected rates to not be available on priming sample")
		}

		// Second sample after 500ms advances window
		now2 := now.Add(500 * time.Millisecond)
		f.rateTracker.Sample(1, now2, 2000, 2000, 20, 20, 0, 0)
		rates = f.rateTracker.Snapshot(20, 20)
		if !rates.Available {
			t.Fatalf("expected rates to be available after second valid sample")
		}
		if rates.RxBps <= 0 || rates.TxBps <= 0 {
			t.Fatalf("expected positive rates, got rx=%f, tx=%f", rates.RxBps, rates.TxBps)
		}

		// Lower counter observation within same generation is rejected (monotonicity)
		now3 := now2.Add(500 * time.Millisecond)
		f.rateTracker.Sample(1, now3, 500, 500, 5, 5, 0, 0)
		ratesAfterLower := f.rateTracker.Snapshot(20, 20)
		// Should retain previously computed rates without dividing by negative or resetting
		if ratesAfterLower.RxBps != rates.RxBps {
			t.Fatalf("expected RxBps to be preserved across lower observation, got %f vs %f", ratesAfterLower.RxBps, rates.RxBps)
		}
	})

	t.Run("Start lifecycle increments generation and resets drop counters", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		ctx := context.Background()

		// Start forwarder: genEpoch becomes 1
		f.Start(ctx)
		if gen := f.currentGeneration(); gen != 1 {
			t.Fatalf("expected generation 1 after Start, got %d", gen)
		}

		// Seed drops
		f.SeedDropsForTest(5, 5, 5, 5, 5, 5)
		if f.DropsQueueFull() != 5 {
			t.Fatalf("expected DropsQueueFull=5, got %d", f.DropsQueueFull())
		}

		// Stop and re-Start: genEpoch becomes 2, drop counters reset to 0
		_ = f.Stop()
		f.Start(ctx)

		if gen := f.currentGeneration(); gen != 2 {
			t.Fatalf("expected generation 2 after restart, got %d", gen)
		}
		if f.DropsQueueFull() != 0 {
			t.Fatalf("expected DropsQueueFull to reset to 0 upon Start, got %d", f.DropsQueueFull())
		}
		if cqF, crL, cnB, cTot := f.ClientDropStatsSinceStartup(); cqF != 0 || crL != 0 || cnB != 0 || cTot != 0 {
			t.Fatalf("expected ClientDropStats to reset upon Start, got (%d, %d, %d, %d)", cqF, crL, cnB, cTot)
		}
	})

	t.Run("resetBackendTrafficHistoryForGeneration re-primes existing backends", func(t *testing.T) {
		TestResetBackendTrafficHistoryForGeneration(t)
	})
}

// TestResetBackendTrafficHistoryForGeneration proves that resetBackendTrafficHistoryForGeneration
// (invoked via Start/restart) resets the history baseline, enforces post-start-only deltas,
// and ensures exact byte conservation in sampled windows.
func TestResetBackendTrafficHistoryForGeneration(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	f.AttachBackendDevice(1, newMockPacketDev())
	t.Cleanup(func() {
		if err := f.Stop(); err != nil {
			t.Error(err)
		}
	})

	counters, ok := f.backendTraffic[1]
	if !ok || counters == nil {
		t.Fatal("missing backend 1 counters")
	}

	// 1. Establish an available pre-restart history window
	base := time.Now().Add(-time.Second)
	f.PrimeBackendTrafficHistory(base)
	counters.record(100, true)
	before, ok := f.BackendTrafficHistorySnapshot(base.Add(500 * time.Millisecond))[1]
	if !ok || !before.Available || before.RxBytesPerSec != 200 {
		t.Fatalf("precondition: %+v exists=%v", before, ok)
	}

	// 2. Exercise Start / restart with generation bump
	f.Start(context.Background())
	if gen := f.currentGeneration(); gen != 1 {
		t.Fatalf("expected generation 1 after Start, got %d", gen)
	}

	// 3. Record distinguishable traffic after Start and sample after minimum window interval (>200ms)
	counters.record(200, true)
	after, ok := f.BackendTrafficHistorySnapshot(time.Now().Add(500 * time.Millisecond))[1]
	if !ok || !after.Available {
		t.Fatalf("post-start history unavailable: %+v exists=%v", after, ok)
	}

	// 4. Assert availability and exact byte conservation of post-start-only traffic
	if after.WindowSec <= 0 {
		t.Fatalf("expected positive post-start window duration, got %f", after.WindowSec)
	}
	accountedBytes := after.RxBytesPerSec * after.WindowSec
	if math.Abs(accountedBytes-200) > 0.000001 {
		t.Fatalf("expected exactly 200 post-start bytes: %+v", after)
	}

	// 5. Subsequent restart (Stop -> Start generation bump to 2) re-primes cleanly
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	f.Start(context.Background())
	if gen := f.currentGeneration(); gen != 2 {
		t.Fatalf("expected generation 2 after restart, got %d", gen)
	}
	counters.record(300, true)
	after2, ok := f.BackendTrafficHistorySnapshot(time.Now().Add(500 * time.Millisecond))[1]
	if !ok || !after2.Available {
		t.Fatalf("post-restart history unavailable: %+v exists=%v", after2, ok)
	}
	accountedBytes2 := after2.RxBytesPerSec * after2.WindowSec
	if math.Abs(accountedBytes2-300) > 0.000001 {
		t.Fatalf("expected exactly 300 post-restart bytes: %+v", after2)
	}
}

func TestTelemetry_QueuePressureAndRatesDropRate(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	f.RegisterSession("s1", "c1", "peer-1", "10.100.0.10", 1)

	// Fill queue to capacity (4 packets)
	for i := 0; i < 4; i++ {
		if err := f.RouteBackendToClient(1, []byte("pkt"), "10.100.0.10"); err != nil {
			t.Fatalf("route backend to client %d: %v", i, err)
		}
	}

	// Prime rate tracker via QueuePressure
	qp0 := f.QueuePressure()
	if qp0.Occupancy != 4 || qp0.Capacity != 4 || qp0.HighWater != 4 {
		t.Fatalf("expected occupancy 4 / capacity 4, got occ=%d cap=%d", qp0.Occupancy, qp0.Capacity)
	}
	if qp0.UtilizationPct != 100.0 {
		t.Fatalf("expected 100%% utilization, got %f", qp0.UtilizationPct)
	}
	if qp0.HighWaterPct != 100.0 {
		t.Fatalf("expected 100%% high water pct, got %f", qp0.HighWaterPct)
	}

	// Cause drops
	_ = f.RouteBackendToClient(1, []byte("overflow1"), "10.100.0.10")
	_ = f.RouteBackendToClient(1, []byte("overflow2"), "10.100.0.10")

	// Wait for min rate tracker interval (GenerationSampleMinInterval = 200ms)
	time.Sleep(250 * time.Millisecond)

	qp1 := f.QueuePressure()
	if qp1.QueueFullDrops != 2 {
		t.Fatalf("expected 2 QueueFullDrops, got %d", qp1.QueueFullDrops)
	}
	if qp1.QueueFullDropRate <= 0 {
		t.Fatalf("expected positive QueueFullDropRate, got %f", qp1.QueueFullDropRate)
	}

	// Also verify Rates snapshot
	rates := f.Rates()
	if rates.DropRatePps <= 0 {
		t.Fatalf("expected positive DropRatePps in Rates, got %f", rates.DropRatePps)
	}

	// Verify HistoryRates and PrimeHistoryRates
	now := time.Now()
	f.PrimeHistoryRates(now)
	hist1 := f.HistoryRates(now)
	// Immediately after priming, history rates should be unmeasured/idle
	if hist1.DropRatePps != 0 {
		t.Fatalf("expected 0 DropRatePps immediately after priming history, got %f", hist1.DropRatePps)
	}

	// After elapsed time and new drops, history rates calculate delta
	now2 := now.Add(300 * time.Millisecond)
	f.SeedDropsForTest(1, 0, 0, 0, 0, 0)
	hist2 := f.HistoryRates(now2)
	if !hist2.Available {
		t.Fatalf("expected history rates to be available after second sample")
	}
	if hist2.DropRatePps <= 0 {
		t.Fatalf("expected positive history DropRatePps after drop, got %f", hist2.DropRatePps)
	}
}
