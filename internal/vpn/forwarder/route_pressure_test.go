package forwarder

import (
	"math"
	"testing"
	"time"
)

func TestRoutePressureWindowCalculatesDropRateFromElapsedTime(t *testing.T) {
	base := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	var w routePressureWindow

	// 1. Priming sample records baseline and reports zero rate and zero recent drops.
	snap0 := w.sample(base, 10, 2, 1)
	if snap0.DropRatePPS != 0 || snap0.QueueFullDropsRecent != 0 || snap0.ElapsedSec != 0 {
		t.Fatalf("priming sample must have zero drop rate and recent drops, got %+v", snap0)
	}

	// 2. 500ms later: 20 drops occurred (delta = 10 drops over 0.5s -> 20.0 drops/s).
	t1 := base.Add(500 * time.Millisecond)
	snap1 := w.sample(t1, 20, 2, 1)
	if snap1.QueueFullDropsRecent != 10 {
		t.Fatalf("expected 10 recent drops, got %d", snap1.QueueFullDropsRecent)
	}
	if math.Abs(snap1.ElapsedSec-0.5) > 1e-6 {
		t.Fatalf("expected ElapsedSec 0.5, got %f", snap1.ElapsedSec)
	}
	expectedRate1 := 10.0 / 0.5 // 20.0 drops/s
	if math.Abs(snap1.DropRatePPS-expectedRate1) > 1e-6 {
		t.Fatalf("expected DropRatePPS %f, got %f", expectedRate1, snap1.DropRatePPS)
	}

	// 3. Immediate re-read within 200ms sample floor returns previous drop rate and delta unchanged.
	tImmediate := t1.Add(50 * time.Millisecond)
	snapImmediate := w.sample(tImmediate, 35, 5, 2)
	if snapImmediate.QueueFullDropsRecent != 10 || math.Abs(snapImmediate.DropRatePPS-expectedRate1) > 1e-6 {
		t.Fatalf("sample within floor must return previous delta and rate, got %+v", snapImmediate)
	}

	// 4. 2 seconds after t1: 5 new drops occurred (delta = 5 drops over 2.0s -> 2.5 drops/s).
	t2 := t1.Add(2 * time.Second)
	snap2 := w.sample(t2, 25, 2, 1)
	if snap2.QueueFullDropsRecent != 5 {
		t.Fatalf("expected 5 recent drops, got %d", snap2.QueueFullDropsRecent)
	}
	if math.Abs(snap2.ElapsedSec-2.0) > 1e-6 {
		t.Fatalf("expected ElapsedSec 2.0, got %f", snap2.ElapsedSec)
	}
	expectedRate2 := 5.0 / 2.0 // 2.5 drops/s
	if math.Abs(snap2.DropRatePPS-expectedRate2) > 1e-6 {
		t.Fatalf("expected DropRatePPS %f, got %f", expectedRate2, snap2.DropRatePPS)
	}

	// 5. 1 second after t2 with 0 new drops: rate must be 0.
	t3 := t2.Add(1 * time.Second)
	snap3 := w.sample(t3, 25, 2, 1)
	if snap3.QueueFullDropsRecent != 0 || snap3.DropRatePPS != 0 {
		t.Fatalf("expected 0 drops and 0 rate, got %+v", snap3)
	}

	// 6. Counter decrease (route generation replaced): must contribute 0 rate.
	t4 := t3.Add(1 * time.Second)
	snap4 := w.sample(t4, 5, 2, 1)
	if snap4.QueueFullDropsRecent != 0 || snap4.DropRatePPS != 0 {
		t.Fatalf("expected 0 drops and 0 rate on counter reset, got %+v", snap4)
	}
}

func TestInspectRoutesPopulatesQueueFullDropRatePPS(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.RegisterSession("s1", "c1", "peer-droprate", "10.100.0.3", 1)

	// Prime
	routes := f.InspectRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Stats.QueueFullDropRatePPS != 0 {
		t.Fatalf("primed route must have 0 drop rate, got %f", routes[0].Stats.QueueFullDropRatePPS)
	}

	// Advance past routePressureSampleInterval
	time.Sleep(routePressureSampleInterval + 25*time.Millisecond)

	// Simulate queue full drops
	f.mu.RLock()
	route := f.routesByPeer["peer-droprate"]
	route.queueFullDrops.Add(20)
	f.mu.RUnlock()

	// Inspect again: QueueFullDropRatePPS must be populated from pressure window
	routes = f.InspectRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	r := routes[0]
	if r.Stats.QueueFullDropsRecent != 20 {
		t.Fatalf("expected 20 recent drops, got %d", r.Stats.QueueFullDropsRecent)
	}
	if r.Stats.QueueFullDropRatePPS <= 0 {
		t.Fatalf("expected positive QueueFullDropRatePPS, got %f", r.Stats.QueueFullDropRatePPS)
	}
}
