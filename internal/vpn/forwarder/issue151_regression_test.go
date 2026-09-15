package forwarder

import (
	"testing"
)

// TestDefaultClientQueueSize_Capacity verifies that the forwarder default queue
// depth is 2048 packets (issue #151) and that NewForwarder creates routes with that capacity.
func TestDefaultClientQueueSize_Capacity(t *testing.T) {
	if DefaultClientQueueSize != 2048 {
		t.Fatalf("DefaultClientQueueSize = %d, want 2048", DefaultClientQueueSize)
	}

	f := NewForwarder(nil, "10.100.0.0/16")
	f.RegisterSession("s-1", "c-1", "peer-1", "10.100.0.5", 1)

	ch, ok := f.GetClientPacketChannel("peer-1")
	if !ok || ch == nil {
		t.Fatal("expected registered client queue")
	}
	if cap(ch) != DefaultClientQueueSize {
		t.Fatalf("client queue capacity = %d, want %d", cap(ch), DefaultClientQueueSize)
	}
}

// TestDownstreamQueueBurstAbsorption verifies that a 2000-packet microburst is absorbed
// without packet loss by the 2048-packet queue, whereas a 256-packet queue drops 1744 packets (issue #151).
func TestDownstreamQueueBurstAbsorption(t *testing.T) {
	// 1. Forwarder with default 2048-packet queue:
	fEnlarged := NewForwarder(nil, "10.100.0.0/16")
	fEnlarged.RegisterSession("s-1", "c-1", "peer-1", "10.100.0.10", 1)

	burstCount := 2000
	pkt := ipv4Packet([4]byte{10, 100, 0, 10})

	for i := 0; i < burstCount; i++ {
		if err := fEnlarged.RouteBackendToClient(1, pkt, "10.100.0.10"); err != nil {
			t.Fatalf("unexpected drop in enlarged queue at packet %d: %v", i, err)
		}
	}

	qf, noRoute, total := fEnlarged.DropStats()
	if qf != 0 || noRoute != 0 || total != 0 {
		t.Fatalf("expected 0 drops in 2048 queue, got qf=%d, noRoute=%d, total=%d", qf, noRoute, total)
	}

	ch, _ := fEnlarged.GetClientPacketChannel("peer-1")
	if len(ch) != burstCount {
		t.Fatalf("queued packet count = %d, want %d", len(ch), burstCount)
	}

	// 2. Constrained forwarder (legacy 256-packet queue):
	fLegacy := NewForwarder(nil, "10.100.0.0/16", 256)
	fLegacy.RegisterSession("s-legacy", "c-legacy", "peer-legacy", "10.100.0.20", 1)

	legacyDrops := 0
	for i := 0; i < burstCount; i++ {
		if err := fLegacy.RouteBackendToClient(1, pkt, "10.100.0.20"); err != nil {
			if err == ErrQueueFull {
				legacyDrops++
			} else {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	}

	expectedDrops := burstCount - 256
	if legacyDrops != expectedDrops {
		t.Fatalf("legacy queue drops = %d, want %d", legacyDrops, expectedDrops)
	}

	lQf, lNoRoute, lTotal := fLegacy.DropStats()
	if lQf != uint64(expectedDrops) || lNoRoute != 0 || lTotal != uint64(expectedDrops) {
		t.Fatalf("legacy DropStats = (%d, %d, %d), want (%d, 0, %d)", lQf, lNoRoute, lTotal, expectedDrops, expectedDrops)
	}
	if fLegacy.DropsQueueFull() != uint64(expectedDrops) {
		t.Fatalf("DropsQueueFull = %d, want %d", fLegacy.DropsQueueFull(), expectedDrops)
	}
}

// TestDropCounterMetrics_QueueFullAndUnroutable verifies that:
// 1. Packets for unroutable destination IPs increment dropsNoRoute and dropsTotal.
// 2. Packets hitting full queues increment dropsQueueFull and dropsTotal.
// 3. DropStats, DropsNoRoute, and DropsQueueFull report exact counts.
func TestDropCounterMetrics_QueueFullAndUnroutable(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	f.RegisterSession("s-1", "c-1", "peer-1", "10.100.0.30", 1)

	pkt := ipv4Packet([4]byte{10, 100, 0, 30})
	unroutablePkt := ipv4Packet([4]byte{10, 100, 0, 99})

	// Part A: 5 unroutable packets
	for i := 0; i < 5; i++ {
		err := f.RouteBackendToClient(1, unroutablePkt, "10.100.0.99")
		if err != ErrSessionNotRegistered {
			t.Fatalf("RouteBackendToClient unroutable = %v, want ErrSessionNotRegistered", err)
		}
	}

	if nr := f.DropsNoRoute(); nr != 5 {
		t.Fatalf("DropsNoRoute() = %d, want 5", nr)
	}
	if qf := f.DropsQueueFull(); qf != 0 {
		t.Fatalf("DropsQueueFull() = %d, want 0", qf)
	}
	qf, nr, total := f.DropStats()
	if qf != 0 || nr != 5 || total != 5 {
		t.Fatalf("DropStats() = (%d, %d, %d), want (0, 5, 5)", qf, nr, total)
	}

	// Part B: Fill queue (capacity 4) and then cause 3 queue-full drops
	for i := 0; i < 4; i++ {
		if err := f.RouteBackendToClient(1, pkt, "10.100.0.30"); err != nil {
			t.Fatalf("unexpected error filling queue at %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		err := f.RouteBackendToClient(1, pkt, "10.100.0.30")
		if err != ErrQueueFull {
			t.Fatalf("RouteBackendToClient queue full = %v, want ErrQueueFull", err)
		}
	}

	if nr := f.DropsNoRoute(); nr != 5 {
		t.Fatalf("DropsNoRoute() = %d, want 5", nr)
	}
	if qf := f.DropsQueueFull(); qf != 3 {
		t.Fatalf("DropsQueueFull() = %d, want 3", qf)
	}
	qf, nr, total = f.DropStats()
	if qf != 3 || nr != 5 || total != 8 {
		t.Fatalf("DropStats() = (%d, %d, %d), want (3, 5, 8)", qf, nr, total)
	}
}
