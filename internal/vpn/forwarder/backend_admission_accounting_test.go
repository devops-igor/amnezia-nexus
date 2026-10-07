package forwarder

import (
	"testing"
	"time"
)

// TestBackendQueueFullPacketIsNotCountedAsAdmittedThroughput is the required
// regression for issue #424 round 3, finding 2.
//
// The defect: routeClientToBackend incremented totalRxBytes/totalRxPackets,
// route.traffic, backendTraffic and the accountant BEFORE attempting the
// backend-queue send. A packet refused with ErrQueueFull never entered the
// backend queue, so per-backend diagnostics could report "+1500 bytes carried"
// together with "queue-full +1" for one and the same packet the backend never
// accepted. That defeats #432's purpose ("how much traffic each backend is
// actually carrying") and, because route.traffic.record also advances the
// route's last-traffic stamp (#433), it reset "last seen" for a route that
// carried nothing.
//
// The regression fills the backend queue for real, forces a genuine
// ErrQueueFull, and asserts the accounting did NOT move for the rejected
// packet while the drop counters DID.
//
// The last-traffic half needs the pre-rejection stamp to be measurably old,
// otherwise "unchanged" and "reset to now" are indistinguishable: a stamp of
// zero seconds either means "the rejected packet refreshed it" or "the
// fixture never set one". Sleeping past a whole second makes the two
// outcomes distinguishable, so this assertion cannot pass vacuously.
func TestBackendQueueFullPacketIsNotCountedAsAdmittedThroughput(t *testing.T) {
	accountant := NewTrafficAccountant(nil, 0)
	fwd := NewForwarder(accountant, "10.100.0.0/16", 1)

	const (
		peerKey    = "peer-admission"
		backendID  = int64(700)
		packetSize = 100
	)
	fwd.RegisterSession("sess-admission", "conn-admission", peerKey, "10.100.0.21", backendID)

	// The forwarder is never Started, so no backend pump drains the queue:
	// filling it here fills it for the duration of the test.
	pkt := make([]byte, packetSize)
	for i := range DefaultBackendQueueSize {
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("packet %d of %d should be admitted: %v", i+1, DefaultBackendQueueSize, err)
		}
	}

	rxBytesBefore, _, _ := fwd.GetStats()
	rxPacketsBefore, _ := fwd.PacketStats()
	backendBefore := backendSnapshotFor(t, fwd, backendID)
	routeBefore := routeSnapshotFor(t, fwd, peerKey)
	if routeBefore.lastTrafficAgeSec < 0 {
		t.Fatal("the admitted packets must have stamped the route's last-traffic time; the fixture recorded nothing")
	}

	// Let the admitted traffic age past a whole second so a stamp refreshed by
	// the rejected packet is unambiguously distinguishable from an untouched one.
	time.Sleep(1100 * time.Millisecond)

	// Read the stamp back AFTER ageing it, so the age this test reasons about
	// is the one in force at the moment the rejected packet is offered.
	agedAge := routeSnapshotFor(t, fwd, peerKey).lastTrafficAgeSec
	if agedAge < 1 {
		t.Fatalf("fixture is broken: the admitted traffic must be at least a second old before the rejected packet, got age=%ds; "+
			"an age of 0 afterwards would be ambiguous between \"the refused packet reset it\" and \"nothing was ever stamped\"",
			agedAge)
	}

	// The next packet cannot be admitted: the backend queue is exactly full.
	rejected := make([]byte, packetSize)
	if err := fwd.RouteClientToBackend(peerKey, rejected); err != ErrQueueFull {
		t.Fatalf("a full backend queue must refuse the next packet with ErrQueueFull, got %v: this test cannot prove admission-only accounting without a real refusal", err)
	}

	// --- Throughput accounting must NOT move for the rejected packet ---
	rxBytesAfter, _, _ := fwd.GetStats()
	if got := rxBytesAfter - rxBytesBefore; got != 0 {
		t.Errorf("backend RX bytes rose by %d for a packet refused with ErrQueueFull: refused traffic is being reported as carried throughput", got)
	}
	rxPacketsAfter, _ := fwd.PacketStats()
	if got := rxPacketsAfter - rxPacketsBefore; got != 0 {
		t.Errorf("backend RX packets rose by %d for a packet refused with ErrQueueFull", got)
	}

	backendAfter := backendSnapshotFor(t, fwd, backendID)
	if backendAfter.rxBytes != backendBefore.rxBytes {
		t.Errorf("per-backend traffic rx_bytes moved %d -> %d for a refused packet",
			backendBefore.rxBytes, backendAfter.rxBytes)
	}
	if backendAfter.rxPackets != backendBefore.rxPackets {
		t.Errorf("per-backend traffic rx_packets moved %d -> %d for a refused packet",
			backendBefore.rxPackets, backendAfter.rxPackets)
	}

	routeAfter := routeSnapshotFor(t, fwd, peerKey)
	if routeAfter.rxBytes != routeBefore.rxBytes || routeAfter.rxPackets != routeBefore.rxPackets {
		t.Errorf("route traffic moved (rx %d/%d -> %d/%d) for a refused packet",
			routeBefore.rxBytes, routeBefore.rxPackets, routeAfter.rxBytes, routeAfter.rxPackets)
	}
	// #433: lastTraffic must advance only on a routed packet. The stamp was
	// already %ds old when the packet was refused, so an age of 0 afterwards
	// can only mean the refused packet refreshed it.
	if routeAfter.lastTrafficAgeSec < agedAge {
		t.Errorf("last_traffic_age_sec went %d -> %d across a refused packet: the refused packet reset the route's last-seen stamp",
			agedAge, routeAfter.lastTrafficAgeSec)
	}

	// --- The loss must still be fully accounted for as a loss ---
	queueFull, _, _, dropTotal := fwd.ClientDropStats()
	if queueFull != 1 {
		t.Errorf("clientDropsQueueFull=%d, want 1: the refused packet must remain visible as loss", queueFull)
	}
	if dropTotal != 1 {
		t.Errorf("clientDropsTotal=%d, want 1: refusing to count refused traffic as throughput must not lose it from accounting", dropTotal)
	}
}

// routeAccounting is the slice of a route's accounting this regression reads.
type routeAccounting struct {
	rxBytes, rxPackets int64
	lastTrafficAgeSec  int64
}

// backendAccounting is the slice of a backend's accounting this regression reads.
type backendAccounting struct {
	rxBytes, rxPackets int64
}

func routeSnapshotFor(t *testing.T, fwd *Forwarder, peerKey string) routeAccounting {
	t.Helper()
	for _, r := range fwd.InspectRoutes() {
		if r.PeerKey != peerKey {
			continue
		}
		return routeAccounting{
			rxBytes:           r.Traffic.RxBytes,
			rxPackets:         int64(r.Traffic.RxPackets),
			lastTrafficAgeSec: r.LastTrafficAgeSec,
		}
	}
	t.Fatalf("route %q vanished from InspectRoutes: the fixture is broken", peerKey)
	return routeAccounting{}
}

func backendSnapshotFor(t *testing.T, fwd *Forwarder, backendID int64) backendAccounting {
	t.Helper()
	snap, ok := fwd.BackendTrafficSnapshot()[backendID]
	if !ok {
		t.Fatalf("backend %d has no traffic snapshot: the fixture registered no traffic for it", backendID)
	}
	return backendAccounting{rxBytes: snap.RxBytes, rxPackets: int64(snap.RxPackets)}
}
