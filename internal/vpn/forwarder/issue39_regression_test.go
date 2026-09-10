package forwarder

import (
	"sync"
	"testing"
	"time"
)

// gatedDevice is a PacketDevice whose Write blocks until the device is
// closed; it records every frame written to it. It models a slow downstream
// consumer (e.g. SendToPeer blocked on a contended lock or a slow UDP write)
// that later recovers: closing the device opens the gate and releases any
// in-flight Write, so StopPumps can always complete.
type gatedDevice struct {
	mu       sync.Mutex
	gate     chan struct{}
	openOnce sync.Once
	frames   [][]byte
}

func newGatedDevice() *gatedDevice { return &gatedDevice{gate: make(chan struct{})} }

func (g *gatedDevice) Read(p []byte) (int, error) { return 0, nil }
func (g *gatedDevice) Close() error {
	g.openOnce.Do(func() { close(g.gate) })
	return nil
}
func (g *gatedDevice) Write(p []byte) (int, error) {
	<-g.gate
	g.mu.Lock()
	g.frames = append(g.frames, append([]byte(nil), p...))
	g.mu.Unlock()
	return len(p), nil
}
func (g *gatedDevice) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.frames)
}

func ipv4Packet(dst [4]byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[16], pkt[17], pkt[18], pkt[19] = dst[0], dst[1], dst[2], dst[3]
	return pkt
}

// TestQueueFullRecoversAfterConsumerStall pins the primary defect of issue
// #39: a registered route whose consumer stalls during a burst must resume
// draining once the consumer recovers. In production a route whose queue
// stayed full for ~2 hours (7687 "packet queue is full" drops) while the
// route remained registered means the pump was permanently gone or wedged —
// with a live pump this test's invariant (full drain after recovery) holds.
func TestQueueFullRecoversAfterConsumerStall(t *testing.T) {
	f := NewForwarder(nil, 64)
	defer f.StopPumps()

	dev := newGatedDevice()
	defer dev.Close() // runs before StopPumps: releases a blocked Write
	f.AttachPeerDevice("peer-a", dev)
	f.StartPumps(t.Context())
	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.100.0.3", 1)

	pkt := ipv4Packet([4]byte{10, 100, 0, 3})

	// Page-load burst while the consumer is stalled: packets beyond the
	// queue capacity (+1 in flight at the blocked pump) are dropped with
	// ErrQueueFull — bounded backpressure, never a silent discard. The
	// queue must hold everything else for the still-registered route.
	dropped := 0
	for i := 0; i < 300; i++ {
		if err := f.RouteBackendToClient(1, pkt, "10.100.0.3"); err != nil {
			dropped++
		}
	}
	if dropped > 300-65 {
		t.Fatalf("stalled-consumer burst dropped %d packets, queue should have buffered at least 65", dropped)
	}

	// Consumer recovers: the pump must drain everything it accepted.
	_ = dev.Close()
	want := 300 - dropped
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.count() < want {
		time.Sleep(10 * time.Millisecond)
	}
	if dev.count() < want {
		t.Fatalf("queue did not drain after consumer recovery: written=%d, want=%d (dropped=%d)", dev.count(), want, dropped)
	}
	// Every drop must be counted (feeding the stats API), never silent.
	qf, total := f.DropStats()
	if qf != uint64(dropped) || total != uint64(dropped) {
		t.Fatalf("DropStats = (queueFull=%d, total=%d), want (%d, %d)", qf, total, dropped, dropped)
	}
}

// TestReregisteredRouteSurvivesLateUnregister pins the routesByIP/session-
// lifecycle defect of issue #39: when a session is re-registered for the same
// peer key (client rekey/reconnect) and the OLD session's teardown arrives
// late (reaper/API race), the teardown must not kill the NEW route — neither
// in routesByPeer/routesByIP nor its pump. Before the fix, the late
// UnregisterSession deleted the re-registered route: return traffic then got
// ErrSessionNotRegistered forever (session shows CONNECTED, pages time out).
func TestReregisteredRouteSurvivesLateUnregister(t *testing.T) {
	f := NewForwarder(nil, 64)
	defer f.StopPumps()

	dev := newGatedDevice()
	defer dev.Close()
	_ = dev.Close() // consumer healthy for the whole test
	f.AttachPeerDevice("peer-a", dev)
	f.StartPumps(t.Context())

	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.100.0.3", 1)
	// Rekey/reconnect: a new session for the same peer re-registers the route
	// (RegisterSession stops the old pump and replaces the route objects).
	f.RegisterSession("sess-2", "conn-2", "peer-a", "10.100.0.3", 1)
	// The OLD session's teardown arrives late.
	f.UnregisterSession("peer-a")

	// The NEW route must still carry return traffic.
	if err := f.RouteBackendToClient(1, ipv4Packet([4]byte{10, 100, 0, 3}), "10.100.0.3"); err != nil {
		t.Fatalf("return traffic for re-registered route dropped: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if dev.count() < 1 {
		t.Fatal("re-registered route pump never delivered the return packet")
	}
}

// TestStaleRouteCannotCaptureReturnTraffic pins the routesByIP lifetime rule:
// after a session closes, a later session reusing the same IP must receive
// the return traffic. Between the close and the re-open, packets for the
// (now absent) IP must be rejected as unregistered — never silently buffered
// into a stale route that would replay them into the wrong session.
func TestStaleRouteCannotCaptureReturnTraffic(t *testing.T) {
	f := NewForwarder(nil, 64)
	defer f.StopPumps()

	oldDev, newDev := newGatedDevice(), newGatedDevice()
	defer oldDev.Close()
	defer newDev.Close()
	_ = oldDev.Close() // healthy consumer
	_ = newDev.Close()
	f.StartPumps(t.Context())

	f.AttachPeerDevice("peer-old", oldDev)
	f.RegisterSession("sess-1", "conn-1", "peer-old", "10.100.0.7", 1)

	// Close the session (its route is unregistered)...
	f.UnregisterSession("peer-old")

	// ...while return packets for the IP keep arriving from the backend.
	pkt := ipv4Packet([4]byte{10, 100, 0, 7})
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.7"); err != ErrSessionNotRegistered {
		t.Fatalf("return traffic after close: got %v, want ErrSessionNotRegistered", err)
	}

	// A NEW session (new peer key) reuses the same IP.
	f.AttachPeerDevice("peer-new", newDev)
	f.RegisterSession("sess-2", "conn-2", "peer-new", "10.100.0.7", 1)

	// Return traffic must reach the NEW session only.
	for i := 0; i < 10; i++ {
		if err := f.RouteBackendToClient(1, pkt, "10.100.0.7"); err != nil {
			t.Fatalf("return traffic to reopened session dropped: %v", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && newDev.count() < 10 {
		time.Sleep(10 * time.Millisecond)
	}
	if newDev.count() < 10 {
		t.Fatalf("new session did not receive return traffic: got %d/10", newDev.count())
	}
	if oldDev.count() != 0 {
		t.Fatalf("stale session device received %d packets after close", oldDev.count())
	}
}

// TestRouteRegisteredBeforeStartPumpsGetsPump pins the pump lifecycle gap:
// routes registered while pumps are NOT running must start their pump when
// StartPumps is eventually called. (RegisterSession only started a pump when
// f.pumpsRunning was already true; the Service.Start() ordering hole left
// such routes permanently pumpless — queue full for hours at a time.)
func TestRouteRegisteredBeforeStartPumpsGetsPump(t *testing.T) {
	f := NewForwarder(nil, 64)
	defer f.StopPumps()

	dev := newGatedDevice()
	defer dev.Close()
	_ = dev.Close()
	f.AttachPeerDevice("peer-a", dev)
	// Registration happens BEFORE StartPumps (e.g. sessions restored from DB
	// during startup, or StartPumps skipped by a failed partial start).
	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.100.0.3", 1)
	f.StartPumps(t.Context())

	if err := f.RouteBackendToClient(1, ipv4Packet([4]byte{10, 100, 0, 3}), "10.100.0.3"); err != nil {
		t.Fatalf("RouteBackendToClient failed: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if dev.count() < 1 {
		t.Fatal("route registered before StartPumps has no pump: packet never reached the device")
	}
}

// TestStalledRouteRecoversAfterStopStartPumps pins the recovery contract for
// the service-level Stop/Start sequence (EnableVPN/restore paths): after
// StopPumps -> StartPumps, routes registered in between (or carried across)
// must pump again. This is the operator-visible healing path for a stalled
// downstream data plane without restarting the panel process.
func TestStalledRouteRecoversAfterStopStartPumps(t *testing.T) {
	f := NewForwarder(nil, 64)
	defer f.StopPumps()

	dev := newGatedDevice()
	defer dev.Close()
	_ = dev.Close()
	f.AttachPeerDevice("peer-a", dev)

	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.100.0.3", 1)
	f.StartPumps(t.Context())

	// A service-level Stop/Start cycle (e.g. EnableVPN after UpdateConfig).
	f.StopPumps()
	f.StartPumps(t.Context())

	if err := f.RouteBackendToClient(1, ipv4Packet([4]byte{10, 100, 0, 3}), "10.100.0.3"); err != nil {
		t.Fatalf("RouteBackendToClient failed: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if dev.count() < 1 {
		t.Fatal("route pump did not recover after StopPumps/StartPumps cycle")
	}
}
