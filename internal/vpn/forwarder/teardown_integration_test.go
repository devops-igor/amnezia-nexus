package forwarder

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// captureDevice records frames written to it (implements PacketDevice).
// Thread-safe: Write is called from pump goroutines while the test reads.
type captureDevice struct {
	framesMu sync.Mutex
	frames   [][]byte
}

func (c *captureDevice) Read(p []byte) (int, error) { return 0, nil }
func (c *captureDevice) Write(p []byte) (int, error) {
	c.framesMu.Lock()
	c.frames = append(c.frames, append([]byte(nil), p...))
	c.framesMu.Unlock()
	return len(p), nil
}
func (c *captureDevice) Close() error { return nil }
func (c *captureDevice) count() int {
	c.framesMu.Lock()
	defer c.framesMu.Unlock()
	return len(c.frames)
}

func startPumpedForwarder(t *testing.T) (*Forwarder, *captureDevice, *captureDevice) {
	t.Helper()
	f := NewForwarder(nil, "10.100.0.0/16", 64)
	old, neu := &captureDevice{}, &captureDevice{}
	f.AttachBackendDevice(1, old)
	f.AttachBackendDevice(2, neu)
	f.StartPumps(t.Context())
	return f, old, neu
}

func runtimeNumGoroutine() int { return runtime.NumGoroutine() }

// waitFor polls cond until true or the deadline passes.
func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestUnregisterSession_StopsPumpGoroutine is the regression test for the
// per-session goroutine leak: UnregisterSession used to only delete map
// entries, leaving one pumpClientQueue goroutine alive per disconnected
// session until global shutdown.
func TestUnregisterSession_StopsPumpGoroutine(t *testing.T) {
	f, _, _ := startPumpedForwarder(t)
	defer f.StopPumps()

	base := runtimeNumGoroutine()
	for i := 0; i < 50; i++ {
		f.RegisterSession("sess", "conn", "peer", "10.0.0.1", 1)
		f.UnregisterSession("peer")
	}
	if !waitFor(t, func() bool { return runtimeNumGoroutine() <= base+2 }) {
		t.Fatalf("goroutine leak: base=%d now=%d after 50 register/unregister cycles", base, runtimeNumGoroutine())
	}
}

// TestUnregisteredSessionRouteRejected verifies that after teardown a late
// client packet cannot be routed: RouteClientToBackend returns
// ErrSessionNotRegistered (the route map entry is gone) instead of silently
// queueing into an abandoned backend channel.
func TestUnregisteredSessionRouteRejected(t *testing.T) {
	f, _, _ := startPumpedForwarder(t)
	defer f.StopPumps()

	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.0.0.5", 1)
	f.UnregisterSession("peer-a")

	err := f.RouteClientToBackend("peer-a", []byte{0xde, 0xad})
	if err != ErrSessionNotRegistered {
		t.Fatalf("expected ErrSessionNotRegistered after teardown, got %v", err)
	}
}

// TestUpdateSessionBackend_MigratesLiveTraffic pins the failover contract:
// after UpdateSessionBackend, client packets for the session must flow to the
// NEW backend device, not the old (detached) one. This is the exact sequence
// DisableBackend performs on failover.
func TestUpdateSessionBackend_MigratesLiveTraffic(t *testing.T) {
	f, oldBackend, newBackend := startPumpedForwarder(t)
	defer f.StopPumps()

	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.0.0.5", 1)

	pkt := []byte{0xde, 0xad, 0xbe, 0xef}

	// Sanity: traffic initially reaches the backend device attached to tunnel 1.
	if err := f.RouteClientToBackend("peer-a", pkt); err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}
	if !waitFor(t, func() bool { return oldBackend.count() > 0 }) {
		t.Fatal("packet never reached old backend")
	}

	// Failover: DisableBackend detaches the old device, then the service must
	// call UpdateSessionBackend for the session's live route.
	f.DetachBackendDevice(1)
	if err := f.UpdateSessionBackend("peer-a", 2); err != nil {
		t.Fatalf("UpdateSessionBackend failed: %v", err)
	}

	oldCount := oldBackend.count()
	newCount := newBackend.count()
	if err := f.RouteClientToBackend("peer-a", pkt); err != nil {
		t.Fatalf("RouteClientToBackend after failover failed: %v", err)
	}
	if !waitFor(t, func() bool { return newBackend.count() > newCount }) {
		t.Fatal("packet did not reach new backend after failover")
	}
	if oldBackend.count() != oldCount {
		t.Fatalf("old backend received extra packets after detach: %d -> %d", oldCount, oldBackend.count())
	}
}

// TestSessionRouteStopChannelNeverClosedQueue pins the no-panic invariant:
// teardown must not close the client queue, because RouteBackendToClient
// sends to it after releasing the read lock.
func TestSessionRouteStopChannelNeverClosedQueue(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 64)
	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.0.0.5", 1)
	route := f.routesByPeer["peer-a"]
	f.UnregisterSession("peer-a")

	// Sending to the abandoned queue after teardown must be safe (fill or
	// drop, never panic). If teardown had closed the channel this panics.
	select {
	case route.clientQueue <- []byte{1}:
	default:
	}
}

func TestRetireAllRoutes_DrainsQueuesAndJoinsWrites(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 10)
	dev := newBlockingWriteDevice()
	f.AttachPeerDevice("peer-1", dev)

	f.RegisterSession("sess-1", "conn-1", "peer-1", "10.100.0.11", 1)
	f.RegisterSession("sess-2", "conn-2", "peer-2", "10.100.0.12", 1)
	f.RegisterSession("sess-3", "conn-3", "peer-3", "10.100.0.13", 1)

	// Send packets to all three routes
	pkt := returnPacket("10.100.0.11")
	for i := 0; i < 5; i++ {
		if err := f.RouteBackendToClient(1, pkt, "10.100.0.11"); err != nil {
			t.Fatalf("RouteBackendToClient peer-1: %v", err)
		}
		if err := f.RouteBackendToClient(1, returnPacket("10.100.0.12"), "10.100.0.12"); err != nil {
			t.Fatalf("RouteBackendToClient peer-2: %v", err)
		}
		if err := f.RouteBackendToClient(1, returnPacket("10.100.0.13"), "10.100.0.13"); err != nil {
			t.Fatalf("RouteBackendToClient peer-3: %v", err)
		}
	}

	occ, _, _ := f.AggregateQueueStats()
	if occ == 0 {
		t.Fatal("expected positive aggregate queue occupancy before retirement")
	}

	// Start pumps so peer-1 begins writing and blocks in dev.Write
	f.StartPumps(t.Context())
	defer f.StopPumps()
	defer dev.release()

	select {
	case <-dev.startedC:
	case <-time.After(time.Second):
		t.Fatal("device write did not start")
	}

	// An in-flight write is now active on peer-1.
	// RetireAllRoutes must clear maps and return a wait func that joins the write outside f.mu.
	waitRetired := make(chan struct{})
	go func() {
		wait := f.RetireAllRoutes()
		_ = wait(context.Background())
		close(waitRetired)
	}()

	// Verify that wait() does not return while the write is blocked
	select {
	case <-waitRetired:
		t.Fatal("RetireAllRoutes wait returned before admitted write completed")
	case <-time.After(50 * time.Millisecond):
	}

	// While waiting, maps must already be cleared
	f.mu.RLock()
	routesCount := len(f.routesByPeer)
	ipCount := len(f.routesByIP)
	devCount := len(f.clientDevices)
	f.mu.RUnlock()
	if routesCount != 0 || ipCount != 0 || devCount != 0 {
		t.Fatalf("expected route maps to be cleared, got routes=%d ips=%d devs=%d", routesCount, ipCount, devCount)
	}

	// Unblock device write
	dev.release()

	select {
	case <-waitRetired:
	case <-time.After(time.Second):
		t.Fatal("RetireAllRoutes wait timed out after releasing device")
	}

	// Post-retirement assertions
	_, _, activeRoutes := f.GetStats()
	if activeRoutes != 0 {
		t.Fatalf("expected 0 active routes, got %d", activeRoutes)
	}
	if owner := f.ReturnRouteOwner(); owner != "none" {
		t.Fatalf("expected return route owner 'none', got %q", owner)
	}
	occAfter, _, _ := f.AggregateQueueStats()
	if occAfter != 0 {
		t.Fatalf("expected 0 aggregate queue occupancy, got %d", occAfter)
	}
	if err := f.RouteClientToBackend("peer-1", pkt); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("expected ErrSessionNotRegistered for client->backend, got %v", err)
	}
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.11"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("expected ErrSessionNotRegistered for backend->client, got %v", err)
	}
}

func TestRetireRoutesByReturnPath_SelectiveRetirement(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 10)
	beChan := make(chan []byte, 10)
	f.backendQueues[1] = beChan

	upReceived := make(chan []byte, 10)
	upPath := NewReturnPath(func(peer, ip string, p []byte) (int, error) {
		upReceived <- append([]byte(nil), p...)
		return len(p), nil
	})

	// Register 2 custom routes
	f.RegisterSession("sess-c1", "conn-c1", "peer-c1", "10.100.0.11", 1)
	f.RegisterSession("sess-c2", "conn-c2", "peer-c2", "10.100.0.12", 1)

	// Register 2 upstream routes
	if _, err := f.TryRegisterSessionWithReturnPath("sess-u1", "conn-u1", "peer-u1", "10.100.0.21", 1, 0, 0, upPath); err != nil {
		t.Fatal(err)
	}
	if _, err := f.TryRegisterSessionWithReturnPath("sess-u2", "conn-u2", "peer-u2", "10.100.0.22", 1, 0, 0, upPath); err != nil {
		t.Fatal(err)
	}

	_, _, active := f.GetStats()
	if active != 4 {
		t.Fatalf("expected 4 active routes, got %d", active)
	}
	if owner := f.ReturnRouteOwner(); owner != "mixed" {
		t.Fatalf("expected return route owner 'mixed', got %q", owner)
	}

	// Retire only upstream routes
	wait := f.RetireRoutesByReturnPath(upPath)
	_ = wait(context.Background())

	// Upstream routes are removed
	if err := f.RouteBackendToClient(1, returnPacket("10.100.0.21"), "10.100.0.21"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("expected ErrSessionNotRegistered for upstream route 1, got %v", err)
	}
	if err := f.RouteBackendToClient(1, returnPacket("10.100.0.22"), "10.100.0.22"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("expected ErrSessionNotRegistered for upstream route 2, got %v", err)
	}

	// Custom routes remain intact
	_, _, active = f.GetStats()
	if active != 2 {
		t.Fatalf("expected 2 active routes after retiring upstream, got %d", active)
	}
	if owner := f.ReturnRouteOwner(); owner != "custom" {
		t.Fatalf("expected return route owner 'custom', got %q", owner)
	}

	// Custom routes still functional
	customPkt := returnPacket("10.100.0.11")
	if err := f.RouteBackendToClient(1, customPkt, "10.100.0.11"); err != nil {
		t.Fatalf("RouteBackendToClient custom route failed: %v", err)
	}

	// Retire custom routes
	waitCustom := f.RetireCustomRoutes()
	_ = waitCustom(context.Background())

	_, _, active = f.GetStats()
	if active != 0 {
		t.Fatalf("expected 0 active routes after retiring custom, got %d", active)
	}
	if owner := f.ReturnRouteOwner(); owner != "none" {
		t.Fatalf("expected return route owner 'none', got %q", owner)
	}
}

func TestForwarder_Stop_FullCleanupAndDrain(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 10)
	upPath := NewReturnPath(func(peer, ip string, p []byte) (int, error) {
		return len(p), nil
	})

	f.RegisterSession("sess-c", "conn-c", "peer-c", "10.100.0.11", 1)
	if _, err := f.TryRegisterSessionWithReturnPath("sess-u", "conn-u", "peer-u", "10.100.0.21", 1, 0, 0, upPath); err != nil {
		t.Fatal(err)
	}

	// Send packets to populate queue
	if err := f.RouteBackendToClient(1, returnPacket("10.100.0.11"), "10.100.0.11"); err != nil {
		t.Fatal(err)
	}
	if err := f.RouteBackendToClient(1, returnPacket("10.100.0.21"), "10.100.0.21"); err != nil {
		t.Fatal(err)
	}

	occ, _, _ := f.AggregateQueueStats()
	if occ == 0 {
		t.Fatal("expected positive aggregate queue occupancy before stop")
	}
	if owner := f.ReturnRouteOwner(); owner != "mixed" {
		t.Fatalf("expected return route owner 'mixed', got %q", owner)
	}

	if err := f.Stop(); err != nil {
		t.Fatalf("Forwarder.Stop: %v", err)
	}

	if f.IsRunning() {
		t.Fatal("expected IsRunning false after Stop")
	}
	_, _, active := f.GetStats()
	if active != 0 {
		t.Fatalf("expected 0 active routes after Stop, got %d", active)
	}
	if owner := f.ReturnRouteOwner(); owner != "none" {
		t.Fatalf("expected return route owner 'none' after Stop, got %q", owner)
	}
	occAfter, _, _ := f.AggregateQueueStats()
	if occAfter != 0 {
		t.Fatalf("expected 0 queue occupancy after Stop, got %d", occAfter)
	}

	// Verify route rejection
	pkt := returnPacket("10.100.0.11")
	if err := f.RouteClientToBackend("peer-c", pkt); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("expected ErrSessionNotRegistered for RouteClientToBackend, got %v", err)
	}
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.11"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("expected ErrSessionNotRegistered for RouteBackendToClient, got %v", err)
	}

	f.mu.RLock()
	rByPeer := len(f.routesByPeer)
	rByIP := len(f.routesByIP)
	cDevs := len(f.clientDevices)
	f.mu.RUnlock()
	if rByPeer != 0 || rByIP != 0 || cDevs != 0 {
		t.Fatalf("expected maps empty: routesByPeer=%d routesByIP=%d clientDevices=%d", rByPeer, rByIP, cDevs)
	}
}

func TestRetireAllRoutes_PermanentlyBlockedWriteTimesOut(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 10)
	dev := newBlockingWriteDevice()
	f.AttachPeerDevice("peer-blocked", dev)
	f.RegisterSession("sess-b", "conn-b", "peer-blocked", "10.100.0.99", 1)

	pkt := returnPacket("10.100.0.99")
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.99"); err != nil {
		t.Fatalf("RouteBackendToClient: %v", err)
	}

	f.StartPumps(t.Context())
	defer func() {
		dev.release()
		f.StopPumps()
	}()

	select {
	case <-dev.startedC:
	case <-time.After(time.Second):
		t.Fatal("device write did not start")
	}

	wait := f.RetireAllRoutes()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	startWait := time.Now()
	err := wait(ctx)
	elapsed := time.Since(startWait)

	if !errors.Is(err, ErrRetirementTimeout) {
		t.Fatalf("expected ErrRetirementTimeout, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected timeout within ~50ms, took %v", elapsed)
	}
}

func TestForwarder_Stop_PermanentlyBlockedWriteTimesOut(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 10)
	f.SetStopTimeoutForTest(50 * time.Millisecond)
	dev := newBlockingWriteDevice()
	defer dev.release()

	f.AttachPeerDevice("peer-blocked-stop", dev)
	f.RegisterSession("sess-bs", "conn-bs", "peer-blocked-stop", "10.100.0.98", 1)

	pkt := returnPacket("10.100.0.98")
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.98"); err != nil {
		t.Fatalf("RouteBackendToClient: %v", err)
	}

	f.StartPumps(t.Context())

	select {
	case <-dev.startedC:
	case <-time.After(time.Second):
		t.Fatal("device write did not start")
	}

	startStop := time.Now()
	err := f.Stop()
	elapsed := time.Since(startStop)

	if !errors.Is(err, ErrRetirementTimeout) {
		t.Fatalf("expected ErrRetirementTimeout from Forwarder.Stop, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected Forwarder.Stop timeout within ~50ms, took %v", elapsed)
	}
}
