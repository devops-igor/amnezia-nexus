package forwarder

import (
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
	f := NewForwarder(nil, 64)
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
	f := NewForwarder(nil, 64)
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
