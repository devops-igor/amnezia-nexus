package forwarder

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type dummyWriter struct {
	writeDelay time.Duration
}

func (d *dummyWriter) Read(p []byte) (int, error) {
	return 0, nil
}

func (d *dummyWriter) Write(p []byte) (int, error) {
	if d.writeDelay > 0 {
		time.Sleep(d.writeDelay)
	}
	return len(p), nil
}

func (d *dummyWriter) Close() error {
	return nil
}

func TestInspectAndProblemRoutes(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.AttachBackendDevice(1, &dummyWriter{})

	// Register 3 routes
	// Route 1: normal
	f.RegisterSession("s1", "c1", "peer1", "10.100.0.2", 1)
	// Route 2: with drops
	f.RegisterSession("s2", "c2", "peer2", "10.100.0.3", 1)
	// Route 3: normal
	f.RegisterSession("s3", "c3", "peer3", "10.100.0.4", 1)

	// Prime the per-route recency window for every route BEFORE the incident.
	// The first sample of a window only establishes a baseline and reports
	// zero, so a counter that has been rising since the route was created is
	// never reported as a fresh incident (issue #424 round 6, finding 3). The
	// wait is required: the first accepted sample is the priming one, and a
	// sample inside the sampling floor after it is not accepted at all.
	f.InspectRoutes()
	time.Sleep(routePressureWindowAdvance())

	// Simulate REAL drops on Route 2 through the production enqueue path:
	// the client queue is filled to capacity and the next packet is refused.
	// The counter is NOT poked here, because production never pokes it either.
	queue, ok := f.GetClientPacketChannel("peer2")
	if !ok {
		t.Fatal("client queue missing for peer2")
	}
	for i := 0; i < cap(queue); i++ {
		if err := f.RouteBackendToClient(1, returnPacketFor("10.100.0.3"), "10.100.0.3"); err != nil {
			t.Fatalf("priming enqueue %d: %v", i, err)
		}
	}
	if err := f.RouteBackendToClient(1, returnPacketFor("10.100.0.3"), "10.100.0.3"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected the full queue to drop, got %v", err)
	}

	routes := f.InspectRoutes()
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes in InspectRoutes, got %d", len(routes))
	}

	problemRoutes := f.ProblemRoutes(10)
	if len(problemRoutes) != 1 {
		t.Fatalf("expected 1 route in ProblemRoutes, got %d", len(problemRoutes))
	}

	// First route must be peer2 because it has drops
	if problemRoutes[0].PeerKey != "peer2" {
		t.Errorf("expected peer2 to be ranked first due to drops, got %s", problemRoutes[0].PeerKey)
	}
	if !problemRoutes[0].HasPressure {
		t.Errorf("expected peer2 to have HasPressure=true")
	}

	// Limit ProblemRoutes to 1
	top1 := f.ProblemRoutes(1)
	if len(top1) != 1 || top1[0].PeerKey != "peer2" {
		t.Errorf("expected top 1 problem route to be peer2, got %+v", top1)
	}
}

// returnPacketFor builds a minimal routable return-path packet for one
// assigned client IP.
func returnPacketFor(ip string) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	parsed := netip.MustParseAddr(ip).As4()
	pkt[16], pkt[17], pkt[18], pkt[19] = parsed[0], parsed[1], parsed[2], parsed[3]
	return pkt
}

func TestLatencyReservoir(t *testing.T) {
	res := &latencyReservoir{}

	p50, p95, p99 := res.percentiles()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Fatalf("expected 0 for empty reservoir, got p50=%v p95=%v p99=%v", p50, p95, p99)
	}

	// Record 100 samples from 1ms to 100ms
	for i := 1; i <= 100; i++ {
		res.record(time.Duration(i) * time.Millisecond)
	}

	p50, p95, p99 = res.percentiles()
	if p50 < 45*time.Millisecond || p50 > 55*time.Millisecond {
		t.Errorf("expected p50 around 50ms, got %v", p50)
	}
	if p95 < 90*time.Millisecond || p95 > 98*time.Millisecond {
		t.Errorf("expected p95 around 95ms, got %v", p95)
	}
	if p99 < 95*time.Millisecond || p99 > 100*time.Millisecond {
		t.Errorf("expected p99 around 99ms, got %v", p99)
	}
}

func TestForwarder_ClientDropStats(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	// 1. Drop because backend not found
	f.RegisterSession("s1", "c1", "p1", "10.100.0.2", 999)
	f.SetBackendQueueForTest(999, nil)
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[12], pkt[13], pkt[14], pkt[15] = 10, 100, 0, 2
	err = f.RouteClientToBackend("p1", pkt)
	if err != ErrBackendNotFound {
		t.Fatalf("expected ErrBackendNotFound, got %v", err)
	}
	qF, rL, nB, tot := f.ClientDropStats()
	if nB != 1 || tot != 1 || qF != 0 || rL != 0 {
		t.Fatalf("expected noBackend=1, total=1, got qF=%d, rL=%d, nB=%d, tot=%d", qF, rL, nB, tot)
	}

	// 2. Drop because rate limited
	f.AttachBackendDevice(1, &dummyWriter{})
	f.RegisterSession("s2", "c2", "p2", "10.100.0.3", 1)
	if err := f.SetPeerRateLimit("p2", 0, 10); err != nil {
		t.Fatalf("SetPeerRateLimit: %v", err)
	}
	pkt2 := make([]byte, 100)
	pkt2[0] = 0x45
	pkt2[12], pkt2[13], pkt2[14], pkt2[15] = 10, 100, 0, 3
	err = f.RouteClientToBackend("p2", pkt2)
	if err != ErrRateLimitExceeded {
		t.Fatalf("expected ErrRateLimitExceeded, got %v", err)
	}
	qF, rL, nB, tot = f.ClientDropStats()
	if rL != 1 || nB != 1 || tot != 2 {
		t.Fatalf("expected rateLimited=1, noBackend=1, total=2, got qF=%d, rL=%d, nB=%d, tot=%d", qF, rL, nB, tot)
	}

	// 3. Drop because backend queue full
	// Replace backend 1 queue with capacity 1 channel and fill it
	ch := make(chan []byte, 1)
	ch <- []byte{0}
	f.SetBackendQueueForTest(1, ch)

	f.RegisterSession("s3", "c3", "p3", "10.100.0.4", 1)
	pkt3 := make([]byte, 28)
	pkt3[0] = 0x45
	pkt3[12], pkt3[13], pkt3[14], pkt3[15] = 10, 100, 0, 4
	err = f.RouteClientToBackend("p3", pkt3)
	if err != ErrQueueFull {
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}
	qF, rL, nB, tot = f.ClientDropStats()
	if qF != 1 || rL != 1 || nB != 1 || tot != 3 {
		t.Fatalf("expected queueFull=1, rateLimited=1, noBackend=1, total=3, got qF=%d, rL=%d, nB=%d, tot=%d", qF, rL, nB, tot)
	}
}

func TestRouteRegistrationLifecycle(t *testing.T) {
	t.Run("standard registration and rate limits", func(t *testing.T) {
		f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits: %v", err)
		}
		if count := f.ActiveRoutesCount(); count != 0 {
			t.Fatalf("expected 0 active routes, got %d", count)
		}

		// Register standard session with limits
		f.RegisterSessionWithLimit("sess-1", "conn-1", "peer-1", "10.100.0.2", 1, 1000, 2000)
		if count := f.ActiveRoutesCount(); count != 1 {
			t.Fatalf("expected 1 active route, got %d", count)
		}
		if sID := f.RouteSessionID("peer-1"); sID != "sess-1" {
			t.Fatalf("expected sess-1, got %s", sID)
		}
		if !f.HasSessionRoute("peer-1", "sess-1", "conn-1", "10.100.0.2", 1) {
			t.Fatal("expected HasSessionRoute to return true")
		}
		down, up, err := f.GetPeerRateLimit("peer-1")
		if err != nil || down != 1000 || up != 2000 {
			t.Fatalf("GetPeerRateLimit: got down=%d up=%d err=%v, want 1000, 2000", down, up, err)
		}
		if reg := f.PeerRegistration("peer-1"); reg != 1 {
			t.Fatalf("expected PeerRegistration 1, got %d", reg)
		}

		// Re-registration of same peer increments registration generation and replaces route
		ret := f.BeginRegisterSessionWithLimit("sess-2", "conn-2", "peer-1", "10.100.0.3", 1, 0, 0)
		ret.Wait()
		if reg := f.PeerRegistration("peer-1"); reg != 2 {
			t.Fatalf("expected PeerRegistration 2, got %d", reg)
		}
		if sID := f.RouteSessionID("peer-1"); sID != "sess-2" {
			t.Fatalf("expected sess-2, got %s", sID)
		}
		// Old assigned IP should no longer point to active route
		if f.HasSessionRoute("peer-1", "sess-1", "conn-1", "10.100.0.2", 1) {
			t.Fatal("old session route must no longer be active")
		}
		if !f.HasSessionRoute("peer-1", "sess-2", "conn-2", "10.100.0.3", 1) {
			t.Fatal("new session route must be active")
		}
	})

	t.Run("capacity exhaustion and replacement", func(t *testing.T) {
		f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 2)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits: %v", err)
		}
		f.RegisterSession("s1", "c1", "p1", "10.100.0.2", 1)
		f.RegisterSession("s2", "c2", "p2", "10.100.0.3", 1)

		// Third peer exceeds capacity
		_, err = f.TryRegisterSessionWithLimit("s3", "c3", "p3", "10.100.0.4", 1, 0, 0)
		if !errors.Is(err, ErrRouteCapacityExhausted) {
			t.Fatalf("expected ErrRouteCapacityExhausted, got %v", err)
		}

		// Re-registration of existing peer p1 is allowed even at capacity
		ret, err := f.TryRegisterSessionWithLimit("s1-new", "c1-new", "p1", "10.100.0.2", 1, 0, 0)
		if err != nil {
			t.Fatalf("re-registration of existing peer failed: %v", err)
		}
		ret.Wait()
		if sID := f.RouteSessionID("p1"); sID != "s1-new" {
			t.Fatalf("expected s1-new, got %s", sID)
		}
	})

	t.Run("return path binding and closed path rejection", func(t *testing.T) {
		f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits: %v", err)
		}

		closedPath := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
		closedPath.Close()

		// Attempt registration with closed return path
		_, err = f.TryRegisterSessionWithReturnPath("s1", "c1", "p1", "10.100.0.2", 1, 0, 0, closedPath)
		if !errors.Is(err, ErrReturnPathClosed) {
			t.Fatalf("expected ErrReturnPathClosed, got %v", err)
		}

		// Valid return path
		livePath := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
		f.RegisterSessionWithReturnPath("s2", "c2", "p2", "10.100.0.3", 1, livePath)
		if !f.HasRoutesForReturnPath(livePath) {
			t.Fatal("expected HasRoutesForReturnPath to be true for livePath")
		}
		if f.HasRoutesForReturnPath(closedPath) {
			t.Fatal("expected HasRoutesForReturnPath to be false for closedPath")
		}
	})
}

func TestRouteRetirementLifecycle(t *testing.T) {
	t.Run("unconditional unregister", func(t *testing.T) {
		f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits: %v", err)
		}
		f.RegisterSession("s1", "c1", "p1", "10.100.0.2", 1)
		if f.ActiveRoutesCount() != 1 {
			t.Fatal("expected 1 route")
		}
		f.UnregisterSession("p1")
		if f.ActiveRoutesCount() != 0 {
			t.Fatalf("expected 0 routes after UnregisterSession, got %d", f.ActiveRoutesCount())
		}
		if sID := f.RouteSessionID("p1"); sID != "" {
			t.Fatalf("expected empty sessionID, got %s", sID)
		}
	})

	t.Run("begin unregister session generation guarding", func(t *testing.T) {
		f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits: %v", err)
		}
		// Register session-1
		f.RegisterSession("s1", "c1", "p1", "10.100.0.2", 1)
		// Rekey/reconnect replaces with session-2
		f.RegisterSession("s2", "c2", "p1", "10.100.0.2", 1)

		// Late unregister for old session-1 must NOT remove session-2
		retOld := f.BeginUnregisterSession("p1", "s1")
		retOld.Wait()
		if f.ActiveRoutesCount() != 1 || f.RouteSessionID("p1") != "s2" {
			t.Fatalf("stale unregister evicted new session! active=%d sessionID=%s", f.ActiveRoutesCount(), f.RouteSessionID("p1"))
		}

		// Empty sessionID returns zero retirement
		emptyRet := f.BeginUnregisterSession("p1", "")
		emptyRet.Wait()
		if f.ActiveRoutesCount() != 1 {
			t.Fatal("empty sessionID unregister should be no-op")
		}

		// Matching session unregister succeeds
		retCurrent := f.BeginUnregisterSession("p1", "s2")
		retCurrent.Wait()
		if f.ActiveRoutesCount() != 0 {
			t.Fatalf("expected 0 active routes, got %d", f.ActiveRoutesCount())
		}
	})

	t.Run("retire routes by return path and unmanaged", func(t *testing.T) {
		f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits: %v", err)
		}

		pathA := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
		pathB := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })

		f.RegisterSessionWithReturnPath("sa", "ca", "pa", "10.100.0.2", 1, pathA)
		f.RegisterSessionWithReturnPath("sb", "cb", "pb", "10.100.0.3", 1, pathB)
		f.RegisterSession("sc", "cc", "pc", "10.100.0.4", 1) // unmanaged (nil returnPath)

		if f.ActiveRoutesCount() != 3 {
			t.Fatalf("expected 3 routes, got %d", f.ActiveRoutesCount())
		}

		// Retire routes by pathA
		waitA := f.RetireRoutesByReturnPath(pathA)
		if err := waitA(context.Background()); err != nil {
			t.Fatalf("waitA: %v", err)
		}
		if f.ActiveRoutesCount() != 2 {
			t.Fatalf("expected 2 routes remaining after retiring pathA, got %d", f.ActiveRoutesCount())
		}
		if f.HasRoutesForReturnPath(pathA) {
			t.Fatal("expected pathA to have no routes")
		}
		if !f.HasRoutesForReturnPath(pathB) {
			t.Fatal("expected pathB to still have routes")
		}

		// Retire unmanaged routes
		waitUnmanaged := f.RetireUnmanagedRoutes()
		if err := waitUnmanaged(context.Background()); err != nil {
			t.Fatalf("waitUnmanaged: %v", err)
		}
		if f.ActiveRoutesCount() != 1 {
			t.Fatalf("expected 1 route remaining after retiring unmanaged, got %d", f.ActiveRoutesCount())
		}
		if f.RouteSessionID("pb") != "sb" {
			t.Fatal("expected pb with pathB to remain")
		}

		// Retire all routes
		waitAll := f.RetireAllRoutes()
		if err := waitAll(context.Background()); err != nil {
			t.Fatalf("waitAll: %v", err)
		}
		if f.ActiveRoutesCount() != 0 {
			t.Fatalf("expected 0 routes remaining after RetireAllRoutes, got %d", f.ActiveRoutesCount())
		}
	})
}

func TestRouteLifecycleConcurrentLoad(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 20, 50)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	const workers = 8

	for i := 0; i < workers; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			peerKey := fmt.Sprintf("peer-%d", workerID)
			ip := fmt.Sprintf("10.100.%d.%d", workerID/250, 2+(workerID%250))
			iter := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				iter++
				sessionID := fmt.Sprintf("s-%d-%d", workerID, iter)
				connID := fmt.Sprintf("c-%d-%d", workerID, iter)

				// Register with return path
				f.RegisterSessionWithReturnPath(sessionID, connID, peerKey, ip, 1, path)
				_ = f.HasSessionRoute(peerKey, sessionID, connID, ip, 1)
				_ = f.RouteSessionID(peerKey)
				_ = f.PeerRegistration(peerKey)
				_ = f.ActiveRoutesCount()

				// Unregister
				if iter%2 == 0 {
					f.UnregisterSession(peerKey)
				} else {
					ret := f.BeginUnregisterSession(peerKey, sessionID)
					ret.Wait()
				}
			}
		}()
	}

	// Concurrent inspector
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = f.InspectRoutes()
			_ = f.ProblemRoutes(5)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()

	wait := f.RetireAllRoutes()
	if err := wait(context.Background()); err != nil {
		t.Fatalf("RetireAllRoutes: %v", err)
	}
	if count := f.ActiveRoutesCount(); count != 0 {
		t.Fatalf("expected 0 active routes after final retirement, got %d", count)
	}
}
