package vpn

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// TestDualEngine_ConfigAndEnvironment validates engine resolution: upstream is the only
// configured client-facing runtime engine.
func TestDualEngine_ConfigAndEnvironment(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}

	ctx := t.Context()
	stat, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ConfiguredEngine != ClientAWGEngineUpstream {
		t.Fatalf("expected configured engine %q, got %q", ClientAWGEngineUpstream, stat.ConfiguredEngine)
	}
	if stat.ActiveEngine != "none" {
		t.Fatalf("expected active engine 'none' when not running, got %q", stat.ActiveEngine)
	}
	if stat.EngineRunning {
		t.Error("expected engine_running false when not running")
	}
}

// TestDualEngine_StartupUpstreamMode verifies that upstream mode boots IngressEngine,
// does NOT start endpoint.Listener, and populates status.
func TestDualEngine_StartupUpstreamMode(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start: %v", err)
	}

	if svc.ingressEngine == nil || !svc.ingressEngine.Running() {
		t.Fatal("upstream mode: expected ingressEngine to be running")
	}

	stat, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ConfiguredEngine != ClientAWGEngineUpstream {
		t.Errorf("expected configured_engine %q, got %q", ClientAWGEngineUpstream, stat.ConfiguredEngine)
	}
	if stat.ActiveEngine != ClientAWGEngineUpstream {
		t.Errorf("expected active_engine %q, got %q", ClientAWGEngineUpstream, stat.ActiveEngine)
	}
	if stat.ReturnRouteOwner != "none" {
		t.Errorf("expected return_route_owner 'none' without active routes, got %q", stat.ReturnRouteOwner)
	}
	if !stat.EngineRunning {
		t.Error("expected engine_running true")
	}
	if !stat.ListenerRunning {
		t.Error("expected listener_running true")
	}
	if stat.ListenPort <= 0 {
		t.Errorf("expected positive listen_port, got %d", stat.ListenPort)
	}

	// Clean shutdown verification
	if err := svc.Stop(); err != nil {
		t.Fatalf("svc.Stop: %v", err)
	}
	if svc.ingressEngine != nil {
		t.Fatal("expected ingressEngine to be cleared after Stop")
	}
	if svc.IsRunning() {
		t.Fatal("expected IsRunning false after Stop")
	}
}

type safeLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeLogBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

// TestDualEngine_StartupLogging verifies the startup log format:
// "[vpn] active client AWG engine=upstream listen_port=<port>"
func TestDualEngine_StartupLogging(t *testing.T) {
	prevLog := log.Writer()
	defer log.SetOutput(prevLog)

	var buf safeLogBuffer
	log.SetOutput(&buf)

	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	ctx, cancel := context.WithCancel(t.Context())
	if err := svc.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	_ = svc.Stop()

	output := buf.String()
	if !strings.Contains(output, "[vpn] active client AWG engine=upstream listen_port=") {
		t.Fatalf("missing upstream startup log in output:\n%s", output)
	}
}

// TestDualEngine_ReturnPathFailClosedFencing verifies PR #398 mandate:
// Upstream-owned ReturnPath must fail closed on Close and never silently fall back to SendToPeer.
func TestDualEngine_ReturnPathFailClosedFencing(t *testing.T) {
	var writes atomic.Int64
	path := forwarder.NewReturnPath(func(peer, ip string, pkt []byte) (int, error) {
		writes.Add(1)
		return len(pkt), nil
	})

	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 128, 100)
	if err != nil {
		t.Fatal(err)
	}
	fwd.Start(t.Context())
	defer func() { _ = fwd.Stop() }()

	peerKey := "test-peer-fencing"
	assignedIP := "10.100.0.10"
	backendID := int64(1)

	// Register session with upstream return path
	_, err = fwd.TryRegisterSessionWithReturnPath("sess-1", "conn-1", peerKey, assignedIP, backendID, 0, 0, path)
	if err != nil {
		t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
	}

	// Verify route has return path
	if !fwd.HasSessionRouteWithReturnPath(peerKey, "sess-1", "conn-1", assignedIP, backendID, path) {
		t.Fatal("expected route with return path to exist")
	}

	// Close the ReturnPath (simulating upstream engine stop)
	path.Close()
	if !path.Closed() {
		t.Fatal("expected ReturnPath.Closed() to be true")
	}

	// Any route write through closed ReturnPath must fail closed with ErrReturnPathClosed
	// Construct a dummy IPv4 UDP packet matching assignedIP destination
	pkt := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr(assignedIP), 0x9999)

	// Verify RouteClientToBackendWithReturnPath returns ErrReturnPathClosed
	if err := fwd.RouteClientToBackendWithReturnPath(peerKey, pkt, path); !errors.Is(err, forwarder.ErrReturnPathClosed) {
		t.Fatalf("expected ErrReturnPathClosed, got %v", err)
	}
}

// TestDualEngine_ConcurrentInFlightReturnWritesFencing verifies that concurrent
// in-flight return writes are cleanly fenced when an engine is stopped and its
// ReturnPath closed.
func TestDualEngine_ConcurrentInFlightReturnWritesFencing(t *testing.T) {
	var activeWrites sync.WaitGroup
	var acceptedWrites atomic.Int64
	var rejectedWrites atomic.Int64

	path := forwarder.NewReturnPath(func(peer, ip string, pkt []byte) (int, error) {
		time.Sleep(2 * time.Millisecond)
		return len(pkt), nil
	})

	const numWriters = 20
	activeWrites.Add(numWriters)

	destIP := "10.100.0.50"
	pkt := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr(destIP), 0x5555)

	// Launch concurrent writers
	for i := 0; i < numWriters; i++ {
		go func() {
			defer activeWrites.Done()
			for j := 0; j < 50; j++ {
				_, err := path.Write("peer", destIP, pkt)
				if err == nil {
					acceptedWrites.Add(1)
				} else {
					rejectedWrites.Add(1)
				}
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}

	// Close the path mid-flight
	time.Sleep(10 * time.Millisecond)
	path.Close()

	activeWrites.Wait()

	if !path.Closed() {
		t.Fatal("expected path to be closed")
	}
	if rejectedWrites.Load() == 0 {
		t.Fatal("expected some writes to be rejected after path was closed")
	}
}

// TestDualEngine_Telemetry verifies accurate reporting of configured_engine,
// active_engine, engine_running, and return_route_owner across lifecycle states.
func TestDualEngine_Telemetry(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	// State 1: Fresh service, not running
	stat, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ConfiguredEngine != ClientAWGEngineUpstream {
		t.Errorf("expected configured_engine %q, got %q", ClientAWGEngineUpstream, stat.ConfiguredEngine)
	}
	if stat.ActiveEngine != "none" {
		t.Errorf("expected active_engine 'none' when not running, got %q", stat.ActiveEngine)
	}
	if stat.EngineRunning {
		t.Error("expected engine_running false when not running")
	}
	if stat.ReturnRouteOwner != "none" {
		t.Errorf("expected return_route_owner 'none' when not running, got %q", stat.ReturnRouteOwner)
	}

	// State 2: Running in upstream mode without routes
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ConfiguredEngine != ClientAWGEngineUpstream {
		t.Errorf("expected configured_engine %q, got %q", ClientAWGEngineUpstream, stat.ConfiguredEngine)
	}
	if stat.ActiveEngine != ClientAWGEngineUpstream {
		t.Errorf("expected active_engine %q, got %q", ClientAWGEngineUpstream, stat.ActiveEngine)
	}
	if !stat.EngineRunning {
		t.Error("expected engine_running true")
	}
	if stat.ReturnRouteOwner != "none" {
		t.Errorf("expected return_route_owner 'none' without routes, got %q", stat.ReturnRouteOwner)
	}

	// Register an upstream mode route (returnPath != nil)
	upPath := forwarder.NewReturnPath(func(peer, ip string, p []byte) (int, error) {
		return len(p), nil
	})
	_, err = svc.forwarder.TryRegisterSessionWithReturnPath("sess-u", "conn-u", "peer-u", "10.100.0.20", 1, 0, 0, upPath)
	if err != nil {
		t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
	}
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ReturnRouteOwner != ClientAWGEngineUpstream {
		t.Errorf("expected return_route_owner upstream with upstream routes, got %q", stat.ReturnRouteOwner)
	}

	// Verify mixed ownership detection if forwarder contains both route types
	retMixed := svc.forwarder.BeginRegisterSessionWithLimit("sess-m", "conn-m", "peer-m", "10.100.0.30", 1, 0, 0)
	retMixed.Wait()
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ReturnRouteOwner != "mixed" {
		t.Errorf("expected return_route_owner 'mixed' with mixed routes, got %q", stat.ReturnRouteOwner)
	}

	// Stop upstream service cleanly
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ActiveEngine != "none" {
		t.Errorf("expected active_engine 'none' after stop, got %q", stat.ActiveEngine)
	}
	if stat.EngineRunning {
		t.Error("expected engine_running false after stop")
	}
	if stat.ReturnRouteOwner != "none" {
		t.Errorf("expected return_route_owner 'none' after stop, got %q", stat.ReturnRouteOwner)
	}
}

// TestDualEngine_ServiceStopRetiresForwarderRoutes tests that Service.Stop cleanly
// retires and drains forwarder routes in upstream engine mode,
// leaving zero active routes and 'none' return route owner.
func TestDualEngine_ServiceStopRetiresForwarderRoutes(t *testing.T) {
	t.Run("upstream engine mode stop retires forwarder routes and drains queues", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		ctx := t.Context()

		if err := svc.Start(ctx); err != nil {
			t.Fatal(err)
		}

		if svc.ingressEngine == nil || svc.ingressEngine.returnPath == nil {
			t.Fatal("expected non-nil ingressEngine and returnPath in upstream mode")
		}

		// Register upstream routes on forwarder bound to engine.returnPath
		ret1, err := svc.forwarder.TryRegisterSessionWithReturnPath("sess-u1", "conn-u1", "peer-u1", "10.100.0.20", 1, 0, 0, svc.ingressEngine.returnPath)
		if err != nil {
			t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
		}
		ret1.Wait()
		ret2, err := svc.forwarder.TryRegisterSessionWithReturnPath("sess-u2", "conn-u2", "peer-u2", "10.100.0.21", 1, 0, 0, svc.ingressEngine.returnPath)
		if err != nil {
			t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
		}
		ret2.Wait()

		// Stop pumps so enqueued packets remain buffered in client queues for drain verification
		svc.forwarder.StopPumps()

		// Enqueue packets into client queue
		pkt1 := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("10.100.0.20"), 1)
		pkt2 := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("10.100.0.21"), 2)
		if err := svc.forwarder.RouteBackendToClient(1, pkt1, "10.100.0.20"); err != nil {
			t.Fatalf("RouteBackendToClient: %v", err)
		}
		if err := svc.forwarder.RouteBackendToClient(1, pkt2, "10.100.0.21"); err != nil {
			t.Fatalf("RouteBackendToClient: %v", err)
		}

		occ, _, _ := svc.forwarder.AggregateQueueStats()
		if occ == 0 {
			t.Fatal("expected positive aggregate queue occupancy before Stop")
		}
		_, _, active := svc.forwarder.GetStats()
		if active != 2 {
			t.Fatalf("expected 2 active routes, got %d", active)
		}
		if owner := svc.forwarder.ReturnRouteOwner(); owner != ClientAWGEngineUpstream {
			t.Fatalf("expected return route owner upstream, got %q", owner)
		}

		// Calling Service.Stop() must cleanly retire forwarder routes and drain queues
		if err := svc.Stop(); err != nil {
			t.Fatalf("svc.Stop: %v", err)
		}

		if owner := svc.forwarder.ReturnRouteOwner(); owner != "none" {
			t.Errorf("expected return route owner 'none' after Stop, got %q", owner)
		}
		_, _, activeAfter := svc.forwarder.GetStats()
		if activeAfter != 0 {
			t.Errorf("expected 0 active routes in forwarder after Stop, got %d", activeAfter)
		}
		occAfter, _, _ := svc.forwarder.AggregateQueueStats()
		if occAfter != 0 {
			t.Errorf("expected 0 aggregate queue occupancy after Stop, got %d", occAfter)
		}
		if svc.IsRunning() {
			t.Error("expected service IsRunning false after Stop")
		}
	})

	t.Run("dual engine mixed routes stop leaves zero routes and none owner", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		ctx := t.Context()

		if err := svc.Start(ctx); err != nil {
			t.Fatal(err)
		}

		// Register custom route (nil returnPath)
		retC := svc.forwarder.BeginRegisterSessionWithLimit("sess-cm", "conn-cm", "peer-cm", "10.100.0.30", 1, 0, 0)
		retC.Wait()

		// Register upstream route
		retU, err := svc.forwarder.TryRegisterSessionWithReturnPath("sess-um", "conn-um", "peer-um", "10.100.0.31", 1, 0, 0, svc.ingressEngine.returnPath)
		if err != nil {
			t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
		}
		retU.Wait()

		if owner := svc.forwarder.ReturnRouteOwner(); owner != "mixed" {
			t.Fatalf("expected return route owner 'mixed', got %q", owner)
		}
		_, _, active := svc.forwarder.GetStats()
		if active != 2 {
			t.Fatalf("expected 2 active routes, got %d", active)
		}

		if err := svc.Stop(); err != nil {
			t.Fatalf("svc.Stop: %v", err)
		}

		if owner := svc.forwarder.ReturnRouteOwner(); owner != "none" {
			t.Errorf("expected return route owner 'none' after Stop, got %q", owner)
		}
		_, _, activeAfter := svc.forwarder.GetStats()
		if activeAfter != 0 {
			t.Errorf("expected 0 active routes after Stop, got %d", activeAfter)
		}
		occAfter, _, _ := svc.forwarder.AggregateQueueStats()
		if occAfter != 0 {
			t.Errorf("expected 0 queue occupancy after Stop, got %d", occAfter)
		}
	})
}

// TestDualEngine_IngressEngineStopRetiresBoundForwarderRoutes tests that IngressEngine.Stop
// explicitly retires forwarder routes bound to its returnPath and executes the retirement callback.
func TestDualEngine_IngressEngineStopRetiresBoundForwarderRoutes(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	engine, err := svc.NewIngressEngine(ctx, "stop-portal", nil)
	if err != nil {
		t.Fatalf("NewIngressEngine: %v", err)
	}

	// Register an upstream route bound to engine.returnPath
	retU, err := svc.forwarder.TryRegisterSessionWithReturnPath("sess-u", "conn-u", "peer-u", "10.100.0.50", 1, 0, 0, engine.returnPath)
	if err != nil {
		t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
	}
	retU.Wait()

	// Register a custom route on forwarder
	retC := svc.forwarder.BeginRegisterSessionWithLimit("sess-c", "conn-c", "peer-c", "10.100.0.51", 1, 0, 0)
	retC.Wait()

	if owner := svc.forwarder.ReturnRouteOwner(); owner != "mixed" {
		t.Fatalf("expected return route owner 'mixed', got %q", owner)
	}
	_, _, active := svc.forwarder.GetStats()
	if active != 2 {
		t.Fatalf("expected 2 active routes, got %d", active)
	}

	callbackCalled := false
	engine.SetRouteRetirementCallbackForTest(func() {
		callbackCalled = true
		wait := svc.forwarder.RetireRoutesByReturnPath(engine.returnPath)
		_ = wait(context.Background())
	})

	if err := engine.Stop(); err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
		t.Fatalf("engine.Stop: %v", err)
	}

	if !callbackCalled {
		t.Error("expected route retirement callback to be called")
	}

	// Verify upstream route was retired, custom route remains
	if owner := svc.forwarder.ReturnRouteOwner(); owner != ClientAWGEngineCustom {
		t.Errorf("expected return route owner custom, got %q", owner)
	}
	_, _, activeAfter := svc.forwarder.GetStats()
	if activeAfter != 1 {
		t.Errorf("expected 1 active route remaining, got %d", activeAfter)
	}

	// Verify default (non-callback) Stop path on a second engine
	engine2, err := svc.NewIngressEngine(ctx, "stop-portal-2", nil)
	if err != nil {
		t.Fatalf("NewIngressEngine: %v", err)
	}
	retU2, err := svc.forwarder.TryRegisterSessionWithReturnPath("sess-u2", "conn-u2", "peer-u2", "10.100.0.52", 1, 0, 0, engine2.returnPath)
	if err != nil {
		t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
	}
	retU2.Wait()

	if err := engine2.Stop(); err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
		t.Fatalf("engine2.Stop: %v", err)
	}

	// engine2 route retired, custom route still remains
	if owner := svc.forwarder.ReturnRouteOwner(); owner != ClientAWGEngineCustom {
		t.Errorf("expected return route owner custom, got %q", owner)
	}
	_, _, activeAfter2 := svc.forwarder.GetStats()
	if activeAfter2 != 1 {
		t.Errorf("expected 1 active route remaining, got %d", activeAfter2)
	}

	// Clean up remaining custom route
	_ = svc.forwarder.RetireCustomRoutes()(context.Background())
	if owner := svc.forwarder.ReturnRouteOwner(); owner != "none" {
		t.Errorf("expected return route owner 'none', got %q", owner)
	}
}

// TestDualEngine_ConcurrentAdmissionDuringEngineStop verifies that if session admission
// is already in progress when IngressEngine.Stop starts:
//  1. ReturnPath is closed early as an admission fence.
//  2. The in-progress admission fails closed with ErrReturnPathClosed.
//  3. After Stop() returns: active_routes == 0, return_route_owner == "none",
//     and no route in the forwarder references the closed path.
func TestDualEngine_ConcurrentAdmissionDuringEngineStop(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "user-admit-stop", "peer-admit-stop-pubkey1", "10.100.12.5")
	o := ownershipFor(peer)

	engine := svc.IngressEngine()
	if engine == nil {
		t.Fatal("expected non-nil IngressEngine")
	}

	admissionReachedHook := make(chan struct{})
	resumeAdmission := make(chan struct{})

	// Set hook that fires right before route registration inside ensureBackendSessionForIngress
	svc.SetPreIngressRouteRegistrationHookForTest(func() {
		close(admissionReachedHook)
		<-resumeAdmission
	})

	type admissionResult struct {
		sess    *models.VPNSession
		backend *models.BackendTunnel
		err     error
	}
	admitCh := make(chan admissionResult, 1)

	// Launch concurrent admission with the engine's returnPath
	go func() {
		sess, backend, _, err := svc.ensureBackendSessionForIngress(context.Background(), o, engine.returnPath)
		admitCh <- admissionResult{sess: sess, backend: backend, err: err}
	}()

	// Wait until admission has selected backend, created session, but NOT yet registered route
	select {
	case <-admissionReachedHook:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for admission to reach hook")
	}

	// Now stop the engine in a separate goroutine while admission is parked in hook
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- engine.Stop()
	}()

	// Wait for engine.returnPath to be closed by engine.Stop (step b of teardown ordering)
	deadline := time.Now().Add(3 * time.Second)
	closed := false
	for time.Now().Before(deadline) {
		if engine.returnPath.Closed() {
			closed = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !closed {
		t.Fatal("timed out waiting for engine.returnPath to be closed")
	}

	// Resume the paused admission so it attempts to register the route on the now-closed returnPath
	close(resumeAdmission)

	// Admission must fail closed with ErrReturnPathClosed
	var res admissionResult
	select {
	case res = <-admitCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for admission to complete")
	}

	if !errors.Is(res.err, forwarder.ErrReturnPathClosed) {
		t.Fatalf("expected ErrReturnPathClosed from admission, got %v", res.err)
	}

	// Wait for engine.Stop to finish
	select {
	case err := <-stopDone:
		if err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
			t.Fatalf("engine.Stop failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for engine.Stop")
	}

	// Verify required invariants:
	// 1. active_routes == 0
	_, _, active := svc.forwarder.GetStats()
	if active != 0 {
		t.Fatalf("expected 0 active routes, got %d", active)
	}

	// 2. return_route_owner == "none"
	if owner := svc.forwarder.ReturnRouteOwner(); owner != "none" {
		t.Fatalf("expected return_route_owner 'none', got %q", owner)
	}

	// 3. no route references the closed path
	if svc.forwarder.HasRoutesForReturnPath(engine.returnPath) {
		t.Fatal("expected no route to reference closed returnPath")
	}

	// 4. Session rolled back cleanly (not left connected)
	if sess, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey); ok && sess.Status == "connected" {
		t.Fatalf("session for peer was not rolled back: %+v", sess)
	}

	_ = svc.Stop()
}
