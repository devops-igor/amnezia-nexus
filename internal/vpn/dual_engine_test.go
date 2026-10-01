package vpn

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// TestDualEngine_ConfigAndEnvironment validates engine resolution and validation
// from environment variables and setters.
func TestDualEngine_ConfigAndEnvironment(t *testing.T) {
	cleanup := func() {
		os.Unsetenv("VPN_CLIENT_AWG_ENGINE")
		os.Unsetenv("CLIENT_AWG_ENGINE")
		os.Unsetenv("VPN_CLIENT_ENGINE")
	}
	defer cleanup()

	t.Run("default to custom", func(t *testing.T) {
		cleanup()
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		if svc.ClientAWGEngine() != ClientAWGEngineCustom {
			t.Fatalf("expected default engine %q, got %q", ClientAWGEngineCustom, svc.ClientAWGEngine())
		}
	})

	t.Run("VPN_CLIENT_AWG_ENGINE=upstream", func(t *testing.T) {
		cleanup()
		os.Setenv("VPN_CLIENT_AWG_ENGINE", "upstream")
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		if svc.ClientAWGEngine() != ClientAWGEngineUpstream {
			t.Fatalf("expected engine %q, got %q", ClientAWGEngineUpstream, svc.ClientAWGEngine())
		}
	})

	t.Run("CLIENT_AWG_ENGINE fallback", func(t *testing.T) {
		cleanup()
		os.Setenv("CLIENT_AWG_ENGINE", "upstream")
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		if svc.ClientAWGEngine() != ClientAWGEngineUpstream {
			t.Fatalf("expected engine %q, got %q", ClientAWGEngineUpstream, svc.ClientAWGEngine())
		}
	})

	t.Run("VPN_CLIENT_ENGINE fallback", func(t *testing.T) {
		cleanup()
		os.Setenv("VPN_CLIENT_ENGINE", "upstream")
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		if svc.ClientAWGEngine() != ClientAWGEngineUpstream {
			t.Fatalf("expected engine %q, got %q", ClientAWGEngineUpstream, svc.ClientAWGEngine())
		}
	})

	t.Run("invalid engine fails closed", func(t *testing.T) {
		cleanup()
		os.Setenv("VPN_CLIENT_AWG_ENGINE", "unsupported_engine")
		db := setupTestDB(t)
		_, err := NewVPNService(db, nil)
		if err == nil {
			t.Fatal("expected error on invalid engine, got nil")
		}
	})

	t.Run("SetClientAWGEngine transitions and validation", func(t *testing.T) {
		cleanup()
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}

		if err := svc.SetClientAWGEngine("upstream"); err != nil {
			t.Fatalf("SetClientAWGEngine(upstream): %v", err)
		}
		if svc.ClientAWGEngine() != ClientAWGEngineUpstream {
			t.Fatalf("expected engine %q, got %q", ClientAWGEngineUpstream, svc.ClientAWGEngine())
		}

		if err := svc.SetClientAWGEngine("custom"); err != nil {
			t.Fatalf("SetClientAWGEngine(custom): %v", err)
		}
		if svc.ClientAWGEngine() != ClientAWGEngineCustom {
			t.Fatalf("expected engine %q, got %q", ClientAWGEngineCustom, svc.ClientAWGEngine())
		}

		if err := svc.SetClientAWGEngine("invalid"); err == nil {
			t.Fatal("expected error for invalid engine, got nil")
		}
	})

	t.Run("SetClientAWGEngine rejected while running", func(t *testing.T) {
		cleanup()
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		ctx := t.Context()

		if err := svc.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
			t.Fatalf("SetClientAWGEngine: %v", err)
		}
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer func() { _ = svc.Stop() }()

		if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err == nil {
			t.Fatal("expected error modifying engine on running service, got nil")
		}
	})
}

// TestDualEngine_StartupCustomMode verifies that custom mode boots the legacy listener,
// does not start IngressEngine, and correctly populates status.
func TestDualEngine_StartupCustomMode(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	if err := svc.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
		t.Fatalf("SetClientAWGEngine: %v", err)
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if svc.endpoint == nil || !svc.endpoint.IsRunning() {
		t.Fatal("custom mode: expected endpoint listener to be running")
	}
	if svc.ingressEngine != nil {
		t.Fatal("custom mode: expected ingressEngine to be nil")
	}

	stat, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ActiveEngine != ClientAWGEngineCustom {
		t.Errorf("expected active_engine %q, got %q", ClientAWGEngineCustom, stat.ActiveEngine)
	}
	if stat.ReturnRouteOwner != ClientAWGEngineCustom {
		t.Errorf("expected return_route_owner %q, got %q", ClientAWGEngineCustom, stat.ReturnRouteOwner)
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
}

// TestDualEngine_StartupUpstreamMode verifies that upstream mode boots IngressEngine,
// does NOT start endpoint.Listener, does NOT open the legacy Linux TUN, and populates status.
func TestDualEngine_StartupUpstreamMode(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	// Opt in to RequireTunDevice to verify the critical invariant:
	// In upstream mode, legacy Linux TUN opener is completely skipped!
	svc.RequireTunDevice()

	if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		t.Fatalf("SetClientAWGEngine: %v", err)
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start: %v", err)
	}

	// Critical Invariant: In upstream mode, endpoint.Listener must NOT be running
	if svc.endpoint != nil && svc.endpoint.IsRunning() {
		t.Fatal("upstream mode: endpoint.Listener must NOT be running")
	}

	// Critical Invariant: In upstream mode, legacy TUN device must NOT be opened
	if svc.tunDev != nil {
		t.Fatal("upstream mode: legacy Linux TUN device must NOT be opened")
	}

	if svc.ingressEngine == nil || !svc.ingressEngine.Running() {
		t.Fatal("upstream mode: expected ingressEngine to be running")
	}

	stat, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ActiveEngine != ClientAWGEngineUpstream {
		t.Errorf("expected active_engine %q, got %q", ClientAWGEngineUpstream, stat.ActiveEngine)
	}
	if stat.ReturnRouteOwner != ClientAWGEngineUpstream {
		t.Errorf("expected return_route_owner %q, got %q", ClientAWGEngineUpstream, stat.ReturnRouteOwner)
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

// TestDualEngine_MutualPortExclusion verifies that both engines cannot bind or run concurrently.
func TestDualEngine_MutualPortExclusion(t *testing.T) {
	t.Run("custom running blocks upstream start", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		ctx := t.Context()

		if err := svc.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
			t.Fatal(err)
		}
		if err := svc.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = svc.Stop() }()

		// Force engine field to upstream under lock to test the runtime exclusion check
		svc.mu.Lock()
		svc.clientAWGEngine = ClientAWGEngineUpstream
		svc.running = false // simulate re-entrant or racing start attempt
		svc.mu.Unlock()

		err := svc.Start(ctx)
		if err == nil {
			t.Fatal("expected Start() to reject upstream start while custom listener is running")
		}
		if !strings.Contains(err.Error(), "custom endpoint listener is already running") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("upstream running blocks custom start", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		ctx := t.Context()

		if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
			t.Fatal(err)
		}
		if err := svc.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = svc.Stop() }()

		// Force engine field to custom under lock to test the runtime exclusion check
		svc.mu.Lock()
		svc.clientAWGEngine = ClientAWGEngineCustom
		svc.running = false // simulate re-entrant or racing start attempt
		svc.mu.Unlock()

		err := svc.Start(ctx)
		if err == nil {
			t.Fatal("expected Start() to reject custom start while upstream engine is running")
		}
		if !strings.Contains(err.Error(), "upstream ingress engine is already running") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
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

// TestDualEngine_StartupLogging verifies the startup log format:
// "[vpn] active client AWG engine=<custom|upstream> listen_port=<port>"
func TestDualEngine_StartupLogging(t *testing.T) {
	prevLog := log.Writer()
	defer log.SetOutput(prevLog)

	var buf1 safeLogBuffer
	log.SetOutput(&buf1)

	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	ctx1, cancel1 := context.WithCancel(t.Context())
	if err := svc.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
		cancel1()
		t.Fatal(err)
	}
	if err := svc.Start(ctx1); err != nil {
		cancel1()
		t.Fatal(err)
	}
	_ = svc.Stop()
	cancel1()

	output1 := buf1.String()
	if !strings.Contains(output1, "[vpn] active client AWG engine=custom listen_port=") {
		t.Fatalf("missing custom startup log in output:\n%s", output1)
	}

	var buf2 safeLogBuffer
	log.SetOutput(&buf2)

	ctx2, cancel2 := context.WithCancel(t.Context())
	if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		cancel2()
		t.Fatal(err)
	}
	if err := svc.Start(ctx2); err != nil {
		cancel2()
		t.Fatal(err)
	}
	_ = svc.Stop()
	cancel2()

	output2 := buf2.String()
	if !strings.Contains(output2, "[vpn] active client AWG engine=upstream listen_port=") {
		t.Fatalf("missing upstream startup log in output:\n%s", output2)
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

// TestDualEngine_ReturnRouteOwnershipTransfer verifies that Custom -> Upstream cutover
// binds live routes to the new ReturnPath, and Upstream -> Custom rollback cleanly
// rebinds routes to nil or retires them.
func TestDualEngine_ReturnRouteOwnershipTransfer(t *testing.T) {
	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 128, 100)
	if err != nil {
		t.Fatal(err)
	}
	fwd.Start(t.Context())
	defer func() { _ = fwd.Stop() }()

	peerKey := "transfer-peer"
	assignedIP := "10.100.0.25"
	sessionID := "transfer-sess"
	connID := "transfer-conn"
	backendID := int64(42)

	// Step 1: Initial custom route (returnPath == nil)
	_, err = fwd.TryRegisterSessionWithReturnPath(sessionID, connID, peerKey, assignedIP, backendID, 0, 0, nil)
	if err != nil {
		t.Fatalf("initial legacy registration: %v", err)
	}
	if !fwd.HasSessionRoute(peerKey, sessionID, connID, assignedIP, backendID) {
		t.Fatal("expected legacy route to be registered")
	}

	// Step 2: Custom -> Upstream cutover: bind route to new ReturnPath
	var upstreamWritten atomic.Int64
	upstreamPath := forwarder.NewReturnPath(func(peer, ip string, pkt []byte) (int, error) {
		upstreamWritten.Add(1)
		return len(pkt), nil
	})

	retirement, err := fwd.BindSessionReturnPath(sessionID, connID, peerKey, assignedIP, backendID, upstreamPath)
	if err != nil {
		t.Fatalf("cutover BindSessionReturnPath: %v", err)
	}
	retirement.Wait()

	if !fwd.HasSessionRouteWithReturnPath(peerKey, sessionID, connID, assignedIP, backendID, upstreamPath) {
		t.Fatal("expected route to be bound to upstream ReturnPath")
	}

	// Step 3: Upstream -> Custom rollback: rebind route back to nil ReturnPath
	upstreamPath.Close()
	rollbackRetirement, err := fwd.BindSessionReturnPath(sessionID, connID, peerKey, assignedIP, backendID, nil)
	if err != nil {
		t.Fatalf("rollback BindSessionReturnPath: %v", err)
	}
	rollbackRetirement.Wait()

	if !fwd.HasSessionRoute(peerKey, sessionID, connID, assignedIP, backendID) {
		t.Fatal("expected route to remain active after rollback")
	}
	if fwd.HasSessionRouteWithReturnPath(peerKey, sessionID, connID, assignedIP, backendID, upstreamPath) {
		t.Fatal("upstream ReturnPath must no longer be bound after rollback")
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

// TestDualEngine_BidirectionalTrafficRollback_NoConfigRegeneration tests full
// custom -> upstream -> custom cutover and rollback using the same DB, same port,
// and same client configuration without any config regeneration.
func TestDualEngine_BidirectionalTrafficRollback_NoConfigRegeneration(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	// Issue client configuration once at the beginning
	peer, clientCfg := newEnginePeer(t, svc, db, "rollout-client")
	clientIP := netip.MustParseAddr(peer.assignedIP)
	dst := netip.MustParseAddr("198.51.100.1")
	testPkt := engineUDPPacket(clientIP, dst, 0x12345678)

	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	// Phase 1: Start in upstream mode and verify traffic flow
	if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		t.Fatalf("SetClientAWGEngine(upstream): %v", err)
	}
	if err := svc.Start(t.Context()); err != nil {
		t.Fatalf("svc.Start(upstream): %v", err)
	}

	uc1 := startEngineUpstreamClient(t, clientCfg, "rollout-client-1")
	uc1.inject(t, testPkt)
	stopPump1 := pumpEnginePacketUntil(t, uc1, testPkt, nil)

	// Await session admission
	sessionDeadline := time.NewTimer(engineHandshakeTimeout)
	var admittedTunnelID int64
	for {
		got, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
		if ok && got.Status == "connected" {
			admittedTunnelID = got.BackendTunnelID
			break
		}
		select {
		case <-sessionDeadline.C:
			t.Fatal("phase 1: admission never completed for client")
		case <-time.After(25 * time.Millisecond):
		}
	}
	sessionDeadline.Stop()

	queue1, ok := svc.forwarder.GetBackendPacketChannel(admittedTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing", admittedTunnelID)
	}
	awaitEngineBackendPacket(t, queue1, testPkt)
	stopPump1()

	// Stop upstream service cleanly
	if err := svc.Stop(); err != nil {
		t.Fatalf("stop upstream service: %v", err)
	}

	// Phase 2: Instant Rollback to custom mode without config regeneration
	if err := svc.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
		t.Fatalf("SetClientAWGEngine(custom): %v", err)
	}
	if err := svc.Start(t.Context()); err != nil {
		t.Fatalf("svc.Start(custom): %v", err)
	}

	stat, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("GetStatus after rollback: %v", err)
	}
	if stat.ActiveEngine != ClientAWGEngineCustom {
		t.Fatalf("expected active_engine custom after rollback, got %q", stat.ActiveEngine)
	}
	if stat.ReturnRouteOwner != ClientAWGEngineCustom {
		t.Fatalf("expected return_route_owner custom after rollback, got %q", stat.ReturnRouteOwner)
	}

	// Verify database connection row and assigned IP were preserved unmodified
	conn, err := db.GetConnectionByToken(t.Context(), peer.publicKey)
	if err != nil {
		t.Fatalf("GetConnectionByToken: %v", err)
	}
	if conn == nil {
		t.Fatal("connection row not found after rollback")
	}
	if conn.ClientParams["assigned_ip"] != peer.assignedIP {
		t.Fatalf("assigned IP changed: was %s, now %v", peer.assignedIP, conn.ClientParams["assigned_ip"])
	}
	if conn.ClientParams["config_regeneration_required"] == true {
		t.Fatal("unexpected config_regeneration_required flag after rollback")
	}

	// Stop custom service cleanly
	if err := svc.Stop(); err != nil {
		t.Fatalf("stop custom service: %v", err)
	}

	// Phase 3: Cutover back to upstream mode using the exact same frozen client configuration
	if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		t.Fatalf("SetClientAWGEngine(upstream phase 3): %v", err)
	}
	if err := svc.Start(t.Context()); err != nil {
		t.Fatalf("svc.Start(upstream phase 3): %v", err)
	}
	defer func() { _ = svc.Stop() }()

	uc2 := startEngineUpstreamClient(t, clientCfg, "rollout-client-2")
	testPktPhase3 := engineUDPPacket(clientIP, dst, 0x87654321)
	uc2.inject(t, testPktPhase3)
	stopPump2 := pumpEnginePacketUntil(t, uc2, testPktPhase3, nil)
	defer stopPump2()

	sessionDeadline3 := time.NewTimer(engineHandshakeTimeout)
	defer sessionDeadline3.Stop()
	for {
		got, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
		if ok && got.Status == "connected" {
			admittedTunnelID = got.BackendTunnelID
			break
		}
		select {
		case <-sessionDeadline3.C:
			t.Fatal("phase 3: admission never completed for client with unchanged config")
		case <-time.After(25 * time.Millisecond):
		}
	}

	queue3, ok := svc.forwarder.GetBackendPacketChannel(admittedTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing in phase 3", admittedTunnelID)
	}
	awaitEngineBackendPacket(t, queue3, testPktPhase3)
	stopPump2()
}
