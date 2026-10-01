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

	t.Run("default to custom when empty or whitespace", func(t *testing.T) {
		cleanup()
		for _, raw := range []string{"", "   \t"} {
			os.Setenv("VPN_CLIENT_AWG_ENGINE", raw)
			db := setupTestDB(t)
			svc, err := NewVPNService(db, nil)
			if err != nil {
				t.Fatalf("NewVPNService with %q: %v", raw, err)
			}
			if svc.ClientAWGEngine() != ClientAWGEngineCustom {
				t.Fatalf("expected default engine %q, got %q", ClientAWGEngineCustom, svc.ClientAWGEngine())
			}
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

		// Empty string or whitespace defaults to custom
		for _, emptyVal := range []string{"", "   "} {
			if err := svc.SetClientAWGEngine(emptyVal); err != nil {
				t.Fatalf("SetClientAWGEngine(%q): %v", emptyVal, err)
			}
			if svc.ClientAWGEngine() != ClientAWGEngineCustom {
				t.Fatalf("expected default %q for %q, got %q", ClientAWGEngineCustom, emptyVal, svc.ClientAWGEngine())
			}
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
	if stat.ConfiguredEngine != ClientAWGEngineCustom {
		t.Errorf("expected configured_engine %q, got %q", ClientAWGEngineCustom, stat.ConfiguredEngine)
	}
	if stat.ActiveEngine != ClientAWGEngineCustom {
		t.Errorf("expected active_engine %q, got %q", ClientAWGEngineCustom, stat.ActiveEngine)
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

func (s *safeLogBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

// TestDualEngine_StartupLogging verifies the startup log format:
// "[vpn] active client AWG engine=<custom|upstream> listen_port=<port>"
func TestDualEngine_StartupLogging(t *testing.T) {
	prevLog := log.Writer()
	defer log.SetOutput(prevLog)

	var buf safeLogBuffer
	log.SetOutput(&buf)

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
	cancel1()
	_ = svc.Stop()

	output1 := buf.String()
	if !strings.Contains(output1, "[vpn] active client AWG engine=custom listen_port=") {
		t.Fatalf("missing custom startup log in output:\n%s", output1)
	}

	buf.Reset()

	ctx2, cancel2 := context.WithCancel(t.Context())
	if err := svc.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		cancel2()
		t.Fatal(err)
	}
	if err := svc.Start(ctx2); err != nil {
		cancel2()
		t.Fatal(err)
	}
	cancel2()
	_ = svc.Stop()

	output2 := buf.String()
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
	if stat.ConfiguredEngine != ClientAWGEngineCustom {
		t.Errorf("expected configured_engine %q, got %q", ClientAWGEngineCustom, stat.ConfiguredEngine)
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

	// State 2: Running in custom mode without routes
	if err := svc.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ActiveEngine != ClientAWGEngineCustom {
		t.Errorf("expected active_engine custom, got %q", stat.ActiveEngine)
	}
	if !stat.EngineRunning {
		t.Error("expected engine_running true")
	}
	if stat.ReturnRouteOwner != "none" {
		t.Errorf("expected return_route_owner 'none' without routes, got %q", stat.ReturnRouteOwner)
	}

	// Register a custom mode route (returnPath == nil)
	retirement := svc.forwarder.BeginRegisterSessionWithLimit("sess-c", "conn-c", "peer-c", "10.100.0.10", 1, 0, 0)
	retirement.Wait()
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ReturnRouteOwner != ClientAWGEngineCustom {
		t.Errorf("expected return_route_owner custom with custom routes, got %q", stat.ReturnRouteOwner)
	}

	// Stop service cleanly
	svc.forwarder.UnregisterSession("peer-c")
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	stat, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus after stop: %v", err)
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

	// State 3: Process restart into upstream mode
	svcUp := newIngressEngineService(t, db)
	if err := svcUp.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		t.Fatal(err)
	}
	if err := svcUp.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svcUp.Stop() }()

	stat, err = svcUp.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ConfiguredEngine != ClientAWGEngineUpstream {
		t.Errorf("expected configured_engine upstream, got %q", stat.ConfiguredEngine)
	}
	if stat.ActiveEngine != ClientAWGEngineUpstream {
		t.Errorf("expected active_engine upstream, got %q", stat.ActiveEngine)
	}
	if !stat.EngineRunning {
		t.Error("expected engine_running true in upstream mode")
	}
	if stat.ReturnRouteOwner != "none" {
		t.Errorf("expected return_route_owner 'none' without routes, got %q", stat.ReturnRouteOwner)
	}

	// Register an upstream mode route (returnPath != nil)
	upPath := forwarder.NewReturnPath(func(peer, ip string, p []byte) (int, error) {
		return len(p), nil
	})
	_, err = svcUp.forwarder.TryRegisterSessionWithReturnPath("sess-u", "conn-u", "peer-u", "10.100.0.20", 1, 0, 0, upPath)
	if err != nil {
		t.Fatalf("TryRegisterSessionWithReturnPath: %v", err)
	}
	stat, err = svcUp.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ReturnRouteOwner != ClientAWGEngineUpstream {
		t.Errorf("expected return_route_owner upstream with upstream routes, got %q", stat.ReturnRouteOwner)
	}

	// Verify mixed ownership detection if forwarder contains both route types
	retMixed := svcUp.forwarder.BeginRegisterSessionWithLimit("sess-m", "conn-m", "peer-m", "10.100.0.30", 1, 0, 0)
	retMixed.Wait()
	stat, err = svcUp.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if stat.ReturnRouteOwner != "mixed" {
		t.Errorf("expected return_route_owner 'mixed' with mixed routes, got %q", stat.ReturnRouteOwner)
	}

	// Stop upstream service cleanly
	if err := svcUp.Stop(); err != nil {
		t.Fatal(err)
	}
	stat, err = svcUp.GetStatus(ctx)
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
