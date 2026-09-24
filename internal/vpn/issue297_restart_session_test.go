package vpn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestRestartInvalidatesPersistedSessionsAndResetsGauges verifies that restarting
// Nexus invalidates any pre-existing connected or draining database sessions to
// disconnected, prevents ghost sessions from being restored into SessionManager,
// resets backend tunnel active connection gauges to 0, and leaves forwarder routes clean.
func TestRestartInvalidatesPersistedSessionsAndResetsGauges(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) < 2 {
		t.Fatalf("expected at least 2 backend tunnels, got %d (err: %v)", len(tunnels), err)
	}
	tun1 := tunnels[0]
	tun2 := tunnels[1]

	// Simulate pre-restart state where tunnels had active connection counts
	if err := db.UpdateBackendTunnel(ctx, tun1.ID, map[string]any{"active_connections": 3}); err != nil {
		t.Fatalf("failed to update tunnel 1 connections: %v", err)
	}
	if err := db.UpdateBackendTunnel(ctx, tun2.ID, map[string]any{"active_connections": 2}); err != nil {
		t.Fatalf("failed to update tunnel 2 connections: %v", err)
	}

	// Create additional users and user connections
	u2ID, err := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}
	peerKeyBob := "bob-awg-peer-public-key"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   u2ID,
		ServerID: tun1.ServerID,
		Protocol: "awg",
		ClientID: peerKeyBob,
		Name:     "bob-laptop",
	}); err != nil {
		t.Fatalf("CreateConnection bob failed: %v", err)
	}

	u3ID, err := db.CreateUser(ctx, &models.User{Username: "charlie", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser charlie failed: %v", err)
	}
	peerKeyCharlie := "charlie-awg-peer-public-key"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   u3ID,
		ServerID: tun2.ServerID,
		Protocol: "awg",
		ClientID: peerKeyCharlie,
		Name:     "charlie-phone",
	}); err != nil {
		t.Fatalf("CreateConnection charlie failed: %v", err)
	}

	// Pre-populate database with sessions having status 'connected' and 'draining'
	sess1 := &models.VPNSession{
		ID:              "sess-alice-pre-restart",
		UserID:          uID,
		BackendTunnelID: tun1.ID,
		PeerPublicKey:   peerKeyAlice,
		AssignedIP:      "10.100.0.50",
		Status:          "connected",
		ConnectedAt:     time.Now().UTC().Add(-10 * time.Minute),
		LastSeen:        time.Now().UTC().Add(-1 * time.Minute),
	}
	sess2 := &models.VPNSession{
		ID:              "sess-bob-pre-restart",
		UserID:          u2ID,
		BackendTunnelID: tun1.ID,
		PeerPublicKey:   peerKeyBob,
		AssignedIP:      "10.100.0.51",
		Status:          "connected",
		ConnectedAt:     time.Now().UTC().Add(-5 * time.Minute),
		LastSeen:        time.Now().UTC().Add(-30 * time.Second),
	}
	sess3 := &models.VPNSession{
		ID:              "sess-charlie-pre-restart",
		UserID:          u3ID,
		BackendTunnelID: tun2.ID,
		PeerPublicKey:   peerKeyCharlie,
		AssignedIP:      "10.100.0.52",
		Status:          "draining",
		ConnectedAt:     time.Now().UTC().Add(-2 * time.Minute),
		LastSeen:        time.Now().UTC().Add(-20 * time.Second),
	}

	for _, s := range []*models.VPNSession{sess1, sess2, sess3} {
		if err := db.CreateVPNSession(ctx, s); err != nil {
			t.Fatalf("CreateVPNSession %s failed: %v", s.ID, err)
		}
	}

	// Verify pre-restart active sessions count in DB is 2 (connected)
	preActive, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions failed: %v", err)
	}
	if len(preActive) != 2 {
		t.Fatalf("expected 2 active sessions before restart, got %d", len(preActive))
	}

	// Start VPN service (simulating clean service restart)
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("vpnSvc.Start failed: %v", err)
	}
	t.Cleanup(func() {
		vpnSvc.Stop()
	})

	// 1. SessionManager must report 0 active sessions
	if activeCount := vpnSvc.SessionManager().ActiveCount(); activeCount != 0 {
		t.Errorf("expected SessionManager ActiveCount to be 0 on restart, got %d", activeCount)
	}

	// 2. Database active sessions must be 0
	postActive, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions post restart failed: %v", err)
	}
	if len(postActive) != 0 {
		t.Errorf("expected 0 active sessions in DB post restart, got %d", len(postActive))
	}

	// 3. Verify each pre-existing session row transitioned to 'disconnected'
	for _, id := range []string{sess1.ID, sess2.ID, sess3.ID} {
		s, err := db.GetVPNSessionByID(ctx, id)
		if err != nil {
			t.Fatalf("GetVPNSessionByID(%s) failed: %v", id, err)
		}
		if s == nil {
			t.Fatalf("session %s not found in DB", id)
		}
		if s.Status != "disconnected" {
			t.Errorf("session %s expected status 'disconnected', got %q", id, s.Status)
		}
	}

	// 4. Backend tunnel active connection gauges must be reconciled to 0 in both pool and DB
	t1Pool, err := vpnSvc.pool.GetTunnelByID(tun1.ID)
	if err != nil || t1Pool.ActiveConnections != 0 {
		t.Errorf("expected tunnel 1 pool ActiveConnections to be 0, got %v (err: %v)", t1Pool, err)
	}
	t2Pool, err := vpnSvc.pool.GetTunnelByID(tun2.ID)
	if err != nil || t2Pool.ActiveConnections != 0 {
		t.Errorf("expected tunnel 2 pool ActiveConnections to be 0, got %v (err: %v)", t2Pool, err)
	}

	t1DB, err := db.GetBackendTunnel(ctx, tun1.ID)
	if err != nil || t1DB == nil || t1DB.ActiveConnections != 0 {
		t.Errorf("expected tunnel 1 DB ActiveConnections to be 0, got %v (err: %v)", t1DB, err)
	}
	t2DB, err := db.GetBackendTunnel(ctx, tun2.ID)
	if err != nil || t2DB == nil || t2DB.ActiveConnections != 0 {
		t.Errorf("expected tunnel 2 DB ActiveConnections to be 0, got %v (err: %v)", t2DB, err)
	}

	// 5. Forwarder must have no ghost routes registered
	for _, peerKey := range []string{peerKeyAlice, peerKeyBob, peerKeyCharlie} {
		if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKey); ok {
			t.Errorf("expected forwarder route for peer %s to be absent, but found registered", peerKey)
		}
	}

	// 6. Metrics verification
	metrics := vpnSvc.SessionMetrics()
	if metrics["startup_invalidated_sessions_total"] != 3 {
		t.Errorf("expected startup_invalidated_sessions_total to be 3, got %d", metrics["startup_invalidated_sessions_total"])
	}
	if metrics["fresh_handshakes_after_startup_total"] != 0 {
		t.Errorf("expected fresh_handshakes_after_startup_total to be 0, got %d", metrics["fresh_handshakes_after_startup_total"])
	}
}

// TestPeerReconnectPostRestartRestoresForwarderAndGauge verifies that existing clients
// whose sessions were invalidated at startup can reconnect seamlessly via standard handshake,
// creating a connected DB session, allocating IPAM, registering forwarder routes, and
// accurately incrementing tunnel gauges.
func TestPeerReconnectPostRestartRestoresForwarderAndGauge(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("no backend tunnels found")
	}
	tun := tunnels[0]

	// Pre-create connected session for alice
	sessAlice := &models.VPNSession{
		ID:              "alice-prior-sess",
		UserID:          uID,
		BackendTunnelID: tun.ID,
		PeerPublicKey:   peerKeyAlice,
		AssignedIP:      "10.100.0.50",
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, sessAlice); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}

	// Start service (invalidates alice to disconnected)
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() {
		vpnSvc.Stop()
	})

	if vpnSvc.SessionManager().ActiveCount() != 0 {
		t.Fatalf("expected ActiveCount to be 0 after restart")
	}

	// Client reconnects via HandleIncomingPeer (standard handshake)
	sess, backend, err := vpnSvc.HandleIncomingPeer(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for reconnecting peer: %v", err)
	}
	if sess == nil || backend == nil {
		t.Fatalf("expected valid session and backend, got sess=%v, backend=%v", sess, backend)
	}

	// Verify session properties
	if sess.Status != "connected" {
		t.Errorf("expected session status 'connected', got %q", sess.Status)
	}
	if sess.PeerPublicKey != peerKeyAlice {
		t.Errorf("expected session peer public key %s, got %s", peerKeyAlice, sess.PeerPublicKey)
	}
	if sess.AssignedIP == "" {
		t.Errorf("expected non-empty assigned IP")
	}

	// Verify SessionManager active count is 1
	if vpnSvc.SessionManager().ActiveCount() != 1 {
		t.Errorf("expected SessionManager ActiveCount to be 1, got %d", vpnSvc.SessionManager().ActiveCount())
	}

	// Verify forwarder route is registered
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); !ok {
		t.Errorf("expected forwarder route for %s to be registered", peerKeyAlice)
	}

	// Verify pool active connections gauge incremented to 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(backend.ID)
	if err != nil || tunAfter.ActiveConnections != 1 {
		t.Errorf("expected backend %d active connections to be 1, got %v (err: %v)", backend.ID, tunAfter, err)
	}

	// Verify DB reflects connected status
	dbSess, err := db.GetVPNSessionByPeerKey(ctx, peerKeyAlice)
	if err != nil || dbSess == nil {
		t.Fatalf("failed to query session from DB: %v", err)
	}
	if dbSess.Status != "connected" {
		t.Errorf("expected DB session status 'connected', got %q", dbSess.Status)
	}

	// Verify metrics reflect 1 fresh handshake
	metrics := vpnSvc.SessionMetrics()
	if metrics["startup_invalidated_sessions_total"] != 1 {
		t.Errorf("expected startup_invalidated_sessions_total to be 1, got %d", metrics["startup_invalidated_sessions_total"])
	}
	if metrics["fresh_handshakes_after_startup_total"] != 1 {
		t.Errorf("expected fresh_handshakes_after_startup_total to be 1, got %d", metrics["fresh_handshakes_after_startup_total"])
	}
}

// TestServiceRestartIdempotency verifies that successive restarts or clean starts
// without stale sessions behave idempotently without errors or data corruption.
func TestServiceRestartIdempotency(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// 1. InvalidateConnectedSessionsOnRestart on clean DB is a no-op
	count, err := db.InvalidateConnectedSessionsOnRestart(ctx)
	if err != nil {
		t.Fatalf("invalidation on clean DB failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 affected sessions, got %d", count)
	}

	// 2. Start service on clean DB
	vpnSvc, _, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("Start service failed: %v", err)
	}

	metrics := vpnSvc.SessionMetrics()
	if metrics["startup_invalidated_sessions_total"] != 0 {
		t.Errorf("expected 0 startup_invalidated_sessions_total, got %d", metrics["startup_invalidated_sessions_total"])
	}
	if metrics["fresh_handshakes_after_startup_total"] != 0 {
		t.Errorf("expected 0 fresh_handshakes_after_startup_total, got %d", metrics["fresh_handshakes_after_startup_total"])
	}
	vpnSvc.Stop()

	// 3. Second restart on same DB should also start cleanly
	vpnSvc2, _, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc2.Start(ctx); err != nil {
		t.Fatalf("Start service 2 failed: %v", err)
	}
	defer vpnSvc2.Stop()

	if vpnSvc2.SessionManager().ActiveCount() != 0 {
		t.Errorf("expected 0 active sessions on restart, got %d", vpnSvc2.SessionManager().ActiveCount())
	}
}

// TestLeastConnectionBalancingAccurateAfterRestart proves that stale active_connections
// gauges from before restart are reset to 0, ensuring least-connection load balancing
// distributes traffic evenly without distortion from pre-restart ghost sessions.
func TestLeastConnectionBalancingAccurateAfterRestart(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Disable sticky sessions so pure least-connections balancer applies
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db, func(cfg *models.VPNConfig) {
		cfg.AffinityTTLMinutes = -1
	})

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) < 2 {
		t.Fatalf("expected at least 2 backend tunnels, got %d", len(tunnels))
	}
	tun1 := tunnels[0]
	tun2 := tunnels[1]

	// Simulate pre-restart distortion: Tunnel 1 was left with 5 active connections in DB
	if err := db.UpdateBackendTunnel(ctx, tun1.ID, map[string]any{"active_connections": 5}); err != nil {
		t.Fatalf("failed to update tunnel 1 active connections: %v", err)
	}

	// Create 5 stale sessions on Tunnel 1
	for i := 1; i <= 5; i++ {
		staleSess := &models.VPNSession{
			ID:              fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
			UserID:          uID,
			BackendTunnelID: tun1.ID,
			PeerPublicKey:   fmt.Sprintf("test-stale-peer-%d", i),
			AssignedIP:      fmt.Sprintf("10.100.1.%d", i),
			Status:          "connected",
		}
		if err := db.CreateVPNSession(ctx, staleSess); err != nil {
			t.Fatalf("CreateVPNSession %d failed: %v", i, err)
		}
	}

	// Register another user connection for bob
	u2ID, err := db.CreateUser(ctx, &models.User{Username: "bob-lb", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	peerKeyBob := "bob-lb-peer-public-key"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   u2ID,
		ServerID: tun2.ServerID,
		Protocol: "awg",
		ClientID: peerKeyBob,
		Name:     "bob-device",
	}); err != nil {
		t.Fatalf("CreateConnection bob failed: %v", err)
	}

	// Start service: restart must invalidate all 5 sessions and reset tunnel 1 gauge to 0
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() {
		vpnSvc.Stop()
	})

	// Both tunnels must have 0 connections now
	t1After, err := vpnSvc.pool.GetTunnelByID(tun1.ID)
	if err != nil || t1After.ActiveConnections != 0 {
		t.Fatalf("expected tunnel 1 active connections to be 0, got %v (err: %v)", t1After, err)
	}
	t2After, err := vpnSvc.pool.GetTunnelByID(tun2.ID)
	if err != nil || t2After.ActiveConnections != 0 {
		t.Fatalf("expected tunnel 2 active connections to be 0, got %v (err: %v)", t2After, err)
	}

	// Peer 1 connects: gets assigned to one backend, incrementing it to 1
	_, b1, err := vpnSvc.HandleIncomingPeer(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeer alice failed: %v", err)
	}

	// Peer 2 connects: least-connections MUST select the other backend (which still has 0 connections)
	_, b2, err := vpnSvc.HandleIncomingPeer(ctx, peerKeyBob)
	if err != nil {
		t.Fatalf("HandleIncomingPeer bob failed: %v", err)
	}

	if b1.ID == b2.ID {
		t.Errorf("least-connection balancing failed: both peers routed to backend %d instead of balancing across backends", b1.ID)
	}

	// Both backends now have exactly 1 active connection
	t1Final, _ := vpnSvc.pool.GetTunnelByID(tun1.ID)
	t2Final, _ := vpnSvc.pool.GetTunnelByID(tun2.ID)
	if t1Final.ActiveConnections != 1 || t2Final.ActiveConnections != 1 {
		t.Errorf("expected each backend to have 1 connection, got t1=%d, t2=%d", t1Final.ActiveConnections, t2Final.ActiveConnections)
	}
}

// TestRestartFailsClosedOnInvalidationFailure verifies that when session invalidation
// fails during startup (e.g. read-only database or write failure):
// 1. Service.Start() fails immediately and returns a wrapped error.
// 2. Service.IsRunning() remains false.
// 3. Listener is NOT running.
// 4. Forwarder and packet pumps are NOT running.
// 5. No backend devices are attached or leaked.
// 6. When the write error condition is cleared, subsequent Start() succeeds.
func TestRestartFailsClosedOnInvalidationFailure(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("expected backend tunnels, got %d (err: %v)", len(tunnels), err)
	}
	tun1 := tunnels[0]

	// Seed pre-restart state with non-zero active connections and a connected session
	if err := db.UpdateBackendTunnel(ctx, tun1.ID, map[string]any{"active_connections": 4}); err != nil {
		t.Fatalf("failed to update tunnel 1 connections: %v", err)
	}
	staleSess := &models.VPNSession{
		ID:              "sess-fail-closed-test",
		UserID:          uID,
		BackendTunnelID: tun1.ID,
		PeerPublicKey:   peerKeyAlice,
		AssignedIP:      "10.100.0.99",
		Status:          "connected",
		ConnectedAt:     time.Now().UTC().Add(-10 * time.Minute),
		LastSeen:        time.Now().UTC().Add(-1 * time.Minute),
	}
	if err := db.CreateVPNSession(ctx, staleSess); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}

	// Make database read-only via PRAGMA query_only = ON so writes fail
	if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA query_only = ON;"); err != nil {
		t.Fatalf("failed to set PRAGMA query_only: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.SQLDB().ExecContext(context.Background(), "PRAGMA query_only = OFF;")
	})

	// Attempt to start the VPN service: must fail closed
	startErr := vpnSvc.Start(ctx)
	if startErr == nil {
		t.Fatal("expected vpnSvc.Start to fail when database invalidation fails, got nil")
	}

	// Invariant 1: Start returns an error wrapping the invalidation failure
	if !strings.Contains(startErr.Error(), "failed to invalidate persisted VPN sessions on restart") {
		t.Errorf("expected error message to mention invalidation failure, got: %v", startErr)
	}

	// Invariant 2: Service is NOT running
	if vpnSvc.IsRunning() {
		t.Error("expected vpnSvc.IsRunning() to be false after startup failure")
	}

	// Invariant 3: Listener is NOT running
	if vpnSvc.endpoint != nil && vpnSvc.endpoint.IsRunning() {
		t.Error("expected endpoint listener to not be running")
	}

	// Invariant 4: Forwarder is NOT running
	if vpnSvc.forwarder != nil && vpnSvc.forwarder.IsRunning() {
		t.Error("expected forwarder to not be running")
	}

	// Invariant 5: No backend devices attached or leaked
	vpnSvc.mu.RLock()
	devCount := len(vpnSvc.backendDevices)
	vpnSvc.mu.RUnlock()
	if devCount != 0 {
		t.Errorf("expected 0 backend devices attached, got %d", devCount)
	}

	// Invariant 6: Database state is unmodified due to atomic rollback
	sessCheck, err := db.GetVPNSessionByID(ctx, staleSess.ID)
	if err != nil || sessCheck == nil {
		t.Fatalf("failed to query session after failed start: %v", err)
	}
	if sessCheck.Status != "connected" {
		t.Errorf("expected session to remain 'connected' after transaction rollback, got %q", sessCheck.Status)
	}

	// Restore database writeability and verify clean start recovery
	if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA query_only = OFF;"); err != nil {
		t.Fatalf("failed to clear PRAGMA query_only: %v", err)
	}

	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("expected vpnSvc.Start to succeed after clearing read-only, got: %v", err)
	}
	defer vpnSvc.Stop()

	if !vpnSvc.IsRunning() {
		t.Error("expected vpnSvc.IsRunning() to be true after successful start")
	}

	sessRecovered, err := db.GetVPNSessionByID(ctx, staleSess.ID)
	if err != nil || sessRecovered == nil {
		t.Fatalf("failed to query session after recovery start: %v", err)
	}
	if sessRecovered.Status != "disconnected" {
		t.Errorf("expected session status to be 'disconnected' after recovery start, got %q", sessRecovered.Status)
	}

	tunRecovered, err := vpnSvc.pool.GetTunnelByID(tun1.ID)
	if err != nil || tunRecovered.ActiveConnections != 0 {
		t.Errorf("expected tunnel active connections to be reset to 0, got %d (err: %v)", tunRecovered.ActiveConnections, err)
	}
}
