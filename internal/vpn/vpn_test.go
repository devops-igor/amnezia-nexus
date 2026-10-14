package vpn

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

func setupTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_vpn_service.db")
	db, err := database.Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func TestServiceAndBalancerSelection(t *testing.T) {
	lb := loadbalancer.NewLeastConnectionsBalancer(loadbalancer.CapacityConfig{})
	ctx := context.Background()

	// No tunnels
	req := &loadbalancer.RoutingRequest{AvailableTunnels: nil}
	_, err := lb.SelectBackend(ctx, req)
	if err == nil {
		t.Errorf("expected error with no tunnels")
	}

	// Degraded / disabled tunnels only
	tunnels := []*BackendTunnel{
		{ID: 1, InterfaceName: "awg-be-1", Status: TunnelStatusDegraded, ActiveConnections: 0},
		{ID: 2, InterfaceName: "awg-be-2", Status: TunnelStatusDisabled, ActiveConnections: 0},
	}
	_, err = lb.SelectBackend(ctx, &loadbalancer.RoutingRequest{AvailableTunnels: tunnels})
	if err == nil {
		t.Errorf("expected error when no active tunnels exist")
	}

	// Active tunnels selection
	tunnels = append(tunnels,
		&BackendTunnel{ID: 3, InterfaceName: "awg-be-3", Enabled: true, Status: TunnelStatusActive, ActiveConnections: 5},
		&BackendTunnel{ID: 4, InterfaceName: "awg-be-4", Enabled: true, Status: TunnelStatusActive, ActiveConnections: 2},
		&BackendTunnel{ID: 5, InterfaceName: "awg-be-5", Enabled: true, Status: TunnelStatusActive, ActiveConnections: 8},
	)

	best, err := lb.SelectBackend(ctx, &loadbalancer.RoutingRequest{AvailableTunnels: tunnels})
	if err != nil {
		t.Fatalf("SelectBackend failed: %v", err)
	}

	if best.ID != 4 {
		t.Errorf("expected tunnel ID 4 (2 active connections), got ID %d (%d connections)", best.ID, best.ActiveConnections)
	}

	// Production NewVPNService
	svc, err := NewVPNService(nil, &models.VPNConfig{Algorithm: models.LBLeastConnections})
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	bestSvc, err := svc.SelectTunnel(ctx, tunnels)
	if err != nil || bestSvc.ID != 4 {
		t.Errorf("SelectTunnel mismatch: %+v, err: %v", bestSvc, err)
	}
}

func setupTestVPNService(t *testing.T, db *database.DB, cfgMutators ...func(*models.VPNConfig)) (*Service, int64, int64, string, string) {
	t.Helper()
	ctx := context.Background()

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "US East", Host: "198.51.100.1", Protocols: map[string]any{
		"awg": map[string]any{"public_key": "us-east-pubkey", "port": 51820},
	}})
	s2ID, _ := db.CreateServer(ctx, &models.Server{Name: "EU West", Host: "198.51.100.2", Protocols: map[string]any{
		"awg": map[string]any{"public_key": "eu-west-pubkey", "port": 51820},
	}})

	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1ID,
		InterfaceName: "awg-be-1",
		PublicKey:     "us-east-pubkey",
		PrivateKey:    "us-east-privkey",
		Endpoint:      "198.51.100.1:51820",
		Status:        "active",
		LatencyMS:     30,
	})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s2ID,
		InterfaceName: "awg-be-2",
		PublicKey:     "eu-west-pubkey",
		PrivateKey:    "eu-west-privkey",
		Endpoint:      "198.51.100.2:51820",
		Status:        "active",
		LatencyMS:     50,
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "alice",
		Enabled:  true,
	})
	peerKeyAlice := "alice-awg-peer-public-key"
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKeyAlice,
		Name:     "alice-phone",
	})

	tempConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	testPort := 51820
	if err == nil {
		testPort = tempConn.LocalAddr().(*net.UDPAddr).Port
		_ = tempConn.Close()
	}

	cfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         testPort,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{s1ID: 50, s2ID: 50},
	}
	for _, mutate := range cfgMutators {
		mutate(cfg)
	}

	vpnSvc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}
	vpnSvc.SetProbeFunc(mockProbe)

	return vpnSvc, s1ID, s2ID, uID, peerKeyAlice
}

func TestVPNServiceSetupAndStatus(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, _, _ := setupTestVPNService(t, db)

	// Start
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !vpnSvc.IsRunning() {
		t.Errorf("expected vpnSvc to be running")
	}
	_ = vpnSvc.Start(ctx) // Double start noop

	// Status Check
	status, err := vpnSvc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if status.ActiveTunnels != 2 {
		t.Errorf("expected 2 active tunnels in status, got %d", status.ActiveTunnels)
	}

	// Backends / Tunnels Query
	backends, err := vpnSvc.GetBackends(ctx)
	if err != nil || len(backends) != 2 {
		t.Fatalf("GetBackends mismatch: len=%d, err=%v", len(backends), err)
	}
	tunnelsList, err := vpnSvc.GetTunnels(ctx)
	if err != nil || len(tunnelsList) != 2 {
		t.Fatalf("GetTunnels mismatch: len=%d, err=%v", len(tunnelsList), err)
	}

	if err := vpnSvc.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestVPNServicePeerConnections(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	_ = vpnSvc.Start(ctx)
	defer func() { _ = vpnSvc.Stop() }()

	// Handle Incoming Peer Connection
	sess, backend, err := vpnSvc.HandleIncomingPeerForTest(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeerForTest failed: %v", err)
	}
	if sess.UserID != uID || sess.PeerPublicKey != peerKeyAlice || sess.AssignedIP == "" {
		t.Errorf("invalid session returned: %+v", sess)
	}
	if backend == nil {
		t.Errorf("invalid backend returned")
	}

	// User Connection State Query
	userState, err := vpnSvc.GetUserConnectionState(ctx, uID)
	if err != nil || !userState.Connected || userState.Session == nil {
		t.Fatalf("GetUserConnectionState mismatch: %+v, err: %v", userState, err)
	}
	if userState.BackendEndpoint == "" {
		t.Errorf("expected non-empty backend endpoint")
	}

	ghostState, err := vpnSvc.GetUserConnectionState(ctx, "ghost-user")
	if err != nil || ghostState.Connected {
		t.Errorf("expected disconnected for ghost user")
	}

	// Disconnect Session
	if err := vpnSvc.DisconnectSession(ctx, sess.ID); err != nil {
		t.Fatalf("DisconnectSession failed: %v", err)
	}
	if err := vpnSvc.DisconnectSession(ctx, "ghost-session"); err == nil {
		t.Errorf("expected error disconnecting non-existent session")
	}

	// Reconnect and DisconnectUser
	_, _, _ = vpnSvc.HandleIncomingPeerForTest(ctx, peerKeyAlice)
	if err := vpnSvc.DisconnectUser(ctx, uID); err != nil {
		t.Fatalf("DisconnectUser failed: %v", err)
	}
	stateAfterDisconnect, _ := vpnSvc.GetUserConnectionState(ctx, uID)
	if stateAfterDisconnect.Connected {
		t.Errorf("expected disconnected after DisconnectUser")
	}

	// Enable & Disable Backend
	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	t1Status, _ := vpnSvc.pool.GetTunnel(s1ID)
	if t1Status.Enabled {
		t.Error("expected backend to be administratively disabled")
	}
	if t1Status.Status != "active" {
		t.Errorf("administrative disable changed runtime health: got %s, want active", t1Status.Status)
	}

	if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}
	t1Status, _ = vpnSvc.pool.GetTunnel(s1ID)
	if t1Status.Status != "active" {
		t.Errorf("expected status active, got %s", t1Status.Status)
	}
}

func TestVPNServiceConfigAndBackends(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	_ = vpnSvc.Start(ctx)
	defer func() { _ = vpnSvc.Stop() }()

	curCfg, err := vpnSvc.GetConfig(ctx)
	if err != nil || curCfg.Algorithm != models.LBLeastConnections {
		t.Fatalf("GetConfig mismatch: %+v, err: %v", curCfg, err)
	}

	curCfg.Algorithm = models.LBWeighted
	if err := vpnSvc.UpdateConfig(ctx, curCfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if err := vpnSvc.UpdateConfig(ctx, nil); err == nil {
		t.Errorf("expected error updating nil config")
	}

	// Generate Client Config
	cfgStr, filename, err := vpnSvc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, "[Interface]") || !strings.Contains(cfgStr, "[Peer]") {
		t.Errorf("invalid config generated: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, "DNS = 94.140.14.14, 94.140.15.15") {
		t.Errorf("expected AdGuard DNS (94.140.14.14, 94.140.15.15) in client config, got:\n%s", cfgStr)
	}
	if strings.Contains(cfgStr, "1.1.1.1") || strings.Contains(cfgStr, "1.0.0.1") {
		t.Errorf("client config must not contain Cloudflare DNS (1.1.1.1, 1.0.0.1), got:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "Jc =") || !strings.Contains(cfgStr, "S1 =") || !strings.Contains(cfgStr, "H1 =") {
		t.Errorf("expected AWG obfuscation parameters in config: %s", cfgStr)
	}
	if strings.Contains(cfgStr, "Endpoint = 198.51.100.1:") {
		t.Errorf("client config must NEVER use backend server endpoint, got: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, "Endpoint = ") {
		t.Errorf("expected Endpoint directive in config: %s", cfgStr)
	}
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, k+" =") || strings.HasPrefix(trimmed, k+"=") {
				t.Errorf("client config must NEVER contain %s (Issue #15), got:\n%s", k, cfgStr)
			}
		}
	}
	if filename != "amnezia-portal-alice.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	// Verify the client public key was persisted to user_connections and can be authenticated
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 || conns[0].ClientID == "" {
		t.Fatalf("expected registered connection for alice: %+v", conns)
	}
	newClientPub := conns[0].ClientID
	if sess, _, err := vpnSvc.HandleIncomingPeerForTest(ctx, newClientPub); err != nil || sess == nil {
		t.Fatalf("peer authentication with generated client key failed: %v", err)
	}

	if _, _, err := vpnSvc.GenerateClientConfig(ctx, "ghost-user"); err == nil {
		t.Errorf("expected error for ghost user config generation")
	}
}

func TestVPNServiceEdgeCases1(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// 1. Invalid Subnet CIDR
	invalidCfg := &models.VPNConfig{SubnetCIDR: "invalid-cidr"}
	if _, err := NewVPNService(db, invalidCfg); err == nil {
		t.Errorf("expected error on invalid subnet CIDR")
	}

	// 2. Nil Cfg with DB
	svcWithDB, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService with nil cfg failed: %v", err)
	}
	if svcWithDB.cfg.SubnetCIDR != "10.100.0.0/16" {
		t.Errorf("unexpected default CIDR: %s", svcWithDB.cfg.SubnetCIDR)
	}

	// 3. Nil Cfg without DB
	svcNoDB, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService without DB failed: %v", err)
	}
	if svcNoDB.cfg.Algorithm != models.LBLeastConnections {
		t.Errorf("unexpected default algorithm: %s", svcNoDB.cfg.Algorithm)
	}

	// 4. SetHealthProber
	svcNoDB.SetHealthProber(nil)

	// 5. GetStatus with nil sub-components
	emptySvc := &Service{}
	st, err := emptySvc.GetStatus(ctx)
	if err != nil || st.ListenerRunning || st.ActiveTunnels != 0 || st.ForwarderAvailable {
		t.Errorf("GetStatus emptySvc mismatch: %+v, err: %v", st, err)
	}
}

func TestVPNServiceEdgeCases2(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	emptySvc := &Service{}
	svcWithDB, _ := NewVPNService(db, nil)

	// 6. GetBackends with nil pool
	if _, err := emptySvc.GetBackends(ctx); err == nil {
		t.Errorf("expected error GetBackends nil pool")
	}

	// 7. EnableBackend and DisableBackend with nil pool
	if err := emptySvc.EnableBackend(ctx, 1); err == nil {
		t.Errorf("expected error EnableBackend nil pool")
	}
	if err := emptySvc.DisableBackend(ctx, 1); err == nil {
		t.Errorf("expected error DisableBackend nil pool")
	}

	// 8. DisableBackend non-existent server
	if err := svcWithDB.DisableBackend(ctx, 99999); err == nil {
		t.Errorf("expected error DisableBackend non-existent")
	}

	// 9. GetConfig with nil cfg
	if _, err := emptySvc.GetConfig(ctx); err == nil {
		t.Errorf("expected error GetConfig nil cfg")
	}

	// 10. GetUserConnectionState with nil sessionMgr
	state, err := emptySvc.GetUserConnectionState(ctx, "user-1")
	if err != nil || state.Connected {
		t.Errorf("expected disconnected for nil sessionMgr: %+v, err: %v", state, err)
	}

	// 11. DisconnectUser and DisconnectSession with nil sessionMgr
	if err := emptySvc.DisconnectUser(ctx, "user-1"); err != nil {
		t.Errorf("expected nil error on DisconnectUser nil sessionMgr")
	}
	if err := emptySvc.DisconnectSession(ctx, "sess-1"); err != nil {
		t.Errorf("expected nil error on DisconnectSession nil sessionMgr")
	}

	// 12. EnsureBackendSessionForIngress uninitialized
	if _, _, _, err := emptySvc.EnsureBackendSessionForIngress(ctx, ingress.PeerOwnership{PeerPublicKey: "peer"}); err == nil {
		t.Errorf("expected error EnsureBackendSessionForIngress uninitialized")
	}

	// 13. EnsureBackendSessionForIngress no active backends
	uID, _ := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true})
	_, _ = db.CreateServer(ctx, &models.Server{Name: "Server", Host: "10.0.0.1"})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: "bob-peer-key",
	})
	if _, _, _, err := svcWithDB.EnsureBackendSessionForIngress(ctx, ingress.PeerOwnership{PeerPublicKey: "bob-peer-key", UserID: uID}); err == nil {
		t.Errorf("expected error EnsureBackendSessionForIngress when no active backends")
	}

	// 14. GenerateClientConfig without DB and user not found
	if _, _, err := emptySvc.GenerateClientConfig(ctx, "any"); err == nil {
		t.Errorf("expected error GenerateClientConfig nil DB")
	}
	if _, _, err := svcWithDB.GenerateClientConfig(ctx, "non-existent-user"); err == nil {
		t.Errorf("expected error GenerateClientConfig user not found")
	}

	// 15. SelectTunnel uninitialized
	if _, err := emptySvc.SelectTunnel(ctx, nil); err == nil {
		t.Errorf("expected error SelectTunnel uninitialized")
	}

	// 16. Start error propagation on invalid listener port
	invalidListenerSvc, _ := NewVPNService(db, nil)
	// Bind to an occupied port to force listener error
	occConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err == nil {
		defer occConn.Close()
		occPort := occConn.LocalAddr().(*net.UDPAddr).Port
		cfg, err := invalidListenerSvc.GetConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ListenPort = occPort
		if err := invalidListenerSvc.UpdateConfig(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := invalidListenerSvc.Start(ctx); err == nil {
			t.Errorf("expected error from Start when port is occupied")
		}
		if invalidListenerSvc.IsRunning() {
			t.Errorf("expected IsRunning to be false after Start failure")
		}
	}
}

// --- config divergence regression tests (Issue #5 findings 1, 4, 7, 8, 9, 15) ---

func TestGetStatus_ExposesBoundedRouteQueueDiagnostics(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.forwarder.RegisterSession("session-1", "connection-1", "peer-secret", "10.100.0.10", 1)
	if err := svc.forwarder.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
		t.Fatalf("RouteBackendToClient failed: %v", err)
	}

	status, err := svc.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	// The map key is ingress.PeerKeyFingerprint, the opaque
	// collision-resistant identifier (issue #424 round 6, finding 2). The
	// round 5 form, a RedactKey prefix, could not be used here: two peers
	// sharing 8 leading characters produced the same key and one route was
	// silently dropped from the payload.
	stats, ok := status.ForwarderRouteQueues[ingress.PeerKeyFingerprint("peer-secret")]
	if !ok {
		t.Fatalf("route queue diagnostics missing: %+v", status.ForwarderRouteQueues)
	}
	if stats.Occupancy != 1 || stats.Capacity != 2048 || stats.HighWater != 1 {
		t.Fatalf("unexpected route queue diagnostics: %+v", stats)
	}
	// The redacted DISPLAY form is still available for a human reader, and is
	// still not a usable identifier.
	if stats.PeerKeyDisplay != ingress.RedactKey("peer-secret") {
		t.Fatalf("peer_key_display = %q, want the redacted display form %q",
			stats.PeerKeyDisplay, ingress.RedactKey("peer-secret"))
	}
	if len(status.ForwarderRouteQueues) != 1 {
		t.Fatalf("expected exactly one route in the map, got %d: %+v",
			len(status.ForwarderRouteQueues), status.ForwarderRouteQueues)
	}
}

func createTestServerAndKey(t *testing.T, db *database.DB, name, host string) (int64, string, string) {
	t.Helper()
	ctx := context.Background()
	pub, priv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateCurve25519KeyPair failed: %v", err)
	}
	sID, err := db.CreateServer(ctx, &models.Server{
		Name: name,
		Host: host,
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	return sID, pub, priv
}

type testBackendDevice struct {
	*tunnel.AWGClientDevice
	createdAt       time.Time
	lastHandshakeFn func() time.Time
	dropCount       atomic.Uint64
	inPacketsCh     chan []byte
}

func (m *testBackendDevice) CreatedAt() time.Time {
	if !m.createdAt.IsZero() {
		return m.createdAt
	}
	return m.AWGClientDevice.CreatedAt()
}

func (m *testBackendDevice) LastHandshakeTime() time.Time {
	if m.lastHandshakeFn != nil {
		return m.lastHandshakeFn()
	}
	return m.AWGClientDevice.LastHandshakeTime()
}

func (m *testBackendDevice) DroppedPackets() uint64 {
	base := uint64(0)
	if m.AWGClientDevice != nil {
		base = m.AWGClientDevice.DroppedPackets()
	}
	return base + m.dropCount.Load()
}

// DeviceStats mirrors the fixture's direct dropCount into the EXTERNAL
// bucket of the underlying VirtualTUN's snapshot.
//
// dropCount is loss the fixture records itself, with no direction and no
// reason — which is exactly what VirtualTUN.RecordDrop models, and exactly
// what DroppedPackets reports as a total. Reporting it as external keeps the
// fixture's injected loss visible to the diagnostics breakdown (issue #424
// round 3, finding 1) instead of letting it disappear now that the breakdown
// reads the axes rather than the total. It is deliberately NOT injected as
// queue-full: that is the mislabelling this rework removes.
//
// The external figure goes in DropsExternal, not just DropsTotal: the
// external count is RECORDED on the recording path, so a snapshot that only
// raised the total would report the loss in no population at all
// (issue #424 round 5, finding 2). DropsTotal is raised alongside it to keep
// the snapshot's own coherence invariant intact.
func (m *testBackendDevice) DeviceStats() virtualtun.StatsSnapshot {
	snap := virtualtun.StatsSnapshot{}
	if m.AWGClientDevice != nil {
		snap = m.AWGClientDevice.DeviceStats()
	}
	snap.DropsExternal += m.dropCount.Load()
	snap.DropsTotal = snap.Sum() + snap.DropsExternal
	return snap
}

func (m *testBackendDevice) Write(p []byte) (int, error) {
	if m.inPacketsCh != nil {
		buf := make([]byte, len(p))
		copy(buf, p)
		select {
		case m.inPacketsCh <- buf:
		default:
		}
	}
	if m.AWGClientDevice != nil {
		return m.AWGClientDevice.Write(p)
	}
	return len(p), nil
}

func TestStart_AdminDisabledBackendStaysDetachedWhileEnabledBackendReprobes(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pub1, priv1, _ := tunnel.GenerateCurve25519KeyPair()
	pub2, priv2, _ := tunnel.GenerateCurve25519KeyPair()

	s1ID, err := db.CreateServer(ctx, &models.Server{
		Name: "Restore Srv 1",
		Host: "198.51.100.51",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub1,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer 1 failed: %v", err)
	}

	s2ID, err := db.CreateServer(ctx, &models.Server{
		Name: "Restore Srv 2",
		Host: "198.51.100.52",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub2,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer 2 failed: %v", err)
	}

	// Create active tunnel for server 1
	now := time.Now().UTC()
	tun1 := &models.BackendTunnel{
		ServerID:      s1ID,
		InterfaceName: fmt.Sprintf("awg-be-%d", s1ID),
		PublicKey:     pub1,
		PrivateKey:    priv1,
		Endpoint:      "198.51.100.51:51820",
		Status:        TunnelStatusActive,
		CreatedAt:     now,
	}
	tun1ID, err := db.CreateBackendTunnel(ctx, tun1)
	if err != nil {
		t.Fatalf("CreateBackendTunnel 1 failed: %v", err)
	}
	tun1.ID = tun1ID

	// Create administratively disabled tunnel for server 2. Its runtime
	// health snapshot is intentionally active and must remain untouched.
	tun2 := &models.BackendTunnel{
		ServerID:      s2ID,
		InterfaceName: fmt.Sprintf("awg-be-%d", s2ID),
		PublicKey:     pub2,
		PrivateKey:    priv2,
		Endpoint:      "198.51.100.52:51820",
		Enabled:       false,
		Status:        TunnelStatusActive,
		DisableReason: models.DisableReasonAdmin,
		CreatedAt:     now,
	}
	tun2ID, err := db.CreateBackendTunnel(ctx, tun2)
	if err != nil {
		t.Fatalf("CreateBackendTunnel 2 failed: %v", err)
	}
	tun2.ID = tun2ID

	// Start fresh Service
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	// Avoid 3-second network probe timeouts on unreachable test endpoints during background health loop
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Enabled tunnel 1 is reset to unknown health and then probed. Wait for
	// the successful startup probe to attach its device.
	deadline := time.Now().Add(2 * time.Second)
	for svc.GetBackendDeviceForTest(tun1ID) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	dev1 := svc.GetBackendDeviceForTest(tun1ID)
	if dev1 == nil {
		t.Fatalf("enabled backend %d was not attached after fresh startup probe", tun1ID)
	}

	// Administratively disabled tunnel 2 is never probed or attached.
	if dev2 := svc.GetBackendDeviceForTest(tun2ID); dev2 != nil {
		t.Errorf("expected no backend device for admin-disabled tunnel %d on Start, got %+v", tun2ID, dev2)
	}
	disabledTun, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel 2 failed: %v", err)
	}
	if disabledTun.Enabled || disabledTun.Status != TunnelStatusActive || disabledTun.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("startup changed admin-disabled backend dimensions: %+v", disabledTun)
	}
}

func TestStart_RestoresBackendDevices_DegradesOnAttachFailure(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Degrade Srv", "198.51.100.99")

	now := time.Now().UTC()
	tun := &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: fmt.Sprintf("awg-be-%d", sID),
		PublicKey:     pub,
		PrivateKey:    priv,
		Endpoint:      "198.51.100.99:999999", // invalid port causes attach to fail
		Status:        TunnelStatusActive,
		CreatedAt:     now,
	}
	tunID, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Device should not be present
	dev := svc.GetBackendDeviceForTest(tunID)
	if dev != nil {
		t.Errorf("expected nil device when restore fails, got %+v", dev)
	}

	// The initial startup probe succeeds, but data-plane attachment fails,
	// so health must eventually become degraded rather than trusting the
	// persisted active snapshot.
	deadline := time.Now().Add(2 * time.Second)
	var tStatus *models.BackendTunnel
	for time.Now().Before(deadline) {
		tStatus, err = svc.pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tStatus.Status == TunnelStatusDegraded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if tStatus == nil || tStatus.Status != TunnelStatusDegraded {
		t.Fatalf("expected tunnel status degraded after attach failure, got %+v", tStatus)
	}
}

func TestService_GetStatus_ExposesDroppedPackets(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Drops Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-drops", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	dev := &testBackendDevice{
		AWGClientDevice: realDev,
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Initially 0 drops
	st, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if st.DroppedPackets != 0 {
		t.Errorf("expected 0 dropped packets initially, got %d", st.DroppedPackets)
	}
	if svc.TotalDroppedPackets() != 0 {
		t.Errorf("expected 0 total dropped packets, got %d", svc.TotalDroppedPackets())
	}

	// Simulate 42 drops
	dev.dropCount.Add(42)

	st, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if st.DroppedPackets != 42 {
		t.Errorf("expected 42 dropped packets in status, got %d", st.DroppedPackets)
	}
	if svc.TotalDroppedPackets() != 42 {
		t.Errorf("expected 42 total dropped packets from helper, got %d", svc.TotalDroppedPackets())
	}

	// Simulate 100 more drops to trigger rate-limited log
	dev.dropCount.Add(100)
	st, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if st.DroppedPackets != 142 {
		t.Errorf("expected 142 dropped packets in status, got %d", st.DroppedPackets)
	}
}

func TestStart_RequiresFreshProbeBeforeRestoringBackendDevice(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pub, priv, _ := tunnel.GenerateCurve25519KeyPair()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Degraded Srv",
		Host: "198.51.100.77",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Persist stale degraded health. Service.Start must not trust it.
	now := time.Now().UTC()
	tun := &models.BackendTunnel{
		ServerID:        sID,
		InterfaceName:   fmt.Sprintf("awg-be-%d", sID),
		PublicKey:       pub,
		PrivateKey:      priv,
		Endpoint:        "198.51.100.77:51820",
		Status:          TunnelStatusDegraded,
		LastHealthCheck: &now,
		LatencyMS:       444,
		CreatedAt:       now,
	}
	tunID, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	var once sync.Once
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		once.Do(func() { close(probeStarted) })
		select {
		case <-releaseProbe:
			return 10 * time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})

	startDone := make(chan error, 1)
	go func() {
		startDone <- svc.Start(ctx)
	}()
	defer func() {
		select {
		case <-releaseProbe:
		default:
			close(releaseProbe)
		}
		_ = svc.Stop()
	}()

	select {
	case <-probeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("startup health probe did not begin")
	}
	select {
	case err := <-startDone:
		t.Fatalf("Start returned before fresh health was established: %v", err)
	default:
	}

	// While the fresh probe is unresolved, stale health must not be routable
	// and no backend device may be restored from the persisted snapshot.
	startingTun, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if !startingTun.Enabled || startingTun.Status != TunnelStatusConnecting {
		t.Fatalf("expected enabled backend with unknown startup health, got %+v", startingTun)
	}
	if startingTun.LastHealthCheck != nil || startingTun.LatencyMS != 0 {
		t.Fatalf("stale health metadata survived startup reset: %+v", startingTun)
	}
	if dev := svc.GetBackendDeviceForTest(tunID); dev != nil {
		t.Fatalf("stale backend device restored before fresh probe: %v", dev)
	}

	close(releaseProbe)

	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start failed after fresh probe: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not complete after fresh probe")
	}

	probedTun, getErr := svc.pool.GetTunnel(sID)
	if getErr != nil {
		t.Fatalf("GetTunnel after startup probe failed: %v", getErr)
	}
	if probedTun.Status != TunnelStatusActive || svc.GetBackendDeviceForTest(tunID) == nil {
		t.Fatalf("fresh startup probe did not activate backend and attach device: tunnel=%+v device=%v",
			probedTun, svc.GetBackendDeviceForTest(tunID))
	}
}

// --- Issue #25: Full AmneziaWG 3.0 Compliance for Load Balancer Client Configs ---

func parseDirectiveInt(t *testing.T, configStr, directive string) int {
	t.Helper()
	for _, line := range strings.Split(configStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, directive+" =") || strings.HasPrefix(line, directive+"=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				valStr := strings.TrimSpace(parts[1])
				v, err := strconv.Atoi(valStr)
				if err != nil {
					t.Fatalf("failed to parse integer for %s: %v in line %s", directive, err, line)
				}
				return v
			}
		}
	}
	t.Fatalf("directive %s not found in config:\n%s", directive, configStr)
	return 0
}

func parseDirectiveString(t *testing.T, configStr, directive string) string {
	t.Helper()
	for _, line := range strings.Split(configStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, directive+" =") || strings.HasPrefix(line, directive+"=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	t.Fatalf("directive %s not found in config:\n%s", directive, configStr)
	return ""
}

func parseDirectiveRange(t *testing.T, configStr, directive string) *awg.TimingRange {
	t.Helper()
	str := parseDirectiveString(t, configStr, directive)
	tr, err := awg.ParseTimingRange(str)
	if err != nil {
		t.Fatalf("failed to parse timing range for %s: %v in value %q", directive, err, str)
	}
	return tr
}

func extractAddressFromConfig(t *testing.T, cfgStr string) string {
	t.Helper()
	for _, line := range strings.Split(cfgStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				ipPart := strings.Split(val, "/")[0]
				return strings.TrimSpace(ipPart)
			}
		}
	}
	t.Fatalf("Address line not found in config:\n%s", cfgStr)
	return ""
}

func TestSessionReaperHook_Teardown(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	var targetTunnel *models.BackendTunnel
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			targetTunnel = tun
			break
		}
	}
	if targetTunnel == nil {
		targetTunnel = tunnels[0]
	}
	tunID := targetTunnel.ID

	// 1. Establish state simulating an active session:
	// - session in sessionMgr
	// - route registered in forwarder
	// - sticky affinities in stickyMgr
	// - incremented connection count in pool
	sessID := "sess-reaper-test-1"
	assignedIP := "10.100.0.88"
	createdSess, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	vpnSvc.forwarder.RegisterSession(createdSess.ID, "conn-1", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// Verify pre-conditions
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); !ok {
		t.Fatalf("expected forwarder route to be registered")
	}
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Fatalf("expected user sticky affinity to be %d, got %d (ok=%v)", tunID, tid, ok)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Fatalf("expected peer sticky affinity to be %d, got %d (ok=%v)", tunID, tid, ok)
	}
	tunBefore, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunBefore.ActiveConnections != 1 {
		t.Fatalf("expected pool ActiveConnections=1, got %d (err=%v)", tunBefore.ActiveConnections, err)
	}

	// 2. Age session past IdleTimeout (default 3m, age by 10m)
	createdSess.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// 3. Trigger timeout sweep through service (which invokes the registered SessionReaperHook)
	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) == 0 {
		t.Fatalf("expected at least 1 timed out session, got 0")
	}
	if timedOut[0].ID != createdSess.ID {
		t.Fatalf("expected timed out session %s, got %s", createdSess.ID, timedOut[0].ID)
	}

	// 4. Verify post-conditions after reaper hook teardown:
	// a) Session is removed from sessionMgr
	if _, ok := vpnSvc.sessionMgr.GetSessionByID(createdSess.ID); ok {
		t.Errorf("session still found in sessionMgr after sweep")
	}

	// b) Forwarder route unregistered
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); ok {
		t.Errorf("forwarder route for %s still registered after reaper teardown", peerKeyAlice)
	}

	// c) Sticky affinities preserved within AffinityTTL (issue #294)
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Errorf("expected user sticky affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Errorf("expected peer sticky affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}

	// Verify sticky affinity expires naturally once time advances past AffinityTTL (30m)
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time {
		return time.Now().UTC().Add(35 * time.Minute)
	})
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); ok {
		t.Errorf("expected user sticky affinity to expire after TTL, got %d", tid)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); ok {
		t.Errorf("expected peer sticky affinity to expire after TTL, got %d", tid)
	}

	// d) Pool connection count decremented to 0
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections=0 after reaper teardown, got %d (err=%v)", tunAfter.ActiveConnections, err)
	}
}

func TestService_ReapSession_EdgeCases(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, _, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	// Calling with nil session should not panic or error
	vpnSvc.reapSession(ctx, nil)

	// Calling with empty/non-existent session fields should not panic
	dummySess := &models.VPNSession{
		ID:              "non-existent",
		UserID:          "",
		PeerPublicKey:   "no-such-peer",
		BackendTunnelID: 999999,
	}
	vpnSvc.reapSession(ctx, dummySess)
}

func TestSessionReaperHook_ReconnectRace(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tunID = tun.ID
			break
		}
	}

	// 1. Session A is active
	sessIDA := "sess-reconnect-race-A"
	assignedIPA := "10.100.0.91"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPA, tunID, sessIDA)
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-1", peerKeyAlice, assignedIPA, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 2. Age session A past idle timeout
	sessA.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// 3. Intercept reaper hook execution to simulate delayed reaper execution
	reaperChan := make(chan *models.VPNSession, 1)
	vpnSvc.SetSessionReaperHookForTest(func(ctx context.Context, s *models.VPNSession) {
		reaperChan <- s
	})

	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected session A to time out, got %+v", timedOut)
	}

	var reapedSessA *models.VPNSession
	select {
	case reapedSessA = <-reaperChan:
	default:
		t.Fatalf("expected reaperChan to receive session A")
	}

	// 4. Client reconnects creating session B before session A's reaper hook executes
	assignedIPB := "10.100.0.92"
	sessB, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPB, tunID, "conn-b")
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-b", peerKeyAlice, assignedIPB, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tunMid, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunMid.ActiveConnections != 2 {
		t.Fatalf("expected pool ActiveConnections=2 before reaper A runs, got %d", tunMid.ActiveConnections)
	}

	// 5. Now execute the delayed reapSession for session A
	vpnSvc.reapSession(ctx, reapedSessA)

	// 6. Assertions for Session B:
	// a) Session B must still be active in sessionMgr
	if current, ok := vpnSvc.sessionMgr.GetSession(peerKeyAlice); !ok || current.ID != sessB.ID {
		t.Errorf("expected session B to still be active in sessionMgr, got ok=%v, sess=%+v", ok, current)
	}

	// b) Session B's forwarder route must remain intact
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); !ok {
		t.Errorf("expected forwarder route for session B to remain intact")
	}

	// c) Session B's sticky peer affinity must remain intact
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Errorf("expected peer sticky affinity to remain %d, got %d (ok=%v)", tunID, tid, ok)
	}

	// d) Session B's sticky user affinity must remain intact
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Errorf("expected user sticky affinity to remain %d, got %d (ok=%v)", tunID, tid, ok)
	}

	// e) Tunnel ActiveConnections must be exactly 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 1 {
		t.Errorf("expected pool ActiveConnections=1 after reaper A runs, got %d", tunAfter.ActiveConnections)
	}
}

func TestSessionReaperHook_ReconcileRace(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tunID = tun.ID
			break
		}
	}

	// 1. Session A is active
	sessIDA := "sess-reconcile-race-A"
	assignedIPA := "10.100.0.93"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPA, tunID, sessIDA)
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-1", peerKeyAlice, assignedIPA, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 2. Age session A past idle timeout
	sessA.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// Intercept reaper hook
	reaperChan := make(chan *models.VPNSession, 1)
	vpnSvc.SetSessionReaperHookForTest(func(ctx context.Context, s *models.VPNSession) {
		reaperChan <- s
	})

	// 3. Trigger SweepTimedOutSessions
	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected session A to time out, got %+v", timedOut)
	}
	if timedOut[0].TimedOutAt.IsZero() {
		t.Fatalf("expected TimedOutAt to be set on timed-out session")
	}

	var reapedSessA *models.VPNSession
	select {
	case reapedSessA = <-reaperChan:
	default:
		t.Fatalf("expected reaperChan to receive session A")
	}

	// 4. Session B connects for another peer
	peerKeyBob := "peer-reconcile-bob"
	assignedIPB := "10.100.0.94"
	sessB, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyBob, assignedIPB, tunID, "conn-bob")
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-bob", peerKeyBob, assignedIPB, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 5. Periodic reconciliation runs before session A's reaper hook runs
	vpnSvc.reconcileConnectionCounts(ctx)

	tunReconciled, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunReconciled.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1 after reconciliation, got %d", tunReconciled.ActiveConnections)
	}
	if vpnSvc.lastReconcileTime.IsZero() || !vpnSvc.lastReconcileTime.After(reapedSessA.TimedOutAt) {
		t.Fatalf("expected lastReconcileTime to be after TimedOutAt")
	}

	// 6. Now the delayed reapSession for session A runs
	vpnSvc.reapSession(ctx, reapedSessA)

	// 7. Verify pool counter was NOT decremented to 0
	tunFinal, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunFinal.ActiveConnections != 1 {
		t.Errorf("expected pool ActiveConnections to remain 1 after stale reaper, got %d", tunFinal.ActiveConnections)
	}
}

func TestSessionReaperHook_ConcurrentDeadlock(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	peerKeyBob := "peer-deadlock-bob"
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKeyBob,
		Name:     "bob-phone",
	})

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Worker 1: repeatedly creates sessions and ages them
	wg.Add(1)
	go func() {
		defer wg.Done()
		peers := []string{peerKeyAlice, peerKeyBob}
		for i := 0; i < 50; i++ {
			p := peers[i%len(peers)]
			sess, _, err := vpnSvc.HandleIncomingPeerForTest(ctx, p)
			if err == nil && sess != nil {
				vpnSvc.sessionMgr.SetSessionLastSeen(p, time.Now().UTC().Add(-10*time.Minute))
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 2: repeatedly triggers timeout sweeps
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = vpnSvc.SweepTimedOutSessions(ctx)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 3: runs periodic reconciliation
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			vpnSvc.reconcileConnectionCounts(ctx)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded without deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock detected: concurrent timeout sweep, HandleIncomingPeer, and reconciliation did not complete in 10s")
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-stale-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.91", tunID, "conn-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-a", peerKeyA, "10.100.0.91", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// 2. Configure reconcilePostSnapshotHook:
	// While reconciliation is paused post-DB read, create a new Session B and increment live pool counter.
	// This mutates sessionMgr lifecycle version and moves live gauge to 2.
	// Because DB snapshot only contains Session A (count 1), if the snapshot were applied,
	// it would clobber the gauge back to 1.
	hookFired := false
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		hookFired = true
		peerKeyB := "peer-reconcile-stale-b"
		sessB, errCreate := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyB, "10.100.0.92", tunID, "conn-b")
		if errCreate != nil {
			t.Fatalf("hook: CreateSession B failed: %v", errCreate)
		}
		vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-b", peerKeyB, "10.100.0.92", tunID)
		vpnSvc.pool.IncrementConnections(tunID)
	})

	// 3. Run reconcileConnectionCounts:
	// Prior to DB read: lifecycleVersion is V1.
	// DB read returns 1 session (Session A).
	// Hook fires: Session B created, lifecycleVersion becomes V2, pool gauge is 2.
	// Reconciliation acquires lock: sees lifecycleVersion V2 != V1 -> aborts!
	vpnSvc.reconcileConnectionCounts(ctx)

	if !hookFired {
		t.Fatal("expected reconcilePostSnapshotHook to fire")
	}

	// 4. Verify pool gauge remains 2, not reset to 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 2 {
		t.Errorf("expected pool ActiveConnections to remain 2, got %d (stale snapshot was not rejected)", tunAfter.ActiveConnections)
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected_ReplacementFailure(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-replace-fail-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.91", tunID, "conn-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-a", peerKeyA, "10.100.0.91", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// 2. Configure reconcilePostSnapshotHook:
	// While reconciliation is paused post-DB read (which captured Session A with count 1),
	// trigger a replacement for Session A with a canceled context so persistence fails.
	// The replacement removes Session A from memory maps and advances lifecycleVersion.
	// We also adjust live pool gauge (decrement by 1 to 0) to represent Session A being torn down.
	// If the stale snapshot were applied, it would reset the live gauge back to 1.
	hookFired := false
	versionBeforeReconcile := vpnSvc.sessionMgr.LifecycleVersion()
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		hookFired = true
		cancCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, errReplace := vpnSvc.sessionMgr.CreateSession(cancCtx, uID, peerKeyA, "10.100.0.91", tunID, "conn-a-replacement")
		if errReplace == nil {
			t.Fatal("expected CreateSession replacement to fail due to canceled context")
		}

		// Verify that lifecycleVersion was advanced even though CreateSession returned an error
		if vpnSvc.sessionMgr.LifecycleVersion() <= versionBeforeReconcile {
			t.Fatalf("expected lifecycleVersion to advance on replacement removal, but got %d (was %d)",
				vpnSvc.sessionMgr.LifecycleVersion(), versionBeforeReconcile)
		}

		// Adjust live pool counter to 0
		vpnSvc.pool.DecrementConnections(tunID)
	})

	// 3. Run reconcileConnectionCounts:
	// DB read captured Session A (desired count 1).
	// Hook fired: replacement failed, but advanced lifecycleVersion. Live gauge is 0.
	// Reconcile acquires lock: detects lifecycleVersion mutated -> aborts!
	vpnSvc.reconcileConnectionCounts(ctx)

	if !hookFired {
		t.Fatal("expected reconcilePostSnapshotHook to fire")
	}

	// 4. Verify pool gauge remains 0, not reset to stale count 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to remain 0, got %d (stale snapshot was not rejected)", tunAfter.ActiveConnections)
	}
}

func TestSessionReaperHook_ReconcileFailureDoesNotSuppressReaper(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) < 2 {
		t.Fatalf("expected at least 2 active tunnels in pool, got %d", len(tunnels))
	}
	var tun1ID, tun2ID int64
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tun1ID = tun.ID
		} else if tun.ServerID == s2ID {
			tun2ID = tun.ID
		}
	}
	if tun1ID == 0 || tun2ID == 0 {
		t.Fatalf("failed to resolve tunnel IDs for servers %d and %d", s1ID, s2ID)
	}

	// 1. Session A is active on Tunnel 1
	sessIDA := "sess-reconcile-fail-A"
	assignedIPA := "10.100.0.95"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPA, tun1ID, sessIDA)
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-1", peerKeyAlice, assignedIPA, tun1ID)
	vpnSvc.pool.IncrementConnections(tun1ID)

	// 2. Age session A past idle timeout
	sessA.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// Intercept reaper hook so delayed reapSession execution can be controlled
	reaperChan := make(chan *models.VPNSession, 1)
	vpnSvc.SetSessionReaperHookForTest(func(ctx context.Context, s *models.VPNSession) {
		reaperChan <- s
	})

	// 3. Trigger SweepTimedOutSessions
	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected session A to time out, got %+v", timedOut)
	}
	if timedOut[0].TimedOutAt.IsZero() {
		t.Fatalf("expected TimedOutAt to be set on timed-out session")
	}

	var reapedSessA *models.VPNSession
	select {
	case reapedSessA = <-reaperChan:
	default:
		t.Fatalf("expected reaperChan to receive session A")
	}

	// 4. Session B connects on Tunnel 1, bringing live ActiveConnections to 2 (1 stale A + 1 live B)
	peerKeyBob := "peer-reconcile-bob-fail"
	assignedIPB := "10.100.0.96"
	sessB, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyBob, assignedIPB, tun1ID, "conn-bob")
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-bob", peerKeyBob, assignedIPB, tun1ID)
	vpnSvc.pool.IncrementConnections(tun1ID)

	tun1Before, err := vpnSvc.pool.GetTunnelByID(tun1ID)
	if err != nil || tun1Before.ActiveConnections != 2 {
		t.Fatalf("expected Tunnel 1 ActiveConnections=2 before reconcile, got %d", tun1Before.ActiveConnections)
	}

	// 5. Run reconcileConnectionCounts with an injected failure during SetConnectionCount:
	// Reconciliation reads DB (desired count for Tunnel 1 is 1 for Session B).
	// Hook cancels context so SetConnectionCount DB persistence fails for Tunnel 1.
	ctxReconcile, cancelReconcile := context.WithCancel(context.Background())
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		cancelReconcile()
	})
	vpnSvc.reconcileConnectionCounts(ctxReconcile)

	// 6. Verify reconciliation state under lock:
	// Tunnel 1 failed persistence: lastReconcileByTunnel[tun1ID] must NOT be set!
	// Tunnel 2 had zero drift: lastReconcileByTunnel[tun2ID] was successfully set.
	// Because Tunnel 1 failed, global lastReconcileTime must NOT be updated.
	vpnSvc.mu.RLock()
	tun1ReconcileTime := vpnSvc.lastReconcileByTunnel[tun1ID]
	tun2ReconcileTime := vpnSvc.lastReconcileByTunnel[tun2ID]
	globalReconcileTime := vpnSvc.lastReconcileTime
	vpnSvc.mu.RUnlock()

	if !tun1ReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[tun1ID] to be zero after failure, got %v", tun1ReconcileTime)
	}
	if tun2ReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[tun2ID] to be non-zero for successful tunnel, got zero")
	}
	if !globalReconcileTime.IsZero() {
		t.Errorf("expected global lastReconcileTime to remain zero when any tunnel fails, got %v", globalReconcileTime)
	}

	// 7. Now execute delayed reapSession for session A.
	// Since Tunnel 1's reconciliation timestamp was not recorded, reaper must NOT skip decrement.
	vpnSvc.reapSession(ctx, reapedSessA)

	// 8. Verify Tunnel 1 ActiveConnections was decremented to 0
	tunFinal, err := vpnSvc.pool.GetTunnelByID(tun1ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunFinal.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to be decremented to 0, got %d (reaper decrement was improperly suppressed)", tunFinal.ActiveConnections)
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected_TimeoutDuringApply(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-timeout-apply-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.95", tunID, "conn-apply-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-apply-a", peerKeyA, "10.100.0.95", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// Age session past IdleTimeout (default 3m, age by 10m)
	vpnSvc.sessionMgr.SetSessionLastSeen(peerKeyA, time.Now().UTC().Add(-10*time.Minute))

	versionBefore := vpnSvc.sessionMgr.LifecycleVersion()

	var wg sync.WaitGroup
	var hookFired atomic.Bool
	var sweepErr error
	var timedOut []*models.VPNSession

	vpnSvc.SetReconcilePreApplyHook(func() {
		hookFired.Store(true)

		vpnSvc.sessionMgr.UnlockLifecycle()
		defer vpnSvc.sessionMgr.LockLifecycle()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// SweepTimedOutSessions runs CheckTimeouts under SessionManager.mu,
			// increments lifecycleVersion, and then invokes registered reaperHook
			// which calls svc.reapSession(ctx, sess) blocking on Service.mu.
			timedOut, sweepErr = vpnSvc.SweepTimedOutSessions(ctx)
		}()

		// Wait until CheckTimeouts has removed session A and advanced lifecycleVersion
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_, found := vpnSvc.sessionMgr.GetSessionByID(sessA.ID)
			if !found && vpnSvc.sessionMgr.LifecycleVersion() > versionBefore {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}

		// Yield to allow the reaper goroutine to reach reapSession and block on Service.mu
		time.Sleep(50 * time.Millisecond)
	})

	// 2. Run reconcileConnectionCounts:
	// DB read captured Session A (desired count 1).
	// Passes initial version check under Service.mu.
	// Hook fires: Session A times out, lifecycleVersion advances, reaper blocks on Service.mu.
	// Reconcile resumes: detects lifecycleVersion mutated -> refuses to apply snapshot and aborts!
	// Reconcile releases Service.mu.
	vpnSvc.reconcileConnectionCounts(ctx)

	// Wait for the reaper goroutine to finish
	wg.Wait()

	if !hookFired.Load() {
		t.Fatal("expected reconcilePreApplyHook to fire")
	}
	if sweepErr != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", sweepErr)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected 1 timed out session %s, got %+v", sessA.ID, timedOut)
	}

	// 3. Verify reconciliation timestamps were NOT committed
	vpnSvc.mu.RLock()
	var tunReconcileTime time.Time
	if vpnSvc.lastReconcileByTunnel != nil {
		tunReconcileTime = vpnSvc.lastReconcileByTunnel[tunID]
	}
	globalReconcileTime := vpnSvc.lastReconcileTime
	vpnSvc.mu.RUnlock()

	if !tunReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[%d] to be zero after abort, got %v", tunID, tunReconcileTime)
	}
	if !globalReconcileTime.IsZero() {
		t.Errorf("expected global lastReconcileTime to remain zero after abort, got %v", globalReconcileTime)
	}

	// 4. Verify pool gauge is 0 (decremented by reaper, not restored to 1 by reconciliation)
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to be 0, got %d (stale snapshot restored count)", tunAfter.ActiveConnections)
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected_TimeoutBeforeCommit(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-timeout-commit-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.96", tunID, "conn-commit-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-commit-a", peerKeyA, "10.100.0.96", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// Age session past IdleTimeout (default 3m, age by 10m)
	vpnSvc.sessionMgr.SetSessionLastSeen(peerKeyA, time.Now().UTC().Add(-10*time.Minute))

	versionBefore := vpnSvc.sessionMgr.LifecycleVersion()

	var wg sync.WaitGroup
	var hookFired atomic.Bool
	var sweepErr error
	var timedOut []*models.VPNSession

	vpnSvc.SetReconcilePreCommitHook(func() {
		hookFired.Store(true)

		// Temporarily release session lifecycle lock so background sweep can proceed
		vpnSvc.sessionMgr.UnlockLifecycle()
		defer vpnSvc.sessionMgr.LockLifecycle()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// SweepTimedOutSessions runs CheckTimeouts under SessionManager.mu,
			// increments lifecycleVersion, and then invokes registered reaperHook
			// which calls svc.reapSession(ctx, sess) blocking on Service.mu.
			timedOut, sweepErr = vpnSvc.SweepTimedOutSessions(ctx)
		}()

		// Wait until CheckTimeouts has removed session A and advanced lifecycleVersion
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_, found := vpnSvc.sessionMgr.GetSessionByID(sessA.ID)
			if !found && vpnSvc.sessionMgr.LifecycleVersion() > versionBefore {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}

		// Yield to allow the reaper goroutine to reach reapSession and block on Service.mu
		time.Sleep(50 * time.Millisecond)
	})

	// 2. Run reconcileConnectionCounts:
	// DB read captured Session A (desired count 1).
	// Passes initial version check under Service.mu and sm.LockLifecycle.
	// Drift evaluated in Phase 1 (no changes yet applied).
	// Pre-commit hook fires: temporarily releases sm.LockLifecycle,
	// Session A times out, lifecycleVersion advances, reaper blocks on Service.mu,
	// sm.LockLifecycle re-acquired.
	// Reconcile resumes from hook: detects lifecycleVersion mutated,
	// aborts Phase 2 commit immediately (SetConnectionCount never called, timestamps not committed).
	// Reconcile releases sm.UnlockLifecycle and Service.mu.
	vpnSvc.reconcileConnectionCounts(ctx)

	// Wait for the reaper goroutine to finish
	wg.Wait()

	if !hookFired.Load() {
		t.Fatal("expected reconcilePreCommitHook to fire")
	}
	if sweepErr != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", sweepErr)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected 1 timed out session %s, got %+v", sessA.ID, timedOut)
	}

	// 3. Verify reconciliation timestamps were NOT committed
	vpnSvc.mu.RLock()
	var tunReconcileTime time.Time
	if vpnSvc.lastReconcileByTunnel != nil {
		tunReconcileTime = vpnSvc.lastReconcileByTunnel[tunID]
	}
	globalReconcileTime := vpnSvc.lastReconcileTime
	vpnSvc.mu.RUnlock()

	if !tunReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[%d] to be zero after abort, got %v", tunID, tunReconcileTime)
	}
	if !globalReconcileTime.IsZero() {
		t.Errorf("expected global lastReconcileTime to remain zero after abort, got %v", globalReconcileTime)
	}

	// 4. Verify pool gauge is 0 (decremented by reaper, not restored to 1 by reconciliation)
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to be 0, got %d (stale snapshot restored count)", tunAfter.ActiveConnections)
	}
}

func TestService_ReapSession_DoesNotPruneExpiredAffinity(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tunID = tun.ID
			break
		}
	}

	// 1. Establish session A for Alice (active, unexpired)
	sessID := "sess-prune-test-a"
	assignedIP := "10.100.0.199"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-a", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 2. Add an expired affinity record for an older peer/user (Bob)
	uIDBob := "user-bob-expired"
	peerKeyBob := "peer-bob-expired"
	vpnSvc.stickyMgr.AssignAffinity(uIDBob, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyBob, tunID)

	uCount, pCount := vpnSvc.stickyMgr.AffinityCount()
	if uCount != 2 || pCount != 2 {
		t.Fatalf("expected initial AffinityCount=(2, 2), got (%d, %d)", uCount, pCount)
	}

	// Override clock: Bob was assigned 35m ago (> 30m AffinityTTL)
	tNow := time.Now().UTC().Add(35 * time.Minute)
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time { return tNow })

	// Refresh Alice's affinity timestamp to tNow (unexpired)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)

	// 3. Trigger reapSession for session A
	sessA.LastSeen = tNow.Add(-10 * time.Minute) // aged past IdleTimeout (3m)
	vpnSvc.reapSession(ctx, sessA)

	// 4. reapSession must NOT prune affinity records (eliminates O(K*N) lock contention under Service.mu)
	uCountAfterReap, pCountAfterReap := vpnSvc.stickyMgr.AffinityCount()
	if uCountAfterReap != 2 || pCountAfterReap != 2 {
		t.Fatalf("expected AffinityCount=(2, 2) after reapSession (no per-session pruning), got (%d, %d)", uCountAfterReap, pCountAfterReap)
	}

	// 5. Calling PruneExpiredAffinity explicitly prunes the expired records
	pruned := vpnSvc.PruneExpiredAffinity()
	if pruned != 2 {
		t.Fatalf("expected 2 pruned records, got %d", pruned)
	}

	uCountAfterPrune, pCountAfterPrune := vpnSvc.stickyMgr.AffinityCount()
	if uCountAfterPrune != 1 || pCountAfterPrune != 1 {
		t.Fatalf("expected AffinityCount=(1, 1) after PruneExpiredAffinity, got (%d, %d)", uCountAfterPrune, pCountAfterPrune)
	}

	// Alice's affinity is preserved within AffinityTTL
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Errorf("expected Alice's user affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Errorf("expected Alice's peer affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}
}

func TestService_PruneExpiredAffinity_ExecutesOutsideServiceMutex(t *testing.T) {
	db := setupTestDB(t)
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	tNow := time.Now().UTC()
	vpnSvc.stickyMgr.AssignAffinity(uID, 1)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, 1)

	// Setup synchronization channels
	insidePrune := make(chan struct{})
	proceedPrune := make(chan struct{})

	vpnSvc.stickyMgr.SetNowFunc(func() time.Time {
		select {
		case <-insidePrune:
		default:
			close(insidePrune)
		}
		<-proceedPrune
		return tNow.Add(1 * time.Hour) // force expiry
	})

	doneCh := make(chan int)
	go func() {
		doneCh <- vpnSvc.PruneExpiredAffinity()
	}()

	// Wait until sm.PruneExpired() begins executing inside StickySessionManager
	select {
	case <-insidePrune:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PruneExpired to execute")
	}

	// While PruneExpired is executing, Service.mu MUST NOT be held.
	// We verify that TryLock on vpnSvc.mu succeeds immediately.
	acquired := vpnSvc.mu.TryLock()
	if !acquired {
		t.Errorf("expected Service.mu to be available while PruneExpired executes, but TryLock failed")
	} else {
		vpnSvc.mu.Unlock()
	}

	// Allow PruneExpired to finish
	close(proceedPrune)

	select {
	case pruned := <-doneCh:
		if pruned != 2 {
			t.Fatalf("expected 2 pruned records, got %d", pruned)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PruneExpiredAffinity to return")
	}
}

func TestService_PostSweepHook_PrunesExpiredAffinity(t *testing.T) {
	db := setupTestDB(t)
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	tNow := time.Now().UTC()
	vpnSvc.stickyMgr.AssignAffinity(uID, 1)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, 1)

	// Advance time past TTL
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time { return tNow.Add(1 * time.Hour) })

	uCount, pCount := vpnSvc.stickyMgr.AffinityCount()
	if uCount != 1 || pCount != 1 {
		t.Fatalf("expected initial AffinityCount=(1, 1), got (%d, %d)", uCount, pCount)
	}

	// Trigger listener's postSweepHook
	vpnSvc.PruneExpiredAffinity()

	uCountAfter, pCountAfter := vpnSvc.stickyMgr.AffinityCount()
	if uCountAfter != 0 || pCountAfter != 0 {
		t.Fatalf("expected AffinityCount=(0, 0) after pruning, got (%d, %d)", uCountAfter, pCountAfter)
	}
}

func TestService_StartedAt_LifecycleAndFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	defer func() { _ = svc.Stop() }()

	// 1. Before Start: startedAt is zero
	svc.mu.RLock()
	if !svc.startedAt.IsZero() {
		t.Fatalf("expected startedAt to be zero before Start, got %v", svc.startedAt)
	}
	svc.mu.RUnlock()

	// 2. Start failure: canceled context guarantees Start fails during sync/invalidation
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.Start(ctxCancel)
	if err == nil {
		t.Fatal("expected Start with canceled context to fail")
	}

	svc.mu.RLock()
	if !svc.startedAt.IsZero() {
		t.Fatalf("expected startedAt to remain zero after Start failure, got %v", svc.startedAt)
	}
	if svc.running {
		t.Fatal("expected running to be false after Start failure")
	}
	svc.mu.RUnlock()

	// 3. Start success: with active context
	ctx := context.Background()
	svc.mu.Lock()
	svc.retiredIngressLosses.router.MalformedPacketDrops = 500
	svc.retiredBackendDeviceDrops.ClientQueueFull = 100
	svc.mu.Unlock()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("expected Start to succeed, got %v", err)
	}

	svc.mu.RLock()
	if svc.startedAt.IsZero() {
		t.Fatal("expected startedAt to be non-zero after successful Start")
	}
	if !svc.running {
		t.Fatal("expected running to be true after successful Start")
	}
	if svc.retiredIngressLosses.router.MalformedPacketDrops != 0 {
		t.Errorf("expected retiredIngressLosses to be reset on Start, got %d", svc.retiredIngressLosses.router.MalformedPacketDrops)
	}
	if svc.retiredBackendDeviceDrops.ClientQueueFull != 0 {
		t.Errorf("expected retiredBackendDeviceDrops to be reset on Start, got %d", svc.retiredBackendDeviceDrops.ClientQueueFull)
	}
	svc.mu.RUnlock()

	// 4. Stop: resets startedAt to zero
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	svc.mu.RLock()
	if !svc.startedAt.IsZero() {
		t.Fatalf("expected startedAt to be zero after Stop, got %v", svc.startedAt)
	}
	if svc.running {
		t.Fatal("expected running to be false after Stop")
	}
	svc.mu.RUnlock()
}

func TestSessionsLive_IncludesConnectionID(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Live Server", Host: "198.51.100.5"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	peerKey := "bob-awg-peer-public-key"
	connID := "conn-bob-live-123"

	// Create user_connection with explicit ID and peer client_id
	_, err = db.SQLDB().ExecContext(ctx,
		`INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, name) VALUES (?, ?, ?, 'awg', ?, 'bob-laptop')`,
		connID, uID, sID, peerKey)
	if err != nil {
		t.Fatalf("failed to insert user_connection: %v", err)
	}

	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-live",
		PublicKey:     "pub-live",
		PrivateKey:    "priv-live",
		Endpoint:      "198.51.100.5:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	svc, err := NewVPNService(db, &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51822,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
	})
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, "10.100.1.5", tID, "bob-laptop")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	live, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("SessionsLive failed: %v", err)
	}

	if len(live) != 1 {
		t.Fatalf("expected 1 live session, got %d", len(live))
	}

	got := live[0]
	if got.ID != sess.ID {
		t.Errorf("session ID: got %q, want %q", got.ID, sess.ID)
	}
	if got.Username != "bob" {
		t.Errorf("username: got %q, want 'bob'", got.Username)
	}
	if got.ConnectionID != connID {
		t.Errorf("connection_id: got %q, want %q", got.ConnectionID, connID)
	}
	if got.ConnectionName != "bob-laptop" {
		t.Errorf("connection_name: got %q, want 'bob-laptop'", got.ConnectionName)
	}
}
