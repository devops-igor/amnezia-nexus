package vpn

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
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
	if got := parseDirectiveString(t, cfgStr, "I1"); !strings.HasPrefix(got, "<b 0x5245474953544552") {
		t.Fatalf("expected SIP REGISTER I1, got %q", got)
	}
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, k := range []string{"I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, k+" =") || strings.HasPrefix(trimmed, k+"=") {
				t.Errorf("client config must not contain %s, got:\n%s", k, cfgStr)
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
