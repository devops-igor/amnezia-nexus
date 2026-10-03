package vpn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
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

type mockAWGStatusProvider struct {
	status map[string]any
	err    error
}

func (m *mockAWGStatusProvider) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return m.status, m.err
}

func TestEnableBackend_DynamicFallback(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	ctx := context.Background()

	// 1. Server with no AWG in DB, but awgProvider discovers it running
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name:      "dynamic-awg-host",
		Host:      "198.51.100.20",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	mockProv := &mockAWGStatusProvider{
		status: map[string]any{
			"container_running": true,
			"port":              51820,
			"public_key":        "dynamic-discovered-pubkey",
			"psk":               "dynamic-psk",
			"awg_params": map[string]string{
				"H1": "1",
			},
		},
	}
	svc.SetAWGStatusProvider(mockProv)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend with dynamic fallback failed: %v", err)
	}

	// Verify DB record was updated
	srv, err := db.GetServerByID(ctx, srvID)
	if err != nil {
		t.Fatalf("GetServerByID failed: %v", err)
	}
	awgInfo, ok := srv.Protocols["awg"].(map[string]any)
	if !ok {
		t.Fatalf("expected awg in srv.Protocols, got: %+v", srv.Protocols)
	}
	if installed, _ := awgInfo["installed"].(bool); !installed {
		t.Errorf("expected installed true, got: %v", awgInfo["installed"])
	}
	if awgInfo["public_key"] != "dynamic-discovered-pubkey" {
		t.Errorf("expected public_key dynamic-discovered-pubkey, got: %v", awgInfo["public_key"])
	}
	if fmt.Sprint(awgInfo["port"]) != "51820" {
		t.Errorf("expected port 51820, got: %v", awgInfo["port"])
	}

	// Verify backend tunnel exists and is active
	backends, err := svc.GetBackends(ctx)
	if err != nil {
		t.Fatalf("GetBackends failed: %v", err)
	}
	var found bool
	for _, b := range backends {
		if b.ServerID == srvID {
			found = true
			if b.Status != TunnelStatusActive {
				t.Errorf("expected tunnel status active, got %s", b.Status)
			}
			if b.PublicKey != "dynamic-discovered-pubkey" {
				t.Errorf("expected tunnel pubkey dynamic-discovered-pubkey, got %s", b.PublicKey)
			}
		}
	}
	if !found {
		t.Errorf("expected backend tunnel for server %d in backends list", srvID)
	}

	// 2. Server where AWG is NOT running
	srvNoAWGID, err := db.CreateServer(ctx, &models.Server{
		Name:      "not-running-host",
		Host:      "198.51.100.21",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	svc.SetAWGStatusProvider(&mockAWGStatusProvider{
		status: map[string]any{
			"container_running": false,
		},
	})
	if err := svc.EnableBackend(ctx, srvNoAWGID); err == nil {
		t.Error("expected EnableBackend to fail when container is not running")
	}

	// 3. Provider returns error
	svc.SetAWGStatusProvider(&mockAWGStatusProvider{
		err: errors.New("ssh connection failed"),
	})
	if err := svc.EnableBackend(ctx, srvNoAWGID); err == nil {
		t.Error("expected EnableBackend to fail when provider returns error")
	}
}

type mockAWGManagerWithClientAdder struct {
	status         map[string]any
	statusErr      error
	addedClients   []map[string]any
	addClientErr   error
	addClientCalls int
	onAddClient    func()
}

func (m *mockAWGManagerWithClientAdder) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return m.status, m.statusErr
}

func (m *mockAWGManagerWithClientAdder) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	m.addClientCalls++
	m.addedClients = append(m.addedClients, clientParams)
	if m.onAddClient != nil {
		m.onAddClient()
	}
	if m.addClientErr != nil {
		return nil, m.addClientErr
	}
	return map[string]any{"client_id": clientParams["client_public_key"]}, nil
}

// TestEnableBackend_RegistersProberPeerOnBackend asserts the WIRING only:
// EnableBackend registers BOTH portal peers on the backend via AddClient —
// the DATA device peer (identity derive(PrivateKey), allowed_ips 0.0.0.0/0)
// first, then the dedicated probe peer (identity derive(ProbePrivateKey),
// no allowed_ips key). It uses a MOCK AddClient, so it cannot verify what the
// real manager does with those params (round-2 review: a mock asserting its
// own inputs is a false positive). The real-path coverage — [Peer] PublicKey
// == caller-supplied key, no PresharedKey, idempotent re-registration — lives
// in awg_probe_rework_test.go (TestAWGManager_AddClient_ProbePeerUsesCallerKey_R3),
// and the real-container acceptance test lives in
// awg_container_integration_test.go (TestAWGRealContainer_HandshakeWithPSKLessProbePeer).
func TestEnableBackend_RegistersProberPeerOnBackend(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-peer-reg-server",
		Host: "198.51.100.30",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	// Issue #43 key separation: exactly two registrations — DATA plane first,
	// health probe second.
	if adder.addClientCalls != 2 {
		t.Fatalf("expected 2 AddClient calls, got %d", adder.addClientCalls)
	}
	if len(adder.addedClients) != 2 {
		t.Fatalf("expected 2 added clients, got %d", len(adder.addedClients))
	}
	dataParams := adder.addedClients[0]
	probeParams := adder.addedClients[1]

	if dataParams["clientName"] != "Portal Data Plane" {
		t.Errorf("expected first clientName 'Portal Data Plane', got: %v", dataParams["clientName"])
	}
	if probeParams["clientName"] != "Portal Health Probe" {
		t.Errorf("expected second clientName 'Portal Health Probe', got: %v", probeParams["clientName"])
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}

	// DATA peer: identity = derive(PrivateKey), allowed_ips = portal subnet (never 0.0.0.0/0).
	dataPub, ok := dataParams["client_public_key"].(string)
	if !ok || len(dataPub) == 0 {
		t.Fatalf("missing or empty client_public_key in data params: %+v", dataParams)
	}
	derivedDataPub, err := health.ComputePublicKeyFromPrivate(tun.PrivateKey)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate (data) failed: %v", err)
	}
	if dataPub != derivedDataPub {
		t.Errorf("registered data public key %s does not match tunnel-derived data pubkey %s", dataPub, derivedDataPub)
	}
	if aip, ok := dataParams["allowed_ips"]; !ok || aip != "10.100.0.0/16" {
		t.Errorf("expected data peer allowed_ips '10.100.0.0/16', got: %v", dataParams["allowed_ips"])
	}
	if aip, ok := dataParams["allowed_ips"]; ok && aip == "0.0.0.0/0" {
		t.Errorf("data peer allowed_ips must NEVER be 0.0.0.0/0 (causes routing hijack on reboot)")
	}

	// PROBE peer: identity = derive(ProbePrivateKey), distinct from data key,
	// and NO allowed_ips key at all (manager defaults it to clientIP/32).
	probePub, ok := probeParams["client_public_key"].(string)
	if !ok || len(probePub) == 0 {
		t.Fatalf("missing or empty client_public_key in probe params: %+v", probeParams)
	}
	if tun.ProbePrivateKey == "" {
		t.Fatalf("tunnel must carry a dedicated probe private key after EnableBackend")
	}
	derivedProbePub, err := health.ComputePublicKeyFromPrivate(tun.ProbePrivateKey)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate (probe) failed: %v", err)
	}
	if probePub != derivedProbePub {
		t.Errorf("registered probe public key %s does not match tunnel-derived probe pubkey %s", probePub, derivedProbePub)
	}
	if probePub == dataPub {
		t.Errorf("probe public key must differ from data public key (key separation is the whole fix)")
	}
	if aip, present := probeParams["allowed_ips"]; present {
		t.Errorf("probe peer must carry NO allowed_ips key (defaults to clientIP/32), got: %v", aip)
	}
}

func TestRegisterBackendPortalPeers_CustomSubnet(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.cfg = &models.VPNConfig{SubnetCIDR: "10.200.0.0/16"}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-custom-subnet-server",
		Host: "198.51.100.44",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey-custom",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	if len(adder.addedClients) < 1 {
		t.Fatalf("expected at least 1 added client, got %d", len(adder.addedClients))
	}
	dataParams := adder.addedClients[0]
	if aip, ok := dataParams["allowed_ips"]; !ok || aip != "10.200.0.0/16" {
		t.Errorf("expected custom portal subnet '10.200.0.0/16', got: %v", dataParams["allowed_ips"])
	}
	if aip, ok := dataParams["allowed_ips"]; ok && aip == "0.0.0.0/0" {
		t.Errorf("portal data plane peer must never receive 0.0.0.0/0")
	}
}

func TestEnableBackend_AddClientErrorFailsLoudly(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-peer-reg-err-server",
		Host: "198.51.100.31",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey-2",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{
		addClientErr: errors.New("remote SSH connection refused"),
	}
	svc.SetAWGStatusProvider(adder)

	// EnableBackend must fail loudly when AddClient fails, and not mark the tunnel active
	if err := svc.EnableBackend(ctx, srvID); err == nil {
		t.Fatal("expected EnableBackend to fail when AddClient fails, got nil")
	}

	if adder.addClientCalls != 1 {
		t.Errorf("expected 1 AddClient call attempt, got %d", adder.addClientCalls)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil || tun == nil {
		t.Fatalf("expected tunnel in pool, got %+v (err=%v)", tun, err)
	}
	if tun.Status == "active" {
		t.Errorf("expected tunnel not to be active after failed registration, got %s", tun.Status)
	}
	if tun.Status != "degraded" {
		t.Errorf("expected tunnel to be degraded after failed registration, got %s", tun.Status)
	}
}

func TestEnableBackend_UpdateBackendTunnelErrorAbortsAndLeavesStateIntact(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	initialHost := "198.51.100.45"
	initialPort := 51820
	initialPub := "server-endpoint-pubkey-initial"

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "persist-fault-server",
		Host: initialHost,
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       initialPort,
				"public_key": initialPub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	// 1. Initial EnableBackend establishes tunnel in pool and DB
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend failed: %v", err)
	}

	initialTun, err := svc.pool.GetTunnel(srvID)
	if err != nil || initialTun == nil {
		t.Fatalf("expected initial tunnel in pool, got %+v (err=%v)", initialTun, err)
	}
	expectedInitialEndpoint := "198.51.100.45:51820"
	if initialTun.Endpoint != expectedInitialEndpoint || initialTun.PublicKey != initialPub {
		t.Fatalf("initial tunnel mismatch: endpoint=%s, pub=%s", initialTun.Endpoint, initialTun.PublicKey)
	}
	initialPrivKey := initialTun.PrivateKey
	initialProbePrivKey := initialTun.ProbePrivateKey
	initialVersion := initialTun.StateVersion

	// 2. Update server configuration in DB with new host, port, and public key
	newHost := "198.51.100.46"
	newPort := 51822
	newPub := "server-endpoint-pubkey-updated"
	if err := db.UpdateServer(ctx, srvID, map[string]any{"host": newHost}); err != nil {
		t.Fatalf("UpdateServer host failed: %v", err)
	}
	if err := db.UpdateServerProtocols(ctx, srvID, map[string]any{
		"awg": map[string]any{
			"installed":  true,
			"port":       newPort,
			"public_key": newPub,
		},
	}); err != nil {
		t.Fatalf("UpdateServerProtocols failed: %v", err)
	}

	// 3. Trigger context cancellation right before pool.AddTunnel inside EnableBackend
	reqCtx, cancelReq := context.WithCancel(ctx)
	svc.SetEnableBackendPreAddTunnelHookForTest(func() {
		cancelReq()
	})

	initialClientAddCount := adder.addClientCalls

	// EnableBackend must fail when AddTunnel's DB persistence fails
	err = svc.EnableBackend(reqCtx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when DB persistence fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to register backend tunnel") {
		t.Errorf("expected error wrapping failed to register backend tunnel, got: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to persist backend tunnel updates") {
		t.Errorf("expected error wrapping failed to persist backend tunnel updates, got: %v", err)
	}

	// Verify AddClient was not called during this aborted round
	if adder.addClientCalls != initialClientAddCount {
		t.Errorf("AddClient was called %d times; expected no new calls on aborted update", adder.addClientCalls-initialClientAddCount)
	}

	// Verify in-memory pool state is completely untouched
	curTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if curTun.Endpoint != expectedInitialEndpoint {
		t.Errorf("in-memory endpoint mutated on DB failure: got %q, want %q", curTun.Endpoint, expectedInitialEndpoint)
	}
	if curTun.PublicKey != initialPub {
		t.Errorf("in-memory public key mutated on DB failure: got %q, want %q", curTun.PublicKey, initialPub)
	}
	if curTun.PrivateKey != initialPrivKey {
		t.Errorf("in-memory private key mutated on DB failure: got %q, want %q", curTun.PrivateKey, initialPrivKey)
	}
	if curTun.ProbePrivateKey != initialProbePrivKey {
		t.Errorf("in-memory probe private key mutated on DB failure: got %q, want %q", curTun.ProbePrivateKey, initialProbePrivKey)
	}
	if curTun.StateVersion != initialVersion {
		t.Errorf("in-memory state version mutated on DB failure: got %d, want %d", curTun.StateVersion, initialVersion)
	}

	// Verify DB record is also untouched
	dbTun, err := db.GetBackendTunnel(ctx, initialTun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Endpoint != expectedInitialEndpoint {
		t.Errorf("DB endpoint mutated on DB failure: got %q, want %q", dbTun.Endpoint, expectedInitialEndpoint)
	}
	if dbTun.PublicKey != initialPub {
		t.Errorf("DB public key mutated on DB failure: got %q, want %q", dbTun.PublicKey, initialPub)
	}

	// 4. Retry EnableBackend with valid context and verify it cleanly updates memory and DB
	svc.SetEnableBackendPreAddTunnelHookForTest(nil)
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("subsequent EnableBackend with valid context failed: %v", err)
	}

	expectedNewEndpoint := "198.51.100.46:51822"
	updatedTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel after retry failed: %v", err)
	}
	if updatedTun.Endpoint != expectedNewEndpoint {
		t.Errorf("expected updated endpoint %q, got %q", expectedNewEndpoint, updatedTun.Endpoint)
	}
	if updatedTun.PublicKey != newPub {
		t.Errorf("expected updated public key %q, got %q", newPub, updatedTun.PublicKey)
	}

	updatedDBTun, err := db.GetBackendTunnel(ctx, initialTun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel after retry failed: %v", err)
	}
	if updatedDBTun.Endpoint != expectedNewEndpoint {
		t.Errorf("expected DB endpoint %q, got %q", expectedNewEndpoint, updatedDBTun.Endpoint)
	}
	if updatedDBTun.PublicKey != newPub {
		t.Errorf("expected DB public key %q, got %q", newPub, updatedDBTun.PublicKey)
	}
}

func TestVPNEnableBackend_ExistingMissingDBRowFailsWithoutMemoryMutation(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	initialHost := "198.51.100.47"
	initialPort := 51820
	initialPub := "server-endpoint-pubkey-initial"

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "missing-db-twin-server",
		Host: initialHost,
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       initialPort,
				"public_key": initialPub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	// 1. Initial EnableBackend establishes tunnel in pool and DB
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend failed: %v", err)
	}

	initialTun, err := svc.pool.GetTunnel(srvID)
	if err != nil || initialTun == nil {
		t.Fatalf("expected initial tunnel in pool, got %+v (err=%v)", initialTun, err)
	}
	expectedInitialEndpoint := "198.51.100.47:51820"
	if initialTun.Endpoint != expectedInitialEndpoint || initialTun.PublicKey != initialPub {
		t.Fatalf("initial tunnel mismatch: endpoint=%s, pub=%s", initialTun.Endpoint, initialTun.PublicKey)
	}
	initialPrivKey := initialTun.PrivateKey
	initialProbePrivKey := initialTun.ProbePrivateKey
	initialVersion := initialTun.StateVersion

	// 2. Delete the DB row directly, leaving in-memory pool entry intact
	if err := db.DeleteBackendTunnel(ctx, initialTun.ID); err != nil {
		t.Fatalf("DeleteBackendTunnel failed: %v", err)
	}

	// 3. Update server configuration in DB with new host, port, and public key
	newHost := "198.51.100.48"
	newPort := 51822
	newPub := "server-endpoint-pubkey-updated"
	if err := db.UpdateServer(ctx, srvID, map[string]any{"host": newHost}); err != nil {
		t.Fatalf("UpdateServer host failed: %v", err)
	}
	if err := db.UpdateServerProtocols(ctx, srvID, map[string]any{
		"awg": map[string]any{
			"installed":  true,
			"port":       newPort,
			"public_key": newPub,
		},
	}); err != nil {
		t.Fatalf("UpdateServerProtocols failed: %v", err)
	}

	initialClientAddCalls := adder.addClientCalls

	// 4. Call EnableBackend: must fail because DB row is missing
	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when DB row is missing, got nil")
	}
	if !strings.Contains(err.Error(), "failed to register backend tunnel") {
		t.Errorf("expected error wrapping failed to register backend tunnel, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error containing 'not found', got: %v", err)
	}

	// Verify no AddClient calls were made on failed update
	if adder.addClientCalls != initialClientAddCalls {
		t.Errorf("AddClient was called %d times; expected no new calls on aborted update", adder.addClientCalls-initialClientAddCalls)
	}

	// 5. Verify in-memory pool state is not mutated
	curTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if curTun.Endpoint != expectedInitialEndpoint {
		t.Errorf("in-memory endpoint mutated on missing DB row: got %q, want %q", curTun.Endpoint, expectedInitialEndpoint)
	}
	if curTun.PublicKey != initialPub {
		t.Errorf("in-memory public key mutated on missing DB row: got %q, want %q", curTun.PublicKey, initialPub)
	}
	if curTun.PrivateKey != initialPrivKey {
		t.Errorf("in-memory private key mutated on missing DB row: got %q, want %q", curTun.PrivateKey, initialPrivKey)
	}
	if curTun.ProbePrivateKey != initialProbePrivKey {
		t.Errorf("in-memory probe private key mutated on missing DB row: got %q, want %q", curTun.ProbePrivateKey, initialProbePrivKey)
	}
	if curTun.StateVersion != initialVersion {
		t.Errorf("in-memory state version mutated on missing DB row: got %d, want %d", curTun.StateVersion, initialVersion)
	}

	// Verify DB row remains absent
	dbTun, err := db.GetBackendTunnel(ctx, initialTun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun != nil {
		t.Errorf("expected DB row to remain absent, got %+v", dbTun)
	}
}

func TestEnableBackend_NetworkCallDoesNotHoldServiceLock(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "lock-scope-server",
		Host: "198.51.100.44",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-lock-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adderCalled := false
	lockWasFree := false
	adder := &mockAWGManagerWithClientAdder{
		onAddClient: func() {
			adderCalled = true
			// If svc.mu was held with Lock(), calling IsRunning() or GetStatus()
			// (which acquire svc.mu.RLock()) would cause an immediate deadlock.
			_ = svc.IsRunning()
			st, err := svc.GetStatus(ctx)
			if err == nil && st != nil {
				lockWasFree = true
			}
		},
	}
	svc.SetAWGStatusProvider(adder)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	if !adderCalled {
		t.Error("expected AddClient to be called")
	}
	if !lockWasFree {
		t.Error("expected service lock to be free during AddClient network call")
	}
}

// TestEnableBackend_ConcurrentStateModificationAbortsEnable pins that a genuine
// concurrent modification of the tunnel identity still aborts the enable.
//
// HISTORY (issue #424 round 3): this test previously drove the abort with
// Pool.SetTunnelStatusWithReason — a pure runtime-health observation that only
// records a new status/latency. It asserted that such a bump must abort the
// enable. That assertion encoded the defect, not the intent: the background
// health prober performs exactly that write every 10s, so the "concurrent
// modification" it simulated was indistinguishable from a routine health tick,
// and the guard aborted legitimate administrative enables with HTTP 500. The
// real-prober counterpart now lives in TestEnableBackend_RoutineHealthTickDoesNotAbortEnable.
//
// The guard's actual intent — a concurrent change to the identity the portal
// peers were just registered against — is preserved and asserted below via a
// real endpoint rewrite, which is the same write Pool.AddTunnel and
// Pool.SetTunnelEndpoint use to advance StateVersion.
func TestEnableBackend_ConcurrentStateModificationAbortsEnable(t *testing.T) {
	ctx := context.Background()

	t.Run("ExistingTunnel_EndpointRewriteAbortsEnable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "concurrent-enable-server",
			Host: "198.51.100.77",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "server-concurrent-enable-pubkey",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}

		adder := &mockAWGManagerWithClientAdder{}
		svc.SetAWGStatusProvider(adder)

		// 1. Initial EnableBackend establishes tunnel in pool and DB
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial EnableBackend failed: %v", err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil || tun == nil {
			t.Fatalf("expected initial tunnel, got: %v (err=%v)", tun, err)
		}
		initialVersion := tun.StateVersion

		// 2. Rewrite the endpoint after AddTunnel but before finishEnableBackend,
		// which is exactly the concurrent identity change the guard exists for.
		hookFired := false
		svc.SetEnableBackendPostAddTunnelHookForTest(func() {
			hookFired = true
			if hookErr := svc.pool.SetTunnelEndpoint(ctx, tun.ID, "198.51.100.77:51821"); hookErr != nil {
				t.Errorf("concurrent SetTunnelEndpoint failed: %v", hookErr)
			}
		})
		defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

		// 3. Call EnableBackend again: must abort because the tunnel identity
		// this enable is provisioning against was changed concurrently.
		err = svc.EnableBackend(ctx, srvID)
		if err == nil {
			t.Fatal("expected EnableBackend to fail when the tunnel identity is modified concurrently, got nil")
		}
		if !strings.Contains(err.Error(), "identity modified concurrently") {
			t.Fatalf("unexpected error message: %v", err)
		}
		if !hookFired {
			t.Fatal("expected postAddTunnelHook to fire")
		}

		// 4. The concurrent endpoint rewrite must survive the aborted enable
		// rather than being overwritten with the stale value.
		finalTun, err := svc.pool.GetTunnel(srvID)
		if err != nil || finalTun == nil {
			t.Fatalf("expected tunnel in pool, got %v (err=%v)", finalTun, err)
		}
		if finalTun.Endpoint != "198.51.100.77:51821" {
			t.Errorf("expected the concurrently rewritten endpoint to remain intact, got %q", finalTun.Endpoint)
		}
		if finalTun.StateVersion <= initialVersion {
			t.Errorf("expected StateVersion to reflect concurrent modification (> %d), got %d", initialVersion, finalTun.StateVersion)
		}
	})

	t.Run("NewTunnel_EndpointRewriteAbortsEnable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "concurrent-enable-new-server",
			Host: "198.51.100.78",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "server-concurrent-enable-new-pubkey",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}

		adder := &mockAWGManagerWithClientAdder{}
		svc.SetAWGStatusProvider(adder)

		// Capture the tunnel row AddTunnel is about to create so the hook can
		// target it, then rewrite the endpoint mid-flight.
		var tunID int64
		hookFired := false
		svc.SetEnableBackendPostAddTunnelHookForTest(func() {
			hookFired = true
			cur, gerr := svc.pool.GetTunnel(srvID)
			if gerr != nil {
				t.Errorf("concurrent GetTunnel failed: %v", gerr)
				return
			}
			tunID = cur.ID
			if hookErr := svc.pool.SetTunnelEndpoint(ctx, cur.ID, "198.51.100.78:51821"); hookErr != nil {
				t.Errorf("concurrent SetTunnelEndpoint failed: %v", hookErr)
			}
		})
		defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

		// EnableBackend on a brand new backend: must abort because the tunnel
		// identity was changed concurrently after AddTunnel.
		err = svc.EnableBackend(ctx, srvID)
		if err == nil {
			t.Fatal("expected EnableBackend to fail when a new tunnel's identity is modified concurrently, got nil")
		}
		if !strings.Contains(err.Error(), "identity modified concurrently") {
			t.Fatalf("unexpected error message: %v", err)
		}
		if !hookFired {
			t.Fatal("expected postAddTunnelHook to fire")
		}

		finalTun, err := svc.pool.GetTunnel(srvID)
		if err != nil || finalTun == nil {
			t.Fatalf("expected tunnel in pool, got %v (err=%v)", finalTun, err)
		}
		if finalTun.Endpoint != "198.51.100.78:51821" {
			t.Errorf("expected the concurrently rewritten endpoint to remain intact, got %q", finalTun.Endpoint)
		}
		if tunID == 0 {
			t.Error("expected the hook to have resolved a tunnel id")
		}
	})
}

func TestEnableBackend_TypedSentinelErrors(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	ctx := context.Background()

	// 1. Non-existent server should return ErrServerNotFound wrapped
	err = svc.EnableBackend(ctx, 99999)
	if err == nil {
		t.Fatal("expected error for non-existent server")
	}
	if !errors.Is(err, ErrServerNotFound) {
		t.Errorf("expected ErrServerNotFound, got: %v", err)
	}

	// 2. Server without AWG credentials should return ErrAWGNotInstalled
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name:      "no-awg-server",
		Host:      "10.200.0.1",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected error for server without AWG")
	}
	if !errors.Is(err, ErrAWGNotInstalled) {
		t.Errorf("expected ErrAWGNotInstalled, got: %v", err)
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

func TestUpdateConfig_RollbackPersistenceFailureIsReported(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	baseCfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		ClientQueueSize:    2,
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	// Force runtime application to fail after persistence succeeds: active
	// routes make client queue resizing unsafe. The trigger permits that first
	// save, then rejects the rollback save while the new value is stored.
	svc.forwarder.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	if _, err := db.SQLDB().ExecContext(ctx, `CREATE TRIGGER fail_vpn_rollback BEFORE UPDATE OF value ON settings
		WHEN OLD.key = 'vpn_config' AND OLD.value LIKE '%"client_queue_size":4%'
		BEGIN SELECT RAISE(ABORT, 'rollback persistence unavailable'); END;`); err != nil {
		t.Fatalf("create rollback trigger: %v", err)
	}

	changed := *baseCfg
	changed.ClientQueueSize = 4
	err = svc.UpdateConfig(ctx, &changed)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure in returned error, got: %v", err)
	}

	runtimeCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if runtimeCfg.ClientQueueSize != 2 {
		t.Fatalf("runtime config changed despite failed application: %d", runtimeCfg.ClientQueueSize)
	}
	storedCfg, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if storedCfg.ClientQueueSize != 4 {
		t.Fatalf("expected explicit partial state with new persisted config, got %d", storedCfg.ClientQueueSize)
	}
}

func TestUpdateConfig_SaveFailureDoesNotMutateQueueRuntime(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	baseCfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		ClientQueueSize:    2,
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test DB: %v", err)
	}

	changed := *baseCfg
	changed.ClientQueueSize = 4
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("UpdateConfig unexpectedly succeeded after DB close")
	}
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfg.ClientQueueSize != 2 {
		t.Fatalf("service queue size changed after failed save: %d", cfg.ClientQueueSize)
	}
	svc.forwarder.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	queue, ok := svc.forwarder.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("GetClientPacketChannel did not find registered peer")
	}
	if cap(queue) != 2 {
		t.Fatalf("runtime queue size changed after failed save: %d", cap(queue))
	}
}

func TestUpdateConfig_PreservesObfuscationParams(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	baseCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		HealthThresholdMS:   500,
		ListenPort:          51820,
		SubnetCIDR:          "10.100.0.0/16",
		MaxTotalPeers:       500,
		MaxPeersPerBackend:  100,
		Weights:             map[int64]int{},
		H1:                  models.NewHeaderRange(111111, 115000),
		H2:                  models.NewHeaderRange(600000000, 600005000),
		H3:                  models.NewHeaderRange(1200000000, 1200005000),
		H4:                  models.NewHeaderRange(1800000000, 1800005000),
		S1:                  40,
		S2:                  50,
		S3:                  30,
		S4:                  20,
		HeaderProtectionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Startup generates a real identity; a partial update must preserve it.
	seedCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if seedCfg.ServerPrivateKey == "" || seedCfg.ServerPublicKey == "" {
		t.Fatalf("expected NewVPNService to establish portal identity, got: %+v", seedCfg)
	}

	// Partial update: payload omits H/S (all zero) and identity fields.
	partial := &models.VPNConfig{
		Algorithm:          models.LBWeighted,
		HealthThresholdMS:  600,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		MaxTotalPeers:      800,
		MaxPeersPerBackend: 200,
		Weights:            map[int64]int{},
	}
	if err := svc.UpdateConfig(ctx, partial); err != nil {
		t.Fatalf("UpdateConfig with partial cfg failed: %v", err)
	}

	// s.cfg must retain the stored H/S and identity.
	svcCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if svcCfg.H1 != models.NewHeaderRange(111111, 115000) || svcCfg.H2 != models.NewHeaderRange(600000000, 600005000) || svcCfg.H3 != models.NewHeaderRange(1200000000, 1200005000) || svcCfg.H4 != models.NewHeaderRange(1800000000, 1800005000) {
		t.Errorf("service cfg H values clobbered by partial update: %+v", svcCfg)
	}
	if svcCfg.S1 != 40 || svcCfg.S2 != 50 || svcCfg.S3 != 30 || svcCfg.S4 != 20 {
		t.Errorf("service cfg S values clobbered by partial update: %+v", svcCfg)
	}
	if svcCfg.ServerPrivateKey != seedCfg.ServerPrivateKey || svcCfg.ServerPublicKey != seedCfg.ServerPublicKey {
		t.Errorf("service cfg identity clobbered by partial update: %+v", svcCfg)
	}

	// Stored config must retain them too.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.H1 != models.NewHeaderRange(111111, 115000) || stored.H2 != models.NewHeaderRange(600000000, 600005000) || stored.H3 != models.NewHeaderRange(1200000000, 1200005000) || stored.H4 != models.NewHeaderRange(1800000000, 1800005000) {
		t.Errorf("stored H values clobbered by partial update: %+v", stored)
	}
	if stored.S1 != 40 || stored.S2 != 50 || stored.S3 != 30 || stored.S4 != 20 {
		t.Errorf("stored S values clobbered by partial update: %+v", stored)
	}
	if stored.ServerPrivateKey != seedCfg.ServerPrivateKey || stored.ServerPublicKey != seedCfg.ServerPublicKey {
		t.Errorf("stored portal identity clobbered by partial update: priv=%q pub=%q", stored.ServerPrivateKey, stored.ServerPublicKey)
	}

}

func TestUpdateConfig_RejectsObfuscationChangeWhileRunning(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	before, _ := svc.GetConfig(ctx)

	changed := *before
	changed.H1 = models.DegenerateHeaderRange(987654321)
	changed.S1 = 77
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("expected error when changing obfuscation params while listener runs")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected immutability error, got: %v", err)
	}

	after, _ := svc.GetConfig(ctx)
	if after.H1 != before.H1 {
		t.Errorf("running config was mutated by rejected update: H1 %s -> %s", before.H1, after.H1)
	}
}

func TestUpdateConfig_PropagatesObfuscationChangeWhenIdle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	before, _ := svc.GetConfig(ctx)

	changed := *before
	changed.H1 = models.DegenerateHeaderRange(123456789)
	changed.H2 = models.DegenerateHeaderRange(234567891)
	changed.H3 = models.DegenerateHeaderRange(345678912)
	changed.H4 = models.DegenerateHeaderRange(456789123)
	changed.S1 = 33
	changed.S2 = 44
	changed.S3 = 55
	changed.S4 = 66
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig with changed H/S on idle service failed: %v", err)
	}

	after, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if after.H1 != models.DegenerateHeaderRange(123456789) || after.H2 != models.DegenerateHeaderRange(234567891) || after.H3 != models.DegenerateHeaderRange(345678912) || after.H4 != models.DegenerateHeaderRange(456789123) {
		t.Errorf("service config not updated on idle service: %+v", after)
	}
	if after.S1 != 33 || after.S2 != 44 || after.S3 != 55 || after.S4 != 66 {
		t.Errorf("service S params not updated on idle service: %+v", after)
	}
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.H1 != after.H1 || stored.S1 != after.S1 {
		t.Errorf("persisted config not updated: %+v", stored)
	}
}

func TestGenerateClientConfig_PublicEndpoint(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	_, _, _, uID, _ := setupTestVPNService(t, db)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Ensure env vars are cleared initially
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")

	// Case 1: PublicEndpoint carries host:port — used verbatim.
	cfg1, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	cfg1.PublicEndpoint = "vpn.example.com:51820"
	if err := svc.UpdateConfig(ctx, cfg1); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	cfgStr1, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr1, "Endpoint = vpn.example.com:51820") {
		t.Errorf("expected Endpoint = vpn.example.com:51820, got: %s", cfgStr1)
	}

	// Case 2: bare host — configured ListenPort is appended.
	cfg2, _ := svc.GetConfig(ctx)
	cfg2.PublicEndpoint = "vpn.example.com"
	cfg2.ListenPort = 51821
	if err := svc.UpdateConfig(ctx, cfg2); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	cfgStr2, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr2, "Endpoint = vpn.example.com:51821") {
		t.Errorf("expected Endpoint = vpn.example.com:51821, got: %s", cfgStr2)
	}

	// Case 3: PublicEndpoint empty, env vars set — resolution order respected.
	cfg3, _ := svc.GetConfig(ctx)
	cfg3.PublicEndpoint = ""
	cfg3.ListenPort = 51820
	if err := svc.UpdateConfig(ctx, cfg3); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// 3a: VPN_PUBLIC_ENDPOINT with host:port
	t.Setenv("VPN_PUBLIC_ENDPOINT", "env-vpn.example.com:51822")
	cfgStr3a, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr3a, "Endpoint = env-vpn.example.com:51822") {
		t.Errorf("expected Endpoint = env-vpn.example.com:51822 from VPN_PUBLIC_ENDPOINT, got: %s", cfgStr3a)
	}

	// 3b: PUBLIC_ENDPOINT bare host (VPN_PUBLIC_ENDPOINT unset)
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "env-portal.example.org")
	cfgStr3b, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr3b, "Endpoint = env-portal.example.org:51820") {
		t.Errorf("expected Endpoint = env-portal.example.org:51820 from PUBLIC_ENDPOINT, got: %s", cfgStr3b)
	}

	// 3c: PUBLIC_IP (VPN_PUBLIC_ENDPOINT and PUBLIC_ENDPOINT unset)
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "198.18.0.99")
	cfgStr3c, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr3c, "Endpoint = 198.18.0.99:51820") {
		t.Errorf("expected Endpoint = 198.18.0.99:51820 from PUBLIC_IP, got: %s", cfgStr3c)
	}

	// Case 4: PublicEndpoint empty and no env var — auto-detected local/outbound IP,
	// and NEVER matches any backend server from db.GetAllServers().
	t.Setenv("PUBLIC_IP", "")
	cfgStr4, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	// Assert it never matches backend servers seeded in setupTestVPNService
	servers, err := db.GetAllServers(ctx)
	if err != nil {
		t.Fatalf("GetAllServers failed: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("expected test servers to exist in db")
	}
	for _, srv := range servers {
		if srv.Host != "" && strings.Contains(cfgStr4, "Endpoint = "+srv.Host) {
			t.Errorf("critical defect: client endpoint matched backend server host %s! Generated config:\n%s", srv.Host, cfgStr4)
		}
	}

	// Assert it resolved to a valid host:port format with listenPort 51820
	if !strings.Contains(cfgStr4, ":51820") {
		t.Errorf("expected config to contain listen port :51820, got: %s", cfgStr4)
	}
}

func TestGenerateClientConfig_AutoDetectFallbackAndCaching(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	_, _, _, uID, _ := setupTestVPNService(t, db)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")

	// Mock external detector to fail and force the UDP-dial fallback onto a
	// private (container-local) address: per issue #71 the fallback must
	// reject non-public results and land on 127.0.0.1 instead of caching
	// the private IP for the process lifetime.
	origDetector := externalIPDetector
	origDial := outboundDial
	defer func() {
		externalIPDetector = origDetector
		outboundDial = origDial
	}()
	externalIPDetector = func(ctx context.Context) string {
		return ""
	}
	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &fakeUDPConn{addr: &net.UDPAddr{IP: net.IPv4(172, 19, 0, 3), Port: 51820}}, nil
	}

	cfg, _ := svc.GetConfig(ctx)
	cfg.PublicEndpoint = ""
	cfg.ListenPort = 51820
	_ = svc.UpdateConfig(ctx, cfg)

	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	// Issue #71: the private UDP-dial result must be rejected, so the
	// endpoint falls back to the loopback default instead of the
	// container-local address.
	if !strings.Contains(cfgStr, "127.0.0.1:51820") {
		t.Errorf("expected fallback endpoint 127.0.0.1:51820, got: %s", cfgStr)
	}

	// Verify the non-public result is NOT cached on svc (issue #71: only
	// validated public IPs are cached, so the next resolve retries
	// detection instead of pinning 172.19.0.3 for the process lifetime).
	svc.publicIPMu.RLock()
	cached := svc.detectedPublicIP
	svc.publicIPMu.RUnlock()
	if cached != "" {
		t.Errorf("expected detectedPublicIP to remain empty for non-public detection, got: %q", cached)
	}
}

func TestVPNConfigMigration_FailsLoudly(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Seed a legacy config row without obfuscation parameters so the
	// migration path in NewVPNService is forced to generate and persist.
	legacyJSON := `{"algorithm":"least_connections","listen_port":51820,"subnet_cidr":"10.100.0.0/16","health_threshold_ms":500,"max_total_peers":1000,"max_peers_per_backend":250}`
	if _, err := db.SQLDB().ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", "vpn_config", legacyJSON); err != nil {
		t.Fatalf("failed to seed legacy vpn_config: %v", err)
	}

	// Break persistence for vpn_config saves while keeping the legacy row readable.
	for _, q := range []string{
		`CREATE TRIGGER fail_vpn_config_update BEFORE UPDATE ON settings WHEN NEW.key = 'vpn_config' BEGIN SELECT RAISE(FAIL, 'simulated save failure'); END;`,
		`CREATE TRIGGER fail_vpn_config_insert BEFORE INSERT ON settings WHEN NEW.key = 'vpn_config' BEGIN SELECT RAISE(FAIL, 'simulated save failure'); END;`,
	} {
		if _, err := db.SQLDB().ExecContext(ctx, q); err != nil {
			t.Fatalf("failed to create failure trigger: %v", err)
		}
	}

	// NewVPNService must fail explicitly with the obfuscation-persistence
	// error, not start silently with divergent ephemeral values.
	svc, err := NewVPNService(db, nil)
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected NewVPNService to fail loudly when obfuscation persistence fails")
	}
	if !strings.Contains(err.Error(), "failed to persist obfuscation params") {
		t.Fatalf("expected obfuscation persistence error, got: %v", err)
	}
}

func TestConcurrentFirstRead_ConsistentParams(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Fresh DB: no vpn_config row yet, so both goroutines run the
	// migration path concurrently.

	const goroutines = 2
	results := make(chan models.HeaderRange, goroutines)
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			svc, err := NewVPNService(db, nil)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = svc.Stop() }()
			cfg, err := svc.GetConfig(ctx)
			if err != nil {
				errs <- err
				return
			}
			results <- cfg.H1
		}()
	}

	var h1s []models.HeaderRange
	for i := 0; i < goroutines; i++ {
		select {
		case err := <-errs:
			t.Fatalf("concurrent NewVPNService failed: %v", err)
		case h1 := <-results:
			h1s = append(h1s, h1)
		}
	}

	if h1s[0] != h1s[1] {
		t.Errorf("concurrent first reads diverged: H1 values %v", h1s)
	}

	// Persisted value must match what both services saw.
	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.H1 != h1s[0] {
		t.Errorf("persisted H1 %s does not match service H1 %s", persisted.H1, h1s[0])
	}
	if persisted.H1.IsZero() {
		t.Error("expected persisted H1 to be generated (non-zero)")
	}
}

// --- Issue #16: listen-port change safety (C2) ---

func TestUpdateConfig_RejectsListenPortChangeWhileRunning(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	changed := *before
	changed.ListenPort = before.ListenPort + 7
	err = svc.UpdateConfig(ctx, &changed)
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected error when changing listen_port while listener runs")
	}
	if !strings.Contains(err.Error(), "listen_port cannot be changed while the VPN listener is running") {
		t.Fatalf("expected running-listener rejection error, got: %v", err)
	}

	// The running config must be untouched.
	after, _ := svc.GetConfig(ctx)
	if after.ListenPort != before.ListenPort {
		t.Errorf("running config was mutated by rejected update: listen_port %d -> %d", before.ListenPort, after.ListenPort)
	}
	_ = svc.Stop()

	// Once the listener is idle the same change is accepted...
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig after Stop failed: %v", err)
	}
	cfgAfter, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgAfter.ListenPort != changed.ListenPort {
		t.Errorf("idle config port not updated: want %d, got %d", changed.ListenPort, cfgAfter.ListenPort)
	}
	// ...and persisted, so the next boot binds the new port.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != changed.ListenPort {
		t.Errorf("persisted listen_port not updated: want %d, got %d", changed.ListenPort, stored.ListenPort)
	}
}

func TestUpdateConfig_AllowsListenPortChangeWhenIdle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	changed := *before
	changed.ListenPort = 31458
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig with changed listen_port on idle service failed: %v", err)
	}

	cfgAfter, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgAfter.ListenPort != 31458 {
		t.Errorf("service config listen_port: want 31458, got %d", cfgAfter.ListenPort)
	}

	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != 31458 {
		t.Errorf("persisted listen_port: want 31458, got %d", stored.ListenPort)
	}
}

// --- Issue #16: VPN_LISTEN_PORT env wiring (C1/C4) ---

// TestVPNPortWiring_EnvPortWinsOnFirstBootThenPersists constructs the C1
// wiring sequence that cmd/panel/main.go and cmd/server/main.go run before
// vpnSvc.Start: GetConfig -> set port from env -> UpdateConfig. It asserts
// the port is persisted to the DB config,
// rendered into the client config endpoint, and read back
// unchanged by a fresh service (the "subsequent boots read the persisted
// value" leg of the precedence contract).
func TestVPNPortWiring_EnvPortWinsOnFirstBootThenPersists(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// C1 wiring sequence (env VPN_LISTEN_PORT=31458 differs from DB config).
	const envPort = 31458
	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	wasPort := cfgVPN.ListenPort
	if wasPort == envPort {
		t.Fatalf("test premise: DB config already at env port %d", envPort)
	}
	cfgVPN.ListenPort = envPort
	if err := svc.UpdateConfig(ctx, cfgVPN); err != nil {
		t.Fatalf("UpdateConfig (env wiring) failed: %v", err)
	}
	t.Logf("wired VPN_LISTEN_PORT=%d (was %d)", envPort, wasPort)

	// Persisted for subsequent boots.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != envPort {
		t.Errorf("persisted listen_port: want %d, got %d", envPort, stored.ListenPort)
	}

	// GenerateClientConfig renders the matching endpoint port.
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")
	uID, err := db.CreateUser(ctx, &models.User{Username: "portwire", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, "Endpoint = ") {
		t.Fatalf("expected Endpoint directive in client config: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, ":31458") {
		t.Errorf("client config endpoint must carry the wired listen port :%d, got:\n%s", envPort, cfgStr)
	}

	// A fresh service over the same DB (next boot, env wiring already
	// applied) reads the persisted port without any further update.
	svc2, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService (second boot) failed: %v", err)
	}
	cfg2, err := svc2.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig (second boot) failed: %v", err)
	}
	if cfg2.ListenPort != envPort {
		t.Errorf("second boot must read persisted port %d, got %d", envPort, cfg2.ListenPort)
	}
}

// TestVPNPortWiring_SamePortIsNoop pins the main.go guard: when the env port
// equals the DB config port, the wiring must not call UpdateConfig (no
// rewrite, no spurious audit/persist churn).
func TestVPNPortWiring_SamePortIsNoop(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgVPN.ListenPort == 0 {
		t.Fatalf("expected non-zero ListenPort, got %d", cfgVPN.ListenPort)
	}
}

func TestGenerateClientConfig_NoCPSPackets(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "charlie",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-charlie.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	// Issue #15: Load balancer client configs must be pure AWG 3+ and must NEVER contain I1..I5
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, key := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
				t.Errorf("GenerateClientConfig must not output CPS param %s, config:\n%s", key, cfgStr)
			}
		}
	}

	// Ensure required AWG 3+ parameters are present
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if !strings.Contains(cfgStr, key+" =") {
			t.Errorf("GenerateClientConfig missing required AWG parameter %s, config:\n%s", key, cfgStr)
		}
	}
}

// --- Issue #18 R3: obfuscation migration must preserve listen_port ---

// TestEnsureObfuscationParams_PreservesLegacyListenPort verifies directly that
// the legacy-row migration (zero H1..H4/S1..S4) keeps an already-wired
// listen_port instead of zeroing it (which GetVPNConfig's fill-down would
// re-default, desyncing the running listener from rendered client configs).
func TestEnsureObfuscationParams_PreservesLegacyListenPort(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Legacy row: obfuscation params zero, listen port already wired.
	legacy := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         31458,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            map[int64]int{},
		// H1..H4 / S1..S4 deliberately zero -> triggers the migration.
	}
	if err := db.SaveVPNConfig(ctx, legacy); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	if err := ensureObfuscationParams(ctx, db, legacy); err != nil {
		t.Fatalf("ensureObfuscationParams failed: %v", err)
	}

	if legacy.ListenPort != 31458 {
		t.Errorf("migration must preserve in-memory listen_port, got %d", legacy.ListenPort)
	}
	if legacy.H1.IsZero() || legacy.H2.IsZero() || legacy.H3.IsZero() || legacy.H4.IsZero() {
		t.Errorf("migration did not fill H params: %+v", legacy)
	}
	if legacy.S1 < 0 || legacy.S2 < 0 || legacy.S3 < 0 || legacy.S4 < 0 {
		t.Errorf("migration produced invalid S params: %+v", legacy)
	}

	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != 31458 {
		t.Errorf("persisted listen_port: want 31458, got %d", stored.ListenPort)
	}
	if stored.H1.IsZero() {
		t.Errorf("persisted config missing migrated obfuscation params: %+v", stored)
	}
}

// TestBootWiring_ListenPortPersistsThroughMigration runs the full boot-wiring
// sequence against a legacy DB row (zero obfuscation params): NewVPNService
// triggers ensureObfuscationParams during boot, then the env-wiring sequence
// (GetConfig -> set 31458 -> UpdateConfig) persists the port, and a FRESH
// db.GetVPNConfig must return 31458 with the migrated params intact.
func TestBootWiring_ListenPortPersistsThroughMigration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	legacy := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            map[int64]int{},
		// H1..H4 / S1..S4 zero -> boot-time migration fills and persists them.
	}
	if err := db.SaveVPNConfig(ctx, legacy); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Env wiring sequence from cmd/*/main.go (runs before service Start).
	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgVPN.H1.IsZero() {
		t.Fatalf("boot did not migrate legacy obfuscation params: %+v", cfgVPN)
	}
	cfgVPN.ListenPort = 31458
	if err := svc.UpdateConfig(ctx, cfgVPN); err != nil {
		t.Fatalf("UpdateConfig (env wiring) failed: %v", err)
	}

	// FRESH read from the DB (what the next boot consumes).
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != 31458 {
		t.Errorf("fresh persisted listen_port: want 31458, got %d", stored.ListenPort)
	}
	if stored.H1.IsZero() {
		t.Errorf("fresh persisted config lost migrated obfuscation params: %+v", stored)
	}
}

// TestRejectedUpdateConfigLeavesPersistedRowUntouched extends the
// TestUpdateConfig_RejectsObfuscationChangeWhileRunning pattern to the
// PERSISTED row: a rejected (immutable-while-running) UpdateConfig must leave
// the stored config — including the wired listen_port — completely untouched.
func TestRejectedUpdateConfigLeavesPersistedRowUntouched(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	changed := *before
	changed.H1 = models.DegenerateHeaderRange(987654321)
	changed.S1 = 77
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("expected error when changing obfuscation params while listener runs")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected immutability error, got: %v", err)
	}

	after, _ := svc.GetConfig(ctx)
	if after.H1 != before.H1 || after.S1 != before.S1 || after.ListenPort != before.ListenPort {
		t.Errorf("running config mutated by rejected update: before(H1=%s S1=%d port=%d) after(H1=%s S1=%d port=%d)",
			before.H1, before.S1, before.ListenPort, after.H1, after.S1, after.ListenPort)
	}

	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.H1 != before.H1 || persisted.S1 != before.S1 || persisted.ListenPort != before.ListenPort {
		t.Errorf("persisted row mutated by rejected update: want(H1=%s S1=%d port=%d) got(H1=%s S1=%d port=%d)",
			before.H1, before.S1, before.ListenPort, persisted.H1, persisted.S1, persisted.ListenPort)
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

func TestProbeFunc_MatchByTunID(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "TunID Match Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-tun-id", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	recent := time.Now().Add(-10 * time.Second)
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return recent },
	}

	// Set device with matching tun.ID. Issue #43: the fake-success fast path
	// was REMOVED — ProbeTunnel now ALWAYS runs the real Noise IK probe with
	// the dedicated probe key, regardless of device handshake freshness.
	rtt, err := svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatalf("expected real-probe error against unlistening endpoint (fast path removed), got nil rtt=%d", rtt)
	}

	// Remove matching device by setting with wrong ID; prober falls through to
	// ProbeAWGEndpoint identically (still unlistening endpoint).
	svc.mu.Lock()
	if svc.backendDevices == nil {
		svc.backendDevices = make(map[int64]BackendDevice)
	}
	delete(svc.backendDevices, tun.ID)
	svc.backendDevices[99999] = dev
	svc.mu.Unlock()

	_, err = svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Error("expected ProbeTunnel to fail when device key does not match tun.ID, got nil")
	}
}

func TestProbeFunc_ZeroHandshake_Within90sGrace_SendsTrigger(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Grace Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-grace", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	inCh := make(chan []byte, 10)
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Time{} },
		createdAt:       time.Now().Add(-30 * time.Second),
		inPacketsCh:     inCh,
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Issue #43: fake-success fast path removed. ProbeTunnel now always runs
	// the real Noise IK probe with the dedicated probe key — no dummy trigger
	// packet, no synthetic 10ms RTT. Against an unlistening endpoint it fails.
	if _, err := svc.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint, got nil")
	}
}

func TestProbeFunc_ZeroHandshake_Past90sGrace_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Grace Timeout Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-grace-timeout", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	// Zero handshake, created 95s ago (>= 90s cutoff)
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Time{} },
		createdAt:       time.Now().Add(-95 * time.Second),
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Issue #43: real Noise IK probe always runs; against an unlistening
	// endpoint it fails with the probe transport error (device-based timeout
	// messages no longer apply).
	_, err = svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "failed to receive handshake response") {
		t.Errorf("expected handshake response transport error, got: %v", err)
	}
}

func TestProbeFunc_StaleHandshake_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Stale Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-stale", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	// Handshake 4 minutes ago (>= 3m cutoff). Issue #43: real Noise IK probe
	// always runs; the device-handshake-age fast paths are gone.
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Now().Add(-4 * time.Minute) },
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	_, err = svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "failed to receive handshake response") {
		t.Errorf("expected handshake response transport error, got: %v", err)
	}
}

func TestProbeFunc_RecentHandshake_ReturnsSuccess(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Recent Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-recent", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	// Handshake 45s ago (< 3m cutoff). Issue #43: the fake-success fast path
	// was removed — freshness of the data device's handshake no longer
	// fabricates a probe result; the real Noise IK probe with the dedicated
	// probe key always runs. Against an unlistening endpoint it must fail.
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Now().Add(-45 * time.Second) },
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	if _, err := svc.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint (fresh device handshake must NOT short-circuit), got nil")
	}
}

func TestAttachBackendForwarder_IdempotentClosesOldDevice(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Idempotent Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("first attachBackendForwarder failed: %v", err)
	}

	dev1 := svc.GetBackendDeviceForTest(tun.ID)
	if dev1 == nil {
		t.Fatal("expected dev1 to be attached, got nil")
	}
	if dev1.IsClosed() {
		t.Error("expected dev1 to be open initially")
	}

	// Re-attach device for the same tunnel ID
	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("second attachBackendForwarder failed: %v", err)
	}

	dev2 := svc.GetBackendDeviceForTest(tun.ID)
	if dev2 == nil {
		t.Fatal("expected dev2 to be attached, got nil")
	}
	if dev2 == dev1 {
		t.Error("expected new device instance to replace dev1")
	}
	if !dev1.IsClosed() {
		t.Error("expected old dev1 to be closed after re-attaching")
	}
	if dev2.IsClosed() {
		t.Error("expected new dev2 to remain open")
	}

	// Reading from old closed device returns error, ensuring read goroutine terminates
	buf := make([]byte, 100)
	_, readErr := dev1.Read(buf)
	if readErr == nil {
		t.Error("expected read on closed dev1 to fail, got nil")
	}

	_ = dev2.Close()
}

func TestUpdateBackendServerHost(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Update Host Srv", "198.51.100.1")

	// 1. Initial state: server.Host = old_host, tun.Endpoint = old_host:port, backend_tunnels.endpoint = old_host:port
	tun, err := svc.pool.AddTunnel(ctx, sID, "198.51.100.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	dev1 := svc.GetBackendDeviceForTest(tun.ID)
	if dev1 == nil {
		t.Fatal("expected dev1 to be attached, got nil")
	}

	// 2. Host updated: server.Host = new_host
	if err := db.UpdateServer(ctx, sID, map[string]any{"host": "198.51.100.2"}); err != nil {
		t.Fatalf("UpdateServer failed: %v", err)
	}

	// Call UpdateBackendServerHost
	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.2"); err != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", err)
	}

	// 3. Assert tun.Endpoint == new_host:port in memory
	tunMem, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunMem.Endpoint != "198.51.100.2:51820" {
		t.Errorf("expected memory tunnel endpoint '198.51.100.2:51820', got %q", tunMem.Endpoint)
	}

	// 4. Assert backend_tunnels.endpoint == new_host:port in DB
	tunnelsDB, err := db.GetBackendTunnels(ctx)
	if err != nil {
		t.Fatalf("GetBackendTunnels failed: %v", err)
	}
	var foundInDB *models.BackendTunnel
	for i := range tunnelsDB {
		if tunnelsDB[i].ServerID == sID {
			foundInDB = &tunnelsDB[i]
			break
		}
	}
	if foundInDB == nil {
		t.Fatalf("tunnel for server %d not found in DB", sID)
	}
	if foundInDB.Endpoint != "198.51.100.2:51820" {
		t.Errorf("expected DB backend tunnel endpoint '198.51.100.2:51820', got %q", foundInDB.Endpoint)
	}

	// Verify old device was closed and replaced
	if !dev1.IsClosed() {
		t.Error("expected old dev1 to be closed after endpoint update")
	}
	dev2 := svc.GetBackendDeviceForTest(tun.ID)
	if dev2 == nil {
		t.Fatal("expected dev2 to be attached after endpoint update, got nil")
	}
	if dev2 == dev1 {
		t.Error("expected dev2 to be a newly attached device instance")
	}

	// 5. Assert admin-disabled tunnel remains disabled with updated endpoint
	if err := svc.DisableBackend(ctx, sID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	disabledTun, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel after disable failed: %v", err)
	}
	if disabledTun.Enabled || disabledTun.Status != TunnelStatusActive || disabledTun.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected enabled=false with preserved active health, got enabled=%v status=%s reason=%s", disabledTun.Enabled, disabledTun.Status, disabledTun.DisableReason)
	}

	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.3"); err != nil {
		t.Fatalf("UpdateBackendServerHost on disabled tunnel failed: %v", err)
	}
	disabledTunUpdated, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel after second host update failed: %v", err)
	}
	if disabledTunUpdated.Endpoint != "198.51.100.3:51820" {
		t.Errorf("expected disabled tunnel endpoint '198.51.100.3:51820', got %q", disabledTunUpdated.Endpoint)
	}
	if disabledTunUpdated.Enabled || disabledTunUpdated.Status != TunnelStatusActive || disabledTunUpdated.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected tunnel to remain admin-disabled with preserved health, got enabled=%v status=%s reason=%s", disabledTunUpdated.Enabled, disabledTunUpdated.Status, disabledTunUpdated.DisableReason)
	}
	if dev := svc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Errorf("expected no device attached for admin-disabled tunnel, got %+v", dev)
	}

	// 6. Re-enable administrative intent, then assert restart restores the device.
	if err := svc.pool.SetTunnelEnabled(ctx, sID, true, models.DisableReasonNone); err != nil {
		t.Fatalf("SetTunnelEnabled failed: %v", err)
	}
	if err := svc.pool.SetTunnelStatusWithReason(ctx, sID, TunnelStatusActive, models.DisableReasonNone, 10); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}
	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.4"); err != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", err)
	}
	_ = svc.Stop()

	newSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService (restart) failed: %v", err)
	}
	newSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	if err := newSvc.Start(ctx); err != nil {
		t.Fatalf("newSvc.Start failed: %v", err)
	}
	defer func() { _ = newSvc.Stop() }()

	restartedTun, err := newSvc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel on restarted service failed: %v", err)
	}
	if restartedTun.Endpoint != "198.51.100.4:51820" {
		t.Errorf("expected restarted tunnel endpoint '198.51.100.4:51820', got %q", restartedTun.Endpoint)
	}
	restartedDev := newSvc.GetBackendDeviceForTest(tun.ID)
	if restartedDev == nil {
		t.Error("expected restored backend device on restarted service, got nil")
	}

	// 7. Unmanaged server (not in pool) is a no-op returning nil
	if err := newSvc.UpdateBackendServerHost(ctx, 99999, "198.51.100.99"); err != nil {
		t.Errorf("expected nil for unmanaged server, got: %v", err)
	}

	// 8. Same endpoint is a no-op returning nil
	if err := newSvc.UpdateBackendServerHost(ctx, sID, "198.51.100.4"); err != nil {
		t.Errorf("expected nil for unchanged endpoint, got: %v", err)
	}
}

func TestUpdateBackendServerHost_RaceWithDisableBackend(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Race Server", "198.51.100.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "198.51.100.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if err := svc.pool.SetTunnelStatusWithReason(ctx, sID, TunnelStatusActive, models.DisableReasonNone, 10); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	// Verify device is attached initially
	if svc.GetBackendDeviceForTest(tun.ID) == nil {
		t.Fatal("expected device to be attached initially")
	}

	// Set hook before acquiring s.mu in UpdateBackendServerHost to simulate concurrent DisableBackend
	hookCalled := false
	svc.SetUpdateBackendServerHostPreLockHook(func() {
		hookCalled = true
		if err := svc.DisableBackend(ctx, sID); err != nil {
			t.Errorf("DisableBackend in hook failed: %v", err)
		}
	})

	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.2"); err != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", err)
	}

	if !hookCalled {
		t.Fatal("expected pre-lock hook to be called")
	}

	// Assert administrative disable won while runtime health stayed active.
	tunAfter, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfter.Enabled || tunAfter.Status != TunnelStatusActive || tunAfter.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected enabled=false with active health and admin reason, got enabled=%v status=%q reason=%q",
			tunAfter.Enabled, tunAfter.Status, tunAfter.DisableReason)
	}

	// Assert forwarder device is detached / not reattached
	if dev := svc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Errorf("expected forwarder device to be detached, got %+v", dev)
	}

	// Assert no data-plane device is registered for the disabled tunnel in s.backendDevices
	svc.mu.RLock()
	_, hasDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if hasDev {
		t.Errorf("expected no device in backendDevices for disabled tunnel %d", tun.ID)
	}
}

// TestEnsureBackendDeviceAttached_FencedOnStaleStateVersion verifies that if an endpoint update
// races ensureBackendDeviceAttached after initial validation but before acquiring s.mu,
// the attachment critical section detects the StateVersion mismatch under lock, refuses to
// attach the forwarder device, and returns tunnel.ErrStaleStateVersion.
func TestEnsureBackendDeviceAttached_FencedOnStaleStateVersion(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun := tunMust(t, vpnSvc, s1ID)

	// Ensure device is initially not attached
	vpnSvc.mu.Lock()
	delete(vpnSvc.backendDevices, tun.ID)
	vpnSvc.mu.Unlock()

	var hookCalled atomic.Bool
	vpnSvc.SetEnsureDevicePreLockHook(func() {
		hookCalled.Store(true)
		if err := vpnSvc.pool.SetTunnelEndpoint(ctx, tun.ID, "198.51.100.99:51820"); err != nil {
			t.Errorf("SetTunnelEndpoint in hook failed: %v", err)
		}
	})

	err := vpnSvc.ensureBackendDeviceAttached(ctx, tun)
	if !errors.Is(err, tunnel.ErrStaleStateVersion) {
		t.Fatalf("expected ErrStaleStateVersion, got %v", err)
	}
	if !hookCalled.Load() {
		t.Fatal("expected ensureDevicePreLockHook to be called")
	}

	// Assert that forwarder device was NOT attached for the old tunnel
	if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Fatal("backend device must not be attached after concurrent endpoint update")
	}
}

// TestUpdateBackendServerHost_CanceledContextRollback verifies that if context is canceled
// after SetTunnelEndpoint mutated the pool, UpdateBackendServerHost compensates by reverting
// the endpoint in both SQLite DB and in-memory pool back to the original endpoint.
func TestUpdateBackendServerHost_CanceledContextRollback(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunBefore := tunMust(t, vpnSvc, s1ID)
	origEndpoint := tunBefore.Endpoint

	reqCtx, cancelReq := context.WithCancel(ctx)
	vpnSvc.SetUpdateBackendServerHostPreLockHook(func() {
		cancelReq()
	})

	err := vpnSvc.UpdateBackendServerHost(reqCtx, s1ID, "198.51.100.88")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Assert endpoint in memory pool was reverted to origEndpoint
	tunAfter, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfter.Endpoint != origEndpoint {
		t.Errorf("expected pool endpoint %q, got %q", origEndpoint, tunAfter.Endpoint)
	}

	// Assert endpoint in DB was reverted to origEndpoint
	dbTun, err := db.GetBackendTunnelByServerID(ctx, s1ID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbTun.Endpoint != origEndpoint {
		t.Errorf("expected DB endpoint %q, got %q", origEndpoint, dbTun.Endpoint)
	}
}

// TestUpdateBackendServerHost_RollbackFailure_ReturnsErrVPNRollbackFailed verifies that
// if endpoint rollback fails during compensation, UpdateBackendServerHost returns an error
// joining the original error and ErrVPNRollbackFailed.
func TestUpdateBackendServerHost_RollbackFailure_ReturnsErrVPNRollbackFailed(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunBefore := tunMust(t, vpnSvc, s1ID)
	origEndpoint := tunBefore.Endpoint

	// 1. Hook forwarder sync to fail
	vpnSvc.SetSyncBackendForwarderHookForTest(func() error {
		return errors.New("forwarder sync failure")
	})

	// 2. Hook SetTunnelEndpoint so rollback to origEndpoint fails
	vpnSvc.SetTunnelEndpointHookForTest(func(ctx context.Context, tunnelID int64, endpoint string) error {
		if endpoint == origEndpoint {
			return errors.New("simulated disk error during rollback")
		}
		return nil
	})

	newHost := "198.51.100.89"
	err := vpnSvc.UpdateBackendServerHost(ctx, s1ID, newHost)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrVPNRollbackFailed) {
		t.Errorf("expected error to wrap ErrVPNRollbackFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "forwarder sync failure") {
		t.Errorf("expected error to include original error 'forwarder sync failure', got %v", err)
	}
	if !strings.Contains(err.Error(), "simulated disk error during rollback") {
		t.Errorf("expected error to include rollback error, got %v", err)
	}
}

func TestUpdateBackendServerHost_SameEndpointReconcilesBackendForwarder(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Same Endpoint Srv", "198.51.100.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "198.51.100.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	dev1 := svc.GetBackendDeviceForTest(tun.ID)
	if dev1 == nil {
		t.Fatal("expected dev1 to be attached, got nil")
	}
	if dev1.IsClosed() {
		t.Fatal("expected dev1 to be open initially")
	}

	// 1. When already synchronized, calling with the same host is an idempotent no-op
	// that does NOT recreate the device.
	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.1"); err != nil {
		t.Fatalf("UpdateBackendServerHost (synchronized) failed: %v", err)
	}

	devAfter := svc.GetBackendDeviceForTest(tun.ID)
	if devAfter != dev1 {
		t.Errorf("expected device to remain unchanged, but devAfter != dev1")
	}
	if dev1.IsClosed() {
		t.Error("expected dev1 to remain open when already synchronized")
	}

	// 2. When attachedEndpoint is stale (e.g. set to a different endpoint),
	// calling with the same host reconciles the backend forwarder.
	svc.SetBackendDeviceEndpointForTest(tun.ID, "198.51.100.99:51820")

	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.1"); err != nil {
		t.Fatalf("UpdateBackendServerHost (reconciliation) failed: %v", err)
	}

	dev2 := svc.GetBackendDeviceForTest(tun.ID)
	if dev2 == nil {
		t.Fatal("expected dev2 to be attached, got nil")
	}
	if dev2 == dev1 {
		t.Error("expected new device instance to replace dev1")
	}
	if !dev1.IsClosed() {
		t.Error("expected old dev1 to be closed after stale-endpoint reconciliation")
	}
	if dev2.IsClosed() {
		t.Error("expected new dev2 to remain open")
	}
	if ep := svc.GetBackendDeviceEndpointForTest(tun.ID); ep != "198.51.100.1:51820" {
		t.Errorf("expected backendDeviceEndpoint to be %q, got %q", "198.51.100.1:51820", ep)
	}
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

func TestHealthProber_DegradedTunnel_FailsActivationWithoutDevice(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "NoDev Srv", "198.51.100.88")

	tun := &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: fmt.Sprintf("awg-be-%d", sID),
		PublicKey:     pub,
		PrivateKey:    priv,
		Endpoint:      "198.51.100.88:999999", // invalid port so attach fails
		Status:        TunnelStatusDegraded,
		CreatedAt:     time.Now().UTC(),
	}
	tunID, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}
	tun.ID = tunID

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	// Stub probeFunc to return success
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})

	// Add tunnel to pool
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	// Device is nil
	if dev := svc.GetBackendDeviceForTest(tunID); dev != nil {
		t.Fatalf("expected nil device, got %+v", dev)
	}

	// Probe the tunnel
	_, _ = svc.ProbeTunnel(ctx, tun)

	// Status must REMAIN degraded because data plane could not be attached
	tunAfter, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfter.Status != TunnelStatusDegraded {
		t.Errorf("expected tunnel without data plane device to stay degraded, but got %s", tunAfter.Status)
	}
}

type testMockPacketDev struct {
	mu       sync.Mutex
	pkts     [][]byte
	notifyCh chan struct{}
}

func (m *testMockPacketDev) Read(p []byte) (int, error) {
	return 0, nil
}

func (m *testMockPacketDev) Write(p []byte) (int, error) {
	m.mu.Lock()
	buf := make([]byte, len(p))
	copy(buf, p)
	m.pkts = append(m.pkts, buf)
	m.mu.Unlock()
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (m *testMockPacketDev) Close() error {
	return nil
}

func (m *testMockPacketDev) getPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.pkts))
	for i, b := range m.pkts {
		cp := make([]byte, len(b))
		copy(cp, b)
		out[i] = cp
	}
	return out
}

func TestAttachBackendForwarder_ReattachStopsOldPumpRegression(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	// Start forwarder pumps
	svc.forwarder.Start(ctx)
	svc.forwarder.StartPumps(ctx)
	defer func() { _ = svc.forwarder.Stop() }()

	backendID := int64(999)
	peerKey := "peer-pump-regression"
	svc.forwarder.RegisterSession("sess-p", "conn-p", peerKey, "10.100.0.99", backendID)

	dev1 := &testMockPacketDev{notifyCh: make(chan struct{}, 300)}
	dev2 := &testMockPacketDev{notifyCh: make(chan struct{}, 300)}

	// First attach
	svc.forwarder.AttachBackendDevice(backendID, dev1)

	// Route initial packet to dev1
	if err := svc.forwarder.RouteClientToBackend(peerKey, []byte("pkt-1")); err != nil {
		t.Fatalf("RouteClientToBackend pkt-1 failed: %v", err)
	}

	select {
	case <-dev1.notifyCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial packet on dev1")
	}

	if len(dev1.getPackets()) != 1 {
		t.Fatalf("expected 1 packet on dev1 before re-attach, got %d", len(dev1.getPackets()))
	}

	// Re-attach: Detach old device, Attach new device (mirrors attachBackendForwarder lifecycle)
	svc.forwarder.DetachBackendDevice(backendID)
	svc.forwarder.AttachBackendDevice(backendID, dev2)

	// Route 200 packets
	totalPackets := 200
	for i := 0; i < totalPackets; i++ {
		if err := svc.forwarder.RouteClientToBackend(peerKey, []byte(fmt.Sprintf("pkt-%d", i))); err != nil {
			t.Fatalf("RouteClientToBackend failed at %d: %v", i, err)
		}
	}

	// Wait for packets to arrive on dev2
	deadline := time.Now().Add(2 * time.Second)
	for len(dev2.getPackets()) < totalPackets && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	dev1After := len(dev1.getPackets()) - 1 // minus initial packet
	dev2Count := len(dev2.getPackets())

	// Assert old device receives ZERO packets after re-attach
	if dev1After != 0 {
		t.Errorf("expected old device dev1 to receive 0 packets after re-attach, but got %d (pump leaked)", dev1After)
	}
	// Assert new device receives 100% of packets
	if dev2Count != totalPackets {
		t.Errorf("expected new device dev2 to receive %d packets (100%%), but got %d", totalPackets, dev2Count)
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

func TestGenerateUserClientConfig_AWG3_Compliance(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "dave",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-dave.conf" {
		t.Errorf("unexpected filename: %s, want amnezia-portal-dave.conf", filename)
	}

	// Verify required sections
	if !strings.Contains(cfgStr, "[Interface]") || !strings.Contains(cfgStr, "[Peer]") {
		t.Fatalf("missing required sections in generated config:\n%s", cfgStr)
	}

	// Verify AWG 3.1 timing parameters
	rat := parseDirectiveRange(t, cfgStr, "RekeyAfterTime")
	if rat.Lo < 100 || rat.Hi > 140 {
		t.Errorf("RekeyAfterTime %s not in required range [100, 140]", rat.String())
	}

	rt := parseDirectiveRange(t, cfgStr, "RekeyTimeout")
	if rt.Lo < 4 || rt.Hi > 6 {
		t.Errorf("RekeyTimeout %s not in required range [4, 6]", rt.String())
	}
	if rt.Hi >= rat.Lo {
		t.Errorf("RekeyTimeout %s must be strictly less than RekeyAfterTime %s", rt.String(), rat.String())
	}

	rej := parseDirectiveRange(t, cfgStr, "RejectAfterTime")
	if rej.Lo < 160 || rej.Hi > 200 {
		t.Errorf("RejectAfterTime %s not in required range [160, 200]", rej.String())
	}

	kt := parseDirectiveRange(t, cfgStr, "KeepaliveTimeout")
	if kt.Lo < 8 || kt.Hi > 12 {
		t.Errorf("KeepaliveTimeout %s not in required range [8, 12]", kt.String())
	}

	mha := parseDirectiveRange(t, cfgStr, "MaxHandshakeAttempts")
	if mha.Lo < 4 || mha.Hi > 8 {
		t.Errorf("MaxHandshakeAttempts %s not in required range [4, 8]", mha.String())
	}

	pk := parseDirectiveRange(t, cfgStr, "PersistentKeepalive")
	if pk.Lo < 22 || pk.Hi > 30 {
		t.Errorf("PersistentKeepalive %s not in required range [22, 30]", pk.String())
	}

	// Verify standard AWG obfuscation parameters
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if !strings.Contains(cfgStr, key+" =") {
			t.Errorf("missing required AWG parameter %s in config:\n%s", key, cfgStr)
		}
	}

	// Verify NO CPS packets (Issue #15)
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, key := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
				t.Errorf("Load Balancer client config must not contain %s, got:\n%s", key, cfgStr)
			}
		}
	}
}

func TestGenerateUserClientConfig_StabilityAcrossRefetches(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "alice_stable",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfg1, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("first GenerateUserClientConfig failed: %v", err)
	}

	cfg2, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("second GenerateUserClientConfig failed: %v", err)
	}

	cfg3, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("third GenerateClientConfig failed: %v", err)
	}

	// Verify stability across all 3 fetches
	directives := []string{
		"RekeyAfterTime",
		"RekeyTimeout",
		"RejectAfterTime",
		"KeepaliveTimeout",
		"MaxHandshakeAttempts",
		"PersistentKeepalive",
		"PrivateKey",
	}

	for _, d := range directives {
		val1 := parseDirectiveString(t, cfg1, d)
		val2 := parseDirectiveString(t, cfg2, d)
		val3 := parseDirectiveString(t, cfg3, d)

		if val1 != val2 {
			t.Errorf("directive %s differs between fetch 1 (%s) and fetch 2 (%s)", d, val1, val2)
		}
		if val1 != val3 {
			t.Errorf("directive %s differs between fetch 1 (%s) and fetch 3 (%s)", d, val1, val3)
		}
	}

	// Verify connection record in database has ClientParams persisted
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 {
		t.Fatalf("failed to retrieve connections from db: %v", err)
	}
	conn := conns[0]
	if len(conn.ClientParams) == 0 {
		t.Fatalf("expected ClientParams on user connection, got empty: %+v", conn)
	}

	ratDB := fmt.Sprint(conn.ClientParams["rekey_after_time"])
	ratCfg := parseDirectiveString(t, cfg1, "RekeyAfterTime")
	if ratDB != ratCfg {
		t.Errorf("persisted RekeyAfterTime in DB (%v) does not match config (%s)", ratDB, ratCfg)
	}
}

func TestGenerateUserClientConfig_FingerprintDiversity(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID1, err := db.CreateUser(ctx, &models.User{Username: "client_alice", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	uID2, err := db.CreateUser(ctx, &models.User{Username: "client_bob", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}

	cfgAlice, _, err := svc.GenerateUserClientConfig(ctx, uID1)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig alice failed: %v", err)
	}
	cfgBob, _, err := svc.GenerateUserClientConfig(ctx, uID2)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig bob failed: %v", err)
	}

	// Compare timing parameters
	paramsAlice := []string{
		parseDirectiveString(t, cfgAlice, "RekeyAfterTime"),
		parseDirectiveString(t, cfgAlice, "RekeyTimeout"),
		parseDirectiveString(t, cfgAlice, "RejectAfterTime"),
		parseDirectiveString(t, cfgAlice, "KeepaliveTimeout"),
		parseDirectiveString(t, cfgAlice, "MaxHandshakeAttempts"),
		parseDirectiveString(t, cfgAlice, "PersistentKeepalive"),
	}

	paramsBob := []string{
		parseDirectiveString(t, cfgBob, "RekeyAfterTime"),
		parseDirectiveString(t, cfgBob, "RekeyTimeout"),
		parseDirectiveString(t, cfgBob, "RejectAfterTime"),
		parseDirectiveString(t, cfgBob, "KeepaliveTimeout"),
		parseDirectiveString(t, cfgBob, "MaxHandshakeAttempts"),
		parseDirectiveString(t, cfgBob, "PersistentKeepalive"),
	}

	identicalParams := true
	for i := range paramsAlice {
		if paramsAlice[i] != paramsBob[i] {
			identicalParams = false
			break
		}
	}

	if identicalParams {
		t.Errorf("fingerprint diversity failure: Alice and Bob generated identical timing parameters: %+v", paramsAlice)
	}

	privAlice := parseDirectiveString(t, cfgAlice, "PrivateKey")
	privBob := parseDirectiveString(t, cfgBob, "PrivateKey")
	if privAlice == privBob {
		t.Errorf("Alice and Bob generated identical PrivateKey: %s", privAlice)
	}
}

func TestConfigImmutabilityContract(t *testing.T) {
	ctx := context.Background()

	t.Run("StoredSingleInts_ByteIdentical_NoReRandomization", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_single_ints", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection with single ints (float64 as unmarshaled from JSON)
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-single",
			Name:     "user_single_ints-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-single",
				"rekey_after_time":       float64(125),
				"rekey_timeout":          float64(5),
				"reject_after_time":      float64(180),
				"keepalive_timeout":      float64(10),
				"max_handshake_attempts": float64(6),
				"persistent_keepalive":   float64(26),
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		// First render
		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}

		// Second render
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		// Byte-identical regression check
		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders for same UserConnection!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		// Stored single ints must be rendered unchanged as degenerate "N" (not re-randomized!)
		if !strings.Contains(cfg1, "RekeyAfterTime = 125\n") {
			t.Errorf("expected RekeyAfterTime = 125 preserved unchanged, got:\n%s", cfg1)
		}
		if !strings.Contains(cfg1, "RekeyTimeout = 5\n") {
			t.Errorf("expected RekeyTimeout = 5 preserved unchanged, got:\n%s", cfg1)
		}
		if !strings.Contains(cfg1, "PersistentKeepalive = 26\n") {
			t.Errorf("expected PersistentKeepalive = 26 preserved unchanged, got:\n%s", cfg1)
		}
	})

	t.Run("StoredRanges_ByteIdentical", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_stored_ranges", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection with ranges
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-range",
			Name:     "user_stored_ranges-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-range",
				"rekey_after_time":       "105-135",
				"rekey_timeout":          "4-6",
				"reject_after_time":      "165-195",
				"keepalive_timeout":      "9-11",
				"max_handshake_attempts": "5-7",
				"persistent_keepalive":   "23-28",
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders for stored ranges!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		if !strings.Contains(cfg1, "RekeyAfterTime = 105-135\n") {
			t.Errorf("expected RekeyAfterTime = 105-135, got:\n%s", cfg1)
		}
		if !strings.Contains(cfg1, "PersistentKeepalive = 23-28\n") {
			t.Errorf("expected PersistentKeepalive = 23-28, got:\n%s", cfg1)
		}
	})

	t.Run("PartiallyMissingParam_IndividualFallback_ByteIdentical", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_partial", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection missing rekey_after_time, but having rekey_timeout=5
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-partial",
			Name:     "user_partial-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-partial",
				"rekey_timeout":          float64(5),
				"reject_after_time":      float64(180),
				"keepalive_timeout":      float64(10),
				"max_handshake_attempts": float64(6),
				"persistent_keepalive":   float64(26),
				// rekey_after_time is intentionally missing!
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders for partially missing params!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		// Partner rekey_timeout MUST NOT have been re-rolled
		if !strings.Contains(cfg1, "RekeyTimeout = 5\n") {
			t.Errorf("stored partner RekeyTimeout = 5 was re-rolled wholesale! Cfg:\n%s", cfg1)
		}

		// Missing rekey_after_time was individually backfilled as a range
		rat := parseDirectiveRange(t, cfg1, "RekeyAfterTime")
		if rat == nil || rat.Lo < 100 || rat.Hi > 140 {
			t.Errorf("expected individually backfilled RekeyAfterTime in [100, 140], got %v", rat)
		}
	})

	t.Run("OrderingInvariantClamping_BackfilledParam", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_clamp", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection with an unusually low stored rekey_after_time = 5,
		// and missing rekey_timeout. Backfilled rekey_timeout must be clamped strictly < 5.
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-clamp",
			Name:     "user_clamp-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-clamp",
				"rekey_after_time":       float64(5),
				"reject_after_time":      float64(180),
				"keepalive_timeout":      float64(10),
				"max_handshake_attempts": float64(6),
				"persistent_keepalive":   float64(26),
				// rekey_timeout is missing
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders with clamped partner!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		rt := parseDirectiveRange(t, cfg1, "RekeyTimeout")
		rat := parseDirectiveRange(t, cfg1, "RekeyAfterTime")

		if rt.Hi >= rat.Lo {
			t.Errorf("ordering invariant failed: backfilled rt.Hi (%d) must be < stored rat.Lo (%d)", rt.Hi, rat.Lo)
		}
		if rat.Lo != 5 || rat.Hi != 5 {
			t.Errorf("stored partner rat changed: %+v", rat)
		}
	})

	t.Run("BrandNewUser_ByteIdenticalAcrossRenders", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_brand_new", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: brand new user config not byte-identical across renders!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		// Verify all 6 are emitted as ranges "lo-hi"
		for _, directive := range []string{
			"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
			"KeepaliveTimeout", "MaxHandshakeAttempts", "PersistentKeepalive",
		} {
			val := parseDirectiveString(t, cfg1, directive)
			if !strings.Contains(val, "-") {
				t.Errorf("new user %s should be range 'lo-hi', got %q", directive, val)
			}
		}
	})
}

func TestGenerateUserClientConfig_HeaderProtectionAndContentPadding(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	cfg.HeaderProtectionKey = "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU="
	cfg.ContentPaddingAddition = "16-64"
	cfg.S1 = 4
	cfg.S2 = 6
	cfg.S3 = 8
	cfg.S4 = 10
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "eve",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig failed: %v", err)
	}

	// Verify HeaderProtectionKey rendered in [Interface]
	hpk := parseDirectiveString(t, cfgStr, "HeaderProtectionKey")
	if hpk != "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=" {
		t.Errorf("unexpected HeaderProtectionKey: %s", hpk)
	}

	// Verify S1..S4 >= 12 enforced due to HeaderProtectionKey
	for _, sName := range []string{"S1", "S2", "S3", "S4"} {
		sVal := parseDirectiveInt(t, cfgStr, sName)
		if sVal < 12 {
			t.Errorf("%s = %d; expected >= 12 enforced when HeaderProtectionKey is active", sName, sVal)
		}
	}

	// Verify ContentPaddingAddition rendered in [Interface]
	cpAdd := parseDirectiveString(t, cfgStr, "ContentPaddingAddition")
	if cpAdd != "16-64" {
		t.Errorf("unexpected ContentPaddingAddition: %s, want 16-64", cpAdd)
	}

	// Refetch and ensure ContentPaddingAddition remains stable
	cfgStr2, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("second GenerateUserClientConfig failed: %v", err)
	}
	cpAdd2 := parseDirectiveString(t, cfgStr2, "ContentPaddingAddition")
	if cpAdd2 != "16-64" {
		t.Errorf("refetched ContentPaddingAddition: %s, want 16-64", cpAdd2)
	}
}

func TestEnsureObfuscationParams_HeaderProtectionKeyMigration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Legacy config with H1..H4 already populated with degenerate headers (DEV environment scenario),
	// but HeaderProtectionKey is empty and S values are < 12.
	legacy := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          31458,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       1000,
		MaxPeersPerBackend:  250,
		Weights:             map[int64]int{},
		H1:                  models.DegenerateHeaderRange(359398951),
		H2:                  models.DegenerateHeaderRange(944086617),
		H3:                  models.DegenerateHeaderRange(1418011628),
		H4:                  models.DegenerateHeaderRange(1749149601),
		S1:                  5,
		S2:                  7,
		S3:                  9,
		S4:                  11,
		HeaderProtectionKey: "",
	}
	if err := db.SaveVPNConfig(ctx, legacy); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	if err := ensureObfuscationParams(ctx, db, legacy); err != nil {
		t.Fatalf("ensureObfuscationParams failed: %v", err)
	}

	if legacy.HeaderProtectionKey == "" {
		t.Fatalf("expected HeaderProtectionKey to be generated, got empty string")
	}
	rawKey, err := health.DecodeKey(legacy.HeaderProtectionKey)
	if err != nil || len(rawKey) != 32 {
		t.Fatalf("generated HeaderProtectionKey is not valid 32-byte key: %v", err)
	}

	// Floor constraint S1..S4 >= 12 must be enforced
	if legacy.S1 < 12 || legacy.S2 < 12 || legacy.S3 < 12 || legacy.S4 < 12 {
		t.Errorf("expected S1..S4 >= 12, got S1=%d S2=%d S3=%d S4=%d", legacy.S1, legacy.S2, legacy.S3, legacy.S4)
	}
	// Degenerate headers must be upgraded to ranges (span >= 1000) containing the legacy values
	if legacy.H1.IsDegenerate() || legacy.H1.Hi-legacy.H1.Lo < 1000 || !legacy.H1.Contains(359398951) {
		t.Errorf("H1 not cleanly upgraded to range containing 359398951: %s", legacy.H1.String())
	}
	if legacy.H2.IsDegenerate() || legacy.H2.Hi-legacy.H2.Lo < 1000 || !legacy.H2.Contains(944086617) {
		t.Errorf("H2 not cleanly upgraded to range containing 944086617: %s", legacy.H2.String())
	}
	if legacy.H3.IsDegenerate() || legacy.H3.Hi-legacy.H3.Lo < 1000 || !legacy.H3.Contains(1418011628) {
		t.Errorf("H3 not cleanly upgraded to range containing 1418011628: %s", legacy.H3.String())
	}
	if legacy.H4.IsDegenerate() || legacy.H4.Hi-legacy.H4.Lo < 1000 || !legacy.H4.Contains(1749149601) {
		t.Errorf("H4 not cleanly upgraded to range containing 1749149601: %s", legacy.H4.String())
	}
	if err := awg.ValidateQuadrantDisjointness(legacy.H1, legacy.H2, legacy.H3, legacy.H4); err != nil {
		t.Errorf("upgraded header ranges are not disjoint: %v", err)
	}

	// Verify persistence in DB
	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.HeaderProtectionKey != legacy.HeaderProtectionKey {
		t.Errorf("persisted HeaderProtectionKey mismatch: got %q, want %q", persisted.HeaderProtectionKey, legacy.HeaderProtectionKey)
	}
	if persisted.S1 < 12 || persisted.S2 < 12 || persisted.S3 < 12 || persisted.S4 < 12 {
		t.Errorf("persisted S1..S4 < 12: %+v", persisted)
	}
	if persisted.H1 != legacy.H1 || persisted.H2 != legacy.H2 || persisted.H3 != legacy.H3 || persisted.H4 != legacy.H4 {
		t.Errorf("persisted H values do not match upgraded ranges: %+v", persisted)
	}
}

func TestGenerateClientConfig_PortalOwnHPKey_DoesNotBleedBackend(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Backend server has its own HeaderProtectionKey in DB.
	backendHPKey := "YmFja2VuZC1zZXJ2ZXItaGVhZGVyLXByb3RlY3Rpb24="
	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Backend-Server-1",
		Host: "192.168.1.50",
		Protocols: map[string]any{
			"awg": map[string]any{
				"awg_params": map[string]any{
					"HeaderProtectionKey": backendHPKey,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Portal VPNConfig has its OWN HeaderProtectionKey.
	portalHPKey := "cG9ydGFsLW93bi1oZWFkZXItcHJvdGVjdGlvbi1rZXk="
	portalCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          31458,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       1000,
		MaxPeersPerBackend:  250,
		Weights:             map[int64]int{sID: 100},
		H1:                  models.DegenerateHeaderRange(1000),
		H2:                  models.DegenerateHeaderRange(2000),
		H3:                  models.DegenerateHeaderRange(3000),
		H4:                  models.DegenerateHeaderRange(4000),
		S1:                  15,
		S2:                  25,
		S3:                  15,
		S4:                  15,
		HeaderProtectionKey: portalHPKey,
	}
	if err := db.SaveVPNConfig(ctx, portalCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, portalCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "client_alice",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	// Must render portal's HP key
	renderedHPKey := parseDirectiveString(t, cfgStr, "HeaderProtectionKey")
	if renderedHPKey != portalHPKey {
		t.Errorf("expected portal HP key %q, got %q", portalHPKey, renderedHPKey)
	}

	// Must NOT contain backend server's HP key
	if strings.Contains(cfgStr, backendHPKey) {
		t.Errorf("client config bled backend server's HeaderProtectionKey: %s", cfgStr)
	}
}

func TestUpdateConfig_EnforcesMinSValues(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	baseCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		HealthThresholdMS:   500,
		ListenPort:          51820,
		SubnetCIDR:          "10.100.0.0/16",
		MaxTotalPeers:       500,
		MaxPeersPerBackend:  100,
		Weights:             map[int64]int{},
		H1:                  models.NewHeaderRange(111111, 115000),
		H2:                  models.NewHeaderRange(600000000, 600005000),
		H3:                  models.NewHeaderRange(1200000000, 1200005000),
		H4:                  models.NewHeaderRange(1800000000, 1800005000),
		S1:                  40,
		S2:                  50,
		S3:                  30,
		S4:                  20,
		HeaderProtectionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Partial update with a small NON-ZERO S3: preserveObfuscationParams
	// only fills zero fields, so without enforceMinSValues this would reach
	// the listener with HP key set and S3 < 12 (impossible-state bug).
	update := &models.VPNConfig{
		Algorithm:          models.LBRoundRobin,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
		S3:                 4,
	}
	if err := svc.UpdateConfig(ctx, update); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if update.S3 < 12 {
		t.Errorf("expected S3 clamped to >= 12, got %d", update.S3)
	}
	// Preserved fields must remain.
	if update.H1 != models.NewHeaderRange(111111, 115000) || update.S1 != 40 {
		t.Errorf("expected preserved H1/S1, got H1=%s S1=%d", update.H1, update.S1)
	}
	if update.HeaderProtectionKey == "" {
		t.Error("expected HeaderProtectionKey preserved on partial update")
	}
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

func TestGenerateClientConfig_IPAMPersistence(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)

	// 1. Generate client config for user
	cfg1, _, err := vpnSvc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig 1 failed: %v", err)
	}

	addr1 := extractAddressFromConfig(t, cfg1)
	if addr1 == "" {
		t.Fatalf("empty Address extracted from config")
	}

	// 2. Verify assigned_ip is persisted in user_connections
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 {
		t.Fatalf("failed to fetch user connections: %v", err)
	}
	awgConn := conns[0]
	if awgConn.ClientParams == nil {
		t.Fatalf("expected client_params to be populated")
	}
	persistedIP, ok := awgConn.ClientParams["assigned_ip"].(string)
	if !ok || persistedIP != addr1 {
		t.Fatalf("persisted assigned_ip mismatch: got %v, want %s", awgConn.ClientParams["assigned_ip"], addr1)
	}

	// 3. Repeat call to GenerateClientConfig must return identical IP
	cfg2, _, err := vpnSvc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig 2 failed: %v", err)
	}
	addr2 := extractAddressFromConfig(t, cfg2)
	if addr2 != addr1 {
		t.Fatalf("repeat GenerateClientConfig changed IP: %s != %s", addr2, addr1)
	}
}

func TestGenerateClientConfig_ServerRestartIPAMRestoration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc1, s1ID, s2ID, uID, _ := setupTestVPNService(t, db)
	legacyConns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(legacyConns) != 1 {
		t.Fatalf("get portal client: connections=%+v err=%v", legacyConns, err)
	}
	if updated, err := db.UpdateConnection(ctx, legacyConns[0].ID, map[string]any{"server_id": int64(0)}); err != nil || !updated {
		t.Fatalf("mark client as portal connection: updated=%t err=%v", updated, err)
	}

	// 1. Generate client config
	cfg1, _, err := vpnSvc1.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig on vpnSvc1 failed: %v", err)
	}
	addr1 := extractAddressFromConfig(t, cfg1)

	// Fetch peer public key persisted during config generation
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 {
		t.Fatalf("failed to fetch connections: %v", err)
	}
	clientPub := conns[0].ClientID

	// 2. Simulate server restart: create a new VPNService instance with fresh in-memory IPAM
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
	vpnSvc2, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService for vpnSvc2 failed: %v", err)
	}
	vpnSvc2.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := vpnSvc2.Start(ctx); err != nil {
		t.Fatalf("vpnSvc2.Start failed: %v", err)
	}
	defer func() { _ = vpnSvc2.Stop() }()

	// 3. Connect peer on vpnSvc2: HandleIncomingPeer must retrieve stored assigned_ip and reserve it in fresh IPAM
	sess, _, err := vpnSvc2.HandleIncomingPeerForTest(ctx, clientPub)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed on restarted service: %v", err)
	}
	if sess.AssignedIP != addr1 {
		t.Fatalf("HandleIncomingPeer assigned IP mismatch after restart: got %s, want %s", sess.AssignedIP, addr1)
	}
	if !vpnSvc2.ipam.IsAllocated(net.ParseIP(addr1)) {
		t.Fatalf("IP %s was not marked allocated in restarted IPAM pool", addr1)
	}

	// 4. GenerateClientConfig on vpnSvc2 also preserves addr1
	cfgRestart, _, err := vpnSvc2.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed on restarted service: %v", err)
	}
	addrRestart := extractAddressFromConfig(t, cfgRestart)
	if addrRestart != addr1 {
		t.Fatalf("GenerateClientConfig on restarted service gave %s, want %s", addrRestart, addr1)
	}
}

func TestHandleIncomingPeer_IPAMPersistenceFallbackAndCollision(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("vpnSvc.Start failed: %v", err)
	}
	defer func() { _ = vpnSvc.Stop() }()

	// 1. Peer without prior assigned_ip: allocates new IP and saves to DB client_params
	u2ID, err := db.CreateUser(ctx, &models.User{
		Username: "bob",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	peerKeyBob := "bob-awg-peer-key-test"
	bobConn := &models.UserConnection{
		UserID:   u2ID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKeyBob,
		Name:     "bob-device",
	}
	if _, err := db.CreateConnection(ctx, bobConn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	sessBob, _, err := vpnSvc.HandleIncomingPeerForTest(ctx, peerKeyBob)
	if err != nil {
		t.Fatalf("HandleIncomingPeer for bob failed: %v", err)
	}
	if sessBob.AssignedIP == "" {
		t.Fatalf("expected non-empty assigned IP for bob")
	}

	bobConns, err := db.GetConnectionsByUserID(ctx, u2ID)
	if err != nil || len(bobConns) == 0 {
		t.Fatalf("failed to get bob conns: %v", err)
	}
	if bobConns[0].ClientParams == nil || bobConns[0].ClientParams["assigned_ip"] != sessBob.AssignedIP {
		t.Fatalf("expected bob connection client_params assigned_ip to be %s, got: %+v",
			sessBob.AssignedIP, bobConns[0].ClientParams)
	}

	// 2. Peer with assigned_ip colliding with a different peer's lease:
	// Setup user Charlie with assigned_ip: 10.100.0.50
	u3ID, err := db.CreateUser(ctx, &models.User{
		Username: "charlie",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	peerKeyCharlie := "charlie-awg-peer-key-test"
	targetIP := "10.100.0.50"
	charlieConn := &models.UserConnection{
		UserID:   u3ID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKeyCharlie,
		Name:     "charlie-device",
		ClientParams: map[string]any{
			"assigned_ip": targetIP,
		},
	}
	if _, err := db.CreateConnection(ctx, charlieConn); err != nil {
		t.Fatalf("CreateConnection for charlie failed: %v", err)
	}

	// Simulate stale allocation: reserve 10.100.0.50 to a dummy peer in IPAM
	if err := vpnSvc.ipam.Reserve(net.ParseIP(targetIP), "dummy-stale-peer"); err != nil {
		t.Fatalf("failed to setup dummy stale lease: %v", err)
	}

	// The lease owner cannot be inferred from an IP alone. Refuse the
	// handshake rather than removing the dummy peer's lease.
	if _, _, err := vpnSvc.HandleIncomingPeerForTest(ctx, peerKeyCharlie); !errors.Is(err, ipam.ErrIPAlreadyAllocated) {
		t.Fatalf("expected collision error for charlie, got %v", err)
	}
	if ip, ok := vpnSvc.ipam.GetAssignedIP("dummy-stale-peer"); !ok || ip.String() != targetIP {
		t.Fatalf("collision evicted the existing owner: ip=%v present=%t", ip, ok)
	}
}

func TestEnsureObfuscationParams_DegenerateToRangeUpgrade(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Seed legacy database with DEV environment single values and pre-existing HeaderProtectionKey
	legacyH1 := uint32(359398951)
	legacyH2 := uint32(944086617)
	legacyH3 := uint32(1418011628)
	legacyH4 := uint32(1749149601)
	existingHPKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	legacyCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          port,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       1000,
		MaxPeersPerBackend:  250,
		Weights:             map[int64]int{},
		H1:                  models.DegenerateHeaderRange(legacyH1),
		H2:                  models.DegenerateHeaderRange(legacyH2),
		H3:                  models.DegenerateHeaderRange(legacyH3),
		H4:                  models.DegenerateHeaderRange(legacyH4),
		S1:                  45,
		S2:                  60,
		S3:                  25,
		S4:                  15,
		HeaderProtectionKey: existingHPKey,
	}
	if err := db.SaveVPNConfig(ctx, legacyCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Test Backend",
		Host: "127.0.0.1",
		Protocols: map[string]any{
			"awg": map[string]any{
				"public_key": "backend-pubkey-123456789012345678",
				"port":       51821,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "backend-pubkey-123456789012345678",
		PrivateKey:    "backend-privkey-12345678901234567",
		Endpoint:      "127.0.0.1:51821",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	// Starting NewVPNService runs ensureObfuscationParams
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	upgradedCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	// 1. Assert headers are upgraded to ranges with span >= 1000
	for idx, tc := range []struct {
		rng models.HeaderRange
		val uint32
		q   int
	}{
		{upgradedCfg.H1, legacyH1, 0},
		{upgradedCfg.H2, legacyH2, 1},
		{upgradedCfg.H3, legacyH3, 2},
		{upgradedCfg.H4, legacyH4, 3},
	} {
		if tc.rng.IsDegenerate() {
			t.Errorf("H%d remained degenerate: %s", idx+1, tc.rng)
		}
		if tc.rng.Hi-tc.rng.Lo < 1000 {
			t.Errorf("H%d span < 1000: %s (span=%d)", idx+1, tc.rng, tc.rng.Hi-tc.rng.Lo)
		}
		// Invariant: original legacy single value MUST be contained within the upgraded range
		if !tc.rng.Contains(tc.val) {
			t.Errorf("H%d range %s does not contain legacy value %d", idx+1, tc.rng, tc.val)
		}
		qLo, qHi := awg.QuadrantBounds(tc.q)
		if tc.rng.Lo < qLo || tc.rng.Hi > qHi {
			t.Errorf("H%d range %s outside quadrant %d [%d, %d]", idx+1, tc.rng, tc.q, qLo, qHi)
		}
	}

	// 2. Assert pairwise disjointness
	if err := awg.ValidateQuadrantDisjointness(upgradedCfg.H1, upgradedCfg.H2, upgradedCfg.H3, upgradedCfg.H4); err != nil {
		t.Fatalf("upgraded ranges are not pairwise disjoint: %v", err)
	}

	// 3. Assert upgraded config is persisted to SQLite DB
	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.H1 != upgradedCfg.H1 || persisted.H2 != upgradedCfg.H2 ||
		persisted.H3 != upgradedCfg.H3 || persisted.H4 != upgradedCfg.H4 {
		t.Errorf("persisted config differs from in-memory upgraded config: %+v vs %+v", persisted, upgradedCfg)
	}
	if persisted.H1.IsDegenerate() || persisted.H1.Hi-persisted.H1.Lo < 1000 {
		t.Errorf("persisted H1 is not upgraded range: %s", persisted.H1)
	}

	// 4. Assert GenerateClientConfig emits range strings "lo-hi" for H1-H4
	uID, err := db.CreateUser(ctx, &models.User{Username: "legacy_user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	expectedH1 := fmt.Sprintf("H1 = %d-%d", upgradedCfg.H1.Lo, upgradedCfg.H1.Hi)
	expectedH2 := fmt.Sprintf("H2 = %d-%d", upgradedCfg.H2.Lo, upgradedCfg.H2.Hi)
	expectedH3 := fmt.Sprintf("H3 = %d-%d", upgradedCfg.H3.Lo, upgradedCfg.H3.Hi)
	expectedH4 := fmt.Sprintf("H4 = %d-%d", upgradedCfg.H4.Lo, upgradedCfg.H4.Hi)

	if !strings.Contains(cfgStr, expectedH1) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH1, cfgStr)
	}
	if !strings.Contains(cfgStr, expectedH2) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH2, cfgStr)
	}
	if !strings.Contains(cfgStr, expectedH3) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH3, cfgStr)
	}
	if !strings.Contains(cfgStr, expectedH4) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH4, cfgStr)
	}

	// Must NOT contain single values
	singleH1 := fmt.Sprintf("H1 = %d\n", legacyH1)
	if strings.Contains(cfgStr, singleH1) {
		t.Errorf("client config emitted single value %q instead of range", singleH1)
	}
}

// TestGenerateClientConfig_DNSDefaults verifies Issue #42: GenerateClientConfig emits
// AdGuard DNS (94.140.14.14, 94.140.15.15) instead of Cloudflare DNS (1.1.1.1, 1.0.0.1).
func TestGenerateClientConfig_DNSDefaults(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "dns-test-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-dns-test-user.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	expectedDNS := "DNS = 94.140.14.14, 94.140.15.15"
	if !strings.Contains(cfgStr, expectedDNS) {
		t.Errorf("GenerateClientConfig must emit %q, got:\n%s", expectedDNS, cfgStr)
	}

	for _, badDNS := range []string{"1.1.1.1", "1.0.0.1"} {
		if strings.Contains(cfgStr, badDNS) {
			t.Errorf("GenerateClientConfig must not contain deprecated DNS %s, config:\n%s", badDNS, cfgStr)
		}
	}
}

func TestGenerateClientConfigForConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "targeted-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	otherUID, err := db.CreateUser(ctx, &models.User{
		Username: "other-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	conn := &models.UserConnection{
		ID:         "conn-targeted-1",
		UserID:     uID,
		ServerID:   0,
		Protocol:   "awg",
		ClientID:   "",
		Name:       "Targeted Laptop",
		AWGMimicry: models.AWGMimicryAuto,
		CreatedAt:  time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	// 1. Success on targeted connection
	cfgStr, filename, err := svc.GenerateClientConfigForConnection(ctx, uID, conn.ID)
	if err != nil {
		t.Fatalf("GenerateClientConfigForConnection failed: %v", err)
	}
	if filename != "Targeted Laptop.conf" {
		t.Errorf("expected filename 'Targeted Laptop.conf', got %q", filename)
	}
	if !strings.Contains(cfgStr, "[Interface]") {
		t.Errorf("expected config to contain [Interface], got:\n%s", cfgStr)
	}

	// Verify DB was updated with client_id and client_params
	updated, err := db.GetConnection(ctx, conn.ID)
	if err != nil || updated == nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	if updated.ClientID == "" {
		t.Errorf("expected ClientID to be populated")
	}
	if updated.ClientParams == nil || updated.ClientParams["client_private_key"] == nil {
		t.Errorf("expected ClientParams with client_private_key")
	}

	// Subsequent call returns identical config and preserves ClientID
	cfgStr2, filename2, err := svc.GenerateClientConfigForConnection(ctx, uID, conn.ID)
	if err != nil {
		t.Fatalf("second GenerateClientConfigForConnection failed: %v", err)
	}
	if cfgStr2 != cfgStr {
		t.Errorf("expected second call to generate identical config")
	}
	if filename2 != filename {
		t.Errorf("expected identical filename")
	}

	// Verify no phantom connection created
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID failed: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected exactly 1 connection, got %d", len(conns))
	}

	// 2. Error on non-existent connection
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, "non-existent"); err == nil {
		t.Errorf("expected error for non-existent connection")
	}

	// 3. Error on connection belonging to another user
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, otherUID, conn.ID); err == nil {
		t.Errorf("expected error for connection belonging to another user")
	}

	// 4. Error on ServerID != 0
	serverConn := &models.UserConnection{
		ID:        "conn-server-1",
		UserID:    uID,
		ServerID:  1,
		Protocol:  "awg",
		ClientID:  "server-client-pubkey",
		Name:      "Server Connection",
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, serverConn); err != nil {
		t.Fatalf("CreateConnection serverConn failed: %v", err)
	}
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, serverConn.ID); err == nil {
		t.Errorf("expected error for connection with ServerID != 0")
	}

	// 5. Error on non-awg protocol
	vlessConn := &models.UserConnection{
		ID:        "conn-vless-1",
		UserID:    uID,
		ServerID:  0,
		Protocol:  "vless",
		ClientID:  "vless-key",
		Name:      "VLESS Connection",
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, vlessConn); err != nil {
		t.Fatalf("CreateConnection vlessConn failed: %v", err)
	}
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, vlessConn.ID); err == nil {
		t.Errorf("expected error for non-awg protocol")
	}
}

func TestGenerateClientConfig_NoPhantomOnExistingConnections(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "custconn-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Create custom-named connection
	conn := &models.UserConnection{
		ID:         "conn-custom-phone",
		UserID:     uID,
		ServerID:   0,
		Protocol:   "awg",
		ClientID:   "pubkey-phone",
		Name:       "My Phone",
		AWGMimicry: models.AWGMimicryAuto,
		CreatedAt:  time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	// Call GenerateClientConfig(ctx, uID)
	cfgStr, filename, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, "[Interface]") {
		t.Errorf("expected config to contain [Interface]")
	}
	if filename != "amnezia-portal-custconn-user.conf" {
		t.Errorf("expected filename 'amnezia-portal-custconn-user.conf', got %q", filename)
	}

	// Verify no phantom connection created
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID failed: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected exactly 1 connection in DB, got %d", len(conns))
	}
	if conns[0].Name != "My Phone" {
		t.Errorf("expected connection Name 'My Phone', got %q", conns[0].Name)
	}
}

func TestGenerateClientConfigRejectsSingleRemoteAWGConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "single-remote-awg", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "remote-awg", Host: "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	const remotePeer = "single-remote-peer"
	remoteParams := map[string]any{"remote_setting": "keep"}
	remoteID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: serverID, Protocol: "awg", ClientID: remotePeer,
		ClientParams: remoteParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config, filename, err := svc.GenerateClientConfig(ctx, userID); err == nil {
		t.Fatalf("generated unusable portal config for remote connection: filename=%q config=%q", filename, config)
	}
	conns, err := db.GetConnectionsByUserID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 || conns[0].ID != remoteID || conns[0].ServerID != serverID || conns[0].ClientID != remotePeer || !reflect.DeepEqual(conns[0].ClientParams, remoteParams) {
		t.Fatalf("remote connection changed or portal connection was created: %+v", conns)
	}
	if _, ok := svc.ipam.GetAssignedIP(remotePeer); ok {
		t.Fatal("remote peer reserved a portal IP")
	}
}

func TestGenerateClientConfig_NoPhantomWhenUserHasRemoteServerConnections(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "remote-only-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// User has 2 remote server connections (ServerID > 0).
	server1, err := db.CreateServer(ctx, &models.Server{Name: "remote-1", Host: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	server2, err := db.CreateServer(ctx, &models.Server{Name: "remote-2", Host: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	conn1 := &models.UserConnection{
		ID:        "conn-remote-1",
		UserID:    uID,
		ServerID:  server1,
		Protocol:  "awg",
		ClientID:  "pubkey-remote-1",
		Name:      "Server 1",
		CreatedAt: time.Now(),
	}
	conn2 := &models.UserConnection{
		ID:        "conn-remote-2",
		UserID:    uID,
		ServerID:  server2,
		Protocol:  "vless",
		ClientID:  "uuid-remote-2",
		Name:      "Server 2",
		CreatedAt: time.Now().Add(time.Second),
	}
	if _, err := db.CreateConnection(ctx, conn1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, conn2); err != nil {
		t.Fatal(err)
	}

	// Call GenerateClientConfig(ctx, uID)
	_, _, err = svc.GenerateClientConfig(ctx, uID)
	if err == nil {
		t.Fatal("generated an unpersisted load balancer configuration for a user with only remote connections")
	}

	// Verify no phantom connection was created
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID failed: %v", err)
	}
	if len(conns) != 2 {
		t.Fatalf("expected exactly 2 connections in DB, got %d", len(conns))
	}
	for _, c := range conns {
		if c.Name == "remote-only-user-awg" {
			t.Errorf("phantom connection remote-only-user-awg was created in DB")
		}
	}
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

func TestDisableBackend_PersistenceFailurePreservesStateAndDevice(t *testing.T) {
	t.Run("ContextCanceled", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()

		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		s1ID, pub1, _ := createTestServerAndKey(t, db, "Backend Srv 1", "127.0.0.1")
		s2ID, pub2, _ := createTestServerAndKey(t, db, "Backend Srv 2", "127.0.0.1")

		tun1, err := svc.pool.AddTunnel(ctx, s1ID, "127.0.0.1:51821", pub1)
		if err != nil {
			t.Fatalf("AddTunnel 1 failed: %v", err)
		}
		tun2, err := svc.pool.AddTunnel(ctx, s2ID, "127.0.0.1:51822", pub2)
		if err != nil {
			t.Fatalf("AddTunnel 2 failed: %v", err)
		}

		svc.mu.Lock()
		err = svc.attachBackendForwarder(tun1, nil)
		svc.mu.Unlock()
		if err != nil {
			t.Fatalf("attachBackendForwarder failed: %v", err)
		}

		devBefore := svc.GetBackendDeviceForTest(tun1.ID)
		if devBefore == nil {
			t.Fatal("expected backend device attached before test, got nil")
		}
		if devBefore.IsClosed() {
			t.Fatal("expected backend device to be open before test")
		}
		t.Cleanup(func() { _ = devBefore.Close() })

		uID, err := db.CreateUser(ctx, &models.User{Username: "charlie", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		peerKey := "charlie-peer-key"
		_, err = db.CreateConnection(ctx, &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: peerKey,
			Name:     "charlie-device",
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, "10.100.0.10", tun1.ID, "charlie-device")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		svc.pool.IncrementConnections(tun1.ID)
		svc.stickyMgr.AssignPeerAffinity(peerKey, tun1.ID)
		svc.forwarder.RegisterSession(sess.ID, "charlie-conn", peerKey, "10.100.0.10", tun1.ID)

		tun1Check, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil || tun1Check.ActiveConnections != 1 {
			t.Fatalf("expected tun1 ActiveConnections == 1, got %d (err=%v)", tun1Check.ActiveConnections, err)
		}
		tun2Check, err := svc.pool.GetTunnelByID(tun2.ID)
		if err != nil || tun2Check.ActiveConnections != 0 {
			t.Fatalf("expected tun2 ActiveConnections == 0, got %d (err=%v)", tun2Check.ActiveConnections, err)
		}
		affPre, ok := svc.stickyMgr.GetPeerAffinity(peerKey)
		if !ok || affPre != tun1.ID {
			t.Fatalf("expected peer affinity to tun1 (%d), got ok=%v aff=%d", tun1.ID, ok, affPre)
		}

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		err = svc.DisableBackend(canceledCtx, s1ID)
		if err == nil {
			t.Fatal("expected DisableBackend to return error on DB persistence failure, got nil")
		}
		if !strings.Contains(err.Error(), "failed to persist administrative backend disable") {
			t.Errorf("unexpected error message: %v", err)
		}

		tunAfter, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tunAfter.Status != TunnelStatusActive {
			t.Errorf("expected pool status to remain %q, got %q", TunnelStatusActive, tunAfter.Status)
		}

		devAfter := svc.GetBackendDeviceForTest(tun1.ID)
		if devAfter == nil {
			t.Fatal("expected backend device to remain attached in service map, got nil")
		}
		if devAfter.IsClosed() {
			t.Error("expected backend device to remain open, but IsClosed() is true")
		}

		affPost, ok := svc.stickyMgr.GetPeerAffinity(peerKey)
		if !ok || affPost != tun1.ID {
			t.Errorf("expected peer affinity preserved for tun1 (%d), got ok=%v aff=%d", tun1.ID, ok, affPost)
		}
		tun1Final, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil || tun1Final.ActiveConnections != 1 {
			t.Errorf("expected tun1 ActiveConnections to remain 1, got %d (err=%v)", tun1Final.ActiveConnections, err)
		}
		tun2Final, err := svc.pool.GetTunnelByID(tun2.ID)
		if err != nil || tun2Final.ActiveConnections != 0 {
			t.Errorf("expected tun2 ActiveConnections to remain 0, got %d (err=%v)", tun2Final.ActiveConnections, err)
		}
		liveSess, ok := svc.sessionMgr.GetSession(peerKey)
		if !ok || liveSess.BackendTunnelID != tun1.ID {
			t.Errorf("expected session backend to remain tun1 (%d), got ok=%v id=%d", tun1.ID, ok, liveSess.BackendTunnelID)
		}
	})

	t.Run("ClosedDB", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()

		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		s1ID, pub1, _ := createTestServerAndKey(t, db, "Backend Srv ClosedDB", "127.0.0.1")
		tun1, err := svc.pool.AddTunnel(ctx, s1ID, "127.0.0.1:51823", pub1)
		if err != nil {
			t.Fatalf("AddTunnel failed: %v", err)
		}

		svc.mu.Lock()
		err = svc.attachBackendForwarder(tun1, nil)
		svc.mu.Unlock()
		if err != nil {
			t.Fatalf("attachBackendForwarder failed: %v", err)
		}

		devBefore := svc.GetBackendDeviceForTest(tun1.ID)
		if devBefore == nil {
			t.Fatal("expected backend device attached before test, got nil")
		}
		if devBefore.IsClosed() {
			t.Fatal("expected backend device to be open before test")
		}
		t.Cleanup(func() { _ = devBefore.Close() })

		// Close DB to inject DB write error
		_ = db.Close()

		err = svc.DisableBackend(ctx, s1ID)
		if err == nil {
			t.Fatal("expected DisableBackend to return error when DB is closed, got nil")
		}
		if !strings.Contains(err.Error(), "failed to persist administrative backend disable") {
			t.Errorf("unexpected error message: %v", err)
		}

		tunAfter, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tunAfter.Status != TunnelStatusActive {
			t.Errorf("expected pool status to remain %q, got %q", TunnelStatusActive, tunAfter.Status)
		}

		devAfter := svc.GetBackendDeviceForTest(tun1.ID)
		if devAfter == nil {
			t.Fatal("expected backend device to remain attached in service map, got nil")
		}
		if devAfter.IsClosed() {
			t.Error("expected backend device to remain open, but IsClosed() is true")
		}
	})
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

// Issue #344 Regression Tests: Fail startup on unreadable persisted VPN configuration

func TestNewVPNService_MalformedVPNConfigFailsAndPreservesRow(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	const malformedJSON = "{invalid-json"
	if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', ?)", malformedJSON); err != nil {
		t.Fatalf("failed to insert malformed vpn_config: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected NewVPNService to fail on malformed vpn_config")
	}
	if !strings.Contains(err.Error(), "failed to load VPN config") {
		t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
	}

	var rawValue string
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
		t.Fatalf("failed to read raw vpn_config: %v", err)
	}
	if rawValue != malformedJSON {
		t.Fatalf("malformed setting was overwritten: got %q, want %q", rawValue, malformedJSON)
	}
}

func TestNewVPNService_DatabaseReadErrorFailsWithoutPersistence(t *testing.T) {
	ctx := context.Background()

	t.Run("closed_database", func(t *testing.T) {
		db := setupTestDB(t)
		if err := db.Close(); err != nil {
			t.Fatalf("failed to close test db: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail when database is closed")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}
	})

	t.Run("dropped_settings_table", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatalf("failed to drop settings table: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail when settings table is unreadable")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}
	})
}

func TestEnsureObfuscationParams_ReadFailureAbortsWithoutWrite(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	const malformedJSON = "{invalid-json"
	if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', ?)", malformedJSON); err != nil {
		t.Fatalf("failed to insert malformed vpn_config: %v", err)
	}

	cfg := defaultVPNConfig()
	err := ensureObfuscationParams(ctx, db, cfg)
	if err == nil {
		t.Fatal("expected ensureObfuscationParams to fail on unreadable setting")
	}
	if !strings.Contains(err.Error(), "failed to read persisted VPN config for obfuscation migration") {
		t.Fatalf("expected obfuscation migration read error, got: %v", err)
	}

	// Invariant: Missing obfuscation parameters must NOT be generated on read failure
	if !cfg.H1.IsZero() {
		t.Fatalf("expected cfg.H1 to remain zero, got: %v", cfg.H1)
	}
	if cfg.HeaderProtectionKey != "" {
		t.Fatalf("expected cfg.HeaderProtectionKey to remain empty, got: %q", cfg.HeaderProtectionKey)
	}

	// Invariant: Raw corrupted setting must NOT be overwritten
	var rawValue string
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
		t.Fatalf("failed to read raw vpn_config: %v", err)
	}
	if rawValue != malformedJSON {
		t.Fatalf("malformed setting was overwritten: got %q, want %q", rawValue, malformedJSON)
	}
}

func TestNewVPNService_TrulyAbsentConfigInitializesFirstBoot(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Ensure vpn_config row is completely absent (first boot without pre-seeded row)
	if _, err := db.SQLDB().ExecContext(ctx, "DELETE FROM settings WHERE key = 'vpn_config'"); err != nil {
		t.Fatalf("failed to delete vpn_config setting: %v", err)
	}

	var count int
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM settings WHERE key = 'vpn_config'").Scan(&count); err != nil {
		t.Fatalf("failed to count vpn_config rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 vpn_config rows before init, got %d", count)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed on absent config: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted == nil {
		t.Fatal("expected persisted VPN config to exist")
	}
	if persisted.ListenPort != 51820 {
		t.Errorf("expected ListenPort 51820, got %d", persisted.ListenPort)
	}
	if persisted.H1.IsZero() || persisted.H2.IsZero() || persisted.H3.IsZero() || persisted.H4.IsZero() {
		t.Errorf("expected valid non-zero H values, got H1=%s H2=%s H3=%s H4=%s", persisted.H1, persisted.H2, persisted.H3, persisted.H4)
	}
	if persisted.HeaderProtectionKey == "" {
		t.Errorf("expected non-empty HeaderProtectionKey")
	}

	// Verify the row actually exists in the database settings table
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM settings WHERE key = 'vpn_config'").Scan(&count); err != nil {
		t.Fatalf("failed to count vpn_config rows after init: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 vpn_config row after init, got %d", count)
	}
}

func TestNewVPNService_ExistingEmptySQLNullOrJSONNullConfigFailsAndPreservesRow(t *testing.T) {
	ctx := context.Background()

	t.Run("empty_string", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', '')"); err != nil {
			t.Fatalf("failed to insert empty vpn_config: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail on empty vpn_config")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}

		var rawValue sql.NullString
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
			t.Fatalf("failed to read raw vpn_config: %v", err)
		}
		if !rawValue.Valid || rawValue.String != "" {
			t.Fatalf("expected empty string row preserved, got: %+v", rawValue)
		}
	})

	t.Run("sql_null", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', NULL)"); err != nil {
			t.Fatalf("failed to insert SQL NULL vpn_config: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail on SQL NULL vpn_config")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}

		var rawValue sql.NullString
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
			t.Fatalf("failed to read raw vpn_config: %v", err)
		}
		if rawValue.Valid {
			t.Fatalf("expected SQL NULL preserved, got valid string: %q", rawValue.String)
		}
	})

	t.Run("json_null", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', 'null')"); err != nil {
			t.Fatalf("failed to insert json null vpn_config: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail on json null vpn_config")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}

		var rawValue sql.NullString
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
			t.Fatalf("failed to read raw vpn_config: %v", err)
		}
		if !rawValue.Valid || rawValue.String != "null" {
			t.Fatalf("expected json null string preserved, got: %+v", rawValue)
		}
	})
}
