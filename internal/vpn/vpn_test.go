package vpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/endpoint"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/tunnel"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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

func TestLegacyServiceAndBalancer(t *testing.T) {
	lb := NewLeastConnectionsLoadBalancer()
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
		&BackendTunnel{ID: 3, InterfaceName: "awg-be-3", Status: TunnelStatusActive, ActiveConnections: 5},
		&BackendTunnel{ID: 4, InterfaceName: "awg-be-4", Status: TunnelStatusActive, ActiveConnections: 2},
		&BackendTunnel{ID: 5, InterfaceName: "awg-be-5", Status: TunnelStatusActive, ActiveConnections: 8},
	)

	best, err := lb.SelectBackend(ctx, &loadbalancer.RoutingRequest{AvailableTunnels: tunnels})
	if err != nil {
		t.Fatalf("SelectBackend failed: %v", err)
	}

	if best.ID != 4 {
		t.Errorf("expected tunnel ID 4 (2 active connections), got ID %d (%d connections)", best.ID, best.ActiveConnections)
	}

	// Legacy NewService
	svc := NewService(models.LBLeastConnections)
	bestSvc, err := svc.SelectTunnel(ctx, tunnels)
	if err != nil || bestSvc.ID != 4 {
		t.Errorf("SelectTunnel mismatch: %+v, err: %v", bestSvc, err)
	}
}

func setupTestVPNService(t *testing.T, db *database.DB) (*Service, int64, int64, string, string) {
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
		ServerID: s1ID,
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
	sess, backend, err := vpnSvc.HandleIncomingPeer(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed: %v", err)
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
	_, _, _ = vpnSvc.HandleIncomingPeer(ctx, peerKeyAlice)
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
	if t1Status.Status != "disabled" {
		t.Errorf("expected status disabled, got %s", t1Status.Status)
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
	if sess, _, err := vpnSvc.HandleIncomingPeer(ctx, newClientPub); err != nil || sess == nil {
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
	if err != nil || st.ListenerRunning || st.ActiveTunnels != 0 {
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

	// 12. HandleIncomingPeer uninitialized
	if _, _, err := emptySvc.HandleIncomingPeer(ctx, "peer"); err == nil {
		t.Errorf("expected error HandleIncomingPeer uninitialized")
	}

	// 13. HandleIncomingPeer no active backends
	uID, _ := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true})
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Server", Host: "10.0.0.1"})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: sID,
		Protocol: "awg",
		ClientID: "bob-peer-key",
	})
	if _, _, err := svcWithDB.HandleIncomingPeer(ctx, "bob-peer-key"); err == nil {
		t.Errorf("expected error HandleIncomingPeer when no active backends")
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
		// Create a listener with the already occupied port
		listenerCfg := endpoint.ListenerConfig{ListenPort: occPort}
		occListener, _ := endpoint.NewListener(listenerCfg, db, nil, nil, nil, nil)
		invalidListenerSvc.endpoint = occListener
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

	// DATA peer: identity = derive(PrivateKey), allowed_ips 0.0.0.0/0.
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
	if aip, ok := dataParams["allowed_ips"]; !ok || aip != "0.0.0.0/0" {
		t.Errorf("expected data peer allowed_ips '0.0.0.0/0', got: %v", dataParams["allowed_ips"])
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

func TestAWG3_HandshakeAndTransportRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	vpnCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          port,
		SubnetCIDR:          "10.100.0.0/24",
		H1:                  models.NewHeaderRange(12345678, 12347000),
		H2:                  models.NewHeaderRange(600000000, 600010000),
		H3:                  models.NewHeaderRange(1200000000, 1200010000),
		H4:                  models.NewHeaderRange(1800000000, 1800010000),
		S1:                  45,
		S2:                  60,
		S3:                  25,
		S4:                  15,
		HeaderProtectionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	if err := db.SaveVPNConfig(ctx, vpnCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	// Backend tunnel setup
	sID, err := db.CreateServer(ctx, &models.Server{Name: "US Backend", Host: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "us-backend-pubkey",
		PrivateKey:    "us-backend-privkey",
		Endpoint:      "127.0.0.1:51821",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{Username: "carol", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	vpnSvc, err := NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("vpnSvc.Start failed: %v", err)
	}
	defer func() { _ = vpnSvc.Stop() }()

	// 1. Generate client config & verify persistence/rendering of stored H/S
	cfgStr, _, err := vpnSvc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, "H1 = 12345678-12347000") ||
		!strings.Contains(cfgStr, "H2 = 600000000-600010000") ||
		!strings.Contains(cfgStr, "H4 = 1800000000-1800010000") ||
		!strings.Contains(cfgStr, "S1 = 45") ||
		!strings.Contains(cfgStr, "S2 = 60") {
		t.Fatalf("GenerateClientConfig did not render stored VPNConfig values: %s", cfgStr)
	}
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, k+" =") || strings.HasPrefix(trimmed, k+"=") {
				t.Fatalf("client config must NEVER contain %s (Issue #15), got:\n%s", k, cfgStr)
			}
		}
	}

	// 2. Parse config parameters
	var clientPrivB64, serverPubB64 string
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PrivateKey =") {
			clientPrivB64 = strings.TrimSpace(strings.TrimPrefix(trimmed, "PrivateKey ="))
		} else if strings.HasPrefix(trimmed, "PublicKey =") {
			serverPubB64 = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey ="))
		}
	}
	clientPrivBytes, err := base64.StdEncoding.DecodeString(clientPrivB64)
	if err != nil || len(clientPrivBytes) != 32 {
		t.Fatalf("invalid client priv key: %v", err)
	}
	serverPubBytes, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil || len(serverPubBytes) != 32 {
		t.Fatalf("invalid server pub key: %v", err)
	}
	clientPubBytes, err := curve25519.X25519(clientPrivBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 failed: %v", err)
	}
	clientPubB64 := base64.StdEncoding.EncodeToString(clientPubBytes)

	serverUDPAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	clientConn, err := net.DialUDP("udp", nil, serverUDPAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// 3. Handshake round-trip
	initPacket, state, err := health.BuildAWGInitiationPacket(serverPubBytes, clientPrivBytes, nil, vpnCfg.H1, vpnCfg.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}
	if _, err := clientConn.Write(initPacket); err != nil {
		t.Fatalf("Write initiation failed: %v", err)
	}

	respBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("Read handshake response failed: %v", err)
	}
	if !health.VerifyAWGResponsePacket(respBuf[:n], state, vpnCfg.H2, vpnCfg.S2) {
		t.Fatal("VerifyAWGResponsePacket rejected server response")
	}

	// 4. AWG Transport Framing & Decryption Round-Trip
	routedCh := make(chan []byte, 1)
	vpnSvc.endpoint.SetClientPacketRouter(func(peerKey string, pkt []byte) error {
		if peerKey == clientPubB64 {
			routedCh <- pkt
		}
		return nil
	})

	respPayload := respBuf[vpnCfg.S2:n]
	serverReceiverIdx := respPayload[4:8]
	serverEPub := respPayload[12:44]

	ss3, err := curve25519.X25519(state.ClientEPriv, serverEPub)
	if err != nil {
		t.Fatalf("ss3 DH failed: %v", err)
	}
	ck := health.KDF1(health.KDF1(state.CK, serverEPub), ss3)
	ss4, err := curve25519.X25519(state.ClientPriv, serverEPub)
	if err != nil {
		t.Fatalf("ss4 DH failed: %v", err)
	}
	ck = health.KDF1(ck, ss4)
	ck, _, _ = health.KDF3(ck, make([]byte, 32))
	clientSendKey, clientRecvKey := health.KDF2(ck, nil)

	// 4a. Client -> Endpoint: AWG Transport Frame (S4 padding + H4 header + counter 0)
	aeadSend, err := chacha20poly1305.New(clientSendKey)
	if err != nil {
		t.Fatalf("aeadSend failed: %v", err)
	}
	testPayload := []byte("client-awg3-data-frame-content")
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], 0)

	s4 := vpnCfg.S4
	frameLen := s4 + 16
	transportDatagram := make([]byte, frameLen)
	if _, err := rand.Read(transportDatagram[:s4]); err != nil {
		t.Fatalf("rand failed: %v", err)
	}
	binary.LittleEndian.PutUint32(transportDatagram[s4:s4+4], vpnCfg.H4.PickOne())
	copy(transportDatagram[s4+4:s4+8], serverReceiverIdx)
	binary.LittleEndian.PutUint64(transportDatagram[s4+8:s4+16], 0)
	transportDatagram = aeadSend.Seal(transportDatagram, nonce[:], testPayload, nil)

	if _, err := clientConn.Write(transportDatagram); err != nil {
		t.Fatalf("Write transport data failed: %v", err)
	}

	select {
	case received := <-routedCh:
		if !bytes.Equal(received, testPayload) {
			t.Fatalf("routed packet mismatch: got %q, want %q", received, testPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for endpoint to decrypt and route transport packet")
	}

	// 4b. Endpoint -> Client: SendToPeer AWG Transport Frame
	replyPayload := []byte("reply-from-endpoint-awg3")
	if err := vpnSvc.endpoint.SendToPeer(clientPubB64, replyPayload); err != nil {
		t.Fatalf("SendToPeer failed: %v", err)
	}

	clientRecvBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	nRecv, err := clientConn.Read(clientRecvBuf)
	if err != nil {
		t.Fatalf("Read SendToPeer packet failed: %v", err)
	}
	if nRecv < s4+16+len(replyPayload) {
		t.Fatalf("received frame too short: %d", nRecv)
	}
	replyDatagram := clientRecvBuf[:nRecv]
	replyPayloadPart := replyDatagram[s4:]
	var counter uint64
	var msgType uint32
	if hpKey, _ := health.DecodeKey(vpnCfg.HeaderProtectionKey); len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, replyDatagram[:health.HeaderCipherNonceSize])
		if cip != nil {
			var unmaskedHdr [16]byte
			cip.XORKeyStream(unmaskedHdr[:], replyPayloadPart[:16])
			msgType = binary.LittleEndian.Uint32(unmaskedHdr[0:4])
			counter = binary.LittleEndian.Uint64(unmaskedHdr[8:16])
		}
	}
	if msgType == 0 {
		msgType = binary.LittleEndian.Uint32(replyPayloadPart[0:4])
		counter = binary.LittleEndian.Uint64(replyPayloadPart[8:16])
	}
	if !vpnCfg.H4.Contains(msgType) {
		t.Fatalf("SendToPeer msgType mismatch: got %d, want in %s", msgType, vpnCfg.H4)
	}
	aeadRecv, err := chacha20poly1305.New(clientRecvKey)
	if err != nil {
		t.Fatalf("aeadRecv failed: %v", err)
	}
	var recvNonce [12]byte
	binary.LittleEndian.PutUint64(recvNonce[4:12], counter)
	decryptedReply, err := aeadRecv.Open(nil, recvNonce[:], replyPayloadPart[16:], nil)
	if err != nil {
		t.Fatalf("failed to decrypt SendToPeer packet: %v", err)
	}
	if !bytes.Equal(decryptedReply, replyPayload) {
		t.Fatalf("decrypted reply mismatch: got %q, want %q", decryptedReply, replyPayload)
	}

	// 4c. Negative Test: corrupted H4 transport frame is silently dropped, does not route
	corruptDatagram := make([]byte, len(transportDatagram))
	copy(corruptDatagram, transportDatagram)
	binary.LittleEndian.PutUint32(corruptDatagram[s4:s4+4], 0xCAFEBABE)
	if _, err := clientConn.Write(corruptDatagram); err != nil {
		t.Fatalf("Write corrupt datagram failed: %v", err)
	}
	select {
	case <-routedCh:
		t.Fatal("corrupt H4 datagram was routed when it should have been dropped")
	case <-time.After(150 * time.Millisecond):
		// Expected silent drop
	}

	// 4d. Negative Test: handshake with mismatched H1 must fail cleanly (silent drop)
	wrongH1Packet, _, err := health.BuildAWGInitiationPacket(serverPubBytes, clientPrivBytes, nil, 0x99999999, vpnCfg.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket wrong H1 failed: %v", err)
	}
	if _, err := clientConn.Write(wrongH1Packet); err != nil {
		t.Fatalf("Write wrong H1 packet failed: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	wrongRespBuf := make([]byte, 2048)
	if nWrong, err := clientConn.Read(wrongRespBuf); err == nil {
		t.Fatalf("expected silent drop for wrong H1 handshake, got %d bytes response", nWrong)
	}
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
		ServerPrivateKey:    "kept-priv",
		ServerPublicKey:     "kept-pub",
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// The dummy identity seeded above is not a valid keypair, so
	// EnsureKeypair regenerates and persists a real one; capture the
	// post-init identity — THAT is what a partial update must preserve.
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

	// The listener must agree with the persisted config.
	lc := svc.endpoint.ListenerConfigSnapshot()
	if lc.H1 != models.NewHeaderRange(111111, 115000) || lc.S1 != 40 || lc.H4 != models.NewHeaderRange(1800000000, 1800005000) || lc.S4 != 20 {
		t.Errorf("listener config diverges from stored config: %+v", lc)
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

func TestUpdateConfig_PropagatesObfuscationChangeToIdleListener(t *testing.T) {
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

	lc := svc.endpoint.ListenerConfigSnapshot()
	if lc.H1 != models.DegenerateHeaderRange(123456789) || lc.H2 != models.DegenerateHeaderRange(234567891) || lc.H3 != models.DegenerateHeaderRange(345678912) || lc.H4 != models.DegenerateHeaderRange(456789123) {
		t.Errorf("listener config not updated on idle service: %+v", lc)
	}
	if lc.S1 != 33 || lc.S2 != 44 || lc.S3 != 55 || lc.S4 != 66 {
		t.Errorf("listener S params not updated on idle service: %+v", lc)
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

	// Mock external detector to fail, testing UDP route/localhost fallback
	origDetector := externalIPDetector
	defer func() { externalIPDetector = origDetector }()
	externalIPDetector = func(ctx context.Context) string {
		return ""
	}

	cfg, _ := svc.GetConfig(ctx)
	cfg.PublicEndpoint = ""
	cfg.ListenPort = 51820
	_ = svc.UpdateConfig(ctx, cfg)

	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, ":51820") {
		t.Errorf("expected endpoint with :51820, got: %s", cfgStr)
	}

	// Verify cached on svc
	svc.publicIPMu.RLock()
	cached := svc.detectedPublicIP
	svc.publicIPMu.RUnlock()
	if cached == "" {
		t.Errorf("expected detectedPublicIP to be cached on Service, but was empty")
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

	// Break persistence: close the database so SaveVPNConfig fails.
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close db: %v", err)
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
	boundSnapshot := svc.endpoint.ListenerConfigSnapshot()

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

	// The running config and the bound listener must be untouched.
	after, _ := svc.GetConfig(ctx)
	if after.ListenPort != before.ListenPort {
		t.Errorf("running config was mutated by rejected update: listen_port %d -> %d", before.ListenPort, after.ListenPort)
	}
	if snap := svc.endpoint.ListenerConfigSnapshot(); snap.ListenPort != boundSnapshot.ListenPort {
		t.Errorf("bound listener port was mutated by rejected update: %d -> %d", boundSnapshot.ListenPort, snap.ListenPort)
	}
	_ = svc.Stop()

	// Once the listener is idle the same change is accepted...
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig after Stop failed: %v", err)
	}
	if snap := svc.endpoint.ListenerConfigSnapshot(); snap.ListenPort != changed.ListenPort {
		t.Errorf("idle listener port not updated: want %d, got %d", changed.ListenPort, snap.ListenPort)
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

	if snap := svc.endpoint.ListenerConfigSnapshot(); snap.ListenPort != 31458 {
		t.Errorf("listener config not updated on idle service: want 31458, got %d", snap.ListenPort)
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
// the port is persisted to the DB config, propagated to the (idle)
// listener, rendered into the client config endpoint, and read back
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

	// The (idle) listener will bind the wired port at Start.
	if snap := svc.endpoint.ListenerConfigSnapshot(); snap.ListenPort != envPort {
		t.Errorf("listener config listen_port: want %d, got %d", envPort, snap.ListenPort)
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

	// The service boots with config and listener in agreement; main.go
	// only calls UpdateConfig when the ports DIFFER, so equality must
	// stay a no-op with the listener snapshot still matching.
	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if snap := svc.endpoint.ListenerConfigSnapshot(); snap.ListenPort != cfgVPN.ListenPort {
		t.Errorf("listener diverges from config without any wiring: cfg=%d listener=%d", cfgVPN.ListenPort, snap.ListenPort)
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
	for _, key := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if strings.Contains(cfgStr, key+" =") || strings.Contains(cfgStr, key+"=") {
			t.Errorf("GenerateClientConfig must not output CPS param %s, config:\n%s", key, cfgStr)
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

func TestStart_RestoresBackendDevicesForActiveTunnels(t *testing.T) {
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

	// Create disabled tunnel for server 2
	tun2 := &models.BackendTunnel{
		ServerID:      s2ID,
		InterfaceName: fmt.Sprintf("awg-be-%d", s2ID),
		PublicKey:     pub2,
		PrivateKey:    priv2,
		Endpoint:      "198.51.100.52:51820",
		Status:        TunnelStatusDisabled,
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

	// Active tunnel 1 should have its backend device restored
	dev1 := svc.GetBackendDeviceForTest(tun1ID)
	if dev1 == nil {
		t.Errorf("expected backend device for active tunnel %d to be restored on Start, got nil", tun1ID)
	}

	// Disabled tunnel 2 should NOT have a backend device attached
	dev2 := svc.GetBackendDeviceForTest(tun2ID)
	if dev2 != nil {
		t.Errorf("expected no backend device for disabled tunnel %d on Start, got %+v", tun2ID, dev2)
	}

	// Active tunnel status remains active
	restoredTun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel 1 failed: %v", err)
	}
	if restoredTun1.Status != TunnelStatusActive {
		t.Errorf("expected tunnel 1 status 'active', got %s", restoredTun1.Status)
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

	// Tunnel status should be marked degraded so it does not report active without a data plane
	tStatus, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tStatus.Status != TunnelStatusDegraded {
		t.Errorf("expected tunnel status 'degraded' after attach failure, got %s", tStatus.Status)
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

func TestStart_RestoresBackendDevicesForDegradedTunnels(t *testing.T) {
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

	// Create DEGRADED tunnel
	now := time.Now().UTC()
	tun := &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: fmt.Sprintf("awg-be-%d", sID),
		PublicKey:     pub,
		PrivateKey:    priv,
		Endpoint:      "198.51.100.77:51820",
		Status:        TunnelStatusDegraded,
		CreatedAt:     now,
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
	var probeShouldSucceed atomic.Bool
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if !probeShouldSucceed.Load() {
			return 0, errors.New("probe temporarily disabled during startup")
		}
		return 10 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Degraded tunnel should have its backend device restored
	dev := svc.GetBackendDeviceForTest(tunID)
	if dev == nil {
		t.Fatalf("expected backend device for degraded tunnel %d to be restored on Start, got nil", tunID)
	}
	if dev.IsClosed() {
		t.Error("expected restored device to be open")
	}

	// Tunnel status should remain degraded before probe
	restoredTun, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if restoredTun.Status != TunnelStatusDegraded {
		t.Errorf("expected tunnel status to remain 'degraded' before probe, got %s", restoredTun.Status)
	}

	// Probe the tunnel - now succeeds and transitions to active
	probeShouldSucceed.Store(true)
	rtt, err := svc.ProbeTunnel(ctx, restoredTun)
	if err != nil {
		t.Fatalf("ProbeTunnel failed: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("expected positive rtt, got %d", rtt)
	}

	probedTun, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if probedTun.Status != TunnelStatusActive {
		t.Errorf("expected tunnel status to become 'active' after probe, got %s", probedTun.Status)
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
	for _, key := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if strings.Contains(cfgStr, key+" =") || strings.Contains(cfgStr, key+"=") {
			t.Errorf("Load Balancer client config must not contain %s, got:\n%s", key, cfgStr)
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

func TestGenerateClientConfig_ListenerKeyAgreement_ObfuscatedHandshake(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

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

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "client_bob",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	clientHPKeyStr := parseDirectiveString(t, cfgStr, "HeaderProtectionKey")
	listenerSnapshot := svc.endpoint.ListenerConfigSnapshot()
	if clientHPKeyStr == "" {
		t.Fatalf("client config missing HeaderProtectionKey")
	}
	if clientHPKeyStr != listenerSnapshot.HeaderProtectionKey {
		t.Fatalf("key disagreement: client rendered %q, listener snapshot has %q", clientHPKeyStr, listenerSnapshot.HeaderProtectionKey)
	}

	hpKeyBytes, err := health.DecodeKey(clientHPKeyStr)
	if err != nil {
		t.Fatalf("failed to decode client HP key: %v", err)
	}

	// Parse server public key from [Peer] section
	peerPubKeyStr := parseDirectiveString(t, cfgStr, "PublicKey")
	peerPubBytes, err := base64.StdEncoding.DecodeString(peerPubKeyStr)
	if err != nil {
		t.Fatalf("failed to decode server public key: %v", err)
	}

	// Parse client private key from [Interface] section
	clientPrivKeyStr := parseDirectiveString(t, cfgStr, "PrivateKey")
	clientPrivBytes, err := base64.StdEncoding.DecodeString(clientPrivKeyStr)
	if err != nil {
		t.Fatalf("failed to decode client private key: %v", err)
	}

	h1 := parseDirectiveString(t, cfgStr, "H1")
	s1 := parseDirectiveInt(t, cfgStr, "S1")
	h2 := parseDirectiveString(t, cfgStr, "H2")
	s2 := parseDirectiveInt(t, cfgStr, "S2")

	// Construct obfuscated initiation with the client config parameters
	packet, state, err := health.BuildAWGInitiationPacketObfuscated(peerPubBytes, clientPrivBytes, nil, hpKeyBytes, h1, s1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated failed: %v", err)
	}

	serverAddr, ok := svc.endpoint.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T, want *net.UDPAddr", svc.endpoint.GetListenAddr())
	}

	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write(packet); err != nil {
		t.Fatalf("failed to send initiation: %v", err)
	}

	respBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("handshake failed: no response from listener: %v", err)
	}

	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n], state, hpKeyBytes, h2, s2) {
		t.Errorf("VerifyAWGResponsePacketObfuscated rejected listener's handshake response")
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
	sess, _, err := vpnSvc2.HandleIncomingPeer(ctx, clientPub)
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

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
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
		ServerID: s1ID,
		Protocol: "awg",
		ClientID: peerKeyBob,
		Name:     "bob-device",
	}
	if _, err := db.CreateConnection(ctx, bobConn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	sessBob, _, err := vpnSvc.HandleIncomingPeer(ctx, peerKeyBob)
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

	// 2. Peer with assigned_ip colliding with stale lease in IPAM:
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
		ServerID: s1ID,
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

	// HandleIncomingPeer for Charlie must detect collision, release stale allocation, and reserve targetIP for Charlie
	sessCharlie, _, err := vpnSvc.HandleIncomingPeer(ctx, peerKeyCharlie)
	if err != nil {
		t.Fatalf("HandleIncomingPeer for charlie failed on collision: %v", err)
	}
	if sessCharlie.AssignedIP != targetIP {
		t.Fatalf("expected charlie to receive %s after resolving collision, got %s", targetIP, sessCharlie.AssignedIP)
	}
}

func TestService_HeaderRangeHandshake_AndPerPacketTypeAcceptance(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	hpKeyB64 := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	vpnCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          port,
		SubnetCIDR:          "10.100.0.0/24",
		H1:                  models.NewHeaderRange(1000000, 1005000),
		H2:                  models.NewHeaderRange(2000000, 2005000),
		H3:                  models.NewHeaderRange(3000000, 3005000),
		H4:                  models.NewHeaderRange(4000000, 4005000),
		S1:                  50,
		S2:                  60,
		S3:                  30,
		S4:                  20,
		HeaderProtectionKey: hpKeyB64,
	}
	if err := db.SaveVPNConfig(ctx, vpnCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	// Backend server setup
	sID, err := db.CreateServer(ctx, &models.Server{Name: "US Backend", Host: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-range",
		PublicKey:     "dummy-be-pubkey-123456789012345678",
		PrivateKey:    "dummy-be-privkey-1234567890123456",
		Endpoint:      "127.0.0.1:51825",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})
	if err := vpnSvc.Start(ctx); err != nil {
		t.Fatalf("vpnSvc.Start failed: %v", err)
	}
	defer func() { _ = vpnSvc.Stop() }()

	// Client credentials
	clientPrivBytes := make([]byte, 32)
	if _, err := rand.Read(clientPrivBytes); err != nil {
		t.Fatalf("rand failed: %v", err)
	}
	clientPubBytes, err := curve25519.X25519(clientPrivBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519 failed: %v", err)
	}
	clientPubB64 := base64.StdEncoding.EncodeToString(clientPubBytes)

	uID, err := db.CreateUser(ctx, &models.User{Username: "range_client", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: sID,
		Protocol: "awg",
		ClientID: clientPubB64,
		Name:     "device-range",
	}); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	snap := vpnSvc.endpoint.ListenerConfigSnapshot()
	liveCfg, err := vpnSvc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	serverPubB64 := liveCfg.ServerPublicKey
	serverPubBytes, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil {
		t.Fatalf("DecodeString serverPub failed: %v", err)
	}

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	hpKeyBytes, _ := health.DecodeKey(hpKeyB64)

	// Test 1: Initiation with msgType outside H1 range must be rejected
	badH1 := uint32(999999)
	badInit, _, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, badH1, snap.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated badH1 failed: %v", err)
	}
	if _, err := clientConn.Write(badInit); err != nil {
		t.Fatalf("Write badInit failed: %v", err)
	}
	respBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := clientConn.Read(respBuf); err == nil {
		t.Fatal("expected no response for out-of-range H1 initiation, but got response")
	}

	// Test 2: Initiation with msgType within H1 range [1000000, 1005000] must succeed
	validH1 := uint32(1002500)
	validInit, state, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, validH1, snap.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated validH1 failed: %v", err)
	}
	if _, err := clientConn.Write(validInit); err != nil {
		t.Fatalf("Write validInit failed: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("Read handshake response failed: %v", err)
	}

	// Verify server response packet matches H2 range
	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n], state, hpKeyBytes, snap.H2, snap.S2) {
		t.Fatal("VerifyAWGResponsePacketObfuscated rejected server response for H2 range")
	}

	// Test 3: Transport framing per-packet acceptance
	routedCh := make(chan []byte, 10)
	vpnSvc.endpoint.SetClientPacketRouter(func(peerKey string, pkt []byte) error {
		if peerKey == clientPubB64 {
			routedCh <- pkt
		}
		return nil
	})

	// Derive session keys
	respPayload := respBuf[snap.S2:n]
	cipResp := health.NewHeaderProtectionCipher(hpKeyBytes, respBuf[:health.HeaderCipherNonceSize])
	unmaskedResp := make([]byte, 92)
	cipResp.XORKeyStream(unmaskedResp, respPayload[:92])
	serverReceiverIdx := unmaskedResp[4:8]
	serverEPub := unmaskedResp[12:44]

	ss3, err := curve25519.X25519(state.ClientEPriv, serverEPub)
	if err != nil {
		t.Fatalf("ss3 failed: %v", err)
	}
	ck := health.KDF1(health.KDF1(state.CK, serverEPub), ss3)
	ss4, err := curve25519.X25519(state.ClientPriv, serverEPub)
	if err != nil {
		t.Fatalf("ss4 failed: %v", err)
	}
	ck = health.KDF1(ck, ss4)
	ck, _, _ = health.KDF3(ck, make([]byte, 32))
	clientSendKey, _ := health.KDF2(ck, nil)

	aeadSend, err := chacha20poly1305.New(clientSendKey)
	if err != nil {
		t.Fatalf("aeadSend failed: %v", err)
	}

	// 3a. Send datagram with msgType = 4001234 (within H4 range [4000000, 4005000])
	s4 := snap.S4
	frameLen := s4 + 16
	datagram1 := make([]byte, frameLen)
	_, _ = rand.Read(datagram1[:s4])
	binary.LittleEndian.PutUint32(datagram1[s4:s4+4], 4001234)
	copy(datagram1[s4+4:s4+8], serverReceiverIdx)
	binary.LittleEndian.PutUint64(datagram1[s4+8:s4+16], 0)
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], 0)
	payload1 := []byte("packet-within-h4-range")
	datagram1 = aeadSend.Seal(datagram1, nonce[:], payload1, nil)
	// Apply header protection
	cipData := health.NewHeaderProtectionCipher(hpKeyBytes, datagram1[:health.HeaderCipherNonceSize])
	cipData.XORKeyStream(datagram1[s4:s4+16], datagram1[s4:s4+16])

	if _, err := clientConn.Write(datagram1); err != nil {
		t.Fatalf("Write datagram1 failed: %v", err)
	}

	select {
	case received := <-routedCh:
		if !bytes.Equal(received, payload1) {
			t.Fatalf("routed mismatch: got %q, want %q", received, payload1)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid H4 transport packet to be accepted")
	}

	// 3b. Send datagram with msgType = 5000000 (OUTSIDE H4 range)
	datagramBad := make([]byte, frameLen)
	_, _ = rand.Read(datagramBad[:s4])
	binary.LittleEndian.PutUint32(datagramBad[s4:s4+4], 5000000)
	copy(datagramBad[s4+4:s4+8], serverReceiverIdx)
	binary.LittleEndian.PutUint64(datagramBad[s4+8:s4+16], 1)
	binary.LittleEndian.PutUint64(nonce[4:12], 1)
	payloadBad := []byte("packet-outside-h4-range")
	datagramBad = aeadSend.Seal(datagramBad, nonce[:], payloadBad, nil)
	cipBad := health.NewHeaderProtectionCipher(hpKeyBytes, datagramBad[:health.HeaderCipherNonceSize])
	cipBad.XORKeyStream(datagramBad[s4:s4+16], datagramBad[s4:s4+16])

	if _, err := clientConn.Write(datagramBad); err != nil {
		t.Fatalf("Write datagramBad failed: %v", err)
	}

	select {
	case received := <-routedCh:
		t.Fatalf("out-of-range H4 packet was unexpectedly accepted: %q", received)
	case <-time.After(300 * time.Millisecond):
		// Expected: dropped!
	}

	// Test 4: SendToPeer per-packet type randomization
	observedH4 := make(map[uint32]bool)
	for i := 0; i < 15; i++ {
		msg := []byte(fmt.Sprintf("probe-send-to-peer-%d", i))
		if err := vpnSvc.endpoint.SendToPeer(clientPubB64, msg); err != nil {
			t.Fatalf("SendToPeer failed on iteration %d: %v", i, err)
		}
		buf := make([]byte, 2048)
		_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		nRecv, err := clientConn.Read(buf)
		if err != nil {
			t.Fatalf("Read SendToPeer %d failed: %v", i, err)
		}
		packet := buf[:nRecv]
		cipOut := health.NewHeaderProtectionCipher(hpKeyBytes, packet[:health.HeaderCipherNonceSize])
		unmasked := make([]byte, 16)
		cipOut.XORKeyStream(unmasked, packet[s4:s4+16])
		msgType := binary.LittleEndian.Uint32(unmasked[0:4])

		if !snap.H4.Contains(msgType) {
			t.Fatalf("SendToPeer emitted msgType %d outside H4 range %s", msgType, snap.H4)
		}
		observedH4[msgType] = true
	}

	if len(observedH4) < 2 {
		t.Errorf("expected per-packet H4 randomization across 15 sends, but observed only %d distinct types", len(observedH4))
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
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

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

	// 5. Listener Compatibility: verify listener accepts both legacy single value AND new range values
	lc := svc.endpoint.ListenerConfigSnapshot()
	if lc.H1 != upgradedCfg.H1 {
		t.Fatalf("listener snapshot H1 %s does not match upgraded %s", lc.H1, upgradedCfg.H1)
	}

	hpKeyBytes, err := health.DecodeKey(existingHPKey)
	if err != nil {
		t.Fatalf("DecodeKey failed: %v", err)
	}
	peerPubKeyStr := parseDirectiveString(t, cfgStr, "PublicKey")
	peerPubBytes, _ := base64.StdEncoding.DecodeString(peerPubKeyStr)
	clientPrivKeyStr := parseDirectiveString(t, cfgStr, "PrivateKey")
	clientPrivBytes, _ := base64.StdEncoding.DecodeString(clientPrivKeyStr)

	// Send handshake using legacy single value (359398951)
	legacyPkt, state1, err := health.BuildAWGInitiationPacketObfuscated(peerPubBytes, clientPrivBytes, nil, hpKeyBytes, legacyH1, upgradedCfg.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated legacy failed: %v", err)
	}

	serverAddr := svc.endpoint.GetListenAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write(legacyPkt); err != nil {
		t.Fatalf("failed to send legacy initiation: %v", err)
	}
	respBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("legacy client handshake failed: listener did not respond: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n], state1, hpKeyBytes, upgradedCfg.H2, upgradedCfg.S2) {
		t.Errorf("response verification failed for legacy client")
	}

	// Send handshake using a random value picked within the upgraded range
	pickedH1 := upgradedCfg.H1.PickOne()
	newPkt, state2, err := health.BuildAWGInitiationPacketObfuscated(peerPubBytes, clientPrivBytes, nil, hpKeyBytes, pickedH1, upgradedCfg.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated range failed: %v", err)
	}
	if _, err := clientConn.Write(newPkt); err != nil {
		t.Fatalf("failed to send range initiation: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n2, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("range client handshake failed: listener did not respond: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n2], state2, hpKeyBytes, upgradedCfg.H2, upgradedCfg.S2) {
		t.Errorf("response verification failed for range client")
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
