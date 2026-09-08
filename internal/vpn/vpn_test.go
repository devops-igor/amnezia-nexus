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
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/endpoint"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/loadbalancer"
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

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
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
	if !strings.Contains(cfgStr, "Jc =") || !strings.Contains(cfgStr, "S1 =") || !strings.Contains(cfgStr, "H1 =") {
		t.Errorf("expected AWG obfuscation parameters in config: %s", cfgStr)
	}
	if strings.Contains(cfgStr, "Endpoint = 198.51.100.1:") {
		t.Errorf("client config must NEVER use backend server endpoint, got: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, "Endpoint = ") {
		t.Errorf("expected Endpoint directive in config: %s", cfgStr)
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
}

func (m *mockAWGManagerWithClientAdder) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return m.status, m.statusErr
}

func (m *mockAWGManagerWithClientAdder) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	m.addClientCalls++
	m.addedClients = append(m.addedClients, clientParams)
	if m.addClientErr != nil {
		return nil, m.addClientErr
	}
	return map[string]any{"client_id": clientParams["client_public_key"]}, nil
}

// TestEnableBackend_RegistersProberPeerOnBackend asserts the WIRING only:
// EnableBackend passes the tunnel-derived prober pubkey to AddClient. It uses
// a MOCK AddClient, so it cannot verify what the real manager does with those
// params (round-2 review: a mock asserting its own inputs is a false positive).
// The real-path coverage — [Peer] PublicKey == caller-supplied key, no
// PresharedKey, idempotent re-registration — lives in
// awg_probe_rework_test.go (TestAWGManager_AddClient_ProbePeerUsesCallerKey_R3),
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

	if adder.addClientCalls != 1 {
		t.Fatalf("expected 1 AddClient call, got %d", adder.addClientCalls)
	}
	if len(adder.addedClients) != 1 {
		t.Fatalf("expected 1 added client, got %d", len(adder.addedClients))
	}
	clientParams := adder.addedClients[0]
	if clientParams["clientName"] != "Health Probe" {
		t.Errorf("expected clientName 'Health Probe', got: %v", clientParams["clientName"])
	}
	proberPub, ok := clientParams["client_public_key"].(string)
	if !ok || len(proberPub) == 0 {
		t.Fatalf("missing or empty client_public_key in clientParams: %+v", clientParams)
	}

	// Verify proberPub matches the tunnel's PrivateKey derived public key
	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	derivedPub, err := health.ComputePublicKeyFromPrivate(tun.PrivateKey)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate failed: %v", err)
	}
	if proberPub != derivedPub {
		t.Errorf("registered prober public key %s does not match tunnel derived pubkey %s", proberPub, derivedPub)
	}
}

func TestEnableBackend_AddClientErrorDoesNotBlockEnable(t *testing.T) {
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

	// EnableBackend should log a warning and proceed without failing
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend should succeed even when AddClient fails, got: %v", err)
	}

	if adder.addClientCalls != 1 {
		t.Errorf("expected 1 AddClient call attempt, got %d", adder.addClientCalls)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil || tun == nil || tun.Status != "active" {
		t.Errorf("expected active tunnel in pool, got %+v (err=%v)", tun, err)
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
		Algorithm:  models.LBLeastConnections,
		ListenPort: port,
		SubnetCIDR: "10.100.0.0/24",
		H1:         12345678,
		H2:         23456789,
		H3:         34567890,
		H4:         45678901,
		S1:         45,
		S2:         60,
		S3:         25,
		S4:         15,
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
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
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
	if !strings.Contains(cfgStr, "H1 = 12345678") ||
		!strings.Contains(cfgStr, "H2 = 23456789") ||
		!strings.Contains(cfgStr, "H4 = 45678901") ||
		!strings.Contains(cfgStr, "S1 = 45") ||
		!strings.Contains(cfgStr, "S2 = 60") {
		t.Fatalf("GenerateClientConfig did not render stored VPNConfig values: %s", cfgStr)
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
	binary.LittleEndian.PutUint32(transportDatagram[s4:s4+4], vpnCfg.H4)
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
	msgType := binary.LittleEndian.Uint32(replyPayloadPart[0:4])
	if msgType != vpnCfg.H4 {
		t.Fatalf("SendToPeer msgType mismatch: got %d, want %d", msgType, vpnCfg.H4)
	}
	counter := binary.LittleEndian.Uint64(replyPayloadPart[8:16])
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
		Algorithm:          models.LBLeastConnections,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
		H1:                 111111,
		H2:                 222222,
		H3:                 333333,
		H4:                 444444,
		S1:                 40,
		S2:                 50,
		S3:                 30,
		S4:                 20,
		ServerPrivateKey:   "kept-priv",
		ServerPublicKey:    "kept-pub",
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
	if svcCfg.H1 != 111111 || svcCfg.H2 != 222222 || svcCfg.H3 != 333333 || svcCfg.H4 != 444444 {
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
	if stored.H1 != 111111 || stored.H2 != 222222 || stored.H3 != 333333 || stored.H4 != 444444 {
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
	if lc.H1 != 111111 || lc.S1 != 40 || lc.H4 != 444444 || lc.S4 != 20 {
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
	changed.H1 = 987654321
	changed.S1 = 77
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("expected error when changing obfuscation params while listener runs")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected immutability error, got: %v", err)
	}

	after, _ := svc.GetConfig(ctx)
	if after.H1 != before.H1 {
		t.Errorf("running config was mutated by rejected update: H1 %d -> %d", before.H1, after.H1)
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
	changed.H1 = 123456789
	changed.H2 = 234567891
	changed.H3 = 345678912
	changed.H4 = 456789123
	changed.S1 = 33
	changed.S2 = 44
	changed.S3 = 55
	changed.S4 = 66
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig with changed H/S on idle service failed: %v", err)
	}

	lc := svc.endpoint.ListenerConfigSnapshot()
	if lc.H1 != 123456789 || lc.H2 != 234567891 || lc.H3 != 345678912 || lc.H4 != 456789123 {
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
	results := make(chan uint32, goroutines)
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

	var h1s []uint32
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
		t.Errorf("persisted H1 %d does not match service H1 %d", persisted.H1, h1s[0])
	}
	if persisted.H1 == 0 {
		t.Error("expected persisted H1 to be generated (non-zero)")
	}
}
