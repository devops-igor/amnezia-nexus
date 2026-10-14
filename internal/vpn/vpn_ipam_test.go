package vpn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
)

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
