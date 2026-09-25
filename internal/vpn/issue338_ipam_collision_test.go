package vpn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
)

func TestStartupIPAMCollision_ResolvesDuplicateAndSelfHeals(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// 1. Create Portal Server 0 backend tunnels
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pubkey-338",
		PrivateKey:    "tunnel-privkey-338",
		Endpoint:      "192.0.2.10:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	user1ID, err := db.CreateUser(ctx, &models.User{Username: "client-one", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	user2ID, err := db.CreateUser(ctx, &models.User{Username: "client-two", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const sharedIP = "10.100.0.3"
	peerKey1 := "client-one-peer-key"
	peerKey2 := "client-two-peer-key"

	// Connection 1 has sharedIP
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-peer-1",
		UserID:       user1ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerKey1,
		ClientParams: map[string]any{"assigned_ip": sharedIP},
		CreatedAt:    now.Add(1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Connection 2 has the exact same sharedIP with different peer key (reproducing Issue #338 production collision)
	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-peer-2",
		UserID:       user2ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerKey2,
		ClientParams: map[string]any{"assigned_ip": sharedIP},
		CreatedAt:    now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

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
	}

	// NewVPNService must succeed cleanly without crash loop
	svc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService failed on duplicate assigned_ip collision: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Assert first connection retains sharedIP in IPAM
	assigned1, ok := svc.ipam.GetAssignedIP(peerKey1)
	if !ok || assigned1.String() != sharedIP {
		t.Fatalf("first connection peer %s lost its IP in IPAM: got %v, want %s", peerKey1, assigned1, sharedIP)
	}

	// Assert second connection's conflicting assigned_ip is cleared in SQLite
	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatalf("get connection 2: %v", err)
	}
	if conn2.ClientParams != nil && conn2.ClientParams["assigned_ip"] != nil && conn2.ClientParams["assigned_ip"] != "" {
		t.Fatalf("expected conn2 conflicting assigned_ip to be cleared in SQLite, got: %v", conn2.ClientParams["assigned_ip"])
	}

	// Assert generating config for second client allocates a fresh unique IP
	newConfig, _, err := svc.GenerateClientConfig(ctx, user2ID)
	if err != nil {
		t.Fatalf("GenerateClientConfig for second connection failed: %v", err)
	}
	newIP := extractAddressFromConfig(t, newConfig)
	if newIP == "" {
		t.Fatal("GenerateClientConfig returned empty IP address")
	}
	if newIP == sharedIP {
		t.Fatalf("second connection reused colliding IP %s instead of allocating fresh IP", sharedIP)
	}

	// Verify new IP is persisted in SQLite for second connection
	conn2Updated, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatalf("get updated connection 2: %v", err)
	}
	if conn2Updated.ClientParams == nil || conn2Updated.ClientParams["assigned_ip"] != newIP {
		t.Fatalf("new IP %s was not persisted for conn2: %+v", newIP, conn2Updated.ClientParams)
	}

	// Verify first connection is unchanged
	conn1, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatalf("get connection 1: %v", err)
	}
	if conn1.ClientParams == nil || conn1.ClientParams["assigned_ip"] != sharedIP {
		t.Fatalf("conn1 lost its persisted IP: %+v", conn1.ClientParams)
	}
}

func TestStartupIPAMCollision_ConnectingAllocatesFreshIP(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pubkey-338b",
		PrivateKey:    "tunnel-privkey-338b",
		Endpoint:      "192.0.2.10:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	user1ID, err := db.CreateUser(ctx, &models.User{Username: "client-one-b", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	user2ID, err := db.CreateUser(ctx, &models.User{Username: "client-two-b", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const sharedIP = "10.100.0.3"
	peerKey1 := "client-one-peer-key-b"
	peerKey2 := "client-two-peer-key-b"

	// Conn1 has sharedIP
	_, err = db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-peer-1-b",
		UserID:       user1ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerKey1,
		ClientParams: map[string]any{"assigned_ip": sharedIP},
		CreatedAt:    now.Add(1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Conn2 has the same sharedIP
	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-peer-2-b",
		UserID:       user2ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerKey2,
		ClientParams: map[string]any{"assigned_ip": sharedIP},
		CreatedAt:    now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
	}

	svc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Connecting peer 2 via HandleIncomingPeer directly
	sess, _, err := svc.HandleIncomingPeer(ctx, peerKey2)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for second peer: %v", err)
	}
	if sess.AssignedIP == "" || sess.AssignedIP == sharedIP {
		t.Fatalf("expected fresh assigned IP, got: %s (sharedIP was %s)", sess.AssignedIP, sharedIP)
	}

	// Verify the allocated fresh IP is persisted for conn2 in SQLite
	conn2Updated, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2Updated.ClientParams == nil || conn2Updated.ClientParams["assigned_ip"] != sess.AssignedIP {
		t.Fatalf("persisted assigned_ip mismatch: got %v, want %s", conn2Updated.ClientParams["assigned_ip"], sess.AssignedIP)
	}
}

func TestReservePersistedClientIPs_IPAlreadyAllocated(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	// Pre-allocate 10.100.0.5 in IPAM to peer-existing
	targetIP := net.ParseIP("10.100.0.5")
	if err := ipam.Reserve(targetIP, "peer-existing"); err != nil {
		t.Fatal(err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "user-collide", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	// DB contains connection for peer-new claiming the same 10.100.0.5
	connID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-collide-1",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-new",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.5"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// reservePersistedClientIPs must succeed without error
	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// peer-existing must retain 10.100.0.5 in IPAM
	assigned, ok := ipam.GetAssignedIP("peer-existing")
	if !ok || !assigned.Equal(targetIP) {
		t.Fatalf("peer-existing lost IP: got %v, want %s", assigned, targetIP)
	}

	// conn-collide-1 must have assigned_ip cleared in SQLite
	conn, err := db.GetConnection(ctx, connID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ClientParams != nil && conn.ClientParams["assigned_ip"] != nil && conn.ClientParams["assigned_ip"] != "" {
		t.Fatalf("expected assigned_ip cleared from SQLite, got: %v", conn.ClientParams["assigned_ip"])
	}
}

func TestReservePersistedClientIPs_PeerAddressMismatch(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	// IPAM already has 10.100.0.2 for peer-mismatch
	currentIP := net.ParseIP("10.100.0.2")
	if err := ipam.Reserve(currentIP, "peer-mismatch"); err != nil {
		t.Fatal(err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "user-mismatch", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	// DB contains connection for peer-mismatch claiming 10.100.0.8
	connID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-mismatch-1",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-mismatch",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.8"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// reservePersistedClientIPs must succeed without error
	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// IPAM must retain currentIP (10.100.0.2) for peer-mismatch
	assigned, ok := ipam.GetAssignedIP("peer-mismatch")
	if !ok || !assigned.Equal(currentIP) {
		t.Fatalf("peer-mismatch lost IP in IPAM: got %v, want %s", assigned, currentIP)
	}

	// Conflicting 10.100.0.8 must be cleared in SQLite
	conn, err := db.GetConnection(ctx, connID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ClientParams != nil && conn.ClientParams["assigned_ip"] != nil && conn.ClientParams["assigned_ip"] != "" {
		t.Fatalf("expected conflicting assigned_ip cleared from SQLite, got: %v", conn.ClientParams["assigned_ip"])
	}
}
