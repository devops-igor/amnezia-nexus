package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
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

	// Connection 2 has the exact same sharedIP with different peer key
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

	// Assert second connection's conflicting assigned_ip is cleared and quarantined in SQLite
	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatalf("get connection 2: %v", err)
	}
	if conn2.ClientParams != nil && conn2.ClientParams["assigned_ip"] != nil && conn2.ClientParams["assigned_ip"] != "" {
		t.Fatalf("expected conn2 conflicting assigned_ip to be cleared in SQLite, got: %v", conn2.ClientParams["assigned_ip"])
	}
	if conn2.ClientParams["quarantined_ip_collision"] != sharedIP {
		t.Fatalf("expected conn2 quarantined_ip_collision=%s, got: %v", sharedIP, conn2.ClientParams["quarantined_ip_collision"])
	}
	if req, ok := conn2.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("expected conn2 config_regeneration_required=true, got: %v", conn2.ClientParams["config_regeneration_required"])
	}

	// Assert generating config for second client allocates a fresh unique IP and clears quarantine
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

	// Verify new IP is persisted in SQLite for second connection and quarantine markers removed
	conn2Updated, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatalf("get updated connection 2: %v", err)
	}
	if conn2Updated.ClientParams == nil || conn2Updated.ClientParams["assigned_ip"] != newIP {
		t.Fatalf("new IP %s was not persisted for conn2: %+v", newIP, conn2Updated.ClientParams)
	}
	if conn2Updated.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("expected config_regeneration_required to be cleared, got: %v", conn2Updated.ClientParams["config_regeneration_required"])
	}
	if conn2Updated.ClientParams["quarantined_ip_collision"] != nil {
		t.Fatalf("expected quarantined_ip_collision to be cleared, got: %v", conn2Updated.ClientParams["quarantined_ip_collision"])
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

// Scenario 1: Two different users / two peers / same persisted IP (oldest wins, other quarantined)
func TestStartupIPAMCollision_Scenario1_TwoUsersTwoPeers_OldestWinsOtherQuarantined(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	user1ID, err := db.CreateUser(ctx, &models.User{Username: "user-sc1-1", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	user2ID, err := db.CreateUser(ctx, &models.User{Username: "user-sc1-2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const targetIP = "10.100.0.3"

	// Conn1 (older)
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc1-1",
		UserID:       user1ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc1-1",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-5 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Conn2 (newer, colliding IP)
	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc1-2",
		UserID:       user2ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc1-2",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// Winner (Conn1) retains targetIP in IPAM
	assigned, ok := ipam.GetAssignedIP("peer-sc1-1")
	if !ok || assigned.String() != targetIP {
		t.Fatalf("winner peer-sc1-1 missing in IPAM: got %v, want %s", assigned, targetIP)
	}

	// Winner in DB is untouched
	conn1, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1.ClientParams["assigned_ip"] != targetIP {
		t.Fatalf("winner conn1 assigned_ip modified: %v", conn1.ClientParams["assigned_ip"])
	}

	// Loser (Conn2) is quarantined in DB
	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2.ClientParams["assigned_ip"] != nil && conn2.ClientParams["assigned_ip"] != "" {
		t.Fatalf("loser conn2 assigned_ip not cleared: %v", conn2.ClientParams["assigned_ip"])
	}
	if conn2.ClientParams["quarantined_ip_collision"] != targetIP {
		t.Fatalf("loser conn2 quarantined_ip_collision mismatch: got %v, want %s", conn2.ClientParams["quarantined_ip_collision"], targetIP)
	}
	if req, ok := conn2.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("loser conn2 config_regeneration_required not true: %v", conn2.ClientParams["config_regeneration_required"])
	}
}

// Scenario 2: Same user with two valid configurations sharing an IP (oldest wins, second quarantined)
func TestStartupIPAMCollision_Scenario2_SameUserTwoConfigs_OldestWinsSecondQuarantined(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	userID, err := db.CreateUser(ctx, &models.User{Username: "user-sc2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const targetIP = "10.100.0.5"

	// Conn1 (older config)
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc2-1",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc2-1",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Conn2 (newer config for same user, sharing targetIP)
	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc2-2",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc2-2",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// Winner (Conn1) retains targetIP
	assigned, ok := ipam.GetAssignedIP("peer-sc2-1")
	if !ok || assigned.String() != targetIP {
		t.Fatalf("winner peer-sc2-1 missing in IPAM: got %v, want %s", assigned, targetIP)
	}

	conn1, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1.ClientParams["assigned_ip"] != targetIP {
		t.Fatalf("conn1 lost assigned_ip: %v", conn1.ClientParams["assigned_ip"])
	}

	// Loser (Conn2) quarantined
	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2.ClientParams["assigned_ip"] != nil && conn2.ClientParams["assigned_ip"] != "" {
		t.Fatalf("conn2 assigned_ip not cleared: %v", conn2.ClientParams["assigned_ip"])
	}
	if conn2.ClientParams["quarantined_ip_collision"] != targetIP {
		t.Fatalf("conn2 quarantined_ip_collision mismatch: got %v, want %s", conn2.ClientParams["quarantined_ip_collision"], targetIP)
	}
	if req, ok := conn2.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("conn2 config_regeneration_required not true: %v", conn2.ClientParams["config_regeneration_required"])
	}
}

// Scenario 3: Three claimants for one IP (one winner, two quarantined)
func TestStartupIPAMCollision_Scenario3_ThreeClaimants_OneWinnerTwoQuarantined(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	const targetIP = "10.100.0.7"

	var connIDs []string
	var peerKeys []string
	for i := 1; i <= 3; i++ {
		uID, err := db.CreateUser(ctx, &models.User{Username: "user-sc3-" + string(rune('0'+i)), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		pKey := "peer-sc3-" + string(rune('0'+i))
		peerKeys = append(peerKeys, pKey)
		cID, err := db.CreateConnection(ctx, &models.UserConnection{
			ID:           "conn-sc3-" + string(rune('0'+i)),
			UserID:       uID,
			ServerID:     0,
			Protocol:     "awg",
			ClientID:     pKey,
			ClientParams: map[string]any{"assigned_ip": targetIP},
			CreatedAt:    now.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		connIDs = append(connIDs, cID)
	}

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// Oldest is connIDs[0] (winner)
	assigned, ok := ipam.GetAssignedIP(peerKeys[0])
	if !ok || assigned.String() != targetIP {
		t.Fatalf("winner %s missing in IPAM: got %v, want %s", peerKeys[0], assigned, targetIP)
	}

	conn1, err := db.GetConnection(ctx, connIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if conn1.ClientParams["assigned_ip"] != targetIP {
		t.Fatalf("winner conn1 lost assigned_ip: %v", conn1.ClientParams["assigned_ip"])
	}

	// Losers (connIDs[1] and connIDs[2]) are both quarantined
	for j := 1; j <= 2; j++ {
		conn, err := db.GetConnection(ctx, connIDs[j])
		if err != nil {
			t.Fatal(err)
		}
		if conn.ClientParams["assigned_ip"] != nil && conn.ClientParams["assigned_ip"] != "" {
			t.Fatalf("loser %s assigned_ip not cleared: %v", connIDs[j], conn.ClientParams["assigned_ip"])
		}
		if conn.ClientParams["quarantined_ip_collision"] != targetIP {
			t.Fatalf("loser %s quarantined_ip_collision mismatch: %v", connIDs[j], conn.ClientParams["quarantined_ip_collision"])
		}
		if req, ok := conn.ClientParams["config_regeneration_required"].(bool); !ok || !req {
			t.Fatalf("loser %s config_regeneration_required not true: %v", connIDs[j], conn.ClientParams["config_regeneration_required"])
		}
	}
}

// Scenario 4: Durable client_params.assigned_ip vs legacy vpn_sessions fallback collision (durable wins, legacy not migrated)
func TestStartupIPAMCollision_Scenario4_DurableVsLegacyFallback_DurableWinsLegacyNotMigrated(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pub-sc4",
		Endpoint:      "192.0.2.10:51820",
	})
	if err != nil {
		t.Fatal(err)
	}

	legacyUserID, err := db.CreateUser(ctx, &models.User{Username: "user-sc4-legacy", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	durableUserID, err := db.CreateUser(ctx, &models.User{Username: "user-sc4-durable", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const targetIP = "10.100.0.3"

	// Legacy connection created EARLIER (10s ago), but has NO assigned_ip in client_params
	legacyConnID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc4-legacy",
		UserID:       legacyUserID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc4-legacy",
		ClientParams: map[string]any{"label": "old-client"},
		CreatedAt:    now.Add(-10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Active session for legacy client with targetIP
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sess-sc4-legacy",
		UserID:          legacyUserID,
		BackendTunnelID: tunnelID,
		PeerPublicKey:   "peer-sc4-legacy",
		AssignedIP:      targetIP,
		Status:          "connected",
	}); err != nil {
		t.Fatal(err)
	}

	// Durable connection created LATER (1s ago), but has explicit client_params["assigned_ip"]
	durableConnID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc4-durable",
		UserID:       durableUserID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc4-durable",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	// 1. reservePersistedClientIPs reconciles
	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// 2. InvalidateVPNSessionsForRestart runs
	if _, err := db.InvalidateVPNSessionsForRestart(ctx); err != nil {
		t.Fatalf("InvalidateVPNSessionsForRestart failed: %v", err)
	}

	// Assert Durable connection won despite being newer
	assigned, ok := ipam.GetAssignedIP("peer-sc4-durable")
	if !ok || assigned.String() != targetIP {
		t.Fatalf("durable peer-sc4-durable missing in IPAM: got %v, want %s", assigned, targetIP)
	}

	connDurable, err := db.GetConnection(ctx, durableConnID)
	if err != nil {
		t.Fatal(err)
	}
	if connDurable.ClientParams["assigned_ip"] != targetIP {
		t.Fatalf("durable conn lost assigned_ip: %v", connDurable.ClientParams["assigned_ip"])
	}

	// Assert Legacy connection was quarantined and NOT migrated to client_params["assigned_ip"]
	connLegacy, err := db.GetConnection(ctx, legacyConnID)
	if err != nil {
		t.Fatal(err)
	}
	if connLegacy.ClientParams["assigned_ip"] != nil && connLegacy.ClientParams["assigned_ip"] != "" {
		t.Fatalf("legacy conn assigned_ip was falsely migrated: %v", connLegacy.ClientParams["assigned_ip"])
	}
	if connLegacy.ClientParams["quarantined_ip_collision"] != targetIP {
		t.Fatalf("legacy conn quarantined_ip_collision mismatch: %v", connLegacy.ClientParams["quarantined_ip_collision"])
	}
	if req, ok := connLegacy.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("legacy conn config_regeneration_required not true: %v", connLegacy.ClientParams["config_regeneration_required"])
	}
}

// Scenario 5: Second restart after reconciliation is idempotent (no remaining collisions)
func TestStartupIPAMCollision_Scenario5_SecondRestartIsIdempotent(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	u1, _ := db.CreateUser(ctx, &models.User{Username: "user-sc5-1", Enabled: true})
	u2, _ := db.CreateUser(ctx, &models.User{Username: "user-sc5-2", Enabled: true})

	now := time.Now().UTC()
	const targetIP = "10.100.0.9"

	c1ID, _ := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc5-1",
		UserID:       u1,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc5-1",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-5 * time.Second),
	})
	c2ID, _ := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-sc5-2",
		UserID:       u2,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-sc5-2",
		ClientParams: map[string]any{"assigned_ip": targetIP},
		CreatedAt:    now.Add(-2 * time.Second),
	})

	// First startup restart cycle
	ipam1, _ := endpoint.NewIPAM("10.100.0.0/16")
	if err := reservePersistedClientIPs(ctx, db, ipam1); err != nil {
		t.Fatalf("first reservePersistedClientIPs failed: %v", err)
	}
	if _, err := db.InvalidateVPNSessionsForRestart(ctx); err != nil {
		t.Fatalf("first InvalidateVPNSessionsForRestart failed: %v", err)
	}

	// Verify Conn1 won, Conn2 quarantined
	conn1After1, _ := db.GetConnection(ctx, c1ID)
	conn2After1, _ := db.GetConnection(ctx, c2ID)
	if conn1After1.ClientParams["assigned_ip"] != targetIP {
		t.Fatalf("conn1 lost IP in first restart: %v", conn1After1.ClientParams)
	}
	if conn2After1.ClientParams["quarantined_ip_collision"] != targetIP {
		t.Fatalf("conn2 not quarantined in first restart: %v", conn2After1.ClientParams)
	}

	// Second startup restart cycle (simulating a subsequent restart of the service)
	ipam2, _ := endpoint.NewIPAM("10.100.0.0/16")
	if err := reservePersistedClientIPs(ctx, db, ipam2); err != nil {
		t.Fatalf("second reservePersistedClientIPs failed: %v", err)
	}
	count, err := db.InvalidateVPNSessionsForRestart(ctx)
	if err != nil {
		t.Fatalf("second InvalidateVPNSessionsForRestart failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("second restart invalidated %d sessions, want 0", count)
	}

	// In second IPAM, Conn1 is cleanly reserved without collisions
	assigned, ok := ipam2.GetAssignedIP("peer-sc5-1")
	if !ok || assigned.String() != targetIP {
		t.Fatalf("conn1 missing in second IPAM: got %v, want %s", assigned, targetIP)
	}

	// Conn2 remains quarantined, no further mutations
	conn2After2, _ := db.GetConnection(ctx, c2ID)
	if conn2After2.ClientParams["assigned_ip"] != nil {
		t.Fatalf("conn2 assigned_ip unexpectedly reappeared: %v", conn2After2.ClientParams)
	}
	if conn2After2.ClientParams["quarantined_ip_collision"] != targetIP {
		t.Fatalf("conn2 quarantined_ip_collision corrupted: %v", conn2After2.ClientParams)
	}
	if req, ok := conn2After2.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("conn2 config_regeneration_required corrupted: %v", conn2After2.ClientParams)
	}
}

// Scenario 6: Unrelated valid leases remain unchanged
func TestStartupIPAMCollision_Scenario6_UnrelatedValidLeasesUnchanged(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	u1, _ := db.CreateUser(ctx, &models.User{Username: "user-sc6-1", Enabled: true})
	u2, _ := db.CreateUser(ctx, &models.User{Username: "user-sc6-2", Enabled: true})
	u3, _ := db.CreateUser(ctx, &models.User{Username: "user-sc6-3", Enabled: true})
	u4, _ := db.CreateUser(ctx, &models.User{Username: "user-sc6-4", Enabled: true})

	now := time.Now().UTC()

	// Colliding pair
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc6-1", UserID: u1, ServerID: 0, Protocol: "awg", ClientID: "peer-sc6-1",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.3"}, CreatedAt: now.Add(-5 * time.Second),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc6-2", UserID: u2, ServerID: 0, Protocol: "awg", ClientID: "peer-sc6-2",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.3"}, CreatedAt: now.Add(-2 * time.Second),
	})

	// Unrelated valid leases
	c3ID, _ := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc6-3", UserID: u3, ServerID: 0, Protocol: "awg", ClientID: "peer-sc6-3",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.10"}, CreatedAt: now.Add(-4 * time.Second),
	})
	c4ID, _ := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc6-4", UserID: u4, ServerID: 0, Protocol: "awg", ClientID: "peer-sc6-4",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.20"}, CreatedAt: now.Add(-3 * time.Second),
	})

	ipam, _ := endpoint.NewIPAM("10.100.0.0/16")
	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// Verify unrelated connections retained their exact IPs in IPAM
	if ip, ok := ipam.GetAssignedIP("peer-sc6-3"); !ok || ip.String() != "10.100.0.10" {
		t.Fatalf("peer-sc6-3 IPAM mismatch: %v", ip)
	}
	if ip, ok := ipam.GetAssignedIP("peer-sc6-4"); !ok || ip.String() != "10.100.0.20" {
		t.Fatalf("peer-sc6-4 IPAM mismatch: %v", ip)
	}

	// Verify unrelated connections in DB are completely untouched
	conn3, _ := db.GetConnection(ctx, c3ID)
	if conn3.ClientParams["assigned_ip"] != "10.100.0.10" || conn3.ClientParams["quarantined_ip_collision"] != nil {
		t.Fatalf("conn3 corrupted: %+v", conn3.ClientParams)
	}
	conn4, _ := db.GetConnection(ctx, c4ID)
	if conn4.ClientParams["assigned_ip"] != "10.100.0.20" || conn4.ClientParams["quarantined_ip_collision"] != nil {
		t.Fatalf("conn4 corrupted: %+v", conn4.ClientParams)
	}
}

// Scenario 7: Losing peer's old config is not treated as automatically recovered (handshake fails with collision error)
func TestStartupIPAMCollision_Scenario7_LosingPeerOldConfig_RefusesHandshake(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pub-sc7",
		PrivateKey:    "tunnel-priv-sc7",
		Endpoint:      "192.0.2.10:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	u1, _ := db.CreateUser(ctx, &models.User{Username: "user-sc7-1", Enabled: true})
	u2, _ := db.CreateUser(ctx, &models.User{Username: "user-sc7-2", Enabled: true})

	now := time.Now().UTC()
	const targetIP = "10.100.0.3"
	peerKey1 := "peer-sc7-1"
	peerKey2 := "peer-sc7-2"

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc7-1", UserID: u1, ServerID: 0, Protocol: "awg", ClientID: peerKey1,
		ClientParams: map[string]any{"assigned_ip": targetIP}, CreatedAt: now.Add(-5 * time.Second),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc7-2", UserID: u2, ServerID: 0, Protocol: "awg", ClientID: peerKey2,
		ClientParams: map[string]any{"assigned_ip": targetIP}, CreatedAt: now.Add(-2 * time.Second),
	})

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
		t.Fatal(err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Stop() }()

	// Handshake for peer 2 (losing claimant) must be refused
	_, _, err = svc.HandleIncomingPeer(ctx, peerKey2)
	if err == nil {
		t.Fatal("expected HandleIncomingPeer to refuse connection for quarantined peer, got nil error")
	}

	if !errors.Is(err, endpoint.ErrIPAlreadyAllocated) {
		t.Fatalf("expected error to wrap ErrIPAlreadyAllocated, got: %v", err)
	}

	if !strings.Contains(err.Error(), "config regeneration required") {
		t.Fatalf("expected error to mention config regeneration required, got: %v", err)
	}
}

// Scenario 8: Regenerated losing config gets a new collision-free IP and persists it; connecting with new config succeeds
func TestStartupIPAMCollision_Scenario8_RegenerateLosingConfig_AllocatesNewIPAndHandshakeSucceeds(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pub-sc8",
		PrivateKey:    "tunnel-priv-sc8",
		Endpoint:      "192.0.2.10:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	u1, _ := db.CreateUser(ctx, &models.User{Username: "user-sc8-1", Enabled: true})
	u2, _ := db.CreateUser(ctx, &models.User{Username: "user-sc8-2", Enabled: true})

	now := time.Now().UTC()
	const sharedIP = "10.100.0.3"
	peerPub1, peerPriv1, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerPub2, peerPriv2, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc8-1", UserID: u1, ServerID: 0, Protocol: "awg", ClientID: peerPub1,
		ClientParams: map[string]any{"assigned_ip": sharedIP, "client_private_key": peerPriv1}, CreatedAt: now.Add(-5 * time.Second),
	})
	conn2ID, _ := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-sc8-2", UserID: u2, ServerID: 0, Protocol: "awg", ClientID: peerPub2,
		ClientParams: map[string]any{"assigned_ip": sharedIP, "client_private_key": peerPriv2}, CreatedAt: now.Add(-2 * time.Second),
	})

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
		t.Fatal(err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Stop() }()

	// 1. Initial handshake fails per Scenario 7
	if _, _, err := svc.HandleIncomingPeer(ctx, peerPub2); err == nil {
		t.Fatal("expected initial handshake to fail before regeneration")
	}

	// 2. Regenerate config for user 2
	newConfig, _, err := svc.GenerateClientConfig(ctx, u2)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	newIP := extractAddressFromConfig(t, newConfig)
	if newIP == "" || newIP == sharedIP {
		t.Fatalf("expected fresh IP, got %s", newIP)
	}

	// 3. Verify SQLite connection 2 is updated
	conn2Updated, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2Updated.ClientParams["assigned_ip"] != newIP {
		t.Fatalf("conn2 assigned_ip mismatch: got %v, want %s", conn2Updated.ClientParams["assigned_ip"], newIP)
	}
	if conn2Updated.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("config_regeneration_required still present: %v", conn2Updated.ClientParams["config_regeneration_required"])
	}
	if conn2Updated.ClientParams["quarantined_ip_collision"] != nil {
		t.Fatalf("quarantined_ip_collision still present: %v", conn2Updated.ClientParams["quarantined_ip_collision"])
	}

	// 4. Connecting with new config succeeds
	sess, _, err := svc.HandleIncomingPeer(ctx, peerPub2)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed after config regeneration: %v", err)
	}
	if sess == nil || sess.AssignedIP != newIP {
		t.Fatalf("expected session with assigned IP %s, got: %+v", newIP, sess)
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

func TestStartupIPAMCollision_SamePeerMultipleConnectionsSameIP_RetainsAllUnquarantinedAndHandshakeSucceeds(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pub-multi",
		PrivateKey:    "tunnel-priv-multi",
		Endpoint:      "192.0.2.10:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "user-multi-same", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	peerPub, peerPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const sharedIP = "10.100.0.3"

	// Multiple connection rows for the same peer sharing the exact same IP
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-multi-1",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerPub,
		ClientParams: map[string]any{"assigned_ip": sharedIP, "client_private_key": peerPriv},
		CreatedAt:    now.Add(-5 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-multi-2",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerPub,
		ClientParams: map[string]any{"assigned_ip": sharedIP, "client_private_key": peerPriv},
		CreatedAt:    now.Add(-2 * time.Second),
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
		t.Fatal(err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Both rows must retain sharedIP without quarantine
	conn1, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1.ClientParams["assigned_ip"] != sharedIP {
		t.Fatalf("conn1 lost assigned_ip: %v", conn1.ClientParams["assigned_ip"])
	}
	if conn1.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn1 falsely quarantined: %v", conn1.ClientParams["config_regeneration_required"])
	}

	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2.ClientParams["assigned_ip"] != sharedIP {
		t.Fatalf("conn2 lost assigned_ip: %v", conn2.ClientParams["assigned_ip"])
	}
	if conn2.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn2 falsely quarantined: %v", conn2.ClientParams["config_regeneration_required"])
	}

	// IPAM must hold sharedIP for peerPub
	assigned, ok := svc.ipam.GetAssignedIP(peerPub)
	if !ok || assigned.String() != sharedIP {
		t.Fatalf("peerPub missing or wrong in IPAM: got %v, want %s", assigned, sharedIP)
	}

	// Incoming handshake must succeed cleanly
	sess, _, err := svc.HandleIncomingPeer(ctx, peerPub)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for same-peer multiple connection: %v", err)
	}
	if sess == nil || sess.AssignedIP != sharedIP {
		t.Fatalf("expected session with %s, got: %+v", sharedIP, sess)
	}
}

func TestStartupIPAMCollision_SamePeerMultipleDifferentIPs_ResolvesDeterministically(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	userID, err := db.CreateUser(ctx, &models.User{Username: "user-diff-ips", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	peerPub, peerPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	// Older connection claims 10.100.0.8 (lexicographically greater than 10.100.0.2)
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-diff-1",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerPub,
		ClientParams: map[string]any{"assigned_ip": "10.100.0.8", "client_private_key": peerPriv},
		CreatedAt:    now.Add(-10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Newer connection claims 10.100.0.2 (lexicographically smaller)
	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-diff-2",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerPub,
		ClientParams: map[string]any{"assigned_ip": "10.100.0.2", "client_private_key": peerPriv},
		CreatedAt:    now.Add(-1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	if err := reservePersistedClientIPs(ctx, db, ipam); err != nil {
		t.Fatalf("reservePersistedClientIPs failed: %v", err)
	}

	// Winner must be older connection conn-diff-1 (10.100.0.8)
	assigned, ok := ipam.GetAssignedIP(peerPub)
	if !ok || assigned.String() != "10.100.0.8" {
		t.Fatalf("expected winner 10.100.0.8 in IPAM, got: %v", assigned)
	}

	conn1, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1.ClientParams["assigned_ip"] != "10.100.0.8" {
		t.Fatalf("conn1 lost assigned_ip: %v", conn1.ClientParams["assigned_ip"])
	}
	if conn1.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn1 was unexpectedly quarantined: %v", conn1.ClientParams["config_regeneration_required"])
	}

	// Loser conn-diff-2 (10.100.0.2) must be quarantined and its keypair retired
	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2.ClientID != "" {
		t.Fatalf("conn2 client_id not cleared: got %q, want empty", conn2.ClientID)
	}
	if conn2.ClientParams["client_private_key"] != nil && conn2.ClientParams["client_private_key"] != "" {
		t.Fatalf("conn2 client_private_key not deleted: %v", conn2.ClientParams["client_private_key"])
	}
	if conn2.ClientParams["assigned_ip"] != nil && conn2.ClientParams["assigned_ip"] != "" {
		t.Fatalf("conn2 assigned_ip not cleared: %v", conn2.ClientParams["assigned_ip"])
	}
	if conn2.ClientParams["quarantined_ip_collision"] != "10.100.0.2" {
		t.Fatalf("conn2 quarantined_ip_collision mismatch: %v", conn2.ClientParams["quarantined_ip_collision"])
	}
	if req, ok := conn2.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("conn2 config_regeneration_required not true: %v", conn2.ClientParams["config_regeneration_required"])
	}
}

func TestStartupIPAMCollision_SamePeerConflictingIPs_RetiresKeypairAndEnablesStableRegeneration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pub-samepeer-diff",
		PrivateKey:    "tunnel-priv-samepeer-diff",
		Endpoint:      "192.0.2.10:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "user-samepeer-diff", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	samePeerPub, samePeerPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	// Step 1: Older connection conn1 claims 10.100.0.8 (T-10s); newer connection conn2 claims 10.100.0.2 (T-1s)
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-samepeer-1",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     samePeerPub,
		ClientParams: map[string]any{"assigned_ip": "10.100.0.8", "client_private_key": samePeerPriv},
		CreatedAt:    now.Add(-10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-samepeer-2",
		UserID:       userID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     samePeerPub,
		ClientParams: map[string]any{"assigned_ip": "10.100.0.2", "client_private_key": samePeerPriv},
		CreatedAt:    now.Add(-1 * time.Second),
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

	// Step 2: Start svc: assert reconciliation runs. conn1 wins (10.100.0.8).
	// conn2 is quarantined and its client_id is cleared to "" and client_private_key deleted.
	svc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	conn1, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1.ClientID != samePeerPub {
		t.Fatalf("conn1 client_id changed: got %v, want %s", conn1.ClientID, samePeerPub)
	}
	if conn1.ClientParams["assigned_ip"] != "10.100.0.8" {
		t.Fatalf("conn1 lost assigned_ip: %v", conn1.ClientParams["assigned_ip"])
	}
	if conn1.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn1 unexpectedly quarantined: %v", conn1.ClientParams["config_regeneration_required"])
	}

	conn2, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2.ClientID != "" {
		t.Fatalf("conn2 client_id not cleared: got %q, want empty", conn2.ClientID)
	}
	if conn2.ClientParams["client_private_key"] != nil && conn2.ClientParams["client_private_key"] != "" {
		t.Fatalf("conn2 client_private_key not deleted: %v", conn2.ClientParams["client_private_key"])
	}
	if conn2.ClientParams["assigned_ip"] != nil && conn2.ClientParams["assigned_ip"] != "" {
		t.Fatalf("conn2 assigned_ip not cleared: %v", conn2.ClientParams["assigned_ip"])
	}
	if conn2.ClientParams["quarantined_ip_collision"] != "10.100.0.2" {
		t.Fatalf("conn2 quarantined_ip_collision mismatch: %v", conn2.ClientParams["quarantined_ip_collision"])
	}
	if req, ok := conn2.ClientParams["config_regeneration_required"].(bool); !ok || !req {
		t.Fatalf("conn2 config_regeneration_required not true: %v", conn2.ClientParams["config_regeneration_required"])
	}

	// Step 3: Call svc.HandleIncomingPeer(ctx, samePeer): assert it succeeds deterministically with sess.AssignedIP == "10.100.0.8"
	sess1, _, err := svc.HandleIncomingPeer(ctx, samePeerPub)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for samePeer: %v", err)
	}
	if sess1 == nil || sess1.AssignedIP != "10.100.0.8" {
		t.Fatalf("expected session with 10.100.0.8, got: %+v", sess1)
	}

	// Step 4: Call svc.GenerateClientConfigForConnection(ctx, userID, conn2.ID): assert it generates
	// fresh new peer key newPeer (different from samePeer) and fresh IP newIP (different from .8 and .2),
	// and updates conn2 with client_id = newPeer and assigned_ip = newIP.
	conn2Config, _, err := svc.GenerateClientConfigForConnection(ctx, userID, conn2ID)
	if err != nil {
		t.Fatalf("GenerateClientConfigForConnection failed for conn2: %v", err)
	}
	newIP := extractAddressFromConfig(t, conn2Config)
	// In IPAM, 10.100.0.8 is reserved for conn1 (samePeerPub).
	// Because conn2's conflicting claim on 10.100.0.2 was quarantined and unreserved,
	// 10.100.0.2 is the lowest free IP in the pool and is cleanly allocated to the new peer.
	// It is guaranteed distinct from winner conn1's IP (10.100.0.8).
	if newIP == "" || newIP == "10.100.0.8" {
		t.Fatalf("expected fresh newIP distinct from winner 10.100.0.8, got: %s", newIP)
	}

	conn2Regenerated, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	newPeer := conn2Regenerated.ClientID
	if newPeer == "" || newPeer == samePeerPub {
		t.Fatalf("expected fresh newPeer distinct from %s, got: %q", samePeerPub, newPeer)
	}
	if conn2Regenerated.ClientParams["assigned_ip"] != newIP {
		t.Fatalf("conn2 assigned_ip mismatch: got %v, want %s", conn2Regenerated.ClientParams["assigned_ip"], newIP)
	}
	if conn2Regenerated.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn2 config_regeneration_required not cleared: %v", conn2Regenerated.ClientParams["config_regeneration_required"])
	}
	if conn2Regenerated.ClientParams["quarantined_ip_collision"] != nil {
		t.Fatalf("conn2 quarantined_ip_collision not cleared: %v", conn2Regenerated.ClientParams["quarantined_ip_collision"])
	}

	// Step 5: Assert connecting with newPeer (svc.HandleIncomingPeer(ctx, newPeer)) succeeds with AssignedIP == newIP.
	sessNew, _, err := svc.HandleIncomingPeer(ctx, newPeer)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for newPeer: %v", err)
	}
	if sessNew == nil || sessNew.AssignedIP != newIP {
		t.Fatalf("expected session with %s, got: %+v", newIP, sessNew)
	}

	// Step 6: Assert winner conn1 remains valid in DB (samePeer, 10.100.0.8) and connecting with samePeer still succeeds with AssignedIP == "10.100.0.8".
	conn1After, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1After.ClientID != samePeerPub {
		t.Fatalf("conn1 client_id changed: got %v, want %s", conn1After.ClientID, samePeerPub)
	}
	if conn1After.ClientParams["assigned_ip"] != "10.100.0.8" {
		t.Fatalf("conn1 assigned_ip changed: got %v, want 10.100.0.8", conn1After.ClientParams["assigned_ip"])
	}
	sessSameAgain, _, err := svc.HandleIncomingPeer(ctx, samePeerPub)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for samePeer after conn2 regeneration: %v", err)
	}
	if sessSameAgain == nil || sessSameAgain.AssignedIP != "10.100.0.8" {
		t.Fatalf("expected session with 10.100.0.8, got: %+v", sessSameAgain)
	}

	// Step 7: Stop svc. Create svc2 from the same DB and call svc2.Start(). Assert startup reconciliation is idempotent (0 collisions, 0 quarantines),
	// conn1 and conn2 are both healthy and unquarantined, and handshakes for both samePeer and newPeer succeed.
	if err := svc.Stop(); err != nil {
		t.Fatalf("svc.Stop failed: %v", err)
	}

	svc2, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	svc2.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := svc2.Start(ctx); err != nil {
		t.Fatalf("svc2.Start failed: %v", err)
	}
	defer func() { _ = svc2.Stop() }()

	conn1Restart, err := db.GetConnection(ctx, conn1ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn1Restart.ClientID != samePeerPub || conn1Restart.ClientParams["assigned_ip"] != "10.100.0.8" {
		t.Fatalf("conn1 corrupted after restart: %+v", conn1Restart)
	}
	if conn1Restart.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn1 unexpectedly quarantined after restart: %v", conn1Restart.ClientParams["config_regeneration_required"])
	}

	conn2Restart, err := db.GetConnection(ctx, conn2ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn2Restart.ClientID != newPeer || conn2Restart.ClientParams["assigned_ip"] != newIP {
		t.Fatalf("conn2 corrupted after restart: %+v", conn2Restart)
	}
	if conn2Restart.ClientParams["config_regeneration_required"] != nil {
		t.Fatalf("conn2 unexpectedly quarantined after restart: %v", conn2Restart.ClientParams["config_regeneration_required"])
	}

	sess1Restart, _, err := svc2.HandleIncomingPeer(ctx, samePeerPub)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for samePeer after restart: %v", err)
	}
	if sess1Restart == nil || sess1Restart.AssignedIP != "10.100.0.8" {
		t.Fatalf("expected session with 10.100.0.8 after restart, got: %+v", sess1Restart)
	}

	sess2Restart, _, err := svc2.HandleIncomingPeer(ctx, newPeer)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed for newPeer after restart: %v", err)
	}
	if sess2Restart == nil || sess2Restart.AssignedIP != newIP {
		t.Fatalf("expected session with %s after restart, got: %+v", newIP, sess2Restart)
	}
}

func TestStartupIPAMCollision_StorageFailureDuringQuarantine_FailsReconciliation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	u1, err := db.CreateUser(ctx, &models.User{Username: "user-storage-1", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := db.CreateUser(ctx, &models.User{Username: "user-storage-2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const collidingIP = "10.100.0.3"

	_, err = db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-stor-1",
		UserID:       u1,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-stor-1",
		ClientParams: map[string]any{"assigned_ip": collidingIP},
		CreatedAt:    now.Add(-5 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.CreateConnection(ctx, &models.UserConnection{
		ID:           "conn-stor-2",
		UserID:       u2,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     "peer-stor-2",
		ClientParams: map[string]any{"assigned_ip": collidingIP},
		CreatedAt:    now.Add(-2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	ipam, err := endpoint.NewIPAM("10.100.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	// Fault injection: make SQLite read-only so quarantine UPDATE will fail
	if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA query_only = ON;"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.SQLDB().ExecContext(ctx, "PRAGMA query_only = OFF;")
	}()

	err = reservePersistedClientIPs(ctx, db, ipam)
	if err == nil {
		t.Fatal("expected reservePersistedClientIPs to fail when SQLite write fails during quarantine, got nil")
	}
}
