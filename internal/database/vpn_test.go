package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func TestVPNEmptyAndNotFound(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) != 0 {
		t.Fatalf("GetBackendTunnels empty DB = (%v, %v), want ([], nil)", tunnels, err)
	}

	allTunnels, err := db.GetAllBackendTunnels(ctx)
	if err != nil || len(allTunnels) != 0 {
		t.Errorf("GetAllBackendTunnels empty DB failed: %v", err)
	}

	nonExistentT, err := db.GetBackendTunnel(ctx, 9999)
	if err != nil || nonExistentT != nil {
		t.Errorf("GetBackendTunnel(9999) = (%v, %v), want (nil, nil)", nonExistentT, err)
	}

	nonExistentTByID, err := db.GetBackendTunnelByID(ctx, 9999)
	if err != nil || nonExistentTByID != nil {
		t.Errorf("GetBackendTunnelByID(9999) = (%v, %v), want (nil, nil)", nonExistentTByID, err)
	}

	nonExistentSession, err := db.GetVPNSessionByPeerKey(ctx, "ghost-peer-key")
	if err != nil || nonExistentSession != nil {
		t.Errorf("GetVPNSessionByPeerKey(ghost) = (%v, %v), want (nil, nil)", nonExistentSession, err)
	}

	activeSessionsEmpty, err := db.GetActiveVPNSessions(ctx)
	if err != nil || len(activeSessionsEmpty) != 0 {
		t.Errorf("GetActiveVPNSessions empty = (%v, %v), want (empty, nil)", activeSessionsEmpty, err)
	}
}

func TestVPNBackendTunnelsCreateAndGet(t *testing.T) {
	db, secretKey := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.10.10.1"})
	healthCheckTime := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	encPrivKey, _ := security.EncryptCredential("FERNET_PRIV_KEY", secretKey)

	t1 := &models.BackendTunnel{
		ServerID:          sID,
		InterfaceName:     "awg-be-1",
		PublicKey:         "pubkey-tunnel-1",
		PrivateKey:        "secret-privkey-1",
		Endpoint:          "10.10.10.1:51820",
		Status:            "active",
		LastHealthCheck:   &healthCheckTime,
		LatencyMS:         15,
		ActiveConnections: 5,
		CreatedAt:         time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	t1ID, err := db.CreateBackendTunnel(ctx, t1)
	if err != nil || t1ID <= 0 {
		t.Fatalf("CreateBackendTunnel t1 failed: %v", err)
	}

	t2 := &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-2",
		PublicKey:     "pubkey-tunnel-2",
		PrivateKey:    encPrivKey,
		Endpoint:      "10.10.10.1:51821",
	}
	_, _ = db.CreateBackendTunnel(ctx, t2)

	retrieved, _ := db.GetBackendTunnelByID(ctx, t1ID)
	if retrieved.PrivateKey != "secret-privkey-1" || retrieved.Status != "active" {
		t.Errorf("Backend tunnel 1 mismatch: %+v", retrieved)
	}

	all, _ := db.GetAllBackendTunnels(ctx)
	if len(all) != 2 {
		t.Errorf("expected 2 backend tunnels, got %d", len(all))
	}
}

func TestVPNBackendTunnelsUpdateAndStatus(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.10.10.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be",
		PublicKey:     "pubkey",
		PrivateKey:    "privkey",
		Endpoint:      "10.10.10.1:51820",
	})

	if err := db.UpdateBackendTunnel(ctx, tID, map[string]any{"invalid_col": 123}); err == nil {
		t.Errorf("expected error updating invalid column")
	}
	if err := db.UpdateBackendTunnel(ctx, tID, map[string]any{}); err != nil {
		t.Errorf("UpdateBackendTunnel empty map failed: %v", err)
	}

	newHealth := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	err := db.UpdateBackendTunnel(ctx, tID, map[string]any{
		"interface_name":    "awg-be-renamed",
		"private_key":       "new-plaintext-privkey",
		"latency_ms":        42,
		"last_health_check": &newHealth,
	})
	if err != nil {
		t.Fatalf("UpdateBackendTunnel failed: %v", err)
	}

	_ = db.UpdateBackendTunnel(ctx, tID, map[string]any{"last_health_check": newHealth})

	if err := db.UpdateBackendTunnelStatus(ctx, tID, "degraded", 88); err != nil {
		t.Fatalf("UpdateBackendTunnelStatus failed: %v", err)
	}
	tStatus, _ := db.GetBackendTunnel(ctx, tID)
	if tStatus.Status != "degraded" || tStatus.LatencyMS != 88 {
		t.Errorf("UpdateBackendTunnelStatus mismatch: status=%s, latency=%d", tStatus.Status, tStatus.LatencyMS)
	}
}

func TestUpdateBackendTunnel_NotFound(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	nonExistentID := int64(999999)
	err := db.UpdateBackendTunnel(ctx, nonExistentID, map[string]any{
		"endpoint": "198.51.100.10:51820",
	})
	if err == nil {
		t.Fatal("expected error updating non-existent backend tunnel, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error containing 'not found', got: %v", err)
	}
}

func TestVPNSessionsCRUDAndTraffic(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.10.10.1"})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "vpn_user"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be",
		PublicKey:     "pubkey",
		PrivateKey:    "privkey",
		Endpoint:      "10.10.10.1:51820",
	})

	sess1 := &models.VPNSession{
		ID:              "custom-session-1",
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer-key-alice",
		AssignedIP:      "10.100.0.10",
		ConnectedAt:     time.Date(2026, 8, 26, 1, 0, 0, 0, time.UTC),
		LastSeen:        time.Date(2026, 8, 26, 1, 5, 0, 0, time.UTC),
		RxBytes:         1024,
		TxBytes:         2048,
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, sess1); err != nil {
		t.Fatalf("CreateVPNSession sess1 failed: %v", err)
	}

	retrievedSess, _ := db.GetVPNSessionByPeerKey(ctx, "peer-key-alice")
	if retrievedSess == nil || retrievedSess.ID != "custom-session-1" {
		t.Errorf("GetVPNSessionByPeerKey mismatch: %+v", retrievedSess)
	}

	sess2 := &models.VPNSession{
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer-key-bob",
		AssignedIP:      "10.100.0.11",
	}
	_ = db.CreateVPNSession(ctx, sess2)

	sess1Update := &models.VPNSession{
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer-key-alice",
		AssignedIP:      "10.100.0.20",
		Status:          "disconnected",
	}
	_ = db.CreateVPNSession(ctx, sess1Update)

	bobSess, _ := db.GetVPNSessionByPeerKey(ctx, "peer-key-bob")
	if bobSess == nil {
		t.Fatalf("GetVPNSessionByPeerKey returned nil for peer-key-bob")
	}

	// Regression (review-2 P1 / issue #205): UpdateVPNSessionTraffic must
	// ADD its arguments to the stored counters (deltas in, cumulative
	// totals stored), not overwrite the row with the last window. Exactly
	// the reviewer's case: 100 -> +500 -> 600 -> +300 -> 900. Under the
	// old absolute-SET semantics the row would hold 500 then 300 and this
	// test fails at both checks.
	if err := db.UpdateVPNSessionTraffic(ctx, bobSess.ID, 100, 100); err != nil {
		t.Fatalf("seed UpdateVPNSessionTraffic failed: %v", err)
	}
	row, _ := db.GetVPNSessionByPeerKey(ctx, "peer-key-bob")
	if row == nil || row.RxBytes != 100 || row.TxBytes != 100 {
		t.Fatalf("after first flush: row=%+v, want rx=100 tx=100", row)
	}
	if err := db.UpdateVPNSessionTraffic(ctx, bobSess.ID, 500, 500); err != nil {
		t.Fatalf("second UpdateVPNSessionTraffic failed: %v", err)
	}
	row, _ = db.GetVPNSessionByPeerKey(ctx, "peer-key-bob")
	if row == nil || row.RxBytes != 600 || row.TxBytes != 600 {
		t.Fatalf("after +500: row=%+v, want rx=600 tx=600 cumulative — absolute-SET code fails here with 500", row)
	}
	if err := db.UpdateVPNSessionTraffic(ctx, bobSess.ID, 300, 300); err != nil {
		t.Fatalf("third UpdateVPNSessionTraffic failed: %v", err)
	}
	row, _ = db.GetVPNSessionByPeerKey(ctx, "peer-key-bob")
	if row == nil || row.RxBytes != 900 || row.TxBytes != 900 {
		t.Fatalf("after +300: row=%+v, want rx=900 tx=900 cumulative — absolute-SET code fails here with 300", row)
	}

	activeSess, err := db.GetActiveVPNSessions(ctx)
	if err != nil || len(activeSess) != 1 || activeSess[0].PeerPublicKey != "peer-key-bob" {
		t.Fatalf("GetActiveVPNSessions failed: len=%d, err=%v", len(activeSess), err)
	}
}

func TestVPNDeletionAndNullScanning(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.10.10.1"})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "vpn_user"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be",
		PublicKey:     "pubkey",
		PrivateKey:    "privkey",
		Endpoint:      "10.10.10.1:51820",
	})
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer-key-del",
		AssignedIP:      "10.100.0.99",
	})

	delSess, _ := db.GetVPNSessionByPeerKey(ctx, "peer-key-del")
	if err := db.DeleteVPNSession(ctx, delSess.ID); err != nil {
		t.Fatalf("DeleteVPNSession failed: %v", err)
	}

	if err := db.DeleteBackendTunnel(ctx, tID); err != nil {
		t.Fatalf("DeleteBackendTunnel failed: %v", err)
	}

	_, _ = db.sqlDB.ExecContext(ctx, "INSERT INTO backend_tunnels (id, server_id, interface_name, public_key, private_key, endpoint, created_at) VALUES (777, ?, 'awg-null-ts', 'pubkey-null-ts', 'priv', '10.0.0.1:51820', '2026-08-01T00:00:00Z')", sID)
	tNullTS, err := db.GetBackendTunnel(ctx, 777)
	if err != nil || tNullTS == nil || tNullTS.CreatedAt.IsZero() || tNullTS.LastHealthCheck != nil {
		t.Errorf("expected nil last_health_check in tNullTS, got: %+v", tNullTS)
	}

	_, _ = db.sqlDB.ExecContext(ctx, "INSERT INTO vpn_sessions (id, user_id, backend_tunnel_id, peer_public_key, assigned_ip, connected_at, last_seen) VALUES ('sess-null-ts', ?, 777, 'peer-null-ts', '10.100.0.99', '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')", uID)
	sessNullTS, err := db.GetVPNSessionByPeerKey(ctx, "peer-null-ts")
	if err != nil || sessNullTS == nil || sessNullTS.ConnectedAt.IsZero() || sessNullTS.LastSeen.IsZero() {
		t.Errorf("expected valid timestamps in sessNullTS, got: %+v", sessNullTS)
	}
}

func TestVPNConfig(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// Default config
	cfg, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if cfg.Algorithm != models.LBLeastConnections || cfg.ListenPort != 51820 || cfg.SubnetCIDR != "10.100.0.0/16" {
		t.Errorf("unexpected default cfg: %+v", cfg)
	}

	// Update config
	cfg.Algorithm = models.LBWeighted
	cfg.ListenPort = 51822
	cfg.Weights = map[int64]int{1: 50, 2: 50}
	if err := db.SaveVPNConfig(ctx, cfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}
	if err := db.SaveVPNConfig(ctx, nil); err == nil {
		t.Errorf("expected error saving nil cfg")
	}

	loadedCfg, err := db.GetVPNConfig(ctx)
	if err != nil || loadedCfg.Algorithm != models.LBWeighted || loadedCfg.ListenPort != 51822 || loadedCfg.Weights[1] != 50 {
		t.Errorf("loaded cfg mismatch: %+v, err: %v", loadedCfg, err)
	}
}

func TestVPNQueries(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// Backend tunnel by server ID
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "1.2.3.4"})
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "pubkey1",
		PrivateKey:    "privkey1",
		Endpoint:      "1.2.3.4:51820",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	byServerID, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || byServerID == nil || byServerID.ID != tID {
		t.Errorf("GetBackendTunnelByServerID mismatch: %+v, err: %v", byServerID, err)
	}

	nonExistent, err := db.GetBackendTunnelByServerID(ctx, 99999)
	if err != nil || nonExistent != nil {
		t.Errorf("expected nil for non-existent server ID, got: %+v, err: %v", nonExistent, err)
	}

	// VPNSessionByID and VPNSessionsByUserID
	uID, _ := db.CreateUser(ctx, &models.User{Username: "sess_user"})
	sessID := "session-uuid-123"
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer123",
		AssignedIP:      "10.100.0.15",
	}); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}

	byID, err := db.GetVPNSessionByID(ctx, sessID)
	if err != nil || byID == nil || byID.ID != sessID {
		t.Errorf("GetVPNSessionByID mismatch: %+v, err: %v", byID, err)
	}

	nonExistentSess, err := db.GetVPNSessionByID(ctx, "non-existent")
	if err != nil || nonExistentSess != nil {
		t.Errorf("expected nil for non-existent session ID, got: %+v, err: %v", nonExistentSess, err)
	}

	userSessions, err := db.GetVPNSessionsByUserID(ctx, uID)
	if err != nil || len(userSessions) != 1 || userSessions[0].ID != sessID {
		t.Errorf("GetVPNSessionsByUserID mismatch: len=%d, err=%v", len(userSessions), err)
	}

	emptyUserSessions, err := db.GetVPNSessionsByUserID(ctx, "non-existent-user")
	if err != nil || len(emptyUserSessions) != 0 {
		t.Errorf("expected empty user sessions, got: %d, err: %v", len(emptyUserSessions), err)
	}
}

func TestVPNConfig_NoMigrationOnRead(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// Seed legacy VPN config JSON without H/S fields directly (the state
	// left behind by pre-obfuscation panel versions).
	legacyJSON := `{"algorithm":"least_connections","listen_port":51820,"subnet_cidr":"10.100.0.0/16","health_threshold_ms":500,"max_total_peers":1000,"max_peers_per_backend":250}`
	if _, err := db.sqlDB.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", "vpn_config", legacyJSON); err != nil {
		t.Fatalf("failed to seed legacy vpn_config: %v", err)
	}

	// Layering contract (Issue #5 finding 8): GetVPNConfig must NOT
	// migrate. It returns the stored values verbatim — obfuscation
	// migration is owned by vpn.NewVPNService, so a single component
	// derives, persists, and distributes the parameters.
	cfg, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if !cfg.H1.IsZero() || !cfg.H2.IsZero() || !cfg.H3.IsZero() || !cfg.H4.IsZero() {
		t.Errorf("GetVPNConfig must not generate H values, got H1=%s H2=%s H3=%s H4=%s", cfg.H1, cfg.H2, cfg.H3, cfg.H4)
	}
	if cfg.S1 != 0 || cfg.S2 != 0 || cfg.S3 != 0 || cfg.S4 != 0 {
		t.Errorf("GetVPNConfig must not generate S values, got S1=%d S2=%d S3=%d S4=%d", cfg.S1, cfg.S2, cfg.S3, cfg.S4)
	}

	// Second read: still verbatim, no generation, no persistence side
	// effect.
	cfg2, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("second GetVPNConfig failed: %v", err)
	}
	if !cfg2.H1.IsZero() || cfg2.S1 != 0 {
		t.Errorf("second read changed values: %+v", cfg2)
	}

	// Explicit values round-trip untouched: the DB layer preserves
	// whatever the migration owner persisted.
	explicit := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            map[int64]int{},
		H1:                 models.DegenerateHeaderRange(111111111),
		H2:                 models.DegenerateHeaderRange(222222222),
		H3:                 models.DegenerateHeaderRange(333333333),
		H4:                 models.NewHeaderRange(400000000, 444444444),
		S1:                 31,
		S2:                 41,
		S3:                 21,
		S4:                 16,
	}
	if err := db.SaveVPNConfig(ctx, explicit); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}
	loaded, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig after explicit save failed: %v", err)
	}
	if loaded.H1 != models.DegenerateHeaderRange(111111111) || loaded.H4 != models.NewHeaderRange(400000000, 444444444) || loaded.S1 != 31 || loaded.S4 != 16 {
		t.Errorf("explicit obfuscation values not round-tripped verbatim: %+v", loaded)
	}
}

func TestCreateVPNSession_AssignedIPConflictResolution(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.10.10.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	u1ID, err := db.CreateUser(ctx, &models.User{Username: "user_alice"})
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	u2ID, err := db.CreateUser(ctx, &models.User{Username: "user_bob"})
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be",
		PublicKey:     "pubkey",
		PrivateKey:    "privkey",
		Endpoint:      "10.10.10.1:51820",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	sharedIP := "10.100.0.50"

	// 1. Alice connects and holds sharedIP
	sessAlice := &models.VPNSession{
		ID:              "sess-alice",
		UserID:          u1ID,
		BackendTunnelID: tID,
		PeerPublicKey:   "alice-pubkey",
		AssignedIP:      sharedIP,
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, sessAlice); err != nil {
		t.Fatalf("CreateVPNSession alice failed: %v", err)
	}

	// 2. Bob connects with the same IP (re-leased by IPAM).
	// Must NOT fail with SQLite UNIQUE constraint failed: vpn_sessions.assigned_ip (2067).
	sessBob := &models.VPNSession{
		ID:              "sess-bob",
		UserID:          u2ID,
		BackendTunnelID: tID,
		PeerPublicKey:   "bob-pubkey",
		AssignedIP:      sharedIP,
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, sessBob); err != nil {
		t.Fatalf("CreateVPNSession bob failed on re-leased IP collision: %v", err)
	}

	// 3. Verify Bob now holds the IP in DB and Alice's session was cleanly removed
	bobRetrieved, err := db.GetVPNSessionByPeerKey(ctx, "bob-pubkey")
	if err != nil || bobRetrieved == nil {
		t.Fatalf("failed to retrieve bob's session: %v", err)
	}
	if bobRetrieved.AssignedIP != sharedIP {
		t.Errorf("expected assigned IP %s, got %s", sharedIP, bobRetrieved.AssignedIP)
	}

	aliceRetrieved, err := db.GetVPNSessionByPeerKey(ctx, "alice-pubkey")
	if err != nil {
		t.Fatalf("error checking alice's session: %v", err)
	}
	if aliceRetrieved != nil {
		t.Errorf("expected alice's stale session to be removed, but found: %+v", aliceRetrieved)
	}

	// 4. Verify CloseVPNSession removes bob's session
	if err := db.CloseVPNSession(ctx, bobRetrieved.ID); err != nil {
		t.Fatalf("CloseVPNSession failed: %v", err)
	}
	bobAfterClose, err := db.GetVPNSessionByID(ctx, bobRetrieved.ID)
	if err != nil {
		t.Fatalf("error querying closed session: %v", err)
	}
	if bobAfterClose != nil {
		t.Errorf("expected session to be deleted after CloseVPNSession, got: %+v", bobAfterClose)
	}
}

func TestBackendTunnel_DisableReasonAndStateVersion(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "CAS Server", Host: "192.0.2.55"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// 1. CreateBackendTunnel defaults state_version to 1 if not provided
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-cas-1",
		PublicKey:     "pub-cas-1",
		PrivateKey:    "priv-cas-1",
		Endpoint:      "192.0.2.55:51820",
		Status:        models.TunnelStatusDisabled,
		DisableReason: models.DisableReasonHealth,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	tun, err := db.GetBackendTunnel(ctx, tID)
	if err != nil || tun == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if tun.Status != models.TunnelStatusDisabled {
		t.Errorf("expected status %q, got %q", models.TunnelStatusDisabled, tun.Status)
	}
	if tun.DisableReason != models.DisableReasonHealth {
		t.Errorf("expected disable_reason %q, got %q", models.DisableReasonHealth, tun.DisableReason)
	}
	if tun.StateVersion != 1 {
		t.Errorf("expected state_version 1, got %d", tun.StateVersion)
	}

	// 2. UpdateBackendTunnelStatusWithReason bumps state_version and sets admin disable
	if err := db.UpdateBackendTunnelStatusWithReason(ctx, tID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("UpdateBackendTunnelStatusWithReason failed: %v", err)
	}

	tun, err = db.GetBackendTunnel(ctx, tID)
	if err != nil || tun == nil {
		t.Fatalf("GetBackendTunnel after update failed: %v", err)
	}
	if tun.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected disable_reason %q, got %q", models.DisableReasonAdmin, tun.DisableReason)
	}
	if tun.StateVersion != 2 {
		t.Errorf("expected state_version 2, got %d", tun.StateVersion)
	}

	// 3. CompareAndSwapTunnelStatus fails on mismatched version
	swapped, err := db.CompareAndSwapTunnelStatus(ctx, tID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 1, models.TunnelStatusActive, models.DisableReasonNone, 15)
	if err != nil {
		t.Fatalf("CompareAndSwapTunnelStatus returned unexpected error: %v", err)
	}
	if swapped {
		t.Fatal("expected CAS to fail on stale expected version 1, but it succeeded")
	}

	// 4. CompareAndSwapTunnelStatus fails on mismatched reason
	swapped, err = db.CompareAndSwapTunnelStatus(ctx, tID, models.TunnelStatusDisabled, models.DisableReasonHealth, 2, models.TunnelStatusActive, models.DisableReasonNone, 15)
	if err != nil {
		t.Fatalf("CompareAndSwapTunnelStatus returned unexpected error: %v", err)
	}
	if swapped {
		t.Fatal("expected CAS to fail on mismatched expected reason health, but it succeeded")
	}

	// 5. CompareAndSwapTunnelStatus succeeds on matching state and bumps version
	swapped, err = db.CompareAndSwapTunnelStatus(ctx, tID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 2, models.TunnelStatusActive, models.DisableReasonNone, 15)
	if err != nil {
		t.Fatalf("CompareAndSwapTunnelStatus returned error: %v", err)
	}
	if !swapped {
		t.Fatal("expected CAS to succeed on matching state, but it failed")
	}

	tun, err = db.GetBackendTunnel(ctx, tID)
	if err != nil || tun == nil {
		t.Fatalf("GetBackendTunnel after CAS failed: %v", err)
	}
	if tun.Status != models.TunnelStatusActive {
		t.Errorf("expected status active after CAS, got %q", tun.Status)
	}
	if tun.DisableReason != models.DisableReasonNone {
		t.Errorf("expected empty disable_reason after CAS, got %q", tun.DisableReason)
	}
	if tun.StateVersion != 3 {
		t.Errorf("expected state_version 3 after CAS, got %d", tun.StateVersion)
	}
	if tun.LatencyMS != 15 {
		t.Errorf("expected latency_ms 15 after CAS, got %d", tun.LatencyMS)
	}
}

func TestMigrateBackendTunnelsDisableReason(t *testing.T) {
	ctx := context.Background()
	// Open raw SQLite database without running standard migrations
	rawDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	defer rawDB.Close()

	// Create legacy backend_tunnels table without disable_reason and state_version
	_, err = rawDB.ExecContext(ctx, `
		CREATE TABLE backend_tunnels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			interface_name TEXT NOT NULL,
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'connecting',
			created_at TEXT NOT NULL
		);
		INSERT INTO backend_tunnels (server_id, interface_name, public_key, private_key, endpoint, status, created_at)
		VALUES (1, 'awg-leg-1', 'pub', 'priv', '192.0.2.1:51820', 'disabled', '2026-09-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatalf("failed to create legacy backend_tunnels: %v", err)
	}

	d := &DB{
		sqlDB:     rawDB,
		secretKey: testSecretKey,
	}

	// Run migration
	if err := d.migrateBackendTunnelsDisableReason(ctx); err != nil {
		t.Fatalf("migrateBackendTunnelsDisableReason failed: %v", err)
	}

	// Idempotency: running a second time should not error
	if err := d.migrateBackendTunnelsDisableReason(ctx); err != nil {
		t.Fatalf("idempotent migration call failed: %v", err)
	}

	// Query row and verify defaults
	var disableReason string
	var stateVersion int64
	row := rawDB.QueryRowContext(ctx, "SELECT disable_reason, state_version FROM backend_tunnels WHERE id = 1")
	if err := row.Scan(&disableReason, &stateVersion); err != nil {
		t.Fatalf("failed to scan migrated columns: %v", err)
	}

	if disableReason != "" {
		t.Errorf("expected default empty disable_reason, got %q", disableReason)
	}
	if stateVersion != 1 {
		t.Errorf("expected default state_version 1, got %d", stateVersion)
	}
}

func TestMigrateVPNSessionBackend(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	srv, err := db.CreateServer(ctx, &models.Server{Name: "srv1", Host: "198.51.100.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	t1ID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srv,
		InterfaceName: "awg-1",
		PublicKey:     "pub1",
		PrivateKey:    "priv1",
		Endpoint:      "198.51.100.1:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel 1 failed: %v", err)
	}

	t2ID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srv,
		InterfaceName: "awg-2",
		PublicKey:     "pub2",
		PrivateKey:    "priv2",
		Endpoint:      "198.51.100.1:51821",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel 2 failed: %v", err)
	}

	user, err := db.CreateUser(ctx, &models.User{Username: "testmig"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	sess := &models.VPNSession{
		ID:              "sess-mig-1",
		UserID:          user,
		BackendTunnelID: t1ID,
		PeerPublicKey:   "peer-pub-1",
		AssignedIP:      "10.100.0.99",
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, sess); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}

	// 1. Migrate connected session to t2ID: status must remain connected
	if err := db.MigrateVPNSessionBackend(ctx, sess.ID, t2ID); err != nil {
		t.Fatalf("MigrateVPNSessionBackend failed: %v", err)
	}

	migrated, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if migrated.BackendTunnelID != t2ID {
		t.Errorf("BackendTunnelID = %d, want %d", migrated.BackendTunnelID, t2ID)
	}
	if migrated.Status != "connected" {
		t.Errorf("Status = %q, want 'connected'", migrated.Status)
	}

	// 2. Cannot migrate a session that is no longer connected (e.g. disconnected or draining)
	if err := db.CloseVPNSession(ctx, sess.ID); err != nil {
		t.Fatalf("CloseVPNSession failed: %v", err)
	}
	if err := db.MigrateVPNSessionBackend(ctx, sess.ID, t1ID); err == nil {
		t.Fatal("expected error migrating disconnected session, got nil")
	}

	// 3. Cannot migrate non-existent session
	if err := db.MigrateVPNSessionBackend(ctx, "non-existent-id", t1ID); err == nil {
		t.Fatal("expected error migrating non-existent session, got nil")
	}
}

func TestMigrateVPNSessionToActiveTunnel_RejectsStaleAssignments(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	srv, err := db.CreateServer(ctx, &models.Server{Name: "guarded-migration", Host: "198.51.100.2"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{ServerID: srv, InterfaceName: "awg-source", PublicKey: "guard-src", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{ServerID: srv, InterfaceName: "awg-target", PublicKey: "guard-dst", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser(ctx, &models.User{Username: "guarded-migration-user"})
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "guarded-migration-session"
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: sessionID, UserID: user, BackendTunnelID: source,
		PeerPublicKey: "guarded-migration-peer", AssignedIP: "10.100.0.90", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}
	assertSource := func() {
		t.Helper()
		s, err := db.GetVPNSessionByID(ctx, sessionID)
		if err != nil || s == nil {
			t.Fatalf("GetVPNSessionByID failed: %v", err)
		}
		if s.BackendTunnelID != source || s.Status != "connected" {
			t.Fatalf("session unexpectedly reassigned: %+v", s)
		}
	}

	if err := db.UpdateBackendTunnelStatusWithReason(ctx, target, "disabled", models.DisableReasonAdmin, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateVPNSessionToActiveTunnel(ctx, sessionID, source, target); err == nil {
		t.Fatal("expected migration to disabled target to fail")
	}
	assertSource()
	if err := db.UpdateBackendTunnelStatusWithReason(ctx, target, "active", models.DisableReasonAdmin, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateVPNSessionToActiveTunnel(ctx, sessionID, source, target); err == nil {
		t.Fatal("expected migration to admin-disabled target to fail even with active status")
	}
	assertSource()
	if err := db.UpdateBackendTunnelStatusWithReason(ctx, target, "active", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateVPNSessionToActiveTunnel(ctx, sessionID, target, target); err == nil {
		t.Fatal("expected stale source assignment to fail")
	}
	assertSource()
	if err := db.MigrateVPNSessionToActiveTunnel(ctx, sessionID, source, target); err != nil {
		t.Fatalf("migration to active target failed: %v", err)
	}
	s, err := db.GetVPNSessionByID(ctx, sessionID)
	if err != nil || s == nil || s.BackendTunnelID != target || s.Status != "connected" {
		t.Fatalf("session not migrated to active target: session=%+v err=%v", s, err)
	}
	if err := db.CloseVPNSession(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateVPNSessionToActiveTunnel(ctx, sessionID, target, source); err == nil {
		t.Fatal("expected disconnected session migration to fail")
	}
}
