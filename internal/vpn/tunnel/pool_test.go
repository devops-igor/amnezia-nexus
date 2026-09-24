package tunnel

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestPoolProbeStatusWritesRejectReplacedTunnel(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Recreated Host", Host: "192.0.2.70"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := pool.AddTunnel(ctx, serverID, "192.0.2.70:51820", "old-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.RemoveTunnel(ctx, serverID); err != nil {
		t.Fatal(err)
	}
	replacement, err := pool.AddTunnel(ctx, serverID, "192.0.2.70:51821", "new-key")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID == old.ID {
		t.Fatal("replacement reused old tunnel ID")
	}
	before := *replacement
	if err := pool.SetTunnelStatusIfCurrent(ctx, serverID, old.ID, models.TunnelStatusDegraded, 900); !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("stale status write: got %v, want ErrTunnelNotFound", err)
	}
	swapped, err := pool.CompareAndSwapTunnelStatusForTunnel(ctx, serverID, old.ID,
		replacement.Status, replacement.DisableReason, replacement.StateVersion,
		models.TunnelStatusDisabled, models.DisableReasonHealth, 0)
	if swapped || !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("stale status CAS: swapped=%v err=%v, want false, ErrTunnelNotFound", swapped, err)
	}
	after, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != before.Status || after.DisableReason != before.DisableReason ||
		after.StateVersion != before.StateVersion || after.LatencyMS != before.LatencyMS {
		t.Fatalf("stale probe modified replacement: %+v", after)
	}
}

func setupTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_vpn_tunnel.db")
	db, err := database.Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func TestGenerateCurve25519KeyPair(t *testing.T) {
	pub, priv, err := GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateCurve25519KeyPair failed: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Errorf("empty keys generated: pub=%s, priv=%s", pub, priv)
	}

	derivedPub, err := DeriveClientPublicKey(priv)
	if err != nil {
		t.Fatalf("DeriveClientPublicKey failed: %v", err)
	}
	if derivedPub != pub {
		t.Errorf("DeriveClientPublicKey mismatch: got %s, want %s", derivedPub, pub)
	}

	tunnel := &models.BackendTunnel{PrivateKey: priv}
	tPub, err := ClientPublicKey(tunnel)
	if err != nil || tPub != pub {
		t.Errorf("ClientPublicKey mismatch: got %s (err=%v), want %s", tPub, err, pub)
	}

	if _, err := ClientPublicKey(nil); err == nil {
		t.Errorf("expected error for nil tunnel")
	}
}

func TestTunnelPoolCRUD(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "1.1.1.1"})
	s2ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 2", Host: "2.2.2.2"})

	// Validation
	if _, err := pool.AddTunnel(ctx, 0, "1.1.1.1:51820", ""); err == nil {
		t.Errorf("expected error for serverID <= 0")
	}
	if _, err := pool.AddTunnel(ctx, s1ID, "", ""); err == nil {
		t.Errorf("expected error for empty endpoint")
	}

	// 1. Add Tunnels
	t1, err := pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", "pubkey1")
	if err != nil {
		t.Fatalf("AddTunnel 1 failed: %v", err)
	}
	if t1.ServerID != s1ID || t1.InterfaceName != "awg-be-1" || t1.Status != "active" {
		t.Errorf("invalid t1: %+v", t1)
	}

	t2, err := pool.AddTunnel(ctx, s2ID, "2.2.2.2:51820", "")
	if err != nil {
		t.Fatalf("AddTunnel 2 failed: %v", err)
	}
	if t2.PublicKey == "" || t2.PrivateKey == "" {
		t.Errorf("expected auto-generated keys for t2: %+v", t2)
	}

	// Repeat Add updates endpoint
	t1Updated, err := pool.AddTunnel(ctx, s1ID, "1.1.1.1:51822", "pubkey1-new")
	if err != nil || t1Updated.Endpoint != "1.1.1.1:51822" || t1Updated.PublicKey != "pubkey1-new" {
		t.Errorf("repeat AddTunnel mismatch: %+v, err: %v", t1Updated, err)
	}

	// Lookups
	byServer, err := pool.GetTunnel(s1ID)
	if err != nil || byServer.ID != t1.ID {
		t.Errorf("GetTunnel mismatch: %+v, err: %v", byServer, err)
	}
	if _, err := pool.GetTunnel(9999); err != ErrTunnelNotFound {
		t.Errorf("expected ErrTunnelNotFound for non-existent server ID, got %v", err)
	}

	byID, err := pool.GetTunnelByID(t1.ID)
	if err != nil || byID.ServerID != s1ID {
		t.Errorf("GetTunnelByID mismatch: %+v, err: %v", byID, err)
	}
	if _, err := pool.GetTunnelByID(9999); err != ErrTunnelNotFound {
		t.Errorf("expected ErrTunnelNotFound for non-existent tunnel ID, got %v", err)
	}

	byIf, err := pool.GetTunnelByInterface("awg-be-1")
	if err != nil || byIf.ID != t1.ID {
		t.Errorf("GetTunnelByInterface mismatch: %+v, err: %v", byIf, err)
	}
	if _, err := pool.GetTunnelByInterface("non-existent"); err != ErrTunnelNotFound {
		t.Errorf("expected ErrTunnelNotFound for non-existent interface, got %v", err)
	}

	// Remove tunnel
	if err := pool.RemoveTunnel(ctx, s1ID); err != nil {
		t.Fatalf("RemoveTunnel failed: %v", err)
	}
	if _, err := pool.GetTunnel(s1ID); err != ErrTunnelNotFound {
		t.Errorf("expected tunnel to be removed")
	}
	if err := pool.RemoveTunnel(ctx, 9999); err != ErrTunnelNotFound {
		t.Errorf("expected ErrTunnelNotFound on RemoveTunnel non-existent, got %v", err)
	}
}

func TestTunnelPoolStatusAndConnections(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "1.1.1.1"})
	s2ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 2", Host: "2.2.2.2"})

	_, _ = pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", "pub1")
	t2, _ := pool.AddTunnel(ctx, s2ID, "2.2.2.2:51820", "pub2")

	// Lists
	if len(pool.ListTunnels()) != 2 || len(pool.GetActiveTunnels()) != 2 {
		t.Errorf("expected 2 tunnels in pool")
	}

	// Status and Latency update
	if err := pool.SetTunnelStatus(ctx, s1ID, "degraded", 600); err != nil {
		t.Fatalf("SetTunnelStatus failed: %v", err)
	}
	if err := pool.SetTunnelStatus(ctx, 9999, "active", 10); err != ErrTunnelNotFound {
		t.Errorf("expected ErrTunnelNotFound on SetTunnelStatus non-existent, got %v", err)
	}

	byServer, _ := pool.GetTunnel(s1ID)
	if byServer.Status != "degraded" || byServer.LatencyMS != 600 {
		t.Errorf("status mismatch: status=%s, lat=%d", byServer.Status, byServer.LatencyMS)
	}

	activeAfterDegrade := pool.GetActiveTunnels()
	if len(activeAfterDegrade) != 1 || activeAfterDegrade[0].ServerID != s2ID {
		t.Errorf("expected 1 active tunnel after degrade, got %d", len(activeAfterDegrade))
	}

	// Connection counts
	pool.IncrementConnections(t2.ID)
	pool.IncrementConnections(t2.ID)
	byServer2, _ := pool.GetTunnel(s2ID)
	if byServer2.ActiveConnections != 2 {
		t.Errorf("expected 2 active connections, got %d", byServer2.ActiveConnections)
	}

	pool.DecrementConnections(t2.ID)
	byServer2, _ = pool.GetTunnel(s2ID)
	if byServer2.ActiveConnections != 1 {
		t.Errorf("expected 1 active connection, got %d", byServer2.ActiveConnections)
	}

	pool.DecrementConnections(t2.ID)
	pool.DecrementConnections(t2.ID) // Decrement past zero
	byServer2, _ = pool.GetTunnel(s2ID)
	if byServer2.ActiveConnections != 0 {
		t.Errorf("expected 0 active connections, got %d", byServer2.ActiveConnections)
	}

	// SyncFromDB
	freshPool := NewPool(db)
	if err := freshPool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}
	if len(freshPool.ListTunnels()) != 2 {
		t.Errorf("SyncFromDB mismatch")
	}

	// Close
	if err := pool.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// AddTunnel on closed pool returns ErrPoolClosed
	if _, err := pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", ""); err != ErrPoolClosed {
		t.Errorf("expected ErrPoolClosed on closed pool, got %v", err)
	}
}

// TestProbeKeySeparationFromDataKey is the issue-#43 pool-level invariant:
// the dedicated probe identity must differ from the data device identity for
// every tunnel, and ClientPublicKey/DataDevicePublicKey must derive them from
// the corresponding private keys.
func TestProbeKeySeparationFromDataKey(t *testing.T) {
	priv := "W5vHyr9JHfc+7H5cRgeNSA4XaWKY9zpaBAIu67DJmWU="
	tun := &models.BackendTunnel{
		PrivateKey:      priv,
		ProbePrivateKey: priv, // legacy collision — must be detected
	}

	probePub, err := ClientPublicKey(tun)
	if err != nil {
		t.Fatalf("ClientPublicKey failed: %v", err)
	}
	dataPub, err := DataDevicePublicKey(tun)
	if err != nil {
		t.Fatalf("DataDevicePublicKey failed: %v", err)
	}
	if probePub != dataPub {
		t.Fatalf("expected identical derivation for identical keys, got %s vs %s", probePub, dataPub)
	}

	// Now a properly separated tunnel: identities must diverge.
	pub, sk, err := GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateCurve25519KeyPair failed: %v", err)
	}
	tun.ProbePrivateKey = sk
	probePub, err = ClientPublicKey(tun)
	if err != nil {
		t.Fatalf("ClientPublicKey failed: %v", err)
	}
	if probePub != pub {
		t.Errorf("ClientPublicKey = %s, want derive(ProbePrivateKey) = %s", probePub, pub)
	}
	dataPub, err = DataDevicePublicKey(tun)
	if err != nil {
		t.Fatalf("DataDevicePublicKey failed: %v", err)
	}
	if probePub == dataPub {
		t.Error("probe identity must differ from data identity when keys differ")
	}
	if probePub == priv || dataPub == priv {
		t.Error("derived public keys must never equal a private key")
	}
}

// TestProbeKeySurvivesAddTunnelAndSyncRoundTrip proves the dedicated probe key
// survives the full persistence cycle (issue #43): AddTunnel generates it,
// UpdateBackendTunnel encrypts it at rest (Fernet), and a fresh pool's
// SyncFromDB decrypts back to the exact same key — not a regeneration.
func TestProbeKeySurvivesAddTunnelAndSyncRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "probe-rt-server", Host: "203.0.113.9"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tun, err := pool.AddTunnel(ctx, sID, "203.0.113.9:51820", "server-pub")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}
	if tun.ProbePrivateKey == "" {
		t.Fatal("AddTunnel must generate a dedicated probe private key")
	}
	if tun.ProbePrivateKey == tun.PrivateKey {
		t.Fatal("probe key must differ from data private key at creation")
	}
	probeKeyAtCreation := tun.ProbePrivateKey

	// Simulate an EnableBackend-on-existing round: AddTunnel again for the
	// same server must keep the tunnel AND its probe key stable.
	tun2, err := pool.AddTunnel(ctx, sID, "203.0.113.9:51820", "server-pub")
	if err != nil {
		t.Fatalf("second AddTunnel failed: %v", err)
	}
	if tun2.ProbePrivateKey != probeKeyAtCreation {
		t.Error("AddTunnel on existing tunnel must not rotate the probe key")
	}

	// AddTunnel persists probe_private_key; a fresh pool must decrypt the
	// exact same key back from the DB (Fernet round-trip, no regeneration).
	freshPool := NewPool(db)
	if err := freshPool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}
	restored, err := freshPool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel on fresh pool failed: %v", err)
	}
	if restored.ProbePrivateKey != probeKeyAtCreation {
		t.Errorf("probe key not stable across DB round-trip:\n  at creation: %s\n  after sync:  %s", probeKeyAtCreation, restored.ProbePrivateKey)
	}
	if restored.ProbePrivateKey == restored.PrivateKey {
		t.Error("restored probe key must still differ from the data private key")
	}
}

func TestTunnelPool_SyncFromDB_LoadsDisableReasonAndStateVersion(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "sync-test-server", Host: "192.0.2.10"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Insert tunnel directly in DB with explicit disable_reason and state_version
	now := time.Now().UTC()
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:        sID,
		InterfaceName:   "awg-be-10",
		PublicKey:       "sync-pubkey",
		PrivateKey:      "sync-privkey",
		Endpoint:        "192.0.2.10:51820",
		Status:          models.TunnelStatusDisabled,
		DisableReason:   models.DisableReasonHealth,
		StateVersion:    7,
		CreatedAt:       now,
		LastHealthCheck: &now,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	freshPool := NewPool(db)
	if err := freshPool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun, err := freshPool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tun.ID != tID {
		t.Errorf("expected tunnel ID %d, got %d", tID, tun.ID)
	}
	if tun.Status != models.TunnelStatusDisabled {
		t.Errorf("expected status %q, got %q", models.TunnelStatusDisabled, tun.Status)
	}
	if tun.DisableReason != models.DisableReasonHealth {
		t.Errorf("expected disable_reason %q, got %q", models.DisableReasonHealth, tun.DisableReason)
	}
	if tun.StateVersion != 7 {
		t.Errorf("expected state_version 7, got %d", tun.StateVersion)
	}
}

func TestTunnelPool_SetTunnelStatus_ErrorPropagationAndStateIntegrity(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "err-prop-server", Host: "192.0.2.11"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tun, err := pool.AddTunnel(ctx, sID, "192.0.2.11:51820", "pubkey-11")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}
	if tun.Status != models.TunnelStatusActive || tun.StateVersion != 1 {
		t.Fatalf("initial state unexpected: status=%s, version=%d", tun.Status, tun.StateVersion)
	}

	// 1. Simulate DB failure via canceled context: error must be propagated and in-memory state unchanged
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	err = pool.SetTunnelStatus(canceledCtx, sID, models.TunnelStatusDegraded, 200)
	if err == nil {
		t.Fatal("expected SetTunnelStatus to return error on canceled context, got nil")
	}

	cur, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusActive {
		t.Errorf("expected status to remain active after DB error, got %q", cur.Status)
	}
	if cur.LatencyMS != 10 {
		t.Errorf("expected latency to remain 10 after DB error, got %d", cur.LatencyMS)
	}
	if cur.StateVersion != 1 {
		t.Errorf("expected state_version to remain 1 after DB error, got %d", cur.StateVersion)
	}

	// 2. Successful update with valid context updates memory and DB, bumping state_version
	if err := pool.SetTunnelStatus(ctx, sID, models.TunnelStatusDegraded, 200); err != nil {
		t.Fatalf("SetTunnelStatus with valid context failed: %v", err)
	}

	cur, err = pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel after successful update failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDegraded {
		t.Errorf("expected status degraded, got %q", cur.Status)
	}
	if cur.LatencyMS != 200 {
		t.Errorf("expected latency 200, got %d", cur.LatencyMS)
	}
	if cur.StateVersion != 2 {
		t.Errorf("expected state_version 2, got %d", cur.StateVersion)
	}

	// Verify DB record matches
	dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil || dbTun == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Status != models.TunnelStatusDegraded || dbTun.StateVersion != 2 {
		t.Errorf("DB record mismatch: status=%q, version=%d", dbTun.Status, dbTun.StateVersion)
	}
}

func TestTunnelPool_SetTunnelStatusWithReason(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "reason-test-server", Host: "192.0.2.12"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tun, err := pool.AddTunnel(ctx, sID, "192.0.2.12:51820", "pubkey-12")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// 1. Set disabled with health reason
	if err := pool.SetTunnelStatusWithReason(ctx, sID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusDisabled || cur.DisableReason != models.DisableReasonHealth || cur.StateVersion != 2 {
		t.Errorf("unexpected pool state after SetTunnelStatusWithReason: %+v", cur)
	}

	dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil || dbTun == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Status != models.TunnelStatusDisabled || dbTun.DisableReason != models.DisableReasonHealth || dbTun.StateVersion != 2 {
		t.Errorf("unexpected DB state after SetTunnelStatusWithReason: %+v", dbTun)
	}

	// 2. Set active via SetTunnelStatus: must clear DisableReason to empty string and bump version
	if err := pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 10); err != nil {
		t.Fatalf("SetTunnelStatus active failed: %v", err)
	}

	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusActive || cur.DisableReason != models.DisableReasonNone || cur.StateVersion != 3 {
		t.Errorf("unexpected pool state after SetTunnelStatus active: status=%q, reason=%q, version=%d", cur.Status, cur.DisableReason, cur.StateVersion)
	}

	dbTun, _ = db.GetBackendTunnel(ctx, tun.ID)
	if dbTun.Status != models.TunnelStatusActive || dbTun.DisableReason != models.DisableReasonNone || dbTun.StateVersion != 3 {
		t.Errorf("unexpected DB state after SetTunnelStatus active: status=%q, reason=%q, version=%d", dbTun.Status, dbTun.DisableReason, dbTun.StateVersion)
	}

	// 3. Error propagation on DB failure
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	err = pool.SetTunnelStatusWithReason(canceledCtx, sID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0)
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusActive || cur.StateVersion != 3 {
		t.Errorf("expected pool state unchanged on DB failure: status=%q, version=%d", cur.Status, cur.StateVersion)
	}
}

func TestTunnelPool_CompareAndSwapTunnelStatus(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "cas-test-server", Host: "192.0.2.13"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tun, err := pool.AddTunnel(ctx, sID, "192.0.2.13:51820", "pubkey-13")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if err := pool.SetTunnelStatusWithReason(ctx, sID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	// Current state: status=disabled, reason=health, version=2

	// 1. Non-existent server ID returns ErrTunnelNotFound
	if _, err := pool.CompareAndSwapTunnelStatus(ctx, 99999, models.TunnelStatusDisabled, models.DisableReasonHealth, 2, models.TunnelStatusActive, models.DisableReasonNone, 10); err != ErrTunnelNotFound {
		t.Errorf("expected ErrTunnelNotFound for unknown server, got %v", err)
	}

	// 2. Mismatched version fails
	swapped, err := pool.CompareAndSwapTunnelStatus(ctx, sID, models.TunnelStatusDisabled, models.DisableReasonHealth, 1, models.TunnelStatusActive, models.DisableReasonNone, 10)
	if err != nil {
		t.Fatalf("CAS returned error: %v", err)
	}
	if swapped {
		t.Fatal("expected CAS to fail on stale version 1")
	}

	// 3. Mismatched reason fails
	swapped, err = pool.CompareAndSwapTunnelStatus(ctx, sID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 2, models.TunnelStatusActive, models.DisableReasonNone, 10)
	if err != nil {
		t.Fatalf("CAS returned error: %v", err)
	}
	if swapped {
		t.Fatal("expected CAS to fail on mismatched reason admin")
	}

	// 4. Mismatched status fails
	swapped, err = pool.CompareAndSwapTunnelStatus(ctx, sID, models.TunnelStatusActive, models.DisableReasonHealth, 2, models.TunnelStatusActive, models.DisableReasonNone, 10)
	if err != nil {
		t.Fatalf("CAS returned error: %v", err)
	}
	if swapped {
		t.Fatal("expected CAS to fail on mismatched status active")
	}

	// Assert in-memory state is still untouched
	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusDisabled || cur.DisableReason != models.DisableReasonHealth || cur.StateVersion != 2 {
		t.Fatalf("pool state modified despite failed CAS attempts: %+v", cur)
	}

	// 5. Successful CAS update
	swapped, err = pool.CompareAndSwapTunnelStatus(ctx, sID, models.TunnelStatusDisabled, models.DisableReasonHealth, 2, models.TunnelStatusActive, models.DisableReasonNone, 15)
	if err != nil {
		t.Fatalf("CAS returned error: %v", err)
	}
	if !swapped {
		t.Fatal("expected CAS to succeed on matching state")
	}

	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusActive || cur.DisableReason != models.DisableReasonNone || cur.StateVersion != 3 || cur.LatencyMS != 15 {
		t.Errorf("unexpected pool state after successful CAS: %+v", cur)
	}

	dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil || dbTun == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Status != models.TunnelStatusActive || dbTun.DisableReason != models.DisableReasonNone || dbTun.StateVersion != 3 || dbTun.LatencyMS != 15 {
		t.Errorf("unexpected DB state after successful CAS: %+v", dbTun)
	}

	// 6. DB error during CAS propagates error and leaves state untouched
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	swapped, err = pool.CompareAndSwapTunnelStatus(canceledCtx, sID, models.TunnelStatusActive, models.DisableReasonNone, 3, models.TunnelStatusDisabled, models.DisableReasonHealth, 0)
	if err == nil {
		t.Fatal("expected error on canceled context CAS, got nil")
	}
	if swapped {
		t.Fatal("expected swapped to be false on error")
	}
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusActive || cur.StateVersion != 3 {
		t.Errorf("pool state modified despite error during CAS: %+v", cur)
	}
}
