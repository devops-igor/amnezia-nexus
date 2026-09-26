package tunnel

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
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

func TestTunnelPool_TransferConnectionsIfActive(t *testing.T) {
	db := setupTestDB(t)

	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "T1", Host: "10.0.0.1", SSHPort: 22})
	s2ID, _ := db.CreateServer(ctx, &models.Server{Name: "T2", Host: "10.0.0.2", SSHPort: 22})

	t1, err := pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", "pub1")
	if err != nil {
		t.Fatalf("AddTunnel(1) failed: %v", err)
	}
	t2, err := pool.AddTunnel(ctx, s2ID, "2.2.2.2:51820", "pub2")
	if err != nil {
		t.Fatalf("AddTunnel(2) failed: %v", err)
	}

	pool.IncrementConnections(t1.ID)
	pool.IncrementConnections(t1.ID)

	// 1. Successful transfer
	curT2, _ := pool.GetTunnelByID(t2.ID)
	expectedVersion := curT2.StateVersion
	if err := pool.TransferConnectionsIfActive(t1.ID, t2.ID, expectedVersion); err != nil {
		t.Fatalf("TransferConnectionsIfActive failed: %v", err)
	}

	t1Cur, _ := pool.GetTunnelByID(t1.ID)
	t2Cur, _ := pool.GetTunnelByID(t2.ID)
	if t1Cur.ActiveConnections != 1 || t2Cur.ActiveConnections != 1 {
		t.Fatalf("unexpected connection counts: t1=%d, t2=%d", t1Cur.ActiveConnections, t2Cur.ActiveConnections)
	}

	// 2. Target not found
	if err := pool.TransferConnectionsIfActive(t1.ID, 99999); !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("expected ErrTunnelNotFound, got: %v", err)
	}

	// 3. Target not active
	if err := pool.SetTunnelStatus(ctx, s2ID, models.TunnelStatusDegraded, 400); err != nil {
		t.Fatalf("SetTunnelStatus failed: %v", err)
	}
	if err := pool.TransferConnectionsIfActive(t1.ID, t2.ID); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected error for non-active target, got: %v", err)
	}

	// Restore t2 to active
	if err := pool.SetTunnelStatus(ctx, s2ID, models.TunnelStatusActive, 10); err != nil {
		t.Fatalf("SetTunnelStatus failed: %v", err)
	}
	t2Cur, _ = pool.GetTunnelByID(t2.ID)

	// 4. StateVersion mismatch
	oldVersion := t2Cur.StateVersion - 1
	if err := pool.TransferConnectionsIfActive(t1.ID, t2.ID, oldVersion); err == nil || !strings.Contains(err.Error(), "state version mismatch") {
		t.Fatalf("expected error for state version mismatch, got: %v", err)
	}

	// Counters should not have changed during failed attempts
	t1Cur, _ = pool.GetTunnelByID(t1.ID)
	t2Cur, _ = pool.GetTunnelByID(t2.ID)
	if t1Cur.ActiveConnections != 1 || t2Cur.ActiveConnections != 1 {
		t.Fatalf("counters mutated on failed transfer: t1=%d, t2=%d", t1Cur.ActiveConnections, t2Cur.ActiveConnections)
	}

	// 5. Closed pool
	_ = pool.Close()
	if err := pool.TransferConnectionsIfActive(t1.ID, t2.ID); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("expected ErrPoolClosed on closed pool, got: %v", err)
	}
}

func TestTunnelPool_SetTunnelEndpoint(t *testing.T) {
	ctx := context.Background()
	pool := NewPool(nil)

	tun, err := pool.AddTunnel(ctx, 101, "192.168.1.10:51820", "pubkey101")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if tun.Endpoint != "192.168.1.10:51820" {
		t.Fatalf("unexpected initial endpoint: %s", tun.Endpoint)
	}

	newEndpoint := "192.168.1.20:51820"
	if err := pool.SetTunnelEndpoint(ctx, tun.ID, newEndpoint); err != nil {
		t.Fatalf("SetTunnelEndpoint failed: %v", err)
	}

	// Verify retrieval by ID
	byID, err := pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if byID.Endpoint != newEndpoint {
		t.Errorf("GetTunnelByID endpoint = %q, want %q", byID.Endpoint, newEndpoint)
	}
	if byID.StateVersion != 2 {
		t.Errorf("expected StateVersion = 2, got %d", byID.StateVersion)
	}

	// Verify retrieval by ServerID
	byServer, err := pool.GetTunnel(101)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if byServer.Endpoint != newEndpoint {
		t.Errorf("GetTunnel endpoint = %q, want %q", byServer.Endpoint, newEndpoint)
	}

	// Verify non-existent tunnel ID returns ErrTunnelNotFound
	if err := pool.SetTunnelEndpoint(ctx, 99999, newEndpoint); !errors.Is(err, ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound for unknown tunnel, got: %v", err)
	}
}

func TestTunnelPool_SetTunnelEndpoint_FencesInFlightProbe(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "fencing-test-server", Host: "198.51.100.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tun, err := pool.AddTunnel(ctx, sID, "198.51.100.1:51820", "pubkey-fencing")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if tun.StateVersion != 1 {
		t.Fatalf("expected initial StateVersion = 1, got %d", tun.StateVersion)
	}

	expectedVersion := tun.StateVersion // 1
	expectedStatus := tun.Status        // "active"

	newEndpoint := "198.51.100.2:51820"
	if err := pool.SetTunnelEndpoint(ctx, tun.ID, newEndpoint); err != nil {
		t.Fatalf("SetTunnelEndpoint failed: %v", err)
	}

	// Verify tun.StateVersion is incremented to 2 in memory
	curMem, err := pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if curMem.StateVersion != 2 {
		t.Errorf("expected memory StateVersion = 2, got %d", curMem.StateVersion)
	}
	if curMem.Endpoint != newEndpoint {
		t.Errorf("expected memory Endpoint = %q, got %q", newEndpoint, curMem.Endpoint)
	}

	// Verify DB state_version is 2
	curDB, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if curDB.StateVersion != 2 {
		t.Errorf("expected DB StateVersion = 2, got %d", curDB.StateVersion)
	}
	if curDB.Endpoint != newEndpoint {
		t.Errorf("expected DB Endpoint = %q, got %q", newEndpoint, curDB.Endpoint)
	}

	// In-flight probe attempts CompareAndSwapTunnelStatus with expectedVersion = 1
	swapped, err := pool.CompareAndSwapTunnelStatus(ctx, sID, expectedStatus, models.DisableReasonNone, expectedVersion, models.TunnelStatusActive, models.DisableReasonNone, 25)
	if err != nil {
		t.Fatalf("CompareAndSwapTunnelStatus failed: %v", err)
	}
	if swapped {
		t.Fatal("expected CAS to fail due to version mismatch from SetTunnelEndpoint")
	}

	// Assert tunnel status is unchanged
	afterCAS, err := pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID after CAS failed: %v", err)
	}
	if afterCAS.Status != expectedStatus {
		t.Errorf("expected tunnel status unchanged (%q), got %q", expectedStatus, afterCAS.Status)
	}
	if afterCAS.StateVersion != 2 {
		t.Errorf("expected StateVersion to remain 2, got %d", afterCAS.StateVersion)
	}
}

func TestTunnelPool_SetTunnelStatusIfCurrentWithVersion(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "version-status-server", Host: "198.51.100.10"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tun, err := pool.AddTunnel(ctx, sID, "198.51.100.10:51820", "pubkey-version")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if tun.StateVersion != 1 {
		t.Fatalf("expected initial StateVersion = 1, got %d", tun.StateVersion)
	}

	// 1. Zero expectedTunnelID fails with ErrTunnelNotFound
	if err := pool.SetTunnelStatusIfCurrentWithVersion(ctx, sID, 0, 1, models.TunnelStatusActive, 10); !errors.Is(err, ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound on zero expectedTunnelID, got %v", err)
	}

	// 2. Mismatched tunnel ID fails with ErrTunnelNotFound
	if err := pool.SetTunnelStatusIfCurrentWithVersion(ctx, sID, 9999, 1, models.TunnelStatusActive, 10); !errors.Is(err, ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound on wrong expectedTunnelID, got %v", err)
	}

	// 3. Stale expectedVersion returns ErrStaleStateVersion and does not mutate state
	if err := pool.SetTunnelStatusIfCurrentWithVersion(ctx, sID, tun.ID, 999, models.TunnelStatusDegraded, 500); !errors.Is(err, ErrStaleStateVersion) {
		t.Errorf("expected ErrStaleStateVersion on mismatched expectedVersion, got %v", err)
	}
	memCheck, err := pool.GetTunnelByID(tun.ID)
	if err != nil || memCheck.Status != models.TunnelStatusActive || memCheck.StateVersion != 1 {
		t.Fatalf("pool state mutated after stale version update: %+v", memCheck)
	}

	// 4. Matching expectedVersion succeeds and increments StateVersion in memory and DB
	if err := pool.SetTunnelStatusIfCurrentWithVersion(ctx, sID, tun.ID, 1, models.TunnelStatusDegraded, 150); err != nil {
		t.Fatalf("SetTunnelStatusIfCurrentWithVersion failed on matching version: %v", err)
	}
	memAfter, err := pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if memAfter.Status != models.TunnelStatusDegraded || memAfter.LatencyMS != 150 || memAfter.StateVersion != 2 {
		t.Errorf("unexpected pool state after valid version update: %+v", memAfter)
	}
	dbAfter, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbAfter.Status != models.TunnelStatusDegraded || dbAfter.LatencyMS != 150 || dbAfter.StateVersion != 2 {
		t.Errorf("unexpected DB state after valid version update: %+v", dbAfter)
	}

	// 5. Subsequent update with previous version (1) now fails as stale
	if err := pool.SetTunnelStatusIfCurrentWithVersion(ctx, sID, tun.ID, 1, models.TunnelStatusActive, 10); !errors.Is(err, ErrStaleStateVersion) {
		t.Errorf("expected ErrStaleStateVersion on old version 1, got %v", err)
	}
}

func TestTunnelPool_AddTunnel_ExistingTunnel_PersistenceFailureLeavesMemoryUntouched(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "err-persist-server", Host: "198.51.100.20"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	initialEndpoint := "198.51.100.20:51820"
	initialPubKey := "initial-server-pubkey"

	tun, err := pool.AddTunnel(ctx, sID, initialEndpoint, initialPubKey)
	if err != nil {
		t.Fatalf("initial AddTunnel failed: %v", err)
	}

	initialPrivKey := tun.PrivateKey
	initialProbePrivKey := tun.ProbePrivateKey
	if initialPrivKey == "" || initialProbePrivKey == "" {
		t.Fatalf("expected non-empty initial keys: priv=%q, probePriv=%q", initialPrivKey, initialProbePrivKey)
	}

	// 1. Force UpdateBackendTunnel failure via canceled context
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	attemptedEndpoint := "198.51.100.20:51822"
	attemptedPubKey := "attempted-server-pubkey"

	_, err = pool.AddTunnel(canceledCtx, sID, attemptedEndpoint, attemptedPubKey)
	if err == nil {
		t.Fatal("expected AddTunnel to fail with canceled context, got nil")
	}
	if !strings.Contains(err.Error(), "failed to persist backend tunnel updates") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Verify in-memory state remains untouched
	memTun, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if memTun.Endpoint != initialEndpoint {
		t.Errorf("in-memory endpoint mutated on persistence failure: got %q, want %q", memTun.Endpoint, initialEndpoint)
	}
	if memTun.PublicKey != initialPubKey {
		t.Errorf("in-memory public key mutated on persistence failure: got %q, want %q", memTun.PublicKey, initialPubKey)
	}
	if memTun.PrivateKey != initialPrivKey {
		t.Errorf("in-memory private key mutated on persistence failure: got %q, want %q", memTun.PrivateKey, initialPrivKey)
	}
	if memTun.ProbePrivateKey != initialProbePrivKey {
		t.Errorf("in-memory probe private key mutated on persistence failure: got %q, want %q", memTun.ProbePrivateKey, initialProbePrivKey)
	}

	// Verify DB record also remains untouched
	dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Endpoint != initialEndpoint {
		t.Errorf("DB endpoint mutated on persistence failure: got %q, want %q", dbTun.Endpoint, initialEndpoint)
	}
	if dbTun.PublicKey != initialPubKey {
		t.Errorf("DB public key mutated on persistence failure: got %q, want %q", dbTun.PublicKey, initialPubKey)
	}
}

func TestTunnelPool_AddTunnel_ExistingTunnel_PersistenceSuccessSurvivesSyncFromDB(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "success-persist-server", Host: "198.51.100.21"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	initialEndpoint := "198.51.100.21:51820"
	initialPubKey := "initial-server-pubkey"

	tun, err := pool.AddTunnel(ctx, sID, initialEndpoint, initialPubKey)
	if err != nil {
		t.Fatalf("initial AddTunnel failed: %v", err)
	}
	privKey := tun.PrivateKey
	probePrivKey := tun.ProbePrivateKey

	// 1. Update endpoint and pubkey
	updatedEndpoint := "198.51.100.21:51825"
	updatedPubKey := "updated-server-pubkey"

	updatedTun, err := pool.AddTunnel(ctx, sID, updatedEndpoint, updatedPubKey)
	if err != nil {
		t.Fatalf("AddTunnel update failed: %v", err)
	}
	if updatedTun.Endpoint != updatedEndpoint || updatedTun.PublicKey != updatedPubKey {
		t.Errorf("AddTunnel update mismatch: endpoint=%q, pubkey=%q", updatedTun.Endpoint, updatedTun.PublicKey)
	}
	if updatedTun.PrivateKey != privKey || updatedTun.ProbePrivateKey != probePrivKey {
		t.Errorf("keys should not change during normal update")
	}

	// 2. Update endpoint with empty pubkey preserves existing pubkey
	thirdEndpoint := "198.51.100.21:51830"
	thirdTun, err := pool.AddTunnel(ctx, sID, thirdEndpoint, "")
	if err != nil {
		t.Fatalf("AddTunnel with empty pubkey failed: %v", err)
	}
	if thirdTun.Endpoint != thirdEndpoint {
		t.Errorf("endpoint mismatch: got %q, want %q", thirdTun.Endpoint, thirdEndpoint)
	}
	if thirdTun.PublicKey != updatedPubKey {
		t.Errorf("empty pubkey should preserve existing pubkey: got %q, want %q", thirdTun.PublicKey, updatedPubKey)
	}

	// 3. Fresh pool loads updated values from DB
	freshPool := NewPool(db)
	if err := freshPool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	reloadedTun, err := freshPool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel on fresh pool failed: %v", err)
	}
	if reloadedTun.Endpoint != thirdEndpoint {
		t.Errorf("reloaded endpoint mismatch: got %q, want %q", reloadedTun.Endpoint, thirdEndpoint)
	}
	if reloadedTun.PublicKey != updatedPubKey {
		t.Errorf("reloaded public key mismatch: got %q, want %q", reloadedTun.PublicKey, updatedPubKey)
	}
	if reloadedTun.PrivateKey != privKey {
		t.Errorf("reloaded private key mismatch: got %q, want %q", reloadedTun.PrivateKey, privKey)
	}
	if reloadedTun.ProbePrivateKey != probePrivKey {
		t.Errorf("reloaded probe private key mismatch: got %q, want %q", reloadedTun.ProbePrivateKey, probePrivKey)
	}
}

func TestTunnelPool_AddTunnel_ExistingTunnel_KeyGenerationFailurePropagation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "keygen-fail-server", Host: "198.51.100.22"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	origEndpoint := "198.51.100.22:51820"
	tun, err := pool.AddTunnel(ctx, sID, origEndpoint, "orig-pub")
	if err != nil {
		t.Fatalf("initial AddTunnel failed: %v", err)
	}

	// Case A: Missing PrivateKey and keygen fails
	tun.PrivateKey = ""
	pool.SetGenerateKeyPairForTest(func() (string, string, error) {
		return "", "", errors.New("entropy source depleted")
	})

	_, err = pool.AddTunnel(ctx, sID, "198.51.100.22:51829", "attempted-pub")
	if err == nil {
		t.Fatal("expected error on failed backend private key generation, got nil")
	}
	if !strings.Contains(err.Error(), "failed to generate backend private key") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Verify existing tunnel was not mutated
	memTun, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if memTun.Endpoint != origEndpoint {
		t.Errorf("endpoint mutated on keygen failure: got %q, want %q", memTun.Endpoint, origEndpoint)
	}
	if memTun.PublicKey != "orig-pub" {
		t.Errorf("public key mutated on keygen failure: got %q, want %q", memTun.PublicKey, "orig-pub")
	}

	// Case B: Valid PrivateKey, missing ProbePrivateKey, and keygen fails
	tun.PrivateKey = "existing-valid-private-key"
	tun.ProbePrivateKey = ""

	_, err = pool.AddTunnel(ctx, sID, "198.51.100.22:51839", "attempted-pub-2")
	if err == nil {
		t.Fatal("expected error on failed probe private key generation, got nil")
	}
	if !strings.Contains(err.Error(), "failed to generate probe private key") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Verify existing tunnel was not mutated
	memTun, err = pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if memTun.Endpoint != origEndpoint {
		t.Errorf("endpoint mutated on probe keygen failure: got %q, want %q", memTun.Endpoint, origEndpoint)
	}
	if memTun.PublicKey != "orig-pub" {
		t.Errorf("public key mutated on probe keygen failure: got %q, want %q", memTun.PublicKey, "orig-pub")
	}
}

func TestTunnelPool_AddTunnel_ExistingTunnel_NilDB(t *testing.T) {
	ctx := context.Background()
	pool := NewPool(nil)

	sID := int64(100)
	tun, err := pool.AddTunnel(ctx, sID, "198.51.100.30:51820", "pub1")
	if err != nil {
		t.Fatalf("AddTunnel on nil DB failed: %v", err)
	}

	updated, err := pool.AddTunnel(ctx, sID, "198.51.100.30:51821", "pub2")
	if err != nil {
		t.Fatalf("AddTunnel update on nil DB failed: %v", err)
	}
	if updated.Endpoint != "198.51.100.30:51821" || updated.PublicKey != "pub2" {
		t.Errorf("AddTunnel update mismatch: %+v", updated)
	}
	if updated.ID != tun.ID {
		t.Errorf("tunnel ID should match: %d vs %d", updated.ID, tun.ID)
	}
}

func TestPoolAddTunnel_ExistingMissingDBRowFailsWithoutMemoryMutation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "missing-db-row-server", Host: "198.51.100.25"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	oldEndpoint := "198.51.100.25:51820"
	oldPubKey := "old-server-pubkey"

	tun, err := pool.AddTunnel(ctx, serverID, oldEndpoint, oldPubKey)
	if err != nil {
		t.Fatalf("initial AddTunnel failed: %v", err)
	}

	// Delete the DB row directly, leaving the in-memory pool entry intact
	if err := db.DeleteBackendTunnel(ctx, tun.ID); err != nil {
		t.Fatalf("DeleteBackendTunnel failed: %v", err)
	}

	newEndpoint := "198.51.100.25:51822"
	newPubKey := "new-server-pubkey"

	_, err = pool.AddTunnel(ctx, serverID, newEndpoint, newPubKey)
	if err == nil {
		t.Fatal("expected AddTunnel to fail when DB row is missing, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error containing 'not found', got: %v", err)
	}

	// Verify pool entry retains oldEndpoint and oldPubKey
	memTun, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if memTun.Endpoint != oldEndpoint {
		t.Errorf("in-memory endpoint mutated on missing DB row: got %q, want %q", memTun.Endpoint, oldEndpoint)
	}
	if memTun.PublicKey != oldPubKey {
		t.Errorf("in-memory public key mutated on missing DB row: got %q, want %q", memTun.PublicKey, oldPubKey)
	}

	// Verify DB row remains absent (db.GetBackendTunnel returns nil)
	dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun != nil {
		t.Errorf("expected DB row to remain absent, got %+v", dbTun)
	}
}
