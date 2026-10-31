//go:build with_utls

package vpn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// TestDeleteBackend_ConcurrentEnablePreservesNewBackend verifies finding F5:
// When a concurrent EnableBackend runs while sweepLeftoverBackendLocked is executing
// (after releasing s.mu), the defensive sweep must refuse to delete the newly registered
// backend row from SQLite and pool.
func TestDeleteBackend_ConcurrentEnablePreservesNewBackend(t *testing.T) {
	db := setupTestDB(t)
	svc, s1ID, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	origTun, err := svc.pool.GetTunnel(s1ID)
	if err != nil || origTun == nil {
		t.Fatalf("expected initial tunnel for server %d: %v", s1ID, err)
	}

	var recreatedTunID int64
	svc.SetSweepPreLookupHookForTest(func() {
		// Concurrent enable runs while s.mu is unlocked during the defensive sweep.
		if enableErr := svc.EnableBackend(ctx, s1ID); enableErr != nil {
			t.Errorf("concurrent EnableBackend failed: %v", enableErr)
			return
		}
		newTun, getErr := svc.pool.GetTunnel(s1ID)
		if getErr != nil || newTun == nil {
			t.Errorf("failed to retrieve recreated tunnel from pool: %v", getErr)
			return
		}
		recreatedTunID = newTun.ID
	})
	defer svc.SetSweepPreLookupHookForTest(nil)

	if delErr := svc.DeleteBackend(ctx, s1ID); delErr != nil {
		t.Fatalf("DeleteBackend failed: %v", delErr)
	}

	if recreatedTunID == 0 {
		t.Fatal("concurrent EnableBackend did not run or failed to assign tunnel ID")
	}
	if recreatedTunID == origTun.ID {
		t.Fatalf("expected new tunnel ID for replacement backend, got same ID %d", recreatedTunID)
	}

	// 1. In-memory pool must retain the new tunnel.
	liveTun, err := svc.pool.GetTunnel(s1ID)
	if err != nil || liveTun == nil {
		t.Fatalf("replacement backend missing from pool after DeleteBackend: %v", err)
	}
	if liveTun.ID != recreatedTunID {
		t.Errorf("pool tunnel ID = %d, want %d", liveTun.ID, recreatedTunID)
	}

	// 2. Database registration must be preserved (not deleted by defensive sweep).
	dbRow, err := db.GetBackendTunnelByServerID(ctx, s1ID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbRow == nil {
		t.Fatalf("replacement backend row %d was deleted from SQLite by defensive sweep", recreatedTunID)
	}
	if dbRow.ID != recreatedTunID {
		t.Errorf("durable backend row ID = %d, want %d", dbRow.ID, recreatedTunID)
	}
}

// TestDeleteBackend_ConcurrentEnableWithConfig_MultiProtocolPreservesNewRegistration verifies finding F5
// specifically with EnableBackendWithConfig and multi-protocol proxy backend options.
func TestDeleteBackend_ConcurrentEnableWithConfig_MultiProtocolPreservesNewRegistration(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(cfg *models.VPNConfig) {
		cfg.EnableMultiProtocolBackends = true
	})
	ctx := context.Background()

	naiveRaw, err := json.Marshal(models.NaiveProxyParams{
		Domain:   "example.com",
		Username: "alice",
		Password: "secret-password",
	})
	if err != nil {
		t.Fatalf("failed to marshal naive params: %v", err)
	}

	serverID, err := db.CreateServer(ctx, &models.Server{
		Name: "naive-concurrency-server",
		Host: "198.51.100.99",
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Initial enablement
	err = svc.EnableBackendWithConfig(ctx, serverID, tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolNaive,
		ProtocolParams: naiveRaw,
	})
	if err != nil {
		t.Fatalf("initial EnableBackendWithConfig failed: %v", err)
	}

	origTun, err := svc.pool.GetTunnel(serverID)
	if err != nil || origTun == nil {
		t.Fatalf("expected initial tunnel in pool: %v", err)
	}

	var recreatedTunID int64
	svc.SetSweepPreLookupHookForTest(func() {
		// Concurrent EnableBackendWithConfig establishing replacement proxy tunnel
		enableErr := svc.EnableBackendWithConfig(ctx, serverID, tunnel.BackendTunnelOptions{
			Protocol:       models.ProtocolNaive,
			ProtocolParams: naiveRaw,
		})
		if enableErr != nil {
			t.Errorf("concurrent EnableBackendWithConfig failed: %v", enableErr)
			return
		}
		newTun, getErr := svc.pool.GetTunnel(serverID)
		if getErr != nil || newTun == nil {
			t.Errorf("failed to retrieve recreated tunnel from pool: %v", getErr)
			return
		}
		recreatedTunID = newTun.ID
	})
	defer svc.SetSweepPreLookupHookForTest(nil)

	if delErr := svc.DeleteBackend(ctx, serverID); delErr != nil {
		t.Fatalf("DeleteBackend failed: %v", delErr)
	}

	if recreatedTunID == 0 {
		t.Fatal("concurrent EnableBackendWithConfig did not execute")
	}

	// Replacement proxy backend must remain in pool and database
	liveTun, err := svc.pool.GetTunnel(serverID)
	if err != nil || liveTun == nil {
		t.Fatalf("replacement proxy tunnel missing from pool: %v", err)
	}
	if liveTun.ID != recreatedTunID {
		t.Errorf("pool proxy tunnel ID = %d, want %d", liveTun.ID, recreatedTunID)
	}

	dbRow, err := db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbRow == nil {
		t.Fatalf("replacement proxy backend row %d was deleted from DB", recreatedTunID)
	}
	if dbRow.ID != recreatedTunID {
		t.Errorf("durable proxy row ID = %d, want %d", dbRow.ID, recreatedTunID)
	}
}

// TestDeleteBackend_SweepActiveVPNSessionsError_FailsClosed verifies finding F6:
// If GetActiveVPNSessions fails with an error, the sweep must NOT call DeleteBackendTunnel
// (avoiding cascading session deletion) and must propagate the error.
func TestDeleteBackend_SweepActiveVPNSessionsError_FailsClosed(t *testing.T) {
	db := setupTestDB(t)
	svc, s1ID, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	// Seed a drifted leftover backend_tunnels row for s1ID under a secondary interface name.
	driftID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1ID,
		InterfaceName: "awg-drift-f6",
		PublicKey:     "pub-drift-f6",
		PrivateKey:    "priv-drift-f6",
		Endpoint:      "198.51.100.1:51820",
		Status:        models.TunnelStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to seed drift row: %v", err)
	}

	svc.SetSweepPreLookupHookForTest(func() {
		// Drop the vpn_sessions table to force GetActiveVPNSessions to fail.
		if _, execErr := db.ExecContext(ctx, "DROP TABLE vpn_sessions"); execErr != nil {
			t.Errorf("failed to drop vpn_sessions table: %v", execErr)
		}
	})
	defer svc.SetSweepPreLookupHookForTest(nil)

	err = svc.DeleteBackend(ctx, s1ID)
	if err == nil {
		t.Fatal("expected DeleteBackend to return error when GetActiveVPNSessions fails, got nil")
	}
	if !strings.Contains(err.Error(), "active vpn sessions") {
		t.Errorf("expected error to mention active vpn sessions, got: %v", err)
	}

	// Assert fail-closed: drift row in backend_tunnels must NOT have been deleted.
	var count int
	rowErr := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM backend_tunnels WHERE id = ?", driftID).Scan(&count)
	if rowErr != nil {
		t.Fatalf("failed to query drift row: %v", rowErr)
	}
	if count != 1 {
		t.Errorf("drift row %d was deleted despite GetActiveVPNSessions failure (count = %d)", driftID, count)
	}
}

// TestDeleteBackend_SweepGetBackendTunnelsError_Propagated verifies finding F6:
// If GetBackendTunnelsByServerID fails, the sweep must return the error and restore s.mu.
func TestDeleteBackend_SweepGetBackendTunnelsError_Propagated(t *testing.T) {
	db := setupTestDB(t)
	svc, s1ID, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	svc.SetSweepPreLookupHookForTest(func() {
		// Drop backend_tunnels table so GetBackendTunnelsByServerID fails.
		if _, execErr := db.ExecContext(ctx, "DROP TABLE backend_tunnels"); execErr != nil {
			t.Errorf("failed to drop backend_tunnels table: %v", execErr)
		}
	})
	defer svc.SetSweepPreLookupHookForTest(nil)

	err := svc.DeleteBackend(ctx, s1ID)
	if err == nil {
		t.Fatal("expected DeleteBackend to return error when GetBackendTunnelsByServerID fails, got nil")
	}
	if !strings.Contains(err.Error(), "leftover backend tunnels") {
		t.Errorf("expected error to mention leftover backend tunnels, got: %v", err)
	}

	// Verify s.mu is properly restored (can acquire lock without deadlock or panic).
	svc.mu.Lock()
	_ = svc.isServerDeletedLocked(s1ID)
	svc.mu.Unlock()
}

// TestDeleteBackend_SweepDeleteBackendTunnelError_Propagated verifies finding F6:
// If DeleteBackendTunnel fails, the sweep must propagate the error.
func TestDeleteBackend_SweepDeleteBackendTunnelError_Propagated(t *testing.T) {
	db := setupTestDB(t)
	svc, s1ID, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	// Seed a drifted leftover row so sweep has a row to delete.
	_, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1ID,
		InterfaceName: "awg-drift-del-err",
		PublicKey:     "pub-drift-del-err",
		PrivateKey:    "priv-drift-del-err",
		Endpoint:      "198.51.100.1:51820",
		Status:        models.TunnelStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to seed drift row: %v", err)
	}

	svc.SetSweepPreLookupHookForTest(func() {
		// Trigger an abort on DELETE FROM backend_tunnels.
		triggerSQL := `CREATE TRIGGER abort_del_backend_tunnels BEFORE DELETE ON backend_tunnels
BEGIN
    SELECT RAISE(ABORT, 'forced delete error on backend_tunnels');
END;`
		if _, execErr := db.ExecContext(ctx, triggerSQL); execErr != nil {
			t.Errorf("failed to create abort trigger: %v", execErr)
		}
	})
	defer svc.SetSweepPreLookupHookForTest(nil)

	err = svc.DeleteBackend(ctx, s1ID)
	if err == nil {
		t.Fatal("expected DeleteBackend to return error when DeleteBackendTunnel fails, got nil")
	}
	if !strings.Contains(err.Error(), "delete leftover backend tunnel row") {
		t.Errorf("expected error to mention delete leftover backend tunnel row, got: %v", err)
	}

	// Verify s.mu is properly restored.
	svc.mu.Lock()
	_ = svc.isServerDeletedLocked(s1ID)
	svc.mu.Unlock()
}
