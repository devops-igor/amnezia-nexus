package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestDisableBackend_Lifecycle(t *testing.T) {
	t.Run("disables tunnel detaches device migrates sessions bumps version", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		if err := svc.EnableBackend(ctx, s1ID); err != nil {
			t.Fatalf("EnableBackend s1: %v", err)
		}
		if err := svc.EnableBackend(ctx, s2ID); err != nil {
			t.Fatalf("EnableBackend s2: %v", err)
		}

		tun1 := tunMust(t, svc, s1ID)
		tun2 := tunMust(t, svc, s2ID)

		if dev := svc.GetBackendDeviceForTest(tun1.ID); dev == nil {
			t.Fatal("expected device for s1 before disable")
		}

		// Seed session on s1
		seed := &models.VPNSession{
			UserID:          uID,
			BackendTunnelID: tun1.ID,
			PeerPublicKey:   peerKeyAlice,
			AssignedIP:      "10.201.0.10",
			Status:          "connected",
		}
		if err := db.CreateVPNSession(ctx, seed); err != nil {
			t.Fatalf("CreateVPNSession: %v", err)
		}

		svc.pool.IncrementConnections(tun1.ID)
		svc.forwarder.RegisterSession("sess-1", "conn-1", peerKeyAlice, "10.201.0.10", tun1.ID)
		svc.forwarder.StartPumps(ctx)
		defer svc.forwarder.StopPumps()
		svc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tun1.ID)

		v0 := svc.sessionMgr.LifecycleVersion()

		// Execute DisableBackend
		if err := svc.DisableBackend(ctx, s1ID); err != nil {
			t.Fatalf("DisableBackend failed: %v", err)
		}

		// 1. Tunnel is disabled in pool
		tun1After := tunMust(t, svc, s1ID)
		if tun1After.Enabled {
			t.Errorf("expected tun1.Enabled = false, got true")
		}
		if tun1After.DisableReason != models.DisableReasonAdmin {
			t.Errorf("expected DisableReason = %q, got %q", models.DisableReasonAdmin, tun1After.DisableReason)
		}

		// 2. Forwarder device is detached and cleaned up
		if dev := svc.GetBackendDeviceForTest(tun1.ID); dev != nil {
			t.Errorf("expected backend device for tun1 to be detached/removed, got %v", dev)
		}

		// 3. Active session migrated to s2
		gotTun, _, err := svc.stickyMgr.GetOrAssignBackend(ctx, &loadbalancer.RoutingRequest{
			PeerPublicKey:    peerKeyAlice,
			AvailableTunnels: []*models.BackendTunnel{tun2},
		})
		if err != nil {
			t.Fatalf("GetOrAssignBackend: %v", err)
		}
		if gotTun.ID != tun2.ID {
			t.Errorf("sticky affinity resolves to %d, want %d", gotTun.ID, tun2.ID)
		}

		// 4. Pool counters moved
		curTun1, _ := svc.pool.GetTunnelByID(tun1.ID)
		if curTun1 != nil && curTun1.ActiveConnections != 0 {
			t.Errorf("tun1 ActiveConnections = %d, want 0", curTun1.ActiveConnections)
		}
		curTun2, _ := svc.pool.GetTunnelByID(tun2.ID)
		if curTun2 != nil && curTun2.ActiveConnections != 1 {
			t.Errorf("tun2 ActiveConnections = %d, want 1", curTun2.ActiveConnections)
		}

		// 5. Session lifecycle version was bumped
		v1 := svc.sessionMgr.LifecycleVersion()
		if v1 <= v0 {
			t.Errorf("expected session lifecycle version to be bumped (> %d), got %d", v0, v1)
		}
	})

	t.Run("error on uninitialized pool or unknown server", func(t *testing.T) {
		nilSvc := &Service{}
		if err := nilSvc.DisableBackend(context.Background(), 1); err == nil {
			t.Error("expected error for nil pool, got nil")
		}

		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		if err := svc.DisableBackend(context.Background(), 99999); !errors.Is(err, tunnel.ErrTunnelNotFound) {
			t.Errorf("expected ErrTunnelNotFound for unknown server, got %v", err)
		}
	})
}

func TestUpdateBackendServerHost_Lifecycle(t *testing.T) {
	t.Run("idempotent no-op on matching host", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		if err := svc.EnableBackend(ctx, s1ID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}

		tunBefore := tunMust(t, svc, s1ID)

		// Same host
		if err := svc.UpdateBackendServerHost(ctx, s1ID, "198.51.100.1"); err != nil {
			t.Fatalf("UpdateBackendServerHost same host: %v", err)
		}

		// Bracketed / whitespace host
		if err := svc.UpdateBackendServerHost(ctx, s1ID, " [198.51.100.1] "); err != nil {
			t.Fatalf("UpdateBackendServerHost bracketed host: %v", err)
		}

		tunAfter := tunMust(t, svc, s1ID)
		if tunAfter.Endpoint != tunBefore.Endpoint {
			t.Errorf("endpoint changed unexpectedly: got %s, want %s", tunAfter.Endpoint, tunBefore.Endpoint)
		}
	})

	t.Run("endpoint update success", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}

		newHost := "198.51.100.99"
		if err := svc.UpdateBackendServerHost(ctx, s1ID, newHost); err != nil {
			t.Fatalf("UpdateBackendServerHost: %v", err)
		}

		tun := tunMust(t, svc, s1ID)
		wantEndpoint := "198.51.100.99:51820"
		if tun.Endpoint != wantEndpoint {
			t.Errorf("tun.Endpoint = %q, want %q", tun.Endpoint, wantEndpoint)
		}
	})

	t.Run("rollback on forwarder sync failure", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		tunBefore := tunMust(t, svc, s1ID)
		origEndpoint := tunBefore.Endpoint

		svc.SetSyncBackendForwarderHookForTest(func() error {
			return errors.New("simulated forwarder sync failure")
		})
		defer svc.SetSyncBackendForwarderHookForTest(nil)

		err := svc.UpdateBackendServerHost(ctx, s1ID, "198.51.100.88")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "simulated forwarder sync failure") {
			t.Errorf("expected simulated error, got %v", err)
		}

		// Endpoint must be rolled back
		tunAfter := tunMust(t, svc, s1ID)
		if tunAfter.Endpoint != origEndpoint {
			t.Errorf("expected rolled back endpoint %s, got %s", origEndpoint, tunAfter.Endpoint)
		}
	})

	t.Run("rollback failure wraps ErrVPNRollbackFailed", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		tunBefore := tunMust(t, svc, s1ID)
		origEndpoint := tunBefore.Endpoint

		svc.SetSyncBackendForwarderHookForTest(func() error {
			return errors.New("sync failure")
		})
		defer svc.SetSyncBackendForwarderHookForTest(nil)

		svc.SetTunnelEndpointHookForTest(func(ctx context.Context, tunnelID int64, endpoint string) error {
			if endpoint == origEndpoint {
				return errors.New("rollback disk failure")
			}
			return nil
		})
		defer svc.SetTunnelEndpointHookForTest(nil)

		err := svc.UpdateBackendServerHost(ctx, s1ID, "198.51.100.77")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrVPNRollbackFailed) {
			t.Errorf("expected error wrapping ErrVPNRollbackFailed, got %v", err)
		}
	})
}

func TestDeleteServer_Lifecycle(t *testing.T) {
	t.Run("tombstones server deletes backend clears tombstone on rollback", func(t *testing.T) {
		db := setupTestDB(t)
		svc, serverID, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		if err := svc.EnableBackend(ctx, serverID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}
		tun := tunMust(t, svc, serverID)

		// 1. DeleteServer succeeds
		if err := svc.DeleteServer(ctx, serverID); err != nil {
			t.Fatalf("DeleteServer: %v", err)
		}

		// Tombstone active
		svc.mu.RLock()
		isDel := svc.isServerDeletedLocked(serverID)
		svc.mu.RUnlock()
		if !isDel {
			t.Error("expected server to be tombstoned")
		}

		// Tunnel removed from pool
		if _, err := svc.pool.GetTunnel(serverID); !errors.Is(err, tunnel.ErrTunnelNotFound) {
			t.Errorf("expected ErrTunnelNotFound, got %v", err)
		}

		// Backend device cleaned up
		if dev := svc.GetBackendDeviceForTest(tun.ID); dev != nil {
			t.Errorf("expected backend device to be cleaned up, got %v", dev)
		}

		// Subsequent EnableBackend rejected by tombstone
		if err := svc.EnableBackend(ctx, serverID); !errors.Is(err, ErrServerNotFound) {
			t.Errorf("expected ErrServerNotFound on tombstoned server, got %v", err)
		}

		// Subsequent DeleteBackend returns ErrBackendTunnelNotFound
		if err := svc.DeleteBackend(ctx, serverID); !errors.Is(err, ErrBackendTunnelNotFound) {
			t.Errorf("expected ErrBackendTunnelNotFound on tombstoned server, got %v", err)
		}

		// ClearServerDeletedTombstone restores ability to operate on serverID
		svc.ClearServerDeletedTombstone(serverID)
		svc.mu.RLock()
		isDelAfterClear := svc.isServerDeletedLocked(serverID)
		svc.mu.RUnlock()
		if isDelAfterClear {
			t.Error("expected tombstone to be cleared")
		}
	})

	t.Run("clears tombstone on teardown error", func(t *testing.T) {
		db := setupTestDB(t)
		svc, serverID, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}

		injectedErr := errors.New("simulated delete backend error")
		svc.SetDeleteBackendErrorForTest(injectedErr)
		defer svc.SetDeleteBackendErrorForTest(nil)

		err := svc.DeleteServer(ctx, serverID)
		if !errors.Is(err, injectedErr) {
			t.Fatalf("expected injected error, got %v", err)
		}

		// Tombstone must be unmarked on failure
		svc.mu.RLock()
		isDel := svc.isServerDeletedLocked(serverID)
		svc.mu.RUnlock()
		if isDel {
			t.Error("expected tombstone to be unmarked after rollback")
		}
	})

	t.Run("non-VPN server tombstones cleanly", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()

		if err := svc.DeleteServer(ctx, 9999); err != nil {
			t.Fatalf("DeleteServer for non-VPN server: %v", err)
		}

		svc.mu.RLock()
		isDel := svc.isServerDeletedLocked(9999)
		svc.mu.RUnlock()
		if !isDel {
			t.Error("expected server 9999 to be tombstoned")
		}
	})
}

func TestDeleteBackend_Lifecycle(t *testing.T) {
	t.Run("drains sessions and removes from pool", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)
		ctx := t.Context()

		oldTun := lbTunnel(t, svc, db, 951, "awg951", "pub951", "priv951", "10.9.9.151:51820")
		newTun := lbTunnel(t, svc, db, 952, "awg952", "pub952", "priv952", "10.9.9.152:51820")

		seed := &models.VPNSession{
			UserID:          uID,
			BackendTunnelID: oldTun.ID,
			PeerPublicKey:   "peer-del-lifecycle-1",
			AssignedIP:      "10.201.0.51",
			Status:          "connected",
		}
		if err := db.CreateVPNSession(ctx, seed); err != nil {
			t.Fatalf("CreateVPNSession: %v", err)
		}

		svc.pool.IncrementConnections(oldTun.ID)
		svc.forwarder.RegisterSession("sess-del-lc", "conn-del-lc", "peer-del-lifecycle-1", "10.201.0.51", oldTun.ID)
		svc.forwarder.StartPumps(ctx)
		defer svc.forwarder.StopPumps()
		svc.stickyMgr.AssignPeerAffinity("peer-del-lifecycle-1", oldTun.ID)

		if err := svc.DeleteBackend(ctx, oldTun.ServerID); err != nil {
			t.Fatalf("DeleteBackend: %v", err)
		}

		// 1. Removed from pool
		if _, err := svc.pool.GetTunnel(oldTun.ServerID); err == nil {
			t.Error("tunnel still in pool after DeleteBackend")
		}

		// 2. backend_tunnels DB row deleted
		row, err := db.GetBackendTunnelByServerID(ctx, oldTun.ServerID)
		if err != nil {
			t.Fatalf("GetBackendTunnelByServerID: %v", err)
		}
		if row != nil {
			t.Errorf("backend_tunnels row still exists: %v", row)
		}

		// 3. Session drained and migrated
		sessions, err := db.GetActiveVPNSessions(ctx)
		if err != nil {
			t.Fatalf("GetActiveVPNSessions: %v", err)
		}
		for _, sess := range sessions {
			if sess.PeerPublicKey == "peer-del-lifecycle-1" && sess.BackendTunnelID == oldTun.ID {
				t.Errorf("session still references deleted tunnel %d", oldTun.ID)
			}
		}

		// 4. Sticky affinity migrated to newTun
		gotTun, _, err := svc.stickyMgr.GetOrAssignBackend(ctx, &loadbalancer.RoutingRequest{
			PeerPublicKey:    "peer-del-lifecycle-1",
			AvailableTunnels: []*models.BackendTunnel{newTun},
		})
		if err != nil {
			t.Fatalf("GetOrAssignBackend: %v", err)
		}
		if gotTun.ID != newTun.ID {
			t.Errorf("sticky affinity resolves to %d, want %d", gotTun.ID, newTun.ID)
		}

		// 5. Pool connection counts updated
		curOld, _ := svc.pool.GetTunnelByID(oldTun.ID)
		if curOld != nil && curOld.ActiveConnections != 0 {
			t.Errorf("oldTun ActiveConnections = %d, want 0", curOld.ActiveConnections)
		}
		curNew, _ := svc.pool.GetTunnelByID(newTun.ID)
		if curNew != nil && curNew.ActiveConnections != 1 {
			t.Errorf("newTun ActiveConnections = %d, want 1", curNew.ActiveConnections)
		}
	})

	t.Run("sweeps orphan sessions from DB on drift", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)
		ctx := t.Context()

		oldTun := lbTunnel(t, svc, db, 961, "awg961", "pub961", "priv961", "10.9.9.161:51820")
		newTun := lbTunnel(t, svc, db, 962, "awg962", "pub962", "priv962", "10.9.9.162:51820")

		// Create a drift backend_tunnels row for oldTun.ServerID
		leftoverID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      oldTun.ServerID,
			InterfaceName: "awg961-drift",
			PublicKey:     "pub961-drift",
			PrivateKey:    "priv961-drift",
			Endpoint:      "10.9.9.161:51820",
			Status:        "active",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel drift: %v", err)
		}

		// Seed a connected session on leftoverID
		seed := &models.VPNSession{
			UserID:          uID,
			BackendTunnelID: leftoverID,
			PeerPublicKey:   "peer-drift-lifecycle-1",
			AssignedIP:      "10.201.0.61",
			Status:          "connected",
		}
		if err := db.CreateVPNSession(ctx, seed); err != nil {
			t.Fatalf("CreateVPNSession: %v", err)
		}

		if err := svc.DeleteBackend(ctx, oldTun.ServerID); err != nil {
			t.Fatalf("DeleteBackend: %v", err)
		}

		// Leftover row must be deleted
		row, err := db.GetBackendTunnelByServerID(ctx, oldTun.ServerID)
		if err != nil {
			t.Fatalf("GetBackendTunnelByServerID: %v", err)
		}
		if row != nil {
			t.Errorf("leftover backend_tunnels row still exists: %v", row)
		}

		// Drifted session was reassigned off leftoverID onto newTun
		sess, err := db.GetVPNSessionByID(ctx, seed.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID: %v", err)
		}
		if sess == nil {
			t.Fatal("drifted session not found")
		}
		if sess.BackendTunnelID != newTun.ID {
			t.Errorf("sess.BackendTunnelID = %d, want %d", sess.BackendTunnelID, newTun.ID)
		}
	})
}
