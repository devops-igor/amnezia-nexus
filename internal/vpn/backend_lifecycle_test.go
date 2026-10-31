package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func closeBackendDevices(svc *Service) {
	if svc == nil {
		return
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	for id, dev := range svc.backendDevices {
		if dev != nil && !dev.IsClosed() {
			_ = dev.Close()
		}
		delete(svc.backendDevices, id)
	}
}

func TestDisableBackend_Lifecycle(t *testing.T) {
	t.Run("disables tunnel detaches device migrates sessions bumps version", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
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

		dev1 := svc.GetBackendDeviceForTest(tun1.ID)
		if dev1 == nil {
			t.Fatal("expected device for s1 before disable")
		}
		dev2 := svc.GetBackendDeviceForTest(tun2.ID)
		if dev2 == nil {
			t.Fatal("expected device for s2 before disable")
		}
		t.Cleanup(func() {
			if !dev2.IsClosed() {
				_ = dev2.Close()
			}
		})
		defer func() {
			if !dev2.IsClosed() {
				_ = dev2.Close()
			}
		}()

		// Seed session on s1
		seed := &models.VPNSession{
			UserID:          uID,
			BackendTunnelID: tun1.ID,
			PeerPublicKey:   peerKeyAlice,
			AssignedIP:      "10.100.0.10",
			Status:          "connected",
		}
		if err := db.CreateVPNSession(ctx, seed); err != nil {
			t.Fatalf("CreateVPNSession: %v", err)
		}

		svc.pool.IncrementConnections(tun1.ID)
		svc.forwarder.RegisterSession("sess-1", "conn-1", peerKeyAlice, "10.100.0.10", tun1.ID)
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
		if !dev1.IsClosed() {
			t.Errorf("expected disabled backend device for tun1 to be closed")
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
		curTun1, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil || curTun1 == nil {
			t.Fatalf("failed to retrieve survivor tun1 %d: %v", tun1.ID, err)
		}
		if curTun1.ActiveConnections != 0 {
			t.Errorf("tun1 ActiveConnections = %d, want 0", curTun1.ActiveConnections)
		}
		curTun2, err := svc.pool.GetTunnelByID(tun2.ID)
		if err != nil || curTun2 == nil {
			t.Fatalf("failed to retrieve survivor tun2 %d: %v", tun2.ID, err)
		}
		if curTun2.ActiveConnections != 1 {
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
		defer closeBackendDevices(svc)
		if err := svc.DisableBackend(context.Background(), 99999); !errors.Is(err, tunnel.ErrTunnelNotFound) {
			t.Errorf("expected ErrTunnelNotFound for unknown server, got %v", err)
		}
	})
}

func TestUpdateBackendServerHost_Lifecycle(t *testing.T) {
	t.Run("idempotent no-op on matching host", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		if err := svc.EnableBackend(ctx, s1ID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}

		tunBefore := tunMust(t, svc, s1ID)
		dev1 := svc.GetBackendDeviceForTest(tunBefore.ID)
		if dev1 == nil {
			t.Fatal("expected device for s1 before update")
		}
		t.Cleanup(func() {
			if !dev1.IsClosed() {
				_ = dev1.Close()
			}
		})
		defer func() {
			if !dev1.IsClosed() {
				_ = dev1.Close()
			}
		}()

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
		defer closeBackendDevices(svc)
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
		dev := svc.GetBackendDeviceForTest(tun.ID)
		if dev != nil {
			t.Cleanup(func() {
				if !dev.IsClosed() {
					_ = dev.Close()
				}
			})
			defer func() {
				if !dev.IsClosed() {
					_ = dev.Close()
				}
			}()
		}
	})

	t.Run("rollback on forwarder sync failure", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
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

	t.Run("rollback on real device attachment failure", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		origEndpoint := tunMust(t, svc, s1ID).Endpoint

		err := svc.UpdateBackendServerHost(ctx, s1ID, "bad\x00host")
		if err == nil {
			t.Fatal("expected real device attachment error, got nil")
		}

		// In-memory endpoint rolled back
		tunAfter := tunMust(t, svc, s1ID)
		if tunAfter.Endpoint != origEndpoint {
			t.Errorf("expected rolled back in-memory endpoint %q, got %q", origEndpoint, tunAfter.Endpoint)
		}

		// Database pool endpoint rolled back
		row, err := db.GetBackendTunnelByServerID(ctx, s1ID)
		if err != nil || row == nil {
			t.Fatalf("failed to retrieve backend tunnel from DB: %v", err)
		}
		if row.Endpoint != origEndpoint {
			t.Errorf("expected rolled back DB endpoint %q, got %q", origEndpoint, row.Endpoint)
		}
	})

	t.Run("rollback failure wraps ErrVPNRollbackFailed", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
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

func TestUpdateBackendServerPublicKey_Lifecycle(t *testing.T) {
	setup := func(t *testing.T) (*Service, int64, string) {
		t.Helper()
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		t.Cleanup(func() { closeBackendDevices(svc) })
		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		return svc, s1ID, tunMust(t, svc, s1ID).PublicKey
	}

	t.Run("success persists new key to pool and database", func(t *testing.T) {
		svc, id, _ := setup(t)
		ctx := context.Background()
		if err := svc.UpdateBackendServerPublicKey(ctx, id, "new-public-key"); err != nil {
			t.Fatalf("UpdateBackendServerPublicKey: %v", err)
		}
		tun := tunMust(t, svc, id)
		if tun.PublicKey != "new-public-key" {
			t.Fatalf("pool public key = %q", tun.PublicKey)
		}
		row, err := svc.db.GetBackendTunnelByServerID(ctx, id)
		if err != nil || row == nil || row.PublicKey != "new-public-key" {
			t.Fatalf("durable public key = %+v, err=%v", row, err)
		}
	})

	t.Run("unknown backend is a no-op", func(t *testing.T) {
		svc, _, _ := setup(t)
		if err := svc.UpdateBackendServerPublicKey(context.Background(), 987654, "k"); err != nil {
			t.Fatalf("expected nil for unknown backend, got %v", err)
		}
	})

	t.Run("forwarder sync failure restores old key", func(t *testing.T) {
		svc, id, oldKey := setup(t)
		ctx := context.Background()
		svc.SetSyncBackendForwarderHookForTest(func() error { return errors.New("simulated forwarder sync failure") })
		defer svc.SetSyncBackendForwarderHookForTest(nil)

		err := svc.UpdateBackendServerPublicKey(ctx, id, "candidate-key")
		if err == nil || errors.Is(err, ErrVPNRollbackFailed) {
			t.Fatalf("expected plain sync error, got %v", err)
		}
		if got := tunMust(t, svc, id).PublicKey; got != oldKey {
			t.Fatalf("pool public key = %q, want restored %q", got, oldKey)
		}
		row, rowErr := svc.db.GetBackendTunnelByServerID(ctx, id)
		if rowErr != nil || row == nil || row.PublicKey != oldKey {
			t.Fatalf("durable public key = %+v, err=%v, want %q", row, rowErr, oldKey)
		}
	})

	t.Run("rollback failure wraps ErrVPNRollbackFailed and keeps new key", func(t *testing.T) {
		svc, id, oldKey := setup(t)
		svc.SetSyncBackendForwarderHookForTest(func() error { return errors.New("sync failure") })
		defer svc.SetSyncBackendForwarderHookForTest(nil)
		svc.SetTunnelPublicKeyHookForTest(func(_ context.Context, _ int64, key string) error {
			if key == oldKey {
				return errors.New("rollback disk failure")
			}
			return nil
		})
		defer svc.SetTunnelPublicKeyHookForTest(nil)

		err := svc.UpdateBackendServerPublicKey(context.Background(), id, "candidate-key")
		if !errors.Is(err, ErrVPNRollbackFailed) {
			t.Fatalf("expected ErrVPNRollbackFailed, got %v", err)
		}
		if got := tunMust(t, svc, id).PublicKey; got != "candidate-key" {
			t.Fatalf("pool public key = %q, want unrestored candidate-key", got)
		}
	})

	t.Run("pool hook failure leaves old key and reports error", func(t *testing.T) {
		svc, id, oldKey := setup(t)
		svc.SetTunnelPublicKeyHookForTest(func(context.Context, int64, string) error { return errors.New("pool refused") })
		defer svc.SetTunnelPublicKeyHookForTest(nil)

		if err := svc.UpdateBackendServerPublicKey(context.Background(), id, "candidate-key"); err == nil {
			t.Fatal("expected error")
		}
		if got := tunMust(t, svc, id).PublicKey; got != oldKey {
			t.Fatalf("pool public key = %q, want %q", got, oldKey)
		}
	})
}

func TestDeleteServer_Lifecycle(t *testing.T) {
	t.Run("tombstones server deletes backend clears tombstone on rollback", func(t *testing.T) {
		db := setupTestDB(t)
		svc, serverID, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
		ctx := context.Background()

		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}
		if err := svc.EnableBackend(ctx, serverID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}
		tun := tunMust(t, svc, serverID)
		dev := svc.GetBackendDeviceForTest(tun.ID)
		if dev == nil {
			t.Fatal("expected backend device before DeleteServer")
		}
		t.Cleanup(func() {
			if !dev.IsClosed() {
				_ = dev.Close()
			}
		})
		defer func() {
			if !dev.IsClosed() {
				_ = dev.Close()
			}
		}()

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
		if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
			t.Errorf("expected backend device to be cleaned up, got %v", d)
		}
		if !dev.IsClosed() {
			t.Errorf("expected backend device to be closed after DeleteServer")
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
		defer closeBackendDevices(svc)
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

	t.Run("clears tombstone on real teardown failure", func(t *testing.T) {
		db := setupTestDB(t)
		svc, serverID, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)

		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("SyncFromDB: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := svc.DeleteServer(ctx, serverID)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected canceled persistence failure, got: %v", err)
		}

		svc.mu.RLock()
		isDel := svc.isServerDeletedLocked(serverID)
		svc.mu.RUnlock()
		if isDel {
			t.Fatal("expected server deletion tombstone to be cleared on real teardown failure")
		}
	})

	t.Run("non-VPN server tombstones cleanly", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
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
		defer closeBackendDevices(svc)
		ctx := t.Context()

		oldTun := lbTunnel(t, svc, db, 951, "awg951", "pub951", "priv951", "198.51.100.151:51820")
		newTun := lbTunnel(t, svc, db, 952, "awg952", "pub952", "priv952", "198.51.100.152:51820")

		seed := &models.VPNSession{
			UserID:          uID,
			BackendTunnelID: oldTun.ID,
			PeerPublicKey:   "peer-del-lifecycle-1",
			AssignedIP:      "10.100.0.51",
			Status:          "connected",
		}
		if err := db.CreateVPNSession(ctx, seed); err != nil {
			t.Fatalf("CreateVPNSession: %v", err)
		}

		svc.pool.IncrementConnections(oldTun.ID)
		svc.forwarder.RegisterSession("sess-del-lc", "conn-del-lc", "peer-del-lifecycle-1", "10.100.0.51", oldTun.ID)
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
		curNew, err := svc.pool.GetTunnelByID(newTun.ID)
		if err != nil || curNew == nil {
			t.Fatalf("failed to retrieve survivor newTun %d: %v", newTun.ID, err)
		}
		if curNew.ActiveConnections != 1 {
			t.Errorf("newTun ActiveConnections = %d, want 1", curNew.ActiveConnections)
		}
	})

	t.Run("sweeps orphan sessions from DB on drift", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
		ctx := t.Context()

		oldTun := lbTunnel(t, svc, db, 961, "awg961", "pub961", "priv961", "198.51.100.161:51820")
		newTun := lbTunnel(t, svc, db, 962, "awg962", "pub962", "priv962", "198.51.100.162:51820")

		// Create a drift backend_tunnels row for oldTun.ServerID
		leftoverID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      oldTun.ServerID,
			InterfaceName: "awg961-drift",
			PublicKey:     "pub961-drift",
			PrivateKey:    "priv961-drift",
			Endpoint:      "198.51.100.161:51820",
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
			AssignedIP:      "10.100.0.61",
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

	t.Run("fails closed and retains leftover row on peer preservation failure", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
		ctx := t.Context()

		oldTun := lbTunnel(t, svc, db, 971, "awg971", "pub971", "priv971", "198.51.100.171:51820")
		newTun := lbTunnel(t, svc, db, 972, "awg972", "pub972", "priv972", "198.51.100.172:51820")

		naiveParams, err := json.Marshal(models.NaiveProxyParams{
			Domain:   "failclosed.example.com",
			Username: "drift-failclosed-user",
			Password: "drift-password",
		})
		if err != nil {
			t.Fatalf("Marshal NaiveProxyParams: %v", err)
		}

		var leftoverID int64
		var seed *models.VPNSession

		// Inject the drift leftover row and SQLite trigger during Phase 1 disable,
		// after the Phase 0 pre-check has already passed.
		svc.SetTunnelEnabledHookForTest(func(hookCtx context.Context, sID int64, enabled bool, disableReason string) error {
			var createErr error
			leftoverID, createErr = db.CreateBackendTunnel(hookCtx, &models.BackendTunnel{
				ServerID:       oldTun.ServerID,
				InterfaceName:  "naive971-drift",
				Endpoint:       "198.51.100.171:443",
				Protocol:       models.ProtocolNaive,
				ProtocolParams: naiveParams,
				Status:         "active",
			})
			if createErr != nil {
				return createErr
			}

			seed = &models.VPNSession{
				UserID:          uID,
				BackendTunnelID: leftoverID,
				PeerPublicKey:   "peer-drift-failclosed-1",
				AssignedIP:      "10.100.0.71",
				Status:          "connected",
			}
			if sessErr := db.CreateVPNSession(hookCtx, seed); sessErr != nil {
				return sessErr
			}

			triggerSQL := "CREATE TRIGGER fail_peer_lifecycle_insert BEFORE INSERT ON peer_lifecycle BEGIN SELECT RAISE(ABORT, 'injected peer_lifecycle persistence failure'); END"
			_, trigErr := db.ExecContext(hookCtx, triggerSQL)
			return trigErr
		})

		err = svc.DeleteBackend(ctx, oldTun.ServerID)
		if err == nil {
			t.Fatal("expected DeleteBackend to fail closed on peer preservation failure, got nil")
		}
		if !strings.Contains(err.Error(), "failed to ensure peer preservation for leftover row") {
			t.Fatalf("expected error to mention peer preservation failure for leftover row, got: %v", err)
		}

		// Leftover row MUST remain intact in database
		leftover, err := db.GetBackendTunnelByID(ctx, leftoverID)
		if err != nil {
			t.Fatalf("GetBackendTunnelByID: %v", err)
		}
		if leftover == nil {
			t.Fatal("leftover backend_tunnels row was deleted, expected retained for retry")
		}

		// Session MUST NOT have been reassigned to newTun
		sess, err := db.GetVPNSessionByID(ctx, seed.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID: %v", err)
		}
		if sess == nil {
			t.Fatal("session not found")
		}
		if sess.BackendTunnelID != leftoverID {
			t.Errorf("sess.BackendTunnelID = %d, want retained on leftover %d (survivor was %d)", sess.BackendTunnelID, leftoverID, newTun.ID)
		}
	})

	t.Run("retry cleans up leftover row when preservation succeeds after prior failure", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)
		defer closeBackendDevices(svc)
		ctx := t.Context()

		oldTun := lbTunnel(t, svc, db, 973, "awg973", "pub973", "priv973", "198.51.100.173:51820")
		newTun := lbTunnel(t, svc, db, 974, "awg974", "pub974", "priv974", "198.51.100.174:51820")

		naiveParams, err := json.Marshal(models.NaiveProxyParams{
			Domain:   "retry-success.example.com",
			Username: "drift-retry-user",
			Password: "drift-password",
		})
		if err != nil {
			t.Fatalf("Marshal NaiveProxyParams: %v", err)
		}

		var leftoverID int64
		var seed *models.VPNSession

		svc.SetTunnelEnabledHookForTest(func(hookCtx context.Context, sID int64, enabled bool, disableReason string) error {
			var createErr error
			leftoverID, createErr = db.CreateBackendTunnel(hookCtx, &models.BackendTunnel{
				ServerID:       oldTun.ServerID,
				InterfaceName:  "naive973-drift",
				Endpoint:       "198.51.100.173:443",
				Protocol:       models.ProtocolNaive,
				ProtocolParams: naiveParams,
				Status:         "active",
			})
			if createErr != nil {
				return createErr
			}

			seed = &models.VPNSession{
				UserID:          uID,
				BackendTunnelID: leftoverID,
				PeerPublicKey:   "peer-drift-retry-1",
				AssignedIP:      "10.100.0.73",
				Status:          "connected",
			}
			if sessErr := db.CreateVPNSession(hookCtx, seed); sessErr != nil {
				return sessErr
			}

			triggerSQL := "CREATE TRIGGER fail_peer_lifecycle_insert_retry BEFORE INSERT ON peer_lifecycle BEGIN SELECT RAISE(ABORT, 'injected peer_lifecycle persistence failure'); END"
			_, trigErr := db.ExecContext(hookCtx, triggerSQL)
			return trigErr
		})

		// First call: fails closed during defensive sweep peer preservation.
		err = svc.DeleteBackend(ctx, oldTun.ServerID)
		if err == nil {
			t.Fatal("expected DeleteBackend to fail closed on peer preservation failure, got nil")
		}

		// Tunnel must be absent from pool now.
		if _, poolErr := svc.pool.GetTunnel(oldTun.ServerID); !errors.Is(poolErr, tunnel.ErrTunnelNotFound) {
			t.Fatalf("expected tunnel removed from pool, got: %v", poolErr)
		}

		// Leftover row is still in DB.
		leftover, err := db.GetBackendTunnelByID(ctx, leftoverID)
		if err != nil || leftover == nil {
			t.Fatalf("expected leftover row to survive first DeleteBackend, got row=%v, err=%v", leftover, err)
		}

		// Drop the trigger so peer preservation succeeds on retry.
		if _, dropErr := db.ExecContext(ctx, "DROP TRIGGER fail_peer_lifecycle_insert_retry"); dropErr != nil {
			t.Fatalf("failed to drop trigger: %v", dropErr)
		}

		// Second call: tunnel is NOT in pool, but leftover row exists in DB.
		// DeleteBackend must recognize this state, run defensive sweep, preserve peer, and delete leftover row.
		if retryErr := svc.DeleteBackend(ctx, oldTun.ServerID); retryErr != nil {
			t.Fatalf("expected DeleteBackend retry to succeed, got: %v", retryErr)
		}

		// Leftover row MUST now be deleted from database.
		leftoverAfter, err := db.GetBackendTunnelByID(ctx, leftoverID)
		if err != nil {
			t.Fatalf("GetBackendTunnelByID after retry: %v", err)
		}
		if leftoverAfter != nil {
			t.Fatalf("leftover backend_tunnels row %d was NOT deleted after successful retry", leftoverID)
		}

		// Session MUST have been reassigned to newTun and set to draining.
		sess, err := db.GetVPNSessionByID(ctx, seed.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID: %v", err)
		}
		if sess == nil {
			t.Fatal("session not found after retry")
		}
		if sess.BackendTunnelID != newTun.ID {
			t.Errorf("sess.BackendTunnelID = %d, want reassigned to %d", sess.BackendTunnelID, newTun.ID)
		}
		if sess.Status != "draining" {
			t.Errorf("sess.Status = %q, want draining", sess.Status)
		}

		// Third call: tunnel not in pool and no leftover rows -> must return ErrBackendTunnelNotFound.
		if thirdErr := svc.DeleteBackend(ctx, oldTun.ServerID); !errors.Is(thirdErr, ErrBackendTunnelNotFound) {
			t.Errorf("expected ErrBackendTunnelNotFound on subsequent delete, got: %v", thirdErr)
		}
	})
}
