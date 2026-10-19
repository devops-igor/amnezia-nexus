package vpn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
)

func TestSetPreCommitMigrationHookForTest(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKey := setupTestVPNService(t, db)
	err := svc.pool.SyncFromDB(ctx)
	if err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel s1ID failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel s2ID failed: %v", err)
	}

	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, "10.100.0.21", tun1.ID, "phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	svc.forwarder.RegisterSession(sess.ID, "conn-hook", peerKey, "10.100.0.21", tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	var hookFired bool
	svc.SetPreCommitMigrationHookForTest(func() {
		hookFired = true
	})

	err = svc.MigrateSession(ctx, sess.ID, tun2.ID)
	if err != nil {
		t.Fatalf("MigrateSession failed: %v", err)
	}
	if !hookFired {
		t.Fatalf("expected pre-commit hook to fire during MigrateSession")
	}
}

func TestValidateMigrationTarget(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, _, _ := setupTestVPNService(t, db)
	err := svc.pool.SyncFromDB(ctx)
	if err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel s1ID failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel s2ID failed: %v", err)
	}

	t.Run("valid target returns state version", func(t *testing.T) {
		version, err := svc.validateMigrationTarget(tun1.ID)
		if err != nil {
			t.Fatalf("validateMigrationTarget returned unexpected error: %v", err)
		}
		if version != tun1.StateVersion {
			t.Fatalf("got StateVersion %d, want %d", version, tun1.StateVersion)
		}
	})

	t.Run("unknown target rejected", func(t *testing.T) {
		_, err := svc.validateMigrationTarget(999999)
		if err == nil {
			t.Fatalf("expected error for non-existent target tunnel, got nil")
		}
		if !strings.Contains(err.Error(), "not found in pool") {
			t.Fatalf("error message does not mention 'not found in pool': %v", err)
		}
	})

	t.Run("administratively disabled target rejected", func(t *testing.T) {
		err := svc.pool.SetTunnelEnabled(ctx, s2ID, false, "admin")
		if err != nil {
			t.Fatalf("SetTunnelEnabled failed: %v", err)
		}
		defer func() {
			_ = svc.pool.SetTunnelEnabled(ctx, s2ID, true, "")
		}()

		_, err = svc.validateMigrationTarget(tun2.ID)
		if err == nil {
			t.Fatalf("expected error for disabled target tunnel, got nil")
		}
		if !strings.Contains(err.Error(), "not eligible") {
			t.Fatalf("error message does not mention 'not eligible': %v", err)
		}
		if !strings.Contains(err.Error(), "enabled=false") {
			t.Fatalf("error message does not mention 'enabled=false': %v", err)
		}
	})

	t.Run("inactive status target rejected", func(t *testing.T) {
		err := svc.pool.SetTunnelStatus(ctx, s2ID, models.TunnelStatusDegraded, 100)
		if err != nil {
			t.Fatalf("SetTunnelStatus failed: %v", err)
		}
		defer func() {
			_ = svc.pool.SetTunnelStatus(ctx, s2ID, models.TunnelStatusActive, 50)
		}()

		_, err = svc.validateMigrationTarget(tun2.ID)
		if err == nil {
			t.Fatalf("expected error for inactive target tunnel, got nil")
		}
		if !strings.Contains(err.Error(), "not eligible") {
			t.Fatalf("error message does not mention 'not eligible': %v", err)
		}
	})

	t.Run("nil pool returns zero and no error", func(t *testing.T) {
		svcNilPool := &Service{}
		version, err := svcNilPool.validateMigrationTarget(tun1.ID)
		if err != nil {
			t.Fatalf("expected nil error for nil pool, got: %v", err)
		}
		if version != 0 {
			t.Fatalf("expected version 0 for nil pool, got: %d", version)
		}
	})
}

func TestRollbackMigration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKey := setupTestVPNService(t, db)
	err := svc.pool.SyncFromDB(ctx)
	if err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel s1ID failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel s2ID failed: %v", err)
	}

	t.Run("rolls back all components on failure", func(t *testing.T) {
		assignedIP := "10.100.0.30"
		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, assignedIP, tun1.ID, "phone")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		svc.forwarder.RegisterSession(sess.ID, "conn-rb-1", peerKey, assignedIP, tun1.ID)

		// Mutate all components towards tun2 to simulate mid-migration state
		err = svc.forwarder.UpdateSessionBackend(peerKey, tun2.ID)
		if err != nil {
			t.Fatalf("forwarder UpdateSessionBackend failed: %v", err)
		}
		_, _, _, err = svc.sessionMgr.UpdateSessionBackend(sess.ID, tun2.ID, "connected")
		if err != nil {
			t.Fatalf("sessionMgr UpdateSessionBackend failed: %v", err)
		}
		err = svc.db.MigrateVPNSessionBackend(ctx, sess.ID, tun2.ID)
		if err != nil {
			t.Fatalf("db MigrateVPNSessionBackend failed: %v", err)
		}

		// Rollback all components to tun1
		err = svc.rollbackMigration(ctx, sess.ID, peerKey, tun1.ID, "connected", true, true, true)
		if err != nil {
			t.Fatalf("rollbackMigration failed: %v", err)
		}

		// Verify forwarder route rolled back to tun1
		q1, ok := svc.forwarder.GetBackendPacketChannel(tun1.ID)
		if !ok {
			t.Fatalf("failed to get packet channel for tun1")
		}
		pkt := createDummyIPv4Packet(assignedIP, "1.1.1.1", []byte("rb-all-test"))
		err = svc.forwarder.RouteClientToBackend(peerKey, pkt)
		if err != nil {
			t.Fatalf("RouteClientToBackend failed: %v", err)
		}
		select {
		case received := <-q1:
			if !bytes.Equal(received, pkt) {
				t.Fatalf("packet mismatch on backend 1 queue after rollback")
			}
		default:
			t.Fatalf("expected packet on backend 1 queue after rollback, but channel was empty")
		}

		// Verify session manager rolled back to tun1
		snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
		if !ok {
			t.Fatalf("session not found in sessionMgr")
		}
		if snap.BackendTunnelID != tun1.ID {
			t.Fatalf("sessionMgr BackendTunnelID = %d, want %d", snap.BackendTunnelID, tun1.ID)
		}
		if snap.Status != "connected" {
			t.Fatalf("sessionMgr Status = %q, want 'connected'", snap.Status)
		}

		// Verify DB rolled back to tun1
		dbSess, err := svc.db.GetVPNSessionByID(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID failed: %v", err)
		}
		if dbSess == nil {
			t.Fatalf("db session is nil")
		}
		if dbSess.BackendTunnelID != tun1.ID {
			t.Fatalf("DB BackendTunnelID = %d, want %d", dbSess.BackendTunnelID, tun1.ID)
		}
	})

	t.Run("rolls back successfully under canceled context", func(t *testing.T) {
		assignedIP := "10.100.0.31"
		peerKeyCanceled := "canceled-peer-key"
		_, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: peerKeyCanceled,
			Name:     "canceled-phone",
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyCanceled, assignedIP, tun1.ID, "phone")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		svc.forwarder.RegisterSession(sess.ID, "conn-rb-canceled", peerKeyCanceled, assignedIP, tun1.ID)

		// Mutate DB to tun2
		err = svc.db.MigrateVPNSessionBackend(ctx, sess.ID, tun2.ID)
		if err != nil {
			t.Fatalf("db MigrateVPNSessionBackend failed: %v", err)
		}

		// Cancel context immediately
		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		// Rollback with canceled context: DB rollback must still succeed via WithoutCancel
		err = svc.rollbackMigration(canceledCtx, sess.ID, peerKeyCanceled, tun1.ID, "connected", false, false, true)
		if err != nil {
			t.Fatalf("rollbackMigration with canceled context failed: %v", err)
		}

		dbSess, err := svc.db.GetVPNSessionByID(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID failed: %v", err)
		}
		if dbSess == nil {
			t.Fatalf("db session is nil")
		}
		if dbSess.BackendTunnelID != tun1.ID {
			t.Fatalf("DB BackendTunnelID after canceled-context rollback = %d, want %d", dbSess.BackendTunnelID, tun1.ID)
		}
	})

	t.Run("nil context handled safely", func(t *testing.T) {
		var nilCtx context.Context
		//nolint:staticcheck // explicitly testing defensive nil context handling in rollbackMigration
		err := svc.rollbackMigration(nilCtx, "nonexistent-sess", "nonexistent-peer", tun1.ID, "connected", false, false, false)
		if err != nil {
			t.Fatalf("expected nil error for no-op rollback with nil context, got: %v", err)
		}
	})
}

func TestMigrateSession(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKey := setupTestVPNService(t, db)
	err := svc.pool.SyncFromDB(ctx)
	if err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel s1ID failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel s2ID failed: %v", err)
	}

	t.Run("parameter validation", func(t *testing.T) {
		var nilSvc *Service
		err := nilSvc.MigrateSession(ctx, "sess-1", tun2.ID)
		if err == nil {
			t.Fatalf("expected error for nil service, got nil")
		}

		err = svc.MigrateSession(ctx, "", tun2.ID)
		if err == nil {
			t.Fatalf("expected error for empty session id, got nil")
		}

		err = svc.MigrateSession(ctx, "sess-1", 0)
		if err == nil {
			t.Fatalf("expected error for targetTunnelID <= 0, got nil")
		}

		err = svc.MigrateSession(ctx, "sess-1", -5)
		if err == nil {
			t.Fatalf("expected error for negative targetTunnelID, got nil")
		}
	})

	t.Run("target tunnel validation rejection", func(t *testing.T) {
		err := svc.MigrateSession(ctx, "sess-1", 999999)
		if err == nil {
			t.Fatalf("expected error for non-existent target tunnel, got nil")
		}
		if !strings.Contains(err.Error(), "not found in pool") {
			t.Fatalf("expected 'not found in pool' error, got: %v", err)
		}
	})

	t.Run("uninitialized session manager rejection", func(t *testing.T) {
		svcNoMgr := &Service{
			pool: svc.pool,
		}
		err := svcNoMgr.MigrateSession(ctx, "sess-1", tun2.ID)
		if err == nil {
			t.Fatalf("expected error for uninitialized session manager, got nil")
		}
		if !strings.Contains(err.Error(), "session manager is not initialized") {
			t.Fatalf("expected 'session manager is not initialized' error, got: %v", err)
		}
	})

	t.Run("non-existent session returns ErrSessionNotFound", func(t *testing.T) {
		err := svc.MigrateSession(ctx, "ghost-session-uuid", tun2.ID)
		if err == nil {
			t.Fatalf("expected error for non-existent session, got nil")
		}
		if !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("expected session.ErrSessionNotFound, got: %v", err)
		}
	})

	t.Run("same tunnel no-op", func(t *testing.T) {
		assignedIP := "10.100.0.40"
		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, assignedIP, tun1.ID, "phone")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}

		err = svc.MigrateSession(ctx, sess.ID, tun1.ID)
		if err != nil {
			t.Fatalf("expected no-op nil error for same tunnel, got: %v", err)
		}
	})

	t.Run("successful migration orchestrates all subsystems", func(t *testing.T) {
		assignedIP := "10.100.0.41"
		peerKeySuccess := "success-peer-key"
		_, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: peerKeySuccess,
			Name:     "success-phone",
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeySuccess, assignedIP, tun1.ID, "success-phone")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		svc.forwarder.RegisterSession(sess.ID, "conn-success", peerKeySuccess, assignedIP, tun1.ID)
		svc.pool.IncrementConnections(tun1.ID)

		// Perform migration from tun1 to tun2
		err = svc.MigrateSession(ctx, sess.ID, tun2.ID)
		if err != nil {
			t.Fatalf("MigrateSession failed: %v", err)
		}

		// 1. Forwarder route verified on tun2
		q2, ok := svc.forwarder.GetBackendPacketChannel(tun2.ID)
		if !ok {
			t.Fatalf("failed to get packet channel for tun2")
		}
		pkt := createDummyIPv4Packet(assignedIP, "1.1.1.1", []byte("success-migration-pkt"))
		err = svc.forwarder.RouteClientToBackend(peerKeySuccess, pkt)
		if err != nil {
			t.Fatalf("RouteClientToBackend failed: %v", err)
		}
		select {
		case received := <-q2:
			if !bytes.Equal(received, pkt) {
				t.Fatalf("packet mismatch on backend 2 queue")
			}
		default:
			t.Fatalf("expected packet on backend 2 queue, but channel was empty")
		}

		// 2. SessionManager snapshot verified
		snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
		if !ok {
			t.Fatalf("session not found in sessionMgr")
		}
		if snap.BackendTunnelID != tun2.ID {
			t.Fatalf("sessionMgr BackendTunnelID = %d, want %d", snap.BackendTunnelID, tun2.ID)
		}
		if snap.Status != "connected" {
			t.Fatalf("sessionMgr Status = %q, want 'connected'", snap.Status)
		}

		// 3. Database session verified
		dbSess, err := svc.db.GetVPNSessionByID(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID failed: %v", err)
		}
		if dbSess == nil {
			t.Fatalf("db session is nil")
		}
		if dbSess.BackendTunnelID != tun2.ID {
			t.Fatalf("DB BackendTunnelID = %d, want %d", dbSess.BackendTunnelID, tun2.ID)
		}

		// 4. Counter migration verified
		tun1Live, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil {
			t.Fatalf("failed to get tun1 from pool: %v", err)
		}
		if tun1Live.ActiveConnections != 0 {
			t.Fatalf("tun1 ActiveConnections = %d, want 0", tun1Live.ActiveConnections)
		}

		tun2Live, err := svc.pool.GetTunnelByID(tun2.ID)
		if err != nil {
			t.Fatalf("failed to get tun2 from pool: %v", err)
		}
		if tun2Live.ActiveConnections != 1 {
			t.Fatalf("tun2 ActiveConnections = %d, want 1", tun2Live.ActiveConnections)
		}

		// 5. Sticky affinity assigned to target tunnel
		affTunnelID, hasAffinity := svc.stickyMgr.GetPeerAffinity(peerKeySuccess)
		if !hasAffinity {
			t.Fatalf("expected sticky affinity to be recorded for peer")
		}
		if affTunnelID != tun2.ID {
			t.Fatalf("sticky affinity tunnel ID = %d, want %d", affTunnelID, tun2.ID)
		}
	})

	t.Run("rollback on counter transfer failure", func(t *testing.T) {
		assignedIP := "10.100.0.42"
		peerKeyFail := "fail-transfer-peer-key"
		_, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: peerKeyFail,
			Name:     "fail-phone",
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyFail, assignedIP, tun1.ID, "fail-phone")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		svc.forwarder.RegisterSession(sess.ID, "conn-fail", peerKeyFail, assignedIP, tun1.ID)
		svc.pool.IncrementConnections(tun1.ID)

		// Set pre-commit hook to invalidate target tunnel status in pool before counter commit
		svc.SetPreCommitMigrationHookForTest(func() {
			_ = svc.pool.SetTunnelStatus(ctx, s2ID, models.TunnelStatusDegraded, 200)
		})
		defer func() {
			svc.SetPreCommitMigrationHookForTest(nil)
			_ = svc.pool.SetTunnelStatus(ctx, s2ID, models.TunnelStatusActive, 50)
		}()

		err = svc.MigrateSession(ctx, sess.ID, tun2.ID)
		if err == nil {
			t.Fatalf("expected MigrateSession to fail due to check-to-commit race, got nil")
		}

		// Forwarder route should be rolled back to tun1
		q1, ok := svc.forwarder.GetBackendPacketChannel(tun1.ID)
		if !ok {
			t.Fatalf("failed to get packet channel for tun1")
		}
		pkt := createDummyIPv4Packet(assignedIP, "1.1.1.1", []byte("rollback-verify-pkt"))
		err = svc.forwarder.RouteClientToBackend(peerKeyFail, pkt)
		if err != nil {
			t.Fatalf("RouteClientToBackend failed: %v", err)
		}
		select {
		case received := <-q1:
			if !bytes.Equal(received, pkt) {
				t.Fatalf("packet mismatch on backend 1 queue after rollback")
			}
		default:
			t.Fatalf("expected packet on backend 1 queue after rollback, but channel was empty")
		}

		// Session manager should be rolled back to tun1
		snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
		if !ok {
			t.Fatalf("session not found in sessionMgr")
		}
		if snap.BackendTunnelID != tun1.ID {
			t.Fatalf("sessionMgr BackendTunnelID after rollback = %d, want %d", snap.BackendTunnelID, tun1.ID)
		}

		// DB should be rolled back to tun1
		dbSess, err := svc.db.GetVPNSessionByID(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetVPNSessionByID failed: %v", err)
		}
		if dbSess == nil {
			t.Fatalf("db session is nil")
		}
		if dbSess.BackendTunnelID != tun1.ID {
			t.Fatalf("DB BackendTunnelID after rollback = %d, want %d", dbSess.BackendTunnelID, tun1.ID)
		}

		// Counters should remain at tun1 = 1, tun2 = 0 (or previous count)
		tun1Live, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil {
			t.Fatalf("failed to get tun1 from pool: %v", err)
		}
		if tun1Live.ActiveConnections < 1 {
			t.Fatalf("tun1 ActiveConnections = %d, want at least 1", tun1Live.ActiveConnections)
		}
	})
}

func TestMigrateVPNSession(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKey := setupTestVPNService(t, db)
	err := svc.pool.SyncFromDB(ctx)
	if err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel s1ID failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel s2ID failed: %v", err)
	}

	assignedIP := "10.100.0.50"
	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, assignedIP, tun1.ID, "phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	svc.forwarder.RegisterSession(sess.ID, "conn-alias", peerKey, assignedIP, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	err = svc.MigrateVPNSession(ctx, sess.ID, tun2.ID)
	if err != nil {
		t.Fatalf("MigrateVPNSession failed: %v", err)
	}

	snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("session not found in sessionMgr")
	}
	if snap.BackendTunnelID != tun2.ID {
		t.Fatalf("sessionMgr BackendTunnelID = %d, want %d", snap.BackendTunnelID, tun2.ID)
	}
}

func TestSelectTunnelForPeer(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKey := setupTestVPNService(t, db)
	err := svc.pool.SyncFromDB(ctx)
	if err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel s1ID failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel s2ID failed: %v", err)
	}

	tunnels := []*models.BackendTunnel{tun1, tun2}

	t.Run("respects peer sticky affinity", func(t *testing.T) {
		svc.stickyMgr.AssignPeerAffinity(peerKey, tun2.ID)
		defer svc.stickyMgr.ClearPeerAffinity(peerKey)

		req := &loadbalancer.RoutingRequest{
			UserID:           uID,
			PeerPublicKey:    peerKey,
			AvailableTunnels: tunnels,
		}
		selected, err := svc.selectTunnelForPeer(ctx, req)
		if err != nil {
			t.Fatalf("selectTunnelForPeer failed: %v", err)
		}
		if selected.ID != tun2.ID {
			t.Fatalf("selected tunnel ID = %d, want %d (peer affinity)", selected.ID, tun2.ID)
		}
	})

	t.Run("respects user sticky affinity when peer affinity is absent", func(t *testing.T) {
		otherPeerKey := "other-peer-key"
		svc.stickyMgr.AssignAffinity(uID, tun2.ID)
		defer svc.stickyMgr.ClearAffinity(uID)

		req := &loadbalancer.RoutingRequest{
			UserID:           uID,
			PeerPublicKey:    otherPeerKey,
			AvailableTunnels: tunnels,
		}
		selected, err := svc.selectTunnelForPeer(ctx, req)
		if err != nil {
			t.Fatalf("selectTunnelForPeer failed: %v", err)
		}
		if selected.ID != tun2.ID {
			t.Fatalf("selected tunnel ID = %d, want %d (user affinity)", selected.ID, tun2.ID)
		}
	})

	t.Run("peer affinity takes precedence over user affinity", func(t *testing.T) {
		svc.stickyMgr.AssignAffinity(uID, tun2.ID)
		svc.stickyMgr.AssignPeerAffinity(peerKey, tun1.ID)
		defer func() {
			svc.stickyMgr.ClearAffinity(uID)
			svc.stickyMgr.ClearPeerAffinity(peerKey)
		}()

		req := &loadbalancer.RoutingRequest{
			UserID:           uID,
			PeerPublicKey:    peerKey,
			AvailableTunnels: tunnels,
		}
		selected, err := svc.selectTunnelForPeer(ctx, req)
		if err != nil {
			t.Fatalf("selectTunnelForPeer failed: %v", err)
		}
		if selected.ID != tun1.ID {
			t.Fatalf("selected tunnel ID = %d, want %d (peer precedence)", selected.ID, tun1.ID)
		}
	})

	t.Run("falls back to load balancer when stickyMgr is nil", func(t *testing.T) {
		svcNoSticky := &Service{
			balancer: svc.balancer,
		}
		req := &loadbalancer.RoutingRequest{
			AvailableTunnels: tunnels,
		}
		selected, err := svcNoSticky.selectTunnelForPeer(ctx, req)
		if err != nil {
			t.Fatalf("selectTunnelForPeer failed: %v", err)
		}
		if selected == nil {
			t.Fatalf("expected non-nil selected tunnel")
		}
	})

	t.Run("returns ErrNoActiveBackends when both stickyMgr and balancer are nil", func(t *testing.T) {
		svcEmpty := &Service{}
		req := &loadbalancer.RoutingRequest{
			AvailableTunnels: tunnels,
		}
		_, err := svcEmpty.selectTunnelForPeer(ctx, req)
		if err == nil {
			t.Fatalf("expected ErrNoActiveBackends, got nil")
		}
		if !errors.Is(err, loadbalancer.ErrNoActiveBackends) {
			t.Fatalf("expected loadbalancer.ErrNoActiveBackends, got: %v", err)
		}
	})
}

func TestSelectTunnel(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when balancer is nil", func(t *testing.T) {
		svcNoLB := &Service{}
		_, err := svcNoLB.SelectTunnel(ctx, nil)
		if err == nil {
			t.Fatalf("expected error when load balancer is nil, got nil")
		}
		if !strings.Contains(err.Error(), "load balancer not initialized") {
			t.Fatalf("expected 'load balancer not initialized' error, got: %v", err)
		}
	})

	t.Run("routes to active tunnels using loadbalancer", func(t *testing.T) {
		lb := loadbalancer.NewLeastConnectionsBalancer(loadbalancer.CapacityConfig{})
		svc := &Service{
			balancer: lb,
		}

		tunnels := []*models.BackendTunnel{
			{ID: 10, InterfaceName: "awg-10", Enabled: true, Status: models.TunnelStatusActive, ActiveConnections: 10},
			{ID: 20, InterfaceName: "awg-20", Enabled: true, Status: models.TunnelStatusActive, ActiveConnections: 2},
			{ID: 30, InterfaceName: "awg-30", Enabled: true, Status: models.TunnelStatusActive, ActiveConnections: 5},
		}

		selected, err := svc.SelectTunnel(ctx, tunnels)
		if err != nil {
			t.Fatalf("SelectTunnel failed: %v", err)
		}
		if selected == nil {
			t.Fatalf("expected selected tunnel to be non-nil")
		}
		if selected.ID != 20 {
			t.Fatalf("selected tunnel ID = %d, want 20 (least connections)", selected.ID)
		}
	})
}
