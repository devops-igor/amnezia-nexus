package vpn

import (
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/loadbalancer"
)

// TestDeleteBackendRemovesTunnelAndRow pins the Issue #29 contract for
// Service.DeleteBackend: the tunnel must be gone from the pool, its
// backend_tunnels DB row must be deleted, active sessions must have failed
// over BEFORE removal (no orphaned vpn_sessions rows may keep referencing
// the deleted backend_tunnels row), and deleting an already-deleted backend
// must fail with the not-found sentinel.
func TestDeleteBackendRemovesTunnelAndRow(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	// High server IDs keep clear of the fixture's tunnels (see
	// lb_integration_test.go). lbTunnel creates the servers row the pool's
	// FK needs and registers the tunnel in the pool (which persists the
	// backend_tunnels row).
	oldTun := lbTunnel(t, svc, db, 911, "awg911", "pub911", "priv911", "10.9.9.111:51820")
	newTun := lbTunnel(t, svc, db, 912, "awg912", "pub912", "priv912", "10.9.9.112:51820")

	// A connected vpn_sessions row routed to the backend under delete: after
	// DeleteBackend it must have been reassigned, never left orphaned on the
	// deleted tunnel ID.
	seed := &models.VPNSession{
		UserID:          uID,
		BackendTunnelID: oldTun.ID,
		PeerPublicKey:   "peer-del-1",
		AssignedIP:      "10.201.0.9",
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, seed); err != nil {
		t.Fatalf("setup: CreateVPNSession failed: %v", err)
	}

	// Live forwarder route + sticky affinity + pool counter, mirroring the
	// DisableBackend regression test: DeleteBackend must move all of them.
	svc.pool.IncrementConnections(oldTun.ID)
	svc.forwarder.RegisterSession("sess-del-1", "conn-del-1", "peer-del-1", "10.201.0.9", oldTun.ID)
	svc.forwarder.StartPumps(ctx)
	defer svc.forwarder.StopPumps()
	svc.stickyMgr.AssignPeerAffinity("peer-del-1", oldTun.ID)

	if err := svc.DeleteBackend(ctx, oldTun.ServerID); err != nil {
		t.Fatalf("DeleteBackend(%d) failed: %v", oldTun.ServerID, err)
	}

	// 1. The pool no longer contains the tunnel.
	if _, err := svc.pool.GetTunnel(oldTun.ServerID); err == nil {
		t.Errorf("tunnel for server %d still in pool after DeleteBackend", oldTun.ServerID)
	}

	// 2. The backend_tunnels DB row is gone.
	row, err := db.GetBackendTunnelByServerID(ctx, oldTun.ServerID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if row != nil {
		t.Errorf("backend_tunnels row id=%d still present after DeleteBackend", row.ID)
	}

	// 3. No orphaned session: the connected session must have been
	// reassigned off the deleted tunnel (failover ran before removal).
	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions failed: %v", err)
	}
	for _, sess := range sessions {
		if sess.PeerPublicKey == "peer-del-1" && sess.BackendTunnelID == oldTun.ID {
			t.Errorf("vpn_sessions row for peer-del-1 still references deleted tunnel %d", oldTun.ID)
		}
	}

	// 4. Failover side effects: sticky peer affinity and the live forwarder
	// route must now resolve to the surviving backend, and the connection
	// count must have moved with the session.
	gotTun, _, err := svc.stickyMgr.GetOrAssignBackend(ctx, &loadbalancer.RoutingRequest{
		PeerPublicKey:    "peer-del-1",
		AvailableTunnels: []*models.BackendTunnel{newTun},
	})
	if err != nil {
		t.Fatalf("GetOrAssignBackend after failover failed: %v", err)
	}
	if gotTun.ID != newTun.ID {
		t.Errorf("sticky affinity for peer-del-1 resolves to tunnel %d, want %d", gotTun.ID, newTun.ID)
	}
	if err := svc.forwarder.RouteClientToBackend("peer-del-1", []byte{0xde, 0xad}); err != nil {
		t.Errorf("RouteClientToBackend after failover failed: %v", err)
	}
	if oldTun.ActiveConnections != 0 {
		t.Errorf("deleted backend ActiveConnections = %d, want 0 after migration", oldTun.ActiveConnections)
	}
	if newTun.ActiveConnections != 1 {
		t.Errorf("surviving backend ActiveConnections = %d, want 1 after migration", newTun.ActiveConnections)
	}

	// 5. Deleting an already-deleted backend is a not-found error.
	if err := svc.DeleteBackend(ctx, oldTun.ServerID); err == nil {
		t.Error("second DeleteBackend on deleted backend must fail, got nil")
	} else if !errors.Is(err, ErrBackendTunnelNotFound) {
		t.Errorf("second DeleteBackend error = %v, want ErrBackendTunnelNotFound", err)
	}
}

// TestDeleteBackendMissingDBRowStillSucceeds pins the resilience rule from
// the Issue #29 spec: a missing backend_tunnels DB row must NOT fail the
// delete (log and continue). Simulated by a pool entry without a DB twin —
// DeleteBackendTunnel is invoked on an already-absent row and the call must
// still succeed and drop the tunnel from the pool.
func TestDeleteBackendMissingDBRowStillSucceeds(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	oldTun := lbTunnel(t, svc, db, 921, "awg921", "pub921", "priv921", "10.9.9.121:51820")

	// Remove the DB row behind the pool's back so the sweep-up cleanup finds
	// nothing, while the in-memory pool entry still exists.
	if err := db.DeleteBackendTunnel(ctx, oldTun.ID); err != nil {
		t.Fatalf("setup: DeleteBackendTunnel failed: %v", err)
	}

	if err := svc.DeleteBackend(ctx, oldTun.ServerID); err != nil {
		t.Fatalf("DeleteBackend with missing DB row failed: %v", err)
	}
	if _, err := svc.pool.GetTunnel(oldTun.ServerID); err == nil {
		t.Error("tunnel still in pool after DeleteBackend with missing DB row")
	}
}

// TestDeleteBackendDriftSweepSecondRowForSameServer pins the phase-3
// drift sweep of Service.DeleteBackend. schema.sql has UNIQUE only on
// interface_name (NOT server_id) and CreateBackendTunnel is a plain INSERT,
// so a second backend_tunnels row for the SAME server can legally exist
// under a different interface_name. pool.RemoveTunnel deletes only the row
// matching the in-memory tunnel; the sweep must catch the leftover row:
// reassign its connected sessions onto a surviving active backend and
// delete the row.
func TestDeleteBackendDriftSweepSecondRowForSameServer(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	oldTun := lbTunnel(t, svc, db, 931, "awg931", "pub931", "priv931", "10.9.9.131:51820")
	newTun := lbTunnel(t, svc, db, 932, "awg932", "pub932", "priv932", "10.9.9.132:51820")

	// Surviving active pool tunnels that may legally receive the drifted
	// session (the deleted tunnel itself must never be a target).
	allowedTargets := map[int64]bool{newTun.ID: true}
	for _, tun := range svc.pool.GetActiveTunnels() {
		if tun.ID != oldTun.ID {
			allowedTargets[tun.ID] = true
		}
	}
	if len(allowedTargets) == 0 {
		t.Fatal("setup: no surviving active pool tunnel to fail over onto")
	}

	// Drift: a SECOND backend_tunnels row for server 931 under a different
	// interface_name — legal because UNIQUE is only on interface_name. The
	// pool cannot see this row; only the phase-3 sweep can clean it up.
	leftoverID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      oldTun.ServerID,
		InterfaceName: "awg931-drift",
		PublicKey:     "pub931-drift",
		PrivateKey:    "priv931-drift",
		Endpoint:      "10.9.9.131:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("setup: CreateBackendTunnel (drift row) failed: %v", err)
	}
	if leftoverID == oldTun.ID {
		t.Fatalf("setup: drift row id %d collided with the pool row id", leftoverID)
	}

	// A connected session attached directly to the drifted row: the phase-1
	// failover is keyed on the pool tunnel's ID, so it cannot see this
	// session — only the sweep can reassign it before the row is deleted.
	seed := &models.VPNSession{
		UserID:          uID,
		BackendTunnelID: leftoverID,
		PeerPublicKey:   "peer-drift-1",
		AssignedIP:      "10.201.0.11",
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, seed); err != nil {
		t.Fatalf("setup: CreateVPNSession failed: %v", err)
	}

	if err := svc.DeleteBackend(ctx, oldTun.ServerID); err != nil {
		t.Fatalf("DeleteBackend(%d) failed: %v", oldTun.ServerID, err)
	}

	// 1. NO backend_tunnels row for the server survives. The lookup returns
	// the first matching row, so this catches both the pool row and the
	// drifted leftover.
	row, err := db.GetBackendTunnelByServerID(ctx, oldTun.ServerID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if row != nil {
		t.Errorf("backend_tunnels row id=%d (iface %s) still present for server %d after DeleteBackend", row.ID, row.InterfaceName, oldTun.ServerID)
	}

	// 2. The drifted session was reassigned off the leftover row onto a
	// surviving active tunnel and left draining ('draining' is intentionally
	// terminal per issue #44 — later sweeps must not migrate it again).
	sess, err := db.GetVPNSessionByID(ctx, seed.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if sess == nil {
		t.Fatal("drifted session vanished from vpn_sessions")
	}
	if sess.BackendTunnelID == leftoverID {
		t.Errorf("session %s still references leftover row %d after DeleteBackend", sess.ID, leftoverID)
	}
	if !allowedTargets[sess.BackendTunnelID] {
		t.Errorf("session %s reassigned to tunnel %d, want one of the surviving active tunnels %v", sess.ID, sess.BackendTunnelID, allowedTargets)
	}
	if sess.Status != "draining" {
		t.Errorf("session %s status = %q, want draining after sweep reassignment", sess.ID, sess.Status)
	}
}
