package vpn

// The migration entry point is the destination gate every caller inherits.
//
// Health-disable failover, its retry worker and the scheduled rebalancer all reach the same
// MigrateSession, so a rule implemented there cannot be forgotten by one of them. This is
// asserted through the real service: a marked target refuses the move before any state is
// touched, and clearing the mark lets the ordinary move through.

import (
	"testing"
	"time"
)

func TestMigrateSessionRefusesProviderAbsentTarget(t *testing.T) {
	db := setupTestDB(t)
	svc, s1ID, s2ID, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	// An established session on s1, and s2 is where it would ordinarily move to.
	peer := seedIngressPeer(t, db, "migrate-absence", "migrate-peer-0000000001", "10.100.8.2")
	sess, source, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	if source.ServerID != s1ID {
		t.Fatalf("fixture admitted on server %d, want %d", source.ServerID, s1ID)
	}
	target, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatal(err)
	}

	// The provider confirms the target is gone.
	if err := db.SetServerProviderAbsence(ctx, s2ID, time.Now().UTC(), "acct-migrate"); err != nil {
		t.Fatalf("record absence: %v", err)
	}

	if err := svc.MigrateSession(ctx, sess.ID, target.ID); err == nil {
		t.Fatal("a session was migrated onto the backend the provider confirmed deleted")
	}

	// Nothing moved: the session keeps its backend and its route, and the target kept its
	// row, status and (zero) connection count.
	moved, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil || moved == nil {
		t.Fatalf("read session: %v", err)
	}
	if moved.BackendTunnelID != source.ID {
		t.Fatalf("session backend = %d, want the original %d", moved.BackendTunnelID, source.ID)
	}
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != sess.ID {
		t.Fatalf("session route changed to %q", got)
	}
	after, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Enabled || after.Status != target.Status || after.ActiveConnections != target.ActiveConnections {
		t.Fatalf("the refusal changed the target: enabled %v->%v status %q->%q connections %d->%d",
			target.Enabled, after.Enabled, target.Status, after.Status,
			target.ActiveConnections, after.ActiveConnections)
	}

	// Control: clearing the mark lets the same move through, so the refusal above is the
	// rule and not a broken fixture.
	if err := db.SetServerProviderAbsence(ctx, s2ID, time.Time{}, ""); err != nil {
		t.Fatalf("clear absence: %v", err)
	}
	if err := svc.MigrateSession(ctx, sess.ID, target.ID); err != nil {
		t.Fatalf("after clearing the mark the migration was still refused: %v", err)
	}
	recovered, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil || recovered == nil {
		t.Fatalf("read session after recovery: %v", err)
	}
	if recovered.BackendTunnelID != target.ID {
		t.Fatalf("after recovery the session is on backend %d, want %d", recovered.BackendTunnelID, target.ID)
	}
}
