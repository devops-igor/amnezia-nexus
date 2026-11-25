package vpn

// A provider-confirmed absence must disqualify a backend for NEW session assignment,
// independently of its last health sample.
//
// The mark is a statement about the provider's inventory; it is not a health verdict and
// nothing here converts it into one. So the backend keeps its row, its enabled flag, its
// active status and its connection counters, already-admitted sessions keep running, and a
// recovered listing makes it eligible again with no other action.
//
// The fixtures are the ordinary two-backend service (equal weights, least-connections, the
// lower-latency backend winning a tie), and the assertion is on the real route the
// admission registered, not on a selection helper in isolation.

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestIngressAdmissionSkipsProviderAbsentBackend is the decisive case: the backend that
// would otherwise win the selection is the one the provider has deleted.
//
// The unmarked baseline runs on its own fixture, because an admission changes the
// connection counters and a shared fixture would make "the preferred backend" ambiguous.
func TestIngressAdmissionSkipsProviderAbsentBackend(t *testing.T) {
	t.Run("unmarked baseline prefers the lower-latency backend", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		ctx := t.Context()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		peer := seedIngressPeer(t, db, "absence-base", "absence-peer-0000000000", "10.100.9.1")
		_, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
		if err != nil {
			t.Fatalf("baseline admission: %v", err)
		}
		if backend.ServerID != s1ID {
			t.Fatalf("baseline admission chose server %d, want %d: the fixture no longer prefers the backend this test relies on", backend.ServerID, s1ID)
		}
	})

	t.Run("a confirmed absent backend is not an assignment destination", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, s2ID, _, _ := setupTestVPNService(t, db)
		ctx := t.Context()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		before := poolSnapshotServer(t, svc, s1ID)

		// The provider confirms that s1 is gone, before any session is placed. Its status is
		// untouched: this is an inventory fact, not a health sample.
		if err := db.SetServerProviderAbsence(ctx, s1ID, time.Now().UTC(), "acct-absence"); err != nil {
			t.Fatalf("record absence: %v", err)
		}

		peer := seedIngressPeer(t, db, "absence-second", "absence-peer-0000000002", "10.100.9.3")
		sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
		if err != nil {
			t.Fatalf("admission with an absent backend in the pool: %v", err)
		}
		if backend.ServerID == s1ID {
			t.Fatalf("a new session was assigned to the backend the provider confirmed deleted (server %d)", s1ID)
		}
		if backend.ServerID != s2ID {
			t.Fatalf("new session went to server %d, want the available server %d", backend.ServerID, s2ID)
		}
		if got := svc.forwarder.RouteSessionID(peer.peerKey); got != sess.ID {
			t.Fatalf("route session %q, want the admitted session %q", got, sess.ID)
		}

		// Conservation: the absent backend is untouched - same row, same status, same mark.
		after := poolSnapshotServer(t, svc, s1ID)
		if !after.Enabled || after.Status != before.Status || after.ActiveConnections != before.ActiveConnections {
			t.Fatalf("the disqualification changed the tunnel: enabled %v->%v status %q->%q connections %d->%d",
				before.Enabled, after.Enabled, before.Status, after.Status, before.ActiveConnections, after.ActiveConnections)
		}
		server, err := db.GetServer(ctx, s1ID)
		if err != nil || server == nil {
			t.Fatalf("read back the absent server: %v", err)
		}
		if !server.ProviderAbsent() {
			t.Fatal("the mark is gone from the row")
		}

		// Clearing the mark restores eligibility: s2 now holds one connection and s1 none,
		// so least-connections prefers s1 again with no other action.
		if err := db.SetServerProviderAbsence(ctx, s1ID, time.Time{}, ""); err != nil {
			t.Fatalf("clear absence: %v", err)
		}
		recovered := seedIngressPeer(t, db, "absence-third", "absence-peer-0000000003", "10.100.9.4")
		_, recoveredBackend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(recovered))
		if err != nil {
			t.Fatalf("admission after recovery: %v", err)
		}
		if recoveredBackend.ServerID != s1ID {
			t.Fatalf("after the mark was cleared, admission stayed on server %d; server %d is not eligible again", recoveredBackend.ServerID, s1ID)
		}
	})
}

// An absent backend must not be chosen as a migration destination either, even when it is
// the only same-family alternative that would otherwise qualify.
func TestHealthDisableTargetsSkipProviderAbsentBackend(t *testing.T) {
	db := setupTestDB(t)
	svc, s1ID, s2ID, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	tunnel1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	tunnel2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatal(err)
	}

	// s2 is the only same-family alternative, and the provider says it is gone.
	if err := db.SetServerProviderAbsence(ctx, s2ID, time.Now().UTC(), "acct-absence"); err != nil {
		t.Fatalf("record absence: %v", err)
	}
	if targets := svc.healthDisableTargets(ctx, tunnel1); len(targets) != 0 {
		t.Fatalf("an absent backend was offered as a migration destination: %+v", targets[0])
	}

	// Clearing the mark makes the same backend a destination again.
	if err := db.SetServerProviderAbsence(ctx, s2ID, time.Time{}, ""); err != nil {
		t.Fatalf("clear absence: %v", err)
	}
	targets := svc.healthDisableTargets(ctx, tunnel1)
	if len(targets) != 1 || targets[0].ServerID != s2ID {
		t.Fatalf("after recovery the destination list is %v, want just server %d", targets, s2ID)
	}
	_ = tunnel2
}

// poolSnapshotServer reads the pool's copy of a server's tunnel by server id.
func poolSnapshotServer(t *testing.T, svc *Service, serverID int64) *models.BackendTunnel {
	t.Helper()
	tunnel, err := svc.pool.GetTunnel(serverID)
	if err != nil || tunnel == nil {
		t.Fatalf("pool has no tunnel for server %d: %v", serverID, err)
	}
	return tunnel
}
