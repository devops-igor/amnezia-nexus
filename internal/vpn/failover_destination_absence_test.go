package vpn

// Administrative failover when a candidate goes absent between the snapshot and the choice.
//
// The disable takes its absence snapshot before the service lock, persists the disable,
// detaches the source and only then hands candidates to the sticky failover. An independent
// inventory cycle writes absence under the database lock alone, so it can commit a mark in
// exactly that interval. The failover must therefore make the decision at the moment it
// chooses, not from the snapshot it was given.
//
// These tests drive the REAL DisableBackend, a real SQLite store, the real sticky selector and
// the real forwarder, and assert the actual route. Ordering is deterministic: the mark is
// committed from a hook that runs after the candidate snapshot and before the selection, so the
// race is reproduced instead of hoped for.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// failoverFixture is a service with three active backends of one family, a peer on the
// preferred target and a live route for it.
type failoverFixture struct {
	svc    *Service
	db     ingressTestDB
	source *models.BackendTunnel
	first  *models.BackendTunnel
	second *models.BackendTunnel
	peer   ingressTestPeer
	sess   *models.VPNSession
}

// newFailoverFixture builds the three-backend topology and admits one peer onto the source.
func newFailoverFixture(t *testing.T) *failoverFixture {
	t.Helper()
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tunnels := svc.pool.GetActiveTunnels()
	if len(tunnels) != 2 {
		t.Fatalf("fixture expects two active tunnels, found %d", len(tunnels))
	}
	// A third backend gives the failover a genuine alternative after the preferred one is
	// excluded, which is what "following the available alternative" means.
	srv3, err := svc.db.CreateServer(ctx, &models.Server{Name: "AP South", Host: "198.51.100.3", Protocols: map[string]any{
		"awg": map[string]any{"public_key": "ap-south-pubkey", "port": 51820},
	}})
	if err != nil {
		t.Fatalf("create third server: %v", err)
	}
	if _, err := svc.db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: srv3, InterfaceName: "awg-be-3", PublicKey: "ap-south-pubkey",
		PrivateKey: "ap-south-privkey", Endpoint: "198.51.100.3:51820", Status: "active", LatencyMS: 70,
	}); err != nil {
		t.Fatalf("create third tunnel: %v", err)
	}
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	byLatency := svc.pool.GetActiveTunnels()
	if len(byLatency) != 3 {
		t.Fatalf("fixture expects three active tunnels, found %d", len(byLatency))
	}

	peer := seedIngressPeer(t, db, "failover-absence", "failover-peer-0000000001", "10.100.7.2")
	sess, source, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("admission: %v", err)
	}

	f := &failoverFixture{svc: svc, db: db, source: source, peer: peer, sess: sess}
	for _, tunnel := range byLatency {
		if tunnel.ID == source.ID {
			continue
		}
		if f.first == nil || tunnel.LatencyMS < f.first.LatencyMS {
			f.second = f.first
			f.first = tunnel
			continue
		}
		if f.second == nil || tunnel.LatencyMS < f.second.LatencyMS {
			f.second = tunnel
		}
	}
	if f.first == nil || f.second == nil {
		t.Fatal("fixture did not build two alternative backends")
	}
	return f
}

// markAbsent records a provider absence for a tunnel's server.
func (f *failoverFixture) markAbsent(t *testing.T, tunnel *models.BackendTunnel) {
	t.Helper()
	if err := f.svc.db.SetServerProviderAbsence(context.Background(), tunnel.ServerID, time.Now().UTC(), "acct-failover"); err != nil {
		t.Fatalf("record absence for server %d: %v", tunnel.ServerID, err)
	}
}

// TestAdminFailoverSkipsADestinationMarkedAfterTheSnapshot is the decisive case: the preferred
// alternative goes absent after the disable snapshotted candidates but before the selector
// chose, and the peer must still end up on a backend that exists.
func TestAdminFailoverSkipsADestinationMarkedAfterTheSnapshot(t *testing.T) {
	f := newFailoverFixture(t)

	// The mark commits at the exact boundary the review describes: after the candidate
	// snapshot, before the destination choice.
	f.svc.stickyMgr.SetCandidateSnapshotHookForTest(func() { f.markAbsent(t, f.first) })
	t.Cleanup(func() { f.svc.stickyMgr.SetCandidateSnapshotHookForTest(nil) })

	if err := f.svc.DisableBackend(context.Background(), f.source.ServerID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// The real route must point at the available alternative, never at the backend that went
	// absent before the choice.
	f.assertRoutedTo(t, f.second, f.first)

	// And the durable row agrees with the route.
	row, err := f.svc.db.GetVPNSessionByID(context.Background(), f.sess.ID)
	if err != nil || row == nil {
		t.Fatalf("read session: %v", err)
	}
	if row.BackendTunnelID != f.second.ID {
		t.Fatalf("durable backend %d disagrees with the route's backend %d", row.BackendTunnelID, f.second.ID)
	}

	// Conservation: the absent backend was not disabled, deleted, or otherwise converted.
	absentTunnel, err := f.svc.pool.GetTunnel(f.first.ServerID)
	if err != nil || absentTunnel == nil {
		t.Fatalf("the marked backend disappeared from the pool: %v", err)
	}
	if !absentTunnel.Enabled || absentTunnel.Status != f.first.Status {
		t.Fatalf("the refusal changed the marked backend: enabled %v->%v status %q->%q",
			f.first.Enabled, absentTunnel.Enabled, f.first.Status, absentTunnel.Status)
	}
}

// The same disable with nothing marked keeps the ordinary behaviour: the preferred backend
// takes the peer. Without this control the test above could pass by never failing over at all.
func TestAdminFailoverWithoutAMarkUsesThePreferredBackend(t *testing.T) {
	f := newFailoverFixture(t)

	if err := f.svc.DisableBackend(context.Background(), f.source.ServerID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	f.assertRoutedTo(t, f.first, f.second)
}

// A mark that is already present when the operation starts is excluded as well (the case the
// round-18 review confirmed works), so this file covers both orderings.
func TestAdminFailoverSkipsADestinationMarkedBeforeTheOperation(t *testing.T) {
	f := newFailoverFixture(t)
	f.markAbsent(t, f.first)

	if err := f.svc.DisableBackend(context.Background(), f.source.ServerID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	f.assertRoutedTo(t, f.second, f.first)
}

// An unreadable mark store is UNKNOWN: the peer must not be moved on the strength of the
// snapshot, and it must be reported rather than silently stranded or silently allowed.
func TestAdminFailoverRefusesToChooseWhenAbsenceIsUnknown(t *testing.T) {
	f := newFailoverFixture(t)
	f.svc.stickyMgr.SetCandidateSnapshotHookForTest(func() { f.failAbsentReads(t) })
	t.Cleanup(func() { f.svc.stickyMgr.SetCandidateSnapshotHookForTest(nil) })

	if err := f.svc.DisableBackend(context.Background(), f.source.ServerID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// The route keeps pointing at the backend it had: neither alternative was chosen on stale
	// information. (The source is being disabled, so this is a report-and-retry outcome, not a
	// claim that the peer keeps a working path.)
	f.assertRoutedTo(t, f.source, f.first, f.second)
	// And it is visible: the skip is counted, not silent.
	if got := f.svc.stickyMgr.SkippedMigrationsTotal(); got == 0 {
		t.Fatal("the refusal was not reported as a skipped migration")
	}
}

// routedTo reports whether the peer's live route points at the given backend, using the
// forwarder's own checked assertion (session, connection, IP and backend must all agree).
func (f *failoverFixture) routedTo(t *testing.T, tunnel *models.BackendTunnel) bool {
	t.Helper()
	return f.svc.forwarder.HasSessionRoute(f.peer.peerKey, f.sess.ID, f.peer.connID, f.peer.ip.String(), tunnel.ID)
}

// assertRoutedTo fails unless the live route points at want, and reports where it does point
// when it does not.
func (f *failoverFixture) assertRoutedTo(t *testing.T, want *models.BackendTunnel, alternatives ...*models.BackendTunnel) {
	t.Helper()
	if f.routedTo(t, want) {
		return
	}
	for _, other := range alternatives {
		if f.routedTo(t, other) {
			t.Fatalf("the peer is routed to backend %d (server %d), want backend %d",
				other.ID, other.ServerID, want.ID)
		}
	}
	t.Fatalf("the peer has no checked route (route session %q, admitted session %q)",
		f.svc.forwarder.RouteSessionID(f.peer.peerKey), f.sess.ID)
}

// failAbsentReads makes the sticky manager's provider-absence re-read fail, using the same
// wrapper seam the failover fault-injection tests already use. The service's own reads are not
// exercised here: this test is about the destination decision refusing on unknown information.
func (f *failoverFixture) failAbsentReads(t *testing.T) {
	t.Helper()
	f.svc.stickyMgr.SetAbsentReadFailureForTest(errors.New("injected: absence store unreadable"))
}
