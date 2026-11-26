package orchestrator

// The scheduled rebalance is its own destination source.
//
// It enumerates DURABLE tunnels (`GetBackendTunnels`) rather than the pool snapshot, so the
// provider-absence filter applied to the snapshot never sees its candidates. The rule it has
// to honour is the same one every other destination consumer honours: a backend the
// provider's inventory has confirmed deleted may not receive a session, independently of its
// last health sample. Both of its write paths are exercised here - the live migrator and the
// DB-only fallback - because they are two different code paths to the same wrong outcome.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// markServerAbsent records a provider absence for the server behind a tunnel.
func markServerAbsent(t *testing.T, f *rebalanceFixture, tunnelID int64) {
	t.Helper()
	tunnel, err := f.db.GetBackendTunnel(context.Background(), tunnelID)
	if err != nil || tunnel == nil {
		t.Fatalf("read tunnel %d: %v", tunnelID, err)
	}
	if err := f.db.SetServerProviderAbsence(context.Background(), tunnel.ServerID, time.Now().UTC(), "acct-rebalance"); err != nil {
		t.Fatalf("record provider absence for server %d: %v", tunnel.ServerID, err)
	}
}

func clearServerAbsence(t *testing.T, f *rebalanceFixture, tunnelID int64) {
	t.Helper()
	tunnel, err := f.db.GetBackendTunnel(context.Background(), tunnelID)
	if err != nil || tunnel == nil {
		t.Fatalf("read tunnel %d: %v", tunnelID, err)
	}
	if err := f.db.SetServerProviderAbsence(context.Background(), tunnel.ServerID, time.Time{}, ""); err != nil {
		t.Fatalf("clear provider absence for server %d: %v", tunnel.ServerID, err)
	}
}

// absenceSetFor is the shared destination decision fed with the marks a pass would read.
func absenceSetFor(t *testing.T, f *rebalanceFixture) models.AbsentServerSet {
	t.Helper()
	ids, err := f.db.ListProviderAbsentServerIDs(context.Background())
	if err != nil {
		t.Fatalf("list provider-absent servers: %v", err)
	}
	return models.NewAbsentServerSet(ids)
}

// TestRebalanceSkipsProviderAbsentDestination is the decisive live-migration case: the
// lightest other backend is the one the provider has deleted.
func TestRebalanceSkipsProviderAbsentDestination(t *testing.T) {
	f := setupRebalanceFixture(t)
	// 9 sessions on t1, 1 on t2: t1's excess is 2, and t2 is the only target.
	for i := 1; i <= 9; i++ {
		f.session(t, fmtSessionID(i), f.t1, "connected")
	}
	f.session(t, fmtSessionID(10), f.t2, "connected")

	markServerAbsent(t, f, f.t2)

	migrator := &mockSessionMigrator{}
	orch := New(f.db, nil, WithSessionMigrator(migrator))
	if err := orch.RebalanceVPNSessions(context.Background()); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}
	if got := migrator.getMigrations(); len(got) != 0 {
		t.Fatalf("%d session(s) were moved onto the backend the provider confirmed deleted (target %d)", len(got), got[0].targetTunnelID)
	}

	// Conservation: nothing else changed. The source sessions stay connected on t1 and the
	// mark is still there.
	for i := 1; i <= 9; i++ {
		sess, err := f.db.GetVPNSessionByID(context.Background(), fmtSessionID(i))
		if err != nil || sess == nil {
			t.Fatalf("read session %d: %v", i, err)
		}
		if sess.BackendTunnelID != f.t1 || sess.Status != "connected" {
			t.Fatalf("session %d was disturbed: backend %d status %q", i, sess.BackendTunnelID, sess.Status)
		}
	}

	// Control in the same run: with the mark cleared, the ordinary eligible move happens
	// (the same two excess sessions, the same target).
	clearServerAbsence(t, f, f.t2)
	recovered := &mockSessionMigrator{}
	orch.SetSessionMigrator(recovered)
	if err := orch.RebalanceVPNSessions(context.Background()); err != nil {
		t.Fatalf("rebalance after recovery failed: %v", err)
	}
	got := recovered.getMigrations()
	if len(got) != 2 {
		t.Fatalf("after clearing the mark, %d session(s) moved, want the ordinary 2", len(got))
	}
	for _, m := range got {
		if m.targetTunnelID != f.t2 {
			t.Fatalf("recovered rebalance target = %d, want %d", m.targetTunnelID, f.t2)
		}
	}
}

// The DB-only fallback is a second write path to the same outcome, so it carries the same
// rule; it also re-reads the destination immediately before the write.
func TestRebalanceDBFallbackSkipsProviderAbsentDestination(t *testing.T) {
	f := setupRebalanceFixture(t)
	for i := 1; i <= 9; i++ {
		f.session(t, fmtSessionID(i), f.t1, "connected")
	}
	f.session(t, fmtSessionID(10), f.t2, "connected")

	markServerAbsent(t, f, f.t2)

	orch := New(f.db, nil) // no migrator: the DB-only path
	if err := orch.RebalanceVPNSessions(context.Background()); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	for _, sess := range f.allSessions(t) {
		if sess.Status == "draining" || sess.BackendTunnelID == f.t2 && sess.ID != fmtSessionID(10) {
			t.Fatalf("DB fallback moved session %s onto backend %d (status %q)", sess.ID, sess.BackendTunnelID, sess.Status)
		}
	}

	// Control: clearing the mark lets the fallback do its ordinary work.
	clearServerAbsence(t, f, f.t2)
	if err := orch.RebalanceVPNSessions(context.Background()); err != nil {
		t.Fatalf("rebalance after recovery failed: %v", err)
	}
	draining := 0
	for _, sess := range f.allSessions(t) {
		if sess.Status == "draining" {
			draining++
			if sess.BackendTunnelID != f.t2 {
				t.Fatalf("a drained session landed on backend %d, want %d", sess.BackendTunnelID, f.t2)
			}
		}
	}
	if draining != 2 {
		t.Fatalf("after clearing the mark, %d session(s) drained, want the ordinary 2", draining)
	}
}

// The shared decision itself: one predicate answers for every destination consumer.
func TestTunnelDestinationDecision(t *testing.T) {
	absent := models.NewAbsentServerSet([]int64{2})
	cases := []struct {
		name     string
		tunnel   models.BackendTunnel
		want     bool
		wantNote string
	}{
		{name: "plain active and present", tunnel: models.BackendTunnel{ServerID: 1, Enabled: true, Status: models.TunnelStatusActive}, want: true},
		{name: "active but provider-absent", tunnel: models.BackendTunnel{ServerID: 2, Enabled: true, Status: models.TunnelStatusActive}, want: false,
			wantNote: "the last health sample is not an existence answer"},
		{name: "administratively disabled", tunnel: models.BackendTunnel{ServerID: 1, Enabled: false, Status: models.TunnelStatusActive}, want: false},
		{name: "runtime-degraded", tunnel: models.BackendTunnel{ServerID: 1, Enabled: true, Status: models.TunnelStatusDegraded}, want: false},
		{name: "handshake-blocked carries its own admission elsewhere", tunnel: models.BackendTunnel{ServerID: 1, Enabled: true, Status: models.TunnelStatusHandshakeBlocked}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tunnel := tc.tunnel
			if got := models.TunnelDestinationAllowed(&tunnel, absent); got != tc.want {
				t.Fatalf("allowed = %v, want %v (%s)", got, tc.want, tc.wantNote)
			}
		})
	}

	// An empty set means "nothing confirmed absent": eligibility falls back to the
	// administrative and runtime facts alone.
	if !models.TunnelDestinationAllowed(&models.BackendTunnel{ServerID: 2, Enabled: true, Status: models.TunnelStatusActive}, nil) {
		t.Fatal("a nil absence set disqualified a healthy backend")
	}

	// The slice helper preserves order and drops only what the predicate refuses.
	list := []*models.BackendTunnel{
		{ID: 10, ServerID: 1, Enabled: true, Status: models.TunnelStatusActive},
		{ID: 20, ServerID: 2, Enabled: true, Status: models.TunnelStatusActive},
		{ID: 30, ServerID: 3, Enabled: true, Status: models.TunnelStatusActive},
	}
	kept := models.EligibleTunnelDestinations(list, absent)
	if len(kept) != 2 || kept[0].ID != 10 || kept[1].ID != 30 {
		t.Fatalf("eligible destinations = %v, want tunnel ids 10 and 30 in order", tunnelIDs(kept))
	}
	// And with nothing absent, the SAME list is returned untouched rather than rebuilt
	// empty, which a caller could mistake for "no candidates".
	if got := models.EligibleTunnelDestinations(list, nil); len(got) != 3 {
		t.Fatalf("an empty absence set changed the candidate list to %d entries", len(got))
	}
}

func tunnelIDs(tunnels []*models.BackendTunnel) []int64 {
	ids := make([]int64, 0, len(tunnels))
	for _, tunnel := range tunnels {
		ids = append(ids, tunnel.ID)
	}
	return ids
}

// The DB-only path re-reads the destination and the marks immediately before writing, so a
// mark recorded after the pass took its snapshot still refuses the move.
func TestRebalanceDBDestinationRevalidatedBeforeWrite(t *testing.T) {
	f := setupRebalanceFixture(t)
	orch := New(f.db, nil)
	ctx := context.Background()

	// The pass-level snapshot says nothing is absent...
	snapshot := absenceSetFor(t, f)
	if orch.dbTargetEligible(ctx, f.t2, snapshot) != true {
		t.Fatal("an unmarked destination was refused by the pre-write revalidation")
	}

	// ...and a mark recorded afterwards still refuses it, because the helper re-reads.
	markServerAbsent(t, f, f.t2)
	if orch.dbTargetEligible(ctx, f.t2, snapshot) {
		t.Fatal("the pre-write revalidation trusted a stale snapshot instead of re-reading the mark")
	}

	// Clearing the mark restores eligibility through the same path.
	clearServerAbsence(t, f, f.t2)
	if !orch.dbTargetEligible(ctx, f.t2, absenceSetFor(t, f)) {
		t.Fatal("after the mark was cleared, the destination stayed ineligible")
	}
}
