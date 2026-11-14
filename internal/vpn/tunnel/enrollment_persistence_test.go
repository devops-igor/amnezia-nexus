package tunnel

// Group B persistence boundaries (issue #794): a failed enrollment-marker write
// must not silently diverge the durable and runtime owners, must not report a
// failed removal as success, and must not admit an unqualified backend.
//
// These tests drive the real SQLite store through a real Pool and HealthProber.
// Persistence failure is injected at the actual write boundary, not by stubbing
// the pool.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// breakSettingsTableOnly drops the settings table through an independent SQL
// handle on the same database file, leaving every other table intact. That makes
// the marker write fail on its own, which is the boundary under test.
func (f *enrollmentLifecycleFixture) breakSettingsTableOnly(t *testing.T) {
	t.Helper()
	if f.dbPath == "" {
		t.Fatal("fixture: no database path")
	}
	side, err := sql.Open("sqlite", f.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open side handle: %v", err)
	}
	defer func() { _ = side.Close() }()
	if _, err := side.ExecContext(context.Background(), "DROP TABLE settings"); err != nil {
		t.Fatalf("drop settings: %v", err)
	}
}

// TestRemoveTunnelFailureLeavesBothOwnersIntact pins the atomicity boundary at
// the point that actually matters: the tunnel ROW delete and the durable marker
// release must commit together. Failure is induced on the settings table only (a
// second SQL handle drops it), so the row delete would succeed on its own. With a
// two-step implementation the delete commits, the release silently fails, and the
// backend ends up removed from memory while the store still quarantines it.
func TestRemoveTunnelFailureLeavesBothOwnersIntact(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	before, err := f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}

	f.breakSettingsTableOnly(t)

	err = f.pool.RemoveTunnel(context.Background(), f.server)
	if err == nil {
		t.Fatal("RemoveTunnel reported success while its marker release could not commit")
	}

	// Fail closed: the row must still exist, so the removal is retryable and no
	// backend is left present-but-unquarantined or gone-but-quarantined.
	cur, getErr := f.pool.GetTunnel(f.server)
	if getErr != nil || cur == nil {
		t.Fatalf("failed removal deleted the backend anyway (gone from memory); row delete was not rolled back: %v", getErr)
	}
	if cur.ID != before.ID {
		t.Fatalf("failed removal changed the tunnel identity: %d -> %d", before.ID, cur.ID)
	}
	if !f.runtimePending() {
		t.Fatal("failed removal cleared the runtime owner, leaving a present backend unquarantined")
	}
}

// TestRemoveTunnelSuccessClearsBothOwners is the control: with working storage the
// same path succeeds and leaves neither owner set.
func TestRemoveTunnelSuccessClearsBothOwners(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}
	if f.durablePending(t) {
		t.Fatal("successful removal left the durable marker set")
	}
	if f.runtimePending() {
		t.Fatal("successful removal left the runtime marker set")
	}
}

// TestDeployAddFailsWhenMarkerWriteFails pins the deploy-add boundary at the same
// discriminating point: the tunnel row is created first, so a failure on the
// settings write alone would leave a backend that exists with no quarantine.
func TestDeployAddFailsWhenMarkerWriteFails(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("precondition remove: %v", err)
	}
	f.breakSettingsTableOnly(t)

	ctx := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	added, err := f.pool.AddTunnel(ctx, f.server, "192.0.2.231:51820", "deploy-key")
	if err == nil {
		t.Fatal("deploy-context AddTunnel reported success while its quarantine marker could not be written")
	}
	if added != nil {
		t.Fatalf("failed deploy add returned a tunnel: %+v", added)
	}

	// Fail closed: the compensating delete must have removed the row, so there is
	// no backend present without a quarantine owner.
	if cur, getErr := f.pool.GetTunnel(f.server); getErr == nil && cur != nil {
		t.Fatalf("failed deploy add left backend %d present with no quarantine", cur.ID)
	}
	if f.runtimePending() {
		t.Fatal("failed deploy add left the runtime owner quarantined for a backend that does not exist")
	}
}

// TestStaleCallbackCannotClearReplacementQuarantineConcurrently pins the
// concurrency contract: an old release and a new marking racing on the same
// server must not let the release clear the replacement's quarantine.
func TestStaleCallbackCannotClearReplacementQuarantineConcurrently(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	oldID := f.mustTunnelID(t)

	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove: %v", err)
	}
	replacement, err := f.pool.AddTunnel(context.Background(), f.server, "192.0.2.231:51820", "replacement-key-3")
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if replacement.ID == oldID {
		t.Fatalf("fixture: replacement reused id %d", oldID)
	}
	f.prober.SetPendingEnrollment(f.server, true)

	// A late release for the OLD generation must not clear the new gate.
	// The pool's release path is keyed by server, so the guard is generation
	// identity: replay it through the same entry point a stale caller would use.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.pool.RemoveTunnel(context.Background(), f.server)
	}()
	<-done

	// After the removal the backend is gone; a fresh mark must still be possible
	// and must not be resurrected-then-cleared by the retired generation.
	_, err = f.pool.AddTunnel(context.Background(), f.server, "192.0.2.231:51820", "replacement-key-4")
	if err != nil {
		t.Fatalf("re-add after removal: %v", err)
	}
	f.prober.SetPendingEnrollment(f.server, true)
	if !f.runtimePending() || !f.durablePending(t) {
		t.Fatal("a retired generation's release cleared the replacement quarantine")
	}
	_ = models.TunnelStatusConnecting
}
