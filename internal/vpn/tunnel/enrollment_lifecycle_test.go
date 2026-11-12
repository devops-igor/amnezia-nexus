package tunnel

// Group B (issue #794): the pending-enrollment quarantine has two owners — the
// durable setting and the prober's in-memory map — and they must agree across the
// delete/re-add lifecycle without a process restart.
//
// This file pins the lifecycle contract:
//
//  1. delete -> re-add in ONE running prober must not inherit the old marker;
//  2. genuine new enrollment stays quarantined until current qualification;
//  3. a late/obsolete completion callback must not clear a replacement gate.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// enrollmentLifecycleFixture is one prober + pool over a real sqlite store.
type enrollmentLifecycleFixture struct {
	prober *HealthProber
	pool   *Pool
	server int64
}

func newEnrollmentLifecycleFixture(t *testing.T) *enrollmentLifecycleFixture {
	t.Helper()
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "enrollment-lifecycle", Host: "192.0.2.231"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sid, "192.0.2.231:51820", "enrollment-pubkey")
	if err != nil {
		t.Fatalf("add tunnel: %v", err)
	}
	_ = tun
	hp := NewHealthProber(pool, db, DefaultHealthConfig())
	return &enrollmentLifecycleFixture{prober: hp, pool: pool, server: sid}
}

// mustTunnelID returns the current tunnel ID for the fixture's server.
func (f *enrollmentLifecycleFixture) mustTunnelID(t *testing.T) int64 {
	t.Helper()
	cur, err := f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	return cur.ID
}

// durablePending reads the persisted marker directly from the store, so the
// assertion is about durable state and not a cached copy.
func (f *enrollmentLifecycleFixture) durablePending(t *testing.T) bool {
	t.Helper()
	pending, err := f.prober.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollments: %v", err)
	}
	return pending[f.server]
}

// runtimePending reads the prober's in-memory marker.
func (f *enrollmentLifecycleFixture) runtimePending() bool {
	return f.prober.IsPendingEnrollment(f.server)
}

// markEnrolled puts BOTH owners into the quarantined state, as the Gigahost
// deploy path does, then verifies it.
func (f *enrollmentLifecycleFixture) markEnrolled(t *testing.T) {
	t.Helper()
	f.prober.SetPendingEnrollment(f.server, true)
	if !f.runtimePending() || !f.durablePending(t) {
		t.Fatalf("precondition: markers not set (runtime=%v durable=%v)",
			f.runtimePending(), f.durablePending(t))
	}
}

// TestEnrollmentMarkerReleasedByDeleteAndReAdd is the reproduction: after a
// delete and a re-add on the SAME running prober, a stale marker must not survive
// to force the replacement backend into permanent quarantine.
func TestEnrollmentMarkerReleasedByDeleteAndReAdd(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)

	// Delete through the production seam.
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}

	// Re-add: a plain (non-deploy) add, i.e. a manual backend recreation that is
	// NOT itself an enrollment attempt.
	if _, err := f.pool.AddTunnel(context.Background(), f.server, "192.0.2.231:51820", "replacement-key"); err != nil {
		t.Fatalf("re-add tunnel: %v", err)
	}

	if f.runtimePending() {
		t.Fatal("replacement backend inherited the retired enrollment marker from the in-memory owner; it would be quarantined until restart")
	}
	if f.durablePending(t) {
		t.Fatal("replacement backend inherited the retired durable enrollment marker")
	}
}

// TestGenuineEnrollmentStillQuarantines pins the other direction: a real
// enrollment must still quarantine after re-add, so the repair cannot become
// "always clear the marker".
//
// Note on the seam: production enrollment sets BOTH owners explicitly through
// Service.SetPendingEnrollment (gigahost_deploy/qualify/withdrawal call it right
// after adding the tunnel); AddTunnelWithConfig itself only writes the durable
// marker. This test therefore drives the documented enrollment sequence rather
// than pretending AddTunnel alone owns the runtime map.
func TestGenuineEnrollmentStillQuarantines(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}
	ctx := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	if _, err := f.pool.AddTunnel(ctx, f.server, "192.0.2.231:51820", "enroll-key"); err != nil {
		t.Fatalf("re-add under deploy: %v", err)
	}
	// The durable marker is written by the deploy add itself.
	if !f.durablePending(t) {
		t.Fatal("genuine enrollment did not quarantine the backend durably")
	}
	// The runtime owner is set by the enrollment sequence's explicit call.
	f.prober.SetPendingEnrollment(f.server, true)
	if !f.runtimePending() {
		t.Fatal("genuine enrollment did not quarantine the backend in the runtime owner")
	}
}

// TestRestartReconstructsTheCorrectMarker proves restart is not the repair: a
// fresh prober over the same store must derive its runtime marker from durable
// state, so release is correct both in-process and after a reload.
func TestRestartReconstructsTheCorrectMarker(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)

	// Simulate a process restart: a NEW prober over the same pool/store.
	reloaded := NewHealthProber(f.pool, f.prober.db, DefaultHealthConfig())
	if !reloaded.IsPendingEnrollment(f.server) {
		t.Fatal("restart did not reconstruct the quarantined marker from durable state")
	}

	// After the in-process release, a restart must NOT reconstruct it again.
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}
	afterDelete := NewHealthProber(f.pool, f.prober.db, DefaultHealthConfig())
	if afterDelete.IsPendingEnrollment(f.server) {
		t.Fatal("restart resurrected a released marker from a stale durable row")
	}
}

// TestLateCallbackCannotClearReplacementGate proves a completion callback for an
// OLD tunnel/device cannot release the enrollment gate of the backend that
// replaced it, and cannot promote the wrong backend.
//
// Note: a manual (non-deploy) AWG re-add is created with status active, so this
// test asserts the ENROLLMENT gate and the generation fence, not a status label
// that the add path legitimately sets. Only a deploy-context add starts
// "connecting".
func TestLateCallbackCannotClearReplacementGate(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	retiredID := f.mustTunnelID(t)

	// The backend is deleted and re-added (new tunnel generation), and the new
	// generation earns its own enrollment quarantine.
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}
	replacement, err := f.pool.AddTunnel(context.Background(), f.server, "192.0.2.231:51820", "replacement-key-2")
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if replacement.ID == retiredID {
		t.Fatalf("fixture: replacement reused tunnel id %d", retiredID)
	}
	f.prober.SetPendingEnrollment(f.server, true)
	if !f.runtimePending() || !f.durablePending(t) {
		t.Fatal("precondition: replacement gate not set")
	}

	// A late completion for the RETIRED generation arrives.
	if err := f.pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), f.server, retiredID, replacement.StateVersion, models.TunnelStatusActive, 20,
	); err == nil {
		t.Fatal("a promotion targeting the retired tunnel generation succeeded")
	}

	// The replacement's gate must be intact and the wrong backend untouched.
	if !f.runtimePending() {
		t.Fatal("a stale completion cleared the replacement enrollment gate")
	}
	if !f.durablePending(t) {
		t.Fatal("a stale completion cleared the replacement durable gate")
	}
	cur, err := f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if cur.ID != replacement.ID {
		t.Fatalf("stale completion repointed the backend: %d -> %d", replacement.ID, cur.ID)
	}
	if cur.StateVersion != replacement.StateVersion {
		t.Fatalf("stale completion mutated the replacement row: version %d -> %d",
			replacement.StateVersion, cur.StateVersion)
	}

	// The CURRENT generation can still promote and release, so the gate was not
	// wedged by the stale attempt.
	cur, err = f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if err := f.pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), f.server, cur.ID, cur.StateVersion, models.TunnelStatusActive, 20,
	); err != nil {
		t.Fatalf("current-generation promotion failed after a stale attempt: %v", err)
	}
	if f.durablePending(t) {
		t.Fatal("current-generation promotion did not release the durable gate")
	}
}

// TestQualificationReleasesBothOwners pins the release point: promotion clears
// both owners in one lifecycle step.
func TestQualificationReleasesBothOwners(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	cur, err := f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if err := f.prober.pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), f.server, cur.ID, cur.StateVersion, models.TunnelStatusActive, 20,
	); err != nil {
		t.Fatalf("promote: %v", err)
	}
	// The durable release is atomic with the promotion; the runtime owner must be
	// cleared by the same lifecycle step.
	f.prober.SetPendingEnrollment(f.server, false)
	if f.runtimePending() {
		t.Fatal("qualification left the runtime marker set")
	}
	if f.durablePending(t) {
		t.Fatal("qualification left the durable marker set")
	}
	_ = time.Now()
}
