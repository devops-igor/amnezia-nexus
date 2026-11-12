package tunnel

// Retired-owner isolation for the enrollment release path (issue #794 group B).
//
// Pool.RemoveTunnel releases locks in this order:
//
//	p.mu.Lock -> delete row + entries -> capture hook -> p.mu.Unlock -> hook(ctx, serverID)
//
// The callback carries only serverID, so a replacement that is added and
// quarantined in the unlocked window is indistinguishable from the retired
// backend and loses its runtime marker. Synchronous execution in the same call
// does NOT exclude that: another goroutine can acquire p.mu in the gap.
//
// These tests force that exact window with a barrier instead of racing for it.

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestRetiredReleaseCannotClearReplacementQuarantineAfterUnlock forces the
// production window deterministically:
//
//  1. remove the backend, pausing inside the registration callback so the pool
//     lock has already been released;
//  2. while paused, create and quarantine a replacement through the real pool;
//  3. release the old callback and assert the replacement keeps BOTH markers,
//     its row identity, and remains non-selectable until qualification.
func TestRetiredReleaseCannotClearReplacementQuarantineAfterUnlock(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	retiredID := f.mustTunnelID(t)

	// Replace the release callback with one that pauses AFTER the pool unlocked.
	entered := make(chan struct{})
	resume := make(chan struct{})
	var observedPending bool
	f.pool.SetEnrollmentReleaseHook(func(ctx context.Context, serverID, retiredTunnelID int64) {
		close(entered)
		<-resume
		// The real runtime owner release, executed late, exactly as the
		// production callback would.
		f.prober.releaseRuntimeEnrollmentIfGeneration(serverID, retiredTunnelID)
		observedPending = f.prober.IsPendingEnrollment(serverID)
	})

	removed := make(chan error, 1)
	go func() { removed <- f.pool.RemoveTunnel(context.Background(), f.server) }()

	// The pool lock is released at this point and the row is gone.
	<-entered

	// --- the window: a concurrent replacement arrives and is quarantined ---
	replacement, err := f.pool.AddTunnel(context.Background(), f.server, "192.0.2.231:51820", "replacement-gen2")
	if err != nil {
		t.Fatalf("add replacement inside the window: %v", err)
	}
	if replacement.ID == retiredID {
		t.Fatalf("fixture: replacement reused retired id %d", retiredID)
	}
	f.prober.SetPendingEnrollment(f.server, true)
	if !f.runtimePending() || !f.durablePending(t) {
		t.Fatal("precondition: replacement quarantine not established")
	}

	// --- release the retired callback now ---
	close(resume)
	if err := <-removed; err != nil {
		t.Fatalf("removal failed: %v", err)
	}

	// The retired release must not have touched the replacement's gate.
	if !f.runtimePending() {
		t.Fatal("the retired generation's release cleared the REPLACEMENT runtime quarantine (observed pending=" +
			boolStr(observedPending) + ")")
	}
	if !f.durablePending(t) {
		t.Fatal("the retired generation's release cleared the replacement durable quarantine")
	}
	cur, err := f.pool.GetTunnel(f.server)
	if err != nil || cur == nil {
		t.Fatalf("read replacement: %v", err)
	}
	if cur.ID != replacement.ID {
		t.Fatalf("replacement identity changed: %d -> %d", replacement.ID, cur.ID)
	}
	// The runtime owner is what gates admission for a quarantined backend
	// (GetActiveTunnels keys on status alone, and a manual re-add is created
	// active), so assert the owner rather than the raw status list.
	if !f.prober.IsPendingEnrollment(f.server) {
		t.Fatal("replacement is no longer quarantined, so it would be admitted unqualified")
	}

	// And the CURRENT generation can still qualify and release normally.
	cur, err = f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read replacement: %v", err)
	}
	if err := f.pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), f.server, cur.ID, cur.StateVersion, models.TunnelStatusActive, 20,
	); err != nil {
		t.Fatalf("current qualification after the retired release: %v", err)
	}
	if f.durablePending(t) {
		t.Fatal("current qualification did not release the replacement durable gate")
	}
}

// TestRetiredReleaseBlockedByGenerationAlsoLeavesOtherServersAlone is the control
// that a generation-safe release does not become a no-op for the case it exists
// for: a plain removal with NO replacement must still clear the runtime marker.
func TestRemovalWithNoReplacementStillReleasesRuntime(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}
	if f.runtimePending() {
		t.Fatal("a plain removal with no replacement left the runtime marker set")
	}
	if f.durablePending(t) {
		t.Fatal("a plain removal with no replacement left the durable marker set")
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
