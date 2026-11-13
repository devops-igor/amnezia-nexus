package tunnel

// Ownership transfer of the runtime caller mark across a sequential enrollment
// retry (issue #794 group B).
//
// A backend has three quarantine owners. The durable row and the pool's generation
// gate are re-bound to a new enrollment attempt by the pool itself. The prober's
// server-keyed caller mark is established BEFORE that attempt exists, by a deploy
// consumer that marks the server while the slot still holds the previous row, so it
// keeps whichever attempt last wrote it — and a FAILED attempt stamps it on the way
// out. Without a producer statement re-binding it, the successful retry's own
// release is refused and the next ordinary healthy sweep re-applies the quarantine.
//
// These tests pin that statement and, just as importantly, the transfer it must NOT
// perform: stealing a later attempt's mark, inventing a mark that does not exist, or
// transferring ownership from an enrollment that never committed.

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// runtimeMark reads the caller mark ALONE. IsPendingEnrollment ORs in the pool's
// generation gate, so it can be true while the caller mark is already released; a
// test about the caller mark must not read that combined answer as proof of the map.
func (f *enrollmentLifecycleFixture) runtimeMark() bool {
	f.prober.mu.RLock()
	defer f.prober.mu.RUnlock()
	return f.prober.pendingEnrollment[f.server]
}

// enrollmentOwnerState is the three quarantine owners a qualifiable backend has.
type enrollmentOwnerState struct{ durable, pool, runtime bool }

// ownerState reads the three quarantine owners of the fixture's server as they are
// actually persisted/held, so an assertion is about state rather than an error code.
func (f *enrollmentLifecycleFixture) ownerState() enrollmentOwnerState {
	pending, err := f.prober.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		panic("read durable enrollment: " + err.Error())
	}
	return enrollmentOwnerState{
		durable: pending[f.server],
		pool:    f.pool.EnrollmentPending(f.server),
		runtime: f.runtimeMark(),
	}
}

// failedAttemptThenRetry produces the real handoff: attempt A is issued and its
// caller mark is stamped by A (what withdrawObservedBackendLocked does for a failed
// qualification), then a committed retry B re-enrolls the same row.
func failedAttemptThenRetry(t *testing.T, f *enrollmentLifecycleFixture) (attemptA, attemptB *models.BackendTunnel) {
	t.Helper()
	ctx := context.Background()
	deploy := context.WithValue(ctx, DeployEnrollmentKey, true)

	f.prober.SetPendingEnrollment(f.server, true) // the deploy consumer's premark
	attemptA, err := f.pool.AddTunnel(deploy, f.server, "192.0.2.231:51820", "enrollment-pubkey")
	if err != nil {
		t.Fatalf("enrollment A: %v", err)
	}
	if attemptA.EnrollmentAttempt == 0 {
		t.Fatal("fixture: attempt A carries no attempt id")
	}
	// The failed enrollment's withdraw path stamps the caller mark with its own
	// attempt, exactly as Service.WithdrawObservedEnrollment does.
	f.prober.MarkEnrollmentForAttempt(f.server, attemptA.ID, attemptA.EnrollmentAttempt)

	f.prober.SetPendingEnrollment(f.server, true) // the retry's own premark
	attemptB, err = f.pool.AddTunnel(deploy, f.server, "192.0.2.231:51820", "enrollment-pubkey")
	if err != nil {
		t.Fatalf("enrollment B: %v", err)
	}
	if attemptB.ID != attemptA.ID {
		t.Fatalf("fixture: the retry moved to a different row %d -> %d", attemptA.ID, attemptB.ID)
	}
	if attemptB.EnrollmentAttempt == attemptA.EnrollmentAttempt {
		t.Fatalf("fixture: the retry did not start a new attempt (still %d)", attemptB.EnrollmentAttempt)
	}
	return attemptA, attemptB
}

// TestCallerMarkOwnershipFollowsCommittedRetry is the direct regression for the
// sequential handoff: after the retry commits, its own release must work, and the
// failed attempt's release must still be refused.
func TestCallerMarkOwnershipFollowsCommittedRetry(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	attemptA, attemptB := failedAttemptThenRetry(t, f)

	// Before the service publishes the retry's attempt, the mark still belongs to
	// the FAILED attempt and its release is refused — this is the defect state.
	if !f.runtimeMark() {
		t.Fatal("fixture: the caller mark is not set")
	}

	// The owner statement: the enrollment that committed attempt B owns this mark.
	f.prober.AdoptEnrollmentAttempt(f.server, attemptB.ID, attemptB.EnrollmentAttempt)

	// The failed attempt's release is still refused: adoption must not turn the
	// fence into an unconditional release.
	f.prober.ReleaseEnrollmentForAttempt(f.server, attemptA.EnrollmentAttempt)
	if !f.runtimeMark() {
		t.Fatal("the FAILED attempt's release cleared the retry's caller mark")
	}

	// The retry's own release now succeeds, and the durable/pool owners are
	// untouched by any runtime release.
	if own := f.ownerState(); !own.durable || !own.pool {
		t.Fatalf("fixture: the committed retry is not quarantined: %+v", own)
	}
	f.prober.ReleaseEnrollmentForAttempt(f.server, attemptB.EnrollmentAttempt)
	if f.runtimeMark() {
		t.Fatal("the retry could not release the caller mark it now owns")
	}
	if own := f.ownerState(); !own.durable || !own.pool {
		t.Fatalf("a caller-mark release disturbed the durable/pool owners: %+v", own)
	}
	// Its qualification then commits and admits.
	cur, err := f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if err := f.pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), f.server, cur.ID, cur.StateVersion, models.TunnelStatusActive, 20,
	); err != nil {
		t.Fatalf("qualified retry promotion: %v", err)
	}
	if own := f.ownerState(); own.durable || own.pool || own.runtime {
		t.Fatalf("the qualified retry kept an owner: %+v", own)
	}
}

// TestAdoptNeverStealsALaterAttempt pins the ordering half: attempt ids are
// monotonic and never reused, so a recorded owner GREATER than the one being
// adopted belongs to a later enrollment. A delayed publication for a superseded
// enrollment must not take that gate over.
func TestAdoptNeverStealsALaterAttempt(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	attemptA, attemptB := failedAttemptThenRetry(t, f)

	f.prober.AdoptEnrollmentAttempt(f.server, attemptB.ID, attemptB.EnrollmentAttempt)

	// A late publication carrying the SUPERSEDED attempt arrives now.
	f.prober.AdoptEnrollmentAttempt(f.server, attemptA.ID, attemptA.EnrollmentAttempt)

	// B still owns it: B's release works, A's does not.
	f.prober.ReleaseEnrollmentForAttempt(f.server, attemptA.EnrollmentAttempt)
	if !f.runtimeMark() {
		t.Fatal("a superseded attempt's adoption stole the current attempt's mark")
	}
	f.prober.ReleaseEnrollmentForAttempt(f.server, attemptB.EnrollmentAttempt)
	if f.runtimeMark() {
		t.Fatal("the current attempt could not release its own mark")
	}
}

// TestAdoptCreatesNoMark is the smallest-boundary control: adoption transfers
// ownership of an EXISTING mark and never establishes one. A backend that no
// caller marked has no runtime owner to hand over, so nothing is quarantined on
// its behalf.
func TestAdoptCreatesNoMark(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	ctx := context.Background()
	deploy := context.WithValue(ctx, DeployEnrollmentKey, true)
	// A deploy add with no consumer premark: no caller mark exists.
	enrolled, err := f.pool.AddTunnel(deploy, f.server, "192.0.2.231:51820", "enrollment-pubkey")
	if err != nil {
		t.Fatalf("deploy add: %v", err)
	}
	f.prober.AdoptEnrollmentAttempt(f.server, enrolled.ID, enrolled.EnrollmentAttempt)

	own := f.ownerState()
	if own.runtime {
		t.Fatal("adoption invented a runtime quarantine for a backend no caller marked")
	}
	if !own.durable || !own.pool {
		t.Fatalf("fixture: the deploy add did not establish its own quarantine: %+v", own)
	}
}

// TestFailedEnrollmentCommitDoesNotConsumePriorProtection is the adjacent negative
// the assignment calls out: a new enrollment whose commit is REFUSED must not take
// ownership away from the attempt that still legitimately holds the mark.
//
// The refusal is the pool's own version-fenced reset against a stale expected
// version, i.e. the same "changed concurrently or row is missing" path a real
// conflicting writer produces. Nothing about the previous owner may move.
func TestFailedEnrollmentCommitDoesNotConsumePriorProtection(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	attemptA, _ := failedAttemptThenRetry(t, f)

	// Another writer moved the row's health after B's reset, so the next deploy
	// re-enrollment's fenced reset is stale and must be refused.
	ctx := context.Background()
	if err := f.pool.SetTunnelStatus(ctx, f.server, models.TunnelStatusConnecting, 5); err != nil {
		t.Fatalf("intervening health write: %v", err)
	}
	stale, err := f.pool.GetTunnel(f.server)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	refused, err := f.prober.db.ResetBackendTunnelForEnrollment(
		ctx, stale.ID, stale.StateVersion-1, map[string]any{"endpoint": "192.0.2.250:51820"},
	)
	if err != nil {
		t.Fatalf("refused reset reported an error instead of a refusal: %v", err)
	}
	if refused {
		t.Fatal("fixture: the fenced reset was not refused")
	}

	// No attempt was issued for the refused enrollment, so no quarantine owner was
	// released by it — the intervening health write and the refusal changed nothing
	// about ownership.
	if own := f.ownerState(); !own.durable || !own.pool {
		t.Fatalf("a refused enrollment commit released a quarantine owner: %+v", own)
	}
	if routableID := f.pool.GetActiveTunnels(); len(routableID) != 0 {
		t.Fatalf("a refused enrollment commit admitted the backend: %d active", len(routableID))
	}
	// The failed attempt's release is still refused, exactly as before. (The
	// intervening health write legitimately cleared the caller mark, so the
	// assertion is that A's release did not MOVE anything: the durable and pool
	// owners still hold the backend, and it is still unroutable.)
	f.prober.ReleaseEnrollmentForAttempt(f.server, attemptA.EnrollmentAttempt)
	if own := f.ownerState(); !own.durable || !own.pool {
		t.Fatalf("the failed attempt released an owner of an enrollment it never owned: %+v", own)
	}
	if routableID := f.pool.GetActiveTunnels(); len(routableID) != 0 {
		t.Fatalf("the failed attempt made the backend routable: %d active", len(routableID))
	}
}
