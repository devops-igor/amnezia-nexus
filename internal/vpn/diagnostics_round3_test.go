package vpn

// Regression coverage for issue #424 round 3, finding 2: an UNRESOLVED peer
// sync reconciliation failure must hold the health condition DEGRADED until a
// successful reconcile clears it.
//
// The defect this pins: the peer_sync health condition was gated ONLY on the
// windowed deltas SyncFailuresRecent / EnqueueFailuresRecent. Those are rates,
// not states. The tracker returns 0 on its first observation (baseline
// establishment) and falls back to 0 once the cumulative counter stops rising,
// so a peer sync that failed and then went quiet reported HEALTHY while the
// last reconciliation was still failing. The sticky signal already existed and
// already had exactly the right lifecycle: peerSynchronizer.fail sets
// LastError, and only a successful reconcile clears it.
//
// The test drives the real producer (peerSynchronizer.reconcileNow against a
// device whose RemovePeer fails, so a revoked peer cannot be withdrawn) and the
// real consumer (Service.populateOperationalDiagnostics, which samples the
// delta window and then evaluates health). No field is poked by hand.

import (
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// peerSyncHealthWindow bounds the sampling-window advance. The delta tracker
// throttles resampling below 200ms, so the window must exceed that.
const peerSyncHealthWindow = 250 * time.Millisecond

// peerSyncHealthCondition returns the peer_sync DEGRADED condition, if any.
func peerSyncHealthCondition(t *testing.T, status *Status) (string, bool) {
	t.Helper()
	for _, c := range status.HealthAssessment.Conditions {
		if c.Category == "peer_sync" && c.Severity == "DEGRADED" {
			return c.Message, true
		}
	}
	return "", false
}

// TestUnresolvedPeerSyncFailureHoldsDegradedUntilRecovery is the finding-2
// regression: fail, sample, sample again with NO new failure, recover.
func TestUnresolvedPeerSyncFailureHoldsDegradedUntilRecovery(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-health-sticky")
	ps, _, portal := newTestPeerSynchronizer(t, svc, db)

	// newIngressEngineService seeds a half-populated durable row (a client id
	// with no assigned IP). That row genuinely cannot be resolved, so since
	// issue #424 round 4 item G it correctly reports InvalidRows > 0 and holds
	// peer_sync DEGRADED on its own. This test is about LastError stickiness,
	// so the fixture is REPAIRED first: the baseline must really be healthy or
	// the DEGRADED it asserts on later could be coming from the invalid row
	// instead of the unresolved failure. No assertion is relaxed; the
	// precondition is made true.
	ownerUserID := peerOwnerUserID(t, db, peer.publicKey)
	for _, c := range mustGetConnections(t, db) {
		if _, err := db.DeleteConnection(ctx, c.ID); err != nil {
			t.Fatalf("repair seeded fixture rows: %v", err)
		}
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: ownerUserID, ServerID: 0, Protocol: "awg",
		ClientID: peer.publicKey, ClientParams: map[string]any{"assigned_ip": peer.assignedIP},
	}); err != nil {
		t.Fatalf("restore the engine peer row: %v", err)
	}

	// A successful baseline reconcile: no unresolved failure, healthy.
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("baseline reconcile: %v", err)
	}
	if stats := ps.Status(); stats.InvalidRows != 0 {
		t.Fatalf("precondition: the repaired fixture must have no invalid rows, got %+v", stats)
	}
	if stats := ps.Status(); stats.LastError != "" {
		t.Fatalf("precondition: a successful reconcile must leave no LastError, got %q", stats.LastError)
	}

	// sampler is a bare Service: the peer sync delta window and the health
	// evaluation under test need no forwarder or ingress engine.
	sampler := &Service{}

	// ForwarderAvailable and EngineRunning are set by the status assembly in
	// vpn.go, not by populateOperationalDiagnostics. Without them
	// EvaluateForwarderHealth short-circuits to UNAVAILABLE and the peer_sync
	// conditions it appends are never evaluated at all.
	sample := func() *Status {
		t.Helper()
		stats := ps.Status()
		status := &Status{
			ForwarderAvailable: true,
			EngineRunning:      true,
			PeerSync:           &stats,
		}
		sampler.populateOperationalDiagnostics(status)
		return status
	}

	// Prime the delta tracker so the first window is a baseline, not an
	// incident.
	if _, degraded := peerSyncHealthCondition(t, sample()); degraded {
		t.Fatal("precondition: a healthy peer sync must not report a peer_sync DEGRADED condition")
	}

	// Step 1+2: a real reconciliation failure. Revoking the peer durably makes
	// the reconcile withdraw it upstream, which the injected device refuses.
	ps.setPortalDeviceForTest(failingRemovePeerDevice{real: portal})
	if _, err := db.ToggleUser(ctx, peerOwnerUserID(t, db, peer.publicKey), false); err != nil {
		t.Fatalf("durable revocation: %v", err)
	}
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err == nil {
		t.Fatal("expected the reconcile to report the injected removal failure")
	}
	failed := ps.Status()
	if failed.LastError == "" {
		t.Fatal("a failed reconciliation must set LastError")
	}
	if failed.SyncFailures == 0 {
		t.Fatal("a failed reconciliation must raise SyncFailures")
	}

	// Step 3: sample immediately. The recent delta is non-zero here, so the
	// old delta-only gate also reported DEGRADED at this point.
	time.Sleep(peerSyncHealthWindow)
	duringFirst := sample()
	if _, degraded := peerSyncHealthCondition(t, duringFirst); !degraded {
		t.Fatalf("expected peer_sync DEGRADED while the failure is unresolved: %+v",
			duringFirst.HealthAssessment.Conditions)
	}

	// Step 4: advance through another full sampling window with NO new
	// failure. The delta is now 0 on both counters, which is exactly the
	// condition under which the old gate reported HEALTHY.
	time.Sleep(peerSyncHealthWindow)
	duringSecond := sample()
	if duringSecond.PeerSync.SyncFailuresRecent != 0 {
		t.Fatalf("precondition: expected a zero recent sync delta in the quiet window, got %d",
			duringSecond.PeerSync.SyncFailuresRecent)
	}
	if duringSecond.PeerSync.EnqueueFailuresRecent != 0 {
		t.Fatalf("precondition: expected a zero recent enqueue delta in the quiet window, got %d",
			duringSecond.PeerSync.EnqueueFailuresRecent)
	}
	msg, degraded := peerSyncHealthCondition(t, duringSecond)
	if !degraded {
		t.Fatalf("an unresolved failure must stay DEGRADED after the delta window goes quiet; "+
			"conditions were %+v", duringSecond.HealthAssessment.Conditions)
	}
	if !strings.Contains(msg, ps.Status().LastError) {
		t.Errorf("the condition must cite the unresolved error, got %q", msg)
	}
	if !strings.Contains(msg, "recent activity") {
		t.Errorf("the condition must keep the recent-activity context, got %q", msg)
	}
	if duringSecond.HealthAssessment.Status == "HEALTHY" {
		t.Errorf("headline status must not be HEALTHY while a failure is unresolved, got %q",
			duringSecond.HealthAssessment.Status)
	}

	// Step 5+6: a successful reconciliation clears LastError, and health
	// recovers on the next window even though the cumulative counter stays.
	ps.setPortalDeviceForTest(portal)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if stats := ps.Status(); stats.LastError != "" {
		t.Fatalf("a successful reconcile must clear LastError, got %q", stats.LastError)
	}
	time.Sleep(peerSyncHealthWindow)
	after := sample()
	if _, degraded := peerSyncHealthCondition(t, after); degraded {
		t.Fatalf("health must recover after a successful reconcile, got %+v",
			after.HealthAssessment.Conditions)
	}
	if after.PeerSync.SyncFailures == 0 {
		t.Error("the cumulative failure count must survive as history after recovery")
	}
	if after.PeerSync.SyncFailuresRecent != 0 {
		t.Errorf("expected a zero recent sync delta after recovery, got %d",
			after.PeerSync.SyncFailuresRecent)
	}
}

// TestUnresolvedPeerSyncFailureMessageIsBounded pins that an upstream error
// string cannot make the health message (and the API payload carrying it)
// arbitrarily large. peerSynchronizer.fail joins every reconciliation error.
func TestUnresolvedPeerSyncFailureMessageIsBounded(t *testing.T) {
	long := strings.Repeat("peering failure ", 200)
	ps := &PeerSyncStatus{
		DesiredPeers:            1,
		ActualPeers:             1,
		SyncFailures:            3,
		SyncFailuresRecent:      1,
		FailuresWindowSec:       5,
		LastError:               long,
		LastSuccessfulReconcile: time.Now().UTC(),
	}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	if len(conds) != 1 {
		t.Fatalf("expected exactly one condition, got %+v", conds)
	}
	if len(conds[0].Message) > maxDiagnosticErrorTextLen+200 {
		t.Errorf("condition message is unbounded: %d characters", len(conds[0].Message))
	}
	if strings.Contains(conds[0].Message, long) {
		t.Error("the raw error string was embedded without clamping")
	}
	if !strings.Contains(conds[0].Message, "...") {
		t.Errorf("a clamped message must mark the truncation, got %q", conds[0].Message)
	}
}

// TestPeerSyncNoSuccessfulReconcileYet pins that a never-successful reconcile
// is described as "never" rather than rendered as a year 1 timestamp, which
// would read as an infinitely stale reconcile.
func TestPeerSyncNoSuccessfulReconcileYet(t *testing.T) {
	ps := &PeerSyncStatus{LastError: "injected failure"}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	if len(conds) != 1 {
		t.Fatalf("expected exactly one condition, got %+v", conds)
	}
	if !strings.Contains(conds[0].Message, "last successful reconcile never") {
		t.Errorf("a zero reconcile timestamp must read as never, got %q", conds[0].Message)
	}
}

// TestLifetimePeerSyncFailuresWithoutUnresolvedErrorStayHealthy is the negative
// control. A cumulative counter with no unresolved error is history, not a
// current condition: gating on the cumulative value alone would pin DEGRADED
// forever after a single incident.
func TestLifetimePeerSyncFailuresWithoutUnresolvedErrorStayHealthy(t *testing.T) {
	ps := &PeerSyncStatus{
		DesiredPeers:          2,
		ActualPeers:           2,
		SyncFailures:          7,
		AddFailures:           4,
		RemoveFailures:        2,
		UpdateFailures:        1,
		EnqueueFailures:       3,
		LastError:             "",
		LastEnqueueError:      "transient enqueue failure",
		SyncFailuresRecent:    0,
		EnqueueFailuresRecent: 0,
	}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	for _, c := range conds {
		if c.Category == "peer_sync" && c.Severity == "DEGRADED" {
			t.Errorf("lifetime counters with no unresolved reconcile failure must not degrade: %+v", conds)
		}
	}
}

// TestTransientEnqueueFailureDoesNotPinDegradedForever documents why
// LastEnqueueError is NOT a sticky gate. Nothing in the peer synchronizer ever
// clears it, so treating it as an unresolved state would pin DEGRADED
// permanently after a single transient enqueue failure.
func TestTransientEnqueueFailureDoesNotPinDegradedForever(t *testing.T) {
	ps := &PeerSyncStatus{
		DesiredPeers:          1,
		ActualPeers:           1,
		EnqueueFailures:       1,
		LastEnqueueError:      "database listener stopped",
		EnqueueFailuresRecent: 0,
	}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	for _, c := range conds {
		if c.Category == "peer_sync" && c.Severity == "DEGRADED" {
			t.Errorf("an uncleared LastEnqueueError must not pin DEGRADED forever: %+v", conds)
		}
	}
}

// mustGetConnections enumerates every durable connection.
func mustGetConnections(t *testing.T, db *database.DB) []models.UserConnection {
	t.Helper()
	conns, err := db.GetAllConnections(t.Context())
	if err != nil {
		t.Fatalf("enumerate connections: %v", err)
	}
	return conns
}

// peerOwnerUserID returns the user id that owns a peer key. Used to revoke it
// durably so the reconcile has a real withdrawal to fail on.
func peerOwnerUserID(t *testing.T, db *database.DB, peerKey string) string {
	t.Helper()
	userID, _ := peerOwnerOf(t, db, peerKey)
	if userID == "" {
		t.Fatal("no durable user owns the peer key")
	}
	return userID
}
