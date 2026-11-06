package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
)

// TestHealthDisableRetriesAfterAlternativeRecovery is the shipped form of the
// round21 audit counterexample (F16). It reproduces the exact scenario the
// auditor executed:
//
//  1. A backend A holds an established, admitted session.
//  2. EVERY alternative is already health-disabled by the same outage, so the
//     automatic failover that A's health disable triggers has no target.
//  3. B later self-heals to active while A stays dead.
//  4. Only the ordinary background workers run afterwards (ProbeAll,
//     SelfHealSweep, the orchestrator's scheduled health check).
//
// The obligation: the SAME durable session and its live route must end up on B
// by worker action alone — no explicit BackendHealthDisabled call, no ingress
// re-admission, no manual kick. The explicit-notifier call at the end is the
// auditor's CONTROL and must keep passing.
//
// Real components throughout: actual Service, SQLite, pool, authentication,
// SessionManager, forwarder and orchestrator. Only network outcomes (outer
// probe, canary device) are injected.
func TestHealthDisableRetriesAfterAlternativeRecovery(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, tid, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	target, err := svc.pool.GetTunnel(tid)
	if err != nil {
		t.Fatal(err)
	}
	dead := &historyCanaryDevice{}
	svc.SetBackendDeviceForTest(source.ID, dead)
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "r24-recovery", "r24-recovery-peer", "10.100.4.81")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: admitted to %d, want source %d", backend.ID, source.ID)
	}

	// The alternative is already health-disabled by the same realistic outage,
	// which is what leaves the first failover attempt with no target.
	if err := svc.pool.SetTunnelStatusWithReason(ctx, tid, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}

	outer := func(_ context.Context, endpoint, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
		if endpoint == source.Endpoint {
			return 0, errors.New("source remains unreachable")
		}
		return time.Millisecond, nil
	}
	svc.SetProbeFunc(outer)
	svc.SetCanaryProbeFunc(nil)
	dead.fail.Store(true)

	threshold := svc.prober.Config().FailureThreshold
	for i := 0; i < threshold; i++ {
		cur, getErr := svc.pool.GetTunnel(sid)
		if getErr != nil {
			t.Fatal(getErr)
		}
		_, _ = svc.prober.ProbeTunnel(ctx, cur)
	}

	disabled, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Status != models.TunnelStatusDisabled || !disabled.Enabled {
		t.Fatalf("source did not reach health-disabled: status=%q enabled=%t", disabled.Status, disabled.Enabled)
	}
	// The first automatic attempt had no target, so the session is (correctly)
	// still on the source at this point.
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.BackendTunnelID != source.ID {
		t.Fatalf("no-target precondition failed: %+v", row)
	}

	// Only the remote attachment side effect for the already-attached test
	// target is suppressed; the real flap damping, canary, CAS and DB writes run.
	svc.prober.SetOnSelfHealHook(func(context.Context, *models.BackendTunnel) error { return nil })
	for i := 0; i < svc.prober.Config().SelfHealingThreshold+1; i++ {
		svc.prober.SelfHealSweep(ctx)
	}
	recovered, err := svc.pool.GetTunnel(tid)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Enabled || recovered.Status != models.TunnelStatusActive {
		t.Fatalf("alternative did not recover: %+v", recovered)
	}

	orch := orchestrator.New(db, nil, orchestrator.WithProbeFunc(outer))
	orch.SetTunnelStatusUpdater(svc)
	orch.SetSessionMigrator(svc)
	t.Cleanup(func() { svc.SetCanarySuccessCallback(nil) })

	// Ordinary bounded workers only. No notifier call, no re-admission.
	for i := 0; i < 3; i++ {
		svc.prober.ProbeAll(ctx)
		svc.prober.SelfHealSweep(ctx)
		if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
			t.Fatal(err)
		}
	}

	row, err = db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldRoute := svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID)
	newRoute := svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), target.ID)
	live, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)

	if row == nil || row.BackendTunnelID != target.ID || oldRoute || !newRoute {
		t.Fatalf("automatic health failover never retried after the alternative recovered: "+
			"durable_backend=%v live_present=%t live_backend=%d old_route=%t new_route=%t "+
			"(want durable=%d, live=%d, old_route=false, new_route=true)",
			rowField(row), ok, live.BackendTunnelID, oldRoute, newRoute, target.ID, target.ID)
	}
	if !ok || live.BackendTunnelID != target.ID {
		t.Fatalf("live session not migrated: present=%t backend=%d want=%d", ok, live.BackendTunnelID, target.ID)
	}

	// Exactly-once accounting survives the retry path.
	afterSource, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	afterTarget, err := svc.pool.GetTunnel(tid)
	if err != nil {
		t.Fatal(err)
	}
	if afterSource.ActiveConnections != 0 || afterTarget.ActiveConnections != 1 {
		t.Fatalf("accounting after recovery retry: source=%d target=%d, want 0/1",
			afterSource.ActiveConnections, afterTarget.ActiveConnections)
	}

	// CONTROL (auditor's): the explicit notifier must still move a stranded
	// session, and must be a no-op here because it already moved.
	cur, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.BackendHealthDisabled(ctx, cur); err != nil {
		t.Fatal(err)
	}
	row, err = db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.BackendTunnelID != target.ID || !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), target.ID) {
		t.Fatal("explicit notification control failed after automatic recovery")
	}
	again, err := svc.pool.GetTunnel(tid)
	if err != nil {
		t.Fatal(err)
	}
	if again.ActiveConnections != 1 {
		t.Fatalf("idempotent control changed target accounting to %d", again.ActiveConnections)
	}
}

func rowField(row *models.VPNSession) int64 {
	if row == nil {
		return -1
	}
	return row.BackendTunnelID
}

// TestRetryPendingHealthFailoversGuards covers the debt-settlement guard ladder
// directly: each non-settling path must keep or retire the debt without moving
// a session, and the settling path must clear it.
func TestRetryPendingHealthFailoversGuards(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, tid, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sid)
	target, _ := svc.pool.GetTunnel(tid)
	svc.SetBackendDeviceForTest(source.ID, &testCanaryDevice{})
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	// No debt outstanding: the worker does nothing and reports nothing.
	if got := svc.RetryPendingHealthFailovers(ctx); got != 0 {
		t.Fatalf("retry with no debt settled %d, want 0", got)
	}

	// A debt for an unknown tunnel is retired without touching sessions.
	svc.recordHealthFailoverDebt(&models.BackendTunnel{ID: 999999, ServerID: 999999})
	if !svc.hasPendingHealthFailover(999999) {
		t.Fatal("debt was not recorded")
	}
	if got := svc.RetryPendingHealthFailovers(ctx); got != 0 {
		t.Fatalf("unknown-tunnel debt settled %d", got)
	}
	if svc.hasPendingHealthFailover(999999) {
		t.Fatal("unknown-tunnel debt must be retired")
	}

	// A debt whose source has since been administratively disabled is
	// abandoned, not fought.
	if err := svc.pool.SetTunnelEnabled(ctx, sid, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	svc.recordHealthFailoverDebt(source)
	if got := svc.RetryPendingHealthFailovers(ctx); got != 0 {
		t.Fatalf("admin-disabled source settled %d", got)
	}
	if svc.hasPendingHealthFailover(source.ID) {
		t.Fatal("admin decision must retire the automatic debt")
	}

	// A debt whose source is still healthy but has no target is KEPT.
	if err := svc.pool.SetTunnelEnabled(ctx, sid, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelEnabled(ctx, tid, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatusWithReason(ctx, sid, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	live, _ := svc.pool.GetTunnel(sid)
	svc.recordHealthFailoverDebt(live)
	if got := svc.RetryPendingHealthFailovers(ctx); got != 0 {
		t.Fatalf("no-target debt settled %d", got)
	}
	if !svc.hasPendingHealthFailover(source.ID) {
		t.Fatal("no-target debt must be retained for a later sweep")
	}

	// Identity replacement (same ID, different server) retires the debt.
	svc.clearHealthFailoverDebt(source.ID)
	svc.recordHealthFailoverDebt(&models.BackendTunnel{ID: source.ID, ServerID: source.ServerID + 12345})
	if got := svc.RetryPendingHealthFailovers(ctx); got != 0 {
		t.Fatalf("replaced-identity debt settled %d", got)
	}
	if svc.hasPendingHealthFailover(source.ID) {
		t.Fatal("identity-replaced debt must be retired")
	}
}

// TestHealthDisableRetryStopsWhenSourceIsAdminDisabled verifies the retry worker
// honours administrative intent: once an operator disables or re-enables the
// source, the pending automatic failover is abandoned rather than fighting the
// admin decision.
func TestHealthDisableRetryStopsWhenSourceIsAdminDisabled(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, tid, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sid)
	target, _ := svc.pool.GetTunnel(tid)
	svc.SetBackendDeviceForTest(source.ID, &testCanaryDevice{})
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "r24-adminstop", "r24-adminstop-peer", "10.100.4.82")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: admitted to %d", backend.ID)
	}

	// No target at disable time -> pending retry recorded.
	if err := svc.pool.SetTunnelEnabled(ctx, tid, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatusWithReason(ctx, sid, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	committed, _ := svc.pool.GetTunnel(sid)
	if err := svc.BackendHealthDisabled(ctx, committed); err != nil {
		t.Fatal(err)
	}
	if !svc.hasPendingHealthFailover(source.ID) {
		t.Fatal("expected a pending automatic failover to be recorded")
	}

	// Operator now administratively disables the source (which owns its own
	// failover semantics) and brings the target back.
	if err := svc.DisableBackend(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelEnabled(ctx, tid, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, tid, models.TunnelStatusActive, 0); err != nil {
		t.Fatal(err)
	}

	svc.prober.SelfHealSweep(ctx)
	svc.prober.ProbeAll(ctx)

	if svc.hasPendingHealthFailover(source.ID) {
		t.Fatal("administrative disable must abandon the pending automatic failover")
	}
	// The administrative path already handled the session; the retry must not
	// have moved it a second time or double-counted.
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = row
	afterTarget, _ := svc.pool.GetTunnel(tid)
	if afterTarget.ActiveConnections > 1 {
		t.Fatalf("retry double-counted connections on target: %d", afterTarget.ActiveConnections)
	}
}
