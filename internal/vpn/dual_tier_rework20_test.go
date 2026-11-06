package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
)

type rework20CanaryDevice struct {
	testCanaryDevice
	fail        bool
	canaryCalls int
}

func (d *rework20CanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	if d.fail {
		return errors.New("rework20 simulated canary timeout")
	}
	return nil
}

// TestDualTier_Rework20_OuterFailureSibling_PreservesEstablishedSession verifies [HIGH F14]:
// When an established backend transitions to handshake_blocked on a transient inner failure,
// and on the next sweep its outer probe fails below threshold (outer-failure sibling path),
// the prober MUST NOT immediately degrade the backend or discard established sessions.
// Established sessions and live forwarder routes remain preserved until sustained consecutive failures reach threshold.
func TestDualTier_Rework20_OuterFailureSibling_PreservesEstablishedSession(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, other, _, _ := setupTestVPNService(t, db)
	svc.SetCanaryProbeFunc(nil)

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatal(err)
	}

	source, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	target, err := svc.pool.GetTunnel(other)
	if err != nil {
		t.Fatal(err)
	}

	dev := &rework20CanaryDevice{fail: true}
	svc.SetBackendDeviceForTest(source.ID, dev)
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "rework20-f14", "rework20-f14-peer", "10.100.3.96")
	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusActive, 0); err != nil {
		t.Fatal(err)
	}

	outerFail := false
	svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		if outerFail {
			return 0, errors.New("simulated transient outer handshake drop")
		}
		return 20 * time.Millisecond, nil
	})

	probe := func(label string) {
		t.Helper()
		cur, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		_, pErr := svc.prober.ProbeTunnel(ctx, cur)
		if outerFail && pErr == nil {
			t.Fatal("expected injected outer probe error")
		}
		if !outerFail && pErr != nil {
			t.Fatal(pErr)
		}
		cur, err = svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := db.GetBackendTunnel(ctx, source.ID)
		if err != nil {
			t.Fatal(err)
		}
		if cur.Status != stored.Status || cur.StateVersion != stored.StateVersion {
			t.Fatalf("pool/DB divergence: pool=%s db=%s", cur.Status, stored.Status)
		}
	}

	// Step 1: Outer PASS, Inner FAIL -> handshake_blocked (inner fail count 1)
	probe("first_inner_failure")
	cur, _ := svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s after first inner failure, got %s", models.TunnelStatusHandshakeBlocked, cur.Status)
	}
	if fc := svc.prober.GetCanaryFailCount(sid); fc != 1 {
		t.Fatalf("expected canaryFailCount 1, got %d", fc)
	}

	// Step 2: Next sweep has Outer FAIL (DPI drop) and Inner FAIL (canary timeout).
	// Under [F14], handleProbeFailure must NOT immediately degrade or drop sessions!
	outerFail = true
	probe("second_inner_failure_outer_fail")
	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("[HIGH F14 REGRESSION] outer-failure sibling degraded backend below threshold! status: %s", cur.Status)
	}
	if fc := svc.prober.GetCanaryFailCount(sid); fc != 2 {
		t.Fatalf("expected canaryFailCount 2 under bounded confirmation, got %d", fc)
	}

	// Verify that ingress reuses the established session and live forwarder route
	again, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != sess.ID {
		t.Fatalf("expected session %s to be preserved, but got %s", sess.ID, again.ID)
	}
	if backend.ID != source.ID {
		t.Fatalf("expected session to stay on source backend %d, but migrated to %d", source.ID, backend.ID)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("expected live forwarder route to remain intact on source backend")
	}

	// Step 3: Third consecutive failure reaches FailureThreshold (3 >= 3) -> transitions to thresholdDisabled
	probe("third_consecutive_failure")
	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s after reaching threshold, got %s", models.TunnelStatusDisabled, cur.Status)
	}
}

// TestDualTier_Rework20_SchedulerSuccess_ClearsHealthProberFailureStreak verifies [HIGH F15]:
// When an established backend has an inner failure recorded by HealthProber (canaryFailCount=1),
// and an intervening scheduler health check verifies inner canary success via Service.ProbeCanary,
// HealthProber's own failure counter MUST be reset to 0 so subsequent non-consecutive timeouts
// do not prematurely disable the backend.
func TestDualTier_Rework20_SchedulerSuccess_ClearsHealthProberFailureStreak(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, other, _, _ := setupTestVPNService(t, db)
	svc.SetCanaryProbeFunc(nil)

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatal(err)
	}

	source, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	target, err := svc.pool.GetTunnel(other)
	if err != nil {
		t.Fatal(err)
	}

	dev := &rework20CanaryDevice{fail: true}
	svc.SetBackendDeviceForTest(source.ID, dev)
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "rework20-f15", "rework20-f15-peer", "10.100.3.95")
	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusActive, 0); err != nil {
		t.Fatal(err)
	}

	svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})

	// Step 1: HealthProber probe: outer PASS, inner FAIL -> handshake_blocked, canaryFailCount = 1
	cur, _ := svc.pool.GetTunnel(sid)
	_, _ = svc.prober.ProbeTunnel(ctx, cur)
	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s, got %s", models.TunnelStatusHandshakeBlocked, cur.Status)
	}
	if fc := svc.prober.GetCanaryFailCount(sid); fc != 1 {
		t.Fatalf("expected canaryFailCount 1, got %d", fc)
	}

	// Step 2: Intervening scheduled health check: inner canary SUCCEEDS
	dev.fail = false
	orch := orchestrator.New(db, nil, orchestrator.WithProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}))
	orch.SetTunnelStatusUpdater(svc)
	orch.SetSessionMigrator(svc)
	t.Cleanup(func() { svc.SetCanarySuccessCallback(nil) })

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("scheduled check failed: %v", err)
	}

	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusActive {
		t.Fatalf("expected status restored to %s, got %s", models.TunnelStatusActive, cur.Status)
	}

	// [HIGH F15 CHECK]: HealthProber's own failure counter MUST be reset to 0!
	if fc := svc.prober.GetCanaryFailCount(sid); fc != 0 {
		t.Fatalf("[HIGH F15 REGRESSION] HealthProber canaryFailCount not reset on scheduler success! got: %d", fc)
	}

	// Step 3: Next ordinary inner timeout (1st failure after recovery) -> records 1, not 2!
	dev.fail = true
	cur, _ = svc.pool.GetTunnel(sid)
	_, _ = svc.prober.ProbeTunnel(ctx, cur)
	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s, got %s", models.TunnelStatusHandshakeBlocked, cur.Status)
	}
	if fc := svc.prober.GetCanaryFailCount(sid); fc != 1 {
		t.Fatalf("expected canaryFailCount to be 1 after recovery, got %d", fc)
	}

	// Step 4: Second ordinary inner timeout -> records 2, not 3! Tunnel stays handshake_blocked
	cur, _ = svc.pool.GetTunnel(sid)
	_, _ = svc.prober.ProbeTunnel(ctx, cur)
	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s to be maintained on second failure, got %s", models.TunnelStatusHandshakeBlocked, cur.Status)
	}
	if fc := svc.prober.GetCanaryFailCount(sid); fc != 2 {
		t.Fatalf("expected canaryFailCount to be 2, got %d", fc)
	}

	// Ingress session and forwarder route must remain intact
	again, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != sess.ID || backend.ID != source.ID {
		t.Fatalf("expected session %s on backend %d to be preserved, got session %s on backend %d", sess.ID, source.ID, again.ID, backend.ID)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("expected live forwarder route to remain intact on source backend")
	}

	// Step 5: Third consecutive failure reaches FailureThreshold (3 >= 3) -> transitions to disabled
	cur, _ = svc.pool.GetTunnel(sid)
	_, _ = svc.prober.ProbeTunnel(ctx, cur)
	cur, _ = svc.pool.GetTunnel(sid)
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s after reaching threshold, got %s", models.TunnelStatusDisabled, cur.Status)
	}
}
