package vpn

// Group A completion (issue #794): the attachment-failure path and the
// orchestrator's scheduled health writer must both preserve the same working
// backend, in realistic alternating sequence, after the native prober has already
// established fresh matched inner evidence.
//
// This reuses the existing #742 joint fixture, which wires BOTH production
// writers to one real Service, pool, sqlite store, session manager and
// forwarder:
//
//	orchestrator.CheckBackendTunnelHealth  -> svc (scheduled writer)
//	HealthProber.ProbeTunnel               -> svc.prober (native prober)
//
// Only the outer RTT and the device's inner verdict are injected. Status CAS,
// session migration, forwarder rewiring and connection counters are production
// code. This file adds the attachment-hook failure as a THIRD writer so the
// realistic interleaving is covered.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// setHookFails installs the attachment-hook outcome on the joint fixture's
// service, which is the same seam Service wires to ensureBackendDeviceAttached.
func (f *issue742JointFixture) setHookFails(fails bool) {
	f.sweep.svc.prober.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error {
		if fails {
			return errors.New("data-plane attach failed: remote peer registration unavailable")
		}
		return nil
	})
}

// probeNativeOnce runs one real native ProbeTunnel on the source backend and
// returns the resulting pool and durable status.
func (f *issue742JointFixture) probeNativeOnce(t *testing.T, rtt time.Duration) (poolStatus, durableStatus string) {
	t.Helper()
	ctx := t.Context()
	f.sweep.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return rtt, nil
	})
	live, err := f.sweep.svc.pool.GetTunnel(f.sweep.source.ServerID)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if _, err := f.sweep.svc.prober.ProbeTunnel(ctx, live); err != nil {
		t.Logf("native probe returned %v", err)
	}
	cur, err := f.sweep.svc.pool.GetTunnel(f.sweep.source.ServerID)
	if err != nil {
		t.Fatalf("re-read source: %v", err)
	}
	row, err := f.sweep.svc.db.GetBackendTunnel(ctx, cur.ID)
	if err != nil || row == nil {
		t.Fatalf("read durable row: %v", err)
	}
	return cur.Status, row.Status
}

// TestIssue794_HookFailurePreservedThroughNativeAndScheduledWriters is the
// realistic multi-writer sequence: native recovery establishes fresh inner
// evidence, attachment failures then reach their threshold through the native
// path, and the scheduled orchestrator writer runs in between. No writer may
// withdraw or migrate the backend, and the established session, route,
// accounting and payload must survive every step.
func TestIssue794_HookFailurePreservedThroughNativeAndScheduledWriters(t *testing.T) {
	// Healthy scheduler RTT on purpose: the schedulers's own slow-outer latency
	// policy is a separate, pre-existing contract (#732), so a degradation here
	// could only come from the attachment path under test.
	f := newIssue742JointFixture(t, models.TunnelStatusHandshakeBlocked, 20*time.Millisecond, &issue742NativeVerdict{})

	// 1. Fresh matched inner evidence from the attached device, established by the
	//    real native prober with a healthy outer handshake.
	poolStatus, durableStatus := f.probeNativeOnce(t, 20*time.Millisecond)
	if poolStatus != models.TunnelStatusActive {
		t.Fatalf("native precondition: pool status %q, want active after a healthy probe", poolStatus)
	}
	if durableStatus != poolStatus {
		t.Fatalf("native precondition: durable %q disagrees with pool %q", durableStatus, poolStatus)
	}
	if f.native.canaryCalls == 0 {
		t.Fatal("native precondition: the inner canary was never consulted, so there is no fresh evidence")
	}

	// The established session and its live route, captured before the failures.
	preserved := f.sweep.sweep(t)
	assertIssue732SessionPreservedOnSource(t, preserved)

	// 2. Attachment failures reach the threshold through the native path, with the
	//    scheduled orchestrator writer running between each one.
	threshold := f.sweep.svc.prober.Config().FailureThreshold
	f.setHookFails(true)
	for i := 0; i < threshold; i++ {
		ps, ds := f.probeNativeOnce(t, 20*time.Millisecond)
		if ps == models.TunnelStatusDisabled || ds == models.TunnelStatusDisabled {
			t.Fatalf("attachment failure %d of %d disabled the backend (pool=%q durable=%q) despite fresh inner evidence",
				i+1, threshold, ps, ds)
		}
		// The scheduled writer runs in the same interval and must agree.
		obs := f.sweep.sweep(t)
		if obs.sourceStatus == models.TunnelStatusDisabled {
			t.Fatalf("scheduled writer disabled the backend after attachment failure %d", i+1)
		}
		assertIssue732SessionPreservedOnSource(t, obs)
	}

	// 3. Final state: one working backend, its established session and route, and
	//    a NEW client still admitted onto it with payload.
	final := f.sweep.sweep(t)
	if final.sourceStatus == models.TunnelStatusDisabled {
		t.Fatalf("final scheduled sweep left the backend disabled: %q", final.sourceStatus)
	}
	assertIssue732SessionPreservedOnSource(t, final)
	if row, err := f.sweep.svc.db.GetBackendTunnel(t.Context(), f.sweep.source.ID); err != nil || row == nil {
		t.Fatalf("read final durable row: %v", err)
	} else if row.Status == models.TunnelStatusDisabled {
		t.Fatalf("durable row health-disabled at the end: %q/%q", row.Status, row.DisableReason)
	}
}

// TestIssue794_HookFailurePreservedThenSustainedInnerLossWithdraws is the
// control for the same multi-writer sequence: once the inner path is genuinely
// lost, the attachment threshold must still withdraw the backend and the
// established session must follow the existing failover policy. Preservation
// cannot become immortality.
func TestIssue794_HookFailurePreservedThenSustainedInnerLossWithdraws(t *testing.T) {
	inner := &issue742NativeVerdict{}
	f := newIssue742JointFixture(t, models.TunnelStatusHandshakeBlocked, 20*time.Millisecond, inner)

	if ps, _ := f.probeNativeOnce(t, 20*time.Millisecond); ps != models.TunnelStatusActive {
		t.Fatalf("precondition: native probe left pool status %q, want active", ps)
	}
	f.sweep.sweep(t)

	// Preserved while the inner path answers.
	threshold := f.sweep.svc.prober.Config().FailureThreshold
	f.setHookFails(true)
	for i := 0; i < threshold; i++ {
		ps, _ := f.probeNativeOnce(t, 20*time.Millisecond)
		if ps == models.TunnelStatusDisabled {
			t.Fatalf("attachment failure %d of %d disabled the backend before the inner path was lost", i+1, threshold)
		}
	}

	// The inner path is now genuinely lost; the attachment threshold must
	// withdraw eligibility again.
	inner.fail = true
	var last string
	for i := 0; i < threshold; i++ {
		last, _ = f.probeNativeOnce(t, 20*time.Millisecond)
		if last == models.TunnelStatusDisabled {
			break
		}
		f.sweep.sweep(t)
	}
	if last != models.TunnelStatusDisabled {
		t.Fatalf("sustained attachment failure with a lost inner path never withdrew the backend: %q", last)
	}
}
