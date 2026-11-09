package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// issue742NativeVerdict is the injected inner verdict for the native prober.
type issue742NativeVerdict struct {
	fail        bool
	canaryCalls int
}

func (d *issue742NativeVerdict) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	if d.fail {
		return errors.New("simulated inner data-plane loss")
	}
	return nil
}

// issue742JointFixture is one blocked backend carrying an established admitted
// session and live route, with BOTH production writers wired to the same real
// VPN service, pool, session manager, forwarder and sqlite store:
//
//   - the scheduled orchestrator (CheckBackendTunnelHealth -> svc), and
//   - the native HealthProber inside that same service (ProbeTunnel).
//
// Only two things are injected: the outer probe RTT and the device's inner
// verdict. Everything that matters — status CAS, session migration, forwarder
// rewiring and connection counters — is production code.
type issue742JointFixture struct {
	sweep  *issue732SweepFixture
	native *issue742NativeVerdict
}

// issue742Device is a BackendDevice whose canary verdict is shared with the test.
type issue742Device struct {
	inner *issue742NativeVerdict
}

func (d *issue742Device) Read([]byte) (int, error)     { return 0, nil }
func (d *issue742Device) Write(p []byte) (int, error)  { return len(p), nil }
func (d *issue742Device) Close() error                 { return nil }
func (d *issue742Device) IsClosed() bool               { return false }
func (d *issue742Device) CreatedAt() time.Time         { return time.Now() }
func (d *issue742Device) LastHandshakeTime() time.Time { return time.Now() }
func (d *issue742Device) DroppedPackets() uint64       { return 0 }
func (d *issue742Device) ProbeCanary(ctx context.Context, _ time.Duration) error {
	return d.inner.ProbeCanary(ctx, 0)
}

// probeCalls reports the shared inner-probe count so the scheduler fixture's
// observation log reports the device that is actually attached.
func (d *issue742Device) probeCalls() int { return d.inner.canaryCalls }

// newIssue742JointFixture reuses the established issue732 fixture (real
// admission, pinned 500ms persisted threshold, real orchestrator) with the given
// scheduler-side outer RTT, and attaches one device that serves BOTH workers so
// their inner verdicts are observable through a single counter.
func newIssue742JointFixture(t *testing.T, startStatus string, schedulerRTT time.Duration, inner *issue742NativeVerdict) *issue742JointFixture {
	t.Helper()
	base := &issue732CanaryDevice{}
	f := newIssue732SweepFixture(t, startStatus, schedulerRTT, base, base)
	dev := &issue742Device{inner: inner}
	f.svc.SetBackendDeviceForTest(f.source.ID, dev)
	f.inner = dev
	return &issue742JointFixture{sweep: f, native: inner}
}

// slowIssue742Fixture is the F742-01 shape: the scheduler also samples above the
// pinned latency threshold.
func slowIssue742Fixture(t *testing.T, startStatus string, inner *issue742NativeVerdict) *issue742JointFixture {
	t.Helper()
	return newIssue742JointFixture(t, startStatus,
		time.Duration(issue732PinnedThresholdMS+400)*time.Millisecond, inner)
}

// runNative executes ONE real native HealthProber.ProbeTunnel sweep on the
// blocked source backend and reads back the pool and durable status.
func (f *issue742JointFixture) runNative(t *testing.T, rtt time.Duration) (poolStatus, durableStatus string) {
	t.Helper()
	ctx := t.Context()

	f.sweep.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return rtt, nil
	})

	current, err := f.sweep.svc.pool.GetTunnel(f.sweep.source.ServerID)
	if err != nil {
		t.Fatalf("read source tunnel for native probe: %v", err)
	}
	if _, err := f.sweep.svc.prober.ProbeTunnel(ctx, current); err != nil {
		t.Fatalf("native outer probe: %v", err)
	}

	poolTun, err := f.sweep.svc.pool.GetTunnel(f.sweep.source.ServerID)
	if err != nil {
		t.Fatalf("read source tunnel after native probe: %v", err)
	}
	durable, err := f.sweep.svc.db.GetBackendTunnel(ctx, f.sweep.source.ID)
	if err != nil {
		t.Fatalf("read durable source row after native probe: %v", err)
	}
	t.Logf("native probe rtt=%s => pool=%s durable=%s canary_calls=%d",
		rtt, poolTun.Status, durable.Status, f.native.canaryCalls)
	return poolTun.Status, durable.Status
}

// The F742-01 cross-worker defect: the scheduler preserves the blocked source,
// then the NATIVE prober takes one slow SUCCESSFUL outer sample with a working
// inner path and persists degraded, and the next scheduler sweep migrates the
// real session, route and counters. All three are normal sequential workers —
// no race and no concurrency is required.
func TestIssue742_BlockedBackend_NativeSlowOuterSuccess_WorkingInner_PreservesThroughScheduler(t *testing.T) {
	f := slowIssue742Fixture(t, models.TunnelStatusHandshakeBlocked, &issue742NativeVerdict{})

	// 1. The repaired scheduler must preserve the established live path.
	before := f.sweep.sweep(t)
	if before.sourceStatus != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("scheduler precondition: expected handshake_blocked, got %q", before.sourceStatus)
	}
	assertIssue732SessionPreservedOnSource(t, before)

	// 2. One native slow successful outer sample must not remove protection.
	poolStatus, durableStatus := f.runNative(t, time.Duration(issue732PinnedThresholdMS+400)*time.Millisecond)
	if poolStatus != models.TunnelStatusHandshakeBlocked {
		t.Errorf("native worker removed blocked-session protection: pool status %q, want %q",
			poolStatus, models.TunnelStatusHandshakeBlocked)
	}
	if durableStatus != models.TunnelStatusHandshakeBlocked {
		t.Errorf("native worker persisted the wrong status: durable %q, want %q",
			durableStatus, models.TunnelStatusHandshakeBlocked)
	}
	if f.native.canaryCalls == 0 {
		t.Error("expected the native worker to consult the inner canary")
	}

	// 3. The next scheduler sweep must still find the session on the source.
	after := f.sweep.sweep(t)
	assertIssue732SessionPreservedOnSource(t, after)
	if after.sourceStatus != models.TunnelStatusHandshakeBlocked {
		t.Errorf("scheduler after the native worker: expected handshake_blocked, got %q", after.sourceStatus)
	}
}

// Retained control: legitimate fast native recovery still promotes the blocked
// backend and keeps the established session in place.
func TestIssue742_BlockedBackend_NativeFastOuterSuccess_WorkingInner_Recovers(t *testing.T) {
	f := newIssue742JointFixture(t, models.TunnelStatusHandshakeBlocked, 20*time.Millisecond, &issue742NativeVerdict{})

	poolStatus, durableStatus := f.runNative(t, 20*time.Millisecond)
	if poolStatus != models.TunnelStatusActive || durableStatus != models.TunnelStatusActive {
		t.Fatalf("expected native fast recovery to active, got pool=%q durable=%q", poolStatus, durableStatus)
	}
	if f.native.canaryCalls == 0 {
		t.Error("expected the native worker to consult the inner canary on recovery")
	}
	// The scheduler with an equally fast sample must keep the recovered session
	// on the source; this is the recovery half of the preservation contract.
	after := f.sweep.sweep(t)
	if after.sourceStatus != models.TunnelStatusActive {
		t.Errorf("expected the recovered backend to stay active, got %q", after.sourceStatus)
	}
	assertIssue732SessionPreservedOnSource(t, after)
}

// Retained control: sustained genuine inner loss still reaches the failure
// threshold and terminal health disable, so the repair cannot silence it. The
// loop pins the default threshold of 3 by behaviour: if the configured
// threshold ever drifted, the below-threshold assertion would fail rather than
// let this control pass vacuously.
func TestIssue742_BlockedBackend_NativeSlowOuterSuccess_SustainedInnerFailure_Disables(t *testing.T) {
	inner := &issue742NativeVerdict{fail: true}
	f := slowIssue742Fixture(t, models.TunnelStatusHandshakeBlocked, inner)
	const threshold = 3

	var poolStatus, durableStatus string
	for i := 0; i < threshold; i++ {
		poolStatus, durableStatus = f.runNative(t, time.Duration(issue732PinnedThresholdMS+400)*time.Millisecond)
		if i < threshold-1 && poolStatus != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("observation %d of %d: inner loss below threshold must keep handshake_blocked, got %q",
				i+1, threshold, poolStatus)
		}
	}
	if poolStatus != models.TunnelStatusDisabled || durableStatus != models.TunnelStatusDisabled {
		t.Fatalf("expected terminal health disable after %d sustained inner failures, got pool=%q durable=%q",
			threshold, poolStatus, durableStatus)
	}
}

// Retained control: an ADMIN-DISABLED backend is never probed and never has its
// status written, so the repair cannot resurrect it.
func TestIssue742_AdminDisabledBackend_NativeProbeDoesNotWriteStatus(t *testing.T) {
	f := slowIssue742Fixture(t, models.TunnelStatusHandshakeBlocked, &issue742NativeVerdict{})

	ctx := t.Context()
	if err := f.sweep.svc.pool.SetTunnelEnabled(ctx, f.sweep.source.ServerID, false, models.DisableReasonAdmin); err != nil {
		t.Fatalf("admin-disable source backend: %v", err)
	}
	current, err := f.sweep.svc.pool.GetTunnel(f.sweep.source.ServerID)
	if err != nil {
		t.Fatalf("read admin-disabled tunnel: %v", err)
	}
	if _, err := f.sweep.svc.prober.ProbeTunnel(ctx, current); err == nil {
		t.Fatal("expected the native prober to refuse an administratively disabled tunnel")
	}
	after, err := f.sweep.svc.pool.GetTunnel(f.sweep.source.ServerID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	if after.Enabled {
		t.Error("administrative disable was cleared by a native probe")
	}
}

// Retained control: previously-active slow-latency behaviour is unchanged — an
// ACTIVE backend still degrades on a slow native sample.
func TestIssue742_ActiveBackend_NativeSlowOuterSuccess_KeepsLatencyPolicy(t *testing.T) {
	f := slowIssue742Fixture(t, models.TunnelStatusActive, &issue742NativeVerdict{})

	poolStatus, durableStatus := f.runNative(t, time.Duration(issue732PinnedThresholdMS+400)*time.Millisecond)
	if poolStatus != models.TunnelStatusDegraded || durableStatus != models.TunnelStatusDegraded {
		t.Fatalf("previously-active latency policy changed: pool=%q durable=%q, want degraded",
			poolStatus, durableStatus)
	}
}
