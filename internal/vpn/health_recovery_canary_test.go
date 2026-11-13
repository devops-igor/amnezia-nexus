package vpn

// Consumer-level recovery proof for the health-disabled backend requirement:
// a backend that health probing withdrew must be able to come back through
// fresh matched in-tunnel replies on its EXISTING attached device while the
// outer handshake is still failing — without the outer handshake ever being
// reported as healthy, and without overriding any other authority.
//
// Chain exercised (production code except where stated):
//
//	REAL HealthProber.ProbeTunnel / SelfHealSweep / CanaryAdmissible
//	  -> REAL Service.EnableBackend self-heal hook wiring
//	  -> REAL tunnel.Pool CAS + DB row
//	  -> REAL Forwarder routes, REAL SessionManager sessions
//	  -> REAL ingress engine (netstack client) for payload
//
// Fixture-only parts: the outer handshake outcome is injected through the
// existing ProbeFunc seam, and the backend data device is an in-memory netstack
// echo wrapper that answers the genuine matched ICMP canary through the real
// CanaryResponseDemuxer path. No canary override is installed, so every verdict
// comes from the real in-tunnel probe. The fixture is shared with the #731
// admission tests (canary_admission_e2e_test.go).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// healthDisabledRecoveryEnv is the shared #731 fixture viewed as a backend that
// can be driven into health-disable and back.
type healthDisabledRecoveryEnv struct {
	*canaryAdmissionEnv
}

func newHealthDisabledRecoveryEnv(t *testing.T) *healthDisabledRecoveryEnv {
	t.Helper()
	return &healthDisabledRecoveryEnv{canaryAdmissionEnv: newCanaryAdmissionEnv(t)}
}

// setOuterHandshake installs the injected outer handshake outcome.
func (e *healthDisabledRecoveryEnv) setOuterHandshake(fails bool) {
	e.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		if fails {
			return 0, fmt.Errorf("outer handshake dropped")
		}
		return 20 * time.Millisecond, nil
	})
}

// driveToHealthDisabled takes the backend to disabled/health through the real
// failing-outer + failing-inner path and returns the disabled row.
func (e *healthDisabledRecoveryEnv) driveToHealthDisabled(t *testing.T) *models.BackendTunnel {
	t.Helper()
	e.setOuterHandshake(true)
	e.dev.state.Store(canaryDevDead)
	for i := 0; i < e.svc.prober.Config().FailureThreshold; i++ {
		e.oneSweep(t)
	}
	return e.requireRecoveryStatus(t, "precondition", models.TunnelStatusDisabled, models.DisableReasonHealth)
}

// heal runs the automatic recovery sweeps and returns the resulting row.
func (e *healthDisabledRecoveryEnv) heal(t *testing.T) *models.BackendTunnel {
	t.Helper()
	e.healSweeps(t)
	return e.readTunnel(t)
}

// healSweeps runs the automatic recovery sweeps without reading the row back,
// so a case that expects the tunnel to be gone can use it.
func (e *healthDisabledRecoveryEnv) healSweeps(t *testing.T) {
	t.Helper()
	for i := 0; i < e.svc.prober.Config().SelfHealingThreshold+1; i++ {
		e.svc.prober.SelfHealSweep(t.Context())
	}
}

// readTunnel returns the current pool row for the candidate backend.
func (e *healthDisabledRecoveryEnv) readTunnel(t *testing.T) *models.BackendTunnel {
	t.Helper()
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	return cur
}

// requireRecoveryStatus asserts the in-memory row and the durable row agree.
func (e *healthDisabledRecoveryEnv) requireRecoveryStatus(t *testing.T, who, status, reason string) *models.BackendTunnel {
	t.Helper()
	cur := e.readTunnel(t)
	if cur.Status != status || cur.DisableReason != reason {
		t.Fatalf("%s: pool status = %q/%q, want %q/%q", who, cur.Status, cur.DisableReason, status, reason)
	}
	dbRow, err := e.svc.db.GetBackendTunnel(t.Context(), cur.ID)
	if err != nil || dbRow == nil {
		t.Fatalf("%s: read durable row: %v", who, err)
	}
	if dbRow.Status != status || dbRow.DisableReason != reason {
		t.Fatalf("%s: durable status = %q/%q, want %q/%q", who, dbRow.Status, dbRow.DisableReason, status, reason)
	}
	return cur
}

// TestHealthDisabledBackendRecoversOnFreshCanaryWithFailingOuter is the headline
// requirement: repeated outer-handshake failure plus fresh successful matched
// in-tunnel replies restores routing eligibility through the existing attached
// device, and the restored label is handshake_blocked, never active.
func TestHealthDisabledBackendRecoversOnFreshCanaryWithFailingOuter(t *testing.T) {
	e := newHealthDisabledRecoveryEnv(t)
	disabled := e.driveToHealthDisabled(t)
	if e.dev.IsClosed() {
		t.Fatal("health disable closed the attached device; the established station is gone")
	}

	// The device still answers the genuine in-tunnel canary, while the outer
	// handshake keeps failing exactly as before the disable.
	e.dev.state.Store(canaryDevAlive)
	e.heal(t)
	recovered := e.requireRecoveryStatus(t, "recovery", models.TunnelStatusHandshakeBlocked, models.DisableReasonNone)
	if recovered.StateVersion <= disabled.StateVersion {
		t.Fatalf("recovery did not advance state_version: %d then %d", disabled.StateVersion, recovered.StateVersion)
	}
	// Truthful labeling: the outer handshake never succeeded, so the backend must
	// not report active and must not claim a latency sample from a failed probe.
	if recovered.LatencyMS != 0 {
		t.Fatalf("recovery reported latency=%d from a failed outer handshake, want 0", recovered.LatencyMS)
	}
	if got := e.svc.GetBackendDeviceForTest(e.blocked.ID); got != e.dev {
		t.Fatal("recovery replaced the attached device instead of preserving it")
	}
}

// TestHealthDisabledBackendRecoveryPreservesSessionsRoutesAndPayload proves the
// recovered backend is the SAME working backend: the established session and
// forwarder route survive, its connection accounting is unchanged, and both the
// established client and a brand-new client complete real bidirectional payload
// through it under the existing #731 admission policy.
func TestHealthDisabledBackendRecoveryPreservesSessionsRoutesAndPayload(t *testing.T) {
	e := newHealthDisabledRecoveryEnv(t)
	conn, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "recovery-existing")
	if err != nil {
		t.Fatalf("initial admission on the active backend: %v", err)
	}
	if err := echo(conn, "recovery-pre-disable", 5*time.Second); err != nil {
		t.Fatalf("pre-disable payload: %v", err)
	}
	preOwnership := e.ownership(t, e.existing.publicKey)
	if !preOwnership.admitted || preOwnership.activeConns != 1 {
		t.Fatalf("precondition ownership = %+v", preOwnership)
	}

	e.driveToHealthDisabled(t)
	withdrawn := e.ownership(t, e.existing.publicKey)
	if withdrawn.sessionID != preOwnership.sessionID || withdrawn.routeSessionID != preOwnership.sessionID {
		t.Fatalf("health disable discarded the established session/route: before %+v after %+v", preOwnership, withdrawn)
	}
	if e.dev.IsClosed() {
		t.Fatal("health disable closed the device instead of leaving the established data path attached")
	}

	e.dev.state.Store(canaryDevAlive)
	e.heal(t)
	e.requireRecoveryStatus(t, "recovery", models.TunnelStatusHandshakeBlocked, models.DisableReasonNone)

	after := e.ownership(t, e.existing.publicKey)
	if after.sessionID != preOwnership.sessionID {
		t.Fatalf("recovery replaced the established session: %q -> %q", preOwnership.sessionID, after.sessionID)
	}
	if after.routeSessionID != preOwnership.sessionID {
		t.Fatalf("recovery lost the forwarder route: %q, want %q", after.routeSessionID, preOwnership.sessionID)
	}
	if after.activeConns != preOwnership.activeConns {
		t.Fatalf("recovery changed connection accounting: %d -> %d", preOwnership.activeConns, after.activeConns)
	}
	if err := echo(conn, "recovery-preserved-route", 5*time.Second); err != nil {
		t.Fatalf("established client lost payload after recovery: %v", err)
	}

	// A brand-new client must now be admitted onto the recovered backend and
	// carry payload, under the unchanged #731 blocked-backend policy.
	fresh, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "recovery-fresh")
	if err != nil {
		t.Fatalf("new client refused on the recovered backend: %v", err)
	}
	if err := echo(fresh, "recovery-new-client", 5*time.Second); err != nil {
		t.Fatalf("new client got no bidirectional payload: %v", err)
	}
	// Admission must not relabel the backend: the outer handshake is still failing.
	if cur := e.readTunnel(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("admission relabelled the recovered backend to %q", cur.Status)
	}
	if got := e.svc.GetBackendDeviceForTest(e.blocked.ID); got != e.dev {
		t.Fatal("recovery replaced the attached device instead of preserving it")
	}
}

// TestHealthDisabledBackendRecoveryRefusals pins every case where automatic
// recovery must stay out: no evidence, failed evidence, unverifiable identity,
// sustained inner loss, and each competing authority.
func TestHealthDisabledBackendRecoveryRefusals(t *testing.T) {
	t.Run("inner canary still failing keeps the backend withdrawn", func(t *testing.T) {
		e := newHealthDisabledRecoveryEnv(t)
		e.driveToHealthDisabled(t)
		e.dev.state.Store(canaryDevDead)
		if cur := e.heal(t); cur.Status != models.TunnelStatusDisabled {
			t.Fatalf("recovery promoted a backend whose inner path is confirmed dead: %q", cur.Status)
		}
	})

	t.Run("no attached device is not unconditional success", func(t *testing.T) {
		e := newHealthDisabledRecoveryEnv(t)
		e.driveToHealthDisabled(t)
		// Unknown health must never be read as health: with no device in the
		// provider the prober cannot obtain in-tunnel evidence at all.
		e.svc.SetBackendDeviceForTest(e.blocked.ID, nil)
		if cur := e.heal(t); cur.Status != models.TunnelStatusDisabled {
			t.Fatalf("recovery promoted a backend with no verifiable data path: %q", cur.Status)
		}
	})

	t.Run("administrative disable is never overridden", func(t *testing.T) {
		e := newHealthDisabledRecoveryEnv(t)
		e.driveToHealthDisabled(t)
		e.dev.state.Store(canaryDevAlive)
		if err := e.svc.pool.SetTunnelEnabled(t.Context(), e.blocked.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("administrative disable: %v", err)
		}
		e.heal(t)
		cur := e.readTunnel(t)
		if cur.Enabled {
			t.Fatal("automatic recovery re-enabled an administratively disabled backend")
		}
	})

	t.Run("pending enrollment quarantine is never released", func(t *testing.T) {
		e := newHealthDisabledRecoveryEnv(t)
		e.driveToHealthDisabled(t)
		e.dev.state.Store(canaryDevAlive)
		e.svc.prober.SetPendingEnrollment(e.blocked.ServerID, true)
		if cur := e.heal(t); cur.Status != models.TunnelStatusDisabled {
			t.Fatalf("automatic recovery released the enrollment quarantine: %q", cur.Status)
		}
	})

	t.Run("deleted tunnel is not resurrected", func(t *testing.T) {
		e := newHealthDisabledRecoveryEnv(t)
		e.driveToHealthDisabled(t)
		e.dev.state.Store(canaryDevAlive)
		if err := e.svc.pool.RemoveTunnel(t.Context(), e.blocked.ServerID); err != nil {
			t.Fatalf("remove tunnel: %v", err)
		}
		e.healSweeps(t)
		if _, err := e.svc.pool.GetTunnel(e.blocked.ServerID); err == nil {
			t.Fatal("automatic recovery recreated a deleted tunnel")
		}
	})

	t.Run("sustained inner failure withdraws the recovered backend again", func(t *testing.T) {
		e := newHealthDisabledRecoveryEnv(t)
		e.driveToHealthDisabled(t)
		e.dev.state.Store(canaryDevAlive)
		e.heal(t)
		e.requireRecoveryStatus(t, "recovery", models.TunnelStatusHandshakeBlocked, models.DisableReasonNone)

		// The inner path now genuinely fails while the outer handshake still
		// does: confirmed sustained loss must withdraw eligibility again.
		e.dev.state.Store(canaryDevDead)
		for i := 0; i < e.svc.prober.Config().FailureThreshold; i++ {
			e.oneSweep(t)
		}
		e.requireRecoveryStatus(t, "re-withdrawal", models.TunnelStatusDisabled, models.DisableReasonHealth)
	})
}
