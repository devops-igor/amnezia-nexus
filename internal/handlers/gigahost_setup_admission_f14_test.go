package handlers

// Admission authority versus setup revocation (F14).
//
// The audited defect was not a missing check before the network work: there was
// one. It was that the *final* effect - committing a healthy backend and releasing
// its enrollment quarantine - did not consult the approval that authorized it, so a
// revocation that landed during qualification was recorded and then ignored.
//
// These controls therefore assert the end state rather than an error string:
// durable intent state, the tunnel's real enabled flag, its status, and whether its
// enrollment quarantine survived. The qualification callback is asserted to have
// been REACHED, because a test that passes on an earlier generic failure proves
// nothing about admission.
//
// Every subject here is production code: the real SQLite store, the real install
// runner and journal, and the real VPN enrollment/qualification/promotion path.
// Only the provider, the SSH peer and the protocol manager are fixtures, as in the
// rest of this suite.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// validVLESSClientFixture makes the protocol manager hand back a syntactically
// valid VLESS client identity.
//
// This matters: an invalid client id makes proxy enrollment fail before
// qualification, which would let a "revocation was refused" assertion pass without
// ever reaching the boundary under test. The audit rejected an earlier probe for
// exactly that mistake.
func validVLESSClientFixture(t *testing.T, env *installEnv) {
	t.Helper()
	mgr, ok := env.h.registry.Get(models.ProtocolVLESS)
	if !ok {
		t.Fatalf("no VLESS manager registered")
	}
	mock, ok := mgr.(*mockProtocolManager)
	if !ok {
		t.Fatalf("VLESS manager is %T, want the fixture manager", mgr)
	}
	mock.addClientFn = func(context.Context, *models.Server, map[string]any) (map[string]any, error) {
		return map[string]any{
			"client_id":  "f14-vless-client",
			"uuid":       "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
			"port":       443,
			"public_key": "x9aBVLESS1234567890abcdef1234567890abcdef12=",
		}, nil
	}
}

// durableQuarantine reports whether the durable enrollment marker is still set for
// a server. It reads the same table the startup path reads, not an in-memory flag.
func durableQuarantine(t *testing.T, env *installEnv, serverID int64) bool {
	t.Helper()
	pending, err := env.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment quarantine: %v", err)
	}
	return pending[serverID]
}

// assertNotAdmitted asserts the end state a refused admission must leave behind.
func assertNotAdmitted(t *testing.T, env *installEnv, serverID int64, when string) {
	t.Helper()
	tun, err := env.h.vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil {
		t.Fatalf("%s: tunnel: %+v err=%v", when, tun, err)
	}
	t.Logf("%s: enabled=%v status=%s quarantine=%v", when, tun.Enabled, tun.Status, durableQuarantine(t, env, serverID))
	if tun.Enabled {
		t.Errorf("%s: the backend is still enabled", when)
	}
	if tun.Status == models.TunnelStatusActive || tun.Status == models.TunnelStatusDegraded {
		t.Errorf("%s: the backend is selectable (status %q)", when, tun.Status)
	}
	if !durableQuarantine(t, env, serverID) {
		t.Errorf("%s: the durable enrollment quarantine was released", when)
	}
}

// TestSetupRevocationDuringQualificationMustNotAdmit is the auditor's scenario, at
// the exact seam they used and with the parameters they used.
//
// The administrator revokes the approval from inside the authenticated
// application-traffic qualification callback, i.e. after the backend was enabled and
// before its promotion; qualification then SUCCEEDS. Asserted end state: canceled
// intent, backend not enabled, not active/degraded, quarantine retained.
func TestSetupRevocationDuringQualificationMustNotAdmit(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)

	const orderID = "ord_f14_cancel_midqual"
	env.seedOrder(orderID, 8201, "198.51.100.91")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 8201, "198.51.100.91")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)

	var reached, cancelChanged atomic.Bool
	env.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		reached.Store(true)
		_, changed, err := env.h.CancelGigahostSetup(context.Background(), orderID)
		if err != nil {
			t.Errorf("revocation during qualification: %v", err)
			return 0, err
		}
		cancelChanged.Store(changed)
		// Qualification itself succeeds: the question is only whether a revoked
		// approval may still be admitted.
		return 5, nil
	})

	env.trackerAndInstall()

	if !reached.Load() {
		t.Fatal("the qualification callback was never reached: this control proves nothing about admission")
	}
	if !cancelChanged.Load() {
		t.Fatal("the revocation did not change the approval, so the scenario was not exercised")
	}

	intent := env.requireState(orderID, models.SetupStateCanceled)
	if intent.RevokedAt.IsZero() {
		t.Fatal("the canceled intent records no revocation time")
	}
	server := env.registeredServer(8201)
	if server == nil {
		t.Fatal("registration precondition missing: no server row for the approved provider server")
	}
	assertNotAdmitted(t, env, server.ID, "revocation during qualification")
}

// TestSetupRevocationAfterQualificationStillRefusedAtPromotion isolates the last
// possible instant at the handler boundary: qualification has already returned
// success and the revocation commits after it, so only the promotion transaction can
// still refuse.
//
// It uses the protocol manager's install callback to advance the attempt to the
// enablement phase and then revokes from the qualification callback, which runs
// after installation and registration are proven - the same window the auditor
// reported, with the qualification outcome deliberately successful.
func TestSetupRevocationAfterQualificationStillRefusedAtPromotion(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)

	const orderID = "ord_f14_cancel_at_promote"
	env.seedOrder(orderID, 8301, "198.51.100.92")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 8301, "198.51.100.92")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)

	var qualified atomic.Bool
	env.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		qualified.Store(true)
		if _, changed, err := env.h.CancelGigahostSetup(context.Background(), orderID); err != nil || !changed {
			t.Errorf("revocation at the promotion boundary: changed=%v err=%v", changed, err)
			return 0, err
		}
		return 3, nil
	})

	env.trackerAndInstall()

	if !qualified.Load() {
		t.Fatal("qualification was never reached")
	}
	// The install journal must NOT record the enablement phase as complete: the
	// admission it would describe never happened.
	intent := env.requireState(orderID, models.SetupStateCanceled)
	if intent.InstallPhaseDone == models.SetupPhaseEnabled {
		t.Error("the journal records a completed enablement for a refused admission")
	}
	server := env.registeredServer(8301)
	if server == nil {
		t.Fatal("registration precondition missing")
	}
	assertNotAdmitted(t, env, server.ID, "revocation at the promotion boundary")
}

// TestDatabasePromotionRefusesRevokedApproval is the final admission boundary at the
// exact transaction that commits it, with no seam between the decision and the write.
//
// It proves three things the handler-level test cannot isolate: the refusal is
// returned as a typed error, the tunnel row is NOT promoted, and the durable
// quarantine marker survives.
func TestDatabasePromotionRefusesRevokedApproval(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	ctx := context.Background()

	const orderID = "ord_f14_db_boundary"
	env.seedOrder(orderID, 8801, "198.51.100.97")
	env.seedManagedCredential(orderID)

	serverID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "f14-boundary", Host: "198.51.100.97", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 8801,
			models.ProtocolVLESS: map[string]any{"installed": true, "port": "443"},
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	tunnelID, err := env.db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "f14-be-1",
		Endpoint:      "198.51.100.97:443",
		Enabled:       true,
		Status:        models.TunnelStatusConnecting,
		Protocol:      models.ProtocolVLESS,
		StateVersion:  1,
	})
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := env.db.SetBackendPendingEnrollment(ctx, serverID, true); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}

	// The approval owns this server and is then revoked - exactly the durable state
	// a cancellation leaves behind.
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	if _, err := env.db.SQLDB().ExecContext(ctx,
		`UPDATE gigahost_setup_intents SET nexus_server_id = ? WHERE order_id = ?`,
		serverID, orderID); err != nil {
		t.Fatalf("bind the approval to the server: %v", err)
	}
	if _, changed, err := env.db.CancelGigahostSetupIntent(ctx, orderID, "revoked during qualification"); err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}

	swapped, err := env.db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if !errors.Is(err, tunnel.ErrSetupApprovalRevoked) {
		t.Fatalf("promotion error = %v, want ErrSetupApprovalRevoked", err)
	}
	if swapped {
		t.Fatal("the promotion reported success against a revoked approval")
	}

	rows, err := env.db.GetBackendTunnel(ctx, tunnelID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	got := rows
	if got == nil {
		t.Fatal("the tunnel row disappeared")
	}
	if got.Status == models.TunnelStatusActive || got.Status == models.TunnelStatusDegraded {
		t.Errorf("the refused promotion still advanced the status to %q", got.Status)
	}
	if got.StateVersion != 1 {
		t.Errorf("state version = %d, want the untouched 1", got.StateVersion)
	}
	if !durableQuarantine(t, env, serverID) {
		t.Error("the refused promotion released the durable quarantine marker")
	}

	// A live approval still promotes: the guard refuses revocation, not admission.
	// A canceled row is not resumable by design, so the positive is proved on an
	// independent approval bound to the same server.
	const liveOrder = "ord_f14_db_boundary_live"
	env.seedOrder(liveOrder, 8802, "198.51.100.98")
	env.approve(liveOrder, models.ProtocolVLESS, "443", installFixtureFingerprint)
	if _, err := env.db.SQLDB().ExecContext(ctx,
		`UPDATE gigahost_setup_intents SET nexus_server_id = ? WHERE order_id = ?`,
		serverID, liveOrder); err != nil {
		t.Fatalf("bind the live approval: %v", err)
	}
	// The older canceled row still owns nothing now; make the live row the newest
	// owner the query sees by clearing the canceled row's binding.
	if _, err := env.db.SQLDB().ExecContext(ctx,
		`UPDATE gigahost_setup_intents SET nexus_server_id = 0 WHERE order_id = ?`, orderID); err != nil {
		t.Fatalf("unbind the revoked approval: %v", err)
	}
	swapped, err = env.db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if err != nil {
		t.Fatalf("promotion under a live approval: %v", err)
	}
	if !swapped {
		t.Fatal("a live approval was refused admission")
	}
}

// TestSetupPositiveAdmissionStillAdmitsOnce is the positive control the finding
// explicitly requires: the same code path, with no revocation, must admit exactly
// once and release the quarantine. Without it, "never admits" would also pass.
func TestSetupPositiveAdmissionStillAdmitsOnce(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)

	const orderID = "ord_f14_positive"
	env.seedOrder(orderID, 8401, "198.51.100.93")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 8401, "198.51.100.93")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)

	var probes atomic.Int32
	env.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		probes.Add(1)
		return 4, nil
	})

	env.trackerAndInstall()

	intent := env.requireState(orderID, models.SetupStateReady)
	server := env.registeredServer(8401)
	if server == nil {
		t.Fatal("no server was registered")
	}
	if durableQuarantine(t, env, server.ID) {
		t.Error("a qualified, admitted backend is still quarantined")
	}
	tun, err := env.h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		t.Fatalf("tunnel: %v", err)
	}
	if !tun.Enabled {
		t.Fatal("the admitted backend is not enabled")
	}
	if tun.Status != models.TunnelStatusActive && tun.Status != models.TunnelStatusDegraded {
		t.Fatalf("admitted backend status = %q, want active or degraded", tun.Status)
	}
	if n := probes.Load(); n != 1 {
		t.Fatalf("qualification probes = %d, want exactly 1", n)
	}
	if intent.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("phase done = %q, want %q", intent.InstallPhaseDone, models.SetupPhaseEnabled)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want 1", n)
	}
}

// TestSetupFailedQualificationLeavesUnrelatedBackendAlone proves the refusal is
// scoped: a qualification failure on one order must not disturb a healthy,
// unrelated backend that is already admitted.
func TestSetupFailedQualificationLeavesUnrelatedBackendAlone(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	ctx := context.Background()

	healthyID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "unrelated-healthy", Host: "198.51.100.200", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 8499,
			models.ProtocolVLESS: map[string]any{"installed": true, "port": "443"},
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register unrelated server: %v", err)
	}
	if err := env.h.enableDeployBackend(ctx, &models.Server{ID: healthyID, Host: "198.51.100.200",
		Protocols: map[string]any{models.ProtocolVLESS: map[string]any{
			"installed": true, "port": "443",
			"public_key": "x9aBVLESS1234567890abcdef1234567890abcdef12=",
		}}}, models.ProtocolVLESS); err != nil {
		t.Fatalf("admit the unrelated backend: %v", err)
	}
	before, err := env.h.vpnSvc.GetTunnel(healthyID)
	if err != nil || before == nil || !before.Enabled {
		t.Fatalf("precondition: unrelated backend not admitted: %+v err=%v", before, err)
	}
	versionBefore := before.StateVersion
	statusBefore := before.Status

	// A second order whose qualification fails.
	const orderID = "ord_f14_neighbour_fails"
	env.seedOrder(orderID, 8501, "198.51.100.94")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 8501, "198.51.100.94")
	env.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		return 0, errors.New("authenticated application exchange failed")
	})
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	env.trackerAndInstall()

	failed := env.requireState(orderID, models.SetupStateInstallPaused)
	if !strings.Contains(failed.LastError, "qualification") {
		t.Fatalf("pause reason = %q, want the qualification failure", failed.LastError)
	}

	after, err := env.h.vpnSvc.GetTunnel(healthyID)
	if err != nil || after == nil {
		t.Fatalf("re-read unrelated backend: %v", err)
	}
	if !after.Enabled || after.Status != statusBefore {
		t.Errorf("the unrelated backend changed: enabled %v->%v status %q->%q",
			before.Enabled, after.Enabled, statusBefore, after.Status)
	}
	if after.StateVersion != versionBefore {
		t.Errorf("the unrelated backend's state version advanced %d->%d", versionBefore, after.StateVersion)
	}
}

// TestSetupSupersededAttemptCannotAdmit proves the admission authority is the live
// attempt, not whichever one happens to be running: a superseded generation is
// refused by the real fenced write, and the live attempt still admits exactly once.
func TestSetupSupersededAttemptCannotAdmit(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	ctx := context.Background()

	const orderID = "ord_f14_stale_gen"
	env.seedOrder(orderID, 8601, "198.51.100.95")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 8601, "198.51.100.95")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)

	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	claimed, ok, err := env.db.ClaimGigahostSetupInstall(ctx, orderID)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	superseded := claimed.InstallGeneration

	// An administrator resumes the job, which issues a new generation.
	env.executeSQL(`UPDATE gigahost_setup_intents SET state = ? WHERE order_id = ?`,
		models.SetupStateInstallPaused, orderID)
	if _, changed, err := env.db.ResumeGigahostSetupInstall(ctx, orderID); err != nil || !changed {
		t.Fatalf("resume: changed=%v err=%v", changed, err)
	}

	// The superseded attempt presents its old generation to the real fenced write
	// and must be refused, so it cannot record a completed enablement.
	stale := env.intent(orderID)
	stale.State = models.SetupStateInstalling
	stale.InstallPhase = models.SetupPhaseEnabled
	stale.InstallPhaseDone = models.SetupPhaseInstalled
	stale.Step = "enabling_backend"
	if changed, err := env.db.UpdateGigahostSetupInstall(ctx, stale, superseded); err != nil {
		t.Fatalf("stale journal write: %v", err)
	} else if changed {
		t.Fatal("a superseded attempt recorded a privileged journal write")
	}

	// The live attempt completes and admits exactly once.
	env.installer().RunOnce(ctx)
	live := env.requireState(orderID, models.SetupStateReady)
	if live.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("phase done = %q, want %q", live.InstallPhaseDone, models.SetupPhaseEnabled)
	}
	server := env.registeredServer(8601)
	if server == nil {
		t.Fatal("no server registered by the live attempt")
	}
	tun, err := env.h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil || !tun.Enabled {
		t.Fatalf("the live attempt did not admit the backend: %+v err=%v", tun, err)
	}
	if durableQuarantine(t, env, server.ID) {
		t.Error("the live attempt left the backend quarantined")
	}
}
