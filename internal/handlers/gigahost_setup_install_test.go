package handlers

// Behavioural tests for the durable install lifecycle.
//
// Every test drives the real installer state machine, the real SQLite ledger and
// the real handlers over the controlled provider/SSH/manager/traffic boundaries
// the repository already uses for the synchronous deploy path. What they prove is
// the ordering guarantee: one attempt at a time, a completed effect never
// repeated, an unknown effect paused instead of retried, and a revocation that
// reaches work already in flight.
//
// What they do NOT prove is stated rather than implied: no real host was
// configured, no real provider was contacted, and no browser journey was run.
// Those remain separately gated acceptance.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestSetupInstallCompletesOnceAndAdmits proves the positive lifecycle: an
// approved ready order is installed exactly once, registered once, admitted only
// through qualification, and recorded complete.
func TestSetupInstallCompletesOnceAndAdmits(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_ok", 6001, "198.51.100.61")
	env.seedManagedCredential("ord_ok")
	env.providerServes("ord_ok", 6001, "198.51.100.61")
	env.approve("ord_ok", models.ProtocolAWG, "51820", installFixtureFingerprint)

	env.trackerAndInstall()

	got := env.requireState("ord_ok", models.SetupStateReady)
	if got.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("completed phase = %q, want %q (step %q)", got.InstallPhaseDone, models.SetupPhaseEnabled, got.Step)
	}
	if got.InstallGeneration != 1 {
		t.Fatalf("generation = %d, want exactly one attempt", got.InstallGeneration)
	}
	if got.NexusServerID <= 0 {
		t.Fatalf("no registered server recorded on the intent")
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	if env.counters.enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1", env.counters.enables)
	}
	server := env.registeredServer(6001)
	if server == nil || server.ID != got.NexusServerID {
		t.Fatalf("registered server = %+v, want id %d for provider server 6001", server, got.NexusServerID)
	}
	tun, err := env.h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		t.Fatalf("no backend tunnel after a completed install: %v", err)
	}
	if !tun.Enabled || tun.Status != models.TunnelStatusActive {
		t.Fatalf("backend not admitted: enabled=%v status=%q", tun.Enabled, tun.Status)
	}

	// A pass over a completed job does nothing at all.
	env.trackerAndInstall()
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("a second pass re-installed: installs = %d", n)
	}
	if env.counters.enables != 1 {
		t.Fatalf("a second pass re-enabled the backend: enables = %d", env.counters.enables)
	}
}

// TestSetupInstallResumeVerifiesInsteadOfReinstalling is the crash-window test.
//
// The previous attempt proved installation and died inside enablement, so the
// installation must not run again. The resumed attempt verifies, admits, and
// completes - with the install counter still at one.
func TestSetupInstallResumeVerifiesInsteadOfReinstalling(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	paused := env.pauseAtEnablement("ord_resume", 6002, "198.51.100.62")
	if paused.InstallPhase != models.SetupPhaseEnabled {
		t.Fatalf("paused phase = %q, want %q", paused.InstallPhase, models.SetupPhaseEnabled)
	}
	installsBefore := env.counters.totalInstalls()
	enablesBefore := env.counters.enables

	resumed, changed, err := env.h.ResumeGigahostSetup(context.Background(), "ord_resume")
	if err != nil || !changed {
		t.Fatalf("resume: changed=%v err=%v", changed, err)
	}
	if resumed.State != models.SetupStateInstalling {
		t.Fatalf("state after resume = %q, want %q", resumed.State, models.SetupStateInstalling)
	}

	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass after resume: %v", err)
	}

	got := env.requireState("ord_resume", models.SetupStateReady)
	if got.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("completed phase = %q, want %q", got.InstallPhaseDone, models.SetupPhaseEnabled)
	}
	if n := env.counters.totalInstalls(); n != installsBefore {
		t.Fatalf("the resumed attempt re-installed: installs %d -> %d", installsBefore, n)
	}
	// The interrupted enablement left no tunnel, which is proof it did not land,
	// so the resume performs the first real admission attempt - exactly one more.
	if env.counters.enables != enablesBefore+1 {
		t.Fatalf("enablements = %d, want %d (one proven-absent enablement re-attempted)",
			env.counters.enables, enablesBefore+1)
	}
	if servers, _ := env.db.GetAllServers(context.Background()); len(servers) != 1 {
		t.Fatalf("server rows = %d, want exactly 1: a resume registered again", len(servers))
	}
}

// TestSetupInstallRestartDuringInstallationPausesAndThenVerifies proves the
// unknown-outcome rule: a row left in the installing state is taken over, its
// in-flight phase is verified rather than replayed, and the attempt pauses when
// the record cannot prove the effect.
func TestSetupInstallRestartDuringInstallationPausesAndThenVerifies(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.crashDuringInstall("ord_crash", 6003, "198.51.100.63")

	// The next pass takes the row over and must NOT install again.
	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	got := env.requireState("ord_crash", models.SetupStateInstallPaused)
	if env.counters.totalInstalls() != 0 {
		t.Fatalf("the takeover replayed a protocol install: installs = %d", env.counters.totalInstalls())
	}
	if !strings.Contains(got.LastError, "interrupted") {
		t.Fatalf("pause reason = %q, want it to name the unverified step", got.LastError)
	}
	if got.InstallPhase != models.SetupPhaseInstalled {
		t.Fatalf("in-flight phase was cleared: %q", got.InstallPhase)
	}

	// Once the recorded server row proves the installation, an explicit resume
	// verifies it and finishes - still without a second install.
	env.recordInstalledWithoutEffect(6003)
	if _, changed, err := env.h.ResumeGigahostSetup(context.Background(), "ord_crash"); err != nil || !changed {
		t.Fatalf("resume: changed=%v err=%v", changed, err)
	}
	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass after resume: %v", err)
	}
	env.requireState("ord_crash", models.SetupStateReady)
	if env.counters.totalInstalls() != 0 {
		t.Fatalf("the verified resume installed again: installs = %d", env.counters.totalInstalls())
	}
}

// recordInstalledWithoutEffect marks the server row as holding a proven
// installation without going through the protocol manager, which is how a restart
// observes work a previous process had already completed on the host.
func (e *installEnv) recordInstalledWithoutEffect(providerServerID int64) {
	e.t.Helper()
	server := e.registeredServer(providerServerID)
	if server == nil {
		e.t.Fatalf("no registered server for provider server %d", providerServerID)
	}
	server.Protocols[models.ProtocolAWG] = map[string]any{
		"installed":  true,
		"port":       "51820",
		"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
	}
	if err := e.db.UpdateServerProtocols(context.Background(), server.ID, server.Protocols); err != nil {
		e.t.Fatalf("record proven installation: %v", err)
	}
}

// TestSetupInstallPausedIsNotRetriedWithoutResume proves a pause is a real
// stopping point: no pass of either worker touches it, so an unknown remote
// outcome cannot be replayed by a background loop.
func TestSetupInstallPausedIsNotRetriedWithoutResume(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.pauseAtEnablement("ord_hold", 6004, "198.51.100.64")
	installsBefore := env.counters.totalInstalls()
	enablesBefore := env.counters.enables

	for k := 0; k < 3; k++ {
		if err := env.installer().RunOnce(context.Background()); err != nil {
			t.Fatalf("pass %d: %v", k, err)
		}
	}
	env.requireState("ord_hold", models.SetupStateInstallPaused)
	if env.counters.totalInstalls() != installsBefore {
		t.Fatalf("a paused job was re-installed: %d -> %d", installsBefore, env.counters.totalInstalls())
	}
	if env.counters.enables != enablesBefore {
		t.Fatalf("a paused job was re-enabled: %d -> %d", enablesBefore, env.counters.enables)
	}
}

// TestSetupInstallRevocationWinsAgainstRunningAttempt is the administrative
// cancellation control.
//
// A revocation that lands while an attempt is already working must stop it. The
// journal is fenced by state and generation, so the attempt's next write is
// refused and it issues no further remote command.
func TestSetupInstallRevocationWinsAgainstRunningAttempt(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_revoke", 6005, "198.51.100.65")
	env.seedManagedCredential("ord_revoke")
	env.providerServes("ord_revoke", 6005, "198.51.100.65")
	env.approve("ord_revoke", models.ProtocolAWG, "51820", installFixtureFingerprint)

	if err := env.tracker(nil).RunOnce(context.Background()); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}

	// The administrator revokes WHILE the attempt is inside its first effect: the
	// protocol manager's own Install entry point performs the revocation, which is
	// the real race rather than a simulated one. The production runner must then be
	// refused by its next journal write and must issue no further remote command.
	revokedInsideInstall := false
	env.counters.mu.Lock()
	env.counters.duringInstall = func() {
		revokedInsideInstall = true
		if _, changed, err := env.h.CancelGigahostSetup(context.Background(), "ord_revoke"); err != nil || !changed {
			t.Errorf("revoke during install: changed=%v err=%v", changed, err)
		}
	}
	env.counters.mu.Unlock()

	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	env.counters.mu.Lock()
	env.counters.duringInstall = nil
	env.counters.mu.Unlock()
	if !revokedInsideInstall {
		t.Fatal("the fixture never reached the install effect")
	}

	got := env.requireState("ord_revoke", models.SetupStateCanceled)
	if got.RevokedAt.IsZero() {
		t.Fatal("revocation time was not recorded")
	}
	// The revocation stands; the attempt neither finished the job nor rewrote the row.
	if got.InstallPhaseDone == models.SetupPhaseEnabled {
		t.Fatal("a revoked attempt completed the job")
	}
	// Exactly the one installation the revocation arrived during, and no enablement.
	if env.counters.totalInstalls() != 1 {
		t.Fatalf("protocol installs = %d, want exactly the one the revocation interrupted",
			env.counters.totalInstalls())
	}
	if env.counters.enables != 0 {
		t.Fatalf("a revoked approval enabled a backend: enables = %d", env.counters.enables)
	}
}

// TestSetupInstallChangedHostStopsBeforeAnyRemoteCommand proves the trust rule is
// enforced for the install and not only for the provider poll: a server bound to a
// contradicting identity stops the attempt before it installs anything.
func TestSetupInstallChangedHostStopsBeforeAnyRemoteCommand(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_moved", 6006, "198.51.100.66")
	env.seedManagedCredential("ord_moved")
	env.providerServes("ord_moved", 6006, "198.51.100.66")
	env.approve("ord_moved", models.ProtocolAWG, "51820", installFixtureFingerprint)

	if err := env.tracker(nil).RunOnce(context.Background()); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	claimed, ok, err := env.db.ClaimGigahostSetupInstall(context.Background(), "ord_moved")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	// A server row for this provider server now carries a different identity than
	// the one the approval confirmed.
	serverID, err := env.db.CreateServerWithFingerprint(context.Background(), &models.Server{
		Name: "Gigahost-moved", Host: "198.51.100.66", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 6006},
	}, installFixtureFingerprintBound)
	if err != nil {
		t.Fatalf("register bound server: %v", err)
	}

	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	got := env.requireState("ord_moved", models.SetupStateInstallPaused)
	if got.Step != "host_identity_changed" {
		t.Fatalf("step = %q, want host_identity_changed", got.Step)
	}
	if env.counters.totalInstalls() != 0 || env.counters.sshDials != 0 {
		t.Fatalf("a changed host still produced effects: %s", env.describeCounters())
	}
	bound, err := env.db.GetKnownHostFingerprint(context.Background(), serverID)
	if err != nil {
		t.Fatalf("read bound identity: %v", err)
	}
	if bound != installFixtureFingerprintBound {
		t.Fatalf("bound identity was rewritten to %q", bound)
	}
	if claimed.InstallGeneration != 1 {
		t.Fatalf("claim generation = %d", claimed.InstallGeneration)
	}
}

// TestSetupInstallMissingCredentialStopsBeforeRemoteCommand proves a removed
// credential is a safe pause, not a login attempt with no authentication.
func TestSetupInstallMissingCredentialStopsBeforeRemoteCommand(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_nocred", 6007, "198.51.100.67")
	env.seedManagedCredential("ord_nocred")
	env.providerServes("ord_nocred", 6007, "198.51.100.67")
	env.approve("ord_nocred", models.ProtocolAWG, "51820", installFixtureFingerprint)

	if err := env.tracker(nil).RunOnce(context.Background()); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	// The credential disappears between the handoff and the install.
	if _, err := env.db.SQLDB().ExecContext(context.Background(),
		`UPDATE gigahost_orders SET ssh_key_enc = '' WHERE order_id = ?`, "ord_nocred"); err != nil {
		t.Fatalf("remove credential: %v", err)
	}

	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	got := env.requireState("ord_nocred", models.SetupStateInstallPaused)
	if !strings.Contains(got.LastError, "credential") {
		t.Fatalf("pause reason = %q, want it to name the missing credential", got.LastError)
	}
	if env.counters.totalInstalls() != 0 || env.counters.sshDials != 0 {
		t.Fatalf("a missing credential still produced effects: %s", env.describeCounters())
	}
}

// TestSetupInstallFailedPayloadPausesWithoutAdmission proves a failing install
// leaves the backend out of the pool and reports the failing step.
func TestSetupInstallFailedPayloadPausesWithoutAdmission(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_bad", 6008, "198.51.100.68")
	env.seedManagedCredential("ord_bad")
	env.providerServes("ord_bad", 6008, "198.51.100.68")
	env.counters.failInstall = errors.New("protocol payload rejected by host")
	env.approve("ord_bad", models.ProtocolAWG, "51820", installFixtureFingerprint)

	env.trackerAndInstall()

	got := env.requireState("ord_bad", models.SetupStateInstallPaused)
	if !strings.Contains(got.LastError, "payload rejected") {
		t.Fatalf("pause reason = %q, want the host diagnostic", got.LastError)
	}
	if got.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("proven phase = %q, want %q (installation must not be proven)", got.InstallPhaseDone, models.SetupPhaseRegistered)
	}
	if env.counters.enables != 0 {
		t.Fatalf("backend was enabled after a failed install: enables = %d", env.counters.enables)
	}
}

// TestSetupInstallProviderFailureStopsTheJob proves the two terminal outcomes stay
// distinct: a provider terminal failure is `failed`, and it is never turned into
// an install attempt.
func TestSetupInstallProviderFailureStopsTheJob(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_provfail", 6009, "198.51.100.69")
	env.seedManagedCredential("ord_provfail")
	env.provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: "ord_provfail", Status: gigahost.StatusFailed, Error: "no capacity in region",
		}, nil
	}
	env.approve("ord_provfail", models.ProtocolAWG, "51820", installFixtureFingerprint)

	env.trackerAndInstall()

	got := env.requireState("ord_provfail", models.SetupStateFailed)
	if got.LastError != "no capacity in region" {
		t.Fatalf("last error = %q, want the provider's own diagnostic", got.LastError)
	}
	if env.counters.totalInstalls() != 0 || env.counters.sshDials != 0 {
		t.Fatalf("a provider failure produced install effects: %s", env.describeCounters())
	}
	// A resume of a provider-failed job is refused: the order has no server.
	if _, changed, err := env.h.ResumeGigahostSetup(context.Background(), "ord_provfail"); err != nil || changed {
		t.Fatalf("resume of a failed job: changed=%v err=%v", changed, err)
	}
}

// TestSetupInstallTransientProviderErrorKeepsJobPending proves a read failure is
// still "could not ask" after the install half exists: nothing is installed and
// nothing is declared failed.
func TestSetupInstallTransientProviderErrorKeepsJobPending(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_flaky", 6010, "198.51.100.70")
	env.seedManagedCredential("ord_flaky")
	env.provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return nil, errors.New("dial tcp: connection refused")
	}
	env.approve("ord_flaky", models.ProtocolAWG, "51820", installFixtureFingerprint)

	env.trackerAndInstall()

	got := env.requireState("ord_flaky", models.SetupStatePending)
	if got.ReadFailures == 0 {
		t.Fatal("read failure was not recorded")
	}
	if env.counters.totalInstalls() != 0 || env.counters.sshDials != 0 {
		t.Fatalf("an unreadable provider produced install effects: %s", env.describeCounters())
	}
}

// TestSetupInstallProxyAdmitsOnlyAfterQualification proves the stronger proxy
// requirement is preserved: a proxy install whose application-traffic
// qualification FAILS is not admitted, and the job pauses.
//
// The oracle is deliberate about the reason: it asserts the qualification callback
// actually ran. An earlier version accepted any error mentioning "enablement", which
// a failure before the callback would also satisfy - so it could pass without ever
// reaching the boundary it claimed to protect.
func TestSetupInstallProxyAdmitsOnlyAfterQualification(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	env.seedOrder("ord_proxy", 6011, "198.51.100.71")
	env.seedManagedCredential("ord_proxy")
	env.providerServes("ord_proxy", 6011, "198.51.100.71")
	var reached atomic.Bool
	env.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		reached.Store(true)
		return 0, errors.New("authenticated application exchange failed")
	})
	env.approve("ord_proxy", models.ProtocolVLESS, "443", installFixtureFingerprint)

	env.trackerAndInstall()

	if !reached.Load() {
		t.Fatal("the qualification callback never ran: the negative would prove nothing")
	}
	got := env.requireState("ord_proxy", models.SetupStateInstallPaused)
	if !strings.Contains(got.LastError, "qualification") {
		t.Fatalf("pause reason = %q, want the qualification failure", got.LastError)
	}
	if got.NexusServerID <= 0 {
		t.Fatal("no server was registered for the proxy attempt")
	}
	tun, err := env.h.vpnSvc.GetTunnel(got.NexusServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if tun != nil && tun.Enabled {
		t.Error("an unqualified proxy backend was left administratively enabled")
	}
	if tun != nil && (tun.Status == models.TunnelStatusActive || tun.Status == models.TunnelStatusDegraded) {
		t.Errorf("an unqualified proxy backend was admitted (status %q)", tun.Status)
	}
	if !durableQuarantine(t, env, got.NexusServerID) {
		t.Error("an unqualified proxy backend released its durable quarantine")
	}
}

// TestBackendAdmissionStateClassifiesEveryObservation proves the classifier that
// decides "verify vs re-enable" from the tunnel row actually separates its three
// answers. It is the function a resumed attempt trusts to distinguish "the effect
// never landed" from "it landed and its outcome is unknown", so each answer is
// asserted directly against a real tunnel row rather than inferred.
func TestBackendAdmissionStateClassifiesEveryObservation(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	// A server row is needed for the tunnel to attach to.
	server := &models.Server{
		Name: "admission-fixture", Host: "198.51.100.210", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 7100,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
	}
	serverID, err := env.db.CreateServerWithFingerprint(ctx, server, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	server.ID = serverID

	req := GigahostDeployRequest{OrderID: "ord_admission", AssignedIP: server.Host, Protocol: models.ProtocolAWG}

	// 1. No tunnel row at all: enablement provably never landed.
	if got := env.h.backendAdmissionState(ctx, server, models.ProtocolAWG); got != admissionAbsent {
		t.Fatalf("no tunnel: state = %d, want admissionAbsent", got)
	}

	// 2. A tunnel that exists but is administratively disabled: enablement did not
	//    complete (the failure path disables it), so re-running is a first attempt.
	if err := env.h.enableDeployBackend(ctx, server, models.ProtocolAWG); err != nil {
		t.Fatalf("enable backend: %v", err)
	}
	if got := env.h.backendAdmissionState(ctx, server, models.ProtocolAWG); got != admissionAdmitted {
		t.Fatalf("admitted tunnel: state = %d, want admissionAdmitted", got)
	}
	if err := env.h.vpnSvc.DisableBackend(ctx, serverID); err != nil {
		t.Fatalf("disable backend: %v", err)
	}
	if got := env.h.backendAdmissionState(ctx, server, models.ProtocolAWG); got != admissionAbsent {
		t.Fatalf("disabled tunnel: state = %d, want admissionAbsent", got)
	}

	// 3. An enabled tunnel that never reached admittance: genuinely unknown.
	if err := env.h.enableDeployBackend(ctx, server, models.ProtocolAWG); err != nil {
		t.Fatalf("re-enable backend: %v", err)
	}
	if err := env.h.vpnSvc.SetTunnelStatus(ctx, serverID, models.TunnelStatusConnecting, 0); err != nil {
		t.Fatalf("set connecting: %v", err)
	}
	if got := env.h.backendAdmissionState(ctx, server, models.ProtocolAWG); got != admissionAmbiguous {
		t.Fatalf("enrolled-not-admitted tunnel: state = %d, want admissionAmbiguous", got)
	}

	// 4. A tunnel running a different protocol than the approval: ambiguous, never
	//    "admitted" on the strength of another protocol's health.
	if err := env.h.vpnSvc.SetTunnelStatus(ctx, serverID, models.TunnelStatusActive, 1); err != nil {
		t.Fatalf("set active: %v", err)
	}
	if got := env.h.backendAdmissionState(ctx, server, models.ProtocolVLESS); got != admissionAmbiguous {
		t.Fatalf("protocol mismatch: state = %d, want admissionAmbiguous", got)
	}
	_ = req
}

// TestResumeInstallActionFollowsAdmissionState proves the resume decision is
// derived from the admission observation, so the two paths cannot disagree.
func TestResumeInstallActionFollowsAdmissionState(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	server := &models.Server{
		Name: "action-fixture", Host: "198.51.100.211", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 7101,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
	}
	serverID, err := env.db.CreateServerWithFingerprint(ctx, server, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	server.ID = serverID
	req := GigahostDeployRequest{OrderID: "ord_action", AssignedIP: server.Host, Protocol: models.ProtocolAWG}

	// Absent → run (first attempt, not a replay).
	if got := env.h.resumeInstallAction(ctx, req, server); got != actionRun {
		t.Fatalf("absent: action = %q, want %q", got, actionRun)
	}
	// Admitted → skip.
	if err := env.h.enableDeployBackend(ctx, server, models.ProtocolAWG); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := env.h.resumeInstallAction(ctx, req, server); got != actionSkip {
		t.Fatalf("admitted: action = %q, want %q", got, actionSkip)
	}
	// Ambiguous → verify (never a blind re-enable).
	if err := env.h.vpnSvc.SetTunnelStatus(ctx, serverID, models.TunnelStatusConnecting, 0); err != nil {
		t.Fatalf("set connecting: %v", err)
	}
	if got := env.h.resumeInstallAction(ctx, req, server); got != actionVerify {
		t.Fatalf("ambiguous: action = %q, want %q", got, actionVerify)
	}
}

// TestVerifyRecordedProtocolRejectsEveryUnprovenShape proves the resume-time check
// that refuses to treat an unproven installation as complete. Every branch here is
// a way the recorded row can fail to prove the approved install, and each must
// stop the attempt rather than let it continue on an assumption.
func TestVerifyRecordedProtocolRejectsEveryUnprovenShape(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	awgWith := func(meta any) *models.Server {
		return &models.Server{ID: 1, Host: "198.51.100.212", Protocols: map[string]any{models.ProtocolAWG: meta}}
	}
	req := GigahostDeployRequest{Protocol: models.ProtocolAWG, Port: "51820"}

	cases := []struct {
		name   string
		server *models.Server
		req    GigahostDeployRequest
	}{
		{"no protocol entry", &models.Server{ID: 1, Protocols: map[string]any{}}, req},
		{"non-map entry", awgWith("installed"), req},
		{"not installed", awgWith(map[string]any{"installed": false, "port": "51820"}), req},
		{"no port", awgWith(map[string]any{"installed": true}), req},
		{"port wrong type", awgWith(map[string]any{"installed": true, "port": true}), req},
		{"port mismatch", awgWith(map[string]any{"installed": true, "port": "443"}), req},
	}
	for _, tc := range cases {
		if err := env.h.verifyRecordedProtocol(tc.server, tc.req); err == nil {
			t.Fatalf("%s: accepted as proven", tc.name)
		}
	}

	// The positive control, for every port shape the row may legitimately hold.
	for _, port := range []any{"51820", 51820, int64(51820), float64(51820)} {
		server := awgWith(map[string]any{"installed": true, "port": port})
		if err := env.h.verifyRecordedProtocol(server, req); err != nil {
			t.Fatalf("port %v refused a proven install: %v", port, err)
		}
	}
}

// TestSetupInstallResumeRunsEnablementWhenProvablyAbsent covers the one
// installEnableStep branch the other lifecycle tests do not reach: a resumed
// attempt whose persisted journal proves the installation completed while NO tunnel
// exists, so enablement is provably absent and must be run as a first attempt.
//
// It goes through the production runner end to end (claim -> plan -> enable ->
// admit), which is why no test-only journal constructor is needed.
func TestSetupInstallResumeRunsEnablementWhenProvablyAbsent(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	env.seedOrder("ord_absent", 7103, "198.51.100.214")
	env.seedManagedCredential("ord_absent")
	env.providerServes("ord_absent", 7103, "198.51.100.214")
	env.approve("ord_absent", models.ProtocolAWG, "51820", installFixtureFingerprint)

	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	claimed, ok, err := env.db.ClaimGigahostSetupInstall(ctx, "ord_absent")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	// Persisted situation: registration and installation proven, enablement in
	// flight, and NO backend tunnel - the enablement effect provably never landed.
	serverID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "Gigahost-absent", Host: "198.51.100.214", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 7103,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
		CreatedAt: time.Now().UTC(),
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	claimed.InstallPhase = models.SetupPhaseEnabled
	claimed.InstallPhaseDone = models.SetupPhaseInstalled
	claimed.NexusServerID = serverID
	claimed.Step = "enabling_backend"
	if _, err := env.db.UpdateGigahostSetupInstall(ctx, claimed, claimed.InstallGeneration); err != nil {
		t.Fatalf("seed in-flight enablement: %v", err)
	}

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The installation was not repeated; enablement ran exactly once and admitted.
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("the resumed attempt re-installed: installs = %d", n)
	}
	if env.counters.enables != 1 {
		t.Fatalf("enablements = %d, want exactly 1", env.counters.enables)
	}
	got := env.requireState("ord_absent", models.SetupStateReady)
	if got.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("completed phase = %q, want %q", got.InstallPhaseDone, models.SetupPhaseEnabled)
	}
	tun, err := env.h.vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil || !tun.Enabled || tun.Status != models.TunnelStatusActive {
		t.Fatalf("backend not admitted: %+v err=%v", tun, err)
	}
}

// TestSetupInstallResumeSkipsProvenEnablement covers installEnableStep's
// actionSkip branch through the production runner: a journal that already records
// enablement completes the job without touching the backend again.
func TestSetupInstallResumeSkipsProvenEnablement(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	env.seedOrder("ord_skip", 7104, "198.51.100.215")
	env.seedManagedCredential("ord_skip")
	env.providerServes("ord_skip", 7104, "198.51.100.215")
	env.approve("ord_skip", models.ProtocolAWG, "51820", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	claimed, ok, err := env.db.ClaimGigahostSetupInstall(ctx, "ord_skip")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	serverID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "Gigahost-skip", Host: "198.51.100.215", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 7104,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
		CreatedAt: time.Now().UTC(),
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	// Journal says every phase is proven.
	claimed.InstallPhase = ""
	claimed.InstallPhaseDone = models.SetupPhaseEnabled
	claimed.NexusServerID = serverID
	if _, err := env.db.UpdateGigahostSetupInstall(ctx, claimed, claimed.InstallGeneration); err != nil {
		t.Fatalf("seed proven journal: %v", err)
	}

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	if env.counters.totalInstalls() != 0 {
		t.Fatalf("a proven journal re-installed: installs = %d", env.counters.totalInstalls())
	}
	if env.counters.enables != 0 {
		t.Fatalf("a proven journal re-enabled: enables = %d", env.counters.enables)
	}
	env.requireState("ord_skip", models.SetupStateReady)
}

// TestSetupInstallResumeVerifiesInterruptedEnablement covers installEnableStep's
// actionVerify branch when the interrupted enablement DID leave an enabled tunnel
// that is not admitted: the attempt must prove it rather than re-enable, and pause
// when the tunnel cannot be admitted.
func TestSetupInstallResumeVerifiesInterruptedEnablement(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	env.seedOrder("ord_verify", 7105, "198.51.100.216")
	env.seedManagedCredential("ord_verify")
	env.providerServes("ord_verify", 7105, "198.51.100.216")
	env.approve("ord_verify", models.ProtocolAWG, "51820", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	claimed, ok, err := env.db.ClaimGigahostSetupInstall(ctx, "ord_verify")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	serverID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "Gigahost-verify", Host: "198.51.100.216", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 7105,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
		CreatedAt: time.Now().UTC(),
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	claimed.InstallPhase = models.SetupPhaseEnabled
	claimed.InstallPhaseDone = models.SetupPhaseInstalled
	claimed.NexusServerID = serverID
	if _, err := env.db.UpdateGigahostSetupInstall(ctx, claimed, claimed.InstallGeneration); err != nil {
		t.Fatalf("seed in-flight enablement: %v", err)
	}
	// An enrolled tunnel that never reached admittance: genuinely unknown.
	if err := env.h.enableDeployBackend(ctx, &models.Server{ID: serverID, Host: "198.51.100.216",
		Protocols: map[string]any{models.ProtocolAWG: map[string]any{
			"installed": true, "port": "51820",
			"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
		}}}, models.ProtocolAWG); err != nil {
		t.Fatalf("seed tunnel: %v", err)
	}
	if err := env.h.vpnSvc.SetTunnelStatus(ctx, serverID, models.TunnelStatusConnecting, 0); err != nil {
		t.Fatalf("set connecting: %v", err)
	}

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	// Neither re-enabled nor installed: it paused because the outcome is unknown.
	if env.counters.totalInstalls() != 0 {
		t.Fatalf("re-installed: installs = %d", env.counters.totalInstalls())
	}
	got := env.requireState("ord_verify", models.SetupStateInstallPaused)
	if !strings.Contains(got.LastError, "not admitted") {
		t.Fatalf("pause reason = %q, want it to name the unproven admission", got.LastError)
	}
}
