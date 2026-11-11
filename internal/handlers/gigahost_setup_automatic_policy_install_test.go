package handlers

// Current-policy enforcement at the effect boundaries of an automatic setup job.
//
// The claim is an ordering claim and it is measured at the effect, not asserted about
// the code: after the policy stops permitting automatic work, the next prohibition must
// produce zero of the real thing. The real things are counted where they happen - SSH
// authentication and session channels at a live loopback peer, protocol `Install` calls
// and backend enablement at the fixture's protocol manager and VPN service - so a gate
// that merely returned a nice error while still dialling would fail these tests.
//
// Each disabled case is paired with the same scenario under an enabled policy, so the
// zeroes have a control that proves the counters and the path are live.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// errPolicySourceUnavailable stands in for a settings store that cannot be read. It is
// deliberately not a "disabled" answer: the panel does not know, and not knowing is a
// refusal.
var errPolicySourceUnavailable = errors.New("the unattended setup setting could not be read")

// automaticJobEnv is one environment with an entry-created, granted automatic job and a
// real loopback peer, ready for the tracker and installer passes the tests drive.
type automaticJobEnv struct {
	*installEnv
	orderID          string
	providerServerID int64
	peer             *challengePeer
	presented        string
	policy           *stubAutomationPolicy
}

// newAutomaticJobEnv builds the environment and drives the entry and grant.
//
// The job is created by the production entry, not by seeding a row, so every test here
// exercises the real provenance: policy plus binding plus a job the panel itself
// queued.
func newAutomaticJobEnv(t *testing.T, orderID string, providerServerID int64) *automaticJobEnv {
	t.Helper()
	env := newInstallEnv(t, models.ProtocolAWG)
	const ip = "127.0.0.1"
	env.seedAutomaticOrder(orderID, providerServerID, ip)

	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	// The policy is installed before the entry runs, because the entry is exactly one of
	// the boundaries the policy gates.
	policy := env.enableAutomaticSetup(true)
	env.startAutomatic(orderID, automaticOptions)
	env.grantAutomationTrust(orderID, providerServerID)

	return &automaticJobEnv{
		installEnv:       env,
		orderID:          orderID,
		providerServerID: providerServerID,
		peer:             peer,
		presented:        presented,
		policy:           policy,
	}
}

// resumeAfterPolicyPause leaves the paused state through the existing explicit resume,
// which is what a person does after turning unattended setup back on.
//
// A policy refusal deliberately settles the row as a pause rather than auto-retrying, so
// recovery is the same administrative action any other pause needs. The resume issues a
// new install generation, which also fences out the attempt that was refused.
func (e *automaticJobEnv) resumeAfterPolicyPause(t *testing.T) {
	t.Helper()
	_, changed, err := e.h.ResumeGigahostSetup(context.Background(), e.orderID)
	if err != nil {
		t.Fatalf("resume after re-enabling unattended setup: %v", err)
	}
	if !changed {
		t.Fatalf("the resume was refused: state %q", e.intent(e.orderID).State)
	}
}

// requireInert asserts that nothing prohibited happened: no credential was offered, no
// session was opened, no protocol was installed and no backend was enabled.
func (e *automaticJobEnv) requireInert(t *testing.T, what string) {
	t.Helper()
	if n := e.peer.auths.Load(); n != 0 {
		t.Fatalf("%s: the peer was offered a credential (%d authentication attempts)", what, n)
	}
	if n := e.peer.sessions.Load(); n != 0 {
		t.Fatalf("%s: %d session channels were opened at the peer", what, n)
	}
	if n := e.counters.totalInstalls(); n != 0 {
		t.Fatalf("%s: %d protocol installs happened", what, n)
	}
	e.counters.mu.Lock()
	enables := e.counters.enables
	e.counters.mu.Unlock()
	if enables != 0 {
		t.Fatalf("%s: the backend was enabled %d times", what, enables)
	}
}

// requireDisabledStop asserts the persisted refusal: the step names the policy, the
// reason is recorded and non-empty, and the job is not claimed to have succeeded.
func (e *automaticJobEnv) requireDisabledStop(t *testing.T) *models.GigahostSetupIntent {
	t.Helper()
	got := e.intent(e.orderID)
	if got.Step != stepAutomaticSetupDisabled {
		t.Fatalf("step = %q, want %q (state %q, last error %q)",
			got.Step, stepAutomaticSetupDisabled, got.State, got.LastError)
	}
	if got.LastError == "" {
		t.Fatal("the refusal recorded no reason")
	}
	if got.State == models.SetupStateReady {
		t.Fatal("a disabled policy still reported the job as ready")
	}
	return got
}

// TestAutomaticJobProgressesUnderAnEnabledPolicy is the positive control that makes every
// disabled case below meaningful.
//
// It proves the whole path completes - trust, authentication, registration, protocol
// install, enablement, admission - so "zero effects" in the disabled cases is a decision
// and not a path that never worked.
func TestAutomaticJobProgressesUnderAnEnabledPolicy(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_positive", 9301)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	pinned := env.intent(env.orderID)
	if pinned.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			pinned.State, models.SetupStateReadyForSetup, pinned.Step, pinned.LastError)
	}
	if pinned.HostFingerprint != env.presented {
		t.Fatalf("pinned identity = %q, want the peer's (%q)", pinned.HostFingerprint, env.presented)
	}
	if n := env.peer.auths.Load(); n != 0 {
		t.Fatalf("the trust pass authenticated before the pin (%d attempts)", n)
	}

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	final := env.intent(env.orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("final state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1", enables)
	}
	if n := env.peer.auths.Load(); n == 0 {
		t.Fatal("the peer never saw an authentication attempt, so its counter cannot witness anything")
	}
}

// TestAutomaticJobRefusesThePinWhenThePolicyWasTurnedOffAfterCreation is the trust
// boundary: the job was created and granted while unattended setup was enabled, the
// policy is then turned off, and the pass that would pin the observed identity runs.
//
// The pin is the last moment before an identity becomes durably trusted, so this is the
// boundary where a stale permission would do the most damage. The scenario is the real
// one: an administrator disables unattended setup while a job is waiting.
func TestAutomaticJobRefusesThePinWhenThePolicyWasTurnedOffAfterCreation(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_pin_off", 9302)
	ctx := context.Background()

	// The job exists, is granted, and is about to be tracked - and unattended setup is
	// switched off in the meantime.
	env.policy.setEnabled(false)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}

	got := env.intent(env.orderID)
	if got.Step != stepAutomaticDisabledLiteral {
		t.Fatalf("step = %q, want %q (state %q, last error %q)",
			got.Step, stepAutomaticDisabledLiteral, got.State, got.LastError)
	}
	if got.HostFingerprint != "" || got.HostTrustMode != models.SetupTrustModeNone {
		t.Fatalf("a disabled policy still trusted an identity: fingerprint=%q mode=%q",
			got.HostFingerprint, got.HostTrustMode)
	}
	// The observed identity stays available, so a person can see exactly what the address
	// presented when they decide what to do.
	if got.HostCandidateFingerprint != env.presented {
		t.Fatalf("candidate = %q, want the observed %q so the identity is still visible",
			got.HostCandidateFingerprint, env.presented)
	}
	// The refusal must not be reported as a confirmation request: confirming an identity
	// cannot enable unattended setup, so that would be the wrong prompt.
	if got.State == models.SetupStateAwaitingHostConfirm && got.LastError == "" {
		t.Fatal("the refusal recorded a confirmation pause with no reason")
	}
	env.requireInert(t, "the refused pin")

	// The same job under an enabled policy pins on the next scheduled pass. The refusal
	// is a backed-off retry rather than a settled pause, so time has to pass before the
	// tracker asks again - which is what the fixture's clock is for.
	env.policy.setEnabled(true)
	later := time.Now().UTC().Add(2 * time.Hour)
	if err := env.tracker(func() time.Time { return later }).RunOnce(ctx); err != nil {
		t.Fatalf("second tracking pass: %v", err)
	}
	recovered := env.intent(env.orderID)
	if recovered.HostFingerprint != env.presented {
		t.Fatalf("after re-enabling, pinned identity = %q, want %q (state %q, step %q, last error %q)",
			recovered.HostFingerprint, env.presented, recovered.State, recovered.Step, recovered.LastError)
	}
	if recovered.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was lost: policy = %q", recovered.HostTrustPolicy)
	}
}

// TestAutomaticJobRefusesEveryInstallEffectWhenThePolicyIsOff asserts the install-side
// boundaries while the policy is off from the start of the install attempt.
//
// The job already has a durable pin and a granted binding, so every trust fact holds and
// the only thing standing between the job and a real host is the current policy. Each of
// the four install-side boundaries must refuse, and the assertions are at the effect.
func TestAutomaticJobRefusesEveryInstallEffectWhenThePolicyIsOff(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_install_off", 9303)
	ctx := context.Background()

	// Reach the install handoff under an enabled policy.
	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)
	pinned := env.intent(env.orderID).HostFingerprint
	if pinned == "" {
		t.Fatal("precondition: the job has no pinned identity")
	}

	// Now unattended setup is turned off before the install attempt begins.
	env.policy.setEnabled(false)
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	stopped := env.requireDisabledStop(t)
	// The precheck refuses before dialling, so nothing authenticated and nothing
	// installed - the first and most important of the four boundaries.
	env.requireInert(t, "the refused install precheck")
	// Durable provenance is preserved: the pin is not revoked and the count of
	// attempts is unchanged, because no attempt was started.
	if stopped.HostFingerprint != pinned {
		t.Fatalf("the pin was revoked: %q, want %q", stopped.HostFingerprint, pinned)
	}
	if stopped.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was rewritten to %q", stopped.HostTrustPolicy)
	}
	if stopped.InstallPhase != "" || stopped.InstallPhaseDone != "" {
		t.Fatalf("a refused precheck started a phase: in-flight=%q done=%q",
			stopped.InstallPhase, stopped.InstallPhaseDone)
	}

	// Re-enabling lets the same job continue, but only through the existing, explicit
	// resume: the refusal paused the row with a reason, and a pause is a state a person
	// decides to leave. That is the documented lifecycle this checkpoint must not weaken -
	// a disabled policy must never become an automatic silent retry.
	env.policy.setEnabled(true)
	if _, changed, err := env.h.ResumeGigahostSetup(ctx, env.orderID); err != nil || !changed {
		t.Fatalf("resume after re-enabling: changed=%v err=%v", changed, err)
	}
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass after resuming: %v", err)
	}
	if final := env.intent(env.orderID); final.State != models.SetupStateReady {
		t.Fatalf("after resuming, state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1 after recovery", n)
	}
}

// TestAutomaticJobRefusesTheProtocolInstallWhenThePolicyTurnsOffMidAttempt is the
// between-phases case the assignment asks for specifically: the policy is enabled through
// the precheck and the SSH verification, and turns off while the protocol install is about
// to run.
//
// The flip is placed inside the protocol manager's own Install call, which is the effect
// immediately after the registration phase completes. So the attempt really did register
// the server, and then the next phase is refused - which is exactly "already-started
// effects may settle, do not blindly replay".
func TestAutomaticJobRefusesTheProtocolInstallWhenThePolicyTurnsOffMidAttempt(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_midflight", 9304)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	// Turn the policy off as soon as the first side-effecting phase begins. The hook runs
	// inside the protocol manager's Install, so the registration that precedes it has
	// already happened and the phase after it must not.
	env.counters.mu.Lock()
	env.counters.duringInstall = func() { env.policy.setEnabled(false) }
	env.counters.mu.Unlock()

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	stopped := env.intent(env.orderID)
	if stopped.Step != stepAutomaticSetupDisabled {
		t.Fatalf("step = %q, want %q (state %q, last error %q)",
			stopped.Step, stepAutomaticSetupDisabled, stopped.State, stopped.LastError)
	}
	if stopped.State == models.SetupStateReady {
		t.Fatal("a mid-flight policy refusal still admitted the job")
	}
	// The registration and the protocol install that completed before the flip are
	// preserved as proven effects: they are not rolled back, and they are not claimed to
	// have been refused either. The effect that was refused is the one after them.
	if stopped.InstallPhaseDone != models.SetupPhaseInstalled {
		t.Fatalf("proven phase = %q, want %q (the settled effects are kept)",
			stopped.InstallPhaseDone, models.SetupPhaseInstalled)
	}
	if stopped.InstallPhase != "" {
		t.Fatalf("a refused phase was recorded as in flight: %q", stopped.InstallPhase)
	}
	if stopped.HostFingerprint != env.presented {
		t.Fatalf("the pin was revoked mid-flight: %q", stopped.HostFingerprint)
	}
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 0 {
		t.Fatalf("the backend was enabled %d times after the refusal", enables)
	}

	// Recovery: the job continues from its journal rather than replaying anything. The
	// phase that was refused never started, so it is a first attempt, and the enablement
	// after it runs exactly once.
	env.counters.mu.Lock()
	env.counters.duringInstall = nil
	env.counters.mu.Unlock()
	env.policy.setEnabled(true)
	env.resumeAfterPolicyPause(t)
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass after resuming: %v", err)
	}
	final := env.intent(env.orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("after re-enabling, state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1 across both passes", n)
	}
}

// TestAutomaticJobRefusesHealthyAdmissionWhenThePolicyTurnsOffAfterEnablement is the last
// boundary: the policy flips after the backend is enabled, so the effect settled and only
// the terminal success is refused.
//
// This is the case where "do not roll back completed work" has to be literally true: the
// backend exists and is qualified, the journal says so, and the job still must not be
// recorded as finished.
func TestAutomaticJobRefusesHealthyAdmissionWhenThePolicyTurnsOffAfterEnablement(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_admission", 9305)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	// Flip the policy off from the VPN service's own pre-add hook, which runs inside
	// enablement. The hook is chained rather than replaced: the fixture's existing counter
	// is the evidence that enablement really happened, so overwriting it would turn the
	// assertion below into a measurement of nothing.
	env.h.vpnSvc.SetEnableBackendPreAddTunnelHookForTest(func() {
		env.counters.mu.Lock()
		env.counters.enables++
		env.counters.mu.Unlock()
		env.policy.setEnabled(false)
	})

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	stopped := env.intent(env.orderID)
	if stopped.State == models.SetupStateReady {
		t.Fatal("a backend that was not admitted under the enabled policy was still reported ready")
	}
	if stopped.Step != stepAutomaticSetupDisabled {
		t.Fatalf("step = %q, want %q (state %q, last error %q)",
			stopped.Step, stepAutomaticSetupDisabled, stopped.State, stopped.LastError)
	}
	// The completed effects are preserved truthfully: enablement really happened.
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1 (the effect settled)", enables)
	}
	if stopped.InstallPhaseDone == "" {
		t.Fatal("the journal records no proven phase although enablement completed")
	}
	if stopped.HostFingerprint != env.presented {
		t.Fatalf("the pin was revoked: %q", stopped.HostFingerprint)
	}
}

// TestAutomaticJobRefusesWhenThePolicyCannotBeRead covers the error path at an effect
// boundary.
//
// "Could not ask" is not "off" and it is certainly not "on". The job must stop with the
// source error in its recorded reason, and nothing may be installed.
func TestAutomaticJobRefusesWhenThePolicyCannotBeRead(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_error", 9306)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	// The source becomes unreadable between the pin and the install effect.
	env.policy.setError(errPolicySourceUnavailable)
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	stopped := env.requireDisabledStop(t)
	env.requireInert(t, "an unreadable policy")
	if stopped.LastError == "" {
		t.Fatal("an unreadable policy recorded no reason")
	}
}

// TestManualJobIsIndependentOfTheAutomaticPolicy is the manual control.
//
// A job a person approved has no automation provenance, so the unattended-setup setting
// has no authority over it. It must complete with the policy off, unset and unreadable -
// otherwise this checkpoint would have gated administrative work behind a setting about
// unattended work.
func TestManualJobIsIndependentOfTheAutomaticPolicy(t *testing.T) {
	cases := []struct {
		name   string
		policy func(*installEnv)
	}{
		{
			name:   "no policy installed at all",
			policy: func(e *installEnv) { e.h.SetGigahostSetupAutomationPolicyForTest(nil) },
		},
		{
			name:   "the policy answers no",
			policy: func(e *installEnv) { e.enableAutomaticSetup(false) },
		},
		{
			name: "the policy cannot be read",
			policy: func(e *installEnv) {
				p := e.enableAutomaticSetup(true)
				p.setError(errPolicySourceUnavailable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			const orderID = "ord_manual_independent"
			const providerServerID = 9307
			const ip = "127.0.0.1"

			env.seedOrder(orderID, providerServerID, ip)
			// Real generated key material: the install path parses it to configure the
			// handshake, so a placeholder would fail before the boundary under test.
			env.seedOrderCredential(orderID, newManagedTestKey(t))
			env.providerServes(orderID, providerServerID, ip)

			hostSigner := newHandshakeSigner(t)
			peer := newChallengePeer(t, hostSigner)
			presented := sshFingerprintOf(t, hostSigner)
			env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

			tc.policy(env)

			// A person's approval, with the identity they confirmed. No automation
			// policy, so the unattended-setup setting is irrelevant to it.
			env.approve(orderID, models.ProtocolAWG, "51820", presented)
			if got := env.intent(orderID); got.HostTrustPolicy != models.SetupTrustPolicyManual {
				t.Fatalf("precondition: the manual approval carries policy %q", got.HostTrustPolicy)
			}

			env.trackerAndInstall()

			final := env.intent(orderID)
			if final.State != models.SetupStateReady {
				t.Fatalf("a manual job was gated by the unattended-setup policy: state = %q (step %q, last error %q)",
					final.State, final.Step, final.LastError)
			}
			if final.HostTrustPolicy != models.SetupTrustPolicyManual {
				t.Fatalf("the manual job acquired automation provenance: policy = %q", final.HostTrustPolicy)
			}
			if n := env.counters.totalInstalls(); n != 1 {
				t.Fatalf("manual protocol installs = %d, want exactly 1", n)
			}
		})
	}
}

// TestConfirmationDoesNotMakeAnAutomaticJobManual is the provenance half of the
