package handlers

// The provenance and manual controls for the current-policy gates.
//
// Both answer the same question from opposite sides. A manual job has no automation
// provenance, so the unattended-setup setting has no authority over it - otherwise this
// checkpoint would have gated administrative work behind a setting about unattended work.
// And an automatic job keeps its provenance no matter what a person confirms about its
// identity, so a confirmation cannot be used to escape the setting.

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// acceptance: a job cannot become manual merely because someone confirms its identity.
//
// The confirmation is a real decision about *provenance* - it records that a person
// vouched for the value, so the mode becomes `confirmed` - but it is not a decision about
// ownership, and it cannot be used to escape the unattended-setup setting. The row keeps
// its automation policy, and while unattended setup is off that job still does not
// install.
//
// The paused state is seeded rather than produced by the policy path, deliberately: a
// policy refusal is a retry, not a confirmation pause, because confirming an identity
// cannot re-enable unattended setup. The state exercised here is the one an automatic job
// genuinely reaches when its *ownership* proof fails - a changed identity, or a provider
// that attributes the server elsewhere - which is the only case where a person is being
// asked to confirm something about an automatic job.
func TestConfirmationDoesNotMakeAnAutomaticJobManual(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_confirmed", 9308)
	ctx := context.Background()

	// An automatic job that stopped for a human decision about identity.
	env.executeSQL(
		`UPDATE gigahost_setup_intents SET state = ?, step = ?, host_candidate_fingerprint = ? WHERE order_id = ?`,
		models.SetupStateAwaitingHostConfirm, "awaiting_host_confirmation", env.presented, env.orderID)

	// A person confirms the exact identity the panel displayed.
	confirmed, changed, err := env.h.ConfirmGigahostSetupHost(ctx, env.orderID, env.presented)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !changed {
		t.Fatalf("the confirmation was refused: state %q, step %q", confirmed.State, confirmed.Step)
	}
	if confirmed.HostTrustMode != models.SetupTrustModeConfirmed {
		t.Fatalf("trust provenance = %q, want %q", confirmed.HostTrustMode, models.SetupTrustModeConfirmed)
	}
	if confirmed.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("confirmation erased the automation provenance: policy = %q", confirmed.HostTrustPolicy)
	}

	// The row now has a fingerprint and a confirmed mode, and it is still an automatic
	// job - so the disabled policy still stops it before it touches the host.
	env.policy.setEnabled(false)
	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass after confirmation: %v", err)
	}
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	stopped := env.intent(env.orderID)
	if stopped.State == models.SetupStateReady {
		t.Fatal("a confirmed automatic job installed while unattended setup was disabled")
	}
	env.requireInert(t, "a confirmed automatic job under a disabled policy")
	if stopped.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was lost after the install attempt: policy = %q",
			stopped.HostTrustPolicy)
	}

	// With the policy back on, the same job completes through the ordinary resume, so the
	// refusal was the policy and not the confirmation.
	env.policy.setEnabled(true)
	env.resumeAfterPolicyPause(t)
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass after resuming: %v", err)
	}
	if final := env.intent(env.orderID); final.State != models.SetupStateReady {
		t.Fatalf("after resuming, state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
}

// TestAutomaticJobRefusalDoesNotReplayAnUncertainPhase is the safety interaction with the
// existing journal: a disabled policy must never become a reason to re-issue a phase whose
// outcome is unknown.
//
// The row is placed at the persisted interrupted state with the policy off. The attempt
// must stop without issuing the protocol install a second time, and the journal must keep
// describing what actually happened.
func TestAutomaticJobRefusalDoesNotReplayAnUncertainPhase(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_gate_uncertain", 9309)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	// Model a process that died inside the protocol install: the phase is in flight and
	// the state is still `installing`, which is exactly what the real code leaves.
	env.executeSQL(
		`UPDATE gigahost_setup_intents SET state = ?, install_phase = ?, install_generation = install_generation + 1 WHERE order_id = ?`,
		models.SetupStateInstalling, models.SetupPhaseInstalled, env.orderID)

	env.policy.setEnabled(false)
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	stopped := env.requireDisabledStop(t)
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("an uncertain protocol install was replayed %d times under a disabled policy", n)
	}
	// The in-flight phase is preserved as the unknown fact it is; it is not rewritten
	// into a proven one.
	if stopped.InstallPhase != models.SetupPhaseInstalled {
		t.Fatalf("the in-flight phase was rewritten to %q", stopped.InstallPhase)
	}
	if stopped.InstallPhaseDone == models.SetupPhaseInstalled {
		t.Fatal("an unproven protocol install was recorded as proven")
	}
}
