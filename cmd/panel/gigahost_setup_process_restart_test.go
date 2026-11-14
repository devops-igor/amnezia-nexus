package main

// Parent side of the fresh-OS-process restart proof.
//
// Each test seeds ONE persisted situation in a disposable encrypted database, starts
// the real application in a genuinely separate process, and asserts on the durable row
// that process left behind. The helper file states which observations production
// actually writes, and which claims are unavailable without a seam.
//
// Deliberately absent: a test-side effects journal. The previous version asserted zero
// "install"/"enable" markers that nothing in production ever appended, so those counts
// were tautologies. Every assertion below reads state the application owns.

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestPanelProcessRestartResumesSavedWork is the core positive.
//
// A job approved before the panel stopped must be picked up by a different OS process,
// which records provider-unavailable progress and leaves the job pending - never
// "ready", because no provider answered.
func TestPanelProcessRestartResumesSavedWork(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seed(seedShape{trustPolicy: models.SetupTrustPolicyFirstContact})

	env.startChild()

	after := env.read()
	env.requireNotReady(after, "after a fresh process resumed the job")
	// Pending progress, explicitly distinguished from a healthy installation.
	if after.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			after.State, models.SetupStatePending, after.Step, after.LastError)
	}
	if after.Attempts <= seeded.Attempts {
		t.Fatalf("the child did not track the saved approval: attempts stayed at %d", seeded.Attempts)
	}
	if after.ReadFailures == 0 {
		t.Fatal("no provider read failure was recorded, so the child never attempted the read")
	}
	if after.Step != "provider_unreadable" {
		t.Fatalf("step = %q, want the unreadable-provider step %q", after.Step, "provider_unreadable")
	}
	env.requireIdentityPreserved(seeded, after, "after a fresh process resumed the job")
	env.requireSingleIntent("after a fresh process resumed the job")

	// The child really was one separate application process that bound and stopped.
	if n := markerCount(env.journal, "boot"); n != 1 {
		t.Fatalf("boot markers = %d, want exactly 1", n)
	}
	if n := markerCount(env.journal, "serving"); n != 1 {
		t.Fatalf("serving markers = %d, want exactly 1 (the child bound its listener)", n)
	}
	if n := markerCount(env.journal, "clean_shutdown"); n != 1 {
		t.Fatalf("clean_shutdown markers = %d, want exactly 1", n)
	}
}

// TestPanelProcessRestartPreservesPersistedAuthority proves continuity across TWO
// process lifetimes: the second must resume the same row and rewrite no identity.
func TestPanelProcessRestartPreservesPersistedAuthority(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seed(seedShape{trustPolicy: models.SetupTrustPolicyFirstContact})

	env.startChild()
	afterFirst := env.read()
	env.requireNotReady(afterFirst, "after the first process")
	env.requireIdentityPreserved(seeded, afterFirst, "after the first process")

	env.makeWorkDue()

	env.startChild()
	afterSecond := env.read()

	if afterSecond.Attempts <= afterFirst.Attempts {
		t.Fatalf("the second process did not resume the row: attempts stayed at %d", afterFirst.Attempts)
	}
	env.requireNotReady(afterSecond, "after the second process")
	env.requireIdentityPreserved(seeded, afterSecond, "after the second process")
	env.requireSingleIntent("after the second process")

	if n := markerCount(env.journal, "boot"); n != 2 {
		t.Fatalf("boot markers = %d, want exactly 2 (two separate process lifetimes)", n)
	}
}

// TestPanelProcessAutomaticEffectRefusedWhenPolicyOff proves the shipped default-off
// policy stops an unattended job, and that the refusal happened at that boundary.
//
// The row is seeded ready_for_setup so it IS in the installer's due set; the gate, not
// the due set, is what must stop it. Two real observations make the claim: the worker
// claimed the row (P1), and the pause names the automatic policy boundary (P2).
func TestPanelProcessAutomaticEffectRefusedWhenPolicyOff(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seed(seedShape{
		trustPolicy: models.SetupTrustPolicyFirstContact,
		state:       models.SetupStateReadyForSetup,
	})

	env.startChild()

	after := env.read()
	env.requireNotReady(after, "after the automatic refusal")
	// Without a claimed pass, "refused" would be indistinguishable from "never ran".
	env.requireWorkerPassed(seeded, after, "after the automatic refusal")
	env.requireAutomaticPolicyRefusal(after, "after the automatic refusal")
	env.requireIdentityPreserved(seeded, after, "after the automatic refusal")
	env.requireSingleIntent("after the automatic refusal")
}

// TestPanelProcessManualJobIsNotGatedByAutomaticPolicy is the contrast that keeps the
// refusal above about automation policy rather than a permanently frozen row.
//
// A manual job (HostTrustPolicy == models.SetupTrustPolicyManual, the empty default) is
// answered nil by automaticJobRefusal. The worker must still claim it (P1), and the
// pause must NOT be at the automatic policy boundary.
func TestPanelProcessManualJobIsNotGatedByAutomaticPolicy(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seed(seedShape{
		trustPolicy: models.SetupTrustPolicyManual,
		state:       models.SetupStateReadyForSetup,
	})
	if seeded.HostTrustPolicy == models.SetupTrustPolicyFirstContact {
		t.Fatal("precondition: the seeded row was treated as unattended")
	}

	env.startChild()

	after := env.read()
	env.requireNotReady(after, "after the manual pass")
	// The worker ran either way; that is what makes the step comparison meaningful.
	env.requireWorkerPassed(seeded, after, "after the manual pass")
	if after.Step == "automatic_setup_disabled" {
		t.Fatalf("a manual job was stopped by the unattended-setup policy at step %q "+
			"(state %q, last error %q)", after.Step, after.State, after.LastError)
	}
	env.requireIdentityPreserved(seeded, after, "after the manual pass")
	env.requireSingleIntent("after the manual pass")
}

// TestPanelProcessDoesNotReplayAnUncertainInstall is the no-replay control.
//
// A row persisted install_paused with an unverified phase is deliberately absent from
// the installer's due set (intents.go:558-583 selects ready_for_setup and installing
// only), so a fresh process must not claim it again. The assertion is that the
// generation did NOT advance - the precise inverse of requireWorkerPassed, and the
// reason a paused row needs no journal fiction to prove itself.
func TestPanelProcessDoesNotReplayAnUncertainInstall(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seed(seedShape{
		trustPolicy:  models.SetupTrustPolicyFirstContact,
		state:        models.SetupStateInstallPaused,
		installPhase: models.SetupPhaseInstalled,
		generation:   3,
	})
	if seeded.State != models.SetupStateInstallPaused {
		t.Fatalf("precondition: seeded state = %q", seeded.State)
	}

	env.startChild()

	after := env.read()
	env.requireNotReady(after, "after refusing to replay an uncertain install")
	if after.InstallGeneration != seeded.InstallGeneration {
		t.Fatalf("a paused row was re-claimed and replayed: generation %d -> %d",
			seeded.InstallGeneration, after.InstallGeneration)
	}
	if after.State != models.SetupStateInstallPaused {
		t.Fatalf("state = %q, want the paused state preserved", after.State)
	}
	if after.InstallPhase != seeded.InstallPhase {
		t.Fatalf("the crash journal was rewritten: phase %q -> %q",
			seeded.InstallPhase, after.InstallPhase)
	}
	env.requireIdentityPreserved(seeded, after, "after refusing to replay an uncertain install")
	env.requireSingleIntent("after refusing to replay an uncertain install")
}
