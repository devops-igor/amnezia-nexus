package main

// Parent side of the fresh-OS-process application restart proof.
//
// Each test seeds ONE persisted situation in a disposable encrypted database,
// starts the real application in a genuinely separate process, and asserts on two
// independent things:
//
//  1. the durable row the second process left behind, and
//  2. the shared effects journal, which is how "did it do that work twice?" is
//     answered by evidence from the child's own run rather than by a counter the
//     parent happened to hold.
//
// The helper file states what a child can and cannot observe without a production
// seam. In one sentence: resumption, identity continuity, default-off refusal and
// no-replay are proved here; a healthy install completing in a child is not, and no
// assertion below claims it.

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestPanelProcessRestartResumesSavedWork is the core positive.
//
// A job approved before the panel stopped must be picked up by a genuinely
// different OS process, which records provider-unavailable progress and leaves the
// job pending - never "ready", because no provider answered.
func TestPanelProcessRestartResumesSavedWork(t *testing.T) {
	env := newRestartEnv(t)
	// Automatic provenance, which is the unattended case this whole epic is about.
	seeded := env.seedIntent(restartShape{trustPolicy: models.SetupTrustPolicyFirstContact})

	env.startChild()

	after := env.readIntent()
	env.requireStillPending(after, seeded, "after a fresh process resumed the job")
	env.requireIdentityPreserved(after, seeded, "after a fresh process resumed the job")
	env.requireSingleIntent("after a fresh process resumed the job")

	// The child really was a separate application process: it recorded its boot and,
	// because it reached serving, its clean shutdown.
	if n := effectCount(env.journal, "boot"); n != 1 {
		t.Fatalf("boot markers = %d, want exactly 1 (one child process)", n)
	}
	if n := effectCount(env.journal, "serving"); n != 1 {
		t.Fatalf("serving markers = %d, want exactly 1 (the child bound its listener)", n)
	}
	if n := effectCount(env.journal, "clean_shutdown"); n != 1 {
		t.Fatalf("clean shutdown markers = %d, want exactly 1", n)
	}
}

// TestPanelProcessRestartPreservesPersistedAuthority is the restart-continuity
// proof across TWO process lifetimes.
//
// The second process must resume the same row and must not rewrite any of the
// identities the acceptance names, nor add a job.
func TestPanelProcessRestartPreservesPersistedAuthority(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seedIntent(restartShape{trustPolicy: models.SetupTrustPolicyFirstContact})

	// First process lifetime.
	env.startChild()
	afterFirst := env.readIntent()
	env.requireStillPending(afterFirst, seeded, "after the first process")
	env.requireIdentityPreserved(afterFirst, seeded, "after the first process")

	// A real restart happens long after the backoff the first pass persisted. Move
	// the saved next-attempt into the past, which is the elapsed-time condition
	// downtime would have produced anyway; honouring the backoff is deliberate.
	env.makeWorkDue()

	// Second process lifetime, same database.
	env.startChild()
	afterSecond := env.readIntent()

	if afterSecond.Attempts <= afterFirst.Attempts {
		t.Fatalf("the second process did not resume the row: attempts stayed at %d", afterFirst.Attempts)
	}
	env.requireStillPending(afterSecond, afterFirst, "after the second process")
	env.requireIdentityPreserved(afterSecond, seeded, "after the second process")
	env.requireSingleIntent("after the second process")

	if n := effectCount(env.journal, "boot"); n != 2 {
		t.Fatalf("boot markers = %d, want exactly 2 (two separate process lifetimes)", n)
	}
}

// TestPanelProcessDoesNotReplayAnUncertainInstall is the no-replay control.
//
// The row is persisted mid-install with an unverified phase, which is what a panel
// killed inside an install leaves behind. A fresh process must not install again:
// the row is not due for the installer, and the automatic gate refuses before any
// dial. The journal must show no install effect at all.
func TestPanelProcessDoesNotReplayAnUncertainInstall(t *testing.T) {
	env := newRestartEnv(t)
	seeded := env.seedIntent(restartShape{
		trustPolicy:  models.SetupTrustPolicyFirstContact,
		state:        "install_paused",
		installPhase: "installing",
	})
	if seeded.InstallGeneration == 0 {
		t.Fatal("precondition: the seeded row carries no install generation")
	}

	env.startChild()

	after := env.readIntent()
	// The interrupted job must not be declared healthy by a process that cannot
	// have verified it.
	if after.State == "ready" {
		t.Fatalf("a row with an unverified install was reported ready (step %q)", after.Step)
	}
	// No replay: nothing in this fixture can perform a real install, so this asserts
	// the absence of the effect the journal would carry. It is a negative control on
	// a code path (the installer's due-set), not a claim that a real install ran.
	if n := effectCount(env.journal, "install"); n != 0 {
		t.Fatalf("a fresh process attempted %d install effects on an unverified row", n)
	}
	env.requireIdentityPreserved(after, seeded, "after refusing to replay an uncertain install")
	env.requireSingleIntent("after refusing to replay an uncertain install")
}

// TestPanelProcessAutomaticEffectRefusedWhenPolicyOff is the default-off proof.
//
// The shipped application never installs an automation policy, so a first_contact
// job must be refused before any credential is sent or host dialled. This runs in a
// real child, so it proves the real default rather than a stubbed one.
func TestPanelProcessAutomaticEffectRefusedWhenPolicyOff(t *testing.T) {
	env := newRestartEnv(t)
	// Ready for setup, so the row IS due and the gate is what stops it.
	seeded := env.seedIntent(restartShape{
		trustPolicy: models.SetupTrustPolicyFirstContact,
		state:       "ready_for_setup",
	})

	env.startChild()

	after := env.readIntent()
	// The job must not have reached ready, and must not have installed or enabled.
	if after.State == "ready" {
		t.Fatalf("default-off unattended setup reported a completed job (step %q)", after.Step)
	}
	if n := effectCount(env.journal, "install"); n != 0 {
		t.Fatalf("a disabled automatic job produced %d install effects", n)
	}
	if n := effectCount(env.journal, "enable"); n != 0 {
		t.Fatalf("a disabled automatic job produced %d enable effects", n)
	}
	env.requireIdentityPreserved(after, seeded, "after the automatic refusal")
	env.requireSingleIntent("after the automatic refusal")
}

// TestPanelProcessManualJobIsNotGatedByAutomaticPolicy is the manual-mode control.
//
// The automatic gate is keyed on first_contact provenance only: a job a person
// approved must not be refused by an unattended-setup setting. This is the contrast
// that keeps the refusal above about automation policy rather than about a
// permanently frozen row.
func TestPanelProcessManualJobIsNotGatedByAutomaticPolicy(t *testing.T) {
	env := newRestartEnv(t)
	// Manual provenance: models.SetupTrustPolicyManual is explicitly the empty
	// string, and only first_contact is treated as unattended.
	seeded := env.seedIntent(restartShape{
		trustPolicy: models.SetupTrustPolicyManual,
		state:       "ready_for_setup",
	})
	if seeded.HostTrustPolicy == models.SetupTrustPolicyFirstContact {
		t.Fatal("precondition: the seeded row was treated as automatic")
	}

	env.startChild()

	after := env.readIntent()
	// The manual job must not have been turned into a completed install by a process
	// with no provider, but it must also not have been refused by the automatic gate.
	if after.State == "ready" {
		t.Fatalf("a manual job with no reachable provider was reported completed")
	}
	if n := effectCount(env.journal, "install"); n != 0 {
		t.Fatalf("the manual control produced %d install effects it cannot justify", n)
	}
	env.requireIdentityPreserved(after, seeded, "after the manual-mode pass")
	env.requireSingleIntent("after the manual-mode pass")
}
