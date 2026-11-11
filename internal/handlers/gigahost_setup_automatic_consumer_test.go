package handlers

// What a job created by the unattended entry can and cannot do, measured through the
// production tracker and installer against a real loopback SSH peer.
//
// The two claims are opposite halves of one property and are proved together:
//
//   - without a granted binding the job is inert. The tracker observes the identity
//     and offers it for confirmation, and nothing authenticates, opens a session or
//     installs. The peer's own counters are the evidence;
//   - with the existing grant writer applied, the same job pins that identity before
//     authenticating and completes with exactly one install. Without this half the
//     zeroes above would prove nothing about the counters being live.
//
// The grant is not issued by this checkpoint. It stands in for the later phase that
// will, and it is the existing audited writer, unchanged.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAutomaticJobWithoutAGrantIsInert is the real-consumer negative control.
//
// The job the entry creates has a policy and no binding. The production tracker is
// run over it with the production challenge against a real loopback peer, and the
// measured result must be: the identity is observed and offered for confirmation,
// nothing is pinned, nothing authenticates, and the installer has nothing to claim.
// The job keeps retrying, which is the fail-closed behaviour, not a lost job.
func TestAutomaticJobWithoutAGrantIsInert(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)

	const orderID = "ord_auto_inert"
	const providerServerID = 9201
	const ip = "127.0.0.1"
	env.seedAutomaticOrder(orderID, providerServerID, ip)

	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	env.startAutomatic(orderID, automaticOptions)

	tracker := env.h.NewGigahostSetupTracker()
	if tracker == nil {
		t.Fatal("the tracker was not constructed")
	}
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}

	got := env.intent(orderID)
	requireNoTrustAuthority(t, got, "a job with no grant")
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			got.State, models.SetupStatePending, got.Step, got.LastError)
	}
	if got.Step != stepHostTrustUnavailableLiteral {
		t.Fatalf("step = %q, want %q", got.Step, stepHostTrustUnavailableLiteral)
	}
	if got.LastError == "" {
		t.Fatal("the inert job recorded no reason for not trusting the identity")
	}
	// The observed identity is offered to a person, which is the manual path and
	// the whole reason the refusal is safe rather than silent.
	if got.HostCandidateFingerprint != presented {
		t.Fatalf("displayed candidate = %q, want the identity the peer presented (%q)",
			got.HostCandidateFingerprint, presented)
	}

	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("an ungranted job offered a credential (%d authentication attempts)", n)
	}
	if n := peer.sessions.Load(); n != 0 {
		t.Fatalf("an ungranted job opened %d session channels", n)
	}

	// The installer has no installable row, so a pass over it changes nothing.
	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	afterInstall := env.intent(orderID)
	if afterInstall.State != models.SetupStatePending {
		t.Fatalf("the installer acted on an ungranted job: state = %q", afterInstall.State)
	}
	if afterInstall.InstallPhase != "" || afterInstall.InstallPhaseDone != "" {
		t.Fatalf("the installer started a phase: in-flight=%q done=%q",
			afterInstall.InstallPhase, afterInstall.InstallPhaseDone)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("an ungranted job installed %d times", n)
	}

	// A second pass asks again and still refuses, so this is a retryable refusal
	// rather than a one-off: the job is not stranded in a settled state.
	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("second tracking pass: %v", err)
	}
	if again := env.intent(orderID); again.State != models.SetupStatePending {
		t.Fatalf("the refused job settled into %q instead of retrying", again.State)
	}
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the retry offered a credential (%d authentication attempts)", n)
	}
}

// TestAutomaticJobPinsOnceTheExistingGrantExists is the positive control beside the
// negative above.
//
// The job is created by the entry, not by an administrator's approval, and the
// existing grant writer is then applied to it. The production tracker must pin the
// identity the real peer presented without authenticating first, and the production
// installer must then complete the setup with exactly one install. This is the
// property the negative control's zeroes are measured against: the counters and the
// pin really can move.
func TestAutomaticJobPinsOnceTheExistingGrantExists(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)

	const orderID = "ord_auto_granted"
	const providerServerID = 9202
	const ip = "127.0.0.1"
	key := newManagedTestKey(t)
	env.seedPurchasedOrder(orderID, providerServerID, ip)
	env.seedOrderCredential(orderID, key)
	env.providerServes(orderID, providerServerID, ip)

	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	env.startAutomatic(orderID, automaticOptions)

	// The grant is the separate decision this checkpoint does not issue for
	// production; here it stands in for the later phase that will.
	env.grantAutomationTrust(orderID, providerServerID)

	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}

	pinned := env.intent(orderID)
	if pinned.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			pinned.State, models.SetupStateReadyForSetup, pinned.Step, pinned.LastError)
	}
	if pinned.HostFingerprint != presented {
		t.Fatalf("pinned identity = %q, want the identity the peer presented (%q)",
			pinned.HostFingerprint, presented)
	}
	if pinned.HostTrustMode != models.SetupTrustModeFirstContact {
		t.Fatalf("trust provenance = %q, want %q", pinned.HostTrustMode, models.SetupTrustModeFirstContact)
	}
	if pinned.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the entry's policy was lost: %q", pinned.HostTrustPolicy)
	}
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the trust pass offered a credential before the identity was durable (%d attempts)", n)
	}

	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	final := env.intent(orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("final state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no server row was registered for the pinned provider identity")
	}
	bound, err := env.db.GetKnownHostFingerprint(context.Background(), server.ID)
	if err != nil {
		t.Fatalf("read the bound identity: %v", err)
	}
	if bound != presented {
		t.Fatalf("registered known_hosts identity = %q, want the pinned %q", bound, presented)
	}
	if n := peer.auths.Load(); n == 0 {
		t.Fatal("the peer never saw an authentication attempt, so its zero counter proves nothing")
	}
}
