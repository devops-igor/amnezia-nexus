package handlers

// Automatic admission at the ACTUAL healthy-pool boundary.
//
// The C2a checkpoint proved that `finishInstall` refuses to write the journal when the
// automation policy stops permitting the job. That is a journal fact. What it never
// established is the pool fact, and the pool fact is the one the requirement is about: an
// unfinished backend must not become selectable.
//
// The difference matters because of where the two decisions sit:
//
//	qualifyBackendTraffic -> PromoteQualifiedTunnel -> pool.PromoteTunnelWithEnrollmentRelease
//	                            (status active + quarantine released = selectable)
//	finishInstall -> refuseAutomaticEffect(boundaryHealthyAdmission)
//	                            (journal write refused)
//
// Promotion happens BEFORE the journal refusal, so a policy that turns off during
// qualification can leave an admitted backend behind a job that never claims success.
//
// These tests assert the pool, not the journal: the tunnel's Enabled flag, its status, its
// disable reason, and the durable pending-enrollment marker that the ingress admission path
// consults (`vpn_ingress.go`, `IsPendingEnrollment`). A backend that is enabled AND has no
// durable quarantine is selectable; that combination is the failure.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// errAdmissionPolicyUnreadable stands in for a settings store that cannot be read at the
// admission boundary.
var errAdmissionPolicyUnreadable = errors.New("the unattended setup setting could not be read")

// admissionProbe is the observed pool state of one backend, read from the real VPN service
// and the real store.
type admissionProbe struct {
	exists        bool
	enabled       bool
	status        string
	disableReason string
	quarantined   bool // durable pending-enrollment marker still present
	selectable    bool // enabled && !quarantined && status is active/degraded
}

// observeAdmission reads the actual pool and store state for one server.
//
// `selectable` is derived the way the ingress path decides it: an administratively disabled
// backend is out, a backend under the durable enrollment quarantine is out, and a status
// that is not active/degraded is out. It is the question a client connection actually asks.
func observeAdmission(t *testing.T, env *installEnv, serverID int64) admissionProbe {
	t.Helper()
	ctx := context.Background()

	probe := admissionProbe{}
	tun, err := env.h.vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil {
		return probe
	}
	probe.exists = true
	probe.enabled = tun.Enabled
	probe.status = tun.Status
	probe.disableReason = tun.DisableReason

	// The durable marker is what survives a restart, so it is the one that counts.
	marks, markErr := env.db.GetBackendPendingEnrollments(ctx)
	if markErr != nil {
		t.Fatalf("read durable enrollment markers: %v", markErr)
	}
	probe.quarantined = marks[serverID]

	probe.selectable = probe.enabled && !probe.quarantined &&
		(tun.Status == models.TunnelStatusActive || tun.Status == models.TunnelStatusDegraded)
	return probe
}

// requireOutsidePool asserts the backend is not selectable, with the observed facts named.
func requireOutsidePool(t *testing.T, probe admissionProbe, what string) {
	t.Helper()
	if !probe.exists {
		return // no tunnel at all is trivially outside the pool
	}
	if probe.selectable {
		t.Fatalf("%s: the backend is SELECTABLE (enabled=%v status=%q quarantine=%v reason=%q)",
			what, probe.enabled, probe.status, probe.quarantined, probe.disableReason)
	}
}

// TestAutomaticAdmissionRefusesWhenPolicyStopsDuringQualification is the decisive control.
//
// The policy is enabled through installation and enablement, and is turned off *while
// qualification is succeeding* - i.e. after the tunnel is enabled and before promotion.
// Qualification really runs (the fixture's probes are counted), so the only thing standing
// between this backend and the pool is the admission authority.
func TestAutomaticAdmissionRefusesWhenPolicyStopsDuringQualification(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_admission_policy_off"
	const providerServerID = 9701
	const ip = "127.0.0.1"

	env.seedAutomaticOrder(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	env.enableAutomaticSetup(true)
	env.startAutomatic(orderID, automaticOptions)
	env.grantAutomationTrust(orderID, providerServerID)
	policy := env.h.setupAutomationPolicy.(*stubAutomationPolicy)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)
	pinned := env.intent(orderID).HostFingerprint
	if pinned == "" {
		t.Fatal("precondition: the job was not pinned")
	}

	// Turn the policy off when the backend is being enabled, which is after the install
	// phase and before qualification/promotion. Everything up to and including enablement
	// therefore completes legitimately; only admission is in question.
	env.h.vpnSvc.SetEnableBackendPreAddTunnelHookForTest(func() {
		env.counters.mu.Lock()
		env.counters.enables++
		env.counters.mu.Unlock()
		policy.setEnabled(false)
	})

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The installed effects really happened - this is not a job that failed early.
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1 (the effect settled)", enables)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}

	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("the install did not register a server, so admission was never reached")
	}

	// THE ASSERTION THIS CHECKPOINT EXISTS FOR: the pool, not the journal.
	probe := observeAdmission(t, env, server.ID)
	requireOutsidePool(t, probe, "a backend whose automation policy stopped during qualification")

	// The durable quarantine must still be in place, because releasing it is what makes a
	// backend selectable and it is released only by a successful promotion.
	if !probe.quarantined {
		t.Fatalf("the durable enrollment quarantine was released without admission "+
			"(enabled=%v status=%q)", probe.enabled, probe.status)
	}

	// The job must not claim success.
	got := env.intent(orderID)
	if got.State == models.SetupStateReady {
		t.Fatal("a job whose backend was refused admission was still reported ready")
	}
	// Durable provenance is preserved: the pin is not revoked and the proven install history
	// is intact. Excluding unfinished work is not permission to erase it.
	if got.HostFingerprint != pinned {
		t.Fatalf("the pin was revoked: %q, want %q", got.HostFingerprint, pinned)
	}
	if got.InstallPhaseDone != models.SetupPhaseEnabled && got.InstallPhaseDone != models.SetupPhaseInstalled {
		t.Fatalf("proven install history was lost: phase_done = %q", got.InstallPhaseDone)
	}
	if got.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was rewritten to %q", got.HostTrustPolicy)
	}
}

// TestAutomaticAdmissionRefusesWhenPolicyIsUnreadableDuringQualification is the error path at
// the same boundary. "Could not ask" must not admit either.
func TestAutomaticAdmissionRefusesWhenPolicyIsUnreadableDuringQualification(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_admission_policy_error"
	const providerServerID = 9702
	const ip = "127.0.0.1"

	env.seedAutomaticOrder(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	env.enableAutomaticSetup(true)
	env.startAutomatic(orderID, automaticOptions)
	env.grantAutomationTrust(orderID, providerServerID)
	policy := env.h.setupAutomationPolicy.(*stubAutomationPolicy)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	env.h.vpnSvc.SetEnableBackendPreAddTunnelHookForTest(func() {
		env.counters.mu.Lock()
		env.counters.enables++
		env.counters.mu.Unlock()
		policy.setError(errAdmissionPolicyUnreadable)
	})

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("the install did not register a server")
	}
	probe := observeAdmission(t, env, server.ID)
	requireOutsidePool(t, probe, "a backend whose policy could not be read during qualification")
	if !probe.quarantined {
		t.Fatal("the durable enrollment quarantine was released without admission")
	}
	if got := env.intent(orderID); got.State == models.SetupStateReady {
		t.Fatal("an unreadable policy still reported the job ready")
	}
}

// TestAutomaticAdmissionPromotesExactlyOnceUnderEnabledPolicy is the positive control beside
// the two refusals.
//
// Without it, "the backend is not selectable" could be satisfied by a job that can never be
// admitted at all. Here the same automatic path admits the backend exactly once, and the
// quarantine is released as part of that admission.
func TestAutomaticAdmissionPromotesExactlyOnceUnderEnabledPolicy(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_admission_positive"
	const providerServerID = 9703
	const ip = "127.0.0.1"

	env.seedAutomaticOrder(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	env.enableAutomaticSetup(true)
	env.startAutomatic(orderID, automaticOptions)
	env.grantAutomationTrust(orderID, providerServerID)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("the install did not register a server")
	}
	probe := observeAdmission(t, env, server.ID)
	if !probe.exists {
		t.Fatal("the enabled-policy path registered no backend tunnel")
	}
	if !probe.selectable {
		t.Fatalf("the enabled-policy path did not admit the backend: "+
			"enabled=%v status=%q quarantine=%v reason=%q",
			probe.enabled, probe.status, probe.quarantined, probe.disableReason)
	}
	if probe.quarantined {
		t.Fatal("a promoted backend is still under the durable enrollment quarantine")
	}
	if probe.status != models.TunnelStatusActive && probe.status != models.TunnelStatusDegraded {
		t.Fatalf("promoted status = %q, want active or degraded", probe.status)
	}

	if got := env.intent(orderID); got.State != models.SetupStateReady {
		t.Fatalf("the positive job did not complete: state = %q (step %q, last error %q)",
			got.State, got.Step, got.LastError)
	}

	// A second installer pass must not promote again or disturb the admission.
	before := probe
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}
	after := observeAdmission(t, env, server.ID)
	if after.status != before.status || after.quarantined != before.quarantined {
		t.Fatalf("a second pass changed the admission: before=%+v after=%+v", before, after)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1 across both passes", n)
	}
}

// TestAutomaticAdmissionKeepsABackendOutOfThePoolWhenQualificationFails covers failure of
// qualification itself, which is a different reason to stay out of the pool than a policy
// refusal.
func TestAutomaticAdmissionKeepsABackendOutOfThePoolWhenQualificationFails(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_admission_qualify_fail"
	const providerServerID = 9704
	const ip = "127.0.0.1"

	env.seedAutomaticOrder(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	env.enableAutomaticSetup(true)
	env.startAutomatic(orderID, automaticOptions)
	env.grantAutomationTrust(orderID, providerServerID)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	// The outer qualification probe fails, which is the pre-existing failure path.
	env.failNextEnablement()

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("the install did not register a server")
	}
	probe := observeAdmission(t, env, server.ID)
	requireOutsidePool(t, probe, "a backend whose qualification failed")
	if got := env.intent(orderID); got.State == models.SetupStateReady {
		t.Fatal("a failed qualification reported the job ready")
	}
}

// TestManualAdmissionIsUnaffectedByTheAutomaticPolicy is the manual control.
//
// A manual approval has no automation provenance, so the unattended-setup setting has no
// authority over its admission. It must reach the pool with the policy off and unreadable.
func TestManualAdmissionIsUnaffectedByTheAutomaticPolicy(t *testing.T) {
	cases := []struct {
		name   string
		policy func(*installEnv)
	}{
		{name: "no policy installed", policy: func(e *installEnv) {
			e.h.SetGigahostSetupAutomationPolicyForTest(nil)
		}},
		{name: "policy disabled", policy: func(e *installEnv) { e.enableAutomaticSetup(false) }},
		{name: "policy unreadable", policy: func(e *installEnv) {
			p := e.enableAutomaticSetup(true)
			p.setError(errAdmissionPolicyUnreadable)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			const orderID = "ord_admission_manual"
			const providerServerID = 9705
			const ip = "127.0.0.1"

			env.seedOrder(orderID, providerServerID, ip)
			env.seedOrderCredential(orderID, newManagedTestKey(t))
			env.providerServes(orderID, providerServerID, ip)

			hostSigner := newHandshakeSigner(t)
			peer := newChallengePeer(t, hostSigner)
			env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

			tc.policy(env)
			env.approve(orderID, models.ProtocolAWG, "51820", sshFingerprintOf(t, hostSigner))

			env.trackerAndInstall()

			server := env.registeredServer(providerServerID)
			if server == nil {
				t.Fatal("the manual install did not register a server")
			}
			probe := observeAdmission(t, env, server.ID)
			if !probe.selectable {
				t.Fatalf("a manual backend was gated by the unattended-setup policy: "+
					"enabled=%v status=%q quarantine=%v reason=%q",
					probe.enabled, probe.status, probe.quarantined, probe.disableReason)
			}
			if got := env.intent(orderID); got.State != models.SetupStateReady {
				t.Fatalf("the manual job did not complete: state = %q (step %q, last error %q)",
					got.State, got.Step, got.LastError)
			}
		})
	}
}
