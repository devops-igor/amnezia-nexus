//go:build with_utls

package handlers

// The automatic AWG consumer: admission decided by a real encrypted AWG exchange, driven
// through the production chain, with the pre-rollback state captured so a remote-only failure
// is diagnosable.
//
// The component proof (gigahost_setup_awg_traffic_test.go) builds the production device and
// canary directly. Every earlier automatic-admission test injected the qualification verdict.
// This drives the whole production path with neither:
//
//	StartAutomaticGigahostSetup      entry; policy opt-in
//	tracker.RunOnce                  provider discovery, association, grant, pin
//	installer.RunOnce
//	  installSSL/register/install    controlled boundaries, as in every checkpoint
//	  enableDeployBackend
//	    EnableBackendWithConfig      pool registration, key generation
//	    resolveBackendCredentials    reads the server row
//	    buildBackendDeviceParams     stored dialect + generated data-plane preamble
//	    provider.AddClient           registers the portal peers on the real peer
//	    attachBackendForwarder       attaches the device, starts the return pump
//	  qualifyBackendTraffic
//	    ProbeTunnel                  real Noise IK handshake
//	    ProbeCanary -> ProbePacketDevice   a real ICMP echo answered by the peer's own stack
//	  promotion + durable quarantine release
//
// The capture inside the canary seam records endpoint equality, per-key dialect equality, the
// presence of the production preamble and the device's own tx/rx/handshake counters - all
// before the failure branch disables the backend and closes the device. Only booleans and
// non-secret counters enter the log.
//
// Scope, stated: this proves the AWG automatic path against a real peer. The provider answer,
// the SSH transport and the protocol installation remain controlled outcomes. Naive is
// untouched, and nothing is claimed about kernel routing.

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAutomaticSetupAdmitsAfterAuthenticAWGTraffic is the A1/A2 positive.
//
// The job starts with no association, no grant and no pin, and production acquires all three.
// The backend is admitted only after the real peer's own IP stack answers the production
// canary, and every prior observation of that exchange is asserted.
func TestAutomaticSetupAdmitsAfterAuthenticAWGTraffic(t *testing.T) {
	const orderID = "ord_awg_consumer_positive"
	const providerServerID = 9981

	f := newAWGConsumerJob(t, orderID, providerServerID, true)
	ctx := context.Background()

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The pre-rollback capture must exist at all: this is what rules out a callback answering
	// the qualification question.
	f.requireObservationCaptured(t, "after the admission attempt")
	// On the positive the canary must have succeeded, so its error is part of the evidence.
	if err := f.observation.canaryErr; err != nil {
		t.Fatalf("the production canary did not complete over a healthy real AWG peer: %v "+
			"(observations: %s)", err, (*f.observation).summary())
	}
	f.requireHealthyObservations(t, "after admission")

	final := f.intent(orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("state = %q, want %q (step %q, last error %q; observations: %s)",
			final.State, models.SetupStateReady, final.Step, final.LastError,
			(*f.observation).summary())
	}
	t.Logf("authentic AWG positive: %s", (*f.observation).summary())

	// The peer really carried the exchange: it registered the portal identities production
	// asked it to, and it holds distinct client peers.
	if n := f.peer.peerCount(); n == 0 {
		t.Fatal("the real peer registered no client peer, so nothing could have handshaked")
	}
	if n := f.peer.registrations(); n == 0 {
		t.Fatal("the production enablement path never called the provider's AddClient")
	}
	if !f.peer.peerKeysAreRealKeyMaterial() {
		t.Fatal("the peer registered an identity that is not a full Curve25519 public key")
	}
	t.Logf("authentic AWG positive: peer registered %d client identities over %d calls",
		f.peer.peerCount(), f.peer.registrations())

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered")
	}
	if !authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("the qualified AWG backend is not selectable by the production pool path")
	}
	if authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("an admitted backend still carries the durable enrollment quarantine")
	}

	// One durable identity from tracking through install, never rewritten.
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after install")
	if final.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was rewritten to %q", final.HostTrustPolicy)
	}

	// One install, one registration, and no purchase anywhere.
	if n := f.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	if n := f.countRegisteredServers(t); n != 1 {
		t.Fatalf("registered panel servers for this provider server = %d, want exactly 1", n)
	}
	if n := f.countEnrollments(t); n != 0 {
		t.Fatalf("durable enrollment markers for the admitted backend = %d, want 0", n)
	}
	f.requireNoPurchases(t, "after admission")

	// A repeated normal tracker+installer pass must add nothing: no second install, no second
	// registration, no second enrollment, no additional client identity, and no purchase.
	beforeInstalls := f.counters.totalInstalls()
	beforeServers := f.countRegisteredServers(t)
	beforePeers := f.peer.peerCount()
	if err := f.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("second tracking pass: %v", err)
	}
	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}
	if n := f.counters.totalInstalls(); n != beforeInstalls {
		t.Fatalf("a repeated pass installed again: installs went from %d to %d", beforeInstalls, n)
	}
	if n := f.countRegisteredServers(t); n != beforeServers {
		t.Fatalf("a repeated pass registered another server: %d, want %d", n, beforeServers)
	}
	if n := f.countEnrollments(t); n != 0 {
		t.Fatalf("a repeated pass left %d durable enrollment markers", n)
	}
	if n := f.peer.peerCount(); n != beforePeers {
		t.Fatalf("a repeated pass registered %d additional client identities on the peer",
			n-beforePeers)
	}
	f.requireNoPurchases(t, "after a repeated pass")

	// The backend is still admitted exactly once after the repeat.
	if !authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a repeated pass removed the admitted backend from the pool")
	}
	if got := f.intent(orderID); got.State != models.SetupStateReady {
		t.Fatalf("a repeated pass changed the terminal state to %q", got.State)
	}
	requireNoFingerprintRewrite(t, f.intent(orderID).HostFingerprint, f.pinnedPresented,
		"after a repeated pass")
}

// TestAutomaticSetupRefusesWhenTheAWGPeerNeverAnswers is the A2 negative for the subtlest case.
//
// The peer is a real AWG server: the encrypted handshake completes and the transport delivers
// datagrams, which is why a handshake-only oracle would admit it. Its stack does not own the
// canary destination, so the payload is never answered and production qualification must
// refuse. The backend must stay out of the pool and the durable quarantine must remain.
func TestAutomaticSetupRefusesWhenTheAWGPeerNeverAnswers(t *testing.T) {
	const orderID = "ord_awg_consumer_no_payload"
	const providerServerID = 9982

	f := newAWGConsumerJob(t, orderID, providerServerID, false)
	ctx := context.Background()

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The exchange reached the production device and the handshake completed: the failure is
	// specifically the missing payload, which is the case this test exists for.
	f.requireObservationCaptured(t, "after the refused admission")
	f.requireHandshakeWithoutPayload(t, "after the refused admission")
	t.Logf("authentic AWG negative: %s", (*f.observation).summary())

	final := f.intent(orderID)
	if final.State == models.SetupStateReady {
		t.Fatalf("a backend whose payload was never answered was reported ready (observations: %s)",
			(*f.observation).summary())
	}
	if final.LastError == "" {
		t.Fatal("the refusal recorded no reason")
	}

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	if authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a backend whose payload was never answered is selectable by the production pool path")
	}
	if !authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("the durable quarantine was released without an answered payload")
	}
	// The pin survives the refusal untouched.
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after refusal")
	f.requireNoPurchases(t, "after a refused admission")
}
