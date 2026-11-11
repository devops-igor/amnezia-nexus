package handlers

// The authentic-traffic checkpoint: automatic admission decided by a REAL VLESS request/reply.
//
// Every prior admission test injected the qualification verdict. Here the production
// qualification runs, and it is the production code that decides - a real authenticated VLESS
// session through a REALITY endpoint, a real HTTP request, and a verified application reply
// from a counted origin.
//
// What is measured at the far end rather than inferred:
//
//	authenticated   REALITY handshakes that completed with the client's UUID
//	originRequests  requests the origin actually received
//	originReplies   replies the origin actually sent back
//
// A handshake alone must never admit a backend, and neither must bytes-written. The negatives
// below are exactly those two cases.

import (
	"context"
	"fmt"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// authenticTrafficFixture wires one automatic job to a real VLESS endpoint.
type authenticTrafficFixture struct {
	*installEnv
	endpoint         *authenticTrafficEndpoint
	orderID          string
	providerServerID int64
	pinnedPresented  string
}

// newAuthenticTrafficJob builds a production-entry automatic job whose install will qualify
// against a real VLESS endpoint.
//
// The SSH boundary is installed BEFORE the tracking pass, so the first-contact challenge and
// the install see the same identity and the pin is preserved rather than re-pointed.
func newAuthenticTrafficJob(
	t *testing.T, orderID string, providerServerID int64, acceptRequests bool,
) *authenticTrafficFixture {
	t.Helper()

	env := newInstallEnv(t, models.ProtocolVLESS)
	// One SSH identity for the whole job: challenge and install observe the same peer.
	env.useAuthenticSSHBoundary()
	// And qualification is the PRODUCTION probe, not the shared fixture's success callback.
	env.useAuthenticQualification()

	endpoint := startAuthenticTrafficFixture(t, acceptRequests)
	t.Cleanup(endpoint.stop)

	const ip = "127.0.0.1"
	env.seedAutomaticOrder(orderID, providerServerID, ip)
	env.providerServes(orderID, providerServerID, ip)

	// The protocol manager's AddClient is the production provisioning contract: it returns the
	// credentials the backend will actually use. Returning this fixture's real VLESS
	// parameters is what makes production derivation produce this endpoint and this
	// forwarding destination - no override, no rewrite of any stored row.
	host, port := splitEndpointHostPort(t, endpoint.endpoint)
	env.provisionVLESSIdentity(t, host, port, endpoint.params)

	env.enableAutomaticSetup(true)
	// The recorded port must be the port the real endpoint listens on: production dials
	// `FormatEndpoint(server.Host, port)` from the tunnel, so a mismatch would be a fixture
	// error masquerading as a qualification failure.
	_, endpointPort := splitEndpointHostPort(t, endpoint.endpoint)
	env.startAutomatic(orderID, AutomaticGigahostSetupOptions{
		Protocol: models.ProtocolVLESS,
		Port:     fmt.Sprintf("%d", endpointPort),
	})
	env.grantAutomationTrust(orderID, providerServerID)

	// A production tracking pass discovers, associates, grants and pins.
	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	pinned := env.intent(orderID).HostFingerprint
	if pinned == "" {
		t.Fatal("precondition: the job was not pinned")
	}
	// The pin must already be the identity this fixture's SSH boundary presents. If it were
	// not, a later "alignment" would be a rewrite, which this checkpoint forbids.
	requireNoFingerprintRewrite(t, pinned, installFixtureFingerprint, "before install")

	return &authenticTrafficFixture{
		installEnv:       env,
		endpoint:         endpoint,
		orderID:          orderID,
		providerServerID: providerServerID,
		pinnedPresented:  pinned,
	}
}

// TestAutomaticSetupAdmitsAfterAuthenticVLESSRequestReply is the A1 positive.
//
// The whole production chain runs with NO qualification override: entry, tracker, installer,
// `QualifyProxyTraffic`, `qualifyVLESS`, `ProbeVLESSTraffic`. The endpoint authenticates the
// client, the origin receives the request and sends the reply, and only then does the backend
// become selectable.
func TestAutomaticSetupAdmitsAfterAuthenticVLESSRequestReply(t *testing.T) {
	const orderID = "ord_authentic_positive"
	const providerServerID = 9970

	f := newAuthenticTrafficJob(t, orderID, providerServerID, true)
	ctx := context.Background()

	// No qualification override is installed anywhere: this fixture never calls
	// SetCanaryProbeFunc or SetProxyTrafficProbeFuncForTest, and it does not use
	// SetProxyCanaryDestinationForTest either. The only way this test can reach the counts
	// asserted below is the production probe (`QualifyProxyTraffic` -> `qualifyVLESS` ->
	// `ProbeVLESSTraffic`), because a callback would not open a REALITY session or talk to
	// the origin at all.

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	final := f.intent(orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}

	// The far end really did the work: this is the whole point of the checkpoint.
	if n := f.endpoint.authenticated.Load(); n == 0 {
		t.Fatal("the VLESS endpoint never authenticated a session, so qualification did not run")
	}
	if n := f.endpoint.originRequests.Load(); n == 0 {
		t.Fatal("the origin never received a request, so no application exchange happened")
	}
	if n := f.endpoint.originReplies.Load(); n == 0 {
		t.Fatal("the origin never sent a reply, so no response was validated")
	}
	t.Logf("authentic positive: authenticated=%d origin_requests=%d origin_replies=%d",
		f.endpoint.authenticated.Load(), f.endpoint.originRequests.Load(), f.endpoint.originReplies.Load())

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered")
	}
	if !authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("the authenticated backend is not selectable by the production pool path")
	}
	if authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("an admitted backend still carries the durable enrollment quarantine")
	}

	// One durable identity from tracking through install, never rewritten.
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after install")
	if final.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was rewritten to %q", final.HostTrustPolicy)
	}
	// One install, one enrollment, no replay.
	if n := f.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
}

// TestAutomaticSetupRefusesWhenTheOriginNeverReplies is the A2 negative for the subtlest case.
//
// The REALITY handshake completes and the endpoint authenticates the client - so a
// handshake-only oracle would admit this - but the origin accepts the request and never
// answers. Production qualification must refuse, the backend must stay out of the pool, and
// the durable quarantine must remain.
func TestAutomaticSetupRefusesWhenTheOriginNeverReplies(t *testing.T) {
	const orderID = "ord_authentic_no_reply"
	const providerServerID = 9971

	f := newAuthenticTrafficJob(t, orderID, providerServerID, false)
	ctx := context.Background()

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The endpoint DID authenticate and the origin DID receive the request: the failure is
	// specifically the missing reply, which is the case this test exists for.
	if n := f.endpoint.authenticated.Load(); n == 0 {
		t.Fatal("the endpoint never authenticated, so the failure was not the missing reply")
	}
	if n := f.endpoint.originRequests.Load(); n == 0 {
		t.Fatal("the origin never received a request, so the failure was not the missing reply")
	}
	if n := f.endpoint.originReplies.Load(); n != 0 {
		t.Fatalf("the origin sent %d replies, so this is not the missing-reply case", n)
	}

	final := f.intent(orderID)
	if final.State == models.SetupStateReady {
		t.Fatal("a backend whose application reply never arrived was reported ready")
	}
	if final.LastError == "" {
		t.Fatal("the refusal recorded no reason")
	}

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	if authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a backend with no application reply is selectable by the production pool path")
	}
	if !authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("the durable quarantine was released without a validated application reply")
	}
	// The pin survives the refusal untouched.
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after refusal")
}

// TestAutomaticSetupRefusesWhenVLESSAuthenticationIsRejected is the A2 negative for wrong
// protocol credentials.
//
// The install provisions a UUID the endpoint does not know, so the authenticated session never
// forms. Qualification must refuse before any application exchange, and nothing may be
// admitted. The credential is wrong; the exchange and the validation are untouched.
func TestAutomaticSetupRefusesWhenVLESSAuthenticationIsRejected(t *testing.T) {
	const orderID = "ord_authentic_bad_uuid"
	const providerServerID = 9972

	f := newAuthenticTrafficJob(t, orderID, providerServerID, true)
	ctx := context.Background()

	// The provisioning contract now hands out a UUID the endpoint does not accept.
	host, port := splitEndpointHostPort(t, f.endpoint.endpoint)
	bad := f.endpoint.params
	bad.UUID = "00000000-0000-4000-8000-000000000000"
	f.provisionVLESSIdentity(t, host, port, bad)

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// A rejected session cannot produce an application exchange.
	if n := f.endpoint.authenticated.Load(); n != 0 {
		t.Fatalf("the endpoint authenticated %d sessions although the client UUID was wrong", n)
	}
	if n := f.endpoint.originRequests.Load(); n != 0 {
		t.Fatalf("the origin received %d requests although authentication failed", n)
	}
	if n := f.endpoint.originReplies.Load(); n != 0 {
		t.Fatalf("the origin sent %d replies although authentication failed", n)
	}

	final := f.intent(orderID)
	if final.State == models.SetupStateReady {
		t.Fatal("a backend whose protocol credentials were rejected was reported ready")
	}
	reg := f.registeredServer(providerServerID)
	if reg == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	if authenticPoolContains(t, f.installEnv, reg.ID) {
		t.Fatal("a backend whose credentials were rejected is selectable")
	}
	if !authenticDurableQuarantine(t, f.installEnv, reg.ID) {
		t.Fatal("the durable quarantine was released without authentication")
	}
}
