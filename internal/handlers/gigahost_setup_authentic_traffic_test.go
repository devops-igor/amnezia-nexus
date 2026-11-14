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
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// errFixturePurchaseRefused is returned by the fixture provider when any purchase path is
// called. Reaching it at all is the failure the counter exists to detect.
var errFixturePurchaseRefused = errors.New("this fixture never performs purchase work")

// authenticTrafficFixture wires one automatic job to a real VLESS endpoint.
type authenticTrafficFixture struct {
	*installEnv
	endpoint         *authenticTrafficEndpoint
	orderID          string
	providerServerID int64
	pinnedPresented  string
	// purchaseAttempts counts purchase-path calls the provider client received.
	purchaseAttempts *atomic.Int64
}

// newAuthenticTrafficJob builds the starting state a real purchase leaves: purchase stamp plus
// managed credential, and NO resource association, grant or pin.
//
// It deliberately does not call grantAutomationTrust, does not seed an address, and does not
// touch the stored fingerprint. Those facts are produced by the production tracking pass below,
// which is the point of this checkpoint.
func newAuthenticTrafficJob(
	t *testing.T, orderID string, providerServerID int64, acceptRequests bool,
) *authenticTrafficFixture {
	t.Helper()

	env := newInstallEnv(t, models.ProtocolVLESS)
	// One SSH identity for the whole job: the first-contact challenge and the install observe
	// the same peer, so the pin is preserved rather than re-pointed later.
	env.useAuthenticSSHBoundary()
	// Qualification is the PRODUCTION probe, not the shared fixture's success callback.
	env.useAuthenticQualification()

	endpoint := startAuthenticTrafficFixture(t, acceptRequests)
	t.Cleanup(endpoint.stop)

	// --- the purchase: stamp + credential, and nothing else -------------------------------
	key := newManagedTestKey(t)
	env.seedFreshPurchase(orderID, key)
	// The provider knows the order and its server; the LEDGER does not, which is exactly the
	// state after a purchase whose provisioning has just finished.
	env.providerServes(orderID, providerServerID, "127.0.0.1")

	// A rejecting purchase counter: any purchase-path call is recorded and refused, so "zero
	// purchases" is a counted fact from the process that would have made them.
	var purchases atomic.Int64
	env.provider.orderServerFn = func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
		purchases.Add(1)
		return nil, errFixturePurchaseRefused
	}
	env.provider.orderServerSafeFn = func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
		purchases.Add(1)
		return nil, errFixturePurchaseRefused
	}

	// The protocol manager's AddClient is the production provisioning contract: it returns the
	// credentials the backend will actually use, which is how production derivation ends up
	// pointing at this fixture's endpoint and origin with no override.
	host, port := splitEndpointHostPort(t, endpoint.endpoint)
	env.provisionVLESSIdentity(t, host, port, endpoint.params)

	env.enableAutomaticSetup(true)
	_, endpointPort := splitEndpointHostPort(t, endpoint.endpoint)
	env.startAutomatic(orderID, AutomaticGigahostSetupOptions{
		Protocol: models.ProtocolVLESS,
		Port:     fmt.Sprintf("%d", endpointPort),
	})

	// --- assert the starting state is genuinely bare --------------------------------------
	requireNoAuthorityYet(t, env, orderID, "before the production tracking pass")

	// --- production background consumers acquire everything --------------------------------
	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	// The chain produced the association, the grant and the pin. Each is asserted, because a
	// pass that silently skipped one could still reach ready_for_setup in some configurations.
	order, found, err := env.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("read order after tracking: found=%v err=%v", found, err)
	}
	if order.ServerID != providerServerID {
		t.Fatalf("the background pass did not record the provider server id: ledger has %d, want %d",
			order.ServerID, providerServerID)
	}
	if order.AssignedIP == "" {
		t.Fatal("the background pass did not record the provider address on the ledger")
	}

	granted := env.intent(orderID)
	if granted.HostTrustOrderID != orderID || granted.HostTrustServerID != providerServerID {
		t.Fatalf("the background pass did not acquire the scoped grant: order=%q server=%d",
			granted.HostTrustOrderID, granted.HostTrustServerID)
	}
	if granted.HostTrustGrantedAt.IsZero() {
		t.Fatal("the background pass did not record when the grant was issued")
	}
	if granted.HostFingerprint == "" {
		t.Fatal("the background pass did not pin a host identity")
	}
	// The pin is the identity this fixture's SSH boundary presents, and it was never rewritten.
	requireNoFingerprintRewrite(t, granted.HostFingerprint, installFixtureFingerprint, "after tracking")

	return &authenticTrafficFixture{
		installEnv:       env,
		endpoint:         endpoint,
		orderID:          orderID,
		providerServerID: providerServerID,
		pinnedPresented:  granted.HostFingerprint,
		purchaseAttempts: &purchases,
	}
}

// requireNoAuthorityYet asserts the starting state carries no resource association, no grant and
// no pin - the facts the production background chain must produce.
func requireNoAuthorityYet(t *testing.T, env *installEnv, orderID, when string) {
	t.Helper()
	ctx := context.Background()

	intent := env.intent(orderID)
	if intent.HostTrustOrderID != "" || intent.HostTrustServerID != 0 ||
		intent.HostTrustAddress != "" || intent.HostTrustKeyID != 0 {
		t.Fatalf("%s: the job already carries a binding: order=%q server=%d address=%q key=%d",
			when, intent.HostTrustOrderID, intent.HostTrustServerID,
			intent.HostTrustAddress, intent.HostTrustKeyID)
	}
	if !intent.HostTrustGrantedAt.IsZero() {
		t.Fatalf("%s: the job already carries a grant timestamp", when)
	}
	if intent.HostFingerprint != "" {
		t.Fatalf("%s: the job already carries a pinned identity: %q", when, intent.HostFingerprint)
	}
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("%s: policy = %q, want %q", when, intent.HostTrustPolicy,
			models.SetupTrustPolicyFirstContact)
	}

	order, found, err := env.db.GetGigahostOrder(ctx, orderID)
	if err != nil || !found {
		t.Fatalf("%s: read order: found=%v err=%v", when, found, err)
	}
	if order.AssignedIP != "" || order.ServerID != 0 {
		t.Fatalf("%s: the ledger already carries a resource association: address=%q server=%d",
			when, order.AssignedIP, order.ServerID)
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		t.Fatalf("%s: the purchase stamp is %q, want %q", when, order.PurchaseOrigin,
			models.PurchaseOriginPanelPurchase)
	}
}

// countRegisteredServersForProvider counts the panel server rows claiming this provider server.
func (f *authenticTrafficFixture) countRegisteredServersForProvider(t *testing.T) int {
	t.Helper()
	servers, err := f.db.GetAllServers(context.Background())
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	count := 0
	for k := range servers {
		if servers[k].Protocols == nil {
			continue
		}
		if provider, _ := servers[k].Protocols["provider"].(string); provider != "gigahost" {
			continue
		}
		if matchProviderServerID(servers[k].Protocols["provider_server_id"], f.providerServerID) {
			count++
		}
	}
	return count
}

// countEnrollmentsForProvider counts durable enrollment markers for this backend.
func (f *authenticTrafficFixture) countEnrollmentsForProvider(t *testing.T) int {
	t.Helper()
	servers, err := f.db.GetAllServers(context.Background())
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	marks, err := f.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment markers: %v", err)
	}
	count := 0
	for k := range servers {
		if servers[k].Protocols == nil {
			continue
		}
		if provider, _ := servers[k].Protocols["provider"].(string); provider != "gigahost" {
			continue
		}
		if matchProviderServerID(servers[k].Protocols["provider_server_id"], f.providerServerID) &&
			marks[servers[k].ID] {
			count++
		}
	}
	return count
}

// requireNoPurchases asserts no purchase-path call was made.
func (f *authenticTrafficFixture) requireNoPurchases(t *testing.T, when string) {
	t.Helper()
	if n := f.purchaseAttempts.Load(); n != 0 {
		t.Fatalf("%s: the provider received %d purchase-path calls, want 0", when, n)
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
	// One install, one registration, one enrollment, and no purchase anywhere.
	if n := f.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	if n := f.countRegisteredServersForProvider(t); n != 1 {
		t.Fatalf("registered panel servers for this provider server = %d, want exactly 1", n)
	}
	if n := f.countEnrollmentsForProvider(t); n != 0 {
		t.Fatalf("durable enrollment markers for the admitted backend = %d, want 0", n)
	}
	f.requireNoPurchases(t, "after admission")

	// A repeated normal tracker+installer pass must add nothing: no second install, no second
	// registration, no second enrollment, and still no purchase.
	beforeInstalls := f.counters.totalInstalls()
	beforeServers := f.countRegisteredServersForProvider(t)
	if err := f.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("second tracking pass: %v", err)
	}
	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}
	if n := f.counters.totalInstalls(); n != beforeInstalls {
		t.Fatalf("a repeated pass installed again: installs went from %d to %d", beforeInstalls, n)
	}
	if n := f.countRegisteredServersForProvider(t); n != beforeServers {
		t.Fatalf("a repeated pass registered another server: %d, want %d", n, beforeServers)
	}
	if n := f.countEnrollmentsForProvider(t); n != 0 {
		t.Fatalf("a repeated pass left %d durable enrollment markers", n)
	}
	f.requireNoPurchases(t, "after a repeated pass")

	// The backend is still admitted exactly once after the repeat.
	if !authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a repeated pass removed the admitted backend from the pool")
	}
	if got := f.intent(orderID); got.State != models.SetupStateReady {
		t.Fatalf("a repeated pass changed the terminal state to %q", got.State)
	}
	requireNoFingerprintRewrite(t, f.intent(orderID).HostFingerprint, f.pinnedPresented, "after a repeated pass")
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
	f.requireNoPurchases(t, "after a refused admission")
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
	f.requireNoPurchases(t, "after a rejected authentication")
}
