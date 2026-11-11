package handlers

// Automatic first-contact host trust through the real setup pipeline (issue #740).
//
// These proofs run the production tracker wiring, the production read-only challenge,
// the production install runner and the real SQLite store. The provider, the protocol
// manager and the SSH transport target are the boundaries replaced, which are the same
// boundaries the existing setup fixtures replace for the manual path.
//
// The central claim is an ordering claim, and it is observed at the peer rather than
// asserted about this code: the real loopback SSH server counts authentication attempts
// and session channels, so "no credential was sent before the identity was durable" is
// a measured fact. What is NOT proven here is that a real provider issued the address,
// and that is stated on the tests that depend on the eligibility facts.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	gossh "golang.org/x/crypto/ssh"
)

// sshFingerprintOf renders the canonical fingerprint of a host signer, which is the
// exact string the panel stores and compares.
func sshFingerprintOf(t *testing.T, signer gossh.Signer) string {
	t.Helper()
	return gossh.FingerprintSHA256(signer.PublicKey())
}

// seedFirstContactOrder records everything the ownership proof reads: a placed order
// with a contracted plan, a managed credential registered at the provider, and a
// provider that lists the server for that order at that address.
//
// The plan id is what distinguishes an order this panel placed from a ledger row that
// the deploy-status mirror created for an order the panel never bought.
func (e *installEnv) seedFirstContactOrder(orderID string, providerServerID int64, ip string) {
	e.t.Helper()
	now := time.Now().UTC()
	// The provenance stamp is what makes this row a purchase this panel made. It is
	// the fact the trust predicate requires now, so the fixture records it exactly as
	// the purchase-intent writer does rather than relying on a plan id.
	if err := e.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: gigahost.StatusReady,
		PlanID: 7, RegionID: 3, AssignedIP: ip,
		PurchaseOrigin:     models.PurchaseOriginPanelPurchase,
		PurchaseRecordedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed order %s: %v", orderID, err)
	}
	// The credential must be real key material: the read-only challenge parses it to
	// configure the attempt, which is the same work the install path does. A
	// placeholder would fail at configuration and never reach the handshake, which
	// would make every ordering assertion below vacuous.
	key := newManagedTestKey(e.t)
	if err := e.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID:       orderID,
		PrivateKey:    key.privPEM,
		PublicKey:     key.pubText,
		ProviderKeyID: 4242,
	}); err != nil {
		e.t.Fatalf("seed managed credential for %s: %v", orderID, err)
	}
	e.provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID, Status: gigahost.StatusReady,
			ServerID: providerServerID, AssignedIP: ip,
		}, nil
	}
	e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, IPv4: ip, Status: "ready"}}, nil
	}
}

// grantAutomationTrust gives the approval the internal automation authority, using the
// same single writer the future controller will use. It is never reachable from a
// request, which is what keeps a client from widening a job's authority.
func (e *installEnv) grantAutomationTrust(orderID string, providerServerID int64) {
	e.t.Helper()
	ctx := context.Background()
	binding, err := e.db.ProveAutomationBinding(ctx, orderID, providerServerID)
	if err != nil {
		e.t.Fatalf("prove the binding for %s: %v", orderID, err)
	}
	if _, changed, err := e.db.SetGigahostSetupAutomationBinding(ctx, binding); err != nil || !changed {
		e.t.Fatalf("grant automation trust for %s: changed=%v err=%v", orderID, changed, err)
	}
}

// TestSetupFirstContactTrustPinsBeforeAuthentication is the primary positive.
//
// A job that provably belongs to this panel and carries the automation policy must
// reach the install handoff with the identity the real peer presented, and the peer must
// have seen zero authentication attempts and zero session channels before that identity
// was durable. The ordering is the point: a credential sent before the pin would be the
// whole defect this capability exists to avoid.
func TestSetupFirstContactTrustPinsBeforeAuthentication(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_fc_real_positive"
	const providerServerID = 8101
	key := newManagedTestKey(t)
	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)

	env.seedFirstContactOrder(orderID, providerServerID, "127.0.0.1")
	// The managed key the order was placed with is what the peer accepts; the
	// challenge never offers it, and the assertion below is what proves that.
	if err := env.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText, ProviderKeyID: 4242,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	env.grantAutomationTrust(orderID, providerServerID)
	env.realSSHAt(map[string]int{"127.0.0.1": peer.port()}, 2*time.Second)

	tracker := env.h.NewGigahostSetupTracker()
	if tracker == nil {
		t.Fatal("the tracker was not constructed")
	}
	if err := tracker.RunOnce(ctx); err != nil {
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
	if pinned.HostCandidateFingerprint != "" {
		t.Fatalf("a confirmed-by-panel identity was also left as a candidate: %q",
			pinned.HostCandidateFingerprint)
	}

	// The ordering claim, measured at the peer.
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the trust pass offered a credential before the identity was durable (%d authentication attempts)", n)
	}
	if n := peer.sessions.Load(); n != 0 {
		t.Fatalf("the trust pass opened %d session channels", n)
	}

	// No confirmation endpoint was used: the job reached the handoff on its own.
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("installs during discovery = %d, want 0", n)
	}
}

// TestSetupFirstContactTrustThenInstallsWithThePinnedIdentity continues the positive:
// the identity pinned by the trust pass is the one the install attempt presents and
// verifies, and it registers the server with that same identity.
func TestSetupFirstContactTrustThenInstallsWithThePinnedIdentity(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_fc_real_install"
	const providerServerID = 8102
	key := newManagedTestKey(t)
	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)

	env.seedFirstContactOrder(orderID, providerServerID, "127.0.0.1")
	if err := env.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText, ProviderKeyID: 4242,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	env.grantAutomationTrust(orderID, providerServerID)

	// The install fixture's dialer answers with the fixture identity; the trust pass
	// must therefore pin exactly that, so trust and install agree.
	env.realSSHAt(map[string]int{"127.0.0.1": peer.port()}, 2*time.Second)

	tracker := env.h.NewGigahostSetupTracker()
	if err := tracker.RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	pinned := env.intent(orderID)
	if pinned.HostFingerprint != presented {
		t.Fatalf("pinned identity = %q, want %q", pinned.HostFingerprint, presented)
	}

	// The install pass runs against the peer that presents the pinned identity.
	authsBefore := peer.auths.Load()
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	final := env.intent(orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if final.HostFingerprint != presented {
		t.Fatalf("the install changed the trusted identity to %q", final.HostFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no server row was registered for the pinned provider identity")
	}
	bound, err := env.db.GetKnownHostFingerprint(ctx, server.ID)
	if err != nil {
		t.Fatalf("read the bound identity: %v", err)
	}
	if bound != presented {
		t.Fatalf("registered known_hosts identity = %q, want the pinned %q", bound, presented)
	}
	// Two facts, and both matter. Before the install started the peer had seen no
	// authentication attempt at all, and once the install ran it did see one - which
	// is what proves the counter above is live rather than stuck at zero. Without the
	// second fact every "zero attempts" assertion in this file would be vacuous.
	if authsBefore != 0 {
		t.Fatalf("authentication attempts before the install started = %d, want 0", authsBefore)
	}
	if authsAfter := peer.auths.Load(); authsAfter == 0 {
		t.Fatal("the peer never saw an authentication attempt, so its counter cannot witness the ordering")
	}
}

// TestSetupFirstContactRefusesAChangedKeyAfterThePin is the changed-key negative.
//
// The pinned identity is durable, so a host that now presents a different key must not
// receive a credential: the handshake is refused before authentication and the pin is
// not overwritten.
func TestSetupFirstContactRefusesAChangedKeyAfterThePin(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_fc_real_changed"
	const providerServerID = 8103
	key := newManagedTestKey(t)
	pinnedSigner := newHandshakeSigner(t)
	pinnedPeer := newChallengePeer(t, pinnedSigner)
	pinned := sshFingerprintOf(t, pinnedSigner)

	env.seedFirstContactOrder(orderID, providerServerID, "127.0.0.1")
	if err := env.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText, ProviderKeyID: 4242,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	env.grantAutomationTrust(orderID, providerServerID)
	env.realSSHAt(map[string]int{"127.0.0.1": pinnedPeer.port()}, 2*time.Second)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	if got := env.intent(orderID).HostFingerprint; got != pinned {
		t.Fatalf("precondition: pinned %q, want %q", got, pinned)
	}

	// A different host is now answering at the same address and port. The install
	// attempt must refuse it before authenticating.
	changedSigner := newHandshakeSigner(t)
	changedPeer := newChallengePeer(t, changedSigner)
	env.realSSHAt(map[string]int{"127.0.0.1": changedPeer.port()}, 2*time.Second)

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	if n := changedPeer.auths.Load(); n != 0 {
		t.Fatalf("the changed host was offered a credential (%d authentication attempts)", n)
	}
	if n := changedPeer.sessions.Load(); n != 0 {
		t.Fatalf("the install opened %d session channels against the changed host", n)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("the changed host received %d protocol installations", n)
	}

	after := env.intent(orderID)
	if after.HostFingerprint != pinned {
		t.Fatalf("the pin was rewritten to %q after a changed key", after.HostFingerprint)
	}
	if after.State == models.SetupStateReady {
		t.Fatal("a changed host key was admitted")
	}
	if after.InstallPhaseDone != "" {
		t.Fatalf("an install phase was proven against a refused host: %q", after.InstallPhaseDone)
	}
}

// TestSetupFirstContactRefusesIneligibleOwnership covers the refusal directions that
// must keep the manual path, and each one must also produce zero authentication
// attempts at the peer while merely discovering.
//
// The cases are the ways a row can look like a managed order without being one: a plan
// the panel never contracted, a ledger row the deploy mirror created, a provider that
// attributes the server elsewhere, and an address another panel server already answers
// on.
func TestSetupFirstContactRefusesIneligibleOwnership(t *testing.T) {
	cases := []struct {
		name string
		// wantState is the state the case must stop in. Two of them stop before the
		// trust gate runs at all - an unreadable credential reference and a provider
		// that attributes the server to another order are both earlier, existing
		// fail-closed gates - and that is correct behaviour, not a gap: the point of
		// each case is that no identity was trusted and nothing authenticated.
		wantState string
		// prepare mutates the environment after the standard seed.
		prepare func(t *testing.T, e *installEnv, orderID string, providerServerID int64, ip string)
	}{
		{
			name:      "no purchase provenance",
			wantState: models.SetupStateAwaitingHostConfirm,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				// The row keeps a plausible plan id and a registered key id, and still
				// must not qualify: only the purchase-origin stamp proves the panel
				// bought it. This is the case the previous version got wrong.
				e.executeSQL(`UPDATE gigahost_orders SET purchase_origin = '' WHERE order_id = ?`, orderID)
			},
		},
		{
			name:      "order not in the ledger",
			wantState: models.SetupStateAwaitingCredentials,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`DELETE FROM gigahost_orders WHERE order_id = ?`, orderID)
			},
		},
		{
			name:      "credential was never registered with the provider",
			wantState: models.SetupStateAwaitingHostConfirm,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`UPDATE gigahost_orders SET provider_ssh_key_id = 0 WHERE order_id = ?`, orderID)
			},
		},
		{
			name:      "provider attributes the server to another order",
			wantState: models.SetupStateFailed,
			prepare: func(t *testing.T, e *installEnv, _ string, providerServerID int64, ip string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return []gigahost.ServerInfo{{
						ID: providerServerID, OrderID: "ord_someone_else", IPv4: ip, Status: "ready",
					}}, nil
				}
			},
		},
		{
			name:      "provider does not list the server at all",
			wantState: models.SetupStateAwaitingHostConfirm,
			prepare: func(t *testing.T, e *installEnv, _ string, _ int64, _ string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return nil, nil
				}
			},
		},
		{
			name:      "provider lists the server at a different address",
			wantState: models.SetupStateAwaitingHostConfirm,
			prepare: func(t *testing.T, e *installEnv, _ string, providerServerID int64, _ string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return []gigahost.ServerInfo{{
						ID: providerServerID, OrderID: "ord_fc_ineligible", IPv4: "203.0.113.99", Status: "ready",
					}}, nil
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()

			const orderID = "ord_fc_ineligible"
			const providerServerID = 8201
			const ip = "127.0.0.1"
			hostSigner := newHandshakeSigner(t)
			peer := newChallengePeer(t, hostSigner)

			env.seedFirstContactOrder(orderID, providerServerID, ip)
			if tc.name == "provider lists the server at a different address" {
				// Keep the order id in the fake above accurate for this row.
				env.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return []gigahost.ServerInfo{{
						ID: providerServerID, OrderID: orderID, IPv4: "203.0.113.99", Status: "ready",
					}}, nil
				}
			}
			env.approve(orderID, models.ProtocolAWG, "51820", "")
			env.grantAutomationTrust(orderID, providerServerID)
			tc.prepare(t, env, orderID, providerServerID, ip)
			env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

			if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
				t.Fatalf("tracking pass: %v", err)
			}

			got := env.intent(orderID)
			if got.HostFingerprint != "" || got.HostTrustMode != models.SetupTrustModeNone {
				t.Fatalf("an ineligible job was trusted: identity=%q mode=%q",
					got.HostFingerprint, got.HostTrustMode)
			}
			if got.State != tc.wantState {
				t.Fatalf("state = %q, want %q (step %q, last error %q)",
					got.State, tc.wantState, got.Step, got.LastError)
			}
			// A row that reached the trust gate must hand the observed identity to a
			// person, with a recorded reason. A row stopped by an earlier gate proves
			// the same property in its own way and is not expected to have a candidate.
			if got.State == models.SetupStateAwaitingHostConfirm {
				if got.HostCandidateFingerprint == "" {
					t.Fatal("the manual path did not display the observed identity for confirmation")
				}
				if got.LastError == "" {
					t.Fatal("the manual pause did not record why the prompt was required")
				}
			}
			if n := peer.auths.Load(); n != 0 {
				t.Fatalf("the discovery offered a credential (%d authentication attempts)", n)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("an ineligible job installed %d times", n)
			}
		})
	}
}

// TestSetupFirstContactRefusesAnImportedServerAtTheSameAddress proves address reuse is
// not identity. A panel server already answering on the address the job would dial is
// history this panel did not create, so the job stays a manual decision even when the
// provider agrees about the order.
func TestSetupFirstContactRefusesAnImportedServerAtTheSameAddress(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_fc_address_conflict"
	const providerServerID = 8301
	const ip = "127.0.0.1"
	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)

	env.seedFirstContactOrder(orderID, providerServerID, ip)
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	env.grantAutomationTrust(orderID, providerServerID)

	// An imported server (no provider identity at all) already answers at this
	// address.
	if _, err := env.db.CreateServer(ctx, &models.Server{
		Name: "imported", Host: ip, SSHPort: 22, SSHUser: "root",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed imported server: %v", err)
	}
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}

	got := env.intent(orderID)
	if got.HostFingerprint != "" || got.HostTrustMode != models.SetupTrustModeNone {
		t.Fatalf("an address already owned by an imported server inherited trust: identity=%q mode=%q",
			got.HostFingerprint, got.HostTrustMode)
	}
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want the manual pause", got.State)
	}
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the refused job still authenticated (%d attempts)", n)
	}
}

// TestSetupFirstContactRequiresThePolicyNotTheApprovalBody proves the authority cannot
// be requested. An approval that looks perfectly eligible but carries no automation
// policy must stay manual, and a request field naming the policy must change nothing
// about that.
func TestSetupFirstContactRequiresThePolicyNotTheApprovalBody(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_fc_no_policy"
	const providerServerID = 8401
	const ip = "127.0.0.1"
	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)

	env.seedFirstContactOrder(orderID, providerServerID, ip)
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	// An HTTP approval body that tries to claim the automation policy. The request
	// type has no such field, so this decodes to nothing and must be ignored.
	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval",
		map[string]any{
			"protocol":             models.ProtocolAWG,
			"port":                 "51820",
			"use_order_credential": true,
			"host_trust_policy":    models.SetupTrustPolicyFirstContact,
			"first_contact":        true,
		})
	if code != http.StatusAccepted && code != http.StatusOK {
		t.Fatalf("approval = %d, want an accepted approval (body: %v)", code, body)
	}

	approved := env.intent(orderID)
	if approved.HostTrustPolicy != models.SetupTrustPolicyManual {
		t.Fatalf("an HTTP approval granted trust policy %q", approved.HostTrustPolicy)
	}

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	got := env.intent(orderID)
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want the manual pause", got.State)
	}
	if got.HostFingerprint != "" || got.HostTrustMode != models.SetupTrustModeNone {
		t.Fatalf("a request-derived policy trusted the host: identity=%q mode=%q",
			got.HostFingerprint, got.HostTrustMode)
	}
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the manual job authenticated during discovery (%d attempts)", n)
	}

	// The manual positive control still works on the same job: the displayed
	// identity is confirmable and the job then reaches the handoff.
	if got.HostCandidateFingerprint == "" {
		t.Fatal("the manual path displayed no identity to confirm")
	}
	code, body = doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": got.HostCandidateFingerprint})
	if code != http.StatusOK {
		t.Fatalf("manual confirmation = %d, want 200 (body: %v)", code, body)
	}
	if confirmed := env.intent(orderID); confirmed.HostTrustMode != models.SetupTrustModeConfirmed {
		t.Fatalf("a manual confirmation recorded provenance %q, want %q",
			confirmed.HostTrustMode, models.SetupTrustModeConfirmed)
	}
}

// TestSetupFirstContactPinSurvivesTheInstallJournal is the stale-writer proof at the
// integration level: after the pin, ordinary tracker and installer passes must not
// replace it, and the refusal of a competing identity must leave the journal alone.
func TestSetupFirstContactPinSurvivesTheInstallJournal(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_fc_stale_writers"
	const providerServerID = 8501
	key := newManagedTestKey(t)
	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	pinned := sshFingerprintOf(t, hostSigner)

	env.seedFirstContactOrder(orderID, providerServerID, "127.0.0.1")
	if err := env.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText, ProviderKeyID: 4242,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	env.grantAutomationTrust(orderID, providerServerID)
	env.realSSHAt(map[string]int{"127.0.0.1": peer.port()}, 2*time.Second)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	if got := env.intent(orderID).HostFingerprint; got != pinned {
		t.Fatalf("precondition: pinned %q, want %q", got, pinned)
	}

	// Several more passes of both workers: none of them may rewrite the pin.
	for i := 0; i < 3; i++ {
		if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
			t.Fatalf("tracking pass %d: %v", i, err)
		}
		if err := env.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
			t.Fatalf("install pass %d: %v", i, err)
		}
		got := env.intent(orderID)
		if got.HostFingerprint != pinned {
			t.Fatalf("pass %d rewrote the pinned identity to %q", i, got.HostFingerprint)
		}
		if got.HostTrustMode != models.SetupTrustModeFirstContact {
			t.Fatalf("pass %d changed the trust provenance to %q", i, got.HostTrustMode)
		}
	}

	// The job completed through the pinned identity, exactly once.
	final := env.intent(orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("final state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}
	if final.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("proven install phase = %q, want %q", final.InstallPhaseDone, models.SetupPhaseEnabled)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
}
