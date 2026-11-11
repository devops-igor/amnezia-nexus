package handlers

// Ownership-proof refusals, one case per fact (issue #740).
//
// Automatic first-contact trust lets the panel pin a host identity with no person in the
// loop, so the ownership question is the whole security boundary. This file drives the
// predicate directly instead of only through a tracking pass, because a pass stops at the
// first refusal and would leave the later facts unexercised.
//
// The facts proved here are deliberately not "a plan id and a key exist". Both can be
// present on a row this panel never bought, so the predicate requires the purchase-origin
// stamp the pre-purchase intent writer records, plus the same provider server id, a
// non-empty address and the provider-registered managed key id.
//
// What is not proven here: that a provider issued the address. That is stated on the
// integration proofs, which observe a real SSH peer.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// firstContactIntent builds the job description the predicate reads. Only its own
// fields matter here; the ownership facts live in the ledger.
func firstContactIntent(orderID string, providerServerID int64, ip, policy string) models.GigahostSetupIntent {
	return models.GigahostSetupIntent{
		OrderID:          orderID,
		ProviderServerID: providerServerID,
		AssignedIP:       ip,
		HostTrustPolicy:  policy,
	}
}

// recordOrderRow records a ledger row with exactly the supplied provenance, which is how
// each case states whether the panel bought the order.
func recordOrderRow(
	t *testing.T, env *installEnv, orderID string, providerServerID int64,
	planID int, ip, origin string,
) {
	t.Helper()
	now := time.Now().UTC()
	if err := env.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: gigahost.StatusReady,
		PlanID: planID, AssignedIP: ip,
		PurchaseOrigin: origin, PurchaseRecordedAt: now,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order %s: %v", orderID, err)
	}
}

// recordManagedCredential records a managed credential with the given provider key id.
func recordManagedCredential(t *testing.T, env *installEnv, orderID string, providerKeyID int64) {
	t.Helper()
	key := newManagedTestKey(t)
	if err := env.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText,
		ProviderKeyID: providerKeyID,
	}); err != nil {
		t.Fatalf("seed credential for %s: %v", orderID, err)
	}
}

// listProviderServer makes the provider list exactly one server.
func listProviderServer(env *installEnv, providerServerID int64, orderID, ip string) {
	env.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{{
			ID: providerServerID, OrderID: orderID, IPv4: ip, Status: "ready",
		}}, nil
	}
}

// TestFirstContactBindingProofRefusesAnUnprovenPurchase is the core of this rework.
//
// Each case carries a plausible plan id and a registered provider key id - the two fields
// the previous version treated as evidence - and each must still refuse, because nothing
// proves this panel bought the order. That is exactly the case the earlier checkpoint
// missed.
func TestFirstContactBindingProofRefusesAnUnprovenPurchase(t *testing.T) {
	const (
		orderID          = "ord_bind_proof"
		providerServerID = int64(9101)
		ip               = "198.51.100.10"
	)

	for _, origin := range []string{models.PurchaseOriginNone, "manual_import"} {
		t.Run("origin="+origin, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			recordOrderRow(t, env, orderID, providerServerID, 9, ip, origin)
			recordManagedCredential(t, env, orderID, 4242)

			reason, ok := env.h.firstContactBindingProof(
				context.Background(),
				firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact), orderID)
			if ok {
				t.Fatal("an unproven purchase was accepted as owned")
			}
			if reason == "" {
				t.Fatal("a refused binding recorded no reason")
			}
			// The store still knows the plan and the key; the refusal is about
			// provenance, not about missing data.
			order, found, err := env.db.GetGigahostOrder(context.Background(), orderID)
			if err != nil || !found {
				t.Fatalf("read the ledger row: found=%v err=%v", found, err)
			}
			if order.PlanID == 0 {
				t.Fatal("precondition: the row should carry a plan id")
			}
			if order.PurchaseOrigin == models.PurchaseOriginPanelPurchase {
				t.Fatal("precondition: the row must not claim a panel purchase")
			}
		})
	}
}

// TestFirstContactBindingProofRefusesAMismatchedResource checks each remaining fact on a
// genuinely purchased row, so each refusal is about that fact alone.
func TestFirstContactBindingProofRefusesAMismatchedResource(t *testing.T) {
	const (
		orderID          = "ord_bind_mismatch"
		providerServerID = int64(9102)
		ip               = "198.51.100.11"
	)

	cases := []struct {
		name  string
		setup func(t *testing.T, env *installEnv)
		job   models.GigahostSetupIntent
	}{
		{
			name: "purchased row whose server id does not match the job",
			setup: func(t *testing.T, env *installEnv) {
				recordManagedCredential(t, env, orderID, 4242)
			},
			job: firstContactIntent(orderID, 9103, ip, models.SetupTrustPolicyFirstContact),
		},
		{
			name: "purchased row with no address",
			setup: func(t *testing.T, env *installEnv) {
				env.executeSQL(`UPDATE gigahost_orders SET assigned_ip = '' WHERE order_id = ?`, orderID)
				recordManagedCredential(t, env, orderID, 4242)
			},
			job: firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact),
		},
		{
			name: "purchased row whose address moved",
			setup: func(t *testing.T, env *installEnv) {
				env.executeSQL(`UPDATE gigahost_orders SET assigned_ip = ? WHERE order_id = ?`, "203.0.113.7", orderID)
				recordManagedCredential(t, env, orderID, 4242)
			},
			job: firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact),
		},
		{
			name: "purchased row with no registered managed key",
			setup: func(t *testing.T, env *installEnv) {
				recordManagedCredential(t, env, orderID, 0)
			},
			job: firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact),
		},
		{
			name:  "purchased row with no credential at all",
			setup: func(t *testing.T, env *installEnv) {},
			job:   firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact),
		},
		{
			name: "job records no address",
			setup: func(t *testing.T, env *installEnv) {
				recordManagedCredential(t, env, orderID, 4242)
			},
			job: firstContactIntent(orderID, providerServerID, "", models.SetupTrustPolicyFirstContact),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			recordOrderRow(t, env, orderID, providerServerID, 9, ip, models.PurchaseOriginPanelPurchase)
			tc.setup(t, env)

			if reason, ok := env.h.firstContactBindingProof(context.Background(), tc.job, orderID); ok {
				t.Fatalf("the binding proof accepted %s", tc.name)
			} else if reason == "" {
				t.Fatal("a refused binding recorded no reason")
			}
		})
	}
}

// TestFirstContactBindingProofAcceptsThePositiveControl is the positive: a genuinely
// purchased, exactly-described resource is accepted, so every refusal above is known to be
// about its own fact rather than about the predicate refusing everything.
func TestFirstContactBindingProofAcceptsThePositiveControl(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	const (
		orderID          = "ord_owned"
		providerServerID = int64(9401)
		ip               = "198.51.100.10"
	)
	recordOrderRow(t, env, orderID, providerServerID, 9, ip, models.PurchaseOriginPanelPurchase)
	recordManagedCredential(t, env, orderID, 4242)
	listProviderServer(env, providerServerID, orderID, ip)

	if reason, ok := env.h.firstContactBindingProof(
		context.Background(),
		firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact), orderID); !ok {
		t.Fatalf("a provably owned job was refused: %q", reason)
	}

	// The whole predicate accepts it too, which is what keeps the legitimate positive
	// control a real control rather than a separate code path.
	ok, reason := env.h.firstContactEligible(
		context.Background(), firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact))
	if !ok {
		t.Fatalf("the eligibility predicate refused a provably owned job: %q", reason)
	}
	if reason != "" {
		t.Fatalf("an accepted job recorded a reason: %q", reason)
	}

	// The provider fact is independent: the same job is refused when the provider
	// attributes the server elsewhere, so the positive above is not the ledger alone.
	listProviderServer(env, providerServerID, "ord_other", ip)
	if ok, reason := env.h.firstContactEligible(
		context.Background(), firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact)); ok {
		t.Fatalf("a server listed under another order was accepted: %q", reason)
	}
}

// TestFirstContactBindingProofRefusesAResourceThatMovedAfterTheGrant proves the binding
// lifetime: once authority is granted for one resource, a job whose order, server, address
// or key later describes something else is refused, so the authority cannot drift onto a
// different host.
func TestFirstContactBindingProofRefusesAResourceThatMovedAfterTheGrant(t *testing.T) {
	const (
		orderID          = "ord_drift"
		providerServerID = int64(9501)
		ip               = "198.51.100.11"
	)

	cases := []struct {
		name  string
		moved func(t *testing.T, env *installEnv, granted *models.GigahostSetupIntent)
	}{
		{
			name: "the provider server id changed",
			moved: func(t *testing.T, env *installEnv, granted *models.GigahostSetupIntent) {
				granted.ProviderServerID = 9502
				env.executeSQL(`UPDATE gigahost_orders SET server_id = ? WHERE order_id = ?`, 9502, orderID)
			},
		},
		{
			name: "the address changed",
			moved: func(t *testing.T, env *installEnv, _ *models.GigahostSetupIntent) {
				env.executeSQL(`UPDATE gigahost_orders SET assigned_ip = ? WHERE order_id = ?`, "203.0.113.8", orderID)
			},
		},
		{
			name: "the provider key id changed",
			moved: func(t *testing.T, env *installEnv, _ *models.GigahostSetupIntent) {
				env.executeSQL(`UPDATE gigahost_orders SET provider_ssh_key_id = ? WHERE order_id = ?`, 9999, orderID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()
			recordOrderRow(t, env, orderID, providerServerID, 9, ip, models.PurchaseOriginPanelPurchase)
			recordManagedCredential(t, env, orderID, 4242)
			listProviderServer(env, providerServerID, orderID, ip)
			// The approval is what the authority is granted on, so it must exist first.
			env.approve(orderID, models.ProtocolAWG, "51820", "")

			// Grant on the correct facts first, so the grant really succeeded.
			binding, err := env.db.ProveAutomationBinding(ctx, orderID, providerServerID)
			if err != nil {
				t.Fatalf("prove binding: %v", err)
			}
			granted, changed, err := env.db.SetGigahostSetupAutomationBinding(ctx, binding)
			if err != nil || !changed {
				t.Fatalf("grant: changed=%v err=%v", changed, err)
			}

			tc.moved(t, env, granted)
			reloaded, found, err := env.db.GetGigahostSetupIntent(ctx, orderID)
			if err != nil || !found {
				t.Fatalf("reload intent: found=%v err=%v", found, err)
			}

			if reason, ok := env.h.firstContactBindingProof(ctx, *reloaded, orderID); ok {
				t.Fatalf("a resource that moved after the grant was accepted: %s", tc.name)
			} else if reason == "" {
				t.Fatal("a refused binding recorded no reason")
			}
			// The store agrees independently, so neither layer is the only guard.
			if holds, err := env.db.BindingHolds(ctx, reloaded); err != nil {
				t.Fatalf("BindingHolds: %v", err)
			} else if holds {
				t.Fatalf("the store still reports the binding holds after %s", tc.name)
			}
		})
	}
}

// TestFirstContactEligibleRefusesWithoutPolicyOrDatabase covers the two gates that come
// before any ownership fact is read.
//
// The policy gate is the one that keeps every ordinary approval manual, and the missing
// database gate is what a partially constructed handler looks like. Neither may reach the
// ownership proof, and neither may record a reason on a job that never asked.
func TestFirstContactEligibleRefusesWithoutPolicyOrDatabase(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	intent := firstContactIntent("ord_gate", 9301, "198.51.100.9", models.SetupTrustPolicyFirstContact)

	manual := intent
	manual.HostTrustPolicy = models.SetupTrustPolicyManual
	if ok, reason := env.h.firstContactEligible(context.Background(), manual); ok || reason != "" {
		t.Fatalf("a manual job = (%v, %q), want (false, empty)", ok, reason)
	}

	unknown := intent
	unknown.HostTrustPolicy = "always"
	if ok, reason := env.h.firstContactEligible(context.Background(), unknown); ok || reason != "" {
		t.Fatalf("an unknown policy = (%v, %q), want (false, empty)", ok, reason)
	}

	empty := intent
	empty.OrderID = "  "
	if ok, reason := env.h.firstContactEligible(context.Background(), empty); ok || reason == "" {
		t.Fatalf("a job with no order = (%v, %q), want a recorded refusal", ok, reason)
	}

	for _, synthetic := range []string{"intent_abc", "unknown_def"} {
		job := intent
		job.OrderID = synthetic
		if ok, reason := env.h.firstContactEligible(context.Background(), job); ok || reason == "" {
			t.Fatalf("synthetic order %q = (%v, %q), want a recorded refusal", synthetic, ok, reason)
		}
	}

	noDB := &Handlers{}
	if ok, reason := noDB.firstContactEligible(context.Background(), intent); ok || reason == "" {
		t.Fatalf("a handler with no database = (%v, %q), want a recorded refusal", ok, reason)
	}
}

// TestFirstContactProviderAssociationRequiresAPositiveAddress is the fail-open this rework
// fixed. The previous version treated "the provider listed the server with no address" as a
// match, which is the same as accepting an unconfirmed address on a trust boundary.
func TestFirstContactProviderAssociationRequiresAPositiveAddress(t *testing.T) {
	const (
		orderID          = "ord_assoc"
		providerServerID = int64(9601)
		ip               = "198.51.100.12"
	)

	cases := []struct {
		name       string
		servers    []gigahost.ServerInfo
		wantOK     bool
		wantReason string
	}{
		{
			name:    "listed for this order at this address",
			servers: []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, IPv4: ip}},
			wantOK:  true,
		},
		{
			name:    "listed for this order with no address",
			servers: []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID}},
			wantOK:  false,
			// Missing is not matching: the same refusal as a different address, because
			// the provider did not confirm this exact address either way.
			wantReason: "the provider does not confirm that address for this server",
		},
		{
			name:    "listed at a different address",
			servers: []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, IPv4: "203.0.113.9"}},
			wantOK:  false,
		},
		{
			name:    "listed under a different order",
			servers: []gigahost.ServerInfo{{ID: providerServerID, OrderID: "ord_other", IPv4: ip}},
			wantOK:  false,
		},
		{
			name:    "listed without any order attribution",
			servers: []gigahost.ServerInfo{{ID: providerServerID, IPv4: ip}},
			wantOK:  false,
		},
		{
			name:    "not listed at all",
			servers: nil,
			wantOK:  false,
		},
		{
			name:    "a different server listed",
			servers: []gigahost.ServerInfo{{ID: providerServerID + 1, OrderID: orderID, IPv4: ip}},
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			env.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
				return tc.servers, nil
			}
			reason, ok := env.h.firstContactProviderAssociation(
				context.Background(),
				firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (reason %q)", ok, tc.wantOK, reason)
			}
			if !tc.wantOK && reason == "" {
				t.Fatal("a refused association recorded no reason")
			}
			if tc.wantReason != "" && reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}
