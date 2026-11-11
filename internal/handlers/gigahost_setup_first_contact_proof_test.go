package handlers

// Ownership-proof refusals, one case per fact (issue #740).
//
// Automatic first-contact trust lets the panel pin a host identity with no person in
// the loop, so the ownership question is the whole security boundary. This file drives
// each refusal fact directly through the production predicate instead of only through a
// tracking pass, because a pass stops at the first refusal and would leave the later
// facts unexercised.
//
// What is proven: every fact on its own is sufficient to refuse. What is not proven
// here: that a provider issued the address - that is stated on the integration proofs.

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

// recordPlacedOrder records a ledger row with the given plan and provider identity.
func recordPlacedOrder(t *testing.T, env *installEnv, orderID string, providerServerID int64, planID int) {
	t.Helper()
	now := time.Now().UTC()
	if err := env.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: gigahost.StatusReady,
		PlanID: planID, AssignedIP: "198.51.100.7", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order %s: %v", orderID, err)
	}
}

// seedCredentialWithProviderID records a managed credential with the given provider key
// id, which is the correlation only the purchase path produces.
func seedCredentialWithProviderID(t *testing.T, env *installEnv, orderID string, providerKeyID int64) {
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

// TestFirstContactOrderProofRefusals proves each ledger fact is sufficient on its own.
func TestFirstContactOrderProofRefusals(t *testing.T) {
	const (
		orderID          = "ord_proof"
		providerServerID = int64(9101)
		ip               = "198.51.100.7"
	)

	cases := []struct {
		name  string
		seed  bool
		plan  int
		order int64 // provider server id recorded on the ledger row
		job   int64 // provider server id the job claims
		jobIP string
		want  string
	}{
		{
			name: "no ledger row", seed: false, plan: 7, order: providerServerID, job: providerServerID, jobIP: ip,
			want: "the order is not recorded in the ledger",
		},
		{
			name: "no contracted plan", seed: true, plan: 0, order: providerServerID, job: providerServerID, jobIP: ip,
			want: "the order records no contracted plan, so the panel did not place it",
		},
		{
			name: "ledger and job disagree about the server", seed: true, plan: 7, order: providerServerID, job: 9102, jobIP: ip,
			want: "the order and the job disagree about the provider server identity",
		},
		{
			name: "job claims no provider server", seed: true, plan: 7, order: 0, job: 0, jobIP: ip,
			want: "the order and the job disagree about the provider server identity",
		},
		{
			name: "job records no address", seed: true, plan: 7, order: providerServerID, job: providerServerID, jobIP: "",
			want: "the job records no address to trust",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			if tc.seed {
				recordPlacedOrder(t, env, orderID, tc.order, tc.plan)
			}
			reason, ok := env.h.firstContactOrderProof(
				context.Background(), firstContactIntent(orderID, tc.job, tc.jobIP, models.SetupTrustPolicyFirstContact), orderID)
			if ok {
				t.Fatalf("the order proof accepted a job it must refuse (%s)", tc.name)
			}
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
		})
	}

	// The positive control: a placed order the job agrees with is accepted.
	env := newInstallEnv(t, models.ProtocolAWG)
	recordPlacedOrder(t, env, orderID, providerServerID, 7)
	reason, ok := env.h.firstContactOrderProof(
		context.Background(), firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact), orderID)
	if !ok {
		t.Fatalf("a placed order was refused: %q", reason)
	}
}

// TestFirstContactCredentialProofRefusals proves the managed-credential facts.
//
// The provider key id is what makes the credential a correlation rather than just
// stored material, so a credential that was never registered at the provider must not
// authorize the panel to trust its own first observation.
func TestFirstContactCredentialProofRefusals(t *testing.T) {
	const orderID = "ord_cred_proof"

	cases := []struct {
		name          string
		seedOrder     bool
		seedCred      bool
		providerKeyID int64
		want          string
	}{
		{
			name: "no credential at all", seedOrder: true, seedCred: false, providerKeyID: 0,
			want: "the order carries no managed credential",
		},
		{
			name: "credential was never registered at the provider", seedOrder: true, seedCred: true, providerKeyID: 0,
			want: "the managed credential was not registered with the provider",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			if tc.seedOrder {
				recordPlacedOrder(t, env, orderID, 9201, 7)
			}
			if tc.seedCred {
				seedCredentialWithProviderID(t, env, orderID, tc.providerKeyID)
			}
			reason, ok := env.h.firstContactCredentialProof(context.Background(), orderID)
			if ok {
				t.Fatalf("the credential proof accepted %s", tc.name)
			}
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
		})
	}

	// The positive control: a credential registered at the provider is accepted.
	env := newInstallEnv(t, models.ProtocolAWG)
	recordPlacedOrder(t, env, orderID, 9201, 7)
	seedCredentialWithProviderID(t, env, orderID, 4242)
	if reason, ok := env.h.firstContactCredentialProof(context.Background(), orderID); !ok {
		t.Fatalf("a registered credential was refused: %q", reason)
	}
}

// TestFirstContactEligibleRefusesWithoutPolicyOrDatabase covers the two gates that come
// before any ownership fact is read.
//
// The policy gate is the one that keeps every ordinary approval manual, and the missing
// database gate is what a partially constructed handler looks like. Neither may reach
// the ownership proof, and neither may record a reason on a job that never asked.
func TestFirstContactEligibleRefusesWithoutPolicyOrDatabase(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	intent := firstContactIntent("ord_gate", 9301, "198.51.100.9", models.SetupTrustPolicyFirstContact)

	// A manual job is refused with no recorded reason: it never asked for automation,
	// so putting a reason in its error field would be a diagnosis nobody needs.
	manual := intent
	manual.HostTrustPolicy = models.SetupTrustPolicyManual
	if ok, reason := env.h.firstContactEligible(context.Background(), manual); ok || reason != "" {
		t.Fatalf("a manual job = (%v, %q), want (false, \"\")", ok, reason)
	}

	// An unknown policy value is not the automation policy either.
	unknown := intent
	unknown.HostTrustPolicy = "always"
	if ok, reason := env.h.firstContactEligible(context.Background(), unknown); ok || reason != "" {
		t.Fatalf("an unknown policy = (%v, %q), want (false, \"\")", ok, reason)
	}

	// A job with no order id cannot be proven, and says so.
	empty := intent
	empty.OrderID = "  "
	if ok, reason := env.h.firstContactEligible(context.Background(), empty); ok || reason == "" {
		t.Fatalf("a job with no order = (%v, %q), want a recorded refusal", ok, reason)
	}

	// A synthetic order id is the ledger's placeholder for a purchase that never
	// resolved, so it can never prove ownership.
	for _, synthetic := range []string{"intent_abc", "unknown_def"} {
		job := intent
		job.OrderID = synthetic
		if ok, reason := env.h.firstContactEligible(context.Background(), job); ok || reason == "" {
			t.Fatalf("synthetic order %q = (%v, %q), want a recorded refusal", synthetic, ok, reason)
		}
	}

	// A handler with no database cannot prove anything.
	noDB := &Handlers{}
	if ok, reason := noDB.firstContactEligible(context.Background(), intent); ok || reason == "" {
		t.Fatalf("a handler with no database = (%v, %q), want a recorded refusal", ok, reason)
	}
}

// TestFirstContactEligibleAcceptsThePositiveControl is the positive ownership answer
// through the whole predicate, so the refusals above are known to be about their own
// fact and not about the predicate refusing everything.
func TestFirstContactEligibleAcceptsThePositiveControl(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	const (
		orderID          = "ord_owned"
		providerServerID = int64(9401)
		ip               = "198.51.100.10"
	)
	recordPlacedOrder(t, env, orderID, providerServerID, 7)
	seedCredentialWithProviderID(t, env, orderID, 4242)
	listProviderServer(env, providerServerID, orderID, ip)

	ok, reason := env.h.firstContactEligible(
		context.Background(), firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact))
	if !ok {
		t.Fatalf("a provably owned job was refused: %q", reason)
	}
	if reason != "" {
		t.Fatalf("an accepted job recorded a reason: %q", reason)
	}

	// A provider list that attributes the server to another order is refused, which
	// also proves the positive answer above depends on the provider fact rather than
	// on the ledger alone.
	listProviderServer(env, providerServerID, "ord_other", ip)
	if ok, reason := env.h.firstContactEligible(
		context.Background(), firstContactIntent(orderID, providerServerID, ip, models.SetupTrustPolicyFirstContact)); ok {
		t.Fatalf("a server listed under another order was accepted: %q", reason)
	}
}
