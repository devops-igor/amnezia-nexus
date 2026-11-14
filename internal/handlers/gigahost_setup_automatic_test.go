package handlers

// The internal entry that starts an unattended setup job, proved against the real
// database.
//
// This file owns what the entry writes: the default-off refusals, the one job it
// creates, and the three properties a durable job needs - its options and mode survive
// a reopen, a replay cannot change them, and a concurrent call cannot create a second
// job or promote an existing manual, canceled or completed one. What such a job can
// then *do* is a separate claim, measured against the real tracker, installer and SSH
// peer in gigahost_setup_automatic_consumer_test.go.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAutomaticSetupRefusesWithoutAnEnabledPolicy is the default-off deployment.
//
// No policy installed, a policy that answers "no" and a policy that cannot answer
// are three different reasons and one outcome: no job, no authority, no order read.
// The order is seeded as a real purchase so the refusal cannot be an accident of a
// missing row.
func TestAutomaticSetupRefusesWithoutAnEnabledPolicy(t *testing.T) {
	cases := []struct {
		name    string
		install func(*installEnv) *stubAutomationPolicy
		wantErr error
	}{
		{
			name:    "no policy is installed at all",
			install: func(*installEnv) *stubAutomationPolicy { return nil },
			wantErr: ErrAutomaticSetupDisabled,
		},
		{
			name:    "the policy answers no",
			install: func(e *installEnv) *stubAutomationPolicy { return e.enableAutomaticSetup(false) },
			wantErr: ErrAutomaticSetupDisabled,
		},
		{
			name: "the policy cannot be read",
			install: func(e *installEnv) *stubAutomationPolicy {
				policy := e.enableAutomaticSetup(true)
				policy.err = errors.New("settings store is unavailable")
				return policy
			},
			wantErr: ErrAutomaticSetupUnavailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			const orderID = "ord_auto_disabled"
			const providerServerID = 9101
			env.seedAutomaticOrder(orderID, providerServerID, "198.51.100.11")
			policy := tc.install(env)

			intent, created, err := env.h.StartAutomaticGigahostSetup(
				context.Background(), orderID, automaticOptions)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if intent != nil || created {
				t.Fatalf("a refused entry returned a job: intent=%v created=%v", intent, created)
			}
			if policy != nil && policy.callCount() == 0 {
				t.Fatal("the entry did not consult the policy at all")
			}

			// Nothing was written, so there is no job to read - which is also what
			// makes "no authority" true rather than merely asserted.
			if _, found, getErr := env.db.GetGigahostSetupIntent(context.Background(), orderID); getErr != nil || found {
				t.Fatalf("a refused entry created a durable job: found=%v err=%v", found, getErr)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("a refused entry installed %d times", n)
			}
		})
	}
}

// TestAutomaticSetupRecordsOnePendingJobWithoutTrustAuthority is the entry's positive.
//
// The order has no address yet, which is the normal state immediately after a
// purchase. The job must exist anyway - the tracker is what waits for the address -
// and it must carry the options and the automation policy while carrying no grant
// and no identity. Both halves survive a reopen of the same database file.
func TestAutomaticSetupRecordsOnePendingJobWithoutTrustAuthority(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)

	const orderID = "ord_auto_created"
	const providerServerID = 9102
	// No address: provisioning has not reported one yet.
	env.seedAutomaticOrder(orderID, providerServerID, "")

	opts := AutomaticGigahostSetupOptions{
		Protocol: models.ProtocolVLESS, Port: "8443", TLSDomain: "vpn.example.test",
	}
	intent := env.startAutomatic(orderID, opts)

	if intent.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q", intent.State, models.SetupStatePending)
	}
	if intent.Protocol != models.ProtocolVLESS || intent.Port != "8443" ||
		intent.TLSDomain != "vpn.example.test" {
		t.Fatalf("recorded options = %q/%q/%q, want the explicit choice",
			intent.Protocol, intent.Port, intent.TLSDomain)
	}
	if intent.CredentialMode != models.SetupCredentialManaged {
		t.Fatalf("credential mode = %q, want %q", intent.CredentialMode, models.SetupCredentialManaged)
	}
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("host trust policy = %q, want %q", intent.HostTrustPolicy, models.SetupTrustPolicyFirstContact)
	}
	if intent.ApprovedBy != "" {
		t.Fatalf("an unattended job recorded an approver: %q", intent.ApprovedBy)
	}
	requireNoTrustAuthority(t, intent, "the freshly created job")

	if intent.ProviderServerID != providerServerID {
		t.Fatalf("provider server id = %d, want %d", intent.ProviderServerID, providerServerID)
	}
	if intent.AssignedIP != "" {
		t.Fatalf("the job claimed an address %q before the provider reported one", intent.AssignedIP)
	}

	// A second connection to the same file is what "survives a reopen" means here:
	// the row is durable state, not this handler's memory.
	reopened, err := database.Open(env.mainDatabasePath(), testSecretKey)
	if err != nil {
		t.Fatalf("reopen the fixture database: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	stored, found, err := reopened.GetGigahostSetupIntent(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("reopen read: found=%v err=%v", found, err)
	}
	if stored.Protocol != models.ProtocolVLESS || stored.Port != "8443" ||
		stored.TLSDomain != "vpn.example.test" {
		t.Fatalf("options after reopen = %q/%q/%q", stored.Protocol, stored.Port, stored.TLSDomain)
	}
	if stored.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("policy after reopen = %q, want %q",
			stored.HostTrustPolicy, models.SetupTrustPolicyFirstContact)
	}
	if stored.State != models.SetupStatePending {
		t.Fatalf("state after reopen = %q, want %q", stored.State, models.SetupStatePending)
	}
	requireNoTrustAuthority(t, stored, "the reopened job")
}

// requireNoTrustAuthority asserts the row carries a policy and no way to act on it.
//
// The distinction is the whole safety property: the policy is the statement that
// this job may one day trust its own observation, and the binding is the record of
// which resource that was granted for. Without the binding the pin statement
// matches no row, so the policy alone cannot produce an effect.
func requireNoTrustAuthority(t *testing.T, intent *models.GigahostSetupIntent, what string) {
	t.Helper()
	if intent.HostTrustOrderID != "" || intent.HostTrustServerID != 0 ||
		intent.HostTrustAddress != "" || intent.HostTrustKeyID != 0 {
		t.Fatalf("%s carries a binding: order=%q server=%d address=%q key=%d",
			what, intent.HostTrustOrderID, intent.HostTrustServerID,
			intent.HostTrustAddress, intent.HostTrustKeyID)
	}
	if !intent.HostTrustGrantedAt.IsZero() {
		t.Fatalf("%s carries a grant timestamp %s", what, intent.HostTrustGrantedAt)
	}
	if intent.HostFingerprint != "" || intent.HostTrustMode != models.SetupTrustModeNone {
		t.Fatalf("%s trusts an identity: fingerprint=%q mode=%q",
			what, intent.HostFingerprint, intent.HostTrustMode)
	}
}

// TestAutomaticSetupReplayKeepsTheOriginalDecision covers a restart replaying the
// entry and a second call arriving with different options.
//
// One identity, the original options and the original authority: a replay is not an
// opportunity to re-point a job at a different protocol, port or domain, and it is
// not a second job.
func TestAutomaticSetupReplayKeepsTheOriginalDecision(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)

	const orderID = "ord_auto_replay"
	const providerServerID = 9103
	env.seedAutomaticOrder(orderID, providerServerID, "")

	first := env.startAutomatic(orderID, AutomaticGigahostSetupOptions{
		Protocol: models.ProtocolAWG, Port: "51820",
	})

	// A replay that tries to change everything it can express.
	again, created, err := env.h.StartAutomaticGigahostSetup(context.Background(), orderID,
		AutomaticGigahostSetupOptions{
			Protocol: models.ProtocolNaive, Port: "9443", TLSDomain: "other.example.test",
		})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if created {
		t.Fatal("a replay created a second job")
	}
	if again.ID != first.ID || again.OrderID != first.OrderID {
		t.Fatalf("replay returned identity %d/%s, want %d/%s",
			again.ID, again.OrderID, first.ID, first.OrderID)
	}
	if again.Protocol != models.ProtocolAWG || again.Port != "51820" || again.TLSDomain != "" {
		t.Fatalf("a replay rewrote the options to %q/%q/%q",
			again.Protocol, again.Port, again.TLSDomain)
	}
	if again.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("replay changed the policy to %q", again.HostTrustPolicy)
	}
	requireNoTrustAuthority(t, again, "the replayed job")

	list, err := env.db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("durable jobs = %d, want exactly 1", len(list))
	}
}

// TestAutomaticSetupConcurrentCallsKeepOneJob is the concurrent entry.
//
// Two callers that race must leave one row, and both must be answered with it: the
// store's unique index is the durable guard, and the loser reads the winner's row
// instead of reporting a failure or creating a second tracker.
func TestAutomaticSetupConcurrentCallsKeepOneJob(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)

	const orderID = "ord_auto_concurrent"
	const providerServerID = 9104
	env.seedAutomaticOrder(orderID, providerServerID, "")

	const callers = 2
	type outcome struct {
		intent  *models.GigahostSetupIntent
		created bool
		err     error
	}
	results := make([]outcome, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			intent, created, err := env.h.StartAutomaticGigahostSetup(
				context.Background(), orderID, automaticOptions)
			results[idx] = outcome{intent: intent, created: created, err: err}
		}(i)
	}
	wg.Wait()

	createdCount := 0
	for i, got := range results {
		if got.err != nil {
			t.Fatalf("caller %d failed: %v", i, got.err)
		}
		if got.intent == nil {
			t.Fatalf("caller %d got no job", i)
		}
		if got.intent.OrderID != orderID {
			t.Fatalf("caller %d got job for %q, want %q", i, got.intent.OrderID, orderID)
		}
		if got.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("callers that created a job = %d, want exactly 1", createdCount)
	}
	if results[0].intent.ID != results[1].intent.ID {
		t.Fatalf("the two callers saw different jobs: %d and %d",
			results[0].intent.ID, results[1].intent.ID)
	}

	list, err := env.db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("durable jobs after two concurrent calls = %d, want exactly 1", len(list))
	}
	requireNoTrustAuthority(t, &list[0], "the surviving job")
}

// TestAutomaticSetupDoesNotUpgradeOrReviveAnExistingJob covers the three states a
// job can already be in, none of which this entry may change.
//
// A manual approval is the important one: it is a person's decision that a job is
// not unattended, so quiet promotion to automatic authority would be exactly the
// authority escalation the policy is supposed to prevent. A canceled job and a
// completed one are equally final.
func TestAutomaticSetupDoesNotUpgradeOrReviveAnExistingJob(t *testing.T) {
	cases := []struct {
		name  string
		state string
		// prepare moves the seeded manual job into the state this case is about.
		prepare func(t *testing.T, e *installEnv, orderID string)
	}{
		{
			name:    "an existing manual approval",
			state:   models.SetupStatePending,
			prepare: func(*testing.T, *installEnv, string) {},
		},
		{
			name:  "a canceled job",
			state: models.SetupStateCanceled,
			prepare: func(t *testing.T, e *installEnv, orderID string) {
				got, changed, err := e.db.CancelGigahostSetupIntent(context.Background(), orderID, "revoked")
				if err != nil || !changed {
					t.Fatalf("cancel seeded job: changed=%v err=%v", changed, err)
				}
				if got.State != models.SetupStateCanceled {
					t.Fatalf("seeded job is %q after cancel", got.State)
				}
			},
		},
		{
			name:  "a completed job",
			state: models.SetupStateReady,
			prepare: func(t *testing.T, e *installEnv, orderID string) {
				e.executeSQL(`UPDATE gigahost_setup_intents SET state = ? WHERE order_id = ?`,
					models.SetupStateReady, orderID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			const orderID = "ord_auto_existing"
			const providerServerID = 9105
			env.seedAutomaticOrder(orderID, providerServerID, "198.51.100.12")
			// The administrator's approval exists before the policy is even
			// consulted, and it carries no automation policy.
			env.approve(orderID, models.ProtocolAWG, "51820", "")
			tc.prepare(t, env, orderID)
			before := env.intent(orderID)
			if before.HostTrustPolicy != models.SetupTrustPolicyManual {
				t.Fatalf("precondition: the seeded job carries policy %q", before.HostTrustPolicy)
			}

			env.enableAutomaticSetup(true)
			got, created, err := env.h.StartAutomaticGigahostSetup(
				context.Background(), orderID, AutomaticGigahostSetupOptions{
					Protocol: models.ProtocolNaive, Port: "443",
				})
			if err != nil {
				t.Fatalf("entry against an existing job: %v", err)
			}
			if created {
				t.Fatal("the entry created a job although one already existed")
			}
			if got.ID != before.ID {
				t.Fatalf("entry returned job %d, want the existing %d", got.ID, before.ID)
			}
			if got.HostTrustPolicy != models.SetupTrustPolicyManual {
				t.Fatalf("an existing job was promoted to policy %q", got.HostTrustPolicy)
			}
			if got.State != tc.state {
				t.Fatalf("state = %q, want %q", got.State, tc.state)
			}
			if got.Protocol != before.Protocol || got.Port != before.Port {
				t.Fatalf("options changed to %q/%q from %q/%q",
					got.Protocol, got.Port, before.Protocol, before.Port)
			}
			requireNoTrustAuthority(t, got, "the pre-existing job")

			// The pipeline still treats it as the person's job: a tracker pass
			// over it cannot trust an identity, whatever state it is in. That is
			// the property an upgrade would have broken.
			if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
				t.Fatalf("tracking pass: %v", err)
			}
			requireNoTrustAuthority(t, env.intent(orderID), "the job after a tracking pass")
		})
	}
}

// TestAutomaticSetupRefusesUnownedOrdersAndInvalidOptions covers every refusal the
// entry makes once the policy has answered yes.
//
// None of these may create a job, and none may reach an authentication attempt or an
// install: the fixture therefore wires a real loopback peer and asserts its counters
// stay at zero.
func TestAutomaticSetupRefusesUnownedOrdersAndInvalidOptions(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, e *installEnv, orderID string) AutomaticGigahostSetupOptions
	}{
		{
			name: "the order was not purchased by this panel",
			setup: func(t *testing.T, e *installEnv, orderID string) AutomaticGigahostSetupOptions {
				// A plausible row - plan, address, credential and provider answer
				// all present - with the provenance stamp cleared, which is what a
				// mirror-created or imported row looks like.
				e.executeSQL(`UPDATE gigahost_orders SET purchase_origin = '' WHERE order_id = ?`, orderID)
				return automaticOptions
			},
		},
		{
			name: "the order id is a purchase placeholder",
			setup: func(t *testing.T, e *installEnv, orderID string) AutomaticGigahostSetupOptions {
				t.Helper()
				e.seedPurchasedOrder(orderID, 9107, "198.51.100.13")
				e.seedOrderCredential(orderID, newManagedTestKey(t))
				return automaticOptions
			},
		},
		{
			name: "the order has no managed credential",
			setup: func(t *testing.T, e *installEnv, orderID string) AutomaticGigahostSetupOptions {
				t.Helper()
				// The purchase is real and the address exists; only the credential
				// its purchase stored is gone.
				e.executeSQL(`UPDATE gigahost_orders SET ssh_key_enc = '', ssh_public_key = '' WHERE order_id = ?`,
					orderID)
				return automaticOptions
			},
		},
		{
			name: "the protocol cannot be installed by this path",
			setup: func(t *testing.T, e *installEnv, _ string) AutomaticGigahostSetupOptions {
				return AutomaticGigahostSetupOptions{Protocol: "telemt"}
			},
		},
		{
			name: "no protocol was named",
			setup: func(t *testing.T, e *installEnv, _ string) AutomaticGigahostSetupOptions {
				return AutomaticGigahostSetupOptions{Port: "51820"}
			},
		},
		{
			name: "the port is not a port",
			setup: func(t *testing.T, e *installEnv, _ string) AutomaticGigahostSetupOptions {
				return AutomaticGigahostSetupOptions{Protocol: models.ProtocolAWG, Port: "70000"}
			},
		},
	}

	// The two synthetic id cases are separate rows, because the fixture's order id
	// is what the seeded row is keyed by.
	syntheticIDs := []string{"intent_1700000000000000000", "unknown_1700000000000000001"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orderID := "ord_auto_refused"
			if strings.Contains(tc.name, "placeholder") && len(syntheticIDs) > 0 {
				orderID = syntheticIDs[0]
			}
			env := newInstallEnv(t, models.ProtocolAWG)
			env.enableAutomaticSetup(true)
			env.seedAutomaticOrder(orderID, 9106, "198.51.100.13")

			peer := newChallengePeer(t, newHandshakeSigner(t))
			env.realSSHAt(map[string]int{"198.51.100.13": peer.port()}, 2*time.Second)

			opts := tc.setup(t, env, orderID)
			intent, created, err := env.h.StartAutomaticGigahostSetup(context.Background(), orderID, opts)
			if err == nil {
				t.Fatalf("entry accepted an invalid request: intent=%v created=%v", intent, created)
			}
			if intent != nil || created {
				t.Fatalf("a refused entry returned a job: intent=%v created=%v", intent, created)
			}
			if _, found, getErr := env.db.GetGigahostSetupIntent(context.Background(), orderID); getErr != nil || found {
				t.Fatalf("a refused entry created a durable job: found=%v err=%v", found, getErr)
			}

			// Nothing reached the host, and nothing installed.
			if n := peer.auths.Load(); n != 0 {
				t.Fatalf("a refused entry authenticated %d times", n)
			}
			if n := peer.sessions.Load(); n != 0 {
				t.Fatalf("a refused entry opened %d sessions", n)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("a refused entry installed %d times", n)
			}
		})
	}

	// The second synthetic prefix, on its own row.
	t.Run("the order id records an unknown purchase outcome", func(t *testing.T) {
		env := newInstallEnv(t, models.ProtocolAWG)
		env.enableAutomaticSetup(true)
		orderID := syntheticIDs[1]
		env.seedPurchasedOrder(orderID, 9108, "198.51.100.14")
		env.seedOrderCredential(orderID, newManagedTestKey(t))

		if _, _, err := env.h.StartAutomaticGigahostSetup(
			context.Background(), orderID, automaticOptions); err == nil {
			t.Fatal("the entry accepted a placeholder order id")
		}
		if _, found, getErr := env.db.GetGigahostSetupIntent(context.Background(), orderID); getErr != nil || found {
			t.Fatalf("a refused placeholder created a durable job: found=%v err=%v", found, getErr)
		}
	})
}
