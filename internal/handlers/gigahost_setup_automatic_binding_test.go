package handlers

// The no-browser positive: a job the entry created, starting from a purchase record with
// no address, acquires its own scoped authority and completes setup with nothing but
// background passes.
//
// This is the checkpoint's central claim, so it is measured end to end rather than at the
// grant alone. The order row starts exactly as a fresh purchase leaves it - order id,
// purchase stamp, managed credential, and no server id or address - and the provider is
// the only source of those facts. Every step after that is production code:
//
//	entry -> tracker pass (association, grant, pin) -> installer pass (register, install,
//	enable, admit)
//
// No endpoint is called anywhere: no approval, no save, no resume, no credential entry,
// no host confirmation. The router is not even constructed. What the tests assert at the
// effect is that the peer saw zero authentication attempts before the pin became durable,
// and that exactly one registration and one install happened afterwards.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// seedFreshPurchase records an order exactly as the pre-purchase writer leaves it: the
// purchase stamp and the managed credential, and neither the provider server id nor the
// address, because the provider has not reported them yet.
//
// This is the shape the whole checkpoint exists for. A row that already carried the
// address would prove nothing about a browser-independent association.
func (e *installEnv) seedFreshPurchase(orderID string, key managedTestKey) {
	e.t.Helper()
	now := time.Now().UTC()
	if err := e.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, Status: "pending_order",
		PlanID: 7, RegionID: 3,
		PurchaseOrigin:     models.PurchaseOriginPanelPurchase,
		PurchaseRecordedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed fresh purchase %s: %v", orderID, err)
	}
	e.seedOrderCredential(orderID, key)
}

// requireLedgerAssociation asserts the ledger now records exactly the provider's answer,
// and that the write did not touch provenance.
func (e *installEnv) requireLedgerAssociation(orderID string, providerServerID int64, ip string) {
	e.t.Helper()
	order, found, err := e.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		e.t.Fatalf("read order %s: found=%v err=%v", orderID, found, err)
	}
	if order.ServerID != providerServerID {
		e.t.Fatalf("ledger server id = %d, want %d", order.ServerID, providerServerID)
	}
	if order.AssignedIP != ip {
		e.t.Fatalf("ledger address = %q, want %q", order.AssignedIP, ip)
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		e.t.Fatalf("the association write changed purchase provenance to %q", order.PurchaseOrigin)
	}
}

// requireScopedGrant asserts the job now carries a binding for exactly this resource,
// and that it was granted once rather than in pieces.
func (e *installEnv) requireScopedGrant(
	orderID string, providerServerID int64, ip string, providerKeyID int64,
) *models.GigahostSetupIntent {
	e.t.Helper()
	got := e.intent(orderID)
	if got.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		e.t.Fatalf("policy = %q, want %q", got.HostTrustPolicy, models.SetupTrustPolicyFirstContact)
	}
	if got.HostTrustOrderID != orderID || got.HostTrustServerID != providerServerID ||
		got.HostTrustAddress != ip || got.HostTrustKeyID != providerKeyID {
		e.t.Fatalf("grant binds (%q, %d, %q, %d), want (%q, %d, %q, %d)",
			got.HostTrustOrderID, got.HostTrustServerID, got.HostTrustAddress, got.HostTrustKeyID,
			orderID, providerServerID, ip, providerKeyID)
	}
	if got.HostTrustGrantedAt.IsZero() {
		e.t.Fatal("the grant recorded no timestamp")
	}
	return got
}

// TestBrowserlessAutomaticSetupCompletesWithoutABrowser is the decisive positive.
//
// The purchase has no address, the entry creates the job, and two background passes carry
// it to a completed setup. The peer's own counters witness the ordering: no credential
// before the pin, then exactly one registration and one install.
func TestBrowserlessAutomaticSetupCompletesWithoutABrowser(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)
	ctx := context.Background()

	const orderID = "ord_browserless_positive"
	const providerServerID = 9401
	const providerKeyID = 4242
	const ip = "127.0.0.1"

	key := newManagedTestKey(t)
	env.seedFreshPurchase(orderID, key)

	// The provider is the only source of the address and server id. Its deploy status and
	// its server list agree, which is what a real provisioned order reports.
	env.providerServes(orderID, providerServerID, ip)

	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	// The job starts with no address: this is the state a fresh purchase is in.
	intent := env.startAutomatic(orderID, automaticOptions)
	if intent.AssignedIP != "" || intent.HostTrustOrderID != "" {
		t.Fatalf("precondition: the new job already carries address=%q grant=%q",
			intent.AssignedIP, intent.HostTrustOrderID)
	}
	if order, _, _ := env.db.GetGigahostOrder(ctx, orderID); order.AssignedIP != "" || order.ServerID != 0 {
		t.Fatalf("precondition: the ledger already carries address=%q server=%d",
			order.AssignedIP, order.ServerID)
	}

	// One tracker pass: resolves readiness, records the association, grants exactly this
	// job, and pins the identity the peer presents.
	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}

	env.requireLedgerAssociation(orderID, providerServerID, ip)
	pinned := env.requireScopedGrant(orderID, providerServerID, ip, providerKeyID)
	if pinned.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			pinned.State, models.SetupStateReadyForSetup, pinned.Step, pinned.LastError)
	}
	if pinned.HostFingerprint != presented {
		t.Fatalf("pinned identity = %q, want the peer's %q", pinned.HostFingerprint, presented)
	}
	if pinned.HostTrustMode != models.SetupTrustModeFirstContact {
		t.Fatalf("trust provenance = %q, want %q",
			pinned.HostTrustMode, models.SetupTrustModeFirstContact)
	}
	// The ordering claim, measured at the real peer.
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the credential was offered before the identity was durable (%d attempts)", n)
	}

	// One installer pass completes the setup.
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	final := env.requireState(orderID, models.SetupStateReady)
	if final.HostFingerprint != presented {
		t.Fatalf("the install changed the pinned identity to %q", final.HostFingerprint)
	}
	if final.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was lost: policy = %q", final.HostTrustPolicy)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1", enables)
	}
	server := env.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no server row was registered from the provider association")
	}
	if server.Host != ip {
		t.Fatalf("registered server host = %q, want %q", server.Host, ip)
	}
	bound, err := env.db.GetKnownHostFingerprint(ctx, server.ID)
	if err != nil {
		t.Fatalf("read the bound identity: %v", err)
	}
	if bound != presented {
		t.Fatalf("registered known_hosts = %q, want the pinned %q", bound, presented)
	}
	// The peer did authenticate once the pin was durable, so the zero above is a live
	// counter rather than a stuck one.
	if n := peer.auths.Load(); n == 0 {
		t.Fatal("the peer never saw an authentication attempt, so its zero proves nothing")
	}
}

// TestBrowserlessGrantRefusesUnprovenResources covers every way the provider and ledger
// facts can fail to prove ownership. None may grant, none may authenticate, none may
// install - and each must leave the job retryable rather than settled, because a
// purchase that is still provisioning is the normal case.
func TestBrowserlessGrantRefusesUnprovenResources(t *testing.T) {
	cases := []struct {
		name string
		// wantState is where the refusal must leave the row. Most refusals are
		// retryable, so the job stays pending; a provider that attributes the server
		// to a different order is a terminal mismatch the tracker already settles.
		wantState string
		// refusedAtEntry marks a case this panel's own entry refuses, before any
		// authority question exists. Those are the strictest form of the same
		// property, so they are asserted at the entry rather than at the grant.
		refusedAtEntry bool
		// prepare mutates the environment after the standard fresh purchase.
		prepare func(t *testing.T, e *installEnv, orderID string, providerServerID int64, ip string)
	}{
		{
			name:      "the provider attributes the server to another order",
			wantState: models.SetupStateFailed,
			prepare: func(t *testing.T, e *installEnv, _ string, providerServerID int64, ip string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return []gigahost.ServerInfo{{
						ID: providerServerID, OrderID: "ord_somebody_else", IPv4: ip, Status: "ready",
					}}, nil
				}
			},
		},
		{
			name:      "the provider does not attribute the server to any order",
			wantState: models.SetupStatePending,
			prepare: func(t *testing.T, e *installEnv, _ string, providerServerID int64, ip string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return []gigahost.ServerInfo{{ID: providerServerID, IPv4: ip, Status: "ready"}}, nil
				}
			},
		},
		{
			name:      "the provider does not list the server at all",
			wantState: models.SetupStatePending,
			prepare: func(t *testing.T, e *installEnv, _ string, _ int64, _ string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return nil, nil
				}
			},
		},
		{
			name:      "the provider reports no address for the server",
			wantState: models.SetupStatePending,
			prepare: func(t *testing.T, e *installEnv, orderID string, providerServerID int64, _ string) {
				e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
					return []gigahost.ServerInfo{{
						ID: providerServerID, OrderID: orderID, Status: "ready",
					}}, nil
				}
			},
		},
		{
			name:           "the order was not purchased by this panel",
			refusedAtEntry: true,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`UPDATE gigahost_orders SET purchase_origin = '' WHERE order_id = ?`, orderID)
			},
		},
		{
			name:           "the managed credential is gone",
			refusedAtEntry: true,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`UPDATE gigahost_orders SET ssh_key_enc = '', ssh_public_key = '' WHERE order_id = ?`,
					orderID)
			},
		},
		{
			name:      "the credential was never registered at the provider",
			wantState: models.SetupStatePending,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`UPDATE gigahost_orders SET provider_ssh_key_id = 0 WHERE order_id = ?`, orderID)
			},
		},
		{
			name:      "the ledger already records a different server id",
			wantState: models.SetupStatePending,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`UPDATE gigahost_orders SET server_id = 999999 WHERE order_id = ?`, orderID)
			},
		},
		{
			name:      "the ledger already records a different address",
			wantState: models.SetupStatePending,
			prepare: func(t *testing.T, e *installEnv, orderID string, _ int64, _ string) {
				e.executeSQL(`UPDATE gigahost_orders SET assigned_ip = '203.0.113.77' WHERE order_id = ?`, orderID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			env.enableAutomaticSetup(true)
			ctx := context.Background()

			const orderID = "ord_browserless_refused"
			const providerServerID = 9402
			const ip = "127.0.0.1"

			env.seedFreshPurchase(orderID, newManagedTestKey(t))
			env.providerServes(orderID, providerServerID, ip)
			tc.prepare(t, env, orderID, providerServerID, ip)

			hostSigner := newHandshakeSigner(t)
			peer := newChallengePeer(t, hostSigner)
			env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

			// Two of these cases are refused by this panel's own entry, before any
			// authority question can even be asked. That is the strictest form of the
			// same property, and it is asserted where it actually happens.
			if tc.refusedAtEntry {
				if _, created, err := env.h.StartAutomaticGigahostSetup(
					ctx, orderID, automaticOptions); err == nil || created {
					t.Fatalf("the entry accepted an order it must refuse: created=%v err=%v", created, err)
				}
				if _, found, _ := env.db.GetGigahostSetupIntent(ctx, orderID); found {
					t.Fatal("a refused entry created a durable job")
				}
				if n := peer.auths.Load(); n != 0 {
					t.Fatalf("the refused entry authenticated %d times", n)
				}
				if n := env.counters.totalInstalls(); n != 0 {
					t.Fatalf("the refused entry installed %d times", n)
				}
				// The purchase provenance was not manufactured by anything here.
				order, _, orderErr := env.db.GetGigahostOrder(ctx, orderID)
				if orderErr != nil {
					t.Fatalf("read order: %v", orderErr)
				}
				if tc.name == "the order was not purchased by this panel" &&
					order.PurchaseOrigin != models.PurchaseOriginNone {
					t.Fatalf("provenance was manufactured: %q", order.PurchaseOrigin)
				}
				return
			}

			env.startAutomatic(orderID, automaticOptions)

			if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
				t.Fatalf("tracking pass: %v", err)
			}

			got := env.intent(orderID)
			requireNoTrustAuthority(t, got, "a job whose ownership could not be proven")
			if got.State != tc.wantState {
				t.Fatalf("state = %q, want %q (step %q, last error %q)",
					got.State, tc.wantState, got.Step, got.LastError)
			}
			if got.LastError == "" {
				t.Fatal("the refusal recorded no reason")
			}
			// Nothing reached the host, and nothing installed.
			if n := peer.auths.Load(); n != 0 {
				t.Fatalf("a refused grant still authenticated (%d attempts)", n)
			}
			if n := peer.sessions.Load(); n != 0 {
				t.Fatalf("a refused grant opened %d sessions", n)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("a refused grant installed %d times", n)
			}
			if err := env.installer().RunOnce(ctx); err != nil {
				t.Fatalf("install pass: %v", err)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("the installer acted on an ungranted job (%d installs)", n)
			}
			// The purchase provenance was not manufactured by the background pass.
			order, _, err := env.db.GetGigahostOrder(ctx, orderID)
			if err != nil {
				t.Fatalf("read order: %v", err)
			}
			if tc.name == "the order was not purchased by this panel" {
				if order.PurchaseOrigin != models.PurchaseOriginNone {
					t.Fatalf("the background pass manufactured provenance: %q", order.PurchaseOrigin)
				}
			}
		})
	}
}
