package handlers

// Three ways the account association could still record a working server as
// absent, and the regression for each:
//
//  1. registration borrowed whichever account the panel was configured with,
//     instead of the account the provider says owns the server;
//  2. a filtered inventory (a key limited to some servers) was accepted as a
//     complete account listing, so a server outside the key's visibility looked
//     deleted;
//  3. the provider's documented numeric account identifier was read as "no
//     account", silently skipping the whole reconciliation.

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// Registration must record the account the provider says owns the server. The
// account the panel's key belongs to is not evidence about someone else's server:
// a durable job can outlive a key switch, and stamping the new account onto the old
// server's row is what let the new account's inventory mark it absent.
func TestRegistrationRecordsTheServersOwnAccountNotNullTheConfiguredOne(t *testing.T) {
	cases := []struct {
		name            string
		configured      string
		perServerStatus int
		serverAccount   string
		want            string
	}{
		{
			name:            "the configured key sees the server: the server's own account is recorded",
			configured:      otherAccount,
			perServerStatus: 200,
			serverAccount:   fixtureAccount,
			want:            fixtureAccount,
		},
		{
			name:            "the configured key cannot see the server: the association stays unknown",
			configured:      otherAccount,
			perServerStatus: 403,
			want:            "",
		},
		{
			name:            "control: an account registering its own server records itself",
			configured:      fixtureAccount,
			perServerStatus: 200,
			serverAccount:   fixtureAccount,
			want:            fixtureAccount,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := context.Background()

			client := &mockGigahostClient{
				getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
					return &gigahost.AccountInfo{ID: tc.configured, CustID: tc.configured}, nil
				},
				getServerFn: func(_ context.Context, serverID int64) (*gigahost.ServerInfo, error) {
					if tc.perServerStatus != 200 {
						return nil, fmt.Errorf("%w: server %d", gigahost.ErrUnauthorized, serverID)
					}
					return &gigahost.ServerInfo{ID: serverID, CustID: gigahost.Identity(tc.serverAccount)}, nil
				},
			}

			fingerprint := ssh.FingerprintSHA256(newHandshakeSigner(t).PublicKey())
			req := GigahostDeployRequest{ServerName: "registered", SSHPort: 22, SSHPassword: "fixture-only"}

			// The same composition both registration paths use: ask the provider
			// about the provisioning's own server, then register with that answer.
			accountID := h.gigahostServerAccount(ctx, client, 9001)
			server, err := h.registerDeployServer(ctx, req, nil, 0, 9001, "198.51.100.9", fingerprint, accountID)
			if err != nil {
				t.Fatalf("registration failed: %v", err)
			}

			if server.ProviderAccountID != tc.want {
				t.Fatalf("registered association = %q, want %q (the configured account is %q)",
					server.ProviderAccountID, tc.want, tc.configured)
			}
			stored, err := db.GetServer(ctx, server.ID)
			if err != nil || stored == nil {
				t.Fatalf("failed to read the registered row: %v", err)
			}
			if stored.ProviderAccountID != tc.want {
				t.Fatalf("stored association = %q, want %q", stored.ProviderAccountID, tc.want)
			}
			// The association is never the configured account unless the provider
			// said so for this server.
			if tc.serverAccount == "" && stored.ProviderAccountID == tc.configured {
				t.Fatal("registration stamped the configured account onto a server it did not provision")
			}
		})
	}
}

// A key limited to some servers returns a successful, self-consistent inventory of
// what it can see. The servers outside its visibility are still running, so the
// listing must not become durable absence - and because such a listing is not the
// account's whole answer, the pass records no absence at all while it is narrowed.
func TestReconcileGigahostInventory_RestrictedKeyIsNotEvidenceOfAbsence(t *testing.T) {
	f := newInventoryFixture(t)

	inScope := f.seedServer("In scope", providerProtocols(501))
	filtered := f.seedServer("Present but not listed", providerProtocols(502))
	genuinelyGone := f.seedServer("Actually deleted", providerProtocols(503))

	// The filtered listing: one server, self-consistent pagination and totals. The
	// account summary says the account holds three servers, so this listing is
	// certified as incomplete and may conclude nothing.
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(3)
	f.provider.answerPerServer(502, http.StatusOK)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	if f.row(inScope).ProviderAbsent() {
		t.Fatal("a server the key can see was marked absent")
	}
	if f.row(filtered).ProviderAbsent() {
		t.Fatal("a server outside the listing was marked absent although the detail endpoint reports it")
	}
	if f.row(genuinelyGone).ProviderAbsent() {
		t.Fatal("a listing that does not enumerate the account concluded absence")
	}
	if calls := f.provider.perServerCallCount(); calls != 2 {
		t.Fatalf("per-server reads = %d, want 2 (one per unlisted server)", calls)
	}

	// Control in the same run: the summary now says the account holds one server, which
	// is what the listing enumerated, so the same pass records both omitted servers as
	// genuinely absent. The detail answers are unchanged between the two passes.
	f.provider.setAccountServers(1)
	f.provider.answerPerServer(502, http.StatusNotFound)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("control pass failed: %v", err)
	}
	if !f.row(filtered).ProviderAbsent() || !f.row(genuinelyGone).ProviderAbsent() {
		t.Fatal("the control pass did not record the absent servers, so the refusals above prove nothing")
	}
	if f.row(inScope).ProviderAbsent() {
		t.Fatal("the control pass marked a listed server absent")
	}
}

// The provider documents cust_id as a JSON number on GET /account. Reading that
// shape as "no account" disabled the whole reconciliation silently.
func TestReconcileGigahostInventory_AcceptsNumericAccountIdentifier(t *testing.T) {
	const numericAccount = int64(12345)

	f := newInventoryFixture(t)
	f.provider.setNumericAccount(numericAccount)
	f.account = fmt.Sprintf("%d", numericAccount)
	listed := f.seedServer("Listed", providerProtocols(501))
	gone := f.seedServer("Gone", providerProtocols(502))

	// The documented numeric shape, with no text form supplied.
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(1)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation refused a documented numeric account identifier: %v", err)
	}
	if calls := f.provider.inventoryCallCount(); calls != 1 {
		t.Fatalf("inventory reads = %d, want 1: the pass stopped before asking", calls)
	}
	if !f.row(gone).ProviderAbsent() {
		t.Fatal("a genuinely absent server was not recorded absent under a numeric account identifier")
	}
	if f.row(listed).ProviderAbsent() {
		t.Fatal("a listed server was marked absent under a numeric account identifier")
	}

	// Control: the same account in the text shape produces the same durable state,
	// so the numeric path is not a different, weaker rule.
	text := newInventoryFixture(t)
	text.provider.setAccount(fmt.Sprintf("%d", numericAccount))
	text.account = fmt.Sprintf("%d", numericAccount)
	textListed := text.seedServer("Listed", providerProtocols(501))
	textGone := text.seedServer("Gone", providerProtocols(502))
	text.provider.set(inventoryJSON(501))
	text.provider.setAccountServers(1)
	if err := text.reconcile(context.Background()); err != nil {
		t.Fatalf("control pass failed: %v", err)
	}
	if text.row(textListed).ProviderAbsent() || !text.row(textGone).ProviderAbsent() {
		t.Fatal("the text-shape control recorded a different state than the numeric shape")
	}
	if got := text.row(textGone).ProviderAbsentAt; got == "" {
		t.Fatal("the control recorded no observation time")
	}
}

// The reconciliation must not be silent when the provider answers without a
// usable identifier: the caller has to be able to tell "the provider stated no
// account" from "this account has no servers".
func TestReconcileGigahostInventory_UnreadableIdentifierIsReportedNotSilent(t *testing.T) {
	f := newInventoryFixture(t)
	f.account = fixtureAccount
	f.seedServer("Listed", providerProtocols(501))
	f.provider.setAccountBody(`{"meta":{"status":200},"data":{"cust_id":true}}`)

	err := f.reconcile(context.Background())
	if err == nil {
		t.Fatal("a response whose account identifier cannot be read was treated as an answer")
	}
	if calls := f.provider.inventoryCallCount(); calls != 0 {
		t.Fatalf("inventory reads = %d, want 0: nothing may be concluded without an account", calls)
	}

	// Control within the same fixture: a readable identifier lets the same pass run.
	f.provider.setAccount(fixtureAccount)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("control pass failed: %v", err)
	}
	if calls := f.provider.inventoryCallCount(); calls != 1 {
		t.Fatalf("control inventory reads = %d, want 1", calls)
	}
}
