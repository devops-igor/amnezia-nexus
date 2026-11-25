package handlers

// A successful inventory read is evidence about one account only: the account
// that answered it. These cases pin the account scope of the provider-absence
// fact on the real handler, the real SQLite store and the shipping provider
// client against a controlled local fixture.
//
// The failure they exist to prevent: pointing the panel at a second Gigahost
// account marks the first account's operational servers absent, and the panel
// then stops contacting hosts that are running perfectly well.

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// The account association decides whether a read may judge a row, so the honest
// scenario has rows of two accounts plus a row whose association is unknown, all
// in one store and all judged in the same run.
func TestReconcileGigahostInventory_ScopesAbsenceToTheAnsweringAccount(t *testing.T) {
	f := newInventoryFixture(t)

	f.account = fixtureAccount
	northListed := f.seedServer("North listed", providerProtocols(501))
	northGone := f.seedServer("North gone", providerProtocols(502))

	f.account = otherAccount
	southListed := f.seedServer("South listed", providerProtocols(601))
	southGone := f.seedServer("South gone", providerProtocols(603))

	// A row from before the association existed: nobody recorded which account
	// owns it, so no read may judge it.
	f.account = ""
	legacy := f.seedServer("Legacy", providerProtocols(701))

	// The panel points at the north account, whose inventory lists 501 only.
	f.provider.setAccount(fixtureAccount)
	f.provider.set(inventoryJSON(501))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	// Same account: a genuinely absent row is marked, the listed row is not.
	if !f.row(northGone).ProviderAbsent() {
		t.Fatal("the answering account's own missing server was not recorded absent")
	}
	if f.row(northListed).ProviderAbsent() {
		t.Fatal("the answering account's listed server was marked absent")
	}
	// Another account's rows, and a row of unknown account, are untouched: this
	// read says nothing about them.
	for _, id := range []int64{southListed, southGone, legacy} {
		if f.row(id).ProviderAbsent() {
			t.Fatalf("server %d was marked absent by a read from another account", id)
		}
	}

	// Now the operator swaps the API key to the south account, whose inventory
	// lists 601 only. This is the reported defect: the north account's rows are
	// not in this answer at all.
	f.provider.setAccount(otherAccount)
	f.provider.set(inventoryJSON(601))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass after the account swap failed: %v", err)
	}
	if f.row(northListed).ProviderAbsent() {
		t.Fatal("swapping the provider account marked the first account's operational server absent")
	}
	if !f.row(northGone).ProviderAbsent() {
		t.Fatal("another account's read cleared a state it cannot speak for")
	}
	if f.row(legacy).ProviderAbsent() {
		t.Fatal("a row of unknown account was marked absent by a read")
	}
	// Live control in the same run: the account that answered still marks its
	// own genuinely absent row, so "nothing changed for the other account" cannot
	// mean "the pass never writes".
	if !f.row(southGone).ProviderAbsent() {
		t.Fatal("the answering account's own missing server was not recorded absent")
	}
	if f.row(southListed).ProviderAbsent() {
		t.Fatal("the answering account's listed server was marked absent")
	}

	// The scope is durable, not an in-memory detail.
	f.restart()
	if f.row(northListed).ProviderAbsent() {
		t.Fatal("the first account's listed server is absent after a restart")
	}
	if !f.row(northGone).ProviderAbsent() || !f.row(southGone).ProviderAbsent() {
		t.Fatal("a recorded absence did not survive a restart")
	}
	if f.row(legacy).ProviderAbsent() {
		t.Fatal("the unknown-account row is absent after a restart")
	}
}

// An inventory read that cannot be attributed to an account is not evidence
// about any row: the pass refuses it whole and changes nothing.
func TestReconcileGigahostInventory_UnattributableAccountChangesNothing(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(f *inventoryFixture)
	}{
		{name: "account read fails", arrange: func(f *inventoryFixture) { f.provider.failAccount(500) }},
		{name: "account read never answers", arrange: func(f *inventoryFixture) { f.provider.stallAccount() }},
		{name: "account answer names no account", arrange: func(f *inventoryFixture) { f.provider.hideAccountIdentity() }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			listed := f.seedServer("Listed", providerProtocols(501))
			gone := f.seedServer("Recorded absent", providerProtocols(502))

			recorded := time.Now().UTC().Add(-time.Hour)
			if err := f.db.SetServerProviderAbsence(context.Background(), gone, recorded); err != nil {
				t.Fatalf("failed to seed the recorded absence: %v", err)
			}
			before := f.row(gone).ProviderAbsentAt

			tc.arrange(f)
			// The provider would answer a complete inventory that omits 502. If the
			// pass applied it without an account, it would either rewrite the
			// absence or mark the listed row absent.
			f.provider.set(inventoryJSON(501))
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if err := f.reconcile(ctx); err == nil {
				t.Fatal("an inventory read with no attributable account was accepted as an answer")
			}

			if got := f.row(gone).ProviderAbsentAt; got != before {
				t.Fatalf("an unattributable read changed the recorded absence: %q, want %q", got, before)
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("an unattributable read marked a listed server absent")
			}
			if calls := f.provider.inventoryCallCount(); calls != 0 {
				t.Fatalf("the inventory was read %d time(s) without an account to attribute it to", calls)
			}

			// Control: the same fixture with the account identity reported does
			// change state, so the assertions above are not a pass that never runs.
			f.provider.setAccount(fixtureAccount)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("the control pass marked a listed server absent")
			}
			if got := f.row(gone).ProviderAbsentAt; got != before {
				t.Fatalf("the control pass rewrote an already-correct absence: %q, want %q", got, before)
			}
			missing := f.seedServer("Missing", providerProtocols(599))
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if !f.row(missing).ProviderAbsent() {
				t.Fatal("the control pass did not record an absent server, so the refusals above prove nothing")
			}
		})
	}
}

// A row whose association is unknown keeps its state in both directions: it is
// never marked absent, and a read that lists it does not clear a state either,
// because clearing would require establishing the association, which nothing may
// infer.
func TestReconcileGigahostInventory_UnknownAccountPreservesStateBothWays(t *testing.T) {
	f := newInventoryFixture(t)
	f.account = ""
	unlisted := f.seedServer("Legacy unlisted", providerProtocols(701))
	listed := f.seedServer("Legacy listed", providerProtocols(702))
	// The control row is registered by the account the provider reports, so the
	// same pass must judge it.
	f.account = fixtureAccount
	control := f.seedServer("Same-account control", providerProtocols(899))

	// A previous build had marked the listed legacy row absent; nothing in this
	// round may guess that it belongs to the answering account.
	recorded := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	if err := f.db.SetServerProviderAbsence(context.Background(), listed, mustParseTime(t, recorded)); err != nil {
		t.Fatalf("failed to seed the recorded absence: %v", err)
	}

	f.provider.set(inventoryJSON(702))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	if f.row(unlisted).ProviderAbsent() {
		t.Fatal("a row of unknown account was marked absent")
	}
	if got := f.row(listed).ProviderAbsentAt; got != recorded {
		t.Fatalf("a read cleared a state it cannot speak for: %q, want %q", got, recorded)
	}
	// The control row carries the answering account, so the same pass judges it.
	if !f.row(control).ProviderAbsent() {
		t.Fatal("the same-account control row was not judged, so the preservation above proves nothing")
	}
}

// The account association is stored as the provider-issued identifier, and the
// credential the client was built with is nowhere in the store: it cannot be read
// back to replay a request.
func TestProviderAccountAssociationStoresNoCredential(t *testing.T) {
	f := newInventoryFixture(t)
	f.account = otherAccount
	id := f.seedServer("Registered by a deployment", providerProtocols(901))

	row := f.row(id)
	if row.ProviderAccountID != otherAccount {
		t.Fatalf("stored account association = %q, want the provider-issued %q", row.ProviderAccountID, otherAccount)
	}
	if !row.ProviderAccountKnown() {
		t.Fatal("a row registered under an account reports its association as unknown")
	}
	if row.ProviderAccountID == testInventoryAPIKey {
		t.Fatal("the stored association is the API key")
	}

	// The fixture's key exists only in the client the handler holds. Scanning the
	// database file proves the row (and everything beside it) carries no form of
	// it that could be replayed.
	raw, err := os.ReadFile(f.dbPath)
	if err != nil {
		t.Fatalf("failed to read the store file: %v", err)
	}
	if bytes.Contains(raw, []byte(testInventoryAPIKey)) {
		t.Fatal("the provider API key is present in the store")
	}
	if bytes.Contains(raw, []byte("X-Gigahost-API-Key")) {
		t.Fatal("a provider request header is present in the store")
	}

	// A row the provider never provisioned keeps an unknown association rather
	// than inheriting a neighbour's.
	operator := f.seedServer("Operator", map[string]any{"awg": map[string]any{"installed": true}})
	if got := f.row(operator).ProviderAccountID; got != "" {
		t.Fatalf("an operator-added row was given the account association %q", got)
	}
	if f.row(operator).ProviderAccountKnown() {
		t.Fatal("an operator-added row claims a provider account")
	}
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("bad fixture timestamp %q: %v", value, err)
	}
	return parsed
}
