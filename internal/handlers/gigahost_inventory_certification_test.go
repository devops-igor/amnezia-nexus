package handlers

// F989-05 (remainder): the certified-complete inventory answer is the only thing that
// can conclude a server absent.
//
// The review's replay: an active server with a known owner, a key for the same account
// with a server filter, a valid self-consistent listing that omits it, and a generic
// detail 404. R11 still wrote the durable mark for that row. It must now stay
// untouched - and a genuinely complete inventory must still mark a server that is
// gone, which is the live control in the same run.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// The replay: nothing here proves the listing covers the account, so nothing may be
// concluded. The row keeps its state byte for byte, including its timestamp.
func TestReconcileGigahostInventory_DetailRefusalReplayLeavesServerUntouched(t *testing.T) {
	f := newInventoryFixture(t)
	active := f.seedServer("Active", providerProtocols(501))
	hidden := f.seedServer("Outside this key", providerProtocols(502))

	// The key is filtered: the listing is valid and self-consistent, and it omits 502.
	// The account summary says the account holds two servers, so the listing is proven
	// incomplete.
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(2)
	// The detail route answers a generic 404 for the omitted server, which is exactly
	// the evidence R11 accepted.
	f.provider.answerPerServer(502, http.StatusNotFound)

	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if f.row(hidden).ProviderAbsent() {
		t.Fatal("a generic detail 404 concluded absence for a server the listing did not cover")
	}
	if f.row(active).ProviderAbsent() {
		t.Fatal("a listed server was marked absent")
	}

	// The row's durable state is untouched, not merely unmarked: a previously recorded
	// observation keeps its exact timestamp through the same replay.
	recorded := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if err := f.db.SetServerProviderAbsence(context.Background(), hidden, recorded); err != nil {
		t.Fatalf("failed to seed the mark: %v", err)
	}
	before := f.row(hidden).ProviderAbsentAt
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("second reconciliation pass failed: %v", err)
	}
	if got := f.row(hidden).ProviderAbsentAt; got != before {
		t.Fatalf("an uncertified listing rewrote the observation: %q, want %q", got, before)
	}

	// Live control in the same run: the same pass, with an inventory certified as the
	// account's whole answer, records the genuinely absent server.
	f.provider.setAccountServers(1)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("control pass failed: %v", err)
	}
	if !f.row(hidden).ProviderAbsent() {
		t.Fatal("a certified-complete inventory did not record a genuinely absent server, so the refusals above prove nothing")
	}
	if f.row(active).ProviderAbsent() {
		t.Fatal("the control pass marked a listed server absent")
	}
}

// Certification is the account summary's count against the listing's size, and only
// equality certifies anything. Everything else keeps the prior observation.
func TestReconcileGigahostInventory_CertificationDecidesAbsence(t *testing.T) {
	cases := []struct {
		name        string
		listed      string
		accountSize int
		wantAbsent  bool
	}{
		{name: "listed equals the account count: certified", listed: inventoryJSON(501), accountSize: 1, wantAbsent: true},
		{name: "listing smaller than the account: filtered", listed: inventoryJSON(501), accountSize: 2, wantAbsent: false},
		{name: "listing larger than the account: contradictory", listed: inventoryJSON(501, 502), accountSize: 1, wantAbsent: false},
		{name: "empty account with an empty listing: certified", listed: inventoryJSON(), accountSize: 0, wantAbsent: true},
		{name: "no service counts at all: nothing attested", listed: inventoryJSON(501), accountSize: -1, wantAbsent: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			gone := f.seedServer("Gone", providerProtocols(502))
			f.provider.set(tc.listed)
			f.provider.setAccountServers(tc.accountSize)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("reconciliation pass failed: %v", err)
			}
			if got := f.row(gone).ProviderAbsent(); got != tc.wantAbsent {
				t.Fatalf("absence = %v, want %v (listed %s, account %d)", got, tc.wantAbsent, tc.listed, tc.accountSize)
			}
		})
	}
}

// An unreadable account summary certifies nothing, so no absence is recorded - while a
// server the detail endpoint still reports is unparked anyway, because presence needs
// no certification.
func TestReconcileGigahostInventory_SummaryOutageKeepsRowsAndStillUnparks(t *testing.T) {
	f := newInventoryFixture(t)
	marked := f.seedServer("Marked", providerProtocols(501))
	returned := f.seedServer("Returned", providerProtocols(502))

	recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := f.db.SetServerProviderAbsence(context.Background(), marked, recorded); err != nil {
		t.Fatalf("failed to seed the mark: %v", err)
	}
	before := f.row(marked).ProviderAbsentAt

	// The listing omits 501 (which would be absent if the summary certified coverage)
	// and 502 comes back from the detail endpoint.
	f.provider.set(inventoryJSON())
	f.provider.setAccountServers(-1) // the summary carries no service counts
	f.provider.answerPerServer(502, http.StatusOK)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if got := f.row(marked).ProviderAbsentAt; got != before {
		t.Fatalf("an uncertified pass rewrote a mark: %q, want %q", got, before)
	}
	if f.row(returned).ProviderAbsent() {
		t.Fatal("presence did not clear a mark, although it needs no certification")
	}

	// Control: once the summary reports the account's size and it matches, the same
	// omission records absence.
	f.provider.setAccountServers(1)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("control pass failed: %v", err)
	}
	if !f.row(marked).ProviderAbsent() {
		t.Fatal("the control pass did not record the absent server")
	}
}
