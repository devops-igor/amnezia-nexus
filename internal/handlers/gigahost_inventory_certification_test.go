package handlers

// The owner's decision: the configured Gigahost key sees every running VPS, so ONE
// successful, fully paginated account listing is authoritative.
//
//	"Key has permissions to view all running VPSs if it is not in the list then it is
//	 DELETED"
//
// Consequences pinned here: a known server the listing does not contain is deleted; a
// server it contains has any mark cleared; a listing that fails, is refused, is
// incomplete across its pages or cannot be decoded changes nothing; and a per-server read
// only ever adds presence. The declared limit - a key that does not in fact see every VPS
// makes an unlisted but working server look deleted - is stated in the code and in the
// handover; the panel cannot detect it from the provider, so the account-wide count is
// logged as a diagnostic and never gates.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// One complete listing is enough: the deleted server is marked, the server the same
// listing contains is cleared, and the account the listing was read from is recorded with
// the mark.
func TestReconcileGigahostInventory_OneCompleteListingDecides(t *testing.T) {
	f := newInventoryFixture(t)
	deleted := f.seedServer("Deleted", providerProtocols(502))
	returned := f.seedServer("Returned", providerProtocols(503))

	// The returned server carries an earlier mark; the deleted one does not.
	earlier := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if err := f.db.SetServerProviderAbsence(context.Background(), returned, earlier, ""); err != nil {
		t.Fatalf("failed to seed the mark: %v", err)
	}

	// One listing of the account: it contains 503 and not 502.
	f.provider.set(inventoryJSON(503))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	if !f.row(deleted).ProviderAbsent() {
		t.Fatal("a server the complete listing does not contain was not recorded as deleted")
	}
	if f.row(returned).ProviderAbsent() {
		t.Fatal("a server the listing contains kept its mark")
	}
	// The account the listing was read from is recorded with the mark, so a later key
	// change is visible rather than silent.
	if got := f.row(deleted).ProviderAbsentAccountID; got != fixtureAccount {
		t.Fatalf("recorded account = %q, want %q", got, fixtureAccount)
	}
	if got := f.row(returned).ProviderAbsentAccountID; got != "" {
		t.Fatalf("clearing left an account id behind: %q", got)
	}
}

// A repeated pass with the same answer is idempotent: the observation time survives.
func TestReconcileGigahostInventory_RepeatedPassKeepsTheObservation(t *testing.T) {
	f := newInventoryFixture(t)
	deleted := f.seedServer("Deleted", providerProtocols(502))
	f.provider.set(inventoryJSON(501))

	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("first pass failed: %v", err)
	}
	first := f.row(deleted).ProviderAbsentAt
	if first == "" {
		t.Fatal("the first pass recorded nothing")
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	if got := f.row(deleted).ProviderAbsentAt; got != first {
		t.Fatalf("a repeated pass rewrote the observation: %q, want %q", got, first)
	}
}

// Nothing may be concluded from a listing that is not a complete, decoded answer.
func TestReconcileGigahostInventory_UnusableListingChangesNothing(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(f *inventoryFixture)
	}{
		{name: "listing refused", arrange: func(f *inventoryFixture) { f.provider.failInventory(http.StatusForbidden) }},
		{name: "listing fails", arrange: func(f *inventoryFixture) { f.provider.failInventory(http.StatusInternalServerError) }},
		{name: "listing undecodable", arrange: func(f *inventoryFixture) { f.provider.set("not-json") }},
		{name: "listing enumerates the account incompletely", arrange: func(f *inventoryFixture) {
			f.provider.set(partialInventoryJSON(501))
		}},
		{name: "listing has an unidentifiable entry", arrange: func(f *inventoryFixture) {
			f.provider.set(`{"meta":{"page":1,"total_pages":1,"total":2},"data":[null,{"srv_id":501}]}`)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			marked := f.seedServer("Marked", providerProtocols(502))

			recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			if err := f.db.SetServerProviderAbsence(context.Background(), marked, recorded, fixtureAccount); err != nil {
				t.Fatalf("failed to seed the mark: %v", err)
			}
			before := f.row(marked)

			tc.arrange(f)
			if err := f.reconcile(context.Background()); err == nil {
				t.Fatal("an unusable listing was accepted as an answer")
			}
			after := f.row(marked)
			if after.ProviderAbsentAt != before.ProviderAbsentAt || after.ProviderAbsentAccountID != before.ProviderAbsentAccountID {
				t.Fatalf("an unusable listing rewrote the mark: %+v -> %+v", before, after)
			}

			// Control: the same fixture with a complete listing does change state, so the
			// assertion above is not a pass that never runs.
			f.provider.set(inventoryJSON(502))
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if f.row(marked).ProviderAbsent() {
				t.Fatal("the control pass kept a mark on a server its listing contains")
			}
		})
	}
}

// The account-wide count is a diagnostic, not a gate: a disagreement is logged and the
// authoritative listing still decides.
func TestReconcileGigahostInventory_CountDisagreementDoesNotGate(t *testing.T) {
	f := newInventoryFixture(t)
	deleted := f.seedServer("Deleted", providerProtocols(502))
	f.provider.set(inventoryJSON(501))
	// The summary says the account holds more servers than this listing enumerated. Under
	// the owner's decision the listing still decides; the disagreement is the visible sign
	// that the configured key may not see everything.
	f.provider.setAccountServers(7)

	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if !f.row(deleted).ProviderAbsent() {
		t.Fatal("a count disagreement gated the authoritative listing")
	}
}

// A per-server read adds presence only: it clears a mark and can never set one.
func TestReconcileGigahostInventory_DetailReadIsPresenceOnly(t *testing.T) {
	f := newInventoryFixture(t)
	missing := f.seedServer("Missing", providerProtocols(502))
	listed := f.seedServer("Listed", providerProtocols(501))
	f.provider.set(inventoryJSON(501))
	// The detail endpoint still reports a server the listing omits: it is present, so any
	// mark is cleared even though the listing does not contain it.
	f.provider.answerPerServer(502, http.StatusOK)

	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if f.row(missing).ProviderAbsent() {
		t.Fatal("a server the detail endpoint reports was recorded as deleted")
	}

	// A refusal on the detail read does not make a listed server appear deleted, and a
	// detail read never sets a mark of its own.
	f.provider.answerPerServer(501, http.StatusForbidden)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	if f.row(listed).ProviderAbsent() {
		t.Fatal("a refused detail read marked a listed server as deleted")
	}
}
