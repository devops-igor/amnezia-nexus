package handlers

// F989-05 (remaining): absence is concluded only from evidence that repeats.
//
// Two consecutive reconciliation passes must agree: each reads its own listing and its
// own account-wide count, and in each the count must equal the listing's size. Only then
// may a repeated omission become a durable absence. A single pass - however consistent
// its own numbers look - can never record one, which is what stops a filtered listing
// that happens to match the account count after an unrelated deletion.
//
// F989-08: the certificate uses only fields the provider documents on a response this
// credential can read - the listing itself and the account summary's service counts.
// No permissions object is read, because the panel's key cannot see one.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// The review's replay: a filtered key's listing matches the account count after an
// unrelated deletion. One pass cannot conclude it, and two passes cannot either, because
// the second pass disagrees. The positive control uses the documented payload exactly as
// the provider documents it - no fixture-only field - and marks a genuinely deleted
// server once two passes agree.
func TestReconcileGigahostInventory_MatchingCountsDoNotCertifyARestrictedKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		detailStatus int
	}{
		{name: "detail answers 403", detailStatus: http.StatusForbidden},
		{name: "detail answers 404", detailStatus: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			active := f.seedServer("Listed", providerProtocols(501))
			hidden := f.seedServer("Working but hidden", providerProtocols(502))

			// Pass one: the key lists 501 only, and the account-wide count happens to be 1
			// because the account's other server (502, which this key cannot see) is not
			// listed and the account's visible member is the only one the summary counts.
			f.provider.set(inventoryJSON(501))
			f.provider.setAccountServers(1)
			f.provider.answerPerServer(502, tc.detailStatus)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("first pass failed: %v", err)
			}
			if f.row(hidden).ProviderAbsent() {
				t.Fatal("a single coincidental equality recorded absence")
			}

			// Pass two: 501 is terminated, so the account holds 502 only and the key sees
			// nothing. The listing (0) and the count (1) disagree, so the carried evidence
			// is cleared and no absence is recorded.
			f.provider.set(inventoryJSON())
			f.provider.setAccountServers(1)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("second pass failed: %v", err)
			}
			if f.row(hidden).ProviderAbsent() {
				t.Fatal("two passes certified a listing that did not enumerate the account")
			}
			if f.row(active).ProviderAbsent() {
				t.Fatal("a listed server was marked absent")
			}

			// A pre-existing observation is untouched through both passes.
			recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			if err := f.db.SetServerProviderAbsence(context.Background(), hidden, recorded); err != nil {
				t.Fatalf("failed to seed the mark: %v", err)
			}
			before := f.row(hidden).ProviderAbsentAt
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("third pass failed: %v", err)
			}
			if got := f.row(hidden).ProviderAbsentAt; got != before {
				t.Fatalf("an uncertified pass rewrote the observation: %q, want %q", got, before)
			}

			// Positive control, documented payload only: the same server is the account's
			// whole enumeration (one server, one listed) for two consecutive passes, so it
			// is recorded absent.
			f.provider.set(inventoryJSON(501))
			f.provider.setAccountServers(1)
			f.confirm(context.Background())
			if !f.row(hidden).ProviderAbsent() {
				t.Fatal("two agreeing documented passes did not record a genuinely absent server")
			}
			if f.row(active).ProviderAbsent() {
				t.Fatal("the control pass marked a listed server absent")
			}
		})
	}
}

// One pass never records absence, two agreeing passes do, and a disagreement between them
// resets the carried evidence.
func TestReconcileGigahostInventory_AbsenceNeedsTwoAgreeingPasses(t *testing.T) {
	f := newInventoryFixture(t)
	gone := f.seedServer("Gone", providerProtocols(502))
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(1)

	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("first pass failed: %v", err)
	}
	if f.row(gone).ProviderAbsent() {
		t.Fatal("a single pass recorded absence")
	}

	// A pass whose own evidence disagrees clears the evidence carried so far.
	f.provider.setAccountServers(2)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	if f.row(gone).ProviderAbsent() {
		t.Fatal("a pass whose counts disagreed recorded absence")
	}

	// Two credible passes in a row then agree, and the absence is recorded on the second.
	f.provider.setAccountServers(1)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("third pass failed: %v", err)
	}
	if f.row(gone).ProviderAbsent() {
		t.Fatal("the first pass after a reset recorded absence")
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("fourth pass failed: %v", err)
	}
	if !f.row(gone).ProviderAbsent() {
		t.Fatal("two consecutive agreeing passes did not record absence")
	}
}

// A pass that lists the server again is presence, and it also clears the carried
// evidence: the next absence needs two fresh passes.
func TestReconcileGigahostInventory_ReappearanceResetsThePassCount(t *testing.T) {
	f := newInventoryFixture(t)
	server := f.seedServer("Server", providerProtocols(501))

	f.provider.set(inventoryJSON())
	f.provider.setAccountServers(0)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("first pass failed: %v", err)
	}
	if f.row(server).ProviderAbsent() {
		t.Fatal("a single pass recorded absence")
	}

	// The server is listed again: it is present, so the streak is void.
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(1)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	if f.row(server).ProviderAbsent() {
		t.Fatal("a listed server was marked absent")
	}

	// Omitted once more: this is a first pass again, so nothing is recorded yet.
	f.provider.set(inventoryJSON())
	f.provider.setAccountServers(0)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("third pass failed: %v", err)
	}
	if f.row(server).ProviderAbsent() {
		t.Fatal("the pass after a reappearance recorded absence on its own")
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("fourth pass failed: %v", err)
	}
	if !f.row(server).ProviderAbsent() {
		t.Fatal("two consecutive omissions after a reappearance did not record absence")
	}
}

// The account summary's count is part of every pass: a pass that cannot read it is not
// credible, records nothing and clears the carried evidence. A server the detail endpoint
// still reports is unparked regardless, because presence needs no certificate.
func TestReconcileGigahostInventory_SummaryOutageKeepsRowsAndStillUnparks(t *testing.T) {
	f := newInventoryFixture(t)
	marked := f.seedServer("Marked", providerProtocols(501))
	returned := f.seedServer("Returned", providerProtocols(502))

	recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := f.db.SetServerProviderAbsence(context.Background(), marked, recorded); err != nil {
		t.Fatalf("failed to seed the mark: %v", err)
	}
	before := f.row(marked).ProviderAbsentAt

	// The summary carries no service counts, so this pass is not credible.
	f.provider.set(inventoryJSON())
	f.provider.setAccountServers(-1)
	f.provider.answerPerServer(502, http.StatusOK)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if got := f.row(marked).ProviderAbsentAt; got != before {
		t.Fatalf("an incredible pass rewrote a mark: %q, want %q", got, before)
	}
	if f.row(returned).ProviderAbsent() {
		t.Fatal("presence did not clear a mark, although it needs no certificate")
	}

	// Control: once the summary is readable and matches the listing, two passes record the
	// absence.
	f.provider.setAccountServers(1)
	f.confirm(context.Background())
	if !f.row(marked).ProviderAbsent() {
		t.Fatal("two credible passes did not record the absent server")
	}
}

// A detail refusal is not an absence observation and does not decide the pass: the
// repeated omission and the counts do. Presence from a detail read still clears a mark.
func TestReconcileGigahostInventory_DetailRefusalDoesNotDecideThePass(t *testing.T) {
	f := newInventoryFixture(t)
	gone := f.seedServer("Gone", providerProtocols(502))
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(1)
	f.provider.answerPerServer(502, http.StatusForbidden)

	f.confirm(context.Background())
	if !f.row(gone).ProviderAbsent() {
		t.Fatal("a confirmed repeated omission was withheld because a detail read was refused")
	}

	// Presence clears it again, and the detail answer is the only evidence for that.
	f.provider.answerPerServer(502, http.StatusOK)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reappearance pass failed: %v", err)
	}
	if f.row(gone).ProviderAbsent() {
		t.Fatal("a server the detail endpoint reports stayed marked absent")
	}
}
