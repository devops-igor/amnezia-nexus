package handlers

// The one-time account association, proved on the real handler, the real SQLite
// store and the shipping provider client against a controlled local fixture.
//
// The property under test is the one an existing deployment needs: a row that
// records no hosting account is skipped by every inventory read - an empty account
// is unknown, never a match - and after the administrator's one-time association the
// ordinary reconciliation judges it unchanged. Each assertion reads the store back,
// so it is about durable state rather than about a response body.
//
// The negative half is the important one, and each case is a way to get this wrong:
//
//	1. a row the provider still lists is associated and is NOT marked absent;
//	2. a row the provider no longer has is associated only under the administrator's
//	   own confirmation, and is neither associated nor marked without it;
//	3. a row the provider refuses to show, or answers about without naming an
//	   account, stays unknown and stays out of every existence decision;
//	4. a row that already records an account is never rewritten, whichever account
//	   the configured key belongs to;
//	5. a second run associates nothing further and says so.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAssociationReconcilesLegacyRows is the compatibility proof the report asks
// for: a legacy row is skipped before the action, reconciled after it, and a legacy
// server the provider has genuinely deleted is marked absent by the next complete
// listing.
func TestAssociationReconcilesLegacyRows(t *testing.T) {
	f := newInventoryFixture(t)
	live := f.seedLegacyServer("Legacy-live", 601)
	gone := f.seedLegacyServer("Legacy-deleted", 602)
	bound := f.seedServer("Registered-with-account", providerProtocols(603))

	// The provider enumerates the account and holds 601 (the legacy row that is
	// still alive), 602 is gone, 603 was registered with its account.
	f.provider.set(inventoryJSON(601, 603))
	for _, id := range []int64{601, 602, 603} {
		f.provider.answerPerServer(id, http.StatusOK)
	}
	f.provider.answerPerServer(602, http.StatusNotFound)

	// Before the action both legacy rows record no account, so the pass judges
	// neither of them: nothing is marked.
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile before the association: %v", err)
	}
	for _, id := range []int64{live, gone} {
		if row := f.row(id); row.ProviderAbsent() {
			t.Fatalf("server %d was marked absent before it recorded an account; the empty account must never match", id)
		}
	}

	preview := f.associationPreviewCall()
	if preview.Candidates != 2 || preview.Attributable != 1 || preview.Unlisted != 1 || preview.Unattributed != 0 {
		t.Fatalf("preview = %+v, want 2 candidates, 1 attributable, 1 unlisted, 0 unattributed", preview)
	}
	if preview.AlreadyBound != 1 {
		t.Fatalf("preview reports %d already-bound rows, want 1 (the row registered with its account)", preview.AlreadyBound)
	}

	result := f.associationActionCall(true)
	if result.Associated != preview.Attributable+preview.Unlisted {
		t.Fatalf("the action associated %d rows, but the preview said %d would be associated",
			result.Associated, preview.Attributable+preview.Unlisted)
	}
	if result.Unlisted != 1 {
		t.Fatalf("the action reports %d unlisted rows, want 1", result.Unlisted)
	}

	for _, id := range []int64{live, gone} {
		row := f.row(id)
		if !row.ProviderAccountKnown() {
			t.Fatalf("server %d still records no account after the association", id)
		}
		if row.ProviderAccountID != fixtureAccount {
			t.Fatalf("server %d was associated with %q, want %q", id, row.ProviderAccountID, fixtureAccount)
		}
		if row.ProviderAbsent() {
			// The action records an association, not an existence verdict. The
			// deletion the administrator confirmed is applied by the next
			// inventory read, which is the only writer of that column.
			t.Fatalf("server %d was marked absent by the association itself", id)
		}
		if row.ProviderAbsentAccountID != "" {
			t.Fatalf("server %d carries an absence observation account %q; the association must set none", id, row.ProviderAbsentAccountID)
		}
	}

	// The ordinary reconciliation now applies unchanged: the legacy row the
	// provider still lists keeps its state, and the one it no longer has is marked
	// by this complete listing.
	f.provider.set(inventoryJSON(601, 603))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile after the association: %v", err)
	}
	if row := f.row(live); row.ProviderAbsent() {
		t.Fatal("a legacy server the provider still lists was marked absent after the association")
	}
	if row := f.row(gone); !row.ProviderAbsent() {
		t.Fatal("a genuinely deleted legacy server was not marked absent by the listing after the association")
	}
	if row := f.row(bound); row.ProviderAccountID != fixtureAccount {
		t.Fatalf("the row registered with its own account was rewritten to %q", row.ProviderAccountID)
	}

	// And when the provider deletes the other one, the same pass marks it: the
	// association did not freeze the row's state.
	f.provider.set(inventoryJSON(603))
	f.provider.answerPerServer(601, http.StatusNotFound)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile after the provider deleted the remaining legacy server: %v", err)
	}
	if row := f.row(live); !row.ProviderAbsent() {
		t.Fatal("a legacy server the provider stopped listing was not marked absent")
	}
}

// TestAssociationNeedsTheAdministratorsConfirmationForUnlistedRows proves the two
// categories stay separate: without the confirmation the provider-named row is
// associated and the deleted one is not, and the deleted row causes no mark.
func TestAssociationNeedsTheAdministratorsConfirmationForUnlistedRows(t *testing.T) {
	f := newInventoryFixture(t)
	live := f.seedLegacyServer("Legacy-live", 611)
	gone := f.seedLegacyServer("Legacy-deleted", 612)
	f.provider.set(inventoryJSON(611))
	f.provider.answerPerServer(611, http.StatusOK)
	f.provider.answerPerServer(612, http.StatusNotFound)

	result := f.associationActionCall(false)
	if result.Associated != 1 || result.Unlisted != 0 {
		t.Fatalf("the action without the confirmation associated %d rows (%d unlisted), want 1 and 0",
			result.Associated, result.Unlisted)
	}
	if row := f.row(live); !row.ProviderAccountKnown() {
		t.Fatal("the row the provider still lists was not associated")
	}
	if row := f.row(gone); row.ProviderAccountKnown() {
		t.Fatal("a row the account no longer lists was associated without the administrator's confirmation")
	}
	if row := f.row(gone); row.ProviderAbsent() {
		t.Fatal("an unassociated row was marked absent")
	}

	// The confirmation then covers exactly that row, and only through the next
	// inventory read does it become an absence observation.
	second := f.associationActionCall(true)
	if second.Associated != 1 || second.Unlisted != 1 {
		t.Fatalf("the confirmed action associated %d rows (%d unlisted), want 1 and 1", second.Associated, second.Unlisted)
	}
	if row := f.row(gone); !row.ProviderAccountKnown() {
		t.Fatal("the confirmed row was not associated")
	}
	if row := f.row(gone); row.ProviderAbsent() {
		t.Fatal("the confirmed row was marked absent by the action itself")
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile after the confirmed association: %v", err)
	}
	if row := f.row(gone); !row.ProviderAbsent() {
		t.Fatal("the confirmed deleted row was not marked absent by the next complete listing")
	}
	if row := f.row(live); row.ProviderAbsent() {
		t.Fatal("a live legacy row was marked absent")
	}
}

// TestAssociationLeavesUnattributableRowsUnknown covers the two provider answers
// that name no account, and proves neither marks anything.
func TestAssociationLeavesUnattributableRowsUnknown(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(*inventoryProvider)
		wantCode string
	}{
		{
			name: "the provider refuses to show the server",
			prepare: func(p *inventoryProvider) {
				p.answerPerServer(621, http.StatusForbidden)
			},
			wantCode: string(gigahostAssociationRefused),
		},
		{
			name: "the provider answers without naming an account",
			prepare: func(p *inventoryProvider) {
				p.answerPerServer(621, http.StatusOK)
				p.setDetailBody(`{"meta":{"status":200},"data":{"srv_id":621,"status":"active"}}`)
			},
			wantCode: string(gigahostAssociationUnnamed),
		},
		{
			name: "the provider cannot be asked",
			prepare: func(p *inventoryProvider) {
				p.answerPerServer(621, http.StatusInternalServerError)
			},
			wantCode: string(gigahostAssociationUnanswered),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			row := f.seedLegacyServer("Legacy", 621)
			f.provider.set(inventoryJSON())
			tc.prepare(f.provider)

			preview := f.associationPreviewCall()
			if preview.Attributable != 0 || preview.Unlisted != 0 || preview.Unattributed != 1 {
				t.Fatalf("preview = %+v, want no association and one unattributed row", preview)
			}
			if len(preview.Reasons) != 1 || preview.Reasons[0].Reason != tc.wantCode || preview.Reasons[0].Count != 1 {
				t.Fatalf("preview reasons = %+v, want one %q", preview.Reasons, tc.wantCode)
			}

			// Even the confirmed action must not associate a row the provider
			// speaks against or says nothing about.
			result := f.associationActionCall(true)
			if result.Associated != 0 || result.Unattributed != 1 {
				t.Fatalf("the confirmed action associated %d rows (%d unattributed), want 0 and 1",
					result.Associated, result.Unattributed)
			}
			if got := f.row(row); got.ProviderAccountKnown() {
				t.Fatalf("an unattributable row was associated with %q", got.ProviderAccountID)
			}

			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if got := f.row(row); got.ProviderAbsent() {
				t.Fatal("a row with no recorded account was marked absent")
			}
		})
	}
}

// TestAssociationNeverRewritesARecordedAccount proves the action is write-once: a
// row that already records another account keeps it, and the configured key's empty
// listing cannot then mark that row.
func TestAssociationNeverRewritesARecordedAccount(t *testing.T) {
	f := newInventoryFixture(t)
	row := f.seedServerUnderAccount("Registered-under-another-account", 631, otherAccount)

	f.provider.set(inventoryJSON())
	preview := f.associationPreviewCall()
	if preview.Candidates != 0 || preview.AlreadyBound != 1 {
		t.Fatalf("preview = %+v, want no candidate and one already-bound row", preview)
	}

	result := f.associationActionCall(true)
	if result.Associated != 0 || result.AlreadyBound != 1 {
		t.Fatalf("the action associated %d rows (%d already bound), want 0 and 1", result.Associated, result.AlreadyBound)
	}
	if got := f.row(row); got.ProviderAccountID != otherAccount {
		t.Fatalf("the recorded account was rewritten to %q, want %q", got.ProviderAccountID, otherAccount)
	}

	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.row(row); got.ProviderAbsent() {
		t.Fatal("a row belonging to another account was marked absent by this account's listing")
	}
}

// TestAssociationIsIdempotent proves a repeated run changes nothing and says so,
// which is what a second click has to report rather than a duplicate count.
func TestAssociationIsIdempotent(t *testing.T) {
	f := newInventoryFixture(t)
	live := f.seedLegacyServer("Legacy-live", 641)
	f.provider.set(inventoryJSON(641))
	f.provider.answerPerServer(641, http.StatusOK)

	first := f.associationActionCall(true)
	if first.Associated != 1 {
		t.Fatalf("the first run associated %d rows, want 1", first.Associated)
	}
	second := f.associationActionCall(true)
	if second.Associated != 0 || second.AlreadyBound != 1 || second.Unattributed != 0 {
		t.Fatalf("the second run = %+v, want 0 associated, 1 already bound, 0 unattributed", second)
	}
	if got := f.row(live); got.ProviderAccountID != fixtureAccount {
		t.Fatalf("the repeated run changed the recorded account to %q", got.ProviderAccountID)
	}
	preview := f.associationPreviewCall()
	if preview.Candidates != 0 || preview.Attributable != 0 || preview.Unlisted != 0 {
		t.Fatalf("the preview after the association = %+v, want nothing left to associate", preview)
	}
	if preview.AlreadyBound != 1 {
		t.Fatalf("the preview after the association reports %d already-bound rows, want 1", preview.AlreadyBound)
	}
}

// TestAssociationRefusesWhenTheProviderCannotAnswer proves a partial or failed read
// associates nothing: an unanswered account or listing is not evidence about who
// owns a row.
func TestAssociationRefusesWhenTheProviderCannotAnswer(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*inventoryProvider)
	}{
		{"the account read fails", func(p *inventoryProvider) { p.failAccount(http.StatusInternalServerError) }},
		{"the account names no identity", func(p *inventoryProvider) { p.hideAccountIdentity() }},
		{"the inventory read fails", func(p *inventoryProvider) { p.failInventory(http.StatusInternalServerError) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			row := f.seedLegacyServer("Legacy", 651)
			f.provider.set(inventoryJSON(651))
			f.provider.answerPerServer(651, http.StatusOK)
			tc.prepare(f.provider)

			rec := f.associationRequest(http.MethodPost, `{"include_unlisted":true}`, models.RoleAdmin)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("the action answered %d, want 503; body=%s", rec.Code, rec.Body.String())
			}
			if got := f.row(row); got.ProviderAccountKnown() {
				t.Fatalf("a refused pass associated the row with %q", got.ProviderAccountID)
			}
		})
	}
}

// TestAssociationTreatsAnEmptyOrUnreadableBodyAsNoConfirmation proves the default
// is the narrow one: a client that sends nothing associates only the rows the
// provider named, and a malformed body is refused rather than read as consent.
func TestAssociationTreatsAnEmptyOrUnreadableBodyAsNoConfirmation(t *testing.T) {
	f := newInventoryFixture(t)
	live := f.seedLegacyServer("Legacy-live", 671)
	gone := f.seedLegacyServer("Legacy-deleted", 672)
	f.provider.set(inventoryJSON(671))
	f.provider.answerPerServer(671, http.StatusOK)
	f.provider.answerPerServer(672, http.StatusNotFound)

	rec := f.associationRequest(http.MethodPost, "", models.RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("the action with no body answered %d: %s", rec.Code, rec.Body.String())
	}
	var result associationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode the outcome: %v (%s)", err, rec.Body.String())
	}
	if result.Associated != 1 || result.Unlisted != 0 {
		t.Fatalf("the action with no body associated %d rows (%d unlisted), want 1 and 0", result.Associated, result.Unlisted)
	}
	if got := f.row(gone); got.ProviderAccountKnown() {
		t.Fatal("a body with no confirmation associated a row the account no longer lists")
	}
	if got := f.row(live); !got.ProviderAccountKnown() {
		t.Fatal("a body with no confirmation did not associate the row the provider names")
	}

	malformed := f.associationRequest(http.MethodPost, `{"include_unlisted":"yes"}`, models.RoleAdmin)
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("a malformed confirmation answered %d, want 400", malformed.Code)
	}
}

// TestAssociationRefusesANonAdministrator proves the handler refuses a request that
// did not arrive as an administrator, independently of the route's own middleware.
func TestAssociationRefusesANonAdministrator(t *testing.T) {
	f := newInventoryFixture(t)
	row := f.seedLegacyServer("Legacy", 661)
	f.provider.set(inventoryJSON(661))

	for _, role := range []models.UserRole{models.RoleSupport, models.RoleUser} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec := f.associationRequest(method, `{"include_unlisted":true}`, role)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s as %q answered %d, want 403", method, role, rec.Code)
			}
		}
	}
	if got := f.row(row); got.ProviderAccountKnown() {
		t.Fatal("a refused request associated the row")
	}
}
