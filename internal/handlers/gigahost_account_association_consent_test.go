package handlers

// The consent a confirmation carries is bound to the preview that produced it.
//
// The counts a preview shows belong to one account and one set of unlisted rows. A
// confirmation that carried only the administrator's checkbox could be applied to
// whatever account the configured key belongs to by the time the request arrives -
// and because the association is write-once, that wrong account would then be
// permanent: every later read skips the row, so switching back cannot correct it.
//
// These cases are the negative half of that property, plus the positive control that
// shows the binding still lets the administrator do the thing they asked for.

import (
	"context"
	"net/http"
	"testing"
)

// TestAssociationConsentIsBoundToItsPreviewAccount is the account-switch regression:
// the administrator previews account A and opts in to the rows A no longer lists; a
// different key (account B) is configured before the confirmation arrives. The
// confirmation must be refused, and no association may be written under B.
func TestAssociationConsentIsBoundToItsPreviewAccount(t *testing.T) {
	f := newInventoryFixture(t)
	row := f.seedLegacyServer("Legacy-deleted", 681)

	// Account A answers "no such server" for the legacy row, so the preview offers it
	// as an unlisted row and the administrator opts in.
	f.provider.set(inventoryJSON())
	f.provider.answerPerServer(681, http.StatusNotFound)
	preview := f.associationPreviewCall()
	if preview.Unlisted != 1 || preview.PreviewID == "" {
		t.Fatalf("preview = %+v, want one unlisted row and a confirmation token", preview)
	}

	// The key is replaced by account B's before the confirmation is sent. B answers
	// exactly the same way for the row, which is why the previous behaviour recorded B
	// permanently.
	f.provider.setAccount(otherAccount)
	f.provider.set(inventoryJSON())
	f.provider.answerPerServer(681, http.StatusNotFound)

	rec := f.associationActionRaw(`{"preview_id":"` + preview.PreviewID + `","include_unlisted":true}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("the confirmation under a different account answered %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if got := f.row(row); got.ProviderAccountKnown() {
		t.Fatalf("the row was associated with %q after the account changed; it must stay unknown", got.ProviderAccountID)
	}

	// The token was dropped, so replaying it under B is refused as stale rather than
	// becoming a second chance at the same write.
	replay := f.associationActionRaw(`{"preview_id":"` + preview.PreviewID + `","include_unlisted":true}`)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replaying the used confirmation answered %d, want 409: %s", replay.Code, replay.Body.String())
	}
	if got := f.row(row); got.ProviderAccountKnown() {
		t.Fatalf("replaying the used confirmation associated the row with %q", got.ProviderAccountID)
	}
}

// TestAssociationConsentUnderItsOwnAccountStillAssociates is the stable-account
// control: the same preview, confirmed without the account changing, associates the
// genuinely missing row under the explicit opt-in. The protection must not block the
// deliberate action it was added to.
func TestAssociationConsentUnderItsOwnAccountStillAssociates(t *testing.T) {
	f := newInventoryFixture(t)
	row := f.seedLegacyServer("Legacy-deleted", 682)

	f.provider.set(inventoryJSON())
	f.provider.answerPerServer(682, http.StatusNotFound)
	preview := f.associationPreviewCall()
	if preview.Unlisted != 1 || preview.Attributable != 0 || preview.PreviewID == "" {
		t.Fatalf("preview = %+v, want one unlisted row and nothing attributable", preview)
	}

	result := f.associationActionCallWithPreview(preview.PreviewID, true)
	if result.Associated != 1 || result.Unlisted != 1 {
		t.Fatalf("the confirmation associated %d rows (%d unlisted), want 1 and 1", result.Associated, result.Unlisted)
	}
	got := f.row(row)
	if got.ProviderAccountID != fixtureAccount {
		t.Fatalf("the row was associated with %q, want %q", got.ProviderAccountID, fixtureAccount)
	}
	if got.ProviderAbsent() {
		t.Fatal("the association itself marked the row absent; only the next inventory read may")
	}

	// The next complete listing of this account is what applies the consequence the
	// preview stated.
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile after the association: %v", err)
	}
	if !f.row(row).ProviderAbsent() {
		t.Fatal("the next inventory read did not mark the genuinely missing server absent")
	}
}

// TestAssociationConsentCannotCoverRowsThePreviewNeverShowed proves the unlisted
// consent is scoped to the preview's own rows: a confirmation that asks for unlisted
// rows a preview never offered is refused instead of applying to whatever the fresh
// read happens to have found.
func TestAssociationConsentCannotCoverRowsThePreviewNeverShowed(t *testing.T) {
	f := newInventoryFixture(t)
	live := f.seedLegacyServer("Legacy-live", 683)

	// The preview has one attributable row and nothing unlisted, so its consent covers
	// no absent-marking consequence at all.
	f.provider.set(inventoryJSON(683))
	f.provider.answerPerServer(683, http.StatusOK)
	preview := f.associationPreviewCall()
	if preview.Attributable != 1 || preview.Unlisted != 0 || preview.PreviewID == "" {
		t.Fatalf("preview = %+v, want one attributable row and nothing unlisted", preview)
	}

	rec := f.associationActionRaw(`{"preview_id":"` + preview.PreviewID + `","include_unlisted":true}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a confirmation of unlisted rows the preview never offered answered %d, want 409: %s",
			rec.Code, rec.Body.String())
	}
	if got := f.row(live); got.ProviderAccountKnown() {
		t.Fatal("the refused confirmation associated the provider-named row anyway")
	}
}
