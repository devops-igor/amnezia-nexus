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
	"strings"
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

// TestAssociationNewerPreviewRetiresTheOlderOne is the first ordering: two Settings
// tabs both preview the same mixed batch. The newer tab confirms without the unlisted
// switch, then the older tab confirms with its earlier opt-in. The older consent was
// retired when the second preview was issued, so it is refused and the unlisted row
// stays unknown - the write-once predicate would otherwise make that binding permanent.
func TestAssociationNewerPreviewRetiresTheOlderOne(t *testing.T) {
	f := newInventoryFixture(t)
	named := f.seedLegacyServer("Legacy-live", 701)
	unlisted := f.seedLegacyServer("Legacy-deleted", 702)

	f.provider.set(inventoryJSON(701))
	f.provider.answerPerServer(701, http.StatusOK)
	f.provider.answerPerServer(702, http.StatusNotFound)

	older := f.associationPreviewCall()
	newer := f.associationPreviewCall()
	if older.PreviewID == "" || newer.PreviewID == "" || older.PreviewID == newer.PreviewID {
		t.Fatalf("two previews must issue two distinct consents: %q / %q", older.PreviewID, newer.PreviewID)
	}

	// The newer tab confirms with the switch off: the named row is associated, the
	// unlisted one is left alone and reported as still needing an answer.
	result := f.associationActionCallWithPreview(newer.PreviewID, false)
	if result.Associated != 1 || result.Unlisted != 0 || result.Unattributed != 1 {
		t.Fatalf("the newer confirmation = %+v, want 1 associated, 0 unlisted, 1 still needing an answer", result)
	}
	if got := f.row(unlisted); got.ProviderAccountKnown() {
		t.Fatalf("the newer confirmation associated the unlisted row with %q", got.ProviderAccountID)
	}

	// The older tab then confirms with its earlier opt-in. That consent is gone.
	rec := f.associationActionRaw(`{"preview_id":"` + older.PreviewID + `","include_unlisted":true}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("the superseded confirmation answered %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "gigahost_association_preview_superseded") {
		t.Fatalf("the refusal is not the superseded-consent one: %s", rec.Body.String())
	}
	if got := f.row(unlisted); got.ProviderAccountKnown() {
		t.Fatalf("the superseded confirmation associated the unlisted row with %q", got.ProviderAccountID)
	}
	if got := f.row(named); got.ProviderAccountID != fixtureAccount {
		t.Fatalf("the newer confirmation did not record the named row: %q", got.ProviderAccountID)
	}
}

// TestAssociationCommitIsFencedByTheEffectiveConfiguration is the round-24 paused
// ordering, both forms: the confirmation pauses inside the provider detail read, and
// the effective configuration or the authority changes before its reply resumes. No
// binding may land from the authority the reply was based on.
func TestAssociationCommitIsFencedByTheEffectiveConfiguration(t *testing.T) {
	t.Run("ClientReplacedDuringThePausedRead", func(t *testing.T) {
		f := newInventoryFixture(t)
		row := f.seedLegacyServer("Legacy", 703)

		f.provider.set(inventoryJSON())
		f.provider.answerPerServer(703, http.StatusNotFound)
		preview := f.associationPreviewCall()
		if preview.Unlisted != 1 || preview.PreviewID == "" {
			t.Fatalf("preview = %+v, want one unlisted row and a consent", preview)
		}

		replaced := false
		f.provider.onDetail = func() {
			if replaced {
				return
			}
			replaced = true
			f.h.SetGigahostClient(f.h.gigahostClient)
		}

		rec := f.associationActionRaw(`{"preview_id":"` + preview.PreviewID + `","include_unlisted":true}`)
		if !replaced {
			t.Fatal("the confirmation never reached the provider detail read, so the fence was not exercised")
		}
		if rec.Code != http.StatusConflict {
			t.Fatalf("the confirmation across a configuration change answered %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "gigahost_association_authority_lost") {
			t.Fatalf("the refusal is not the authority fence: %s", rec.Body.String())
		}
		if got := f.row(row); got.ProviderAccountKnown() {
			t.Fatalf("the fenced confirmation associated the row with %q", got.ProviderAccountID)
		}
	})

	t.Run("NewPreviewTakenDuringThePausedRead", func(t *testing.T) {
		f := newInventoryFixture(t)
		row := f.seedLegacyServer("Legacy", 706)

		f.provider.set(inventoryJSON())
		f.provider.answerPerServer(706, http.StatusNotFound)
		older := f.associationPreviewCall()
		if older.PreviewID == "" {
			t.Fatal("the first preview offered no consent")
		}

		var newer associationPreview
		taken := false
		f.provider.onDetail = func() {
			if taken {
				return
			}
			taken = true
			newer = f.associationPreviewCall()
		}

		rec := f.associationActionRaw(`{"preview_id":"` + older.PreviewID + `","include_unlisted":true}`)
		if !taken {
			t.Fatal("the confirmation never reached the provider detail read, so the newer preview did not interleave")
		}
		if newer.PreviewID == "" || newer.PreviewID == older.PreviewID {
			t.Fatalf("the interleaved preview did not replace the consent: %+v", newer)
		}
		if rec.Code != http.StatusConflict {
			t.Fatalf("the superseded confirmation answered %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if got := f.row(row); got.ProviderAccountKnown() {
			t.Fatalf("the superseded confirmation associated the row with %q", got.ProviderAccountID)
		}
	})
}

// TestAssociationMidBatchInvalidationStopsLaterBindings is the interleaving that the
// single pre-batch check could not catch: the authority is valid when the batch starts,
// and is invalidated before one of the batch's later rows commits. The invalidation is
// placed deterministically between two rows of the same batch; each row's write decides
// its own authority currency, so nothing lands from the invalidated authority.
func TestAssociationMidBatchInvalidationStopsLaterBindings(t *testing.T) {
	seedBatch := func(t *testing.T) (*inventoryFixture, []int64) {
		t.Helper()
		f := newInventoryFixture(t)
		rows := []int64{
			f.seedLegacyServer("Legacy-a", 801),
			f.seedLegacyServer("Legacy-b", 802),
			f.seedLegacyServer("Legacy-c", 803),
		}
		f.provider.set(inventoryJSON(801, 802, 803))
		for _, id := range []int64{801, 802, 803} {
			f.provider.answerPerServer(id, http.StatusOK)
		}
		return f, rows
	}

	t.Run("ProviderKeySavedAfterTheFirstBinding", func(t *testing.T) {
		f, rows := seedBatch(t)
		preview := f.associationPreviewCall()
		if preview.Attributable != 3 || preview.PreviewID == "" {
			t.Fatalf("preview = %+v, want three attributable rows and a consent", preview)
		}

		saved := false
		f.h.associationBindingHook = func(int64) {
			if saved {
				return
			}
			saved = true
			// The administrator saves a key for another account while the batch runs.
			if err := f.db.SetSetting(context.Background(), "gigahost", map[string]any{"api_key": "another-account-key"}); err != nil {
				t.Fatalf("failed to save the provider key mid-batch: %v", err)
			}
		}

		result := f.associationActionCallWithPreview(preview.PreviewID, false)
		if !saved {
			t.Fatal("the batch never reached its second row, so the interleaving was not exercised")
		}
		if result.Associated != 1 {
			t.Fatalf("the batch associated %d rows after the key changed, want exactly the first", result.Associated)
		}
		if result.Unattributed != 2 || !hasReason(result.Reasons, string(gigahostAssociationAuthorityChanged)) {
			t.Fatalf("the batch = %+v, want the two remaining rows reported with the authority reason", result)
		}
		for _, id := range rows[1:] {
			if got := f.row(id); got.ProviderAccountKnown() {
				t.Fatalf("row %d was bound from an authority the key save had invalidated (%q)", id, got.ProviderAccountID)
			}
		}
		if got := f.row(rows[0]); got.ProviderAccountID != fixtureAccount {
			t.Fatalf("the first row's legitimate binding was lost: %q", got.ProviderAccountID)
		}
	})

	t.Run("NewerPreviewTakenAfterTheFirstBinding", func(t *testing.T) {
		f, rows := seedBatch(t)

		older := f.associationPreviewCall()
		var newer associationPreview
		taken := false
		f.h.associationBindingHook = func(int64) {
			if taken {
				return
			}
			taken = true
			newer = f.associationPreviewCall()
		}

		result := f.associationActionCallWithPreview(older.PreviewID, false)
		if !taken || newer.PreviewID == "" || newer.PreviewID == older.PreviewID {
			t.Fatalf("the interleaved preview did not replace the consent: %+v", newer)
		}
		if result.Associated != 1 {
			t.Fatalf("the batch associated %d rows after the newer preview, want exactly the first", result.Associated)
		}
		if result.Unattributed != 2 || !hasReason(result.Reasons, string(gigahostAssociationAuthorityChanged)) {
			t.Fatalf("the batch = %+v, want the two remaining rows reported with the authority reason", result)
		}
		for _, id := range rows[1:] {
			if got := f.row(id); got.ProviderAccountKnown() {
				t.Fatalf("row %d was bound from an authority a newer preview had replaced (%q)", id, got.ProviderAccountID)
			}
		}
	})
}

// TestAssociationRepeatWithoutConsentKeepsTheUnlistedRowCounted is the reporting half:
// a mixed preview confirmed with the switch off must keep reporting the row it left
// alone, and only a run that genuinely leaves nothing may report an all-clear.
func TestAssociationRepeatWithoutConsentKeepsTheUnlistedRowCounted(t *testing.T) {
	f := newInventoryFixture(t)
	named := f.seedLegacyServer("Legacy-live", 704)
	unlisted := f.seedLegacyServer("Legacy-deleted", 705)

	f.provider.set(inventoryJSON(704))
	f.provider.answerPerServer(704, http.StatusOK)
	f.provider.answerPerServer(705, http.StatusNotFound)
	preview := f.associationPreviewCall()

	first := f.associationActionCallWithPreview(preview.PreviewID, false)
	if first.Associated != 1 || first.Unattributed != 1 {
		t.Fatalf("the first confirmation = %+v, want 1 associated and 1 still needing an answer", first)
	}
	if !hasReason(first.Reasons, string(gigahostAssociationNotConfirmed)) {
		t.Fatalf("the excluded row is not reported with its reason: %+v", first.Reasons)
	}

	// The same request repeated: nothing further is written, and the excluded row is
	// still counted rather than reported as an all-clear.
	repeat := f.associationActionCallWithPreview(preview.PreviewID, false)
	if repeat.Associated != 0 {
		t.Fatalf("the repeat associated %d rows, want 0", repeat.Associated)
	}
	if repeat.Unattributed != 1 || !hasReason(repeat.Reasons, string(gigahostAssociationNotConfirmed)) {
		t.Fatalf("the repeat = %+v, want the excluded row and its reason", repeat)
	}
	if got := f.row(unlisted); got.ProviderAccountKnown() {
		t.Fatalf("the repeat associated the excluded row with %q", got.ProviderAccountID)
	}
	if got := f.row(named); got.ProviderAccountID != fixtureAccount {
		t.Fatalf("the named row lost its association: %q", got.ProviderAccountID)
	}

	// With the consent the same preview offered, the row is associated and the result
	// leaves nothing.
	withConsent := f.associationActionCallWithPreview(preview.PreviewID, true)
	if withConsent.Associated != 1 || withConsent.Unlisted != 1 || withConsent.Unattributed != 0 {
		t.Fatalf("the consented confirmation = %+v, want 1 associated, 1 unlisted, 0 remaining", withConsent)
	}
	allClear := f.associationActionCallWithPreview(preview.PreviewID, true)
	if allClear.Associated != 0 || allClear.Unattributed != 0 || len(allClear.Reasons) != 0 {
		t.Fatalf("the genuine no-op repeat = %+v, want an empty all-clear", allClear)
	}
}

// hasReason reports whether a decoded result carries one reason token.
func hasReason(reasons []associationReasonCount, token string) bool {
	for _, reason := range reasons {
		if reason.Reason == token && reason.Count > 0 {
			return true
		}
	}
	return false
}
