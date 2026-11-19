package handlers

// What a card does with a value it did not receive from the operator.
//
// A card sends every field it holds, not only the one the operator edited, so a
// stored value reaches the same check as an entry. Some stored values are ones
// the field's own markup would reject as an entry, and that is by design of this
// build: an empty appearance title, logo or subtitle is what the shell renders as
// its built-in name, icon and label, and a connection limit of zero is what the
// handlers read as "use the default". Enforcing the markup against those values
// made a card unsaveable: the commit produced no request at all, so the operator
// could not save a change they did make, and the failure was reported against a
// field they never touched.
//
// These scenarios are the contract that closes that class:
//   - a card holding a stored value its markup rejects still commits a change to
//     another of its fields, and the stored value is sent back unchanged;
//   - a value the operator types is an entry, so the refusals in
//     settings_save_model_validation_test.go still hold for it.
//
// Every scenario runs on the real /settings page against the real handlers, with
// the stored state in place before the page is rendered, so the inputs show what
// storage holds and the card is exercised exactly as an operator would meet it.

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestSettingsSaveModel_AStoredEmptyFieldDoesNotBlockItsCard is the regression for
// the state the hosted settings suite leaves behind: the panel stores an empty
// logo and subtitle, which the required inputs reject as entries while the shell
// renders its built-in icon and label for them. A change to the title must still
// be committed, and the empty fields must be sent back as they were stored.
func TestSettingsSaveModel_AStoredEmptyFieldDoesNotBlockItsCard(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{storeBeforeRender: map[string]any{
		"appearance": models.AppearanceSettings{Title: "Seed Title", Logo: "", Subtitle: "", Language: "en"},
	}}, settingsWriteSpy+`
cardWrites = 0;
assert.equal(shown(badgeOf('appearanceCard')), false, 'a freshly loaded card is clean');
assert.equal(doc.getElementById('app_logo').value, '', 'the stored logo is what the card shows');
assert.equal(doc.getElementById('app_subtitle').value, '', 'the stored subtitle is what the card shows');

type('app_title', 'Edited While Empty Stored Fields');
assert.equal(shown(badgeOf('appearanceCard')), true, 'the edit makes the card dirty');
commitOf('appearanceCard').click();
await until(() => shown(errorOf('appearanceCard')) || shown(statusOf('appearanceCard')), 'the save to be answered');
await settled();

const s = await stored();
assert.equal(cardWrites, 1, 'the card sent no request; card error: ' + JSON.stringify(errorOf('appearanceCard').textContent));
assert.equal(shown(errorOf('appearanceCard')), false, 'a stored empty field was reported as an entry: ' + errorOf('appearanceCard').textContent);
assert.equal(s.appearance.title, 'Edited While Empty Stored Fields', 'the edit is stored, got ' + JSON.stringify(s.appearance.title));
assert.equal(s.appearance.logo, '', 'the untouched stored logo was rewritten to ' + JSON.stringify(s.appearance.logo));
assert.equal(s.appearance.subtitle, '', 'the untouched stored subtitle was rewritten to ' + JSON.stringify(s.appearance.subtitle));
assert.equal(shown(badgeOf('appearanceCard')), false, 'the card is clean once what it sent is stored');
`)
}

// TestSettingsSaveModel_AStoredEmptyRequiredFieldIsNotAnEntry goes further than the
// hosted state: every appearance field is empty, including the one the markup
// requires most visibly. The card must still commit an edit to one of them, and the
// empty values the operator did not touch must come back unchanged. Without that,
// a panel whose stored title is empty has a card that can be neither saved nor
// repaired from the page.
func TestSettingsSaveModel_AStoredEmptyRequiredFieldIsNotAnEntry(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{storeBeforeRender: map[string]any{
		"appearance": models.AppearanceSettings{Title: "", Logo: "", Subtitle: "", Language: "en"},
	}}, settingsWriteSpy+`
assert.equal(doc.getElementById('app_title').value, '', 'the stored empty title is what the card shows');
cardWrites = 0;
type('app_subtitle', 'A Subtitle');
commitOf('appearanceCard').click();
await until(() => shown(errorOf('appearanceCard')) || shown(statusOf('appearanceCard')), 'the save to be answered');
await settled();

const s = await stored();
assert.equal(cardWrites, 1, 'the card sent no request; card error: ' + JSON.stringify(errorOf('appearanceCard').textContent));
assert.equal(shown(errorOf('appearanceCard')), false, 'a stored empty field was reported as an entry: ' + errorOf('appearanceCard').textContent);
assert.equal(s.appearance.subtitle, 'A Subtitle', 'the edit is stored, got ' + JSON.stringify(s.appearance.subtitle));
assert.equal(s.appearance.title, '', 'the untouched stored title was rewritten to ' + JSON.stringify(s.appearance.title));
assert.equal(s.appearance.logo, '', 'the untouched stored logo was rewritten to ' + JSON.stringify(s.appearance.logo));
`)
}

// TestSettingsSaveModel_AStoredZeroLimitDoesNotBlockItsCard covers the numeric half
// of the same state. Zero is this build's "the field was omitted" value for a
// connection limit: the handlers read a limit of zero as "use the default". The
// inputs declare a minimum of one, so the stored value is one they reject as an
// entry, and the collector that reads the number has to send it back rather than
// refuse it.
func TestSettingsSaveModel_AStoredZeroLimitDoesNotBlockItsCard(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{storeBeforeRender: map[string]any{
		"limits": models.ConnectionLimits{},
	}}, settingsWriteSpy+`
const max = doc.getElementById('max_connections_per_user');
assert.equal(max.value, '0', 'the stored zero is what the card shows');
cardWrites = 0;
type('connection_rate_limit_count', '7');
commitOf('limitsCard').click();
await until(() => shown(errorOf('limitsCard')) || shown(statusOf('limitsCard')), 'the save to be answered');
await settled();

const s = await stored();
assert.equal(cardWrites, 1, 'the card sent no request; card error: ' + JSON.stringify(errorOf('limitsCard').textContent));
assert.equal(shown(errorOf('limitsCard')), false, 'a stored zero was reported as an entry: ' + errorOf('limitsCard').textContent);
assert.equal(s.limits.connection_rate_limit_count, 7, 'the edit is stored, got ' + s.limits.connection_rate_limit_count);
assert.equal(s.limits.max_connections_per_user, 0, 'the untouched stored limit was rewritten to ' + s.limits.max_connections_per_user);
assert.equal(s.limits.connection_rate_limit_window, 0, 'the untouched stored limit was rewritten to ' + s.limits.connection_rate_limit_window);
`)
}

// TestSettingsSaveModel_ATypedValueIsStillAnEntry is the other half of the rule, on
// the same page and the same stored state: the exemption covers the value the card
// loaded, not the field. A stored zero limit is exempt; once the operator has saved
// that field at five, zero is an entry again, the markup rejects it, and the card
// reports it instead of sending.
func TestSettingsSaveModel_ATypedValueIsStillAnEntry(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{storeBeforeRender: map[string]any{
		"limits": models.ConnectionLimits{},
	}}, settingsWriteSpy+rejectedCase+`
// The stored zero is exempt, so this entry is what the card sends.
cardWrites = 0;
type('max_connections_per_user', '5');
commitOf('limitsCard').click();
await until(() => shown(errorOf('limitsCard')) || shown(statusOf('limitsCard')), 'the first save to be answered');
await settled();
let s = await stored();
assert.equal(cardWrites, 1, 'five is inside the range; card error: ' + JSON.stringify(errorOf('limitsCard').textContent));
assert.equal(s.limits.max_connections_per_user, 5, 'five is stored, got ' + s.limits.max_connections_per_user);
assert.equal(doc.getElementById('max_connections_per_user').value, '5', 'the field shows the stored limit');

// The card now holds five, so a zero is something the operator typed.
cardWrites = 0;
type('max_connections_per_user', '0');
assert.equal(shown(badgeOf('limitsCard')), true, 'the entry makes the card dirty');
commitOf('limitsCard').click();
await until(() => shown(errorOf('limitsCard')), 'the rejected entry to be reported');
await settled();

s = await stored();
assert.equal(cardWrites, 0, 'a typed zero sent a request; stored=' + JSON.stringify(s.limits));
assert.equal(s.limits.max_connections_per_user, 5, 'a typed zero changed the stored maximum to ' + s.limits.max_connections_per_user);
rejected('limitsCard', 'a typed zero', 'Max Connections per User');
`)
}
