package handlers

// Staged-edit and announcement contract for the two cards that load their own
// record: Notifications and Policy routing (#888).
//
// Same harness as settings_save_model_test.go: the real /settings page, the
// scripts that page names, and real handlers over HTTP. The policy endpoints are
// answered by an in-memory double, because the handler fixture does not mount
// them; the double is the only injected server behaviour, and it only refuses or
// accepts.

import (
	"context"
	"testing"
)

// TestSettingsStagedEdits_PolicyRefusalKeepsTheEditedForm: a refused policy save
// leaves the operator's input, the unsaved mark and the local error in place. The
// stored record is separate, and is still the one the server holds.
func TestSettingsStagedEdits_PolicyRefusalKeepsTheEditedForm(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
policyDouble.refuse = true;
const policy = card('policyRoutingCard');
const save = policy.querySelector('[data-commit]');
await until(() => !save.disabled || shown(badgeOf('policyRoutingCard')) === false, 'policy record to load');
assert.equal(shown(badgeOf('policyRoutingCard')), false, 'a loaded policy card starts clean');

const enable = doc.getElementById('policy_enabled');
enable.checked = true;
enable.dispatchEvent(new w.Event('change', {bubbles: true}));
type('policy_local_entries', 'corp.example\n198.51.100.0/24');
assert.equal(shown(badgeOf('policyRoutingCard')), true);
assert.equal(save.disabled, false);

save.click();
await until(() => shown(errorOf('policyRoutingCard')) || doc.getElementById('policyAlert').textContent !== '', 'the refusal to be reported');
await settled();

assert.equal(policyDouble.puts.length, 1, 'exactly one write was attempted');
assert.equal(enable.checked, true, 'the refused switch stays on so it can be corrected');
assert.equal(doc.getElementById('policy_local_entries').value, 'corp.example\n198.51.100.0/24', 'the refused text stays in the editor');
assert.equal(shown(badgeOf('policyRoutingCard')), true, 'a refused save must not mark the card clean');
assert.equal(policy.getAttribute('aria-busy'), 'false');
assert.equal(save.disabled, false, 'the operator can try again');
assert.ok(doc.getElementById('policyAlert').textContent.indexOf('direct egress is unavailable') !== -1, 'the server reason is shown in the card');
assert.equal(policyDouble.record.enabled, false, 'the stored record is the one the server kept');
assert.equal(toasts.length, 0, 'no page toast: ' + JSON.stringify(toasts));
`)
}

// TestSettingsStagedEdits_NotificationsSlowSaveKeepsNewerEdits: edits made after
// the request was built are not overwritten by its answer. The card rebases to
// what was sent, so the newer text is still unsaved, and the stored record holds
// what was sent.
func TestSettingsStagedEdits_NotificationsSlowSaveKeepsNewerEdits(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true}, `
const n = card('notificationsCard');
const save = n.querySelector('[data-commit]');
await until(() => doc.getElementById('notifications_url') && !n.querySelector('#notificationHistory .text-muted').textContent.startsWith('Loading') , 'notifications to load');
assert.equal(shown(badgeOf('notificationsCard')), false);

let release;
const gate = new Promise(r => { release = r; });
holdWhen = (u, o) => (String(u).indexOf('/api/notifications/settings') === 0 && isPost(o)) ? gate : null;

type('notifications_url', 'https://gotify.example.test/first');
await until(() => !save.disabled, 'the edited card to be committable');
save.click();
await until(() => held > 0, 'the save request to reach the barrier');
assert.equal(n.getAttribute('aria-busy'), 'true');

type('notifications_url', 'https://gotify.example.test/second');
release();
await until(() => shown(statusOf('notificationsCard')), 'the save to report success');

assert.equal(doc.getElementById('notifications_url').value, 'https://gotify.example.test/second', 'the newer edit survived the answer');
assert.equal(shown(badgeOf('notificationsCard')), true, 'the newer edit is still unsaved');
assert.equal((await (await realFetch(CFG.base + '/api/notifications/settings')).json()).url, 'https://gotify.example.test/first', 'the stored record holds what was sent');
assert.equal(n.getAttribute('aria-busy'), 'false');
`)

	var url string
	var cfg map[string]any
	if err := h.db.GetSetting(context.Background(), "notifications", &cfg); err != nil {
		t.Fatal(err)
	}
	if url, _ = cfg["url"].(string); url != "https://gotify.example.test/first" {
		t.Errorf("the stored destination is %q, want what the request carried", url)
	}
}

// TestSettingsStagedEdits_NotificationsRefusalKeepsInput: a refused notification
// save keeps the typed values and the unsaved mark, and reports in its card.
func TestSettingsStagedEdits_NotificationsRefusalKeepsInput(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true}, `
const n = card('notificationsCard');
const save = n.querySelector('[data-commit]');
await until(() => !n.querySelector('#notificationHistory .text-muted').textContent.startsWith('Loading'), 'notifications to load');
type('notifications_url', 'https://user:secret@gotify.example.test');
await until(() => !save.disabled, 'the edited card to be committable');
save.click();
await until(() => shown(errorOf('notificationsCard')), 'the refusal to be reported in the card');
assert.equal(doc.getElementById('notifications_url').value, 'https://user:secret@gotify.example.test', 'a refused destination stays in the field');
assert.ok(errorOf('notificationsCard').textContent.indexOf('credentials') !== -1, 'the server reason is shown in the card');
assert.equal(shown(badgeOf('notificationsCard')), true);
assert.equal(n.getAttribute('aria-busy'), 'false');
assert.equal(toasts.length, 0);
`)
}

// TestSettingsStagedEdits_PolicySlowSaveKeepsNewerEdits: the policy card's form is
// not locked during a save, so text typed after the request was built must survive
// its answer, stay marked unsaved, and the stored record holds what was sent.
func TestSettingsStagedEdits_PolicySlowSaveKeepsNewerEdits(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
const policy = card('policyRoutingCard');
const save = policy.querySelector('[data-commit]');
await sleep(300);

let release;
const gate = new Promise(r => { release = r; });
holdWhen = (u, o) => (String(u) === '/api/vpn/policy' && String((o && o.method) || '').toUpperCase() === 'PUT') ? gate : null;

type('policy_local_entries', 'sent.example');
await until(() => !save.disabled, 'the edited card to be committable');
save.click();
await until(() => held > 0, 'the save request to reach the barrier');
assert.equal(policy.getAttribute('aria-busy'), 'true');

type('policy_local_entries', 'sent.example\nnewer.example');
release();
holdWhen = null;
await until(() => policy.getAttribute('aria-busy') === 'false', 'the save to finish');
await settled();

assert.equal(doc.getElementById('policy_local_entries').value, 'sent.example\nnewer.example', 'the newer edit survived the answer');
assert.equal(shown(badgeOf('policyRoutingCard')), true, 'the newer edit is still unsaved');
assert.deepEqual(policyDouble.record.local_entries, ['sent.example'], 'the stored record holds what was sent');
assert.equal(policyDouble.puts.length, 1);
`)
}
