package handlers

// Regression tests for the per-card Settings save model (#888).
//
// Each test renders the real /settings page, runs the scripts that page names in
// JSDOM, and talks to the real settings handlers over HTTP (see
// settings_save_model_harness_test.go). Assertions carry messages that name the
// behaviour, so a run against the old page fails on that behaviour.

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestSettingsSaveModel_DirtyIndicationAppearsAndClears: a card shows that it has
// unsaved changes as soon as a field differs from the loaded value, goes back to
// clean when the value is restored, and clears for good on a successful commit.
func TestSettingsSaveModel_DirtyIndicationAppearsAndClears(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
assert.ok(card('appearanceCard'), 'the appearance section is not a card with its own id');
assert.ok(badgeOf('appearanceCard'), 'the appearance card has no unsaved-changes indication');
assert.ok(commitOf('appearanceCard'), 'the appearance card has no commit control of its own');
assert.equal(shown(badgeOf('appearanceCard')), false, 'a freshly loaded card must not look edited');
assert.equal(commitOf('appearanceCard').disabled, true, 'nothing to commit yet');

const original = doc.getElementById('app_title').value;
type('app_title', original + ' edited');
assert.equal(shown(badgeOf('appearanceCard')), true, 'editing a field must mark the card unsaved at once');
assert.equal(badgeOf('appearanceCard').textContent.trim(), CFG.dict.settings_unsaved);
assert.equal(commitOf('appearanceCard').disabled, false, 'an edited card must offer its commit');
assert.equal(shown(badgeOf('sslCard')), false, 'an edit in one card must not mark another');
assert.equal(shown(badgeOf('captchaCard')), false);

type('app_title', original);
assert.equal(shown(badgeOf('appearanceCard')), false, 'restoring the loaded value must clear the indication');
assert.equal(commitOf('appearanceCard').disabled, true);

type('app_title', 'Committed Title');
assert.equal(shown(badgeOf('appearanceCard')), true);
commitOf('appearanceCard').click();
await until(() => shown(statusOf('appearanceCard')), 'the appearance card to report its save');
assert.equal(shown(badgeOf('appearanceCard')), false, 'a successful commit must clear the indication');
assert.equal(commitOf('appearanceCard').disabled, true, 'nothing left to commit after a successful save');
`)
}

// TestSettingsSaveModel_CommitReportsSuccessInItsOwnCard: a commit reports in the
// card that made it, leaves every other card (and its unsaved state) alone, and
// commits only that card's section.
func TestSettingsSaveModel_CommitReportsSuccessInItsOwnCard(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
assert.ok(commitOf('appearanceCard'), 'the appearance card has no commit control of its own');
assert.ok(commitOf('captchaCard'), 'the captcha card has no commit control of its own');

type('app_title', 'Scoped Title');
toggle('captcha_enabled', true);
assert.equal(shown(badgeOf('captchaCard')), true);

commitOf('appearanceCard').click();
await until(() => shown(statusOf('appearanceCard')), 'the appearance card to report success');
assert.equal(statusOf('appearanceCard').textContent.trim(), CFG.dict.settings_saved);

for (const id of ['sslCard', 'limitsCard', 'telegramCard', 'captchaCard', 'notificationsCard', 'gigahostCard']) {
  assert.equal(shown(statusOf(id)), false, id + ' must not report the appearance save');
  assert.equal(shown(errorOf(id)), false, id + ' must not show an error for the appearance save');
}
assert.equal(shown(badgeOf('captchaCard')), true, 'another card keeps its unsaved state across this save');
assert.equal(commitOf('captchaCard').disabled, false, 'and keeps its commit enabled');
assert.equal(toasts.length, 0, 'a card save must not raise a page-level toast: ' + JSON.stringify(toasts));

const s = await stored();
assert.equal(s.appearance.title, 'Scoped Title');
assert.equal(s.captcha.enabled, false, 'saving appearance must not commit the captcha card');
assert.deepEqual(s.limits, {max_connections_per_user: 10, connection_rate_limit_count: 5, connection_rate_limit_window: 60},
  'saving appearance must leave the stored limits as they were');
assert.equal(s.ssl.panel_port, 5000, 'saving appearance must leave the stored SSL port as it was');
assert.equal(s.ssl.domain, 'seed.example.test');
`)

	// The write-only secrets are not readable through the API, so check them in
	// the store: an appearance save must not erase them.
	var ssl models.SSLSettings
	_ = h.db.GetSetting(context.Background(), "ssl", &ssl)
	if ssl.KeyText != probeKeyText || ssl.CertText != probeCertText {
		t.Errorf("an appearance save erased the stored TLS material: key=%q cert=%q", ssl.KeyText, ssl.CertText)
	}
	var tg map[string]any
	_ = h.db.GetSetting(context.Background(), "telegram", &tg)
	if tg["bot_token"] != probeBotToken {
		t.Errorf("an appearance save erased the stored bot token: %v", tg["bot_token"])
	}
}

// TestSettingsSaveModel_UnrelatedSubsystemErrorIsNotShownForASuccessfulSave: the
// page's unconfigured hosting provider and unavailable notification service must
// not surface on an appearance save. Each reports inside its own card instead.
func TestSettingsSaveModel_UnrelatedSubsystemErrorIsNotShownForASuccessfulSave(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
assert.ok(commitOf('appearanceCard'), 'the appearance card has no commit control of its own');

type('app_title', 'No Foreign Error');
commitOf('appearanceCard').click();
await until(() => shown(statusOf('appearanceCard')), 'the appearance card to report success');
await settled();

// Visible text only: the page's inline bootstrap script carries the whole
// translation dictionary, whose key names are not something an operator reads.
const clone = doc.body.cloneNode(true);
clone.querySelectorAll('script, template').forEach(n => n.remove());
const text = clone.textContent;
assert.ok(text.toLowerCase().indexOf('api key not configured') === -1, 'a hosting configuration error is on the page after an appearance save');
assert.ok(text.indexOf('GIGAHOST_API_KEY') === -1, 'a provider environment variable name is on the page');
assert.equal(doc.querySelectorAll('.toast').length, 0, 'a page-level toast is on screen after an appearance save');
assert.equal(toasts.length, 0, 'toasts raised during load and save: ' + JSON.stringify(toasts));
assert.equal(shown(errorOf('appearanceCard')), false);

// The failures are real, so they must still be visible - but in their own cards.
const catalog = doc.getElementById('deployPlanSelect');
assert.ok(catalog.textContent.indexOf(CFG.dict.deploy_vps_catalog_unavailable) !== -1,
  'the hosting card must say its own catalog is unavailable');
assert.ok(card('gigahostCard').contains(catalog));
assert.ok(card('notificationsCard').textContent.indexOf(CFG.dict.notifications_load_failed) !== -1,
  'the notification card must say its own settings could not be read');
`)
}

// TestSettingsSaveModel_FailureStaysInTheCardThatCausedIt: a refused commit
// reports in that card only, keeps the typed value and the unsaved state, and a
// retry that succeeds clears the failure.
func TestSettingsSaveModel_FailureStaysInTheCardThatCausedIt(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
assert.ok(commitOf('limitsCard'), 'the limits card has no commit control of its own');
type('max_connections_per_user', '23');
failSave = true;
commitOf('limitsCard').click();
await until(() => shown(errorOf('limitsCard')), 'the limits card to report the failure');
assert.equal(shown(statusOf('limitsCard')), false);
for (const id of ['appearanceCard', 'sslCard', 'captchaCard', 'telegramCard', 'gigahostCard']) {
  assert.equal(shown(errorOf(id)), false, id + ' must not show the limits failure');
}
assert.equal(toasts.length, 0, 'a card failure must not also raise a page toast: ' + JSON.stringify(toasts));
assert.equal(shown(badgeOf('limitsCard')), true, 'a failed commit leaves the card unsaved');
assert.equal(doc.getElementById('max_connections_per_user').value, '23', 'the typed value is kept');
assert.equal((await stored()).limits.max_connections_per_user, 10, 'a failed commit stores nothing');
assert.equal(commitOf('limitsCard').disabled, false, 'the operator can try again');
assert.equal(card('limitsCard').getAttribute('aria-busy'), 'false');

failSave = false;
commitOf('limitsCard').click();
await until(() => shown(statusOf('limitsCard')), 'the retry to succeed');
assert.equal(shown(errorOf('limitsCard')), false, 'success replaces the failure');
assert.equal((await stored()).limits.max_connections_per_user, 23);
`)
}

// TestSettingsSaveModel_SecurityCommitsPersist: captcha, SSL and the connection
// limits each commit through their own card and are what a reload renders.
func TestSettingsSaveModel_SecurityCommitsPersist(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
for (const id of ['captchaCard', 'sslCard', 'limitsCard']) {
  assert.ok(commitOf(id), id + ' has no commit control of its own');
}
toggle('captcha_enabled', true);
commitOf('captchaCard').click();
await until(() => shown(statusOf('captchaCard')), 'captcha to save');

toggle('ssl_enabled', true);
type('panel_port', '5443');
type('ssl_domain', 'panel.example.test');
type('ssl_cert_path', '/etc/example/cert.pem');
type('ssl_key_path', '/etc/example/key.pem');
commitOf('sslCard').click();
await until(() => shown(statusOf('sslCard')), 'ssl to save');

type('max_connections_per_user', '17');
type('connection_rate_limit_count', '9');
type('connection_rate_limit_window', '120');
commitOf('limitsCard').click();
await until(() => shown(statusOf('limitsCard')), 'limits to save');

const s = await stored();
assert.equal(s.captcha.enabled, true);
assert.equal(s.ssl.enabled, true);
assert.equal(s.ssl.panel_port, 5443);
assert.equal(s.ssl.domain, 'panel.example.test');
assert.equal(s.ssl.cert_path, '/etc/example/cert.pem');
assert.equal(s.ssl.key_path, '/etc/example/key.pem');
assert.deepEqual(s.limits, {max_connections_per_user: 17, connection_rate_limit_count: 9, connection_rate_limit_window: 120});
assert.equal(s.appearance.title, 'Seed Title', 'the security saves must not touch appearance');
`)

	// What a reload renders is what the operator sees next: check the markup.
	page := renderSettingsPageFor(t, h, models.RoleAdmin)
	for _, want := range []string{
		`id="captcha_enabled" checked`,
		`id="ssl_enabled" checked`,
		`id="panel_port" value="5443"`,
		`id="max_connections_per_user" name="max_connections_per_user"`,
		`value="17"`,
		`value="120"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the reloaded settings page does not render %q", want)
		}
	}
	// The stored TLS material survived a save that sent no certificate text.
	var ssl models.SSLSettings
	_ = h.db.GetSetting(context.Background(), "ssl", &ssl)
	if ssl.KeyText != probeKeyText || ssl.CertText != probeCertText {
		t.Errorf("the SSL commit erased the stored TLS material: key=%q cert=%q", ssl.KeyText, ssl.CertText)
	}
}

// TestSettingsSaveModel_WriteOnlySecretsAreDirtyOnlyWhenChanged: a stored secret
// is never rendered, so an empty or masked field is not a change, and a new value
// is.
func TestSettingsSaveModel_WriteOnlySecretsAreDirtyOnlyWhenChanged(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
assert.equal(shown(badgeOf('telegramCard')), false, 'a masked stored token must not make the card look edited on load');
assert.equal(shown(badgeOf('sslCard')), false);
assert.equal(doc.getElementById('telegram_bot_token').value, '********');

type('telegram_bot_token', '');
assert.equal(shown(badgeOf('telegramCard')), false, 'emptying a write-only secret keeps the stored one, so it is not a change');
type('ssl_key_text', 'pasted-key');
assert.equal(shown(badgeOf('sslCard')), true, 'a new secret value is a change');
type('ssl_key_text', '');
assert.equal(shown(badgeOf('sslCard')), false);

type('telegram_bot_token', 'new-token-value');
assert.equal(shown(badgeOf('telegramCard')), true);
commitOf('telegramCard').click();
await until(() => shown(statusOf('telegramCard')), 'telegram to save');
assert.equal(doc.getElementById('telegram_bot_token').value, '********', 'after saving, the field shows the mask again, not the secret');
assert.equal(shown(badgeOf('telegramCard')), false);
`)
	var tg map[string]any
	_ = h.db.GetSetting(context.Background(), "telegram", &tg)
	if tg["bot_token"] != "new-token-value" {
		t.Errorf("the new bot token was not stored: %v", tg["bot_token"])
	}
}

// TestSettingsSaveModel_QuickCommitsDoNotOverwriteEachOther: two cards committed
// back to back both end up stored. The endpoint rewrites four sections per call,
// so an unserialised pair would let the second write restore the first card's
// old value.
func TestSettingsSaveModel_QuickCommitsDoNotOverwriteEachOther(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
let release;
saveGate = new Promise(r => { release = r; });
toggle('captcha_enabled', true);
type('max_connections_per_user', '31');
commitOf('captchaCard').click();
await sleep(150);
commitOf('limitsCard').click();
await sleep(150);
release();
await until(() => shown(statusOf('captchaCard')) && shown(statusOf('limitsCard')), 'both cards to report success');
const s = await stored();
assert.equal(s.captcha.enabled, true, 'the second commit undid the first card');
assert.equal(s.limits.max_connections_per_user, 31);
`)
}

// TestSettingsSaveModel_OnlyALanguageChangeLeavesThePage: the dictionary is
// rendered by a document load, so changing the language is the one save that
// navigates. Every other save stays on the page.
func TestSettingsSaveModel_OnlyALanguageChangeLeavesThePage(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
const moves = [];
w.SettingsSave.navigate = url => moves.push(url);

type('app_title', 'Same Language');
commitOf('appearanceCard').click();
await until(() => shown(statusOf('appearanceCard')), 'the title save');
await sleep(1200);
assert.deepEqual(moves, [], 'a save that keeps the language must not leave the page');

const select = doc.getElementById('appearance_language');
select.value = 'fr';
select.dispatchEvent(new w.Event('change', {bubbles: true}));
commitOf('appearanceCard').click();
await until(() => moves.length > 0, 'the language save to navigate', 6000);
assert.deepEqual(moves, ['/settings']);
assert.equal((await stored()).appearance.language, 'fr');
`)
}

// TestSettingsSaveModel_ProviderCredentialCommitsFromItsOwnCard: the Gigahost key
// is committed by the credentials card, stored, and shown masked afterwards. The
// ordering workflow beside it is a set of immediate actions and never makes the
// card look edited.
func TestSettingsSaveModel_ProviderCredentialCommitsFromItsOwnCard(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
assert.ok(commitOf('gigahostCard'), 'the provider credentials card has no commit control of its own');
assert.equal(shown(badgeOf('gigahostCard')), false, 'the order selectors are immediate actions, not staged settings');
const plan = doc.getElementById('deployPlanSelect');
plan.dispatchEvent(new w.Event('change', {bubbles: true}));
assert.equal(shown(badgeOf('gigahostCard')), false, 'choosing an order option must not mark the credentials unsaved');

type('gigahost_api_key', 'flux_live_probe_key_0123456789');
assert.equal(shown(badgeOf('gigahostCard')), true);
commitOf('gigahostCard').click();
await until(() => shown(statusOf('gigahostCard')), 'the credentials card to report success');
assert.equal(doc.getElementById('gigahost_api_key').value, '********', 'the saved key is shown masked, never echoed');
assert.equal(shown(badgeOf('gigahostCard')), false);
assert.equal(toasts.length, 0, 'no page toast: ' + JSON.stringify(toasts));
`)
	var gh map[string]any
	_ = h.db.GetSetting(context.Background(), "gigahost", &gh)
	if gh["api_key"] != "flux_live_probe_key_0123456789" {
		t.Errorf("the provider key was not stored by its card: %v", gh["api_key"])
	}
}

// TestSettingsSaveModel_TwoClientsInterleavedKeepBothSecurityChanges: the review
// oracle for section ownership. Client A starts an Appearance save and its
// request is held at a barrier on the wire. While it is held, client B, an
// independent page on the same database, commits Captcha and Limits and gets its
// success. Then A's request is released. Both changes must be what a reload
// shows, and the rows and secrets neither client touched must be unchanged.
//
// A client that carried the whole settings document forward would send the
// Captcha and Limits values it read before B's commits, and this fails.
func TestSettingsSaveModel_TwoClientsInterleavedKeepBothSecurityChanges(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, `
const tabB = await openTab();

let release;
saveGate = new Promise(r => { release = r; });
type('app_title', 'Client A Title');
commitOf('appearanceCard').click();
await until(() => saveHeld > 0, 'client A request to reach the barrier');

tabB.toggle('captcha_enabled', true);
tabB.commit('captchaCard');
await until(() => shown(tabB.status('captchaCard')), 'client B captcha to save');
tabB.type('max_connections_per_user', '23');
tabB.commit('limitsCard');
await until(() => shown(tabB.status('limitsCard')), 'client B limits to save');

const mid = await stored();
assert.equal(mid.captcha.enabled, true, 'client B captcha is stored before A is released');
assert.equal(mid.appearance.title, 'Seed Title', 'client A has not written yet');

release();
await until(() => shown(statusOf('appearanceCard')), 'client A to report success');
tabB.close();

const s = await stored();
assert.equal(s.appearance.title, 'Client A Title', 'client A change was lost');
assert.equal(s.captcha.enabled, true, 'client A undid the captcha that client B saved');
assert.equal(s.limits.max_connections_per_user, 23, 'client A undid the limits that client B saved');
assert.equal(s.ssl.domain, 'seed.example.test', 'client A or B changed an ssl row nobody edited');
`)

	ctx := context.Background()
	var ssl models.SSLSettings
	_ = h.db.GetSetting(ctx, "ssl", &ssl)
	if ssl.KeyText != probeKeyText || ssl.CertText != probeCertText {
		t.Errorf("the interleaved saves changed the stored TLS material: key=%q cert=%q", ssl.KeyText, ssl.CertText)
	}
	var tg map[string]any
	_ = h.db.GetSetting(ctx, "telegram", &tg)
	if tg["bot_token"] != probeBotToken || tg["chat_id"] != "-100seed" {
		t.Errorf("the interleaved saves changed the telegram row: %v", tg)
	}
	page := renderSettingsPageFor(t, h, models.RoleAdmin)
	for _, want := range []string{`id="captcha_enabled" checked`, `value="Client A Title"`, `value="23"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the reloaded settings page does not render %q", want)
		}
	}
}
