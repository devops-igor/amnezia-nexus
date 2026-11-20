package web

// Behavioural JSDOM coverage for the shipped policy routing controller (#679).
//
// The assertions run static/js/policy_routing.js — read through StaticFS, i.e. the
// asset the browser loads — against the section markup rendered from
// templates/settings_policy.html. Nothing is re-implemented here: the module is
// evaluated as-is and driven through its exported entry points and the DOM the
// template actually produces.
//
// The cases are paired on purpose. Alongside "a save is accepted" there is "a
// refused enablement must not stay visible as enabled", and alongside "a sync
// succeeds" there is "a failed sync is reported with the server's own wording".
// The API double below records method, URL and body, so the payload contract is
// asserted rather than inferred.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
)

// policySectionHTMLForTest renders the shipped partial with the template helpers
// the page provides, so the fixture is the production markup (ids included).
func policySectionHTMLForTest(t *testing.T) string {
	t.Helper()
	funcs := template.FuncMap{
		"_": func(key string) string { return key },
		"is_admin": func(user any) bool {
			return true
		},
	}
	tmpl, err := template.New("settings_policy.html").Funcs(funcs).ParseFS(TemplatesFS, "templates/settings_policy.html", "templates/settings_save_controls.html")
	if err != nil {
		t.Fatalf("parse settings_policy.html: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "settings_policy", map[string]any{
		"current_user": nil,
		"app_version":  "test",
	}); err != nil {
		t.Fatalf("render settings_policy: %v", err)
	}
	if !strings.Contains(buf.String(), `id="policyRoutingForm"`) {
		t.Fatal("rendered policy section does not contain the form; the fixture is wrong")
	}
	return buf.String()
}

// settingsCardsModuleForTest returns the shared card module as a JSON string, so a
// controller fixture can load it the way the Settings page does.
func settingsCardsModuleForTest(t *testing.T) string {
	t.Helper()
	module, err := StaticFS.ReadFile("static/js/settings_cards.js")
	if err != nil {
		t.Fatalf("read card module: %v", err)
	}
	encoded, err := json.Marshal(string(module))
	if err != nil {
		t.Fatalf("encode card module: %v", err)
	}
	return string(encoded)
}

// policyControllerHarness builds a JSDOM window with the shipped module and the
// rendered section. `prelude` installs the API double before the initial load;
// `scenario` runs after that load has settled.
func policyControllerHarness(t *testing.T, prelude, scenario string) string {
	t.Helper()

	module, err := StaticFS.ReadFile("static/js/policy_routing.js")
	if err != nil {
		t.Fatalf("read policy controller: %v", err)
	}
	encodedModule, err := json.Marshal(string(module))
	if err != nil {
		t.Fatalf("encode module: %v", err)
	}
	encodedCards := settingsCardsModuleForTest(t)
	encodedSection, err := json.Marshal(policySectionHTMLForTest(t))
	if err != nil {
		t.Fatalf("encode section: %v", err)
	}

	return jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="policyFixtureHost"></div>', {runScripts:'outside-only'});
const w = dom.window;
// Every translation key resolves to itself, so an assertion can name the exact
// key a branch chose instead of depending on English wording. Two exceptions are
// keys whose resolution is the contract under test: the rule-count template (its
// substituted values) and the runtime sync-state tokens (a token must be looked
// up in the dictionary, not printed raw).
w._ = key => {
  if (key === 'policy_rule_count_value') return '{domains} domains / {cidrs} prefixes';
  if (key.indexOf('policy_sync_state_') === 0) return 'sync:' + key.slice('policy_sync_state_'.length);
  // The two inventory templates whose substitution is under test: everything else
  // resolves to its own key, so an assertion can name the exact key a branch chose.
  if (key === 'policy_inventory_age_value') return '{days} d / max {max}';
  if (key === 'policy_inventory_override_active') return 'OVERRIDE {count} · {digest}';
  return key;
};

// calls records every request the controller made. The responder decides the
// answer per URL, which is what lets a case hold a failure and its recovery.
const calls = [];
let responder = null;
w.API = {
  request: async (url, options) => {
    const opts = options || {};
    calls.push({url: url, method: opts.method || 'GET', body: opts.body});
    return responder(url, opts);
  }
};
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
const settle = async (rounds) => { for (let i = 0; i < (rounds || 8); i++) await flush(); };
const requestsTo = (suffix, method) => calls.filter(c => c.url.endsWith(suffix) && (!method || c.method === method));
// alertText reads the card's two live regions the way a reader of the page does: the
// text of whichever one has any, and its outcome. There is exactly one status and
// one alert region, and at most one of them has text.
const alertText = () => {
  const box = w.document.getElementById('policyAlert');
  const status = box.querySelector('[data-status]');
  const error = box.querySelector('[data-error]');
  const words = el => el.textContent.replace(/\s+/g, ' ').trim();
  const shown = [status, error].filter(el => words(el) !== '');
  if (shown.length > 1) throw new Error('both result regions have text');
  const el = shown[0] || null;
  return {
    text: el ? words(el) : '',
    state: el ? (el === status ? 'success' : 'error') : '',
    outcome: el ? el.getAttribute('data-outcome') : '',
    regions: box.querySelectorAll('[data-status]').length + ':' + box.querySelectorAll('[data-error]').length
  };
};
const toggle = () => w.document.getElementById('policy_enabled').checked;
// editToggle changes the master switch the way a click does: the value moves and
// the change event follows, which is what the card's dirty tracking listens to.
const editToggle = (on) => {
  const el = w.document.getElementById('policy_enabled');
  el.checked = on;
  el.dispatchEvent(new w.Event('change', {bubbles: true}));
};
const editField = (id, value) => {
  const el = w.document.getElementById(id);
  el.value = value;
  el.dispatchEvent(new w.Event('input', {bubbles: true}));
};
const card = () => w.document.getElementById('policyRoutingCard');
const unsavedBadge = () => {
  const el = card().querySelector('[data-dirty]');
  return {text: el.textContent};
};
const badge = () => {
  const el = w.document.getElementById('policyStatusBadge');
  return {text: el.textContent, enabled: el.getAttribute('data-enabled')};
};
const text = id => w.document.getElementById(id).textContent;
const selectedPreset = () => {
  const checked = w.document.querySelector('input[name="policy_preset"]:checked');
  return checked ? checked.value : '';
};

// Evaluate the module before the section exists: the auto-init entry point must
// be inert without a form, and the test then installs the real markup.
(async () => {
// The page loads the card module before the controller, and the controller hands
// the commit control, the busy state and the focus to it.
w.eval(%s);
w.eval(%s);
assert.equal(w.initPolicyRouting(), false, 'init must be inert without the section');

w.document.getElementById('policyFixtureHost').innerHTML = %s;

// The API double must answer the initial load as well, so it is installed first.
%s

assert.equal(w.initPolicyRouting(), true, 'init must wire the rendered section');
await settle();

%s

console.log('POLICY_SCENARIO_OK');
dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedCards), string(encodedModule), string(encodedSection), prelude, scenario)
}

// runPolicyControllerScenario executes one scenario and fails the test with the
// Node output attached when the script does not report success.
func runPolicyControllerScenario(t *testing.T, prelude, scenario string) {
	t.Helper()
	node := requireJSDOM(t)
	out, err := execNodeScript(node, policyControllerHarness(t, prelude, scenario))
	if err != nil || !strings.Contains(string(out), "POLICY_SCENARIO_OK") {
		t.Fatalf("policy controller scenario failed: %v\n%s", err, out)
	}
}

// policyCDNPayloadForTest is the CDN exclusion block exactly as the API carries
// it, built from the table the classifier consults. Feeding the fixture from the
// real table is what makes the rendering assertions about the shipped set rather
// than about a copy invented here.
func policyCDNPayloadForTest(t *testing.T) string {
	t.Helper()
	entries, err := geodb.CDNExclusions()
	if err != nil {
		t.Fatalf("read the classifier's CDN exclusion set: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the classifier excludes no CDN network; the rendering fixture would be vacuous")
	}
	encoded, err := json.Marshal(map[string]any{
		"source":  geodb.CDNExclusionSource,
		"entries": entries,
	})
	if err != nil {
		t.Fatalf("encode the CDN exclusion payload: %v", err)
	}
	return string(encoded)
}

// policyRecordScript is the API double's default answer: a disabled record with
// a chosen preset, plus the runtime snapshot and counters the status block reads.
func policyRecordScript(t *testing.T, enabled bool, preset string) string {
	t.Helper()
	return fmt.Sprintf(`
const cdn = %s;
const record = () => ({enabled: %t, preset: '%s', custom_urls: [], sync_interval_seconds: 21600,
  inventory_override: [],
  status: {enabled: %t, preset: '%s', domain_count: 1234, cidr_count: 56, sync_state: 'synced',
           last_success: '2026-11-14T10:00:00Z', last_error: '',
           cdn: cdn,
           inventory: {source: 'ipdeny', source_url: 'https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone',
                       retrieved_at: '2026-11-19', prefix_count: 8664, override_prefix_count: 0,
                       age_days: 1, max_age_days: 180, stale: false}}});
const stats = () => ({proxy_bytes: 2048, direct_bytes: 1048576, proxy_drops: 3, direct_drops: 0});
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return stats();
  if (url.endsWith('/api/vpn/policy')) return record();
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};`, policyCDNPayloadForTest(t), enabled, preset, enabled, preset)
}

func TestPolicyRoutingControllerInitialRender(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, "geoblock"), `
assert.equal(toggle(), false, 'the saved record is disabled, so the toggle must be off');
assert.equal(selectedPreset(), 'geoblock', 'the saved preset must be selected');
assert.equal(badge().enabled, 'false', 'a disabled record must not render an enabled badge');
assert.equal(badge().text, 'policy_status_disabled');
assert.equal(text('policyActivePreset'), 'policy_preset_geoblock');
assert.match(text('policyLastSuccess'), /\d{4}|\d{1,2}:\d{2}/, 'the last success must be a timestamp, not "never"');
assert.equal(text('policyLastError'), 'policy_none');
assert.equal(text('policyRuleCount'), '1234 domains / 56 prefixes');
assert.equal(text('policySyncState'), 'sync:synced',
  'the runtime sync-state token must be looked up in the dictionary, not printed raw');
assert.equal(text('policyProxyBytes'), '2.00 KiB');
assert.equal(text('policyDirectBytes'), '1.00 MiB');
assert.equal(text('policyProxyDrops'), '3');
assert.equal(text('policyDirectDrops'), '0');
assert.equal(w.document.getElementById('policyCustomUrlsGroup').style.display, 'none',
  'the custom URL box must stay hidden for a preset that carries no URLs');
// The inventory block reports the shipped set's own provenance and says plainly
// that no operator override is in force.
assert.equal(text('policyInventorySource'), 'ipdeny');
assert.equal(text('policyInventoryPrefixes'), '8664');
assert.equal(text('policyInventoryRetrieved'), '2026-11-19');
assert.equal(text('policyInventoryAge'), '1 d / max 180',
  'a fresh artifact reports its age against the configured bound, without the stale marker');
assert.equal(text('policyInventoryOverrideStatus'), 'policy_inventory_override_none',
  'an absent override must read as "shipped set only", not as an empty override');
assert.equal(text('policyInventoryNotice'), '', 'a usable artifact needs no warning');
assert.equal(requestsTo('/api/vpn/policy/stats', 'GET').length, 1, 'counters come from the server exactly once');
`)
}

func TestPolicyRoutingControllerSaveAccepted(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, ""), `
// The operator picks a preset and toggles the master switch on; the server
// accepts both.
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 1};
  if (url.endsWith('/api/vpn/policy') && opts.method === 'PUT') {
    return {status: 'ok', enabled: true, preset: 'russia_inside', custom_urls: [],
            sync_interval_seconds: 21600,
            policy_status: {enabled: true, preset: 'russia_inside', domain_count: 7, cidr_count: 0,
                            sync_state: 'synced', last_success: '2026-11-15T00:00:00Z', last_error: ''}};
  }
  if (url.endsWith('/api/vpn/policy')) return {enabled: false, preset: '', custom_urls: [],
    sync_interval_seconds: 21600,
    status: {enabled: false, preset: '', domain_count: 0, cidr_count: 0, sync_state: 'disabled'}};
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
w.document.getElementById('policy_preset_russia_inside').checked = true;
w.document.getElementById('policy_enabled').checked = true;
await w.savePolicySettings();
await settle();

const puts = requestsTo('/api/vpn/policy', 'PUT');
assert.equal(puts.length, 1, 'one save is exactly one PUT');
assert.deepEqual(puts[0].body, {enabled: true, preset: 'russia_inside', custom_urls: [],
                                local_entries: [], excluded_domains: [], inventory_override: [],
                                sync_interval_seconds: 21600},
  'the save payload carries the operator intent and the preserved interval');
assert.equal(alertText().state, 'success', 'an accepted save is reported as success');
assert.equal(alertText().text, 'policy_saved');
assert.equal(toggle(), true, 'the accepted record is reflected in the form');
assert.equal(badge().enabled, 'true', 'the runtime snapshot the server returned is enabled');
assert.equal(text('policyRuleCount'), '7 domains / 0 prefixes');
assert.equal(text('policyDirectDrops'), '1', 'counters are refreshed from the stats endpoint');
`)
}

func TestPolicyRoutingControllerRefusedEnableIsNotShownEnabled(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, "geoblock"), `
// The operator asks for enablement; activation is refused (missing direct
// egress). What the server is running is refreshed by a separate read; the
// operator's edit stays in the form, marked unsaved.
let putCalls = 0;
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (url.endsWith('/api/vpn/policy') && opts.method === 'PUT') {
    putCalls++;
    const err = new Error('direct egress is unavailable');
    err.status = 422;
    err.data = {error: 'activation_failed', detail: 'direct egress is unavailable'};
    throw err;
  }
  if (url.endsWith('/api/vpn/policy')) {
    return {enabled: false, preset: 'geoblock', custom_urls: [], sync_interval_seconds: 21600,
            status: {enabled: false, preset: 'geoblock', domain_count: 5, cidr_count: 0,
                     sync_state: 'error', last_success: '', last_error: 'direct egress is unavailable'}};
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
editToggle(true);
await w.savePolicySettings();
await settle();

assert.equal(putCalls, 1, 'the refused save was attempted once');
const alert = alertText();
assert.equal(alert.state, 'error', 'a refusal must be an error, never a success');
assert.ok(alert.text.indexOf('direct egress is unavailable') !== -1,
  'the backend refusal must be surfaced verbatim, got: ' + alert.text);
assert.ok(alert.text.indexOf('policy_save_kept') !== -1,
  'the banner must say the edit is still in the form and not saved');
assert.ok(alert.text.indexOf('unavailable. policy_save_kept') !== -1,
  'the server detail and the refusal must read as separate sentences, got: ' + alert.text);
assert.equal(toggle(), true, 'the refused edit stays in the form so the operator can correct it');
assert.equal(unsavedBadge().text, 'settings_unsaved', 'the card is still marked unsaved after a refusal');
assert.equal(card().getAttribute('aria-busy'), 'false');
assert.equal(w.document.getElementById('policySaveBtn').disabled, false, 'the operator can try again');
assert.equal(badge().enabled, 'false', 'the badge follows what the server runs, not the refused intent');
assert.equal(text('policyLastError'), 'direct egress is unavailable',
  'the status block must show the server-reported error');
`)
}

func TestPolicyRoutingControllerRefusedSaveRestoresLastKnownRecord(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, "antifilter_domains"), `
// The refusal happens and the follow-up status read fails too. The edit stays in
// the form, marked unsaved, and the last runtime observation stays on screen.
responder = async (url, opts) => {
  if (opts.method === 'PUT' || opts.method === 'POST') {
    const err = new Error('policy preset must be selected');
    err.status = 400;
    err.data = {error: 'validation_failed', detail: 'policy preset must be selected'};
    throw err;
  }
  throw new Error('backend unavailable');
};
editToggle(true);
await w.savePolicySettings();
await settle();

assert.ok(alertText().text.indexOf('policy preset must be selected') !== -1,
  'the validation detail must be surfaced, got: ' + alertText().text);
assert.equal(toggle(), true, 'the refused edit must stay in the form');
assert.equal(selectedPreset(), 'antifilter_domains', 'a field the operator did not touch is unchanged');
assert.equal(unsavedBadge().text, 'settings_unsaved', 'a failed status read must not clear the unsaved mark');
assert.equal(badge().enabled, 'false', 'a failed status read keeps the last runtime observation');
`)
}

func TestPolicyRoutingControllerSyncFailureAndSuccess(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, true, "russia_inside"), `
// 1. The sync fails: the server says why, and the button becomes usable again.
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/sync')) {
    const err = new Error('VPN data plane is not available');
    err.status = 503;
    err.data = {error: 'unavailable', detail: 'VPN data plane is not available'};
    throw err;
  }
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (url.endsWith('/api/vpn/policy')) {
    return {enabled: true, preset: 'russia_inside', custom_urls: [], sync_interval_seconds: 21600,
            status: {enabled: true, preset: 'russia_inside', domain_count: 5, cidr_count: 0,
                     sync_state: 'error', last_success: '', last_error: 'VPN data plane is not available'}};
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
w.document.getElementById('policySyncBtn').click();
await settle();

const failedAlert = alertText();
assert.equal(failedAlert.state, 'error');
assert.ok(failedAlert.text.indexOf('VPN data plane is not available') !== -1,
  'a failed sync must show the backend reason, got: ' + failedAlert.text);
assert.equal(w.document.getElementById('policySyncBtn').disabled, false,
  'a failed sync must leave the button usable');
assert.equal(w.document.getElementById('policySyncBtnText').textContent, 'policy_sync_btn',
  'the button label must return to its idle text');
assert.ok(w.document.getElementById('policySyncSpinner').classList.contains('hidden'),
  'the spinner must be hidden after a failed sync');
assert.ok(requestsTo('/api/vpn/policy/sync', 'POST').length === 1, 'exactly one sync was attempted');

// 2. The next sync succeeds and the status block adopts the new snapshot.
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/sync')) {
    return {status: 'ok', published: true, version: 2, generation_id: 'gen-2',
            policy_status: {enabled: true, preset: 'russia_inside', domain_count: 10, cidr_count: 4,
                            sync_state: 'synced', last_success: '2026-11-15T01:00:00Z', last_error: ''}};
  }
  if (url.endsWith('/stats')) return {proxy_bytes: 4096, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (url.endsWith('/api/vpn/policy')) return {enabled: true, preset: 'russia_inside', custom_urls: [],
    sync_interval_seconds: 21600, status: {enabled: true, preset: 'russia_inside', domain_count: 10,
    cidr_count: 4, sync_state: 'synced', last_success: '2026-11-15T01:00:00Z', last_error: ''}};
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
w.document.getElementById('policySyncBtn').click();
await settle();

assert.equal(alertText().state, 'success', 'a completed sync is reported as success');
assert.equal(alertText().text, 'policy_sync_ok');
assert.equal(text('policyRuleCount'), '10 domains / 4 prefixes', 'the status block adopts the new snapshot');
assert.equal(text('policyLastError'), 'policy_none', 'a recovered sync clears the reported error');
assert.equal(text('policyProxyBytes'), '4.00 KiB', 'counters are re-read after a successful sync');
`)
}

func TestPolicyRoutingControllerCustomURLPayload(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, "custom"), `
// The custom preset is the only one that sends URLs; the list is trimmed and
// blank lines are dropped. Validation itself stays server-side.
assert.equal(w.document.getElementById('policyCustomUrlsGroup').style.display, 'block',
  'the custom URL box is shown for the custom preset');
editField('policy_custom_urls',
  '  https://lists.example.com/a.lst  \n\n https://lists.example.com/b.lst \n');
editField('policy_local_entries', ' local.example \n\n 198.51.100.0/24 ');
editField('policy_excluded_domains', ' internal.api.example.com \n\n *.corp.example ');
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (url.endsWith('/api/vpn/policy') && opts.method === 'PUT') {
    const err = new Error('custom URL 1 rejected: scheme must be https');
    err.status = 400;
    err.data = {error: 'validation_failed', detail: 'custom URL 1 rejected: scheme must be https'};
    throw err;
  }
  if (url.endsWith('/api/vpn/policy')) {
    return {enabled: false, preset: 'custom', custom_urls: ['https://lists.example.com/a.lst'],
            sync_interval_seconds: 21600, status: {enabled: false, sync_state: 'disabled'}};
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
await w.savePolicySettings();
await settle();

const puts = requestsTo('/api/vpn/policy', 'PUT');
assert.equal(puts.length, 1, 'one save is exactly one PUT');
assert.deepEqual(puts[0].body.custom_urls,
  ['https://lists.example.com/a.lst', 'https://lists.example.com/b.lst'],
  'the payload carries the operator URLs, trimmed, in order');
assert.deepEqual(puts[0].body.local_entries,
  ['local.example', '198.51.100.0/24'],
  'the payload carries local entries in order; blank/comment handling stays server-side');
assert.deepEqual(puts[0].body.excluded_domains,
  ['internal.api.example.com', '*.corp.example'],
  'the payload carries excluded domains, trimmed and without blank lines');
assert.ok(alertText().text.indexOf('scheme must be https') !== -1,
  'the server validation detail is surfaced, got: ' + alertText().text);
// A rejected entry is not stored, and it is not discarded either: the operator's
// text is still in the box so the URL can be corrected.
assert.equal(w.document.getElementById('policy_custom_urls').value,
  '  https://lists.example.com/a.lst  \n\n https://lists.example.com/b.lst \n',
  'the refused input stays in the editor');
assert.equal(unsavedBadge().text, 'settings_unsaved');
`)
}

// TestPolicyRoutingControllerSingleFlight covers the guard that keeps one save
// and one sync in flight. Disabling the button is not enough on its own: pressing
// Enter in the form reaches the submit handler while the button is already done.
func TestPolicyRoutingControllerSingleFlight(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, "geoblock"), `
let putCalls = 0;
let syncCalls = 0;
const accepted = () => ({status: 'ok', enabled: true, preset: 'geoblock', custom_urls: [],
  sync_interval_seconds: 21600,
  policy_status: {enabled: true, preset: 'geoblock', domain_count: 1, cidr_count: 0,
                  sync_state: 'synced', last_success: '2026-11-15T00:00:00Z', last_error: ''}});
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (url.endsWith('/api/vpn/policy/sync')) {
    syncCalls++;
    await new Promise(resolve => setTimeout(resolve, 10));
    return {status: 'ok', published: true,
            policy_status: {enabled: true, preset: 'geoblock', sync_state: 'synced'}};
  }
  if (url.endsWith('/api/vpn/policy') && opts.method === 'PUT') {
    putCalls++;
    await new Promise(resolve => setTimeout(resolve, 10));
    return accepted();
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};

const firstSave = w.savePolicySettings();
assert.equal(await w.savePolicySettings(), null, 'a save while one is in flight must be ignored');
await firstSave;
await settle();
assert.equal(putCalls, 1, 'two submits must not become two PUTs');
// Busy is a property of the card, not of one button (SET2-15).
assert.equal(w.document.getElementById('policyRoutingCard').getAttribute('aria-busy'), 'false',
  'the busy announcement must be cleared when the request ends');

const firstSync = w.syncPolicy();
assert.equal(await w.syncPolicy(), null, 'a sync while one is in flight must be ignored');
await firstSync;
await settle();
assert.equal(syncCalls, 1, 'two sync requests must not become two POSTs');
`)
}

// TestPolicyRoutingControllerSaveBlockedUntilRecordLoads is the F679-01
// regression. With the stored record still unread the form holds markup defaults
// (switch off, interval blank), so a save would persist `enabled:false` and
// `sync_interval_seconds:0` over an existing enabled policy. Nothing may reach the
// server before the read succeeds, and the release of that read may not be undone.
func TestPolicyRoutingControllerSaveBlockedUntilRecordLoads(t *testing.T) {
	runPolicyControllerScenario(t, `
let releaseInitial = null;
const initialGate = new Promise(resolve => { releaseInitial = resolve; });
// The stored record is enabled and carries a non-default refresh interval.
let stored = {enabled: true, preset: 'geoblock', custom_urls: [], sync_interval_seconds: 7200,
  status: {enabled: true, preset: 'geoblock', sync_state: 'synced', domain_count: 9, cidr_count: 1,
           last_success: '2026-11-15T00:00:00Z', last_error: ''}};
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (opts.method === 'PUT') {
    const body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body;
    stored = Object.assign({}, body,
      {status: {enabled: body.enabled, preset: body.preset, sync_state: 'disabled'}});
    return Object.assign({}, stored, {status: 'ok', policy_status: stored.status});
  }
  // The first read is held: the record has not reached the form yet.
  const held = JSON.parse(JSON.stringify(stored));
  await initialGate;
  return held;
};
`, `
assert.equal(toggle(), false, 'the switch must not claim anything before the record loads');
assert.equal(w.document.getElementById('policySaveBtn').disabled, true,
  'Save must be inert until the stored record has been read');
assert.equal(w.document.getElementById('policyRoutingForm').getAttribute('data-policy-ready'), 'false',
  'the section must advertise that it is not ready');

// The operator picks a preset and clicks the real control.
w.document.getElementById('policy_preset_geoblock').checked = true;
w.document.getElementById('policySaveBtn').click();
await settle();
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0,
  'a save before the record loads must not reach the server at all');
assert.equal(stored.enabled, true, 'the stored enabled policy must survive the attempt');
assert.equal(stored.sync_interval_seconds, 7200, 'the stored interval must survive the attempt');

// The gate is not just a disabled attribute: a direct call is refused as well.
assert.equal(await w.savePolicySettings(), null,
  'the controller must refuse to save before it is ready');
await settle();
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0, 'no request may escape the gate');
assert.ok(alertText().text.indexOf('policy_not_ready') !== -1,
  'the refusal must say that saving waits for the load, got: ' + alertText().text);

// Releasing the read loads the stored record and opens the gate.
releaseInitial();
await settle();
assert.equal(toggle(), true, 'the loaded record is the stored enabled one');
assert.equal(selectedPreset(), 'geoblock');
assert.equal(badge().enabled, 'true', 'the runtime snapshot arrived with the record');
assert.equal(w.document.getElementById('policyRoutingForm').getAttribute('data-policy-ready'), 'true');
// A loaded record is the saved state, so nothing is staged and Save stays
// disabled until the operator changes something (SET2-12).
assert.equal(w.document.getElementById('policySaveBtn').disabled, true, 'a clean card does not commit');
editField('policy_local_entries', 'local.example');
assert.equal(w.document.getElementById('policySaveBtn').disabled, false, 'an edited, loaded card can commit');

// Ordinary post-load control: the accepted save still works, and it carries the
// loaded non-default interval instead of resetting it.
w.document.getElementById('policySaveBtn').click();
await settle();
const puts = requestsTo('/api/vpn/policy', 'PUT');
assert.equal(puts.length, 1, 'one post-load save is exactly one PUT');
assert.equal(puts[0].body.enabled, true);
assert.equal(puts[0].body.preset, 'geoblock');
assert.equal(puts[0].body.sync_interval_seconds, 7200,
  'the loaded non-default interval must be preserved, not reset to 0');
assert.equal(alertText().state, 'success');
`)
}

// TestPolicyRoutingControllerFailedRecoveryKeepsRuntimeState is the F679-02
// regression. Storage keeps `enabled:true` when activation failed at startup, so
// persisted intent is not evidence that the runtime is on: a failed recovery read
// must keep the last runtime observation and its diagnostic.
func TestPolicyRoutingControllerFailedRecoveryKeepsRuntimeState(t *testing.T) {
	runPolicyControllerScenario(t, `
let offline = false;
const stored = () => ({enabled: true, preset: 'geoblock', custom_urls: [],
  sync_interval_seconds: 7200,
  status: {enabled: false, preset: 'geoblock', sync_state: 'error', domain_count: 0, cidr_count: 0,
           last_success: '', last_error: 'activation failed: list source unavailable'}});
responder = async (url) => {
  if (offline) throw new TypeError('Failed to fetch');
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  return stored();
};
`, `
assert.equal(toggle(), true, 'stored intent stays enabled through the failed activation');
assert.equal(badge().enabled, 'false', 'the badge follows the runtime, not the stored intent');
assert.equal(text('policyLastError'), 'activation failed: list source unavailable');

// The panel becomes unreachable: the save and its recovery read both fail.
offline = true;
await w.savePolicySettings();
await settle();
assert.equal(alertText().state, 'error', 'the failed save is still reported');
assert.equal(badge().enabled, 'false',
  'a failed recovery read must not synthesize Enabled from stored intent');
assert.equal(text('policyLastError'), 'activation failed: list source unavailable',
  'the known activation diagnostic must survive the failed read');
assert.equal(toggle(), true, 'the form is restored to the last accepted record');

// A successful reload is still the authority for both facts.
offline = false;
await w.loadPolicySettings();
await settle();
assert.equal(badge().enabled, 'false');
assert.equal(text('policySyncState'), 'sync:error');

// Ordinary control: a fresh observation that reports an active runtime.
responder = async (url) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  return {enabled: true, preset: 'geoblock', custom_urls: [], sync_interval_seconds: 7200,
          status: {enabled: true, preset: 'geoblock', sync_state: 'synced', domain_count: 5,
                   cidr_count: 0, last_success: '2026-11-15T02:00:00Z', last_error: ''}};
};
await w.loadPolicySettings();
await settle();
assert.equal(badge().enabled, 'true', 'a fresh snapshot still drives the badge');
assert.equal(text('policyLastError'), 'policy_none');
`)
}

// TestPolicyRoutingControllerRuntimeSnapshotShapeIsStrict pins the response-shape
// rule: GET carries the runtime as `status`, a successful PUT as `policy_status`,
// and a PUT's `status:"ok"` is a result code that must never be read as a runtime
// observation.
func TestPolicyRoutingControllerRuntimeSnapshotShapeIsStrict(t *testing.T) {
	runPolicyControllerScenario(t, `
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (opts.method === 'PUT') {
    // Management-only deployment: the record saves, but there is no runtime to
    // observe, so the only status field in the answer is the result code.
    return {status: 'ok', enabled: true, preset: 'geoblock', custom_urls: [],
            sync_interval_seconds: 7200};
  }
  return {enabled: false, preset: 'geoblock', custom_urls: [], sync_interval_seconds: 7200};
};
`, `
assert.equal(badge().enabled, 'unknown',
  'without a runtime snapshot the badge must not repeat the stored intent');
assert.equal(badge().text, 'policy_status_unknown');

w.document.getElementById('policy_enabled').checked = true;
await w.savePolicySettings();
await settle();
assert.equal(alertText().state, 'success');
assert.equal(toggle(), true, 'the accepted record is applied to the form');
assert.equal(badge().enabled, 'unknown',
  'the PUT result code "ok" must not be promoted to a runtime snapshot');
`)
}

// TestPolicyRoutingControllerInventoryOverride covers the operator override
// surface (issue #920): the textarea is populated from the stored record, the
// save carries the edited list, and the status distinguishes an operator override
// from the shipped set, including a stale artifact and an unusable one.
func TestPolicyRoutingControllerInventoryOverride(t *testing.T) {
	runPolicyControllerScenario(t, `
const recordWith = (inventory) => ({
  enabled: false, preset: 'aggregate', custom_urls: [], sync_interval_seconds: 21600,
  inventory_override: ['203.0.113.0/24'],
  status: {enabled: false, preset: 'aggregate', domain_count: 0, cidr_count: 0,
           sync_state: 'disabled', last_success: '', last_error: '', inventory: inventory}
});
const shipped = {source: 'ipdeny', retrieved_at: '2026-11-19', prefix_count: 8664,
                 sha256: 'a115697bb8ca', override_prefix_count: 0, age_days: 2,
                 max_age_days: 180, stale: false};
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  if (url.endsWith('/api/vpn/policy') && opts.method === 'PUT') {
    return {status: 'ok', enabled: false, preset: 'aggregate', custom_urls: [],
            inventory_override: ['198.51.100.0/24', '203.0.113.0/24'],
            sync_interval_seconds: 21600,
            policy_status: recordWith(Object.assign({}, shipped, {
              override_prefix_count: 2, override_sha256: 'deadbeefcafe1234', age_days: 200, stale: true
            })).status};
  }
  return recordWith(shipped);
};
`, `
// The stored override is shown as stored, never as an empty box.
assert.equal(w.document.getElementById('policy_inventory_override').value, '203.0.113.0/24',
  'the override textarea is populated from the record');
assert.equal(text('policyInventoryOverrideStatus'), 'policy_inventory_override_none');
assert.equal(text('policyInventoryAge'), '2 d / max 180');
assert.equal(text('policyInventoryNotice'), '');

// The operator replaces it; the payload carries the edited list, and the answer
// renders the accepted override beside the shipped set, with the stale marker the
// server reported and the digest that distinguishes two overrides of equal size.
editField('policy_inventory_override', ' 198.51.100.0/24 \n\n 203.0.113.0/24 ');
await w.savePolicySettings();
await settle();

const puts = requestsTo('/api/vpn/policy', 'PUT');
assert.equal(puts.length, 1, 'one save is exactly one PUT');
assert.deepEqual(puts[0].body.inventory_override, ['198.51.100.0/24', '203.0.113.0/24'],
  'the payload carries the override prefixes, trimmed and without blank lines');
assert.equal(text('policyInventoryPrefixes'), '8664',
  'the shipped prefix count stays the shipped count while an override is in force');
assert.equal(text('policyInventoryOverrideStatus'), 'OVERRIDE 2 · deadbeefcafe',
  'the override is reported beside the shipped set, identified by its digest');
assert.equal(text('policyInventoryAge'), '200 d / max 180 · policy_inventory_stale',
  'a stale artifact is marked stale, not presented as current');
`)
}

// TestPolicyRoutingControllerInventoryUnusable keeps the broken-artifact case
// visible: an operator who sees an empty grid cannot tell "no data" from "the set
// is broken and address-based direct routing is unavailable".
func TestPolicyRoutingControllerInventoryUnusable(t *testing.T) {
	runPolicyControllerScenario(t, `
responder = async (url) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  return {enabled: false, preset: 'geoblock', custom_urls: [], sync_interval_seconds: 21600,
          status: {enabled: false, preset: 'geoblock', domain_count: 0, cidr_count: 0,
                   sync_state: 'disabled', last_error: '',
                   inventory: {error: 'inventory provenance does not match the committed data',
                               prefix_count: 0, max_age_days: 180}}};
};
`, `
assert.equal(text('policyInventoryPrefixes'), '0',
  'an unusable artifact reports no usable prefix count');
assert.equal(text('policyInventoryNotice'), 'policy_inventory_unusable inventory provenance does not match the committed data',
  'the reported error is shown, so a broken set does not read as an empty one');
`)
}

// TestPolicyRoutingControllerCDNExclusions covers the CDN exclusion block (issue
// #934): the section must list the set the classifier actually consults, entry by
// entry, with the source it was read from. The fixture payload is the real table,
// so an entry the surface drops is an entry an operator would not see.
func TestPolicyRoutingControllerCDNExclusions(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, "russia_inside"), fmt.Sprintf(`
const expected = %s;
const rows = w.document.querySelectorAll('#policyCdnEntries li');
assert.equal(text('policyCdnSource'), expected.source,
  'the block must name where the set comes from');
assert.equal(text('policyCdnCount'), String(expected.entries.length),
  'the count must be the number of networks the classifier excludes');
assert.equal(rows.length, expected.entries.length,
  'every excluded network the server reported must be listed');
for (let i = 0; i < expected.entries.length; i++) {
  const entry = expected.entries[i];
  assert.ok(rows[i].textContent.indexOf(entry.provider) !== -1,
    'entry ' + i + ' must name its provider, got: ' + rows[i].textContent);
  assert.ok(rows[i].textContent.indexOf('AS' + entry.asn) !== -1,
    'entry ' + i + ' must name its ASN, got: ' + rows[i].textContent);
}
assert.equal(text('policyCdnNotice'), '', 'a usable set carries no warning');
`, policyCDNPayloadForTest(t)))
}

// TestPolicyRoutingControllerCDNExclusionsEmptyAndUnusable keeps the two honest
// failure shapes apart: a set that is genuinely empty (every CDN destination is
// proxied) must not read as a set that could not be reported, and the other way
// round. Neither may be rendered as an invented count.
func TestPolicyRoutingControllerCDNExclusionsEmptyAndUnusable(t *testing.T) {
	runPolicyControllerScenario(t, `
const recordWith = (cdn) => ({enabled: false, preset: 'geoblock', custom_urls: [],
  sync_interval_seconds: 21600,
  status: {enabled: false, preset: 'geoblock', domain_count: 0, cidr_count: 0,
           sync_state: 'disabled', cdn: cdn}});
let answer = () => recordWith({source: 'geodb.KnownCDNASNs', entries: []});
responder = async (url) => {
  if (url.endsWith('/stats')) return {proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0};
  return answer();
};
`, `
// 1. The set is reported and empty.
assert.equal(text('policyCdnCount'), '0',
  'an empty exclusion set has a count of zero, not a blank');
assert.equal(text('policyCdnEntries'), 'policy_cdn_empty',
  'an empty set must say that the classifier excludes nothing');
assert.equal(text('policyCdnNotice'), '', 'an empty set is not an error');

// 2. The set cannot be described: the count is unknown, not zero, and the server
// reason is shown so the block does not read as "nothing is excluded".
answer = () => recordWith({source: 'geodb.KnownCDNASNs',
  error: 'CDN exclusion entry is unusable: AS0 ""'});
await w.loadPolicySettings();
await settle();
assert.equal(text('policyCdnCount'), '-',
  'an unusable set has no count to report; zero would be a claim the server did not make');
assert.equal(text('policyCdnEntries'), 'policy_cdn_unavailable',
  'an unusable set must not render as an empty list');
assert.equal(text('policyCdnNotice'), 'policy_cdn_unusable CDN exclusion entry is unusable: AS0 ""',
  'the server reason must be shown, so the failure is diagnosable');
`)
}

// TestPolicyRoutingModuleElementIDs guards the wiring between the module and the
// template: every id the controller looks up must exist in the rendered section.
func TestPolicyRoutingModuleElementIDs(t *testing.T) {
	module, err := StaticFS.ReadFile("static/js/policy_routing.js")
	if err != nil {
		t.Fatalf("read policy controller: %v", err)
	}
	section := policySectionHTMLForTest(t)

	lookup := regexp.MustCompile(`(?:policyElement|setPolicyElementText)\('([A-Za-z0-9_]+)'`)
	matches := lookup.FindAllStringSubmatch(string(module), -1)
	if len(matches) < 10 {
		t.Fatalf("found only %d element lookups in the controller; the extraction is wrong", len(matches))
	}
	seen := map[string]bool{}
	for _, match := range matches {
		id := match[1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if !strings.Contains(section, `id="`+id+`"`) {
			t.Errorf("controller looks up #%s, which the rendered policy section does not define", id)
		}
	}
}
