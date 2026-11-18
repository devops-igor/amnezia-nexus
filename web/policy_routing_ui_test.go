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
	tmpl, err := template.New("settings_policy.html").Funcs(funcs).ParseFS(TemplatesFS, "templates/settings_policy.html")
	if err != nil {
		t.Fatalf("parse settings_policy.html: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "settings_policy", map[string]any{"current_user": nil}); err != nil {
		t.Fatalf("render settings_policy: %v", err)
	}
	if !strings.Contains(buf.String(), `id="policyRoutingForm"`) {
		t.Fatal("rendered policy section does not contain the form; the fixture is wrong")
	}
	return buf.String()
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
const alertText = () => {
  const el = w.document.getElementById('policyAlert');
  return {text: el.textContent, state: el.getAttribute('data-state'), display: el.style.display};
};
const toggle = () => w.document.getElementById('policy_enabled').checked;
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
`, string(encodedModule), string(encodedSection), prelude, scenario)
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

// policyRecordScript is the API double's default answer: a disabled record with
// a chosen preset, plus the runtime snapshot and counters the status block reads.
func policyRecordScript(enabled bool, preset string) string {
	return fmt.Sprintf(`
const record = () => ({enabled: %t, preset: '%s', custom_urls: [], sync_interval_seconds: 21600,
  status: {enabled: %t, preset: '%s', domain_count: 1234, cidr_count: 56, sync_state: 'synced',
           last_success: '2026-11-14T10:00:00Z', last_error: ''}});
const stats = () => ({proxy_bytes: 2048, direct_bytes: 1048576, proxy_drops: 3, direct_drops: 0});
responder = async (url, opts) => {
  if (url.endsWith('/stats')) return stats();
  if (url.endsWith('/api/vpn/policy')) return record();
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};`, enabled, preset, enabled, preset)
}

func TestPolicyRoutingControllerInitialRender(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock"), `
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
assert.equal(requestsTo('/api/vpn/policy/stats', 'GET').length, 1, 'counters come from the server exactly once');
`)
}

func TestPolicyRoutingControllerSaveAccepted(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, ""), `
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
                                local_entries: [], sync_interval_seconds: 21600},
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
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock"), `
// The operator asks for enablement; activation is refused (missing direct
// egress). The reload afterwards returns the record the server kept.
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
w.document.getElementById('policy_enabled').checked = true;
await w.savePolicySettings();
await settle();

assert.equal(putCalls, 1, 'the refused save was attempted once');
const alert = alertText();
assert.equal(alert.state, 'error', 'a refusal must be an error, never a success');
assert.ok(alert.text.indexOf('direct egress is unavailable') !== -1,
  'the backend refusal must be surfaced verbatim, got: ' + alert.text);
assert.ok(alert.text.indexOf('policy_save_refused') !== -1,
  'the banner must state that the form was reloaded from the saved configuration');
assert.ok(alert.text.indexOf('unavailable. policy_save_refused') !== -1,
  'the server detail and the refusal must read as separate sentences, got: ' + alert.text);
assert.equal(toggle(), false, 'a refused enablement must not remain visible as enabled');
assert.equal(badge().enabled, 'false', 'the badge must follow the server, not the refused intent');
assert.equal(text('policyLastError'), 'direct egress is unavailable',
  'the status block must show the server-reported error');
`)
}

func TestPolicyRoutingControllerRefusedSaveRestoresLastKnownRecord(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "antifilter_domains"), `
// The refusal happens and the follow-up read fails too. The form must fall back
// to the last record the server returned instead of keeping the refused intent.
responder = async (url, opts) => {
  if (opts.method === 'PUT' || opts.method === 'POST') {
    const err = new Error('policy preset must be selected');
    err.status = 400;
    err.data = {error: 'validation_failed', detail: 'policy preset must be selected'};
    throw err;
  }
  throw new Error('backend unavailable');
};
w.document.getElementById('policy_enabled').checked = true;
await w.savePolicySettings();
await settle();

assert.ok(alertText().text.indexOf('policy preset must be selected') !== -1,
  'the validation detail must be surfaced, got: ' + alertText().text);
assert.equal(toggle(), false, 'the toggled intent must be rolled back to the last server record');
assert.equal(selectedPreset(), 'antifilter_domains', 'the last server preset must be restored');
`)
}

func TestPolicyRoutingControllerSyncFailureAndSuccess(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(true, "russia_inside"), `
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
	runPolicyControllerScenario(t, policyRecordScript(false, "custom"), `
// The custom preset is the only one that sends URLs; the list is trimmed and
// blank lines are dropped. Validation itself stays server-side.
assert.equal(w.document.getElementById('policyCustomUrlsGroup').style.display, 'block',
  'the custom URL box is shown for the custom preset');
w.document.getElementById('policy_custom_urls').value =
  '  https://lists.example.com/a.lst  \n\n https://lists.example.com/b.lst \n';
w.document.getElementById('policy_local_entries').value = ' local.example \n\n 198.51.100.0/24 ';
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
  ['local.example', '', '198.51.100.0/24'],
  'the payload carries local entries in order; blank/comment handling stays server-side');
assert.ok(alertText().text.indexOf('scheme must be https') !== -1,
  'the server validation detail is surfaced, got: ' + alertText().text);
// The reload returns the stored record, so a rejected entry is not shown as saved.
assert.equal(w.document.getElementById('policy_custom_urls').value,
  'https://lists.example.com/a.lst', 'the textarea is reloaded from the saved record');
`)
}

// TestPolicyRoutingControllerSingleFlight covers the guard that keeps one save
// and one sync in flight. Disabling the button is not enough on its own: pressing
// Enter in the form reaches the submit handler while the button is already done.
func TestPolicyRoutingControllerSingleFlight(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock"), `
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
assert.equal(w.document.getElementById('policySaveBtn').getAttribute('aria-busy'), 'false',
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
assert.equal(w.document.getElementById('policySaveBtn').disabled, false);
assert.equal(w.document.getElementById('policyRoutingForm').getAttribute('data-policy-ready'), 'true');

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

// TestPolicyRoutingModuleElementIDs guards the wiring between the module and the
// template: every id the controller looks up must exist in the rendered section.
func TestPolicyRoutingModuleElementIDs(t *testing.T) {
	module, err := StaticFS.ReadFile("static/js/policy_routing.js")
	if err != nil {
		t.Fatalf("read policy controller: %v", err)
	}
	section := policySectionHTMLForTest(t)

	lookup := regexp.MustCompile(`policyElement\('([A-Za-z0-9_]+)'\)`)
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
