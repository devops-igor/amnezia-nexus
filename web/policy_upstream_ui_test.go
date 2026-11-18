package web

// Behavioural JSDOM coverage for the upstream resolver editor (#865).
//
// The assertions run static/js/policy_upstream.js — read through StaticFS, i.e.
// the asset the browser loads — against the section markup rendered from
// templates/settings_policy_upstream.html. Nothing is re-implemented here: the
// module is evaluated as-is and driven through its exported entry points and the
// DOM the template produces.
//
// Scope of this file, stated because it matters: the section is NOT yet included
// by web/templates/settings.html and the partial is NOT yet registered in the
// handler template loader, so the shipped settings page does not render it and no
// translation dictionary defines its keys. The page-level integration and the
// five dictionaries are a separate, serialized step. What is proven here is the
// module itself: it renders from the real template, refuses to write before an
// authoritative read, echoes the fresh record, refuses a concurrent change,
// verifies the server's answer and reports the runtime as an observation.
//
// The cases are paired on purpose. Alongside "a save is accepted" there is "a
// stale read must not replace an accepted save", and alongside "the list is
// adopted" there is "an answer that lost a pin is not a success".

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
)

// upstreamTranslations loads the shipped English dictionary through the embedded
// filesystem, i.e. the wording the page actually resolves. The module tests must not
// carry a private copy of it: a key that is missing from the real dictionary has to
// fail here, not in production.
func upstreamTranslations(t *testing.T) map[string]string {
	t.Helper()
	raw, err := TranslationsFS.ReadFile("translations/en.json")
	if err != nil {
		t.Fatalf("read en.json: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("parse en.json: %v", err)
	}
	if len(dict) < 100 {
		t.Fatalf("en.json parsed to %d keys; the extraction is wrong", len(dict))
	}
	return dict
}

// upstreamFailureKindTokens is the resolver's closed failure-kind set, as the
// backend defines it. The controller resolves a token through this set and shows
// anything outside it verbatim.
var upstreamFailureKindTokens = []string{
	"timeout", "network", "servfail", "invalid_response", "tls_handshake",
	"certificate", "pin_mismatch", "http_status", "redirect", "content_type",
	"response_too_large",
}

// upstreamSectionHTMLForTest renders the isolated partial with the template
// helpers the page provides and the translation fixture. A key the fixture does
// not define renders as MISSING:<key>, which fails the test instead of silently
// producing an empty label.
func upstreamSectionHTMLForTest(t *testing.T) string {
	t.Helper()
	translations := upstreamTranslations(t)
	funcs := template.FuncMap{
		"_": func(key string) string {
			if value, ok := translations[key]; ok && strings.TrimSpace(value) != "" {
				return value
			}
			return "MISSING:" + key
		},
		"is_admin": func(user any) bool { return true },
	}
	tmpl, err := template.New("settings_policy_upstream.html").Funcs(funcs).
		ParseFS(TemplatesFS, "templates/settings_policy_upstream.html", "templates/settings_save_controls.html")
	if err != nil {
		t.Fatalf("parse settings_policy_upstream.html: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "settings_policy_upstream", map[string]any{"current_user": nil}); err != nil {
		t.Fatalf("render settings_policy_upstream: %v", err)
	}
	rendered := buf.String()
	if idx := strings.Index(rendered, "MISSING:"); idx >= 0 {
		end := idx + 60
		if end > len(rendered) {
			end = len(rendered)
		}
		t.Fatalf("the section uses a translation key the fixture does not define: %q", rendered[idx:end])
	}
	if !strings.Contains(rendered, `id="policyUpstreamForm"`) {
		t.Fatal("rendered upstream section does not contain the form; the fixture is wrong")
	}
	return rendered
}

// upstreamHarness builds a JSDOM window with the shipped module and the rendered
// section. `prelude` installs the API double before the initial load; `scenario`
// runs after that load has settled. Every scenario also asserts that the
// controller asked for no translation key outside the fixture, so a typo in a
// runtime key cannot hide behind a stub that echoes whatever it is given.
func upstreamHarness(t *testing.T, prelude, scenario string) string {
	t.Helper()

	module, err := StaticFS.ReadFile("static/js/policy_upstream.js")
	if err != nil {
		t.Fatalf("read upstream controller: %v", err)
	}
	encodedModule, err := json.Marshal(string(module))
	if err != nil {
		t.Fatalf("encode module: %v", err)
	}
	encodedCards := settingsCardsModuleForTest(t)
	encodedSection, err := json.Marshal(upstreamSectionHTMLForTest(t))
	if err != nil {
		t.Fatalf("encode section: %v", err)
	}
	dict, err := json.Marshal(upstreamTranslations(t))
	if err != nil {
		t.Fatalf("encode translations: %v", err)
	}

	return jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="policyUpstreamFixtureHost"></div>', {runScripts:'outside-only'});
const w = dom.window;
const DICT = %s;
const PIN = 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=';

// Every key resolves through the fixture. An unknown key is recorded and the
// scenario fails at the end, which is what stops the stub from hiding a key the
// section uses but no dictionary defines yet.
const missingKeys = [];
w._ = key => {
  if (!Object.prototype.hasOwnProperty.call(DICT, key)) {
    missingKeys.push(key);
    return key;
  }
  return DICT[key];
};

// calls records method, URL and body of every request, so the payload and the
// read-before-write ordering are asserted rather than inferred.
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
const requestsTo = method => calls.filter(c => c.method === method);
const text = id => w.document.getElementById(id).textContent;
const visible = id => !w.document.getElementById(id).classList.contains('hidden');
const rowNodes = () => Array.from(w.document.querySelectorAll('#policyUpstreamRows [data-upstream-role="row"]'));
const rows = () => rowNodes().map(node => ({
  address: node.querySelector('[data-upstream-field="address"]').value,
  port: node.querySelector('[data-upstream-field="port"]').value,
  transport: node.querySelector('[data-upstream-field="transport"]').value,
  pin: node.querySelector('[data-upstream-field="pin"]').value
}));
const setField = (index, name, value) => {
  const el = rowNodes()[index].querySelector('[data-upstream-field="' + name + '"]');
  el.value = value;
  el.dispatchEvent(new w.Event('input', {bubbles: true}));
  el.dispatchEvent(new w.Event('change', {bubbles: true}));
};
const clickRow = (index, action) => rowNodes()[index].querySelector('[data-upstream-action="' + action + '"]').click();
const alertState = () => {
  const el = w.document.getElementById('policyUpstreamAlert');
  return {text: el.textContent, state: el.getAttribute('data-state'), display: el.style.display};
};
const saveBtn = () => w.document.getElementById('policyUpstreamSaveBtn');
const cardNode = () => w.document.getElementById('policyUpstreamCard');
const unsavedText = () => cardNode().querySelector('[data-dirty]').textContent;
const formReady = () => w.document.getElementById('policyUpstreamForm').getAttribute('data-upstream-ready');
const record = (list, extra) => Object.assign({
  enabled: false, preset: 'geoblock', custom_urls: [], sync_interval_seconds: 21600,
  upstream_dns: list, status: {enabled: false, preset: 'geoblock'}
}, extra || {});

(async () => {
w.eval(%s);
w.eval(%s);
assert.equal(w.PolicyUpstreamEditor.init(), false, 'init must be inert without the section');

w.document.getElementById('policyUpstreamFixtureHost').innerHTML = %s;

// The API double must answer the initial load as well, so it is installed first.
%s

assert.equal(w.PolicyUpstreamEditor.init(), true, 'init must wire the rendered section');
await settle();

%s

assert.deepEqual(missingKeys, [], 'the controller used a translation key outside the fixture');
console.log('UPSTREAM_SCENARIO_OK');
dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(dict), string(encodedCards), string(encodedModule), string(encodedSection), prelude, scenario)
}

// runUpstreamScenario executes one scenario and fails the test with the Node
// output attached when the script does not report success.
func runUpstreamScenario(t *testing.T, prelude, scenario string) string {
	t.Helper()
	node := requireJSDOM(t)
	out, err := execNodeScript(node, upstreamHarness(t, prelude, scenario))
	if err != nil || !strings.Contains(string(out), "UPSTREAM_SCENARIO_OK") {
		t.Fatalf("upstream editor scenario failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestPolicyUpstreamSectionUsesShippedDictionaryKeys pins the two consumers of the
// wording: every template key and every runtime key the controller can resolve must
// exist in the shipped English dictionary.
func TestPolicyUpstreamSectionUsesShippedDictionaryKeys(t *testing.T) {
	dict := upstreamTranslations(t)
	partial, err := TemplatesFS.ReadFile("templates/settings_policy_upstream.html")
	if err != nil {
		t.Fatalf("read settings_policy_upstream.html: %v", err)
	}
	if got := strings.Count(string(partial), `{{ _ "`); got < 20 {
		t.Fatalf("found only %d translation lookups in the partial; the extraction is wrong", got)
	}
	for _, chunk := range strings.Split(string(partial), `{{ _ "`)[1:] {
		key := chunk
		if idx := strings.Index(key, `"`); idx >= 0 {
			key = key[:idx]
		}
		// save_changes is the one commit label shared by every settings card, so
		// it is the single key allowed outside the section's own namespace.
		if key != "save_changes" && !strings.HasPrefix(key, "policy_upstream_") {
			t.Errorf("the section uses key %q outside its own namespace", key)
			continue
		}
		if strings.TrimSpace(dict[key]) == "" {
			t.Errorf("en.json does not define %q used by the section template", key)
		}
	}

	module, err := StaticFS.ReadFile("static/js/policy_upstream.js")
	if err != nil {
		t.Fatalf("read upstream controller: %v", err)
	}
	lookup := regexp.MustCompile(`'policy_upstream_[a-z0-9_]*'`)
	seen := map[string]bool{}
	for _, match := range lookup.FindAllString(string(module), -1) {
		key := strings.Trim(match, "'")
		if seen[key] {
			continue
		}
		seen[key] = true
		if strings.HasSuffix(key, "_") {
			// A key the controller completes at run time. The closed set is the
			// backend's, so the expansion is declared here rather than guessed.
			if key != "policy_upstream_failure_" {
				t.Errorf("controller builds keys with the unhandled prefix %q", key)
				continue
			}
			for _, kind := range upstreamFailureKindTokens {
				if strings.TrimSpace(dict[key+kind]) == "" {
					t.Errorf("en.json does not define %q for failure kind %q", key+kind, kind)
				}
			}
			continue
		}
		if strings.TrimSpace(dict[key]) == "" {
			t.Errorf("en.json does not define %q used by the controller", key)
		}
	}
	if len(seen) < 15 {
		t.Fatalf("found only %d controller keys; the extraction is wrong", len(seen))
	}
}

// TestPolicyUpstreamEditorInertUntilRecordLoads is the write-gate contract: with
// the stored record unread the editor holds no rows and no baseline, so nothing
// may reach the server and the loaded entries must appear exactly as stored.
func TestPolicyUpstreamEditorInertUntilRecordLoads(t *testing.T) {
	runUpstreamScenario(t, `
let releaseInitial = null;
const initialGate = new Promise(resolve => { releaseInitial = resolve; });
const stored = () => record([
  {address: '9.9.9.9', port: 53, transport: 'plain'},
  {address: 'dns.example.com', port: 853, transport: 'dot', spki_pin: PIN},
  {address: 'dns.example.net', port: 443, transport: 'doh'}
]);
responder = async () => { const held = stored(); await initialGate; return held; };
`, `
assert.equal(saveBtn().disabled, true, 'Save must be inert until the stored record has been read');
assert.equal(formReady(), 'false', 'the section must advertise that it is not ready');
assert.equal(rowNodes().length, 0, 'no row may be shown before the record loads');

assert.equal(await w.PolicyUpstreamEditor.save(), null, 'a save before the load must be refused');
await settle();
assert.equal(requestsTo('PUT').length, 0, 'no write may escape the gate');
assert.ok(alertState().text.indexOf(DICT.policy_upstream_not_ready) !== -1,
  'the refusal must say the load is pending, got: ' + alertState().text);

releaseInitial();
await settle();
assert.equal(formReady(), 'true');
assert.equal(rowNodes().length, 3, 'every stored entry is rendered, including the one that is not queried');
assert.deepEqual(rows()[0], {address: '9.9.9.9', port: '53', transport: 'plain', pin: ''});
assert.deepEqual(rows()[1], {address: 'dns.example.com', port: '853', transport: 'dot', pin: PIN},
  'the stored pin and port are shown as stored');
assert.deepEqual(rows()[2], {address: 'dns.example.net', port: '443', transport: 'doh', pin: ''});
assert.equal(visible('policyUpstreamDefaultsNotice'), false,
  'a configured list must not claim the built-in defaults');
const notQueried = rowNodes()[2].querySelector('[data-upstream-role="not-queried"]');
assert.equal(notQueried.classList.contains('hidden'), false,
  'the third entry is stored but never queried, and that is stated plainly');
assert.equal(rowNodes()[1].querySelector('[data-upstream-role="not-queried"]').classList.contains('hidden'), true);
assert.equal(w.document.getElementById('policyUpstreamAddBtn').disabled, true,
  'three stored entries are the API maximum, so adding stops here');
assert.equal(saveBtn().disabled, true, 'a loaded record is the saved state, so a clean card does not commit');
setField(0, 'port', '54');
assert.equal(saveBtn().disabled, false, 'a read record with a preset opens the write gate once something is staged');
`)
}

// TestPolicyUpstreamEditorLoadFailureKeepsWritesDisabled is the negative control
// for the gate: an unreadable record must leave the editor read-only, not empty
// and writable.
func TestPolicyUpstreamEditorLoadFailureKeepsWritesDisabled(t *testing.T) {
	runUpstreamScenario(t, `
responder = async () => { throw new Error('backend unavailable'); };
`, `
assert.equal(saveBtn().disabled, true);
assert.equal(formReady(), 'false');
assert.ok(alertState().text.indexOf('backend unavailable') !== -1,
  'the backend reason must be surfaced, got: ' + alertState().text);
assert.ok(alertState().text.indexOf(DICT.policy_upstream_not_ready) !== -1);
assert.equal(await w.PolicyUpstreamEditor.save(), null);
assert.equal(await w.PolicyUpstreamEditor.useDefaults(), null);
await settle();
assert.equal(requestsTo('PUT').length, 0, 'nothing may be written without an authoritative read');
`)
}

// TestPolicyUpstreamEditorEmptyListIsDefaultsNotNoResolver pins the meaning of
// `[]` and the source requirement: an empty stored list is the built-in defaults,
// and a record without a preset cannot be saved at all.
func TestPolicyUpstreamEditorEmptyListIsDefaultsNotNoResolver(t *testing.T) {
	runUpstreamScenario(t, `
let stored = record([], {preset: ''});
responder = async () => stored;
`, `
assert.equal(visible('policyUpstreamDefaultsNotice'), true,
  'an empty list is the inherited default pair, so it must be named as such');
assert.equal(text('policyUpstreamDefaultsNotice'), DICT.policy_upstream_defaults_notice);
assert.equal(visible('policyUpstreamSaveEffects'), true);
assert.equal(text('policyUpstreamSaveEffectsText'), DICT.policy_upstream_needs_source);
assert.equal(saveBtn().disabled, true, 'a record with no list source cannot be saved');
assert.equal(await w.PolicyUpstreamEditor.save(), null);
assert.equal(await w.PolicyUpstreamEditor.useDefaults(), null);
await settle();
assert.equal(requestsTo('PUT').length, 0, 'the editor must not invent a preset');

stored = record([], {preset: 'geoblock'});
await w.PolicyUpstreamEditor.reload();
await settle();
assert.equal(visible('policyUpstreamSaveEffects'), false, 'a chosen list source clears the no-source notice');
assert.equal(saveBtn().disabled, true, 'nothing is staged yet, so a clean card does not commit');
assert.equal(await w.PolicyUpstreamEditor.addRow(), true);
assert.equal(rowNodes().length, 1);
setField(0, 'address', '9.9.9.9');
setField(0, 'port', '53');
assert.equal(saveBtn().disabled, false, 'a chosen list source opens the gate once a valid row is staged');
assert.equal(visible('policyUpstreamDefaultsNotice'), false, 'a row replaces the defaults notice');
`)
}

// TestPolicyUpstreamEditorSaveEchoesFreshRecord is the payload contract: the four
// fields the operator did not edit come from the fresh read, the transport is
// always explicit, a blank port is omitted so the server fills its transport
// default, and the pin travels with the encrypted entry.
func TestPolicyUpstreamEditorSaveEchoesFreshRecord(t *testing.T) {
	runUpstreamScenario(t, `
const stored = () => record(
  [{address: '94.140.14.14', port: 53, transport: 'plain'}],
  {enabled: true, preset: 'custom', custom_urls: ['https://lists.example.com/a.lst'],
   sync_interval_seconds: 7200,
   status: {enabled: true, preset: 'custom', last_upstream: '94.140.14.14:53'}}
);
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    const body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body;
    const saved = record(body.upstream_dns.map(u => Object.assign({port: 853}, u)),
      {enabled: body.enabled, preset: body.preset, custom_urls: body.custom_urls,
       sync_interval_seconds: body.sync_interval_seconds});
    return Object.assign({status: 'ok'}, saved, {
      policy_status: {enabled: true, preset: 'custom', last_upstream: 'dot://dns.example.com:853'}
    });
  }
  return stored();
};
`, `
setField(0, 'address', 'dns.example.com');
setField(0, 'transport', 'dot');
setField(0, 'pin', PIN);
setField(0, 'port', '');
assert.equal(saveBtn().disabled, false);

const savedRecord = await w.PolicyUpstreamEditor.save();
await settle();

const methods = calls.map(c => c.method);
const firstPut = methods.indexOf('PUT');
assert.ok(firstPut > 0, 'a save must read the record before it writes');
assert.equal(methods[firstPut - 1], 'GET', 'the read immediately before the PUT is the fresh one');
assert.equal(requestsTo('PUT').length, 1, 'one save is exactly one PUT');
assert.deepEqual(requestsTo('PUT')[0].body, {
  enabled: true,
  preset: 'custom',
  custom_urls: ['https://lists.example.com/a.lst'],
  sync_interval_seconds: 7200,
  upstream_dns: [{address: 'dns.example.com', transport: 'dot', spki_pin: PIN}]
}, 'the payload echoes the fresh record and omits the blank port');
assert.equal(alertState().state, 'success');
assert.equal(alertState().text, DICT.policy_upstream_saved);
assert.equal(rows()[0].port, '853', 'the server-filled default port is adopted');
assert.equal(text('policyUpstreamHealthState'),
  DICT.policy_upstream_health_last.split('{upstream}').join('dot://dns.example.com:853'));
assert.equal(savedRecord.enabled, true);
`)
}

// TestPolicyUpstreamEditorConflictSendsNoWrite covers the read-to-write window:
// the PUT replaces the whole record, so a list another writer changed since the
// load is shown and the save is refused instead of silently overwriting it.
func TestPolicyUpstreamEditorConflictSendsNoWrite(t *testing.T) {
	runUpstreamScenario(t, `
const stored = () => record([{address: '9.9.9.9', port: 53, transport: 'plain'}]);
const changed = () => record([
  {address: '8.8.8.8', port: 53, transport: 'plain'},
  {address: 'dns.example.com', port: 853, transport: 'dot'}
]);
let reads = 0;
responder = async (url, opts) => {
  if (opts.method === 'PUT') return changed();
  reads++;
  return reads === 1 ? stored() : changed();
};
`, `
setField(0, 'address', '1.1.1.1');
assert.equal(await w.PolicyUpstreamEditor.save(), null);
await settle();

assert.equal(requestsTo('PUT').length, 0, 'a changed baseline must not be overwritten');
assert.equal(alertState().state, 'error');
assert.equal(alertState().text, DICT.policy_upstream_conflict);
assert.deepEqual(rows().map(r => r.address), ['8.8.8.8', 'dns.example.com'],
  'the newer stored list is shown, not the refused edit');
`)
}

// TestPolicyUpstreamEditorLostPinIsNotASuccess is why the answer is verified: the
// server ignores unknown JSON fields silently, so a save whose pin did not land
// must be reported as a mismatch rather than as a success.
func TestPolicyUpstreamEditorLostPinIsNotASuccess(t *testing.T) {
	runUpstreamScenario(t, `
const stored = () => record([{address: 'dns.example.com', port: 853, transport: 'dot', spki_pin: PIN}]);
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    // Simulates the reply of a server that stored the row without the pin.
    return {status: 'ok', enabled: false, preset: 'geoblock', custom_urls: [],
            sync_interval_seconds: 21600,
            upstream_dns: [{address: 'dns.example.com', port: 853, transport: 'dot'}]};
  }
  return stored();
};
`, `
assert.equal(await w.PolicyUpstreamEditor.save(), null);
await settle();

assert.equal(requestsTo('PUT').length, 1);
assert.equal(alertState().state, 'error', 'a lost pin must never be reported as success');
assert.ok(alertState().text.indexOf(DICT.policy_upstream_echo_mismatch) !== -1,
  'the mismatch must be named, got: ' + alertState().text);
assert.ok(alertState().text.indexOf('row 1 pin') !== -1,
  'the mismatch must name the field, got: ' + alertState().text);
assert.equal(rows()[0].pin, '', 'the stored record is adopted as the accepted one');
`)
}

// TestPolicyUpstreamEditorRefusalKeepsTheEditedRows checks the failure path: the
// server's own wording is shown, the rows the operator typed stay in the editor,
// and the card stays marked unsaved, because the refused list was never stored.
func TestPolicyUpstreamEditorRefusalKeepsTheEditedRows(t *testing.T) {
	runUpstreamScenario(t, `
const detail = 'upstream DNS entry 1 rejected: upstream "127.0.0.1" is loopback';
let reads = 0;
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    const err = new Error(detail);
    err.status = 400;
    err.data = {error: 'validation_failed', detail: detail};
    throw err;
  }
  reads++;
  return record([{address: '9.9.9.9', port: 53, transport: 'plain'}]);
};
`, `
setField(0, 'address', '127.0.0.1');
const readsBefore = reads;
await w.PolicyUpstreamEditor.save();
await settle();

assert.equal(alertState().state, 'error');
assert.ok(alertState().text.indexOf(detail) !== -1,
  'the server refusal must be shown verbatim, got: ' + alertState().text);
assert.ok(alertState().text.indexOf(DICT.policy_upstream_save_kept) !== -1,
  'the banner must say the edit is still there and not saved, got: ' + alertState().text);
assert.equal(rows()[0].address, '127.0.0.1', 'the refused edit stays in the editor');
assert.equal(unsavedText(), DICT.settings_unsaved, 'the card is still marked unsaved after a refusal');
assert.equal(cardNode().getAttribute('aria-busy'), 'false');
assert.equal(saveBtn().disabled, false, 'the operator can correct the entry and try again');
assert.ok(reads > readsBefore, 'the runtime diagnostics are still refreshed, by a read of their own');
`)
}

// TestPolicyUpstreamEditorStateInconsistentHasItsOwnMessage pins the one refusal
// that means more than "the edit was rejected": stored and running policy may
// disagree.
func TestPolicyUpstreamEditorStateInconsistentHasItsOwnMessage(t *testing.T) {
	runUpstreamScenario(t, `
const detail = 'restoring the previous policy failed';
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    const err = new Error(detail);
    err.status = 500;
    err.data = {error: 'state_inconsistent', detail: detail};
    throw err;
  }
  return record([{address: '9.9.9.9', port: 53, transport: 'plain'}]);
};
`, `
setField(0, 'port', '8853');
await w.PolicyUpstreamEditor.save();
await settle();

assert.equal(alertState().state, 'error');
assert.ok(alertState().text.indexOf(DICT.policy_upstream_state_inconsistent) !== -1,
  'the inconsistent state needs its own message, got: ' + alertState().text);
assert.ok(alertState().text.indexOf(detail) !== -1);
assert.equal(rows()[0].port, '8853', 'the refused edit stays in the editor');
assert.equal(unsavedText(), DICT.settings_unsaved);
`)
}

// TestPolicyUpstreamEditorStaleReadCannotReplaceAcceptedSave is the ordering
// control. A read issued before an accepted save resolves after it; replaying it
// would show a list the server no longer has.
func TestPolicyUpstreamEditorStaleReadCannotReplaceAcceptedSave(t *testing.T) {
	runUpstreamScenario(t, `
const storedA = () => record([{address: '9.9.9.9', port: 53, transport: 'plain'}]);
let accepted = storedA();
let staleGate = Promise.resolve();
let holdStale = false;
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    const body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body;
    accepted = record(body.upstream_dns, {enabled: body.enabled, preset: body.preset});
    return Object.assign({status: 'ok'}, JSON.parse(JSON.stringify(accepted)));
  }
  if (holdStale) {
    holdStale = false;
    await staleGate;
    return record([{address: '1.1.1.1', port: 53, transport: 'plain'}]);
  }
  return JSON.parse(JSON.stringify(accepted));
};
`, `
let releaseStale = null;
staleGate = new Promise(resolve => { releaseStale = resolve; });
holdStale = true;
const staleReload = w.PolicyUpstreamEditor.reload();
await settle();

setField(0, 'address', '8.8.8.8');
await w.PolicyUpstreamEditor.save();
await settle();
assert.equal(rows()[0].address, '8.8.8.8');
assert.equal(requestsTo('PUT').length, 1);

releaseStale();
await staleReload;
await settle();
assert.equal(rows()[0].address, '8.8.8.8',
  'a read issued before the accepted save must not replace it');
assert.equal(alertState().state, 'success');
`)
}

// TestPolicyUpstreamEditorOrderingAndWarnings covers the list-shaped rules: row
// order and pins are preserved, the third stored row is labelled as not queried
// rather than dropped or called a backup, adding stops at the API's three stored
// entries, and a plain entry after an encrypted one is warned about.
func TestPolicyUpstreamEditorOrderingAndWarnings(t *testing.T) {
	runUpstreamScenario(t, `
const stored = () => record([
  {address: 'dns.example.com', port: 853, transport: 'dot', spki_pin: PIN},
  {address: '9.9.9.9', port: 53, transport: 'plain'},
  {address: 'dns.example.net', port: 443, transport: 'doh'}
]);
responder = async () => stored();
`, `
assert.equal(visible('policyUpstreamPlainWarning'), true, 'a plain entry must be warned about');
assert.equal(visible('policyUpstreamMixedWarning'), true,
  'a plain entry after an encrypted one must be warned about');
assert.equal(rows()[1].transport, 'plain');
assert.equal(rowNodes()[1].querySelector('[data-upstream-role="not-queried"]').classList.contains('hidden'), true,
  'the second entry is queried, so it carries no not-queried label');

assert.equal(w.document.getElementById('policyUpstreamAddBtn').disabled, true,
  'three stored entries are the API maximum');

clickRow(1, 'remove');
assert.equal(rowNodes().length, 2);
assert.equal(visible('policyUpstreamPlainWarning'), false);
assert.equal(visible('policyUpstreamMixedWarning'), false);
assert.equal(w.document.getElementById('policyUpstreamAddBtn').disabled, false,
  'below the API maximum another entry can still be added');

clickRow(0, 'down');
assert.deepEqual(rows().map(r => r.transport), ['doh', 'dot'], 'the order is the operator list order');
assert.equal(rows()[0].pin, '', 'an unencrypted entry keeps no pin');
assert.equal(rows()[1].pin, PIN, 'the encrypted entry keeps its pin through a move');

assert.equal(await w.PolicyUpstreamEditor.addRow(), true);
assert.equal(rowNodes().length, 3);
assert.equal(rows()[2].transport, 'plain', 'a new row starts on the plain transport');
assert.equal(visible('policyUpstreamPlainWarning'), true);
assert.equal(visible('policyUpstreamMixedWarning'), true);
assert.equal(rows()[2].pin, '');

setField(2, 'transport', 'doh');
setField(2, 'address', 'dns.example.net');
assert.ok([...w.document.querySelectorAll('[data-upstream-role="error"]')]
  .some(el => el.textContent === DICT.policy_upstream_duplicate),
  'a duplicate entry must be refused before it is sent');
assert.equal(saveBtn().disabled, true, 'a client-side error keeps Save inert');

setField(2, 'address', '');
assert.ok([...w.document.querySelectorAll('[data-upstream-role="error"]')]
  .some(el => el.textContent === DICT.policy_upstream_address_required));
setField(2, 'address', 'dns.example.org');
setField(2, 'transport', 'plain');
setField(2, 'port', '');
assert.ok([...w.document.querySelectorAll('[data-upstream-role="error"]')]
  .some(el => el.textContent === DICT.policy_upstream_port_required));
setField(2, 'port', '53');
assert.equal(saveBtn().disabled, false);
`)
}

// TestPolicyUpstreamEditorAdmitsAllThreeStoredEntries is the cap regression. The
// API stores three entries (policy.MaxUpstreams) while the resolver queries only
// the first two, so the editor must be able to create, edit and reorder all three
// and must label the third exactly as "not queried". On the previous revision the
// add path stopped at two, which made a valid third entry impossible to author.
func TestPolicyUpstreamEditorAdmitsAllThreeStoredEntries(t *testing.T) {
	runUpstreamScenario(t, `
let current = [];
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    const body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body;
    current = body.upstream_dns.map(entry => Object.assign(
      {port: entry.transport === 'dot' ? 853 : (entry.transport === 'doh' ? 443 : entry.port)}, entry));
    return Object.assign({status: 'ok'}, record(current, {enabled: body.enabled, preset: body.preset}));
  }
  return record(current, {preset: 'geoblock'});
};
`, `
// Build the three entries the API accepts, from an empty list.
assert.equal(await w.PolicyUpstreamEditor.addRow(), true);
setField(0, 'address', 'dns.example.com');
setField(0, 'transport', 'dot');
setField(0, 'pin', PIN);
assert.equal(await w.PolicyUpstreamEditor.addRow(), true,
  'a second entry is admitted');
setField(1, 'address', '9.9.9.9');
setField(1, 'port', '53');
assert.equal(await w.PolicyUpstreamEditor.addRow(), true,
  'a third stored entry is admitted: the API maximum is three');
setField(2, 'address', 'dns.example.net');
setField(2, 'transport', 'doh');
assert.equal(rowNodes().length, 3);
assert.equal(saveBtn().disabled, false, 'three valid entries are saveable');

// A fourth entry is refused before it can be sent, on the API's own bound.
assert.equal(w.document.getElementById('policyUpstreamAddBtn').disabled, true);
assert.equal(await w.PolicyUpstreamEditor.addRow(), false,
  'a fourth entry must not be creatable');
assert.equal(rowNodes().length, 3);

// The third row is labelled exactly as stored-but-not-queried.
const limitNote = rowNodes()[2].querySelector('[data-upstream-role="not-queried"]');
assert.equal(limitNote.classList.contains('hidden'), false);
assert.equal(limitNote.textContent, DICT.policy_upstream_not_queried_note);
assert.equal(rowNodes()[1].querySelector('[data-upstream-role="not-queried"]').classList.contains('hidden'), true,
  'the second entry is queried, so it carries no label');

// Reordering keeps every entry, its position and its pin.
setField(2, 'address', 'dns3.example.org');
clickRow(2, 'up');
clickRow(1, 'up');
assert.deepEqual(rows().map(r => r.transport), ['doh', 'dot', 'plain']);
assert.deepEqual(rows().map(r => r.pin), ['', PIN, '']);

await w.PolicyUpstreamEditor.save();
await settle();
const puts = requestsTo('PUT');
assert.equal(puts.length, 1);
assert.deepEqual(puts[0].body.upstream_dns, [
  {address: 'dns3.example.org', transport: 'doh'},
  {address: 'dns.example.com', transport: 'dot', spki_pin: PIN},
  {address: '9.9.9.9', transport: 'plain', port: 53}
], 'all three entries are sent, in order, with the pin intact');

// The stored record round-trips: the third pin and the order survive a reload.
await w.PolicyUpstreamEditor.reload();
await settle();
assert.equal(rowNodes().length, 3);
assert.deepEqual(rows().map(r => r.transport), ['doh', 'dot', 'plain']);
assert.equal(rows()[1].pin, PIN, 'the stored encrypted entry keeps its pin');
assert.equal(rows()[0].address, 'dns3.example.org');
assert.equal(rows()[2].address, '9.9.9.9');
`)
}

// TestPolicyUpstreamEditorHealthIsAnObservation pins the health line: it is the
// runtime's last observation, labelled as such, matched against the stored list by
// the exact string the backend renders, and an unknown failure token is shown as
// text instead of being translated into a guess.
func TestPolicyUpstreamEditorHealthIsAnObservation(t *testing.T) {
	kindTokens, err := json.Marshal(upstreamFailureKindTokens)
	if err != nil {
		t.Fatalf("encode failure kinds: %v", err)
	}
	prelude := fmt.Sprintf(`
const KINDS = %s;
let snapshot = {enabled: true, preset: 'geoblock', last_upstream: 'dot://dns.example.com:853'};
let withStatus = true;
responder = async () => {
  const base = record([{address: 'dns.example.com', port: 853, transport: 'dot', spki_pin: PIN}],
    {enabled: true, preset: 'geoblock'});
  if (!withStatus) { delete base.status; return base; }
  base.status = snapshot;
  return base;
};
const reloadWith = async (next) => {
  snapshot = next;
  await w.PolicyUpstreamEditor.reload();
  await settle();
};
`, string(kindTokens))
	runUpstreamScenario(t, prelude, `
const STORED = DICT.policy_upstream_health_last.split('{upstream}').join('dot://dns.example.com:853');
assert.equal(text('policyUpstreamHealthState'), STORED,
  'the last observed resolver is matched against the stored list by its rendered form');

await reloadWith({enabled: true, preset: 'geoblock', last_upstream: 'dot://old.example.org:853'});
assert.equal(text('policyUpstreamHealthState'),
  DICT.policy_upstream_health_not_in_list.split('{upstream}').join('dot://old.example.org:853'),
  'a resolver that is no longer configured is reported as a historical observation');

await reloadWith({enabled: true, preset: 'geoblock'});
assert.equal(text('policyUpstreamHealthState'), DICT.policy_upstream_health_waiting);

await reloadWith({enabled: false, preset: 'geoblock'});
assert.equal(text('policyUpstreamHealthState'), DICT.policy_upstream_health_off,
  'health is not claimed while policy routing is off');

withStatus = false;
await w.PolicyUpstreamEditor.reload();
await settle();
assert.equal(text('policyUpstreamHealthState'), DICT.policy_upstream_health_none,
  'a deployment that reports no runtime must not borrow an older observation');
withStatus = true;

for (const kind of KINDS) {
  await reloadWith({enabled: true, preset: 'geoblock', last_upstream: 'dot://dns.example.com:853',
                    last_upstream_failure: 'dot://dns.example.com:853', last_upstream_failure_kind: kind});
  const expected = DICT.policy_upstream_health_failure.split('{kind}').join(DICT['policy_upstream_failure_' + kind]);
  assert.equal(text('policyUpstreamHealthFailure'), expected + ': dot://dns.example.com:853',
    'failure kind ' + kind + ' must be resolved through the dictionary, got: ' + text('policyUpstreamHealthFailure'));
}

await reloadWith({enabled: true, preset: 'geoblock', last_upstream: 'dot://dns.example.com:853',
                  last_upstream_failure: 'quota exceeded', last_upstream_failure_kind: 'quota_exceeded'});
assert.ok(text('policyUpstreamHealthFailure').indexOf('quota_exceeded') !== -1,
  'an unknown kind is shown verbatim, got: ' + text('policyUpstreamHealthFailure'));
assert.ok(text('policyUpstreamHealthFailure').indexOf('quota exceeded') !== -1);
`)
}

// TestPolicyUpstreamEditorPayloadAcceptedByRealValidators is the compatibility
// rule with two consumers: the payloads the controller emits for the editor's own
// form states are fed to the real policy validator and to the resolver's
// admission rule. The editor cannot drift into sending something the server
// refuses without failing here.
func TestPolicyUpstreamEditorPayloadAcceptedByRealValidators(t *testing.T) {
	out := runUpstreamScenario(t, `
let current = [];
responder = async (url, opts) => {
  if (opts.method === 'PUT') {
    const body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body;
    console.log('PAYLOAD:' + JSON.stringify(body));
    const list = body.upstream_dns.map(entry => Object.assign(
      {port: entry.transport === 'dot' ? 853 : (entry.transport === 'doh' ? 443 : entry.port)}, entry));
    current = list;
    return Object.assign({status: 'ok'}, record(list, {enabled: body.enabled, preset: body.preset}));
  }
  return record(current, {preset: 'geoblock'});
};
`, `
// 1. Plain DNS with an explicit port.
await w.PolicyUpstreamEditor.addRow();
setField(0, 'address', ' 9.9.9.9 ');
setField(0, 'port', '53');
await w.PolicyUpstreamEditor.save();
await settle();

// 2. DoT with a pin and no port: the server fills the transport default.
clickRow(0, 'remove');
await w.PolicyUpstreamEditor.addRow();
setField(0, 'address', 'dns.example.com');
setField(0, 'transport', 'dot');
setField(0, 'pin', PIN);
await w.PolicyUpstreamEditor.save();
await settle();

// 3. DoH with no port and no pin.
clickRow(0, 'remove');
await w.PolicyUpstreamEditor.addRow();
setField(0, 'address', 'dns.example.net');
setField(0, 'transport', 'doh');
await w.PolicyUpstreamEditor.save();
await settle();

// 4. The explicit reset to the built-in defaults.
await w.PolicyUpstreamEditor.useDefaults();
await settle();

assert.equal(requestsTo('PUT').length, 4);
`)

	payloads := []string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PAYLOAD:") {
			payloads = append(payloads, strings.TrimPrefix(line, "PAYLOAD:"))
		}
	}
	if len(payloads) != 4 {
		t.Fatalf("captured %d payloads, want 4\n%s", len(payloads), out)
	}

	// The editor trims the address and never sends a whitespace-padded one.
	var plain map[string]any
	if err := json.Unmarshal([]byte(payloads[0]), &plain); err != nil {
		t.Fatalf("decode first payload: %v", err)
	}
	entries, _ := plain["upstream_dns"].([]any)
	if len(entries) != 1 {
		t.Fatalf("first payload has %d entries, want 1", len(entries))
	}
	first, _ := entries[0].(map[string]any)
	if got, _ := first["address"].(string); got != "9.9.9.9" {
		t.Fatalf("the editor sent address %q, want the trimmed 9.9.9.9", got)
	}
	if got, _ := first["transport"].(string); got != string(policy.TransportPlain) {
		t.Fatalf("the editor sent transport %q, want the explicit %q", got, policy.TransportPlain)
	}

	for i, raw := range payloads {
		var settings policy.Settings
		if err := json.Unmarshal([]byte(raw), &settings); err != nil {
			t.Fatalf("payload %d does not decode into the settings record: %v\n%s", i+1, err, raw)
		}
		normalized := settings.Normalize()
		if err := normalized.Validate(); err != nil {
			t.Fatalf("payload %d is refused by the real validator: %v\n%s", i+1, err, raw)
		}
		effective := normalized.EffectiveUpstreams()
		if err := gatewaydns.ValidateUpstreams(effective, false); err != nil {
			t.Fatalf("payload %d is refused by the resolver's admission rule: %v\n%s", i+1, err, raw)
		}
		if i == 3 {
			if len(normalized.UpstreamDNS) != 0 {
				t.Fatalf("the defaults save sent %v, want an explicit empty list", normalized.UpstreamDNS)
			}
			if len(effective) != len(policy.DefaultUpstreams()) {
				t.Fatalf("an explicit reset does not resolve to the default pair: %v", effective)
			}
		}
	}

	// The health line is matched by the backend's own rendering of an entry, so the
	// JS builder and Upstream.String() must not disagree.
	var second policy.Settings
	if err := json.Unmarshal([]byte(payloads[1]), &second); err != nil {
		t.Fatalf("decode second payload: %v", err)
	}
	dot := second.UpstreamDNS[0].WithDefaultPort()
	if got, want := dot.String(), "dot://dns.example.com:853"; got != want {
		t.Fatalf("backend renders the DoT entry as %q, want %q", got, want)
	}
	if got := second.UpstreamDNS[0].SPKIPin; got != "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=" {
		t.Fatalf("the pin did not travel with the encrypted entry: %q", got)
	}
}
