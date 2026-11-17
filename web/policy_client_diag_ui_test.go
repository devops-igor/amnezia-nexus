package web

// Behavioural JSDOM coverage for the shipped per-client diagnosis controller
// (#861).
//
// The assertions run static/js/policy_client_diag.js — read through StaticFS,
// i.e. the asset the browser loads — against the section markup rendered from
// templates/settings_policy_client.html. Nothing is re-implemented: the module is
// evaluated as-is and driven through its entry points and the DOM the template
// actually produces.
//
// The cases are paired: alongside "a selected client's records render" there is
// "a late answer for another client must not render", and alongside "a refresh
// works" there is "a failed refresh clears the picker instead of keeping stale
// sessions selectable".

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"testing"
)

// clientDiagSectionHTMLForTest renders the shipped partial with the template
// helpers the page provides, so the fixture is the production markup.
func clientDiagSectionHTMLForTest(t *testing.T) string {
	t.Helper()
	funcs := template.FuncMap{
		"_": func(key string) string { return key },
		"is_admin": func(any) bool {
			return true
		},
	}
	tmpl, err := template.New("settings_policy_client.html").Funcs(funcs).ParseFS(TemplatesFS, "templates/settings_policy_client.html")
	if err != nil {
		t.Fatalf("parse settings_policy_client.html: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "settings_policy_client", map[string]any{"current_user": nil}); err != nil {
		t.Fatalf("render settings_policy_client: %v", err)
	}
	if !strings.Contains(buf.String(), `id="policyClientCard"`) {
		t.Fatal("rendered per-client section does not contain the card; the fixture is wrong")
	}
	return buf.String()
}

// clientDiagHarness evaluates the shipped module against the rendered section.
// `prelude` installs the API double before the initial list load; `scenario` runs
// after that load has settled.
func clientDiagHarness(t *testing.T, prelude, scenario string) string {
	t.Helper()

	module, err := StaticFS.ReadFile("static/js/policy_client_diag.js")
	if err != nil {
		t.Fatalf("read per-client controller: %v", err)
	}
	encodedModule, err := json.Marshal(string(module))
	if err != nil {
		t.Fatalf("encode module: %v", err)
	}
	encodedSection, err := json.Marshal(clientDiagSectionHTMLForTest(t))
	if err != nil {
		t.Fatalf("encode section: %v", err)
	}

	return jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="policyClientFixtureHost"></div>', {runScripts:'outside-only'});
const w = dom.window;
// Every key resolves to itself so an assertion can name the exact key a branch
// chose instead of depending on English wording. The keys whose substitution is
// under test are the ones with placeholders.
w._ = key => {
  if (key === 'policy_client_truncated') return 'TRUNC {shown}/{total}';
  if (key === 'policy_client_flow_count') return 'FLOWS {shown}/{total}';
  if (key === 'policy_client_partial_scan') return 'PARTIAL {scanned}';
  if (key === 'policy_client_seconds') return '{seconds}s';
  if (key === 'policy_client_dns_coverage') return 'DNS-COVERAGE {stored}/{collapsed}/{evicted}/{aged}';
  if (key === 'policy_client_dns_truncated') return 'DNS-TRUNC {shown}/{total}';
  // Token families resolve to a sentinel, so an assertion can prove the token
  // was looked up in the dictionary instead of being printed raw.
  if (key.indexOf('policy_client_state_') === 0) return 'STATE:' + key.slice('policy_client_state_'.length);
  if (key.indexOf('policy_client_decision_') === 0) return 'DECISION:' + key.slice('policy_client_decision_'.length);
  if (key.indexOf('policy_client_protocol_') === 0) return 'PROTO:' + key.slice('policy_client_protocol_'.length);
  if (key.indexOf('policy_client_limit_') === 0) return 'LIMIT:' + key.slice('policy_client_limit_'.length);
  return key;
};

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
const settle = async (rounds) => { for (let i = 0; i < (rounds || 10); i++) await flush(); };
const requestsTo = (suffix, method) => calls.filter(c => c.url.endsWith(suffix) && (!method || c.method === method));
const text = id => w.document.getElementById(id).textContent;
const card = () => w.document.getElementById('policyClientCard');
const resultHidden = () => w.document.getElementById('policyClientResult').hidden;
const alertText = () => {
  const el = w.document.getElementById('policyClientAlert');
  return {text: el.textContent, state: el.getAttribute('data-state'), display: el.style.display};
};
const options = () => Array.from(w.document.getElementById('policyClientSelect').options)
  .filter(o => o.value !== '').map(o => ({value: o.value, text: o.textContent,
    generation: o.getAttribute('data-route-generation')}));
const rowCount = id => w.document.getElementById(id).children.length;
const rowCells = (id, index) => Array.from(w.document.getElementById(id).children[index].children).map(c => c.textContent);
const selectClient = (id) => {
  const select = w.document.getElementById('policyClientSelect');
  select.value = id;
  select.dispatchEvent(new w.Event('change'));
};

// Evaluate the module before the section exists: the entry point must be inert.
(async () => {
w.eval(%s);
assert.equal(w.initPolicyClientDiagnosis(), false, 'init must be inert without the section');
assert.equal(card(), null, 'the fixture must not have a card yet');

w.document.getElementById('policyClientFixtureHost').innerHTML = %s;

%s

assert.equal(w.initPolicyClientDiagnosis(), true, 'init must wire the rendered section');
await settle();

%s

console.log('CLIENT_DIAG_SCENARIO_OK');
dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedModule), string(encodedSection), prelude, scenario)
}

func runClientDiagScenario(t *testing.T, prelude, scenario string) {
	t.Helper()
	node := requireJSDOM(t)
	out, err := execNodeScript(node, clientDiagHarness(t, prelude, scenario))
	if err != nil || !strings.Contains(string(out), "CLIENT_DIAG_SCENARIO_OK") {
		t.Fatalf("per-client scenario failed: %v\n%s", err, out)
	}
}

// clientTargetsScript is the default answer for the client list: two live
// incarnations with distinct route generations.
const clientTargetsScript = `
const targets = () => ({clients: [
  {session_id: 'sess-a', connection_id: 'conn-a', connection_name: 'phone',
   assigned_ip: '10.100.0.5', connected_at: '2026-11-17T09:00:00Z',
   route_live: true, route_generation: 3, evidence_entries: 2},
  {session_id: 'sess-b', connection_id: 'conn-b', connection_name: 'tablet',
   assigned_ip: '10.100.0.6', connected_at: '2026-11-17T09:05:00Z',
   route_live: true, route_generation: 1, evidence_entries: 0}
], sampled_at: '2026-11-17T09:10:00Z', policy_routing_enabled: true, read_only: true,
 not_covered: ['application_success_not_observable']});
const diagnosis = (session, generation) => ({
  selection: {session_id: session, state: 'live', route_generation: generation,
              connection_name: session === 'sess-a' ? 'phone' : 'tablet',
              assigned_ip: session === 'sess-a' ? '10.100.0.5' : '10.100.0.6'},
  coverage: {policy_routing_enabled: true, sampled_at: '2026-11-17T09:10:00Z',
             evidence_source: 'route_cache_entries_and_live_flows',
             not_covered: ['application_success_not_observable'],
             not_recorded: ['dns_names_not_retained']},
  dns: {available: true, state: 'fresh', generation: 'gen-1',
        names: {match: 'not_recorded', reason: 'dns_names_not_retained'},
        entries: [{address: '93.184.216.34', decision: 'DIRECT',
                   observed_at: '2026-11-17T09:09:30Z', expires_at: '2026-11-17T09:14:30Z',
                   expires_in_seconds: 270, age_seconds: 30, state: 'fresh',
                   names: [], names_match: 'not_recorded'}],
        total: 1, truncated: false},
  flows: {available: true, state: 'recorded', scanned: 2, scan_complete: true, total: 1,
          truncated: false,
          entries: [{protocol: 'tcp', client_src_port: 40002, destination_ip: '93.184.216.34',
                     destination_port: 443, choice: 'DIRECT', route_generation: generation,
                     last_seen: '2026-11-17T09:09:59Z', last_seen_age_seconds: 42,
                     expired: false, close_seen: false, decision_time: 'not_recorded',
                     decision_reason: 'not_recorded', names: [], names_match: 'not_recorded'}]},
  drops: {available: false, state: 'not_recorded', total: 0, truncated: false, entries: []},
  limitations: ['dns_names_not_retained', 'flow_decision_reason_not_recorded'],
  evaluated_at: '2026-11-17T09:10:00Z', read_only: true
});
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return targets();
  if (url.endsWith('/api/vpn/policy/client-diagnosis')) {
    const body = opts.body || {};
    return diagnosis(body.session_id, body.route_generation);
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
`

func TestPolicyClientDiagListsClients(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
assert.equal(requestsTo('/api/vpn/policy/clients', 'GET').length, 1,
  'the list is read exactly once on init, and never polled');
const listed = options();
assert.equal(listed.length, 2, 'both incarnations must be selectable');
assert.equal(listed[0].value, 'sess-a');
assert.equal(listed[0].generation, '3', 'the route generation travels with the option');
assert.ok(listed[0].text.indexOf('10.100.0.5') !== -1, 'the label names the assigned address');
assert.ok(listed[0].text.indexOf('phone') !== -1, 'the label names the connection');
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').disabled, true,
  'nothing is selected yet, so the action must be inert');
assert.equal(alertText().display, 'none', 'a healthy list needs no banner');
`)
}

func TestPolicyClientDiagRendersSelectedIncarnation(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').disabled, false,
  'a selected incarnation makes the action available');
await w.diagnoseSelectedClient();
await settle();

const posts = requestsTo('/api/vpn/policy/client-diagnosis', 'POST');
assert.equal(posts.length, 1, 'one diagnosis is exactly one request');
assert.equal(posts[0].body.session_id, 'sess-a');
assert.equal(posts[0].body.route_generation, 3,
  'the selected route generation must be pinned, not left to the server');

assert.equal(resultHidden(), false, 'a live answer is rendered');
assert.equal(text('policyClientSessionValue'), 'sess-a');
assert.equal(text('policyClientStateValue'), 'STATE:live',
  'the state is translated from the server token');
assert.equal(text('policyClientGenerationValue'), '3');
assert.equal(text('policyClientEvaluatedValue'), '2026-11-17T09:10:00Z');

assert.equal(rowCount('policyClientEvidenceRows'), 1, 'one retained address is rendered');
assert.deepEqual(rowCells('policyClientEvidenceRows', 0),
  ['93.184.216.34', 'DECISION:direct', '2026-11-17T09:09:30Z',
   '2026-11-17T09:14:30Z', 'fresh']);

assert.equal(rowCount('policyClientFlowRows'), 1, 'one live flow is rendered');
assert.deepEqual(rowCells('policyClientFlowRows', 0),
  ['PROTO:tcp', '93.184.216.34:443', 'DECISION:direct', '42s', 'active']);

const limits = Array.from(w.document.getElementById('policyClientLimitations').children).map(li => li.textContent);
assert.deepEqual(limits, ['LIMIT:dns_names_not_retained',
                          'LIMIT:flow_decision_reason_not_recorded'],
  'every stated limitation is rendered from the answer, not invented here');
`)
}

func TestPolicyClientDiagClearsResultOnSelectionChange(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(resultHidden(), false);

// Switching the selection must remove the previous client's records before any
// new answer exists.
selectClient('sess-b');
assert.equal(resultHidden(), true, 'the previous answer must not stay visible');
assert.equal(rowCount('policyClientEvidenceRows'), 0, 'previous rows must be cleared');
assert.equal(rowCount('policyClientFlowRows'), 0, 'previous rows must be cleared');
assert.equal(text('policyClientSessionValue'), '-', 'the identity must be reset');

await w.diagnoseSelectedClient();
await settle();
assert.equal(text('policyClientSessionValue'), 'sess-b', 'the new selection is rendered');
assert.equal(requestsTo('/api/vpn/policy/client-diagnosis', 'POST')[1].body.route_generation, 1,
  'the second request pins its own generation');
`)
}

func TestPolicyClientDiagDropsALateAnswerForAPreviousSelection(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
// A diagnosis for client A is in flight when the operator selects client B. The
// late answer for A must not render under B, and the second action must not
// produce a concurrent request (the server admits one snapshot at a time).
const held = [];
responder = (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return Promise.resolve(targets());
  const body = opts.body || {};
  if (body.session_id === 'sess-a') {
    return new Promise(resolve => { held.push(() => resolve(diagnosis('sess-a', 3))); });
  }
  return Promise.resolve(diagnosis('sess-b', 1));
};

selectClient('sess-a');
const first = w.diagnoseSelectedClient();
selectClient('sess-b');
// One snapshot at a time: the in-flight request blocks a second POST.
assert.equal(await w.diagnoseSelectedClient(), null,
  'a second diagnosis must not start while one is in flight');

held.forEach(fn => fn());
await first;
await settle();
assert.equal(resultHidden(), true,
  'an answer for the previous selection must not render after the selection changed');
assert.equal(text('policyClientSessionValue'), '-', 'no identity may be adopted from a stale answer');

// Once the in-flight request is done, the newly selected client can be read.
selectClient('sess-b');
await w.diagnoseSelectedClient();
await settle();
assert.equal(text('policyClientSessionValue'), 'sess-b');
assert.equal(requestsTo('/api/vpn/policy/client-diagnosis', 'POST').length, 2,
  'exactly one request per operator action');
assert.equal(requestsTo('/api/vpn/policy/client-diagnosis', 'POST')[1].body.route_generation, 1);
`)

}

func TestPolicyClientDiagRejectsMismatchedEcho(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
// The server answers about another incarnation (or none). Rendering it would
// attribute one client's records to another, so nothing may be shown.
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return targets();
  return diagnosis('sess-b', 1);
};
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

assert.equal(resultHidden(), true, 'a mismatched answer must not render');
assert.equal(alertText().state, 'stale', 'the discard must be visible to the operator');
assert.equal(alertText().text, 'policy_client_stale_answer');
assert.equal(rowCount('policyClientEvidenceRows'), 0);
`)
}

func TestPolicyClientDiagErrorStates(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');

// 1. A permission refusal is reported as such, not as a server fault.
responder = async (url) => {
  const err = new Error('Forbidden');
  err.status = 403;
  err.data = {error: 'forbidden', detail: 'admin required'};
  throw err;
};
await w.diagnoseSelectedClient();
await settle();
assert.equal(alertText().state, 'error');
assert.equal(alertText().text, 'policy_client_permission_denied');
assert.equal(resultHidden(), true);
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').disabled, false,
  'a failed read leaves the action usable');

// 2. Another diagnosis in flight is reported as busy, with the server detail.
responder = async (url) => {
  const err = new Error('busy');
  err.status = 429;
  err.data = {error: 'busy', detail: 'Another client diagnosis snapshot is in flight'};
  throw err;
};
await w.diagnoseSelectedClient();
await settle();
assert.equal(alertText().text, 'policy_client_busy');
assert.ok(alertText().text.indexOf('policy_client_permission_denied') === -1,
  'the previous banner must be replaced, not appended');

// 3. A failed refresh clears the picker instead of keeping stale sessions.
responder = async () => { throw new TypeError('Failed to fetch'); };
await w.refreshPolicyClients();
await settle();
assert.equal(options().length, 0, 'a failed refresh must not leave selectable sessions');
assert.equal(alertText().state, 'error');
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').disabled, true);
`)
}

func TestPolicyClientDiagPolicyOff(t *testing.T) {
	runClientDiagScenario(t, `
responder = async (url) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    return {clients: [], sampled_at: '2026-11-17T09:10:00Z',
            policy_routing_enabled: false, read_only: true,
            not_covered: ['application_success_not_observable']};
  }
  throw new Error('unexpected ' + url);
};
`, `
assert.equal(alertText().state, 'policy-off', 'a disabled policy path is stated, not hidden');
assert.equal(alertText().text, 'policy_client_policy_off');
assert.equal(options().length, 0);
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').disabled, true);
assert.equal(requestsTo('/api/vpn/policy/client-diagnosis', 'POST').length, 0,
  'nothing is requested from a disabled data path');
`)
}

func TestPolicyClientDiagTruncationAndPartialScanAreStated(t *testing.T) {
	runClientDiagScenario(t, `
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    return {clients: [{session_id: 'sess-a', route_live: true, route_generation: 2}],
            sampled_at: '2026-11-17T09:10:00Z', policy_routing_enabled: true, read_only: true,
            not_covered: []};
  }
  return {selection: {session_id: 'sess-a', state: 'live', route_generation: 2},
    dns: {available: true, state: 'fresh', entries: [
      {address: '1.1.1.1', decision: 'PROXY', state: 'fresh'}], total: 9, truncated: true,
      names: {match: 'not_recorded'}},
    flows: {available: true, state: 'recorded', scanned: 16384, scan_complete: false,
            total: 600, truncated: true, entries: [
      {protocol: 'udp', destination_ip: '1.1.1.1', destination_port: 53, choice: 'PROXY',
       last_seen_age_seconds: 5, expired: false, close_seen: false}]},
    drops: {available: false, state: 'not_recorded', entries: []},
    limitations: ['flow_scan_window_partial'], evaluated_at: '2026-11-17T09:10:00Z', read_only: true};
};
`, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

assert.equal(w.document.getElementById('policyClientEvidenceFoot').hidden, false,
  'a truncated evidence page must say so');
assert.equal(text('policyClientEvidenceFoot'), 'TRUNC 1/9');
assert.equal(w.document.getElementById('policyClientFlowFoot').hidden, false);
assert.equal(text('policyClientFlowFoot'), 'FLOWS 1/600 PARTIAL 16384',
  'the flow count must be presented as a windowed count');
assert.equal(rowCells('policyClientFlowRows', 0)[0], 'PROTO:udp');
`)
}

// TestPolicyClientDiagModuleElementIDs guards the wiring between the module and
// the template: every id the controller looks up must exist in the rendered
// section.
func TestPolicyClientDiagModuleElementIDs(t *testing.T) {
	module, err := StaticFS.ReadFile("static/js/policy_client_diag.js")
	if err != nil {
		t.Fatalf("read per-client controller: %v", err)
	}
	section := clientDiagSectionHTMLForTest(t)

	lookup := regexp.MustCompile(`clientElement\('([A-Za-z0-9_]+)'\)`)
	matches := lookup.FindAllStringSubmatch(string(module), -1)
	if len(matches) < 8 {
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
			t.Errorf("controller looks up #%s, which the rendered section does not define", id)
		}
	}
}
