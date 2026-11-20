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
		"asset_url": AssetURL,
	}
	tmpl, err := template.New("settings_policy_client.html").Funcs(funcs).ParseFS(TemplatesFS, "templates/settings_policy_client.html")
	if err != nil {
		t.Fatalf("parse settings_policy_client.html: %v", err)
	}
	var buf bytes.Buffer
	// The page supplies the release version, and the controller is referenced
	// through its content-derived URL by the shipped template itself. This package
	// cannot reach the release constant without an import cycle, so the fixture
	// supplies a placeholder for it: the URL must have the production shape even
	// where its exact value is not asserted.
	if err := tmpl.ExecuteTemplate(&buf, "settings_policy_client", map[string]any{
		"current_user": nil,
		"app_version":  "test",
	}); err != nil {
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
	filterModule, err := StaticFS.ReadFile("static/js/policy_client_diag_filter.js")
	if err != nil {
		t.Fatalf("read per-client destination filter: %v", err)
	}
	// The filter is a second shipped asset: it is evaluated first, exactly as the
	// template loads it.
	encodedFilter, err := json.Marshal(string(filterModule))
	if err != nil {
		t.Fatalf("encode destination filter: %v", err)
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
  if (key === 'policy_client_outcome_fmt') return 'OUTCOME {ok}/{failed} · return {return} {packets}';
  if (key === 'policy_client_route_outcome_fmt') return 'ROUTE {route} · {dispatch}';
  if (key === 'policy_client_tried_names_fmt') return 'TRIED {names}';
  if (key === 'policy_client_flow_names_multiple') return 'FIRST {name} PLUS {count}';
  if (key === 'policy_client_drop_truncated') return 'DROP-TRUNC {shown}/{total}';
  if (key === 'policy_client_drop_coverage') return 'DROPCOV {stored}/{merged}/{evicted}/{pruned} session {session_keys} ledger {keys}/{key_limit} {age}';
  if (key === 'policy_client_drop_no_tuple') return 'NO-TUPLE';
  if (key === 'policy_client_drop_empty') return 'DROP-EMPTY';
  if (key === 'policy_client_drop_not_recorded') return 'DROP-NOT-RECORDED';
  if (key === 'policy_client_drop_reason_prohibited_destination') return 'REASON:prohibited';
  if (key === 'policy_client_drop_reason_invalid_client_packet') return 'REASON:invalid';
  if (key === 'policy_client_drop_reason_nat_port_exhaustion') return 'REASON:nat-exhaustion';
  if (key === 'policy_client_drop_reason_flow_table_full') return 'REASON:table-full';
  if (key === 'policy_client_limit_flow_evidence_install_failure_not_recorded')
    return 'LIMIT:flow-evidence-install';
  if (key === 'policy_client_drop_reason_direct_egress_unavailable') return 'REASON:no-egress';
  if (key === 'policy_client_backend_write_fmt') return 'DEVICE {ok}/{failed}';
  if (key === 'policy_client_backend_fmt') return 'BACKEND {backend}';
  if (key === 'policy_client_filter_count') return 'FILTER {shown}/{total} "{term}"';
  if (key === 'policy_client_filter_none') return 'NO MATCH "{term}"';
  if (key === 'policy_client_return_authority_current_tuple_association') return 'RETURN_AUTHORITY:current_tuple_association';
  if (key === 'policy_client_return_chain_fmt')
    return 'RET returned {matched}/{admitted}/{delivered}/{failed}';
  if (key === 'policy_client_dns_events_coverage') return 'EVENTS-COVERAGE {stored}/{collapsed}/{evicted}/{aged}';
  if (key === 'policy_client_dns_events_truncated') return 'EVENTS-TRUNC {shown}/{total}';
  if (key === 'policy_client_delivered_yes') return 'DELIVERED';
  if (key === 'policy_client_delivered_no') return 'NOT-DELIVERED';
  if (key.indexOf('policy_client_dns_event_') === 0) return 'EVENT:' + key.slice('policy_client_dns_event_'.length);
  if (key.indexOf('policy_client_upstream_') === 0) return 'UPSTREAM:' + key.slice('policy_client_upstream_'.length);
  // Token families resolve to a sentinel, so an assertion can prove the token
  // was looked up in the dictionary instead of being printed raw.
  if (key.indexOf('policy_client_state_') === 0) return 'STATE:' + key.slice('policy_client_state_'.length);
  if (key.indexOf('policy_client_decision_reason_') === 0)
    return 'DECISION_REASON:' + key.slice('policy_client_decision_reason_'.length);
  if (key.indexOf('policy_client_decision_') === 0) return 'DECISION:' + key.slice('policy_client_decision_'.length);
  if (key.indexOf('policy_client_protocol_') === 0) return 'PROTO:' + key.slice('policy_client_protocol_'.length);
  if (key.indexOf('policy_client_limit_') === 0) return 'LIMIT:' + key.slice('policy_client_limit_'.length);
  if (key.indexOf('policy_client_reason_') === 0) return 'REASON:' + key.slice('policy_client_reason_'.length);
  if (key.indexOf('policy_client_name_match_') === 0) return 'NAME_MATCH:' + key.slice('policy_client_name_match_'.length);
  if (key.indexOf('policy_client_return_evidence_') === 0) return 'RETURN_EVIDENCE:' + key.slice('policy_client_return_evidence_'.length);
  if (key.indexOf('policy_client_corr_') === 0) return 'CORR:' + key.slice('policy_client_corr_'.length);
  if (key.indexOf('policy_client_failure_') === 0) return 'FAILURE:' + key.slice('policy_client_failure_'.length);
  if (key.indexOf('policy_client_dispatch_') === 0) return 'DISPATCH:' + key.slice('policy_client_dispatch_'.length);
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
// rowHeaders reads the headers of the table that owns a body id, and rowCellTitles
// the tooltips of one row: the cells' detail lives there, not in their text.
const rowHeaders = id => Array.from(
  w.document.getElementById(id).closest('table').querySelectorAll('thead th')).map(th => th.textContent);
const rowCellTitles = (id, index) => Array.from(w.document.getElementById(id).children[index].children)
  .map(c => c.getAttribute('title') || '');
const selectClient = (id) => {
  const select = w.document.getElementById('policyClientSelect');
  select.value = id;
  select.dispatchEvent(new w.Event('change'));
};

// Evaluate the module before the section exists: the entry point must be inert.
(async () => {
w.eval(%s);
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
`, string(encodedFilter), string(encodedModule), string(encodedSection), prelude, scenario)
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
                     expired: false, close_seen: false,
                     decision_time: '2026-11-17T09:09:58Z', decision_reason: 'evidence_direct',
                     policy_generation: 'gen-1',
                     dispatch: {state: 'written_to_wan'}, forward: {packets: 1, bytes: 60, failed: 0},
                     return: {evidence: 'not_observed', packets: 0, bytes: 0},
                     names: ['plain.example'], names_match: 'unique', names_considered: 1,
                     name_candidates: [{name: 'plain.example', dns_seq: 1,
                                        observed_at: '2026-11-17T09:09:30Z',
                                        expires_at: '2026-11-17T09:14:30Z'}]}]},
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
assert.deepEqual(rowHeaders('policyClientFlowRows'),
  ['policy_client_column_protocol', 'policy_client_column_destination',
   'policy_client_column_choice', 'policy_client_column_decision'],
  'the flows table renders the four columns an operator reads');
assert.deepEqual(rowCells('policyClientFlowRows', 0),
  ['PROTO:tcp', '93.184.216.34:443 (plain.example)', 'DECISION:direct',
   'DECISION_REASON:evidence_direct']);
assert.equal(rowCellTitles('policyClientFlowRows', 0)[3],
  '2026-11-17T09:09:58Z · gen-1 · evidence_direct',
  'the instant, the generation and the token the label came from are the cell tooltip');

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
    drops: {available: true, state: 'observed', total: 4, truncated: true,
      entries: [
        {reason: 'prohibited_destination', has_tuple: true, destination_ip: '169.254.169.254',
         destination_port: 80, protocol: 'tcp', count: 4, bytes: 240,
         first_seen: '2026-11-17T09:00:00Z', last_seen: '2026-11-17T09:05:00Z'},
        {reason: 'invalid_client_packet', has_tuple: false, count: 1, bytes: 3,
         first_seen: '2026-11-17T09:01:00Z', last_seen: '2026-11-17T09:01:00Z'},
        {reason: 'nat_port_exhaustion', has_tuple: true, destination_ip: '9.9.9.9',
         destination_port: 443, protocol: 'tcp', count: 2, bytes: 120,
         first_seen: '2026-11-17T09:02:00Z', last_seen: '2026-11-17T09:06:00Z'},
        {reason: 'flow_table_full', has_tuple: true, destination_ip: '93.184.216.21',
         destination_port: 443, protocol: 'tcp', count: 1, bytes: 60,
         first_seen: '2026-11-17T09:07:00Z', last_seen: '2026-11-17T09:07:00Z'}],
      coverage: {stored: 3, merged: 5, evicted: 0, pruned: 1, session_keys: 4, keys: 4,
                 key_limit: 64, age_limit_seconds: 600}},
    limitations: ['flow_scan_window_partial', 'flow_evidence_install_failure_not_recorded'],
    evaluated_at: '2026-11-17T09:10:00Z', read_only: true};
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
  'the flow count must be presented as a windowed count, with the partial scan stated');
assert.deepEqual(rowCells('policyClientFlowRows', 0),
  ['PROTO:udp', '1.1.1.1:53', 'DECISION:proxy', 'DECISION_REASON:not_recorded'],
  'a flow recorded without decision metadata says so instead of showing an empty cell');
// Pre-flow refusals: a real row per reason, an explicit "no tuple" instead of an
// invented destination, the truncation note and the retention coverage.
assert.equal(rowCells('policyClientDropRows', 0)[0], 'REASON:prohibited',
  'the refused reason is rendered from the producer token');
assert.equal(rowCells('policyClientDropRows', 0)[1], '169.254.169.254:80',
  'a well-formed refused packet keeps its destination');
assert.equal(rowCells('policyClientDropRows', 0)[3], '4');
assert.equal(rowCells('policyClientDropRows', 1)[1], 'NO-TUPLE',
  'a malformed packet must not show a destination it never carried');
assert.equal(rowCells('policyClientDropRows', 1)[2], 'NO-TUPLE');
assert.equal(rowCells('policyClientDropRows', 2)[0], 'REASON:nat-exhaustion');
assert.ok(Array.from(w.document.getElementById('policyClientLimitations').children)
  .map(li => li.textContent)
  .includes('LIMIT:flow-evidence-install'),
  'a forwarded flow without an installed decision record is stated as a limitation, not as a drop');
assert.equal(rowCells('policyClientDropRows', 3)[0], 'REASON:table-full',
  'a flow-table refusal is rendered from the same producer token family');
assert.equal(text('policyClientDropFoot'), 'DROP-TRUNC 4/4');
assert.equal(text('policyClientDropCoverage'), 'DROPCOV 3/5/0/1 session 4 ledger 4/64 600',
  'retention and loss are stated beside the rows, with the session separated from the ledger');
`)
}

// TestPolicyClientDiagFlowStateVariety pins the visible rendering of the states a
// recorded flow can be in: several candidate names, no candidate with a stated
// reason, a refused dispatch, an unmeasured return and a flow recorded without
// decision metadata. Each cell is asserted, so a wrong or invented value fails.
func TestPolicyClientDiagFlowStateVariety(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript+`
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return base(url, opts);
  const answer = await base(url, opts);
  answer.drops = {available: true, state: 'observed', total: 3, truncated: true,
    entries: [
      {reason: 'prohibited_destination', has_tuple: true, destination_ip: '169.254.169.254',
       destination_port: 80, protocol: 'tcp', count: 4, bytes: 240,
       first_seen: '2026-11-17T09:00:00Z', last_seen: '2026-11-17T09:05:00Z'},
      {reason: 'invalid_client_packet', has_tuple: false, count: 1, bytes: 3,
       first_seen: '2026-11-17T09:01:00Z', last_seen: '2026-11-17T09:01:00Z'},
      {reason: 'nat_port_exhaustion', has_tuple: true, destination_ip: '9.9.9.9',
       destination_port: 443, protocol: 'tcp', count: 2, bytes: 120,
       first_seen: '2026-11-17T09:02:00Z', last_seen: '2026-11-17T09:06:00Z'},
      {reason: 'flow_table_full', has_tuple: true, destination_ip: '93.184.216.21',
       destination_port: 443, protocol: 'tcp', count: 1, bytes: 60,
       first_seen: '2026-11-17T09:07:00Z', last_seen: '2026-11-17T09:07:00Z'}],
    coverage: {stored: 2, merged: 5, evicted: 0, pruned: 1, session_keys: 3, keys: 3,
               key_limit: 64, age_limit_seconds: 600}};
  answer.flows.entries = [
    {protocol: 'tcp', destination_ip: '93.184.216.34', destination_port: 443, choice: 'PROXY',
     route_generation: 3, last_seen_age_seconds: 5, expired: false, close_seen: false,
     decision_time: '2026-11-17T09:09:58Z', decision_reason: 'proxy_cidr_rule',
     policy_generation: 'gen-1', backend_tunnel_id: 77,
     dispatch: {state: 'failed', reason: 'backend_queue_full'},
     forward: {packets: 0, bytes: 0, failed: 2, failure: 'backend_queue_full',
               backend_writes: 0, backend_write_failed: 0},
     return: {evidence: 'not_measured', packets: 0, bytes: 0},
     names: ['plain.example', 'shared.example'], names_match: 'ambiguous', names_considered: 2,
     name_candidates: []},
    {protocol: 'udp', destination_ip: '8.8.8.8', destination_port: 53, choice: 'PROXY',
     route_generation: 3, last_seen_age_seconds: 9, expired: false, close_seen: false,
     decision_time: '2026-11-17T09:09:57Z', decision_reason: 'no_trusted_evidence',
     policy_generation: 'gen-1',
     dispatch: {state: 'queued_to_backend'},
     forward: {packets: 3, bytes: 0, failed: 0, backend_writes: 2, backend_write_failed: 1,
               backend_write_failure: 'backend_write_failed'},
     return: {evidence: 'observed', authority: 'current_tuple_association',
              matched: 4, admitted: 3, delivered: 2, failed: 1,
              failure: 'client_queue_full'},
     names: [], names_match: 'none', names_reason: 'no_retained_answer', names_considered: 0,
     name_candidates: [],
     name_attempts: [{name: 'missing.example', qtype: 'A', kind: 'nxdomain',
                      received_at: '2026-11-17T09:09:50Z'}]},
    {protocol: 'tcp', destination_ip: '1.1.1.1', destination_port: 80, choice: 'DIRECT',
     route_generation: 3, last_seen_age_seconds: 12, expired: false, close_seen: false,
     decision_time: 'not_recorded', decision_reason: 'not_recorded',
     policy_generation: 'not_recorded',
     dispatch: {state: 'written_to_wan'}, forward: {packets: 4, bytes: 400, failed: 0},
     return: {evidence: 'observed', packets: 2, bytes: 200,
              first_at: '2026-11-17T09:10:00Z', last_at: '2026-11-17T09:10:01Z'},
     names: [], names_match: 'not_recorded', names_considered: 0, name_candidates: []}
  ];
  return answer;
})(responder);
`, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientFlowRows'), 3, 'all three states are rendered');

const ambiguous = rowCells('policyClientFlowRows', 0);
assert.equal(ambiguous[1], '93.184.216.34:443 (FIRST plain.example PLUS 1)',
  'the first of several candidate names is shown with a count of the others, never collapsed to that one alone');
assert.equal(ambiguous[2], 'DECISION:proxy', 'the recorded route is rendered');
assert.equal(ambiguous[3], 'DECISION_REASON:proxy_cidr_rule',
  'the deciding reason is one label, not a sentence of metadata');
assert.equal(rowCellTitles('policyClientFlowRows', 0)[3],
  '2026-11-17T09:09:58Z · gen-1 · BACKEND 77 · proxy_cidr_rule',
  'the instant, the generation, the selected backend and the token are the cell tooltip');

const none = rowCells('policyClientFlowRows', 1);
assert.equal(none[1], '8.8.8.8:53',
  'a name the client tried without an answer is not this flow destination name');
assert.equal(none[3], 'DECISION_REASON:no_trusted_evidence',
  'the fail-closed default has its own label');

const unrecorded = rowCells('policyClientFlowRows', 2);
assert.equal(unrecorded[1], '1.1.1.1:80');
assert.equal(unrecorded[3], 'DECISION_REASON:not_recorded',
  'a flow without decision metadata says so instead of showing an empty instants cell');
assert.equal(rowCellTitles('policyClientFlowRows', 2)[3], '',
  'a decision that recorded nothing offers no tooltip');
`)
}

// TestPolicyClientDiagFlowsTableKeepsFourColumnsAndDropsTheRest pins the flows
// table to the four columns an operator reads (issue #940). Both flows below carry
// the dispatch and return evidence the table used to spell out, and none of it may
// be rendered: not in a column, not under another name, and not hidden by a style.
// The test fails if a removed column comes back.
func TestPolicyClientDiagFlowsTableKeepsFourColumnsAndDropsTheRest(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript+`
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return base(url, opts);
  const answer = await base(url, opts);
  answer.flows.entries = [
    {protocol: 'tcp', destination_ip: '213.180.204.186', destination_port: 443, choice: 'DIRECT',
     route_generation: 3, last_seen_age_seconds: 3, expired: false, close_seen: false,
     decision_time: '2026-11-17T09:09:58Z', decision_reason: 'allocation_direct',
     policy_generation: 'gen-1',
     dispatch: {state: 'written_to_wan'}, forward: {packets: 2, bytes: 120, failed: 0},
     return: {evidence: 'not_observed', packets: 0, bytes: 0},
     names: [], names_match: 'none', names_considered: 0, name_candidates: []},
    {protocol: 'tcp', destination_ip: '185.73.194.82', destination_port: 443, choice: 'DIRECT',
     route_generation: 3, last_seen_age_seconds: 4, expired: false, close_seen: false,
     decision_time: '2026-11-17T09:09:59Z', decision_reason: 'allocation_direct',
     policy_generation: 'gen-1',
     dispatch: {state: 'failed', reason: 'direct_egress_unavailable'},
     forward: {packets: 0, bytes: 0, failed: 1, failure: 'direct_egress_unavailable'},
     return: {evidence: 'not_observed', packets: 0, bytes: 0},
     names: [], names_match: 'none', names_considered: 0, name_candidates: []}
  ];
  return answer;
})(responder);
`, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientFlowRows'), 2, 'both direct flows are rendered');

const headers = rowHeaders('policyClientFlowRows');
assert.deepEqual(headers, ['policy_client_column_protocol', 'policy_client_column_destination',
  'policy_client_column_choice', 'policy_client_column_decision'],
  'the header row is the four columns, not eight');
['policy_client_column_names', 'policy_client_column_outcome',
 'policy_client_column_last_seen', 'policy_client_column_state'].forEach(removed => {
  assert.ok(headers.indexOf(removed) === -1,
    'the removed header ' + removed + ' must not return');
});

Array.from(w.document.getElementById('policyClientFlowRows').children).forEach((row, index) => {
  assert.equal(row.children.length, 4, 'row ' + index + ' carries exactly four cells');
});

// Same route and same deciding reason: the two rows are indistinguishable here
// because the dispatch difference the removed column used to carry is gone from
// the DOM, not merely hidden.
assert.deepEqual(rowCells('policyClientFlowRows', 0),
  ['PROTO:tcp', '213.180.204.186:443', 'DECISION:direct', 'DECISION_REASON:allocation_direct']);
assert.deepEqual(rowCells('policyClientFlowRows', 1),
  ['PROTO:tcp', '185.73.194.82:443', 'DECISION:direct', 'DECISION_REASON:allocation_direct']);

const removedEvidence = ['ROUTE ', 'DISPATCH', 'OUTCOME', 'RETURN', 'DEVICE ', 'FAILURE',
  'direct_egress_unavailable', 'written_to_wan'];
rowCells('policyClientFlowRows', 1).forEach(cell => {
  removedEvidence.forEach(marker => {
    assert.equal(cell.indexOf(marker), -1,
      'the removed dispatch/return evidence must not be rendered as ' + marker);
  });
});
assert.ok(rowCells('policyClientFlowRows', 0).indexOf('active') === -1,
  'the removed state column is not rendered under another name');
`)
}

// TestPolicyClientDiagFlowDestinationNamesOnlyWhenKnown pins the Destination cell:
// the address the tuple carried, and a name only when a stored answer genuinely
// names it. A name the client tried without an answer is not a name; when several
// names match, the first is shown with a count of the others instead of the row
// pretending the address has that one name.
func TestPolicyClientDiagFlowDestinationNamesOnlyWhenKnown(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript+`
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return base(url, opts);
  const answer = await base(url, opts);
  answer.flows.entries = [
    {protocol: 'tcp', destination_ip: '93.184.216.34', destination_port: 443, choice: 'DIRECT',
     last_seen_age_seconds: 3, expired: false, close_seen: false,
     decision_reason: 'evidence_direct', names: [], names_match: 'not_recorded',
     names_reason: 'no_retained_answer',
     name_attempts: [{name: 'missing.example', qtype: 'A', kind: 'nxdomain',
                      received_at: '2026-11-17T09:09:50Z'}]},
    {protocol: 'udp', destination_ip: '8.8.8.8', destination_port: 53, choice: 'PROXY',
     last_seen_age_seconds: 4, expired: false, close_seen: false,
     decision_reason: 'no_trusted_evidence',
     names: ['plain.example'], names_match: 'unique', names_considered: 1},
    {protocol: 'tcp', destination_ip: '1.1.1.1', destination_port: 443, choice: 'PROXY',
     last_seen_age_seconds: 5, expired: false, close_seen: false,
     decision_reason: 'proxy_cached_evidence',
     names: ['plain.example', 'shared.example', 'other.example'],
     names_match: 'ambiguous', names_considered: 3}
  ];
  return answer;
})(responder);
`, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientFlowRows'), 3, 'all three destinations are rendered');

// 1. Only unanswered attempts: no name, because no answer named this address.
const attemptedOnly = rowCells('policyClientFlowRows', 0);
assert.equal(attemptedOnly[1], '93.184.216.34:443',
  'an unanswered attempt must not be presented as the flow destination name');
assert.ok(attemptedOnly[1].indexOf('missing.example') === -1,
  'the attempted name stays out of the destination cell entirely');

// 2. One stored answer names the address: it is shown with the address.
const single = rowCells('policyClientFlowRows', 1);
assert.equal(single[1], '8.8.8.8:53 (plain.example)',
  'the one answer that names the address is shown beside it');

// 3. Several stored answers name it: the first name is shown with a count of the
//    others, so the address never looks like it has that one name.
const several = rowCells('policyClientFlowRows', 2);
assert.equal(several[1], '1.1.1.1:443 (FIRST plain.example PLUS 2)',
  'the first of several matching names is shown with a count of the others');
assert.equal(rowCellTitles('policyClientFlowRows', 2)[1],
  'plain.example, shared.example, other.example',
  'every matching name is available in the cell tooltip');
assert.equal(rowCellTitles('policyClientFlowRows', 0)[1], '',
  'an address with no known name carries no tooltip');
`)
}

// TestPolicyClientDiagFlowDecisionLabels pins the Decision cell: one short label per
// recorded condition, with no instant, generation, backend id or raw token in the
// cell text. The detail the cell cannot show is its tooltip, which is where the
// token stays quotable.
func TestPolicyClientDiagFlowDecisionLabels(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript+`
const reasons = ['allocation_direct', 'allocation_cdn_excluded', 'no_trusted_evidence',
  'prohibited_destination', 'direct_egress_unavailable', 'proxy_cidr_rule',
  'evidence_direct', 'proxy_cached_evidence', 'sticky_flow', 'non_tcp_udp_fallback',
  'not_recorded', 'brand_new_reason'];
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return base(url, opts);
  const answer = await base(url, opts);
  answer.flows.entries = reasons.map((reason, index) => ({
    protocol: 'tcp', destination_ip: '93.184.216.' + (10 + index), destination_port: 443,
    choice: 'DIRECT', last_seen_age_seconds: 3, expired: false, close_seen: false,
    decision_time: reason === 'not_recorded' ? 'not_recorded'
      : '2026-11-17T09:09:5' + (index % 10) + 'Z', decision_reason: reason,
    policy_generation: 'gen-9', backend_tunnel_id: index === 5 ? 77 : undefined,
    names: [], names_match: 'not_recorded', name_attempts: []}));
  return answer;
})(responder);
`, `
// The labels this test asserts are the shipped English wording for each token.
const LABELS = {
  policy_client_decision_reason_allocation_direct: 'Direct by list',
  policy_client_decision_reason_allocation_cdn_excluded: 'Proxy: shared CDN',
  policy_client_decision_reason_no_trusted_evidence: 'Default proxy failover',
  policy_client_decision_reason_prohibited_destination: 'Blocked destination',
  policy_client_decision_reason_direct_egress_unavailable: 'Direct unavailable',
  policy_client_decision_reason_proxy_cidr_rule: 'Operator rule',
  policy_client_decision_reason_evidence_direct: 'DNS evidence',
  policy_client_decision_reason_proxy_cached_evidence: 'DNS evidence: proxy',
  policy_client_decision_reason_sticky_flow: 'Kept earlier choice',
  policy_client_decision_reason_non_tcp_udp_fallback: 'Proxy: protocol fallback',
  policy_client_decision_reason_not_recorded: 'Not recorded',
  policy_client_decision_reason_unknown: 'Other reason'
};
const fallback = w._;
w._ = key => LABELS[key] || fallback(key);

selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientFlowRows'), 12, 'every recorded reason is one row');

const rows = Array.from(w.document.getElementById('policyClientFlowRows').children);
assert.deepEqual(rows.map(row => row.children[3].textContent), [
  'Direct by list',
  'Proxy: shared CDN',
  'Default proxy failover',
  'Blocked destination',
  'Direct unavailable',
  'Operator rule',
  'DNS evidence',
  'DNS evidence: proxy',
  'Kept earlier choice',
  'Proxy: protocol fallback',
  'Not recorded',
  'Other reason'
], 'each recorded reason renders its own short label');

// The cell carries the label and nothing else.
rows.forEach((row, index) => {
  const cell = row.children[3].textContent;
  assert.ok(cell.indexOf('2026-') === -1, 'the decision instant stays out of the cell');
  assert.ok(cell.indexOf('gen-9') === -1, 'the policy generation stays out of the cell');
  assert.ok(cell.indexOf('BACKEND') === -1, 'the backend stays out of the cell');
  assert.equal(cell.indexOf(reasons[index]), -1,
    'the raw reason token stays out of the cell');
});

// The tooltip is where the detail lives.
const titles = rows.map(row => row.children[3].getAttribute('title') || '');
assert.equal(titles[0], '2026-11-17T09:09:50Z · gen-9 · allocation_direct',
  'the instant, generation and token are the cell tooltip');
assert.equal(titles[5], '2026-11-17T09:09:55Z · gen-9 · BACKEND 77 · proxy_cidr_rule',
  'a proxy decision keeps its selected backend in the tooltip');
assert.equal(titles[10], 'gen-9',
  'a flow recorded without a reason has no instant or token to describe');
assert.ok(titles[11].indexOf('brand_new_reason') !== -1,
  'a token this build does not know stays quotable in the tooltip');
`)
}

// TestPolicyClientDiagRendersTerminalQueryEvents covers the terminal-query table:
// an answered query, a no-answer query, an NXDOMAIN, an upstream timeout and a
// truncated reply are each rendered with their own result, transport, instants and
// delivery, and the section states that a recorded query is not route evidence.
func TestPolicyClientDiagRendersTerminalQueryEvents(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript+`
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return base(url, opts);
  const answer = await base(url, opts);
  answer.dns.events_available = true;
  answer.dns.events_total = 5;
  answer.dns.events_truncated = false;
  answer.dns.events = [
    {seq: 5, name: 'big.example', qtype: 'A', rcode: 'NOERROR', kind: 'truncated',
     transport: 'udp', delivered: true, truncated: true,
     received_at: '2026-11-17T09:10:05Z', answered_at: '2026-11-17T09:10:05Z', count: 1,
     first_seen: '2026-11-17T09:10:05Z', last_seen: '2026-11-17T09:10:05Z'},
    {seq: 4, name: 'fail.example', qtype: 'A', rcode: 'SERVFAIL', kind: 'upstream_error',
     upstream_error: 'timeout', transport: 'udp', delivered: true, truncated: false,
     received_at: '2026-11-17T09:10:04Z', answered_at: '2026-11-17T09:10:04Z', count: 1,
     first_seen: '2026-11-17T09:10:04Z', last_seen: '2026-11-17T09:10:04Z'},
    {seq: 3, name: 'nx.example', qtype: 'A', rcode: 'NXDOMAIN', kind: 'nxdomain',
     transport: 'udp', delivered: true, truncated: false,
     received_at: '2026-11-17T09:10:03Z', answered_at: '2026-11-17T09:10:03Z', count: 1,
     first_seen: '2026-11-17T09:10:03Z', last_seen: '2026-11-17T09:10:03Z'},
    {seq: 2, name: 'plain.example', qtype: 'AAAA', rcode: 'NOERROR', kind: 'no_answer',
     transport: 'udp', delivered: true, truncated: false,
     received_at: '2026-11-17T09:10:02Z', answered_at: '2026-11-17T09:10:02Z', count: 1,
     first_seen: '2026-11-17T09:10:02Z', last_seen: '2026-11-17T09:10:02Z'},
    {seq: 1, name: 'plain.example', qtype: 'A', rcode: 'NOERROR', kind: 'answered',
     transport: 'udp', delivered: false, truncated: false,
     received_at: '2026-11-17T09:10:01Z', answered_at: '2026-11-17T09:10:01Z', count: 1,
     first_seen: '2026-11-17T09:10:01Z', last_seen: '2026-11-17T09:10:01Z'}
  ];
  answer.dns.event_coverage = {started_at: '2026-11-17T09:00:00Z', events_stored: 5,
    estimated_bytes: 640, written: 7, collapsed: 1, evicted_per_session: 0, evicted_global: 1,
    aged_out: 0, rejected_no_room: 0,
    limits: {events_per_session: 128, events_total: 4096, max_age_seconds: 1800},
    not_recorded: ['dns_transport_not_recorded']};
  return answer;
})(responder);
`, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

assert.equal(rowCount('policyClientEventRows'), 5, 'every terminal query is rendered');

const truncated = rowCells('policyClientEventRows', 0);
assert.equal(truncated[0], 'big.example');
assert.equal(truncated[2], 'EVENT:truncated', 'a truncated reply says so');
assert.equal(truncated[3], 'UDP', 'the client transport is shown');
assert.equal(truncated[6], 'DELIVERED', 'the reply reached the client');

const failed = rowCells('policyClientEventRows', 1);
assert.equal(failed[2], 'EVENT:upstream_error (UPSTREAM:timeout)',
  'the failed exchange states its class, not a guess');

const nxdomain = rowCells('policyClientEventRows', 2);
assert.equal(nxdomain[2], 'EVENT:nxdomain', 'an NXDOMAIN is a distinct terminal result');

const noAnswer = rowCells('policyClientEventRows', 3);
assert.equal(noAnswer[2], 'EVENT:no_answer', 'a no-answer response is not an error');

const undelivered = rowCells('policyClientEventRows', 4);
assert.equal(undelivered[6], 'NOT-DELIVERED',
  'a response the consumer never received is not reported as delivered');

assert.equal(text('policyClientEventCoverage'), 'EVENTS-COVERAGE 5/1/1/0',
  'the event store coverage is stated');
`)
}

// TestPolicyClientDiagModuleElementIDs guards the wiring between the module and
// the template: every id the controller looks up must exist in the rendered
// section.
func TestPolicyClientDiagModuleElementIDs(t *testing.T) {
	section := clientDiagSectionHTMLForTest(t)

	// Both shipped assets of the section are scanned: the controller and the destination
	// filter module it delegates to.
	source := ""
	for _, asset := range []string{"static/js/policy_client_diag.js", "static/js/policy_client_diag_filter.js"} {
		module, err := StaticFS.ReadFile(asset)
		if err != nil {
			t.Fatalf("read %s: %v", asset, err)
		}
		source = source + string(module)
	}

	lookup := regexp.MustCompile(`(?:clientElement|document.getElementById)\('([A-Za-z0-9_]+)'\)`)
	matches := lookup.FindAllStringSubmatch(source, -1)
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
