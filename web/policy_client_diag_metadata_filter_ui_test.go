package web

// Behavioural JSDOM coverage for the metadata and destination-filter parts of the
// per-client diagnosis panel (#861).
//
// The controller is evaluated as shipped against the rendered partial, so these cases
// describe what an administrator sees: the backend a PROXY decision selected, the policy
// generation an answer was evaluated under, what no retained store holds, and a filter
// that narrows the rows already read for the selected session without reading anything.

import (
	"testing"
)

// clientMetadataFilterScript is one diagnosis answer with two destinations, a proxy flow
// carrying its backend, records carrying their policy generation, a refusal without a
// tuple and explicit coverage lists.
const clientMetadataFilterScript = `
const targets = () => ({clients: [
  {session_id: 'sess-a', connection_name: 'phone', assigned_ip: '10.100.0.5',
   route_live: true, route_generation: 4, evidence_entries: 2},
  {session_id: 'sess-b', connection_name: 'tablet', assigned_ip: '10.100.0.6',
   route_live: true, route_generation: 1, evidence_entries: 0}
], sampled_at: '2026-11-17T09:10:00Z', policy_routing_enabled: true, read_only: true,
 not_covered: []});
const diagnosis = (session) => ({
  selection: {session_id: session, state: 'live', route_generation: session === 'sess-a' ? 4 : 1,
              connection_name: session === 'sess-a' ? 'phone' : 'tablet',
              assigned_ip: session === 'sess-a' ? '10.100.0.5' : '10.100.0.6'},
  coverage: {policy_routing_enabled: true, sampled_at: '2026-11-17T09:10:00Z',
             evidence_source: 'route_cache_entries_and_live_flows',
             not_covered: ['ipv6_not_supported', 'encrypted_dns_not_observed'],
             not_recorded: ['flow_evidence_install_failure_not_recorded']},
  dns: {available: true, state: 'fresh', generation: 'gen-1',
        names: {match: 'not_recorded', reason: 'dns_names_not_retained'},
        entries: [
          {address: '93.184.216.34', decision: 'DIRECT', observed_at: '2026-11-17T09:09:30Z',
           expires_at: '2026-11-17T09:14:30Z', expires_in_seconds: 270, age_seconds: 30,
           state: 'fresh', names: [], names_match: 'not_recorded'},
          {address: '1.1.1.1', decision: 'PROXY', observed_at: '2026-11-17T09:09:20Z',
           expires_at: '2026-11-17T09:14:20Z', expires_in_seconds: 260, age_seconds: 40,
           state: 'fresh', names: [], names_match: 'not_recorded'}
        ],
        total: 2, truncated: false,
        records_available: true, records_total: 2, records_truncated: false,
        records: [
          {seq: 2, name: 'plain.example', qtype: 'A', rcode: 'NOERROR', aliases: [],
           addresses: [{address: '93.184.216.34', decision: 'DIRECT'}], resolved_addresses: 1,
           observed_at: '2026-11-17T09:09:40Z', expires_at: '2026-11-17T09:14:40Z',
           state: 'active', classification: 'valid', cache_write: 'ok', count: 1,
           first_seen: '2026-11-17T09:09:40Z', last_seen: '2026-11-17T09:09:40Z',
           route_generation: 4, route_generation_established: true, policy_generation: 'gen-dns-7'},
          {seq: 1, name: 'other.example', qtype: 'A', rcode: 'NOERROR', aliases: [],
           addresses: [{address: '93.184.216.50', decision: 'PROXY'}], resolved_addresses: 1,
           observed_at: '2026-11-17T09:09:30Z', expires_at: '2026-11-17T09:14:30Z',
           state: 'active', classification: 'valid', cache_write: 'ok', count: 1,
           first_seen: '2026-11-17T09:09:30Z', last_seen: '2026-11-17T09:09:30Z',
           route_generation: 4, route_generation_established: true, policy_generation: 'gen-dns-6'}
        ],
        record_coverage: {
          started_at: '2026-11-17T09:00:00Z', records_stored: 2, estimated_bytes: 512,
          sessions: 1, written: 2, collapsed: 0, evicted_per_session: 0, evicted_global: 0,
          aged_out: 0, rejected_no_room: 0, without_route_generation: 0,
          limits: {records_per_session: 128, records_total: 4096, max_age_seconds: 1800,
                   bytes_total: 4194304, names_per_record: 8, addresses_per_record: 16},
          not_recorded: []
        },
        events_available: true, events_total: 2, events_truncated: false,
        events: [
          {seq: 4, name: 'plain.example', qtype: 'A', kind: 'answered', transport: 'udp',
           delivered: true, received_at: '2026-11-17T09:09:40Z', answered_at: '2026-11-17T09:09:40Z',
           policy_generation: 'gen-dns-7'},
          {seq: 3, name: 'other.example', qtype: 'A', kind: 'nxdomain', transport: 'tcp',
           delivered: true, received_at: '2026-11-17T09:09:30Z', answered_at: '2026-11-17T09:09:30Z',
           policy_generation: 'gen-dns-6'}
        ],
        event_coverage: {started_at: '2026-11-17T09:00:00Z', events_stored: 2, collapsed: 0,
                         evicted_per_session: 0, evicted_global: 0, aged_out: 0, written: 2,
                         limits: {events_per_session: 128, events_total: 4096, max_age_seconds: 1800},
                         not_recorded: []}},
  flows: {available: true, state: 'recorded', scanned: 2, scan_complete: true, total: 2,
          truncated: false,
          entries: [
            {protocol: 'tcp', client_src_port: 40002, destination_ip: '93.184.216.34',
             destination_port: 443, choice: 'PROXY', route_generation: 4,
             last_seen_age_seconds: 12, expired: false, close_seen: false,
             decision_time: '2026-11-17T09:09:58Z', decision_reason: 'proxy_cidr_rule',
             policy_generation: 'gen-flow-9', backend_tunnel_id: 77,
             dispatch: {state: 'queued_to_backend'}, forward: {packets: 2, bytes: 120, failed: 0},
             return: {evidence: 'not_measured', packets: 0, bytes: 0},
             names: ['plain.example'], names_match: 'unique', names_considered: 1,
             name_candidates: []},
            {protocol: 'udp', client_src_port: 40100, destination_ip: '1.1.1.1',
             destination_port: 53, choice: 'DIRECT', route_generation: 4,
             last_seen_age_seconds: 30, expired: false, close_seen: false,
             decision_time: '2026-11-17T09:09:50Z', decision_reason: 'evidence_direct',
             policy_generation: 'gen-flow-8',
             dispatch: {state: 'written_to_wan'}, forward: {packets: 1, bytes: 60, failed: 0},
             return: {evidence: 'not_observed', packets: 0, bytes: 0},
             names: [], names_match: 'not_recorded', names_considered: 0, name_candidates: []}
          ]},
  drops: {available: true, state: 'observed', total: 2, truncated: false,
          entries: [
            {reason: 'prohibited_destination', has_tuple: true, destination_ip: '127.0.0.1',
             destination_port: 53, protocol: 'udp', count: 2, last_seen: '2026-11-17T09:09:45Z'},
            {reason: 'invalid_client_packet', has_tuple: false, count: 1,
             last_seen: '2026-11-17T09:09:20Z'}
          ],
          coverage: {stored: 2, merged: 0, evicted: 0, pruned: 0, session_keys: 1,
                     keys: 1, key_limit: 32, age_limit_seconds: 900}},
  limitations: ['not_an_atomic_cross_subsystem_snapshot', 'flow_counters_are_live_samples'],
  evaluated_at: '2026-11-17T09:10:00Z', read_only: true
});
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return targets();
  if (url.endsWith('/api/vpn/policy/client-diagnosis')) {
    return diagnosis((opts.body || {}).session_id);
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
`

// setDestinationFilter types into the filter input and lets the controller re-render.
const setDestinationFilter = `
const setFilter = async (value) => {
  const input = w.document.getElementById('policyClientDestinationFilter');
  input.value = value;
  input.dispatchEvent(new w.Event('input'));
  await settle();
};
`

// TestPolicyClientDiagRendersRecordedMetadata proves the panel states the backend a
// PROXY decision selected, the policy generation an answer was evaluated under, and the
// two coverage lists separately.
func TestPolicyClientDiagRendersRecordedMetadata(t *testing.T) {
	runClientDiagScenario(t, clientMetadataFilterScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

const proxyFlow = rowCells('policyClientFlowRows', 0);
assert.equal(proxyFlow[1], '93.184.216.34:443 (plain.example)',
  'the destination carries the one stored answer that names it');
assert.equal(proxyFlow[3], 'DECISION_REASON:proxy_cidr_rule',
  'the recorded reason is one label, not a sentence of metadata');
assert.equal(rowCellTitles('policyClientFlowRows', 0)[3],
  '2026-11-17T09:09:58Z · gen-flow-9 · BACKEND 77 · proxy_cidr_rule',
  'the recorded decision states its instant, generation and selected backend as the cell tooltip');
const directFlow = rowCells('policyClientFlowRows', 1);
assert.equal(directFlow[3], 'DECISION_REASON:evidence_direct');
assert.equal(rowCellTitles('policyClientFlowRows', 1)[3], '2026-11-17T09:09:50Z · gen-flow-8 · evidence_direct',
  'a DIRECT decision shows no backend it never selected');

const answer = rowCells('policyClientDNSRows', 0);
assert.equal(answer[0], 'plain.example');
assert.equal(answer[6], 'gen-dns-7',
  'the policy generation the answer was evaluated under is rendered');
assert.equal(rowCells('policyClientDNSRows', 1)[6], 'gen-dns-6');

const notCovered = Array.from(w.document.getElementById('policyClientNotCovered').children).map(li => li.textContent);
assert.deepEqual(notCovered,
  ['LIMIT:ipv6_not_supported', 'LIMIT:encrypted_dns_not_observed'],
  'facts no retained store holds are listed apart from the recorded rows');
const limitations = Array.from(w.document.getElementById('policyClientLimitations').children).map(li => li.textContent);
assert.deepEqual(limitations,
  ['LIMIT:not_an_atomic_cross_subsystem_snapshot', 'LIMIT:flow_counters_are_live_samples'],
  'the limitations list states only what the recorded rows cannot say');
`)
}

// TestPolicyClientDiagDestinationFilterNarrowsWithoutReading proves the filter narrows
// the rows already read for the selected session, keeps each table's own recorded
// counts, and restores the full history when it is cleared - without a single extra
// request.
func TestPolicyClientDiagDestinationFilterNarrowsWithoutReading(t *testing.T) {
	runClientDiagScenario(t, clientMetadataFilterScript, setDestinationFilter+`
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

const diagnosisCalls = () => requestsTo('/api/vpn/policy/client-diagnosis', 'POST').length;
assert.equal(diagnosisCalls(), 1, 'one diagnosis read before filtering');
assert.equal(rowCount('policyClientFlowRows'), 2);
assert.equal(rowCount('policyClientDNSRows'), 2);
assert.equal(rowCount('policyClientEventRows'), 2);
assert.equal(rowCount('policyClientDropRows'), 2);
assert.equal(text('policyClientFilterFoot'), '', 'no filter, no filter line');

// A name narrows every table that records destinations, including the answer that
// named the address.
await setFilter('plain.example');
assert.equal(rowCount('policyClientFlowRows'), 1, 'the flow whose name matches stays');
assert.equal(rowCells('policyClientFlowRows', 0)[1], '93.184.216.34:443 (plain.example)');
assert.equal(rowCount('policyClientDNSRows'), 1, 'the answer record that matches stays');
assert.equal(rowCount('policyClientEventRows'), 1, 'the query that matches stays');
assert.equal(rowCount('policyClientDropRows'), 0, 'no refusal carries that destination');
assert.equal(text('policyClientFilterFoot'), 'FILTER 3/10 "plain.example"',
  'the filter line states what it left out of the recorded rows');
assert.equal(text('policyClientFlowFoot'), 'FLOWS 2/2',
  'the section foot still describes the recorded page, not the filtered one');

// An address narrows by the address the router wrote, and the refusal that carried no
// tuple has no destination to match.
await setFilter('1.1.1.1');
assert.equal(rowCount('policyClientFlowRows'), 1);
assert.equal(rowCells('policyClientFlowRows', 0)[1], '1.1.1.1:53');
assert.equal(rowCount('policyClientDNSRows'), 0, 'no answer carries that destination');
assert.equal(rowCount('policyClientDropRows'), 0,
  'a refusal without a tuple cannot match a destination filter');
assert.equal(text('policyClientFilterFoot'), 'FILTER 2/10 "1.1.1.1"',
  'the answer evidence, the flow and nothing else carry that address');

// A term nothing carries says so instead of looking like an empty history.
await setFilter('nothing.example');
assert.equal(rowCount('policyClientFlowRows'), 0);
assert.equal(rowCount('policyClientDNSRows'), 0);
assert.equal(text('policyClientFilterFoot'), 'NO MATCH "nothing.example"');
assert.equal(text('policyClientDNSFoot'), '',
  'an empty filtered table makes no claim about the recorded page');

// Clearing the filter restores the whole selected history and mutated nothing.
await setFilter('');
assert.equal(rowCount('policyClientFlowRows'), 2, 'the full history is back');
assert.equal(rowCount('policyClientDNSRows'), 2);
assert.equal(rowCount('policyClientEventRows'), 2);
assert.equal(rowCount('policyClientDropRows'), 2);
assert.equal(text('policyClientFilterFoot'), '', 'the filter line is cleared');
assert.equal(diagnosisCalls(), 1, 'filtering never re-reads the server');
`)
}

// TestPolicyClientDiagDestinationFilterLeavesWithTheSelection proves a selection change
// clears the filter and the rows, so a filter can never narrow another client's history.
func TestPolicyClientDiagDestinationFilterClearsWithTheSelection(t *testing.T) {
	runClientDiagScenario(t, clientMetadataFilterScript, setDestinationFilter+`
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
await setFilter('plain.example');
assert.equal(rowCount('policyClientDNSRows'), 1);

// Changing the selection invalidates the answer, the filter text and the rows.
selectClient('sess-b');
assert.equal(w.document.getElementById('policyClientDestinationFilter').value, '',
  'the filter text leaves with the selection');
assert.equal(rowCount('policyClientDNSRows'), 0, 'the previous client rows are cleared');
assert.equal(rowCount('policyClientFlowRows'), 0);
assert.equal(resultHidden(), true, 'the result block is hidden until the new read');

// The new selection's own answer renders unfiltered.
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientFlowRows'), 2);
assert.equal(text('policyClientFilterFoot'), '', 'the new answer is unfiltered');
`)
}
