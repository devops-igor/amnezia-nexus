package web

// Behavioural JSDOM coverage for the DNS observation table of the per-client
// diagnosis panel (issue #861, slice 2).
//
// The shipped controller is evaluated as-is against the shipped template, so the
// assertions describe what the browser renders from a real diagnosis answer: the
// observed answers with their addresses and decisions, the collector's coverage
// line, and the explicit gaps of this build's observation boundary.

import (
	"testing"
)

// clientDNSDiagnosisScript answers one diagnosis with two stored answers and one
// coverage block, mirroring the shipped wire shape.
const clientDNSDiagnosisScript = `
const targets = () => ({clients: [
  {session_id: 'sess-a', connection_name: 'phone', assigned_ip: '10.100.0.5',
   route_live: true, route_generation: 4}
], sampled_at: '2026-11-17T09:10:00Z', policy_routing_enabled: true, read_only: true,
 not_covered: []});
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return targets();
  return {
    selection: {session_id: 'sess-a', state: 'live', route_generation: 4},
    dns: {
      available: true, state: 'fresh', names: {match: 'not_recorded'},
      records_available: true, records_total: 2, records_truncated: false,
      records: [
        {seq: 7, name: 'alias.example', qtype: 'A', rcode: 'NOERROR',
         aliases: ['plain.example'],
         addresses: [{address: '93.184.216.34', decision: 'DIRECT'}],
         resolved_addresses: 1, observed_at: '2026-11-17T09:09:40Z',
         received_at: 'not_recorded', transport: 'not_recorded',
         expires_at: '2026-11-17T09:14:40Z', expires_in_seconds: 280,
         state: 'active', classification: 'valid', cache_write: 'ok',
         count: 3, first_seen: '2026-11-17T09:09:40Z', last_seen: '2026-11-17T09:09:55Z',
         route_generation: 4, route_generation_established: true,
         policy_generation: 'gen-1'},
        {seq: 6, name: 'typed.example', qtype: 'AAAA', rcode: 'NOERROR', aliases: [],
         addresses: [], resolved_addresses: 0, observed_at: '2026-11-17T09:09:30Z',
         received_at: 'not_recorded', transport: 'not_recorded', expires_at: '',
         expires_in_seconds: 0, state: 'not_recorded', classification: 'invalid',
         classification_reason: 'invalid DNS answer envelope', cache_write: 'ok',
         count: 1, first_seen: '2026-11-17T09:09:30Z', last_seen: '2026-11-17T09:09:30Z',
         route_generation_established: false, policy_generation: 'gen-1'}
      ],
      record_coverage: {
        started_at: '2026-11-17T09:00:00Z', records_stored: 2, estimated_bytes: 512,
        sessions: 1, written: 6, collapsed: 3, evicted_per_session: 1, evicted_global: 2,
        aged_out: 4, rejected_no_room: 0, without_route_generation: 1,
        limits: {records_per_session: 128, records_total: 4096, max_age_seconds: 1800,
                 bytes_total: 4194304, names_per_record: 8, addresses_per_record: 16},
        not_recorded: []
      }
    },
    flows: {available: true, state: 'recorded', scanned: 1, scan_complete: true, total: 0,
            truncated: false, entries: []},
    drops: {available: false, state: 'not_recorded', entries: []},
    limitations: ['not_an_atomic_cross_subsystem_snapshot'], evaluated_at: '2026-11-17T09:10:00Z', read_only: true
  };
};
`

func TestPolicyClientDiagRendersObservedDNSAnswers(t *testing.T) {
	runClientDiagScenario(t, clientDNSDiagnosisScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

assert.equal(rowCount('policyClientDNSRows'), 2, 'both stored answers are rendered');

// The alias chain is shown on the queried name, not as a second row.
const aliasRow = rowCells('policyClientDNSRows', 0);
assert.equal(aliasRow[0], 'alias.example → plain.example',
  'the validated CNAME chain is rendered on the queried name');
assert.equal(aliasRow[1], 'A', 'the observed query type is rendered');
assert.equal(aliasRow[2], '93.184.216.34 (DECISION:direct)',
  'the address is rendered with the decision that was written');
assert.equal(aliasRow[3], '2026-11-17T09:09:40Z', 'the observation instant is rendered');
assert.equal(aliasRow[4], '2026-11-17T09:14:40Z', 'the evidence deadline is rendered');
assert.equal(aliasRow[5], '3', 'the collapsed repeat count is rendered');
assert.equal(aliasRow[6], 'gen-1', 'the policy generation the answer was evaluated under is rendered');
assert.equal(aliasRow[7], 'STATE:active', 'the record state is translated from its token');

// A rejected answer keeps its row and states that nothing was evaluated.
const typedRow = rowCells('policyClientDNSRows', 1);
assert.equal(typedRow[0], 'typed.example');
assert.equal(typedRow[1], 'AAAA');
assert.equal(typedRow[2], '-', 'a rejected answer has no address to show');
assert.equal(typedRow[6], 'gen-1', 'a rejected answer still states its policy generation');
assert.equal(typedRow[7], 'STATE:not_recorded');

// Coverage is stated, and the answer table no longer claims gaps that the query
// history beside it records.
assert.equal(text('policyClientDNSCoverage'),
  'DNS-COVERAGE 2/3/3/4',
  'the collector coverage line reports stored, collapsed, evicted and aged counts');
const gaps = Array.from(w.document.getElementById('policyClientDNSGaps').children).map(li => li.textContent);
assert.deepEqual(gaps, [], 'the answer section claims no gap the query history records');
assert.equal(w.document.getElementById('policyClientDNSFoot').hidden, true,
  'a complete page needs no truncation note');
`)
}

func TestPolicyClientDiagDNSEmptyAndUnavailableStates(t *testing.T) {
	runClientDiagScenario(t, `
let recordsAvailable = true;
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    return {clients: [{session_id: 'sess-a', route_live: true, route_generation: 1}],
            sampled_at: '2026-11-17T09:10:00Z', policy_routing_enabled: true, read_only: true,
            not_covered: []};
  }
  return {selection: {session_id: 'sess-a', state: 'live', route_generation: 1},
    dns: {available: true, state: 'fresh', names: {match: 'not_recorded'}, entries: [],
          records_available: recordsAvailable, records: [], record_coverage: {not_recorded: []}},
    flows: {available: true, state: 'recorded', scanned: 0, scan_complete: true, total: 0,
            truncated: false, entries: []},
    drops: {available: false, state: 'not_recorded', entries: []},
    limitations: [], evaluated_at: '2026-11-17T09:10:00Z', read_only: true};
};
`, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientDNSRows'), 0);
assert.equal(text('policyClientDNSFoot'), 'policy_client_dns_empty',
  'a readable collector with no answers says so');
assert.equal(w.document.getElementById('policyClientDNSFoot').hidden, false);

// A build without a collector must not report the same thing.
recordsAvailable = false;
await w.diagnoseSelectedClient();
await settle();
assert.equal(text('policyClientDNSFoot'), 'policy_client_dns_not_recorded',
  'an unread collector says it does not record, not that nothing happened');
`)
}

func TestPolicyClientDiagDNSTruncationIsStated(t *testing.T) {
	runClientDiagScenario(t, clientDNSDiagnosisScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();

// Re-answer as a truncated page.
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return base(url, opts);
  const answer = await base(url, opts);
  answer.dns.records = answer.dns.records.slice(0, 1);
  answer.dns.records_total = 9;
  answer.dns.records_truncated = true;
  return answer;
})(responder);
await w.diagnoseSelectedClient();
await settle();

assert.equal(rowCount('policyClientDNSRows'), 1);
assert.equal(text('policyClientDNSFoot'), 'DNS-TRUNC 1/9',
  'a cut history reports shown and total');
assert.equal(w.document.getElementById('policyClientDNSFoot').hidden, false);
`)
}

// TestPolicyClientDiagDNSRowsAreClearedOnReselection keeps the selection rule
// intact for the new table: the previous client's answers must not survive a
// selection change.
func TestPolicyClientDiagDNSRowsAreClearedOnReselection(t *testing.T) {
	runClientDiagScenario(t, clientDNSDiagnosisScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(rowCount('policyClientDNSRows'), 2);

selectClient('');
assert.equal(rowCount('policyClientDNSRows'), 0, 'a reselection must clear the DNS table');
assert.equal(text('policyClientDNSCoverage'), '', 'and its coverage line');
assert.equal(w.document.getElementById('policyClientDNSGaps').children.length, 0, 'and its gaps');
`)
}
