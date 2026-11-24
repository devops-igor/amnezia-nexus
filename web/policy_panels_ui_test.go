package web

// Behavioural JSDOM coverage for the four policy readouts (#971).
//
// Each readout answers one question, so each is asserted in its healthy state and
// in every state the design contract enumerates as unhealthy: a panel that only
// ever renders "current" and "no error" cannot be told apart from one that never
// reads the server at all. The harness, the API double and the fixtures live in
// policy_routing_ui_test.go, which loads the same shipped modules and markup.

import (
	"fmt"
	"testing"
)

// TestPolicyRoutingControllerInventoryOverride covers the operator override
// surface (issue #920): the textarea is populated from the stored record, the
// save carries the edited list, and the status distinguishes an operator override
// from the shipped set, including a stale artifact and an unusable one.
func TestPolicyRoutingControllerInventoryOverride(t *testing.T) {
	runPolicyControllerScenario(t, `
const recordWith = (inventory) => ({
  enabled: false, sync_interval_seconds: 21600,
  inventory_override: ['203.0.113.0/24'],
  status: {enabled: false, ready: false, cidr_count: 0,
           sync_state: 'disabled', last_success: '', last_error: '', inventory: inventory}
});
const shipped = {source: 'ipdeny', retrieved_at: '2026-11-19', prefix_count: 8664,
                 sha256: 'a115697bb8ca', override_prefix_count: 0, age_days: 2,
                 max_age_days: 180, stale: false};
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy') && opts.method === 'PUT') {
    return {status: 'ok', enabled: false,
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
assert.equal(text('policyInventoryAge'), '2 days');
assert.equal(text('policyInventoryNotice'), '');
assert.equal(hidden('policyInventoryDigestRow'), true);

// The operator replaces it; the payload carries the edited list, and the answer
// renders the accepted override beside the shipped set, with the stale verdict
// the server reported and the digest that distinguishes two overrides of equal
// size.
editField('policy_inventory_override', ' 198.51.100.0/24 \n\n 203.0.113.0/24 ');
await w.savePolicySettings();
await settle();

const puts = requestsTo('/api/vpn/policy', 'PUT');
assert.equal(puts.length, 1, 'one save is exactly one PUT');
assert.deepEqual(puts[0].body.inventory_override, ['198.51.100.0/24', '203.0.113.0/24'],
  'the payload carries the override prefixes, trimmed and without blank lines');
assert.equal(text('policyInventoryPrefixes'), '8664',
  'the shipped prefix count stays the shipped count while an override is in force');
assert.equal(text('policyInventoryOverrideStatus'), 'OVERRIDE 2',
  'the override is reported beside the shipped set, by its configured count');
assert.equal(text('policyInventoryAge'), '200 days',
  'the age is the artifact age the server reported');
assert.equal(text('policyInventoryLimit'), '180 days', 'the limit is reported beside the age');
assert.equal(text('policyInventoryDigest'), 'deadbeefcafe',
  'the digest is shown, truncated to its reading length, so two overrides of equal size differ');
assert.equal(hidden('policyInventoryDigestRow'), false, 'with an override the digest row is shown');
assert.equal(answerState('policyInventoryAnswer'), 'warning',
  'a stale artifact is marked for attention, not presented as current');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_update_needed');
assert.equal(text('policyInventoryAnswerBody'), 'policy_inventory_update_needed_body');
// A single configured prefix reads in the singular.
responder = async (url, opts) => {
  return recordWith(Object.assign({}, shipped, {override_prefix_count: 1, override_sha256: 'aaaabbbbcccc'}));
};
await w.loadPolicySettings();
await settle();
assert.equal(text('policyInventoryOverrideStatus'), 'OVERRIDE1 1');
`)
}

// TestPolicyRoutingControllerInventoryUnusable keeps the broken-artifact case
// visible: an operator who sees an empty grid cannot tell "no data" from "the set
// is broken and the classifier cannot be installed".
//
// The fixture is the shape the producer actually emits. An unusable artifact sets
// `error`, the threshold and the configured override but not the age, and
// `age_days` has no omitempty, so the payload carries `age_days: 0` and
// `prefix_count: 0` — two zeros the panel must not render as facts.
func TestPolicyRoutingControllerInventoryUnusable(t *testing.T) {
	runPolicyControllerScenario(t, `
responder = async (url) => {
  return {enabled: false, sync_interval_seconds: 21600,
          status: {enabled: false, ready: false, cidr_count: 0,
                   sync_state: 'disabled', last_error: '',
                   inventory: {error: 'inventory provenance does not match the committed data',
                               age_days: 0, prefix_count: 0, max_age_days: 180,
                               override_prefix_count: 2, override_sha256: 'deadbeefcafe1234'}}};
};
`, `
assert.equal(answerState('policyInventoryAnswer'), 'danger');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_unusable_headline');
assert.equal(text('policyInventoryAnswerBody'), 'policy_inventory_unusable',
  'the unusable answer is the reported state, not a placeholder age');
assert.equal(text('policyInventoryPrefixes'), 'policy_not_available',
  'an unusable artifact reports no usable prefix count, never the payload zero');
assert.equal(text('policyInventoryAge'), 'policy_not_available',
  'the error is honoured before the age: the producer\'s unavoidable age_days 0 is not an age');
assert.equal(text('policyInventoryLimit'), '180 days',
  'the reported freshness threshold is kept even when the artifact is unusable');
assert.equal(text('policyInventoryOverrideStatus'), 'OVERRIDE 2',
  'the configured override is kept beside the unusable artifact');
assert.equal(text('policyInventoryDigest'), 'deadbeefcafe',
  'the override digest is kept, so two same-size overrides still differ');
assert.equal(text('policyInventoryNotice'), 'inventory provenance does not match the committed data',
  'the reported error is preserved verbatim inside the disclosure');
assert.equal(hidden('policyInventoryActionStatus'), false,
  'the unusable answer points at the panel that states the active routing state');

// The action moves focus to the named heading, and opens nothing it does not need.
el('policyInventoryActionStatus').click();
assert.equal(activeId(), 'policyStatusTitle',
  'the action must move focus to the policy status heading, not only change the URL');
`)

	// Control: a genuine same-day artifact still reports zero days, so the guard is
	// about the error and not about the number zero.
	runPolicyControllerScenario(t, `
responder = async () => ({enabled: true, sync_interval_seconds: 21600,
  status: {enabled: true, ready: true, cidr_count: 1, sync_state: 'synced',
           last_success: '2026-11-15T00:00:00Z', last_error: '',
           inventory: {source: 'ipdeny', retrieved_at: '2026-11-15', prefix_count: 8664,
                       age_days: 0, max_age_days: 180, stale: false, override_prefix_count: 0}}});
`, `
assert.equal(text('policyInventoryAge'), '0 days',
  'an artifact retrieved today has an age of zero days, and that is a real fact');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_current');
assert.equal(text('policyInventoryOverrideStatus'), 'policy_inventory_override_none',
  'a reported zero override count means none configured');
`)
}

// TestPolicyRoutingControllerCDNExclusions covers the CDN exclusion block (issue
// #934): the section must list the set the classifier actually consults, entry by
// entry, with the source it was read from. The fixture payload is the real table,
// so an entry the surface drops is an entry an operator would not see.
func TestPolicyRoutingControllerCDNExclusions(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, `["203.0.113.0/24"]`), fmt.Sprintf(`
const expected = %s;
assert.equal(answerState('policyCdnAnswer'), 'success');
assert.equal(text('policyCdnAnswerHeadline'), 'COUNT ' + expected.entries.length,
  'the headline states how many networks the classifier excludes');
assert.equal(text('policyCdnAnswerBody'), 'policy_cdn_count_answer_body');
const rows = w.document.querySelectorAll('#policyCdnEntries li');
assert.equal(rows.length, expected.entries.length,
  'every excluded network the server reported must be listed, in server order');
for (let i = 0; i < expected.entries.length; i++) {
  const entry = expected.entries[i];
  assert.ok(rows[i].textContent.indexOf(entry.provider) !== -1,
    'entry ' + i + ' must name its provider, got: ' + rows[i].textContent);
  assert.ok(rows[i].textContent.indexOf('AS' + entry.asn) !== -1,
    'entry ' + i + ' must name its ASN, got: ' + rows[i].textContent);
}
assert.equal(text('policyCdnDisclosureLabel'), 'policy_cdn_view_networks',
  'a populated set is reached through the list label');
assert.equal(hidden('policyCdnNetworksDetails'), false,
  'the disclosure is always reachable: one element answers every state');
assert.equal(text('policyCdnSource'), expected.source,
  'the block must name where the set comes from');
assert.equal(text('policyCdnCount'), String(expected.entries.length),
  'the count must be the number of networks the classifier excludes');
assert.equal(text('policyCdnNotice'), '', 'a usable set carries no warning');
`, policyCDNPayloadForTest(t)))
}

// TestPolicyRoutingControllerCDNExclusionsEmptyAndUnusable keeps the three honest
// shapes apart: a set that is genuinely empty (no network excluded) must not read
// as a set that could not be reported, an unreported set must not read as empty,
// and neither may be rendered as an invented count.
func TestPolicyRoutingControllerCDNExclusionsEmptyAndUnusable(t *testing.T) {
	runPolicyControllerScenario(t, `
const recordWith = (cdn) => ({enabled: false,
  sync_interval_seconds: 21600,
  status: {enabled: false, ready: false, cidr_count: 0,
           sync_state: 'disabled', cdn: cdn}});
let answer = () => recordWith({source: 'geodb.KnownCDNASNs', entries: []});
responder = async (url) => answer();
`, `
// 1. The set is reported and empty.
assert.equal(text('policyCdnCount'), '0',
  'an empty exclusion set has a count of zero, not a blank');
assert.equal(text('policyCdnEntries'), 'policy_cdn_empty',
  'an empty set must say that no network is excluded');
assert.equal(text('policyCdnAnswerHeadline'), 'COUNT 0',
  'the headline count is zero, stated as a fact');
assert.equal(text('policyCdnAnswerBody'), 'policy_cdn_empty_body',
  'an empty list is evidence about this list only, so the body says so');
assert.equal(text('policyCdnNotice'), '', 'an empty set is not an error');
assert.equal(text('policyCdnDisclosureLabel'), 'policy_cdn_entries_details',
  'without a list to read the disclosure is named for its details');

// 2. The set cannot be described: the count is unknown, not zero, and the server
// reason is shown so the block does not read as "nothing is excluded".
answer = () => recordWith({source: 'geodb.KnownCDNASNs',
  error: 'CDN exclusion entry is unusable: AS0 ""'});
await w.loadPolicySettings();
await settle();
assert.equal(answerState('policyCdnAnswer'), 'danger');
assert.equal(text('policyCdnAnswerHeadline'), 'policy_cdn_answer_unusable');
assert.equal(text('policyCdnCount'), 'policy_not_available',
  'an unusable set has no count to report; zero would be a claim the server did not make');
assert.equal(text('policyCdnEntries'), 'policy_cdn_answer_unusable',
  'the list placeholder names the unusable set, not an unreported one');
assert.equal(text('policyCdnNotice'), 'CDN exclusion entry is unusable: AS0 ""',
  'the raw server reason must be preserved, so the failure is diagnosable');

// 3. The deployment reported no set at all.
answer = () => recordWith(null);
await w.loadPolicySettings();
await settle();
assert.equal(text('policyCdnAnswerHeadline'), 'policy_cdn_not_reported');
assert.equal(text('policyCdnAnswerBody'), 'policy_cdn_not_reported_body');
assert.equal(text('policyCdnEntries'), 'policy_cdn_unavailable',
  'an unreported set never renders as an empty one');
assert.equal(text('policyCdnCount'), 'policy_not_available');
`)
}

// TestPolicyCDNDisclosureKeepsOpenStateAcrossVariants is the defect 971-R1-03
// named: the readout used to ship one disclosure per variant, so the state change
// under the operator closed the panel they were reading and dropped their focus.
func TestPolicyCDNDisclosureKeepsOpenStateAcrossVariants(t *testing.T) {
	runPolicyControllerScenario(t, `
const cdn = `+policyCDNPayloadForTest(t)+`;
let variant = 'populated';
const record = () => ({enabled: false, sync_interval_seconds: 21600,
  status: {enabled: false, ready: false, cidr_count: 0, sync_state: 'disabled',
           cdn: variant === 'populated' ? cdn
              : variant === 'empty' ? {source: 'geodb.KnownCDNASNs', entries: []}
              : {source: 'geodb.KnownCDNASNs', error: 'CDN exclusion entry is unusable: AS0 ""'}}});
responder = async () => record();
`, `
const details = el('policyCdnNetworksDetails');
const summary = details.querySelector('summary');
details.open = true;
summary.focus();
assert.equal(details.open, true);
assert.equal(w.document.activeElement, summary);

variant = 'unusable';
await w.loadPolicySettings();
await settle();
assert.equal(details.open, true,
  'the disclosure the operator opened stays open when the state changes under it');
assert.equal(w.document.activeElement, summary,
  'focus stays on the summary the operator was using');
assert.equal(text('policyCdnDisclosureLabel'), 'policy_cdn_entries_details',
  'the label follows the new state');
assert.equal(text('policyCdnNotice'), 'CDN exclusion entry is unusable: AS0 ""',
  'the raw reason the state change carried is rendered in the same disclosure');

variant = 'empty';
await w.loadPolicySettings();
await settle();
assert.equal(details.open, true, 'a second state change does not close it either');
assert.equal(w.document.activeElement, summary);
assert.equal(text('policyCdnEntries'), 'policy_cdn_empty');
`)
}

// TestPolicyInventoryRequiresProvenanceBeforeCallingTheListCurrent is the other
// half of 971-R1-01: a freshness flag alone is not enough to say the shipped list
// is current, and a field the server omitted is not the same value as a reported
// zero. Both directions are asserted, so the rule cannot pass by refusing every
// artifact.
func TestPolicyInventoryRequiresProvenanceBeforeCallingTheListCurrent(t *testing.T) {
	runPolicyControllerScenario(t, `
let inventory = {source: 'ipdeny', retrieved_at: '2026-11-19', prefix_count: 8664,
                 age_days: 1, max_age_days: 180, stale: false, override_prefix_count: 0};
responder = async () => ({enabled: false, sync_interval_seconds: 21600,
  status: {enabled: false, ready: false, cidr_count: 0, sync_state: 'disabled',
           inventory: inventory}});
`, `
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_current',
  'a complete provenance with a fresh verdict is Current');

// The source is missing: the panel cannot say which list it judged.
inventory = {retrieved_at: '2026-11-19', prefix_count: 8664, age_days: 1,
             max_age_days: 180, stale: false, override_prefix_count: 0};
await w.loadPolicySettings();
await settle();
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_freshness_not_reported',
  'without a named source the freshness claim is not made');
assert.equal(text('policyInventorySource'), 'policy_not_available',
  'a source the server did not name is not available, not an answer of "none"');
assert.equal(text('policyInventoryAge'), '1 day', 'the reported age is still shown');

// The retrieval date is missing: same reasoning, and the date field says so.
inventory = {source: 'ipdeny', prefix_count: 8664, age_days: 1,
             max_age_days: 180, stale: false, override_prefix_count: 0};
await w.loadPolicySettings();
await settle();
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_freshness_not_reported');
assert.equal(text('policyInventoryRetrieved'), 'policy_not_available',
  'a retrieval date the server did not report is not available, not "none"');

// A null shipped count is unreported, not zero prefixes in the shipped list.
inventory = {source: 'ipdeny', retrieved_at: '2026-11-19', prefix_count: null,
             age_days: 1, max_age_days: 180, stale: false, override_prefix_count: 0};
await w.loadPolicySettings();
await settle();
assert.equal(text('policyInventoryPrefixes'), 'policy_not_available',
  'a null prefix count is unknown, not a shipped list of zero prefixes');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_freshness_not_reported');

// A null override count is unreported too: it does not mean "none configured",
// which is a statement about the stored override.
inventory = {source: 'ipdeny', retrieved_at: '2026-11-19', prefix_count: 8664,
             age_days: 1, max_age_days: 180, stale: false, override_prefix_count: null};
await w.loadPolicySettings();
await settle();
assert.equal(text('policyInventoryOverrideStatus'), 'policy_not_available',
  'an unreported override count must not read as "None configured"');
assert.equal(hidden('policyInventoryDigestRow'), true, 'with no override there is no digest');

// Control: a reported zero override count does mean none configured.
inventory = {source: 'ipdeny', retrieved_at: '2026-11-19', prefix_count: 8664,
             age_days: 1, max_age_days: 180, stale: false, override_prefix_count: 0};
await w.loadPolicySettings();
await settle();
assert.equal(text('policyInventoryOverrideStatus'), 'policy_inventory_override_none');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_current');
`)
}

// TestPolicySyncErrorKeepsUnconfirmedApartFromClean pins the third state the design
// review found conflated: an active runtime that reported no sync state has not
// confirmed a successful sync, and the readout must not dress that as success.
func TestPolicySyncErrorKeepsUnconfirmedApartFromClean(t *testing.T) {
	runPolicyControllerScenario(t, `
let snapshot = () => ({enabled: true, ready: true, sync_state: 'synced',
  last_success: '2026-11-15T00:00:00Z', last_error: ''});
responder = async () => ({enabled: true, sync_interval_seconds: 21600, status: snapshot()});
`, `
assert.equal(answerState('policySyncErrorAnswer'), 'success',
  'a confirmed successful sync is the one success treatment');
assert.equal(text('policySyncErrorAnswerBody'), 'NOERR ' + text('policyLastSuccess'),
  'the healthy answer names the last successful sync');

// Active, no error reported, but no sync state at all: unconfirmed.
snapshot = () => ({enabled: true, ready: false, last_success: '', last_error: ''});
await w.loadPolicySettings();
await settle();
assert.equal(answerState('policySyncErrorAnswer'), 'info',
  'an unconfirmed sync is not painted as a clean one');
assert.equal(text('policySyncErrorAnswerHeadline'), 'policy_sync_error_none');
assert.equal(text('policySyncErrorAnswerBody'), 'policy_sync_error_pending_body');
assert.equal(text('policyStatusAnswerHeadline'), 'policy_status_active_unconfirmed',
  'the two readouts agree about the same snapshot');

// Pending is its own neutral answer.
snapshot = () => ({enabled: true, ready: false, sync_state: 'pending', last_error: ''});
await w.loadPolicySettings();
await settle();
assert.equal(answerState('policySyncErrorAnswer'), 'info');
assert.equal(text('policySyncErrorAnswerBody'), 'policy_sync_error_pending_body');
assert.equal(hidden('policySyncNowBtn'), true, 'pending is not a retryable failure');

// A failure with a loaded rule set says so; the same failure without one says that.
snapshot = () => ({enabled: true, ready: true, sync_state: 'error', last_error: 'sync failed'});
await w.loadPolicySettings();
await settle();
assert.equal(answerState('policySyncErrorAnswer'), 'danger');
assert.equal(text('policySyncErrorAnswerBody'), 'policy_sync_error_failed_body_ready');
assert.equal(hidden('policySyncNowBtn'), false, 'an active failure is retryable');
snapshot = () => ({enabled: true, ready: false, sync_state: 'error', last_error: 'sync failed'});
await w.loadPolicySettings();
await settle();
assert.equal(text('policySyncErrorAnswerBody'), 'policy_sync_error_failed_body_not_ready');

// A failure with no detail text still states the failure and says the detail is absent.
snapshot = () => ({enabled: true, ready: false, sync_state: 'error', last_error: ''});
await w.loadPolicySettings();
await settle();
assert.equal(answerState('policySyncErrorAnswer'), 'danger');
assert.equal(text('policyLastError'), 'policy_no_error_detail');

// No snapshot at all: the detail block is unavailable, not "None", which would read
// as an observation that no error exists.
snapshot = () => null;
await w.loadPolicySettings();
await settle();
assert.equal(text('policySyncErrorAnswerHeadline'), 'policy_sync_error_unavailable');
assert.equal(text('policyLastError'), 'policy_not_available');
`)
}

// TestPolicyPanelsShowLoadingNotAnAnswer holds the first read open and asserts the
// four readouts say they are loading. A neutral "off", "current" or "no error"
// shown before the server answered is a factual claim nobody made.
func TestPolicyPanelsShowLoadingNotAnAnswer(t *testing.T) {
	runPolicyControllerScenario(t, `
let releaseInitial = null;
const initialGate = new Promise(resolve => { releaseInitial = resolve; });
responder = async (url) => {
  await initialGate;
  return {enabled: false, sync_interval_seconds: 21600,
          status: {enabled: false, ready: false, cidr_count: 0, sync_state: 'disabled',
                   last_success: '', last_error: ''}};
};
`, `
assert.equal(text('policyStatusAnswerHeadline'), 'policy_status_loading');
assert.equal(hidden('policyStatusAnswerBody'), true, 'a loading answer carries no explanation');
assert.equal(answerState('policyStatusAnswer'), 'loading');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_panel_loading');
assert.equal(text('policyCdnAnswerHeadline'), 'policy_panel_loading');
assert.equal(text('policySyncErrorAnswerHeadline'), 'policy_panel_loading');
assert.equal(text('policySyncState'), '…', 'the value placeholder must not read as a state');
assert.equal(text('policyLastSuccess'), '…');
assert.equal(text('policyInventoryAge'), '…');
assert.equal(badge().enabled, 'unknown', 'the badge ships as unknown until the runtime answers');

releaseInitial();
await settle();
assert.equal(text('policyStatusAnswerHeadline'), 'policy_status_off');
assert.equal(text('policySyncErrorAnswerHeadline'), 'policy_sync_error_none');
assert.equal(text('policySyncErrorAnswerBody'), 'policy_sync_error_off_body');
`)
}

// TestPolicyPanelsSurviveARefresh keeps a disclosure the operator opened open, and
// keeps focus on the control they were using, across a re-read. A refresh that
// rebuilt the readout would close the detail under them and drop their place.
func TestPolicyPanelsSurviveARefresh(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(t, false, `["203.0.113.0/24"]`), `
const summary = el('policyCdnNetworksDetails').querySelector('summary');
const expected = Number(el('policyCdnCount').textContent);
assert.ok(expected > 0, 'the fixture must list at least one excluded network');
el('policyCdnNetworksDetails').open = true;
summary.focus();
assert.equal(w.document.activeElement, summary, 'focus is on the disclosure the test opens');

await w.loadPolicySettings();
await settle();

assert.equal(el('policyCdnNetworksDetails').open, true,
  'a disclosure the operator opened stays open across a refresh');
assert.equal(w.document.activeElement, summary,
  'focus stays on the summary the operator was using');
assert.equal(w.document.querySelectorAll('#policyCdnEntries li').length, expected,
  'a refresh re-lists every excluded network');
`)
}

// TestPolicyRuleCountDistinguishesZeroFromUnreported pins the difference between a
// count the server reported as zero and a count it did not report at all. "0 loaded
// rules" is a real, healthy answer; a missing count rendered as 0 would tell an
// operator the classifier has nothing loaded when the snapshot simply said nothing.
func TestPolicyRuleCountDistinguishesZeroFromUnreported(t *testing.T) {
	runPolicyControllerScenario(t, `
let snapshot = () => ({enabled: true, ready: true, sync_state: 'synced',
  last_success: '2026-11-15T00:00:00Z', last_error: ''});
responder = async () => ({enabled: true, sync_interval_seconds: 21600, status: snapshot()});
`, `
const ruleDetails = el('policyRuleDetails');
ruleDetails.open = true;
assert.equal(text('policyRuleCount'), 'policy_not_available',
  'a snapshot that reports no rule count must not be read as zero loaded rules');
assert.equal(hidden('policyRuleDetails'), false,
  'the rule count stays reachable while its value is unavailable');

snapshot = () => ({enabled: true, ready: true, cidr_count: 0, sync_state: 'synced',
  last_success: '2026-11-15T00:00:00Z', last_error: ''});
await w.loadPolicySettings();
await settle();
assert.equal(text('policyRuleCount'), '0',
  'zero loaded rules is a valid count and must read as zero');
assert.equal(ruleDetails.open, true,
  'a refresh does not close the disclosure the operator opened');

// A partial snapshot can carry the key with no value at all. That is an unknown
// count, not zero loaded rules, and the two must not render alike.
snapshot = () => ({enabled: true, ready: true, cidr_count: null, sync_state: 'synced',
  last_success: '2026-11-15T00:00:00Z', last_error: ''});
await w.loadPolicySettings();
await settle();
assert.equal(text('policyRuleCount'), 'policy_not_available',
  'a null rule count is unreported, not zero');
`)
}
