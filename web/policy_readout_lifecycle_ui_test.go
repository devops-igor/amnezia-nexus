package web

// Behavioural JSDOM coverage for the lifecycles around the four policy readouts:
// a first read that fails, a retry that succeeds while the operator's focus is on
// its control, and the form's sync action in a runtime state where the operation
// cannot run. The harness and fixtures live in policy_routing_ui_test.go.

import (
	"testing"
)

// TestPolicyPanelsSettleAfterAFailedFirstRead is the defect 971-R1-02 named: the
// template starts in Loading, so a read that fails before any render used to leave
// four readouts claiming a request that was no longer running was still in flight.
// The form stays gated and the failure is still announced.
func TestPolicyPanelsSettleAfterAFailedFirstRead(t *testing.T) {
	runPolicyControllerScenario(t, `
let releaseInitial = null;
let failInitial = null;
const initialGate = new Promise((resolve, reject) => {
  releaseInitial = resolve;
  failInitial = reject;
});
responder = async (url, opts) => {
  if (opts.method && opts.method !== 'GET') throw new Error('no write may follow a failed read');
  await initialGate;
  return {};
};
`, `
// While the read is genuinely in flight, loading is the truthful answer.
assert.equal(text('policyStatusAnswerHeadline'), 'policy_status_loading');
assert.equal(answerState('policyStatusAnswer'), 'loading');

failInitial(new Error('backend unavailable'));
await settle();

// Settled, and unavailable: not loading, and not a neutral answer either.
assert.equal(text('policyStatusAnswerHeadline'), 'policy_status_unavailable');
assert.equal(text('policyStatusAnswerBody'), 'policy_status_unavailable_body');
assert.equal(text('policyInventoryAnswerHeadline'), 'policy_inventory_not_reported');
assert.equal(text('policyCdnAnswerHeadline'), 'policy_cdn_not_reported');
assert.equal(text('policySyncErrorAnswerHeadline'), 'policy_sync_error_unavailable');
assert.equal(text('policySyncState'), 'policy_not_available');
assert.equal(text('policyLastSuccess'), 'policy_not_available');
assert.equal(text('policyLastError'), 'policy_not_available',
  'an unread deployment has no error detail to report, and does not report "None"');
for (const id of ['policyStatusAnswer', 'policyInventoryAnswer', 'policyCdnAnswer', 'policySyncErrorAnswer']) {
  assert.notEqual(el(id).getAttribute('data-state'), 'loading', id + ' must not still claim to be loading');
}

// The form stays gated and the read failure is still announced, once.
assert.equal(el('policySaveBtn').disabled, true, 'a failed read leaves nothing safe to submit');
assert.equal(el('policyRoutingForm').getAttribute('data-policy-ready'), 'false');
assert.ok(alertText().text.indexOf('policy_load_failed') !== -1,
  'the failure is announced in the existing feedback region, got: ' + alertText().text);
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0, 'no write followed the failed read');
`)
}

// TestPolicySyncRetrySuccessRestoresFocusToTheVisibleAnswer is the defect
// 971-R1-03 named: the retry control hides itself on success, and the busy guard
// used to try to restore focus to it anyway — a no-op that left a keyboard operator
// on the document body. The fixture models the browser's blur when a control is
// disabled, which JSDOM does not do on its own.
func TestPolicySyncRetrySuccessRestoresFocusToTheVisibleAnswer(t *testing.T) {
	runPolicyControllerScenario(t, `
let releaseSync = null;
const syncGate = new Promise(resolve => { releaseSync = resolve; });
let posting = 0;
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/sync')) {
    posting++;
    await syncGate;
    return {status: 'ok', published: true,
            policy_status: {enabled: true, ready: true, cidr_count: 4,
                            sync_state: 'synced', last_success: '2026-11-15T01:00:00Z', last_error: ''}};
  }
  if (url.endsWith('/api/vpn/policy')) {
    return {enabled: true, sync_interval_seconds: 21600,
            status: {enabled: true, ready: true, cidr_count: 4, sync_state: 'error',
                     last_success: '', last_error: 'sync failed'}};
  }
  throw new Error('unexpected ' + (opts.method || 'GET') + ' ' + url);
};
`, `
const retry = el('policySyncNowBtn');
assert.equal(hidden('policySyncNowBtn'), false, 'an active sync failure offers the retry');
assert.ok(retry.classList.contains('policy-answer-action'),
  'the retry carries the readout action treatment: 44 px target and no shared motion');
retry.focus();
assert.equal(activeId(), 'policySyncNowBtn', 'the operator activates the retry from focus');

retry.click();
await settle();
assert.equal(posting, 1, 'the retry runs the same POST as the form action');
assert.equal(retry.disabled, true, 'the retry is disabled while the request runs');
assert.equal(retry.getAttribute('aria-busy'), 'true');

// A browser moves focus off a control the moment it is disabled; model that so the
// restoration path is exercised the way it runs for a keyboard operator. (JSDOM
// keeps focus on a disabled element and ignores element.blur(), so the document's
// active element is blurred instead.)
// A browser moves focus off a control the moment it is disabled; model that so the
// restoration path runs the way it does for a keyboard operator. JSDOM keeps focus
// on a disabled element and refuses to blur one, so focus is moved to the document
// body explicitly instead.
w.document.body.tabIndex = -1;
w.document.body.focus();
assert.equal(activeId(), '', 'focus left the disabled control');

releaseSync();
await settle(12);

assert.equal(hidden('policySyncNowBtn'), true, 'the successful retry removes its own control');
assert.equal(text('policySyncErrorAnswerHeadline'), 'policy_sync_error_none');
assert.equal(activeId(), 'policySyncErrorTitle',
  'focus lands on the visible answer heading instead of the control that disappeared');
assert.equal(el('policySyncErrorTitle').getAttribute('tabindex'), '-1',
  'the heading is focusable only because it declares it, not because an element can take focus');
`)
}

// TestFormSyncControlFollowsTheOperationsEligibility is the design-review finding:
// the backend refuses a sync while policy routing is off ("policy routing is not
// started"), so the form must not offer an operation that cannot start with it.
func TestFormSyncControlFollowsTheOperationsEligibility(t *testing.T) {
	runPolicyControllerScenario(t, `
let snapshot = () => ({enabled: false, ready: false, sync_state: 'disabled', last_error: ''});
responder = async () => ({enabled: false, sync_interval_seconds: 21600, status: snapshot()});
`, `
assert.equal(el('policySyncBtn').disabled, true,
  'a sync cannot start a stopped runtime, so the control does not offer it');
assert.equal(hidden('policySyncUnavailableHint'), false,
  'the control explains why it is unavailable');
assert.equal(text('policySyncUnavailableHint'), 'policy_sync_unavailable_hint');

snapshot = () => ({enabled: true, ready: true, cidr_count: 5, sync_state: 'synced', last_error: ''});
await w.loadPolicySettings();
await settle();
assert.equal(el('policySyncBtn').disabled, false, 'an active runtime can be synced');
assert.equal(hidden('policySyncUnavailableHint'), true, 'the explanation goes away with the state');

// A startup failure is the same unavailable operation, not a retryable one.
snapshot = () => ({enabled: false, ready: false, sync_state: 'error', last_error: 'did not start'});
await w.loadPolicySettings();
await settle();
assert.equal(el('policySyncBtn').disabled, true);
assert.equal(hidden('policySyncUnavailableHint'), false);

// With no snapshot the eligibility is unknown, so the backend's own refusal stays
// the honest answer rather than a disabled control that hides the missing read.
snapshot = () => null;
await w.loadPolicySettings();
await settle();
assert.equal(el('policySyncBtn').disabled, false, 'an unobserved runtime does not disable the action');
assert.equal(hidden('policySyncUnavailableHint'), true);
`)
}
