package web

// Behavioural JSDOM coverage for the read-only decision dry run inside the
// policy section (issue #825). The shipped controller is evaluated as-is against
// the shipped template, and the API double records the payload, so the tests
// describe what the browser sends and renders rather than what the source says.

import (
	"testing"
)

// explainResponderScript installs an answer for the explain endpoint in front of
// the default policy responder, and stubs the three keys the readout resolves.
const explainResponderScript = `
w._ = key => {
  if (key === 'policy_explain_result') return '{value} :: {decision} :: {reason}';
  if (key === 'policy_explain_decision_proxy') return 'DECISION-PROXY';
  if (key === 'policy_explain_decision_direct') return 'DECISION-DIRECT';
  if (key === 'policy_explain_reason_no_trusted_evidence') return 'REASON-NO-EVIDENCE';
  if (key === 'policy_explain_reason_fresh_evidence_direct') return 'REASON-FRESH-DIRECT';
  if (key === 'policy_explain_reason_cidr_rule') return 'REASON-CIDR';
  if (key === 'policy_explain_prospective_rule') return 'PROSPECTIVE[{rule}|{shape}|{source}]';
  if (key === 'policy_explain_current_prefix') return 'PREFIX[{prefix}|{source}]';
  if (key === 'policy_explain_needs_value') return 'NEEDS-VALUE';
  return key;
};
responder = ((base) => async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/explain')) {
    const body = opts.body || {};
    if (body.domain === 'fail.example') {
      const err = new Error('domain: domain contains illegal characters or scheme');
      err.status = 400;
      err.data = {error: 'validation_failed', detail: 'domain: domain contains illegal characters or scheme'};
      throw err;
    }
    // The current action is the safe default; the rule match is reported as a
    // separate prospective classification, exactly as the repaired API does.
    const prospective = {matched: true, decision: 'PROXY', reason: 'domain_rule',
      rule: {base: 'www.example', shape: 'apex_and_subdomains', contributors: ['geoblock']},
      matched_name: 'www.example', requires_observed_answer: true};
    if (body.ip) {
      return {input: {value: body.ip, kind: 'address'}, decision: 'PROXY',
              reason: 'cidr_rule',
              prefix: {prefix: '198.51.200.0/24', sources: ['custom-1']},
              read_only: true};
    }
    if (body.domain === 'plain.example') {
      // No rule match and no range: the detail line must stay hidden rather than
      // show an empty bracket.
      return {input: {value: body.domain, kind: 'domain', normalized: 'plain.example'},
              decision: 'PROXY', reason: 'no_trusted_evidence', read_only: true};
    }
    return {input: {value: body.domain, kind: 'domain', normalized: 'www.example'},
            decision: 'PROXY', reason: 'no_trusted_evidence', prospective: prospective,
            read_only: true};
  }
  return base(url, opts);
})(responder);
`

func TestPolicyRoutingControllerExplainsDestination(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = '  WWW.Example  ';
w.document.getElementById('policyExplainBtn').click();
await settle();

const posts = requestsTo('/api/vpn/policy/explain', 'POST');
assert.equal(posts.length, 1, 'the button must issue exactly one explanation request');
assert.equal(posts[0].body.domain, 'WWW.Example',
  'the typed value is sent for the server to normalise, not pre-normalised here');
assert.equal(text('policyExplainResult'), 'www.example :: DECISION-PROXY :: REASON-NO-EVIDENCE',
  'the readout must show the normalised value, the decision and the cause');
assert.equal(w.document.getElementById('policyExplainResult').getAttribute('data-state'), 'proxy',
  'the readout carries the decision as a state token');
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0,
  'explaining must never save settings');
`)
}

// TestPolicyRoutingControllerExplainSendsAnAddressAsAnAddress pins the payload
// classification: an IPv4 literal goes as ip, everything else as domain. The
// server still validates it.
func TestPolicyRoutingControllerExplainSendsAnAddressAsAnAddress(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = '198.51.200.9';
w.document.getElementById('policyExplainBtn').click();
await settle();

const posts = requestsTo('/api/vpn/policy/explain', 'POST');
assert.equal(posts.length, 1);
assert.equal(posts[0].body.ip, '198.51.200.9', 'an address must be sent as ip');
assert.equal(posts[0].body.domain, undefined, 'an address must not be sent as a domain');
`)
}

// TestPolicyRoutingControllerExplainRequiresInput proves an empty field sends
// nothing and says why, instead of issuing a request the server would reject.
func TestPolicyRoutingControllerExplainRequiresInput(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
w.document.getElementById('policy_explain_value').value = '   ';
w.document.getElementById('policyExplainBtn').click();
await settle();

assert.equal(requestsTo('/api/vpn/policy/explain', 'POST').length, 0,
  'an empty field must not reach the server');
assert.equal(text('policyExplainResult'), 'NEEDS-VALUE',
  'the readout must ask for a destination');
`)
}

// TestPolicyRoutingControllerExplainReportsRefusal keeps the server's own
// wording: the readout is the operator's only feedback for a rejected name.
func TestPolicyRoutingControllerExplainReportsRefusal(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'fail.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const readout = w.document.getElementById('policyExplainResult');
assert.equal(readout.getAttribute('data-state'), 'error', 'a refusal must be marked as an error');
assert.match(readout.textContent, /illegal characters/,
  'the server detail must be shown, not replaced by a generic message');
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0, 'a refusal must not save anything');
`)
}

// TestPolicyRoutingControllerExplainOnEnter runs the same explanation from the
// field, and proves Enter does not submit the settings form.
func TestPolicyRoutingControllerExplainOnEnter(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'www.example';
field.dispatchEvent(new w.KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
await settle();

assert.equal(requestsTo('/api/vpn/policy/explain', 'POST').length, 1,
  'Enter in the field must explain the destination');
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0,
  'Enter in the dry-run field must not submit the settings form');
assert.equal(text('policyExplainResult'), 'www.example :: DECISION-PROXY :: REASON-NO-EVIDENCE');
`)
}

// TestPolicyRoutingControllerExplainShowsRuleAndSource is the HIGH-02
// regression: a matched rule and the lists that contributed it are rendered,
// labelled prospective, next to the current action.
func TestPolicyRoutingControllerExplainShowsRuleAndSource(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'www.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, false, 'a matched rule must be shown');
assert.equal(detail.textContent, 'PROSPECTIVE[www.example|apex_and_subdomains|geoblock]',
  'the rule, its shape and the contributing list must be rendered');
assert.equal(text('policyExplainResult'), 'www.example :: DECISION-PROXY :: REASON-NO-EVIDENCE',
  'the current action keeps its own line, separate from the prospective rule');
`)
}

// TestPolicyRoutingControllerExplainShowsPrefixAndSource covers the address
// path: the CIDR range that decided the current action is rendered with its
// source.
func TestPolicyRoutingControllerExplainShowsPrefixAndSource(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = '198.51.200.9';
w.document.getElementById('policyExplainBtn').click();
await settle();

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, false, 'a matched range must be shown');
assert.equal(detail.textContent, 'PREFIX[198.51.200.0/24|custom-1]',
  'the range and the list that supplied it must be rendered');
`)
}

// TestPolicyRoutingControllerExplainHidesDetailWithoutAMatch keeps the line
// honest: nothing matched, so nothing is claimed.
func TestPolicyRoutingControllerExplainHidesDetailWithoutAMatch(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'plain.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, true, 'no match must render no detail');
assert.equal(detail.textContent, '', 'no match must not leave stale text');
`)
}
