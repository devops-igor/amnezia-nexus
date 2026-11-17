package web

// Behavioural JSDOM coverage for the read-only decision dry run inside the
// policy section (issue #825). The shipped controller is evaluated as-is against
// the shipped template, and the API double records the payload, so the tests
// describe what the browser sends and renders rather than what the source says.
//
// The readout has two jobs that must not blur: it may report the policy's own
// evaluation, and it may report a client's route only when the answer carries
// that client's evidence. The cases below pin both, and pin the limit: without
// client context the headline names no route at all.

import (
	"testing"
)

// explainResponderScript installs an answer for the explain endpoint in front of
// the default policy responder, and stubs the keys the readout resolves. Every
// answer mirrors the shipped wire shape; the domain and address cases carry no
// echoed session and list the no-session limitation, which is what the panel's
// own form produces.
const explainResponderScript = `
w._ = key => {
  if (key === 'policy_explain_result') return '{value} :: {decision} :: {reason}';
  if (key === 'policy_explain_result_no_context') return '{value} :: NO-CONTEXT-RESULT';
  if (key === 'policy_explain_policy_evaluation_label') return 'POLICY-LABEL';
  if (key === 'policy_explain_decision_proxy') return 'DECISION-PROXY';
  if (key === 'policy_explain_decision_direct') return 'DECISION-DIRECT';
  if (key === 'policy_explain_reason_no_trusted_evidence') return 'REASON-NO-EVIDENCE';
  if (key === 'policy_explain_reason_no_trusted_evidence_no_session') return 'REASON-NO-EVIDENCE-PROSPECTIVE';
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
    // A session echoed while the answer still lists the no-session limitation:
    // the two fields contradict each other, so nothing about a route may be
    // claimed from it.
    if (body.domain === 'inconsistent.example') {
      return {input: {value: body.domain, kind: 'domain', normalized: 'inconsistent.example',
                      session: 'session-1'},
              decision: 'PROXY', reason: 'no_trusted_evidence',
              limitations: ['encrypted_dns_not_observed', 'evidence_requires_a_selected_session'],
              read_only: true};
    }
    // The rule match is the policy's prospective classification; the headline
    // action is the fail-closed default, exactly as the shipped API reports it.
    const prospective = {matched: true, decision: 'PROXY', reason: 'domain_rule',
      rule: {base: 'www.example', shape: 'apex_and_subdomains', contributors: ['geoblock']},
      matched_name: 'www.example', requires_observed_answer: true};
    if (body.ip) {
      return {input: {value: body.ip, kind: 'address'}, decision: 'PROXY',
              reason: 'cidr_rule',
              prefix: {prefix: '198.51.200.0/24', sources: ['custom-1']},
              limitations: ['encrypted_dns_not_observed', 'evidence_requires_a_selected_session'],
              read_only: true};
    }
    if (body.domain === 'plain.example') {
      return {input: {value: body.domain, kind: 'domain', normalized: 'plain.example'},
              decision: 'PROXY', reason: 'no_trusted_evidence',
              limitations: ['encrypted_dns_not_observed', 'evidence_requires_a_selected_session'],
              read_only: true};
    }
    return {input: {value: body.domain, kind: 'domain', normalized: 'www.example'},
            decision: 'PROXY', reason: 'no_trusted_evidence', prospective: prospective,
            limitations: ['encrypted_dns_not_observed', 'evidence_requires_a_selected_session'],
            read_only: true};
  }
  return base(url, opts);
})(responder);
`

// explainSessionScript makes the double answer as if a session had been read, by
// echoing one on every explain answer. The request body still carries no
// session_id, and that is the point: the echo is the server's own statement of
// what it read, so the readout may then report that session's route.
const explainSessionScript = `
responder = ((base) => async (url, opts) => {
  const answer = await base(url, opts);
  if (url.endsWith('/api/vpn/policy/explain')) {
    answer.input = Object.assign({}, answer.input, {session: 'session-1'});
    // A session that really was read cannot also carry the no-session
    // limitation; leaving it in place would test the contradiction case instead.
    if (Array.isArray(answer.limitations)) {
      answer.limitations = answer.limitations.filter(l => l !== 'evidence_requires_a_selected_session');
    }
  }
  return answer;
})(responder);
`

// TestPolicyRoutingControllerExplainsDestination pins the payload and the
// no-context headline: the panel sends the typed value, and because it selects no
// session its answer must not be presented as this client's route.
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
assert.equal(posts[0].body.session_id, undefined,
  'the premise: this form selects no session, so none can be inspected');
assert.equal(text('policyExplainResult'), 'www.example :: NO-CONTEXT-RESULT',
  'the readout must show the normalised value and no route verdict');
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
// wording: the readout is the operator's only feedback for a rejected name. A
// refusal must also clear the policy evaluation left by an earlier answer, so a
// stale evaluation cannot survive as if it described the refused request.
func TestPolicyRoutingControllerExplainReportsRefusal(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
const detail = w.document.getElementById('policyExplainDetail');

field.value = 'www.example';
w.document.getElementById('policyExplainBtn').click();
await settle();
assert.equal(detail.hidden, false, 'a successful answer renders a policy evaluation');

field.value = 'fail.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const readout = w.document.getElementById('policyExplainResult');
assert.equal(readout.getAttribute('data-state'), 'error', 'a refusal must be marked as an error');
assert.match(readout.textContent, /illegal characters/,
  'the server detail must be shown, not replaced by a generic message');
assert.equal(detail.hidden, true, 'a refusal must clear the stale policy evaluation');
assert.equal(detail.textContent, '', 'a refusal must not leave stale text');
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
assert.equal(text('policyExplainResult'), 'www.example :: NO-CONTEXT-RESULT');
`)
}

// TestPolicyRoutingControllerExplainWithoutContextNamesNoRoute is the
// truthfulness regression: a name, a decision and a cause from the policy are
// not a measured route for a client whose evidence was never read, so the
// headline must not name one and the policy facts must be labelled as such.
func TestPolicyRoutingControllerExplainWithoutContextNamesNoRoute(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'www.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const result = w.document.getElementById('policyExplainResult');
const headline = result.textContent;
assert.equal(headline, 'www.example :: NO-CONTEXT-RESULT',
  'without client context the headline must not name a route');
assert.ok(!/DECISION-|REASON-/.test(headline),
  'neither the decision nor the cause belongs in a headline that has no client context');
assert.ok(!['proxy', 'direct'].includes(result.getAttribute('data-state')),
  'the readout must not be styled as a client route it did not observe');
assert.equal(result.getAttribute('data-state'), 'no-context',
  'the readout carries the missing-context cause as its state');

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, false, 'the policy evaluation must still be shown');
assert.equal(detail.textContent,
  'POLICY-LABEL REASON-NO-EVIDENCE-PROSPECTIVE · PROSPECTIVE[www.example|apex_and_subdomains|geoblock]',
  'the cause and the matched rule are rendered under the policy label');
assert.equal(requestsTo('/api/vpn/policy', 'PUT').length, 0,
  'explaining must still never save settings');
`)
}

// TestPolicyRoutingControllerExplainKeepsRouteWithClientContext is the
// counterweight: when the answer names the session it read, that session's
// evidence really was consulted, so the route and its session-scoped cause stay
// and no policy-evaluation label is added.
func TestPolicyRoutingControllerExplainKeepsRouteWithClientContext(t *testing.T) {
	runPolicyControllerScenario(t,
		policyRecordScript(false, "geoblock")+explainResponderScript+explainSessionScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'www.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

assert.equal(text('policyExplainResult'), 'www.example :: DECISION-PROXY :: REASON-NO-EVIDENCE',
  'a selected session keeps the session-scoped verdict and cause');
assert.equal(w.document.getElementById('policyExplainResult').getAttribute('data-state'), 'proxy',
  'a session-backed answer carries its decision as the state');

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, false, 'the matched rule is still shown');
assert.equal(detail.textContent, 'PROSPECTIVE[www.example|apex_and_subdomains|geoblock]',
  'a session-backed answer needs no policy-evaluation label');
`)
}

// TestPolicyRoutingControllerExplainIgnoresSelfContradictoryContext covers the
// inconsistent answer: a session is echoed while the limitations still say one
// is required. The answer cannot be trusted either way, so it is rendered as
// missing context rather than as a route.
func TestPolicyRoutingControllerExplainIgnoresSelfContradictoryContext(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'inconsistent.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const result = w.document.getElementById('policyExplainResult');
assert.equal(result.textContent, 'inconsistent.example :: NO-CONTEXT-RESULT',
  'a self-contradictory answer must not be rendered as a route');
assert.equal(result.getAttribute('data-state'), 'no-context');
assert.equal(text('policyExplainDetail'), 'POLICY-LABEL REASON-NO-EVIDENCE-PROSPECTIVE',
  'its cause is still reported, under the policy label');
`)
}

// TestPolicyRoutingControllerExplainShowsRuleAndSource keeps the rule and the
// lists that contributed it visible for a name with no client context: the
// information is useful, and it is labelled prospective so it is not read as
// this destination's route.
func TestPolicyRoutingControllerExplainShowsRuleAndSource(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'www.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, false, 'a matched rule must be shown');
assert.match(detail.textContent, /PROSPECTIVE\[www\.example\|apex_and_subdomains\|geoblock\]/,
  'the rule, its shape and the contributing list must be rendered');
assert.match(detail.textContent, /^POLICY-LABEL/,
  'the rule is a policy evaluation, not a measured route');
`)
}

// TestPolicyRoutingControllerExplainShowsPrefixAndSource covers the address
// path: the CIDR range the policy evaluated is rendered with its source, again
// under the policy label because no client evidence was read.
func TestPolicyRoutingControllerExplainShowsPrefixAndSource(t *testing.T) {
	runPolicyControllerScenario(t, policyRecordScript(false, "geoblock")+explainResponderScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = '198.51.200.9';
w.document.getElementById('policyExplainBtn').click();
await settle();

assert.equal(text('policyExplainResult'), '198.51.200.9 :: NO-CONTEXT-RESULT',
  'an address without client context also carries no route verdict');

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, false, 'a matched range must be shown');
assert.equal(detail.textContent, 'POLICY-LABEL REASON-CIDR · PREFIX[198.51.200.0/24|custom-1]',
  'the range and the list that supplied it are rendered under the policy label');
`)
}

// TestPolicyRoutingControllerExplainHidesDetailWithoutAMatch keeps the line
// honest: a session-backed answer with nothing matched renders no detail rather
// than an empty label or a stale line.
func TestPolicyRoutingControllerExplainHidesDetailWithoutAMatch(t *testing.T) {
	runPolicyControllerScenario(t,
		policyRecordScript(false, "geoblock")+explainResponderScript+explainSessionScript, `
const field = w.document.getElementById('policy_explain_value');
field.value = 'plain.example';
w.document.getElementById('policyExplainBtn').click();
await settle();

const detail = w.document.getElementById('policyExplainDetail');
assert.equal(detail.hidden, true, 'no match must render no detail');
assert.equal(detail.textContent, '', 'no match must not leave stale text');
`)
}
