package web

// Behavioural JSDOM coverage for picker refresh and diagnosis incarnation pinning
// (#861).
//
// A refresh can remove the selected session or move it to another route generation
// while a diagnosis is in flight, and it can move an incarnation whose result is already
// on screen. The panel must not keep showing, or later render, history that belongs to an
// incarnation the refreshed picker no longer accepts - while an unchanged incarnation
// keeps its valid result.

import (
	"testing"
)

// TestPolicyClientDiagRefreshRemovingTheSelectionRejectsAPendingDiagnosis: the session is
// removed by a refresh while its diagnosis is pending. The late answer must not render,
// and the panel must not stay busy.
func TestPolicyClientDiagRefreshRemovingTheSelectionRejectsAPendingDiagnosis(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
let releaseDiagnosis;
responder = (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    // A refreshed list that no longer contains the selected session.
    return Promise.resolve({...targets(), clients: []});
  }
  return new Promise(resolve => { releaseDiagnosis = () => resolve(diagnosis('sess-a', 3)); });
};
const pending = w.diagnoseSelectedClient();
await w.refreshPolicyClients();
assert.equal(w.document.getElementById('policyClientSelect').value, '',
  'the removed session cannot stay selected');
releaseDiagnosis();
await pending;
await settle();
assert.equal(resultHidden(), true, 'a removed selection must not regain its late diagnosis');
assert.equal(text('policyClientSessionValue'), '-', 'no identity may be adopted from a stale answer');
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').hasAttribute('disabled'), true,
  'with no selection the action stays inert, not busy');
assert.equal(requestsTo('/api/vpn/policy/client-diagnosis', 'POST').length, 1,
  'the refresh adds no diagnosis request');
`)
}

// TestPolicyClientDiagRefreshMovingTheGenerationRejectsAPendingDiagnosis: the session stays
// listed under a new route generation while its diagnosis is pending. The late answer
// belongs to the old incarnation and must not render; the new generation then reads
// normally with its own pin.
func TestPolicyClientDiagRefreshMovingTheGenerationRejectsAPendingDiagnosis(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
let releaseDiagnosis;
responder = (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    return Promise.resolve({...targets(), clients: targets().clients.map(c =>
      ({...c, route_generation: c.session_id === 'sess-a' ? 4 : c.route_generation}))});
  }
  const body = opts.body || {};
  if (body.route_generation === 3) {
    return new Promise(resolve => { releaseDiagnosis = () => resolve(diagnosis('sess-a', 3)); });
  }
  return Promise.resolve(diagnosis('sess-a', body.route_generation));
};
const pending = w.diagnoseSelectedClient();
await w.refreshPolicyClients();
assert.equal(options()[0].generation, '4', 'the picker states the refreshed generation');
releaseDiagnosis();
await pending;
await settle();
assert.equal(resultHidden(), true,
  'a refreshed generation must reject the pending diagnosis of the old one');

// The new generation is readable, and its request carries its own pin.
await w.diagnoseSelectedClient();
await settle();
assert.equal(resultHidden(), false, 'the refreshed incarnation reads normally');
assert.equal(text('policyClientGenerationValue'), '4');
const posts = requestsTo('/api/vpn/policy/client-diagnosis', 'POST');
assert.equal(posts.length, 2, 'one request per operator action');
assert.equal(posts[1].body.route_generation, 4, 'the diagnosis is pinned to the refreshed generation');
`)
}

// TestPolicyClientDiagRefreshMovingTheGenerationClearsARenderedResult: no request is
// pending; the result on screen belongs to the old generation and must be cleared by the
// refresh that moves it.
func TestPolicyClientDiagRefreshMovingTheGenerationClearsARenderedResult(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(resultHidden(), false, 'the first generation reads normally');
assert.equal(text('policyClientGenerationValue'), '3');

responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    return {...targets(), clients: targets().clients.map(c =>
      ({...c, route_generation: c.session_id === 'sess-a' ? 4 : c.route_generation}))};
  }
  const body = opts.body || {};
  return diagnosis('sess-a', body.route_generation);
};
await w.refreshPolicyClients();
await settle();
assert.equal(options()[0].generation, '4');
assert.equal(resultHidden(), true, 'a generation change must clear the rendered history');
assert.equal(text('policyClientSessionValue'), '-', 'no identity survives the cleared result');

await w.diagnoseSelectedClient();
await settle();
assert.equal(resultHidden(), false, 'the refreshed incarnation reads normally');
assert.equal(text('policyClientGenerationValue'), '4');
`)
}

// TestPolicyClientDiagRejectsAnEchoOfAnotherGeneration: the answer names the right
// session but another generation than the one requested, so it is not this panel's
// result.
func TestPolicyClientDiagRejectsAnEchoOfAnotherGeneration(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
responder = async (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) return targets();
  return diagnosis('sess-a', 4);
};
await w.diagnoseSelectedClient();
await settle();
assert.equal(resultHidden(), true, 'an echo of another generation is not this result');
assert.equal(alertText().state, 'stale', 'the refusal is stated as a stale answer');
assert.equal(text('policyClientSessionValue'), '-');
`)
}

// TestPolicyClientDiagFailedRefreshWhileAPendingDiagnosisRejectsTheLateAnswer: the list
// request fails while a diagnosis is pending, so the picker is emptied. The late answer
// must not render, the refresh error stays stated, and the panel is not left busy.
func TestPolicyClientDiagFailedRefreshWhileAPendingDiagnosisRejectsTheLateAnswer(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
let releaseDiagnosis;
responder = (url, opts) => {
  if (url.endsWith('/api/vpn/policy/clients')) {
    const err = new Error('list unavailable');
    err.status = 503;
    return Promise.reject(err);
  }
  return new Promise(resolve => { releaseDiagnosis = () => resolve(diagnosis('sess-a', 3)); });
};
const pending = w.diagnoseSelectedClient();
await w.refreshPolicyClients();
await settle();
assert.equal(w.document.getElementById('policyClientSelect').value, '',
  'a failed list leaves no selection');
assert.equal(alertText().state, 'error', 'the failed refresh is stated');
releaseDiagnosis();
await pending;
await settle();
assert.equal(resultHidden(), true, 'the late answer must not render under the emptied picker');
assert.equal(alertText().state, 'error', 'the stale answer does not overwrite the refresh error');
assert.equal(w.document.getElementById('policyClientDiagnoseBtn').hasAttribute('disabled'), true,
  'nothing is left busy');
`)
}

// TestPolicyClientDiagUnchangedIncarnationKeepsAValidResult: a refresh that returns the
// same session and generation leaves the rendered result, its filter and its identity
// alone, and reads nothing new.
func TestPolicyClientDiagUnchangedIncarnationKeepsAValidResult(t *testing.T) {
	runClientDiagScenario(t, clientTargetsScript, `
selectClient('sess-a');
await w.diagnoseSelectedClient();
await settle();
assert.equal(resultHidden(), false);
const filter = w.document.getElementById('policyClientDestinationFilter');
filter.value = '93.184.216.34';
filter.dispatchEvent(new w.Event('input'));
await settle();
assert.equal(rowCount('policyClientFlowRows'), 1, 'the filter narrows the result');

await w.refreshPolicyClients();
await settle();
assert.equal(resultHidden(), false, 'an unchanged incarnation retains its valid result');
assert.equal(text('policyClientGenerationValue'), '3', 'and its generation');
assert.equal(w.document.getElementById('policyClientDestinationFilter').value, '93.184.216.34',
  'and the operator filter');
assert.equal(rowCount('policyClientFlowRows'), 1, 'the filter still applies to the retained rows');
assert.equal(requestsTo('/api/vpn/policy/client-diagnosis', 'POST').length, 1,
  'the refresh reads no diagnosis');
`)
}
