package handlers

// Busy and live-announcement contract on all nine settings cards (#888).
//
// A role attribute on a node that is hidden is not an announcement: browsers
// register a live region reliably only when it is already in the accessibility
// tree before its text changes. These tests therefore do not look for roles. They
// check, before any edit and again after, that each node is mounted, not hidden by
// the markup or by an inline style, and empty; and that the text arrives later,
// once per transition. JSDOM has no layout engine, so "exposed" here means the
// nodes a browser would put in the accessibility tree: not [hidden], not
// display:none, not visibility:hidden, not aria-hidden. Geometry is not claimed.

import "testing"

// settingsA11yHelpers is shared scenario code: the nine cards, a test of whether
// a node is exposed, and an observer that records every text change of the three
// live nodes of a card.
const settingsA11yHelpers = `
const CARDS = ['appearanceCard', 'captchaCard', 'sslCard', 'limitsCard', 'telegramCard', 'gigahostCard',
  'notificationsCard', 'policyRoutingCard', 'policyUpstreamCard'];
function exposed(el) {
  for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
    if (n.hidden || n.getAttribute('aria-hidden') === 'true') return false;
    const st = w.getComputedStyle(n);
    if (st.display === 'none' || st.visibility === 'hidden') return false;
    if (n.classList.contains('hidden')) return false;
  }
  return true;
}
// The two policy cards report through one banner of their own whose role follows
// the outcome; every other card has a status node and an alert node.
const BANNERS = {policyRoutingCard: 'policyAlert', policyUpstreamCard: 'policyUpstreamAlert'};
const liveNodes = id => BANNERS[id]
  ? {dirty: card(id).querySelector('[data-dirty]'), banner: doc.getElementById(BANNERS[id])}
  : {dirty: card(id).querySelector('[data-dirty]'), status: card(id).querySelector('[data-status]'), error: card(id).querySelector('[data-error]')};
const resultText = id => Object.entries(liveNodes(id)).filter(([k]) => k !== 'dirty').map(([, el]) => el.textContent).join('');
// watch records every write to the live nodes of a card, one entry per mutation
// record and not per callback: the callback batches synchronous writes, which would
// hide a node that is rewritten on every keystroke. text is what was written.
function watch(id) {
  const log = [];
  const nodes = liveNodes(id);
  for (const k of Object.keys(nodes)) {
    new w.MutationObserver(records => {
      for (const r of records) {
        const written = Array.from(r.addedNodes).map(n => n.textContent).join('');
        log.push({node: k, text: r.type === 'characterData' ? r.target.textContent : written});
      }
    }).observe(nodes[k], {childList: true, characterData: true, subtree: true});
  }
  return log;
}
`

// TestSettingsA11y_LiveNodesAreExposedBeforeTheirTextChanges: on every card, the
// unsaved badge, the success region and the error region exist, are exposed and
// are empty before anything happens, and the dirty announcement is written once
// per transition, not per keystroke.
func TestSettingsA11y_LiveNodesAreExposedBeforeTheirTextChanges(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true}, settingsA11yHelpers+`
await sleep(600);
for (const id of CARDS) {
  const nodes = liveNodes(id);
  for (const [name, el] of Object.entries(nodes)) {
    assert.ok(el, id + ' has no ' + name + ' live node');
    assert.equal(exposed(el), true, id + ' ' + name + ' is hidden before it announces anything');
    assert.equal(el.textContent, '', id + ' ' + name + ' must be empty until it has something to say');
  }
  assert.equal(nodes.dirty.getAttribute('role'), 'status', id + ' unsaved role');
  if (nodes.banner) {
    assert.equal(nodes.banner.getAttribute('role'), 'status', id + ' banner starts as a polite status');
  } else {
    assert.equal(nodes.status.getAttribute('role'), 'status', id + ' success role');
    assert.equal(nodes.error.getAttribute('role'), 'alert', id + ' error role');
  }
}

// One transition, many keystrokes: the unsaved text is written once.
const log = watch('appearanceCard');
for (const v of ['A', 'Ab', 'Abc', 'Abcd', 'Abcde']) type('app_title', v);
await sleep(50); // mutation records are delivered after the current task
const dirtyWrites = log.filter(e => e.node === 'dirty' && e.text !== '');
assert.equal(dirtyWrites.length, 1, 'the unsaved announcement must fire on the transition, not per keystroke: ' + JSON.stringify(log));
assert.equal(exposed(liveNodes('appearanceCard').dirty), true);
`)
}

// TestSettingsA11y_SuccessAndFailureUseDistinctSemantics: a success is written to
// the polite status node, a failure to the alert node, and never the other way.
func TestSettingsA11y_SuccessAndFailureUseDistinctSemantics(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsA11yHelpers+`
const log = watch('limitsCard');
type('max_connections_per_user', '12');
commitOf('limitsCard').click();
await until(() => shown(statusOf('limitsCard')), 'success');
const nodes = liveNodes('limitsCard');
assert.equal(nodes.status.getAttribute('role'), 'status');
assert.equal(nodes.error.textContent, '', 'a success must not write the alert node');
assert.equal(exposed(nodes.status), true);

failSave = true;
type('max_connections_per_user', '13');
commitOf('limitsCard').click();
await until(() => shown(errorOf('limitsCard')), 'failure');
failSave = false;
assert.equal(nodes.error.getAttribute('role'), 'alert');
assert.equal(nodes.status.textContent, '', 'a failure must clear the success node');
assert.equal(exposed(nodes.error), true);
assert.ok(log.some(e => e.node === 'status' && e.text !== ''), 'the success text was written to the status node');
assert.ok(log.some(e => e.node === 'error' && e.text !== ''), 'the failure text was written to the alert node');
`)
}

// TestSettingsA11y_PolicyBannersSwitchRoleWithTheOutcome: the two policy cards keep
// their own banner. It is mounted and exposed while empty, polite for a success
// and assertive for a failure.
func TestSettingsA11y_PolicyBannersSwitchRoleWithTheOutcome(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsA11yHelpers+`
await sleep(300);
for (const [cardId, bannerId, fieldId] of [['policyRoutingCard', 'policyAlert', 'policy_local_entries'], ['policyUpstreamCard', 'policyUpstreamAlert', null]]) {
  const banner = doc.getElementById(bannerId);
  assert.equal(exposed(banner), true, bannerId + ' must be exposed before it has text');
  assert.equal(banner.textContent, '', bannerId + ' must start empty');
  assert.equal(banner.hasAttribute('hidden'), false);
  assert.notEqual(banner.style.display, 'none');
}

const banner = doc.getElementById('policyAlert');
type('policy_local_entries', 'corp.example');
card('policyRoutingCard').querySelector('[data-commit]').click();
await until(() => banner.textContent !== '', 'the policy success');
assert.equal(banner.getAttribute('role'), 'status', 'a success is a status');
assert.equal(banner.getAttribute('aria-live'), 'polite');
assert.equal(exposed(banner), true);

policyDouble.refuse = true;
type('policy_local_entries', 'other.example');
card('policyRoutingCard').querySelector('[data-commit]').click();
await until(() => banner.getAttribute('data-state') === 'error', 'the policy refusal');
assert.equal(banner.getAttribute('role'), 'alert', 'a failure is an alert');
assert.equal(banner.getAttribute('aria-live'), 'assertive');
assert.equal(exposed(banner), true);
`)
}

// TestSettingsA11y_BusyAndFocusHoldOnAllNineCards: committing any card marks that
// card aria-busy, disables its commit and shows its spinner, clears all three when
// the operation ends, puts keyboard focus back, and leaves every other card's
// state alone. The save is held at the network so the busy interval is observable.
func TestSettingsA11y_BusyAndFocusHoldOnAllNineCards(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true}, settingsA11yHelpers+`
await until(() => !card('notificationsCard').querySelector('#notificationHistory .text-muted').textContent.startsWith('Loading'), 'notifications to load');
await until(() => card('policyUpstreamCard').querySelectorAll('[data-upstream-role="row"]').length > 0, 'upstream rows to load');
await sleep(300);

const edits = {
  appearanceCard: () => type('app_title', 'Busy Title'),
  captchaCard: () => toggle('captcha_enabled', true),
  sslCard: () => type('ssl_domain', 'busy.example.test'),
  limitsCard: () => type('max_connections_per_user', '19'),
  telegramCard: () => type('telegram_chat_id', '-100busy'),
  gigahostCard: () => type('gigahost_api_key', 'flux_live_busy_key_0123456789'),
  notificationsCard: () => type('notifications_cooldown', '45'),
  policyRoutingCard: () => type('policy_local_entries', 'busy.example'),
  policyUpstreamCard: () => {
    const a = card('policyUpstreamCard').querySelector('[data-upstream-field="port"]');
    a.value = '5353'; a.dispatchEvent(new w.Event('input', {bubbles: true})); a.dispatchEvent(new w.Event('change', {bubbles: true}));
  }
};
const holds = {
  default: u => String(u).indexOf('/api/settings/save') === 0,
  notificationsCard: u => String(u).indexOf('/api/notifications/settings') === 0,
  policyRoutingCard: u => String(u) === '/api/vpn/policy',
  policyUpstreamCard: u => String(u) === '/api/vpn/policy'
};

for (const id of CARDS) {
  const el = card(id);
  const commit = el.querySelector('[data-commit]');
  const spinner = commit.querySelector('.spinner');
  assert.ok(spinner, id + ' commit has no spinner');
  assert.equal(el.getAttribute('aria-busy') === 'true', false, id + ' starts idle');

  edits[id]();
  await until(() => !commit.disabled, id + ' commit to be offered');

  let release;
  const gate = new Promise(r => { release = r; });
  const match = holds[id] || holds.default;
  const before = held;
  holdWhen = (u, o) => (match(u) && (isPost(o) || String((o && o.method) || '').toUpperCase() === 'PUT')) ? gate : null;

  commit.focus();
  assert.equal(doc.activeElement, commit, id + ' commit takes focus');
  commit.click();
  await until(() => held > before, id + ' request to reach the barrier');

  assert.equal(el.getAttribute('aria-busy'), 'true', id + ' card must be aria-busy while the request runs');
  assert.equal(commit.disabled, true, id + ' commit must be disabled while busy');
  assert.equal(spinner.classList.contains('hidden'), false, id + ' spinner must show while busy');
  for (const other of CARDS) {
    if (other !== id) assert.equal(card(other).getAttribute('aria-busy') === 'true', false, other + ' must not look busy while ' + id + ' commits');
  }

  release();
  holdWhen = null;
  await until(() => el.getAttribute('aria-busy') === 'false', id + ' to finish');

  assert.equal(spinner.classList.contains('hidden'), true, id + ' spinner must clear');
  const active = doc.activeElement;
  assert.ok(el.contains(active) && active !== doc.body, id + ' focus must stay in the card, is on ' + (active && active.tagName));
  assert.ok(resultText(id) !== '', id + ' must report a completion or an error in its own card');
}
`)
}
