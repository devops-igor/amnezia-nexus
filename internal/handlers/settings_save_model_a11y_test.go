package handlers

// Busy and live-announcement contract on all eight settings cards (#888).
//
// A role attribute on a node that is hidden is not an announcement: browsers
// register a live region reliably only when it is already in the accessibility
// tree before its text changes. These tests therefore do not look for roles. They
// check, before any edit and again after, that each node is mounted, not hidden by
// the markup or by an inline style, and empty; and that the text arrives later,
// once per transition. JSDOM has no layout engine, so "exposed" here means the
// nodes a browser would put in the accessibility tree: not [hidden], not
// display:none, not visibility:hidden, not aria-hidden. Geometry is not claimed.

import (
	"strings"
	"testing"
)

// settingsA11yHelpers is shared scenario code: the eight cards, a test of whether
// a node is exposed, and an observer that records every text change of the three
// live nodes of a card.
const settingsA11yHelpers = `
const CARDS = ['appearanceCard', 'captchaCard', 'sslCard', 'limitsCard', 'telegramCard', 'gigahostCard',
  'notificationsCard', 'policyRoutingCard'];
function exposed(el) {
  for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
    if (n.hidden || n.getAttribute('aria-hidden') === 'true') return false;
    const st = w.getComputedStyle(n);
    if (st.display === 'none' || st.visibility === 'hidden') return false;
    if (n.classList.contains('hidden')) return false;
  }
  return true;
}
// Every card has the same three live nodes: the unsaved badge, one status region
// and one alert region. The two policy cards carry theirs inside a wrapper above
// the form, which is the only difference in where they sit.
const liveNodes = id => ({
  dirty: card(id).querySelector('[data-dirty]'),
  status: card(id).querySelector('[data-status]'),
  error: card(id).querySelector('[data-error]')
});
const resultText = id => [liveNodes(id).status, liveNodes(id).error].map(el => el.textContent.trim()).join('');
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
  assert.equal(nodes.status.getAttribute('role'), 'status', id + ' success role');
  assert.equal(nodes.error.getAttribute('role'), 'alert', id + ' error role');
  assert.equal(card(id).querySelectorAll('[data-status]').length, 1, id + ' must have exactly one status region');
  assert.equal(card(id).querySelectorAll('[data-error]').length, 1, id + ' must have exactly one alert region');
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

// TestSettingsA11y_PolicyCardsUseFixedStatusAndAlertRegions: the two policy cards
// report into the same fixed pair of regions as every other card. A success lands
// in the status region and a refusal in the alert region, and neither region ever
// changes its role to suit the message. The review asked for this instead of one
// banner that switches semantics in the same update as its text.
func TestSettingsA11y_PolicyCardsUseFixedStatusAndAlertRegions(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsA11yHelpers+`
await sleep(400);
for (const [cardId, wrapperId] of [['policyRoutingCard', 'policyAlert']]) {
  const wrapper = doc.getElementById(wrapperId);
  assert.ok(wrapper.contains(liveNodes(cardId).status) && wrapper.contains(liveNodes(cardId).error), cardId + ' regions sit in the result wrapper');
  assert.equal(wrapper.getAttribute('role'), null, wrapperId + ' is a plain wrapper, not a live region of its own');
  assert.equal(wrapper.hasAttribute('hidden'), false);
  assert.equal(exposed(liveNodes(cardId).status), true, cardId + ' status region is exposed while empty');
  assert.equal(exposed(liveNodes(cardId).error), true, cardId + ' alert region is exposed while empty');
}

const nodes = liveNodes('policyRoutingCard');
const roles = () => [nodes.status.getAttribute('role'), nodes.error.getAttribute('role')];
assert.deepEqual(roles(), ['status', 'alert']);

type('policy_local_entries', 'corp.example');
card('policyRoutingCard').querySelector('[data-commit]').click();
await until(() => nodes.status.textContent.trim() !== '', 'the policy success');
assert.equal(nodes.error.textContent.trim(), '', 'a success must not write the alert region');
assert.deepEqual(roles(), ['status', 'alert'], 'roles do not change with the outcome');

policyDouble.refuse = true;
type('policy_local_entries', 'other.example');
card('policyRoutingCard').querySelector('[data-commit]').click();
await until(() => nodes.error.textContent.trim() !== '', 'the policy refusal');
assert.equal(nodes.status.textContent.trim(), '', 'a refusal must clear the success region');
assert.deepEqual(roles(), ['status', 'alert'], 'roles do not change with the outcome');
assert.equal(nodes.error.getAttribute('data-outcome'), 'refused');
assert.equal(wrapperState(), 'error');
function wrapperState() { return doc.getElementById('policyAlert').getAttribute('data-state'); }
`)
}

// TestSettingsA11y_BusyAndFocusHoldOnAllEightCards: committing any card marks that
// card aria-busy, disables its commit and shows its spinner, clears all three when
// the operation ends, puts keyboard focus back, and leaves every other card's
// state alone. The save is held at the network so the busy interval is observable.
func TestSettingsA11y_BusyAndFocusHoldOnAllEightCards(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true}, settingsA11yHelpers+`
await until(() => !card('notificationsCard').querySelector('#notificationHistory .text-muted').textContent.startsWith('Loading'), 'notifications to load');
await sleep(300);

const edits = {
  appearanceCard: () => type('app_title', 'Busy Title'),
  captchaCard: () => toggle('captcha_enabled', true),
  sslCard: () => type('ssl_domain', 'busy.example.test'),
  limitsCard: () => type('max_connections_per_user', '19'),
  telegramCard: () => type('telegram_chat_id', '-100busy'),
  gigahostCard: () => type('gigahost_api_key', 'flux_live_busy_key_0123456789'),
  notificationsCard: () => type('notifications_cooldown', '45'),
  policyRoutingCard: () => type('policy_local_entries', 'busy.example')
};
const holds = {
  default: u => String(u).indexOf('/api/settings/save') === 0,
  notificationsCard: u => String(u).indexOf('/api/notifications/settings') === 0,
  policyRoutingCard: u => String(u) === '/api/vpn/policy'
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

// TestSettingsA11y_LateCompletionNeverTakesFocusFromAnotherCard is the regression the
// review named. A save starts from its own control and is held on the wire. The
// operator moves to an enabled input in a different card and types there. The save
// then settles, once as a success and once as a failure, and focus and the typed
// value must be exactly where the operator left them. The matrix repeats this for
// every card; this test keeps the single case readable.
func TestSettingsA11y_LateCompletionNeverTakesFocusFromAnotherCard(t *testing.T) {
	for _, outcome := range []string{"success", "failure"} {
		t.Run(outcome, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			runSettingsScenario(t, h, settingsA11yHelpers+`
const failing = `+map[bool]string{true: "true", false: "false"}[outcome == "failure"]+`;
let release;
const gate = new Promise(r => { release = r; });
holdWhen = (u, o) => (String(u).indexOf('/api/settings/save') === 0 && String((o && o.method) || '').toUpperCase() === 'POST') ? gate : null;
if (failing) refuseWhen = u => String(u).indexOf('/api/settings/save') === 0;

type('max_connections_per_user', '41');
const commit = commitOf('limitsCard');
commit.focus();
commit.click();
await until(() => held > 0, 'the save to reach the barrier');

const elsewhere = doc.getElementById('app_title');
elsewhere.focus();
type('app_title', 'typed while the other card was saving');
assert.equal(doc.activeElement, elsewhere, 'the operator is now in another card');

release();
holdWhen = null;
await until(() => card('limitsCard').getAttribute('aria-busy') === 'false', 'the save to settle');
await settled();

assert.equal(doc.activeElement, elsewhere, 'a late ' + (failing ? 'failure' : 'success') + ' must leave focus where the operator put it');
assert.equal(elsewhere.value, 'typed while the other card was saving', 'what was typed there is still there');
assert.equal(shown(badgeOf('appearanceCard')), true, 'the other card is still marked unsaved');
assert.equal(card('limitsCard').contains(doc.activeElement), false);
`)
		})
	}
}

// focusDropScenario is the shared body of the "operation lost focus" cases: a save
// is held, the focused control is disabled by the operation, drop() leaves focus
// the way a browser would, and the save settles.
const focusDropScenario = `
let release;
const gate = new Promise(r => { release = r; });
holdWhen = (u, o) => (String(u).indexOf('/api/settings/save') === 0 && String((o && o.method) || '').toUpperCase() === 'POST') ? gate : null;
type('max_connections_per_user', '43');
const commit = commitOf('limitsCard');
commit.focus();
commit.click();
await until(() => held > 0, 'the save to reach the barrier');
assert.equal(commit.disabled, true, 'the commit is disabled while the request runs');
DROP_FOCUS
release();
holdWhen = null;
await until(() => card('limitsCard').getAttribute('aria-busy') === 'false', 'the save to settle');
await settled();
assert.ok(card('limitsCard').contains(doc.activeElement) && doc.activeElement !== doc.body,
  'focus the operation lost comes back to the card, is on ' + doc.activeElement.tagName);
assert.ok(!doc.activeElement.disabled, 'and to an element that can take it (the heading, since a clean card disables its commit)');
assert.equal(doc.activeElement.classList.contains('card-title'), true, 'the card heading is the fallback');
`

// TestSettingsA11y_FocusIsRestoredWhenTheOperationLostIt is the other half of the
// rule: when nothing else took focus and the operation dropped it, it comes back.
//
// Two ways to lose focus exist. A browser may move focus to the page body when the
// focused control becomes disabled; JSDOM never does (it keeps the disabled control
// as the active element, and blur() does not clear it), so that case cannot be
// reached through the page here and is covered by the Chromium test instead.
// What JSDOM does produce is the second: focus left on the disabled control. That
// is the case below, and it must end on the card heading.
func TestSettingsA11y_FocusIsRestoredWhenTheOperationLostIt(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsA11yHelpers+strings.Replace(focusDropScenario, "DROP_FOCUS",
		"assert.equal(doc.activeElement, commit, 'focus is left on the disabled control');", 1))
}
