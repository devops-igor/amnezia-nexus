package handlers

// What a card may send, and what it shows once it has stored.
//
// The commit control is a button, so the browser's own form validation never
// ran: a card could send a value its markup rejects, a collector substituted a
// default for what it could not parse, and the card then reported success while
// still displaying what the operator typed.
//
// These scenarios are the contract that closes that class:
//   - an entry the card's own markup rejects sends no request, is reported in
//     that card, and leaves the card unsaved;
//   - a collector never invents a value, even for a field the markup lets the
//     operator empty;
//   - a value the card accepts is stored and displayed identically, at both ends
//     of the declared range and for an entry whose text is not canonical.
//
// Every scenario runs on the real /settings page against the real handlers, so
// a case that passes here is the behaviour an operator gets.

import (
	"testing"
)

// settingsWriteSpy counts the writes the page attempts, over every endpoint a
// settings card commits through. A rejected entry leaves the count where it was.
const settingsWriteSpy = `
let cardWrites = 0;
const rawCardFetch = w.fetch;
w.fetch = (u, o) => {
  const path = String(u).split('?')[0];
  const m = String((o && o.method) || 'GET').toUpperCase();
  if ((m === 'POST' && (path === '/api/settings/save' || path === '/api/notifications/settings')) ||
      (m === 'PUT' && path === '/api/vpn/policy')) cardWrites++;
  return rawCardFetch(u, o);
};
`

// rejectedCase is the body of one rejected-entry assertion. The report belongs
// to the card that made it, names the field, and the card keeps what the
// operator typed plus its unsaved mark.
const rejectedCase = `
function rejected(cardID, what, label) {
  const err = errorOf(cardID);
  assert.equal(shown(statusOf(cardID)), false, what + ': no success may be reported');
  assert.equal(shown(err), true, what + ': the rejection must be reported in the card');
  assert.ok(err.textContent.indexOf(label) !== -1, what + ': the message must name the field, got: ' + err.textContent);
  assert.equal(shown(badgeOf(cardID)), true, what + ': the card must keep its unsaved state');
  assert.notEqual(doc.getElementById(cardID).getAttribute('aria-busy'), 'true', what + ': the card is not busy');
  assert.equal(toasts.length, 0, what + ': no page toast: ' + JSON.stringify(toasts));
}
`

// TestSettingsSaveModel_LimitsCardRejectsWhatItsMarkupRejects: the three limit
// fields declare a required type=number with a range. An entry outside it is
// reported, sends nothing and stays unsaved.
//
// The boundary saves run first so the stored value differs from every default a
// collector could substitute: a leaked write is then visible as a change of the
// stored number instead of hiding behind a value that happened to match.
func TestSettingsSaveModel_LimitsCardRejectsWhatItsMarkupRejects(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsWriteSpy+rejectedCase+`
const field = doc.getElementById.bind(doc);

async function saveLimits(value, note) {
  cardWrites = 0;
  type('max_connections_per_user', value);
  commitOf('limitsCard').click();
  await until(() => shown(statusOf('limitsCard')) || shown(errorOf('limitsCard')), note + ' to be answered');
  await settled();
}

// Both ends of the declared range are accepted, stored and displayed as entered.
for (const value of ['1', '1000']) {
  await saveLimits(value, 'the boundary ' + value);
  assert.equal(cardWrites, 1, value + ' must be sent exactly once');
  assert.equal(shown(errorOf('limitsCard')), false, value + ' is inside the range: ' + errorOf('limitsCard').textContent);
  const s = await stored();
  assert.equal(String(s.limits.max_connections_per_user), value, value + ' is stored as entered; stored=' + s.limits.max_connections_per_user);
  assert.equal(field('max_connections_per_user').value, value, value + ' is displayed as stored; shown=' + field('max_connections_per_user').value);
  assert.equal(shown(badgeOf('limitsCard')), false, value + ': a stored card is clean');
}

// Every entry the markup rejects. Each case starts from the values the card has
// stored, so the field the card reports is the one under test and not an earlier
// case's leftover: zero and empty are the two the collector used to replace with
// the field default, and the stored value must not move for any of them.
function resetLimits() {
  type('max_connections_per_user', '1000');
  type('connection_rate_limit_count', '5');
  type('connection_rate_limit_window', '60');
}

const CASES = [
  {id: 'max_connections_per_user', value: '0', kept: '0', label: 'Max Connections per User', what: 'zero'},
  {id: 'connection_rate_limit_count', value: '', kept: '', label: 'Rate Limit (connections)', what: 'empty'},
  {id: 'connection_rate_limit_window', value: '9', kept: '9', label: 'Rate Limit Window (seconds)', what: 'below min'},
  {id: 'max_connections_per_user', value: '1001', kept: '1001', label: 'Max Connections per User', what: 'above max'},
  {id: 'connection_rate_limit_count', value: 'abc', kept: '', label: 'Rate Limit (connections)', what: 'non-numeric'},
  {id: 'max_connections_per_user', value: '1.5', kept: '1.5', label: 'Max Connections per User', what: 'a fraction step does not allow'}
];
for (const c of CASES) {
  const what = c.id + '=' + JSON.stringify(c.value) + ' (' + c.what + ')';
  resetLimits();
  cardWrites = 0;
  type(c.id, c.value);
  assert.equal(shown(badgeOf('limitsCard')), true, what + ' makes the card dirty');
  assert.equal(commitOf('limitsCard').disabled, false, what + ' is committable');
  commitOf('limitsCard').click();
  await until(() => shown(errorOf('limitsCard')) || shown(statusOf('limitsCard')), what + ' to be answered');
  await settled();
  const s = await stored();
  assert.equal(cardWrites, 0, what + ' sent a request; stored=' + JSON.stringify(s.limits) +
    ' shown=' + JSON.stringify(field(c.id).value) + ' title=' + field('max_connections_per_user').value);
  assert.equal(s.limits.max_connections_per_user, 1000, what + ' changed the stored maximum to ' + s.limits.max_connections_per_user);
  assert.equal(s.limits.connection_rate_limit_count, 5, what + ' changed the stored rate count to ' + s.limits.connection_rate_limit_count);
  assert.equal(s.limits.connection_rate_limit_window, 60, what + ' changed the stored window to ' + s.limits.connection_rate_limit_window);
  rejected('limitsCard', what, c.label);
  assert.equal(field(c.id).value, c.kept, what + ': the entry stays where it can be corrected');
}
`)
}

// TestSettingsSaveModel_SSLPortRejectsWhatItMustAndIsNotRefilledWithTheDefault:
// the panel port line carried the other half of the class. It had no declared
// bounds at all, and an emptied field was replaced by the default port, so a
// save could move the panel to a port the operator never entered.
func TestSettingsSaveModel_SSLPortRejectsWhatItMustAndIsNotRefilledWithTheDefault(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsWriteSpy+rejectedCase+`
const port = doc.getElementById('panel_port');

async function savePort(value, note) {
  cardWrites = 0;
  type('panel_port', value);
  commitOf('sslCard').click();
  await until(() => shown(statusOf('sslCard')) || shown(errorOf('sslCard')), note + ' to be answered');
  await settled();
}

// Both ends of the declared port range, stored and displayed as entered.
for (const value of ['1', '65535']) {
  await savePort(value, 'the boundary port ' + value);
  assert.equal(cardWrites, 1, 'port ' + value + ' must be sent exactly once');
  assert.equal(shown(errorOf('sslCard')), false, 'port ' + value + ' is inside the range: ' + errorOf('sslCard').textContent);
  const s = await stored();
  assert.equal(String(s.ssl.panel_port), value, 'port ' + value + ' is stored; stored=' + s.ssl.panel_port);
  assert.equal(port.value, value, 'port ' + value + ' is displayed as stored; shown=' + port.value);
  assert.equal(shown(badgeOf('sslCard')), false, 'port ' + value + ': a stored card is clean');
}

// The stored port is 65535 here, so the default port 5000 is a value the field
// does not hold and was never entered.
const CASES = [
  {value: '0', kept: '0', what: 'zero'},
  {value: '-5', kept: '-5', what: 'below min'},
  {value: '65536', kept: '65536', what: 'above max'},
  {value: 'abc', kept: '', what: 'non-numeric'},
  {value: '', kept: '', what: 'empty'}
];
for (const c of CASES) {
  const what = 'panel_port=' + JSON.stringify(c.value) + ' (' + c.what + ')';
  cardWrites = 0;
  type('panel_port', c.value);
  commitOf('sslCard').click();
  await until(() => shown(errorOf('sslCard')) || shown(statusOf('sslCard')), what + ' to be answered');
  await settled();
  const s = await stored();
  assert.equal(cardWrites, 0, what + ' sent a request; stored port=' + s.ssl.panel_port + ' shown=' + JSON.stringify(port.value));
  assert.equal(String(s.ssl.panel_port), '65535', what + ' changed the stored port to ' + s.ssl.panel_port + '; the default 5000 is not a value the operator entered');
  rejected('sslCard', what, 'Panel Port');
  assert.equal(port.value, c.kept, what + ': the entry stays where it can be corrected');
}
`)
}

// TestSettingsSaveModel_ACollectorNeverInventsAValue is the class rule without
// the browser's help: with the field's own constraints taken off the markup, an
// empty entry is a valid field and only the collector stands between it and the
// stored setting. It must still send nothing and invent nothing.
func TestSettingsSaveModel_ACollectorNeverInventsAValue(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsWriteSpy+rejectedCase+`
const input = doc.getElementById('max_connections_per_user');
input.removeAttribute('required');
input.removeAttribute('min');
input.removeAttribute('max');
assert.equal(input.checkValidity(), true, 'the field is unconstrained for this case');

cardWrites = 0;
type('max_connections_per_user', '');
assert.equal(shown(badgeOf('limitsCard')), true, 'an emptied field makes the card dirty');
commitOf('limitsCard').click();
await until(() => shown(errorOf('limitsCard')) || shown(statusOf('limitsCard')), 'the card to answer');
await settled();

const s = await stored();
assert.equal(cardWrites, 0, 'an unparseable entry sent a request; stored=' + JSON.stringify(s.limits) + ' shown=' + JSON.stringify(input.value));
assert.equal(s.limits.max_connections_per_user, 10, 'no default was invented; stored=' + s.limits.max_connections_per_user);
rejected('limitsCard', 'an unconstrained empty field', 'Max Connections per User');
`)
}

// TestSettingsSaveModel_EveryCardValidatesItsOwnMarkup: the rule is the markup's,
// not a list of fields kept in the script. A card with a required text field
// that is not one of the numeric cards is refused the same way.
func TestSettingsSaveModel_EveryCardValidatesItsOwnMarkup(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsWriteSpy+rejectedCase+`
cardWrites = 0;
type('app_title', '');
assert.equal(shown(badgeOf('appearanceCard')), true, 'an emptied title makes the card dirty');
commitOf('appearanceCard').click();
await until(() => shown(errorOf('appearanceCard')) || shown(statusOf('appearanceCard')), 'the card to answer');
await settled();

const s = await stored();
assert.equal(cardWrites, 0, 'an empty required title sent a request; stored title=' + JSON.stringify(s.appearance.title));
assert.equal(s.appearance.title, 'Seed Title', 'the stored title is untouched, got ' + JSON.stringify(s.appearance.title));
rejected('appearanceCard', 'an empty required title', 'Title');
`)
}

// TestSettingsSaveModel_NotificationsCooldownIsNotSentAsAnOmittedField is the
// third collector of the class. The storage layer reads a cooldown of zero as
// "the field was omitted" and keeps the value it already holds, so zero is not a
// cooldown this build can store: the card refuses it and names the field instead
// of reporting a save that did not happen. An emptied field is refused the same
// way. A cooldown inside the declared range is stored and shown as stored.
func TestSettingsSaveModel_NotificationsCooldownIsNotSentAsAnOmittedField(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true}, settingsWriteSpy+rejectedCase+`
const cooldown = () => doc.getElementById('notifications_cooldown');
await until(() => cooldown() && !card('notificationsCard').querySelector('#notificationHistory .text-muted').textContent.startsWith('Loading'), 'notifications to load');

cardWrites = 0;
type('notifications_cooldown', '45');
commitOf('notificationsCard').click();
await until(() => shown(statusOf('notificationsCard')) || shown(errorOf('notificationsCard')), 'the cooldown save to be answered');
await settled();
const saved = await (await realFetch(CFG.base + '/api/notifications/settings')).json();
assert.equal(cardWrites, 1, 'an accepted cooldown is sent exactly once');
assert.equal(shown(errorOf('notificationsCard')), false, '45 is inside the range: ' + errorOf('notificationsCard').textContent);
assert.equal(saved.cooldown_seconds, 45, 'the cooldown is stored as entered, got ' + saved.cooldown_seconds);
assert.equal(cooldown().value, '45', 'the field shows the stored cooldown, got ' + JSON.stringify(cooldown().value));

for (const value of ['0', '']) {
  const what = 'cooldown=' + JSON.stringify(value);
  cardWrites = 0;
  type('notifications_cooldown', value);
  commitOf('notificationsCard').click();
  await until(() => shown(errorOf('notificationsCard')) || shown(statusOf('notificationsCard')), what + ' to be answered');
  await settled();
  const after = await (await realFetch(CFG.base + '/api/notifications/settings')).json();
  assert.equal(cardWrites, 0, what + ' sent a request; stored=' + after.cooldown_seconds + ' shown=' + JSON.stringify(cooldown().value));
  assert.equal(after.cooldown_seconds, 45, what + ' changed the stored cooldown to ' + after.cooldown_seconds);
  rejected('notificationsCard', what, 'Cooldown (seconds)');
}
`)
}

// TestSettingsSaveModel_TheCardShowsTheValueThatWasStored: an entry whose text is
// not the stored number is stored once and then shown as stored, so the field and
// the setting cannot disagree after a save.
func TestSettingsSaveModel_TheCardShowsTheValueThatWasStored(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	runSettingsScenario(t, h, settingsWriteSpy+`
const input = doc.getElementById('max_connections_per_user');
cardWrites = 0;
type('max_connections_per_user', '007');
assert.equal(input.value, '007', 'the entry is what the field holds before the save');
commitOf('limitsCard').click();
await until(() => shown(statusOf('limitsCard')) || shown(errorOf('limitsCard')), 'the save to be answered');
await settled();

const s = await stored();
assert.equal(cardWrites, 1, 'the entry is sent once');
assert.equal(shown(errorOf('limitsCard')), false, 'the entry is accepted: ' + errorOf('limitsCard').textContent);
assert.equal(s.limits.max_connections_per_user, 7, 'the stored setting is the number the entry names, got ' + s.limits.max_connections_per_user);
assert.equal(input.value, '7', 'the field shows the stored setting, got ' + JSON.stringify(input.value));
assert.equal(shown(badgeOf('limitsCard')), false, 'the card is clean once what it sent is stored');
`)
}
