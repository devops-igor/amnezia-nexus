package web

// Per-order freshness regressions for the status view.
//
// These pin the retained F1 finding: "last successful check" is a fact about one order's
// provider answer, not about the page read that happened to render it. The earlier shape
// assigned every row this read's time and returned early on the first confirmation, so a
// failed order displayed a fresh time it never had, and another order's success removed the
// only warning that existed for it.
//
// The whole test is ONE continuous JSDOM lifecycle over the shipped modules at four distinct
// clocks - success, total outage, mixed, recovery - because the defect only appears across
// reads: a fixture that builds a new window per phase cannot see a retained timestamp or a
// suppressed failure. Assertions read the rendered <time datetime> and the stale/error sinks,
// not label presence.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func runPerOrderFreshnessScenario(t *testing.T, marker, scenario string) {
	t.Helper()
	modelModule, err := StaticFS.ReadFile("static/js/gigahost_order_status_model.js")
	if err != nil {
		t.Fatalf("read the classification module: %v", err)
	}
	statusModule, err := StaticFS.ReadFile("static/js/gigahost_order_status.js")
	if err != nil {
		t.Fatalf("read the status module: %v", err)
	}
	intentsModule, err := StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read the setup intents module: %v", err)
	}
	encodedModel, _ := json.Marshal(string(modelModule))
	encodedStatus, _ := json.Marshal(string(statusModule))
	encodedIntents, _ := json.Marshal(string(intentsModule))

	node := requireJSDOM(t)
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<button id="refresh"></button><div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.triggerGigahostSetup = () => {};
const flush = async () => { for (let i = 0; i < 16; i++) await new Promise(r => setImmediate(r)); };

w.eval(%s);
w.eval(%s);
w.eval(%s);

// ---- fixture: one response phase at a time, driven by the scenario ----
let clock = '2026-11-11T01:00:00Z';
w.gigahostOrderStatusNow = () => new Date(clock);
let phase = '';

// Two orders whose provider answers are set per phase. The order ids match the auditor's
// replay so an assertion here means the same thing it meant there.
function responseFor(phaseName) {
  const obs = (id) => {
    switch (phaseName) {
      case 'confirmed': return {outcome:'confirmed', status:'ready'};
      case 'outage':    return {outcome:'unavailable', error:'controlled provider timeout for ' + id};
      case 'mixed':     return id === 'audit-a'
        ? {outcome:'unavailable', error:'controlled provider timeout for audit-a'}
        : {outcome:'confirmed', status:'ready'};
      case 'recovered': return {outcome:'confirmed', status:'ready'};
      default: throw new Error('unknown phase ' + phaseName);
    }
  };
  return {
    orders: [
      {order_id:'audit-b', status:'ready', assigned_ip:'198.51.100.77'},
      {order_id:'audit-a', status:'ready', assigned_ip:'198.51.100.77'}
    ],
    provider_observations: { 'audit-a': obs('audit-a'), 'audit-b': obs('audit-b') }
  };
}
w.API = {
  get: async (url) => {
    if (url === '/api/admin/hosting/gigahost/orders') return responseFor(phase);
    if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
    if (url === '/api/vpn/backends') return {backends: []};
    if (url.endsWith('/status')) return {deploy: {status:'ready'}};
    throw new Error('unexpected GET ' + url);
  },
  post: async () => { throw new Error('the status view must not POST'); },
  delete: async () => { throw new Error('the status view must not DELETE'); }
};

const container = () => w.document.getElementById('recentOrdersContainer');
// Row lookups are by order id, never by position: a reorder must not change what is asserted.
const cellFor = (id) => container().querySelector('.gigahost-order-status[data-order-id="' + id + '"]');
const checkedTime = (id) => {
  const cell = cellFor(id);
  if (!cell) return null;
  const times = Array.from(cell.querySelectorAll('.gigahost-order-status-details time'));
  // The first time element in the panel is "Last successful check".
  return times.length ? times[0].getAttribute('datetime') : null;
};
const notChecked = (id) => {
  const cell = cellFor(id);
  return !!cell && /gigahost_status_not_checked/.test(cell.querySelector('.gigahost-order-status-details').textContent);
};
const rowStale = (id) => { const c = cellFor(id); return c ? c.getAttribute('data-stale') : null; };
const viewStale = () => container().getAttribute('data-stale');
const flat = (node) => (node ? node.textContent.replace(/\s+/g, ' ') : '');

(async()=>{
%s
 console.log('`+marker+`'); dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedModel), string(encodedIntents), string(encodedStatus), scenario)

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), marker) {
		t.Fatalf("per-order freshness scenario failed: %v\n%s", err, out)
	}
}

// TestGigahostOrderStatusPerOrderFreshness replays the reviewer's exact four-phase ordering in
// one lifecycle and asserts the rendered per-order timestamps and failure sinks.
func TestGigahostOrderStatusPerOrderFreshness(t *testing.T) {
	runPerOrderFreshnessScenario(t, "PER_ORDER_FRESHNESS_OK", `
 // 1. Both orders confirmed at 01:00. Each row shows that confirmation time.
 phase = 'confirmed'; clock = '2026-11-11T01:00:00Z';
 await w.loadRecentOrders();
 assert.equal(checkedTime('audit-a'), '2026-11-11T01:00:00.000Z', 'a confirmed row shows its confirmation time');
 assert.equal(checkedTime('audit-b'), '2026-11-11T01:00:00.000Z');
 assert.equal(rowStale('audit-a'), null, 'a confirmed row is not stale');
 assert.equal(viewStale(), null);

 // 2. TOTAL OUTAGE at 02:00. The provider answered nothing, so neither row may claim 02:00.
 //    The view is stale and both rows carry their own diagnostics.
 phase = 'outage'; clock = '2026-11-11T02:00:00Z';
 await w.loadRecentOrders();
 assert.equal(viewStale(), 'true', 'a total outage must mark the view stale');
 assert.equal(checkedTime('audit-a'), '2026-11-11T01:00:00.000Z',
   'a failed read must retain the last confirmed time, saw ' + checkedTime('audit-a'));
 assert.equal(checkedTime('audit-b'), '2026-11-11T01:00:00.000Z',
   'one order must not borrow another read time during an outage');
 assert.equal(rowStale('audit-a'), 'true', 'a failed row must be visibly stale');
 assert.equal(rowStale('audit-b'), 'true');
 assert.match(flat(container()), /controlled provider timeout for audit-a/, 'the failing diagnostic must be visible');
 assert.match(flat(container()), /controlled provider timeout for audit-b/);

 // 3. MIXED at 03:00: order B confirms, order A still fails. A keeps 01:00 and stays visibly
 //    stale with its diagnostic; B advances to 03:00. This is the case the earlier code got
 //    wrong in both directions at once.
 phase = 'mixed'; clock = '2026-11-11T03:00:00Z';
 await w.loadRecentOrders();
 assert.equal(checkedTime('audit-b'), '2026-11-11T03:00:00.000Z',
   'the confirmed order must advance to this read time');
 assert.equal(checkedTime('audit-a'), '2026-11-11T01:00:00.000Z',
   'another order success must not advance the failed row, saw ' + checkedTime('audit-a'));
 assert.equal(rowStale('audit-b'), null, 'the confirmed row is not stale');
 assert.equal(rowStale('audit-a'), 'true', 'the failed row stays stale even though another order succeeded');
 assert.equal(viewStale(), 'true', 'a mixed response with a failure must still mark the view stale');
 assert.match(flat(container()), /controlled provider timeout for audit-a/,
   'the failed order diagnostic must survive another order success');

 // 4. RECOVERY at 04:00: both confirm again. A advances and its stale state clears.
 phase = 'recovered'; clock = '2026-11-11T04:00:00Z';
 await w.loadRecentOrders();
 assert.equal(checkedTime('audit-a'), '2026-11-11T04:00:00.000Z', 'recovery advances the previously failed row');
 assert.equal(checkedTime('audit-b'), '2026-11-11T04:00:00.000Z');
 assert.equal(rowStale('audit-a'), null, 'recovery must clear the per-row stale state');
 assert.equal(viewStale(), null, 'recovery must clear the view stale state');
 assert.equal(/controlled provider timeout/.test(flat(container())), false, 'recovery must clear the diagnostic');
`)
}

// TestGigahostOrderStatusNeverConfirmedShowsNotChecked covers the adjacent case: a row that has
// never been confirmed must not display the fetch time as a success. It also covers unconfirmed
// and not_checked observations, which are neither confirmations nor failures.
func TestGigahostOrderStatusNeverConfirmedShowsNotChecked(t *testing.T) {
	runPerOrderFreshnessScenario(t, "PER_ORDER_FRESHNESS_NOTCHECKED_OK", `
 // A fresh page whose very first read cannot confirm anything: nothing is known, so nothing
 // may be presented as checked. The time element must be absent and the panel must say so.
 w.API.get = (function(original){
   return async (url) => {
     if (url === '/api/admin/hosting/gigahost/orders') {
       return {orders: [
         {order_id:'audit-a', status:'ready'},
         {order_id:'audit-b', status:'ready'},
         {order_id:'audit-c', status:'ready'}
       ], provider_observations: {
         'audit-a': {outcome:'unavailable', error:'never confirmed at all'},
         'audit-b': {outcome:'unconfirmed'},
         'audit-c': {outcome:'not_checked'}
       }};
     }
     if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
     if (url === '/api/vpn/backends') return {backends: []};
     if (url.endsWith('/status')) return {deploy: {}};
     throw new Error('unexpected GET ' + url);
   };
 })(w.API.get);
 clock = '2026-11-11T05:00:00Z';
 await w.loadRecentOrders();

 // The read happened at 05:00, and none of these rows was confirmed then or ever.
 assert.equal(checkedTime('audit-a'), null, 'a never-confirmed row must not render a success time');
 assert.equal(checkedTime('audit-b'), null, 'an unconfirmed row must not render a success time');
 assert.equal(checkedTime('audit-c'), null, 'a not_checked row must not render a success time');
 assert.equal(notChecked('audit-a'), true, 'the panel must say Not checked for a never-confirmed row');
 assert.equal(notChecked('audit-b'), true);
 assert.equal(notChecked('audit-c'), true);
 assert.equal(/\d{2}:\d{2}/.test(flat(cellFor('audit-b'))), false,
   'no clock time may appear for a row nobody confirmed');

 // The unavailable row is the only one that reports a failure; the other two are silent, and a
 // silent answer must not be dressed up as either success or failure.
 assert.equal(rowStale('audit-a'), 'true');
 assert.equal(rowStale('audit-b'), null, 'an unconfirmed read is not a failure');
 assert.equal(rowStale('audit-c'), null, 'a not_checked read is not a failure');
 assert.match(flat(container()), /never confirmed at all/);
 assert.equal(/unconfirmed/.test(flat(container())), false, 'a silent answer must not become a diagnostic');
`)
}

// TestGigahostOrderStatusFreshnessSurvivesReorder keeps the memory attached to the order rather
// than to a row position, so a list reorder cannot transfer one order's confirmation to another.
func TestGigahostOrderStatusFreshnessSurvivesReorder(t *testing.T) {
	runPerOrderFreshnessScenario(t, "PER_ORDER_FRESHNESS_REORDER_OK", `
 phase = 'confirmed'; clock = '2026-11-11T01:00:00Z';
 await w.loadRecentOrders();
 assert.equal(checkedTime('audit-a'), '2026-11-11T01:00:00.000Z');

 // The provider now returns the same two orders in the opposite order, with A failing.
 w.API.get = (function(original){
   return async (url) => {
     if (url === '/api/admin/hosting/gigahost/orders') {
       return {orders: [
         {order_id:'audit-a', status:'ready'},
         {order_id:'audit-b', status:'ready'}
       ], provider_observations: {
         'audit-a': {outcome:'unavailable', error:'controlled provider timeout for audit-a'},
         'audit-b': {outcome:'confirmed', status:'ready'}
       }};
     }
     if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
     if (url === '/api/vpn/backends') return {backends: []};
     if (url.endsWith('/status')) return {deploy: {}};
     throw new Error('unexpected GET ' + url);
   };
 })(w.API.get);
 clock = '2026-11-11T06:00:00Z';
 await w.loadRecentOrders();

 // Identity, not position, decides: A keeps its 01:00 and is stale; B advances to 06:00.
 assert.equal(checkedTime('audit-a'), '2026-11-11T01:00:00.000Z',
   'a reordered failed row must keep its own confirmed time, saw ' + checkedTime('audit-a'));
 assert.equal(checkedTime('audit-b'), '2026-11-11T06:00:00.000Z');
 assert.equal(rowStale('audit-a'), 'true');
 assert.equal(rowStale('audit-b'), null);
 assert.match(flat(cellFor('audit-a')), /controlled provider timeout for audit-a/);
 assert.equal(/controlled provider timeout/.test(flat(cellFor('audit-b'))), false,
   'the confirmed row must not display the failed row diagnostic');
`)
}
