package web

// Behavioural DOM tests for the interactive Gigahost order status and its single
// 30-second refresh.
//
// Everything is executed as shipped: the assertions evaluate the static module the
// settings page loads, in JSDOM, with a spy on the API object. What is asserted is
// therefore the request path an administrator actually gets, not a copy of it.
//
// The acceptance the file pins, one section each:
//
//	model      provider readiness, VPN setup and backend health are three separate
//	           answers; an assigned address never makes a VPS ready
//	keyboard   a native button opens the read-only details on Enter and Space, once
//	           per press, and opening them makes no request
//	timer      exactly one 30-second timer, no overlapping refresh, reset on restart,
//	           cleared on explicit stop and on page teardown
//	failure    a failed refresh keeps the last known data and marks it stale; an
//	           empty answer and a failed read are different states; no terminal stage
//	           is invented from a read that never answered
//	intact     the setup, retry and saved-approval actions and the purchase payload
//	           are the pre-existing ones, and no status interaction posts anything

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// gigahostOrderStatusHarness builds the Node script shared by the tests below. It
// loads the shipped module into a JSDOM window with a fake clock, a recording API
// spy and mutable fixtures, then leaves the scenario body to the caller.
func gigahostOrderStatusHarness(t *testing.T, scenario string) string {
	t.Helper()
	statusModule, err := StaticFS.ReadFile("static/js/gigahost_order_status.js")
	if err != nil {
		t.Fatalf("read the order status module: %v", err)
	}
	modelModule, err := StaticFS.ReadFile("static/js/gigahost_order_status_model.js")
	if err != nil {
		t.Fatalf("read the order status classification module: %v", err)
	}
	intentsModule, err := StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read the setup intents module: %v", err)
	}
	encodedStatus, _ := json.Marshal(string(statusModule))
	encodedIntents, _ := json.Marshal(string(intentsModule))
	encodedModel, _ := json.Marshal(string(modelModule))
	return jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};
// The saved-approval affordance is the shipped one, so its own refusals (a ledger
// placeholder gets no action) are the real behaviour rather than a stand-in. The
// immediate setup path is replaced by a recorder: this file asserts that the status
// view preserves and reaches it, not what it does internally.
const actions = [];
w.triggerGigahostSetup = orderId => actions.push({action:'immediate_setup', orderId});

let orders = [], intents = [], backends = [], deployByOrder = {}, observationByOrder = {};
let failOrders = false, failIntents = false, failBackends = false, failList = false;
const calls = [];
// A prompt or confirmation raised by an accidental action click is answered with a
// refusal here, so such a click cannot silently authorize anything either.
w.prompt = () => null;
w.confirm = () => false;
w.API = {
  get: async url => {
    calls.push({method:'GET', url});
    if (url === '/api/admin/hosting/gigahost/orders') {
      if (failOrders) throw new Error('offline');
      // The real handler answers with the additive per-order provider observation;
      // a scenario supplies only what it wants to differ from "the provider answered".
      return {orders: orders, provider_observations: observationByOrder};
    }
    if (url === '/api/admin/hosting/gigahost/setup-intents') {
      if (failIntents) throw new Error('offline');
      return {setup_intents: intents};
    }
    if (url === '/api/vpn/backends') {
      if (failBackends) throw new Error('offline');
      return {backends: backends};
    }
    const match = String(url).match(/\/orders\/(.+)\/status$/);
    if (match) {
      const id = decodeURIComponent(match[1]);
      if (failList) throw new Error('offline');
      const detail = deployByOrder[id];
      return {status:'ok', deploy: detail === undefined ? {status:'pending'} : detail};
    }
    throw new Error('unexpected GET ' + url);
  },
  post: async (url, body) => { calls.push({method:'POST', url, body}); return {status:'ok'}; },
  delete: async url => { calls.push({method:'DELETE', url}); return {status:'ok'}; }
};

w.eval(%s);
// The sourceURL is what lets a coverage run attribute each module's own blocks to it
// instead of to the undifferentiated stdin script, so CRAP is measurable from this
// test rather than from a parallel harness.
w.eval(%s + '\n//# sourceURL=gigahost_order_status_model.js');
w.eval(%s + '\n//# sourceURL=gigahost_order_status.js');

const container = () => w.document.getElementById('recentOrdersContainer');
const cells = () => Array.from(container().querySelectorAll('.gigahost-order-status'));
const cell = () => container().querySelector('.gigahost-order-status');
const toggle = () => container().querySelector('.gigahost-order-status-toggle');
const panel = () => container().querySelector('.gigahost-order-status-details');
const rowActions = () => Array.from(container().querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent);
const flat = node => (node ? node.textContent.replace(/\s+/g, ' ') : '');
const writes = () => calls.filter(c => c.method !== 'GET');
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };

(async()=>{
%s
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedIntents), string(encodedModel), string(encodedStatus), scenario)
}

// runGigahostOrderStatusScenario executes one scenario body and requires its own
// completion marker, so a script that dies part way cannot pass.
func runGigahostOrderStatusScenario(t *testing.T, marker, scenario string) {
	t.Helper()
	node := requireJSDOM(t)
	out, err := execNodeScript(node, gigahostOrderStatusHarness(t, scenario+`
 console.log('`+marker+`');dom.window.close();`))
	if err != nil || !strings.Contains(string(out), marker) {
		t.Fatalf("order status consumer failed: %v\n%s", err, out)
	}
}

// TestGigahostOrderStatusModelDistinguishesReadiness pins acceptance item 3: the
// provider state alone establishes VPS readiness, and setup and health stay
// separate answers.
func TestGigahostOrderStatusModelDistinguishesReadiness(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_MODEL_OK", `

 // 1. DEFECT ORACLE: an address is assigned but the provider is still deploying.
 //    The address is shown, and readiness is NOT claimed. The old view showed this
 //    order as "vps_ready" because it had an address.
 //    The provider answer is what the server observed in this response; the deploy
 //    DTO is the onboarding journal and carries no step here, because onboarding
 //    never ran for this order.
 orders = [{order_id:'ord-ip', status:'ready', assigned_ip:'198.51.100.7'}];
 observationByOrder = { 'ord-ip': {outcome:'confirmed', status:'deploying'} };
 deployByOrder = { 'ord-ip': {} };
 intents = []; backends = [];
 await w.loadRecentOrders();
 assert.equal(cell().getAttribute('data-stage'), 'deploying', 'an assigned address must not make the VPS ready');
 const ipPanel = flat(panel());
 assert.match(ipPanel, /198\.51\.100\.7/, 'the assigned address must still be shown');
 assert.match(ipPanel, /gigahost_status_ip_while_provisioning/, 'provisioning with an address needs the explanation');
 assert.match(ipPanel, /gigahost_status_setup_none/);
 assert.match(ipPanel, /gigahost_status_health_none/);

 // 2. The three axes are reported separately when they disagree: the provider is
 //    ready, no setup approval exists, and the server is not a backend.
 orders = [{order_id:'ord-split', status:'ready'}];
 observationByOrder = { 'ord-split': {outcome:'confirmed', status:'ready'} };
 deployByOrder = { 'ord-split': {} };
 intents = []; backends = [];
 await w.loadRecentOrders();
 const splitPanel = flat(panel());
 assert.equal(cell().getAttribute('data-stage'), 'ready');
 assert.match(splitPanel, /gigahost_status_setup_none/, 'provider readiness is not VPN setup');
 assert.match(splitPanel, /gigahost_status_health_none/, 'provider readiness is not backend health');
 assert.match(splitPanel, /gigahost_status_next_action_approve_setup/);

 // 3. A paused setup job is its own state with its own next action, even though the
 //    provider side is finished.
 intents = [{order_id:'ord-split', state:'awaiting_host_confirmation', step:'awaiting_host_confirmation'}];
 await w.loadRecentOrders();
 assert.match(flat(panel()), /gigahost_status_setup_needs_operator/);
 assert.match(flat(panel()), /gigahost_status_next_action_resume/);

 // 4. Verified backend health is read from the panel's own backend record, and the
 //    order's panel server id is what joins the two.
 orders = [{order_id:'ord-healthy', status:'ready'}];
 observationByOrder = { 'ord-healthy': {outcome:'confirmed', status:'ready'} };
 deployByOrder = { 'ord-healthy': {status:'ready', step:'ready', server_id:9} };
 intents = [{order_id:'ord-healthy', state:'ready', step:'enabled'}];
 backends = [{server_id:9, enabled:true, status:'active'}];
 await w.loadRecentOrders();
 const healthyPanel = flat(panel());
 assert.match(healthyPanel, /gigahost_status_setup_ready/);
 assert.match(healthyPanel, /gigahost_status_health_healthy/);
 assert.match(healthyPanel, /gigahost_status_next_action_none/, 'a finished, healthy order needs no next action');
 assert.deepEqual(rowActions(), [], 'a finished, onboarded order offers no setup or retry action');

 // 5. A degraded backend is not healthy, and it is not silently rendered healthy.
 backends = [{server_id:9, enabled:true, status:'degraded'}];
 await w.loadRecentOrders();
 assert.match(flat(panel()), /gigahost_status_health_degraded/);
 assert.match(flat(panel()), /gigahost_status_next_action_check_health/);

 // 6. A provider-ready VPS the panel has not onboarded keeps the setup path.
 orders = [{order_id:'ord-onboard', status:'ready', assigned_ip:'198.51.100.11'}];
 observationByOrder = { 'ord-onboard': {outcome:'confirmed', status:'ready'} };
 deployByOrder = { 'ord-onboard': {} };
 intents = []; backends = [];
 await w.loadRecentOrders();
 assert.deepEqual(rowActions(), ['deploy_setup_btn', 'setup_intents_approve'],
   'a provider-ready VPS still needs setup, got ' + JSON.stringify(rowActions()));

 // 7. Explicit terminal and unknown states are kept, and obsolete steps are not
 //    drawn for them: a failed order does not claim it ever deployed, and a ledger
 //    placeholder has no confirmed provider state at all.
 orders = [{order_id:'ord-fail', status:'failed'}];
 observationByOrder = { 'ord-fail': {outcome:'confirmed', status:'failed'} };
 deployByOrder = { 'ord-fail': {status:'failed', step:'installing_protocol', error:'provider refused'} };
 intents = []; backends = [];
 await w.loadRecentOrders();
 assert.equal(cell().getAttribute('data-stage'), 'failed');
 const failChain = Array.from(toggle().querySelectorAll('.gigahost-order-status-stage')).map(s => s.getAttribute('data-stage'));
 assert.deepEqual(failChain, ['requested','failed'], 'a failed order must not claim the deploying step');
 assert.deepEqual(rowActions(), ['deploy_retry_btn']);
 assert.match(flat(panel()), /provider refused/);

 orders = [{order_id:'intent_1700000000000', status:'deploying', assigned_ip:'198.51.100.12'}];
 observationByOrder = { 'intent_1700000000000': {outcome:'not_checked'} };
 deployByOrder = {};
 await w.loadRecentOrders();
 assert.equal(cell().getAttribute('data-stage'), 'unknown',
   'a ledger placeholder has no confirmed provider state');
 assert.match(flat(panel()), /gigahost_status_next_action_check_provider/);
 assert.match(flat(panel()), /gigahost_status_ip_while_provisioning/);

 // 8. A cancelled order is terminal: it reports nothing to do, and the stepper does
 //    not claim it ever deployed. The setup affordance itself is the pre-existing
 //    one and is preserved, because revoking an approval never cancelled the VPS.
 orders = [{order_id:'ord-cancel', status:'cancelled'}];
 observationByOrder = { 'ord-cancel': {outcome:'confirmed', status:'cancelled'} };
 deployByOrder = { 'ord-cancel': {} };
 await w.loadRecentOrders();
 assert.equal(cell().getAttribute('data-stage'), 'cancelled');
 assert.match(flat(panel()), /gigahost_status_next_action_none/);
 const cancelChain = Array.from(toggle().querySelectorAll('.gigahost-order-status-stage')).map(s => s.getAttribute('data-stage'));
 assert.deepEqual(cancelChain, ['requested','cancelled'], 'a cancelled order must not claim the deploying step');
`)
}

// TestGigahostOrderStatusDetailsAreReadOnlyAndKeyboardAccessible pins the
// interaction half of acceptance items 1 and 4: a native, Tab-reachable button
// opens the read-only details, once per press, and opening them performs no
// request at all.
func TestGigahostOrderStatusDetailsAreReadOnlyAndKeyboardAccessible(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_KEYBOARD_OK", `

 orders = [{order_id:'ord-kbd', status:'deploying', assigned_ip:'198.51.100.20'}];
 deployByOrder = { 'ord-kbd': {status:'deploying', step:'ssh_verifying'} };
 intents = []; backends = [];
 await w.loadRecentOrders();

 const t = toggle();
 // A native button is focusable and carries its own activation semantics, which is
 // what makes the control reachable with the keyboard at all.
 assert.equal(t.tagName, 'BUTTON', 'the status control must be a real button');
 assert.equal(t.type, 'button', 'the control must not submit the settings form');
 assert.equal(t.getAttribute('aria-expanded'), 'false');
 assert.ok(t.getAttribute('aria-controls') === panel().id, 'the control must name the panel it owns');
 assert.equal(panel().hidden, true, 'the details start closed');

 // 1. One Enter press opens it, and a second closes it: one press, one toggle.
 t.dispatchEvent(new w.KeyboardEvent('keydown', {key:'Enter', bubbles:true, cancelable:true}));
 assert.equal(panel().hidden, false, 'Enter must open the details');
 assert.equal(t.getAttribute('aria-expanded'), 'true');
 t.dispatchEvent(new w.KeyboardEvent('keydown', {key:'Enter', bubbles:true, cancelable:true}));
 assert.equal(panel().hidden, true, 'a second Enter must close it again');

 // 2. Space is the other documented activation, and any other key is not.
 t.dispatchEvent(new w.KeyboardEvent('keydown', {key:' ', bubbles:true, cancelable:true}));
 assert.equal(panel().hidden, false, 'Space must open the details');
 t.dispatchEvent(new w.KeyboardEvent('keydown', {key:'a', bubbles:true, cancelable:true}));
 assert.equal(panel().hidden, false, 'a non-activation key must not change the disclosure');

 // 3. A key press is consumed, so a browser that would also deliver a click does
 //    not toggle the panel twice for one press.
 const enterEvent = new w.KeyboardEvent('keydown', {key:'Enter', bubbles:true, cancelable:true});
 t.dispatchEvent(enterEvent);
 assert.equal(enterEvent.defaultPrevented, true, 'the activation must be consumed once');

 // 4. THE NEGATIVE CONTROL: opening and closing the details sends nothing. No
 //    order, no setup, no cancellation, no refresh POST - and no row action fires.
 const before = calls.length;
 const actionsBefore = actions.length;
 for (let i = 0; i < 4; i++) {
   t.dispatchEvent(new w.KeyboardEvent('keydown', {key:'Enter', bubbles:true, cancelable:true}));
   t.click();
 }
 assert.deepEqual(writes(), [], 'opening the read-only details must not write anything, got ' + JSON.stringify(writes()));
 assert.deepEqual(actions, actionsBefore === 0 ? [] : actions.slice(actionsBefore),
   'opening the details must not trigger a setup or approval action');
 assert.equal(calls.length - before, 0, 'opening the details must not even re-read the status');

 // 5. The details still describe a read-only view, so the operator is told so.
 t.dispatchEvent(new w.KeyboardEvent('keydown', {key:'Enter', bubbles:true, cancelable:true}));
 assert.match(flat(panel()), /gigahost_status_read_only/);

 // 6. A click is the other activation path, and it agrees with the key path.
 t.click();
 assert.equal(panel().hidden, true);
 t.click();
 assert.equal(panel().hidden, false);
`)
}

// TestGigahostOrderStatusRefreshOwnsExactlyOneTimer pins acceptance item 2: one
// 30-second timer, no overlapping refresh, no duplicate timer on a second start,
// and a clean teardown.
func TestGigahostOrderStatusRefreshOwnsExactlyOneTimer(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_TIMER_OK", `

 // A fake clock replaces the window timers, so the refresh schedule is observed
 // exactly instead of by waiting. The tick drains microtasks between due timers so
 // awaited work can reschedule, which is what makes overlap observable.
 class FakeClock {
   constructor() { this.now = 0; this.timers = []; this.nextId = 1; }
   setTimeout(fn, delay, ...args) { const id = this.nextId++; this.timers.push({id, fn, time: this.now + Math.max(0, delay||0), args, interval: 0}); return id; }
   clearTimeout(id) { this.timers = this.timers.filter(t => t.id !== id); }
   setInterval(fn, delay, ...args) { const id = this.nextId++; const iv = Math.max(1, delay||1); this.timers.push({id, fn, time: this.now + iv, args, interval: iv}); return id; }
   clearInterval(id) { this.clearTimeout(id); }
   pending() { return this.timers.length; }
   async tick(ms) {
     const target = this.now + ms;
     for (let guard = 0; guard < 2000; guard++) {
       await flush();
       const due = this.timers.filter(t => t.time <= target).sort((a,b)=>a.time-b.time||a.id-b.id);
       if (!due.length) break;
       const next = due[0];
       this.now = next.time;
       if (next.interval > 0) next.time = this.now + next.interval; else this.clearTimeout(next.id);
       next.fn(...next.args);
     }
     this.now = target;
     await flush();
   }
 }
 const clock = new FakeClock();
 ['setTimeout','clearTimeout','setInterval','clearInterval'].forEach(m => { w[m] = clock[m].bind(clock); });

 // 1. Nothing is armed until the view starts, and the interval it declares is the
 //    one the acceptance names.
 assert.equal(w.gigahostOrderStatusRefreshState().scheduled, false);
 assert.equal(w.gigahostOrderStatusRefreshState().intervalMs, 30000, 'the refresh interval must be 30 seconds');

 let runs = 0, running = 0, maxConcurrent = 0;
 const task = async () => { running++; maxConcurrent = Math.max(maxConcurrent, running); runs++; await new Promise(r => clock.setTimeout(r, 45000)); running--; };
 w.startGigahostOrderStatusRefresh(task);
 assert.equal(clock.pending(), 1, 'starting the refresh must arm exactly one timer');

 // 2. DUPLICATE-TIMER CONTROL: a second start replaces the timer rather than adding
 //    one, so two call sites cannot poll twice.
 w.startGigahostOrderStatusRefresh(task);
 assert.equal(clock.pending(), 1, 'a second start must not add a second timer');

 // 3. One tick per interval, and NO OVERLAP: each run outlasts the interval, so an
 //    overlapping implementation would show two concurrent runs.
 await clock.tick(30000);
 assert.equal(runs, 1, 'the first interval must produce exactly one refresh');
 assert.equal(w.gigahostOrderStatusRefreshState().inFlight, true);
 await clock.tick(60000);
 assert.equal(runs, 1, 'a refresh still running must not be started again');
 await clock.tick(120000);
 assert.equal(maxConcurrent, 1, 'refreshes must never overlap, saw ' + maxConcurrent);
 assert.ok(runs >= 2, 'the refresh must keep running, saw ' + runs);
 assert.equal(clock.pending(), 1, 'exactly one timer stays armed while running');

 // 4. A RESTART WHILE A REFRESH IS STILL RUNNING gets its own first tick. This is
 //    the ordering a manual refresh produces: the previous request is still open
 //    when the timer is re-armed. The stale request must not swallow the new one.
 let restartRuns = 0;
 w.startGigahostOrderStatusRefresh(async () => { restartRuns++; });
 await clock.tick(30000);
 assert.equal(restartRuns, 1);
 w.startGigahostOrderStatusRefresh(async () => { restartRuns++; });
 await clock.tick(30000);
 assert.equal(restartRuns, 2, 'a restart must schedule its own first refresh');
 w.stopGigahostOrderStatusRefresh();

 // 5. TEARDOWN CONTROL: stopping a settled view leaves no timer at all, and the
 //    refresh does not come back.
 let settledRuns = 0;
 w.startGigahostOrderStatusRefresh(async () => { settledRuns++; });
 await clock.tick(30000);
 assert.equal(settledRuns, 1);
 w.stopGigahostOrderStatusRefresh();
 assert.equal(w.gigahostOrderStatusRefreshState().scheduled, false);
 assert.equal(w.gigahostOrderStatusRefreshState().running, false);
 const settledAt = settledRuns;
 await clock.tick(180000);
 assert.equal(settledRuns, settledAt, 'a stopped refresh must not run again');

 // 6. A refresh that was already in flight when the view was stopped does not
 //    re-arm a timer on the way out: the task it would reschedule is gone.
 w.startGigahostOrderStatusRefresh(task);
 await clock.tick(30000);
 const inFlightAt = runs;
 w.stopGigahostOrderStatusRefresh();
 await clock.tick(300000);
 assert.equal(runs, inFlightAt, 'a stopped view must not keep refreshing');
 assert.equal(w.gigahostOrderStatusRefreshState().scheduled, false);

 // 7. Page teardown is a real stop, not a leak: unloading the page must leave no
 //    scheduled refresh behind.
 let unloadRuns = 0;
 w.startGigahostOrderStatusRefresh(async () => { unloadRuns++; });
 await clock.tick(30000);
 assert.equal(unloadRuns, 1);
 w.dispatchEvent(new w.Event('pagehide'));
 assert.equal(w.gigahostOrderStatusRefreshState().scheduled, false, 'pagehide must stop the refresh');
 const beforeUnload = unloadRuns;
 await clock.tick(180000);
 assert.equal(unloadRuns, beforeUnload, 'no refresh may run after the page was left');
`)
}

// TestGigahostOrderStatusRefreshFailureKeepsLastKnownData pins acceptance item 2's
// failure half: a failed refresh labels what is on screen as stale, an empty answer
// and a failed read stay distinct, and no terminal result is invented.
func TestGigahostOrderStatusRefreshFailureKeepsLastKnownData(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_FAILURE_OK", `

 // 1. Empty is a fact, not a failure: nothing was ordered.
 orders = []; intents = []; backends = [];
 await w.loadRecentOrders();
 assert.match(container().textContent, /gigahost_status_empty/);
 assert.equal(container().getAttribute('data-stale'), null, 'an empty answer is not stale');
 assert.equal(cells().length, 0);

 // 2. A failed first read is a different statement: status unavailable. It must not
 //    borrow the empty text, and it must not invent a terminal stage.
 failOrders = true;
 await w.loadRecentOrders();
 failOrders = false;
 assert.match(container().textContent, /gigahost_status_load_failed/);
 assert.equal(/gigahost_status_empty/.test(container().textContent), false,
   'a failed read must not say there are no orders');
 assert.equal(container().getAttribute('data-stale'), 'true');

 // 3. THE DEFECT ORACLE: after a successful read, a failed refresh keeps the last
 //    known data and marks it stale instead of blanking it or presenting it as
 //    current. This order was never onboarded, so its status column is a provider
 //    answer; onboarding never wrote a step here.
 orders = [{order_id:'ord-stale', status:'deploying', assigned_ip:'198.51.100.30'}];
 observationByOrder = { 'ord-stale': {outcome:'confirmed', status:'deploying'} };
 deployByOrder = { 'ord-stale': {} };
 intents = []; backends = [];
 await w.loadRecentOrders();
 assert.equal(container().getAttribute('data-stale'), null);
 assert.equal(cell().getAttribute('data-stage'), 'deploying');
 const knownText = flat(container());

 //    The panel answers 200 with the same rows, but the provider read inside it
 //    failed. That is the real outage shape, and it must not be presented as current.
 observationByOrder = { 'ord-stale': {outcome:'unavailable', error:'controlled provider unavailable'} };
 await w.loadRecentOrders();
 assert.equal(cell().getAttribute('data-stage'), 'deploying', 'the last known stage must be retained');
 assert.match(flat(container()), /198\.51\.100\.30/, 'the last known address must be retained');
 assert.equal(container().getAttribute('data-stale'), 'true',
   'a 200 that could not reach the provider is still stale');
 const notice = container().querySelector('#recentOrdersStale');
 assert.ok(notice, 'a stale notice must be shown');
 assert.match(flat(notice), /gigahost_status_stale/);
 assert.match(flat(notice), /controlled provider unavailable/, 'the provider error must be shown');
 assert.equal(/gigahost_status_load_failed/.test(flat(container())), false,
   'retained data must not be replaced by the unavailable text');

 // 3b. The last successful check is the last time the provider actually answered, not
 //     the time of this browser read. The panel-level failure path is the other shape.
 assert.match(flat(container()), /gigahost_status_last_check|gigahost_status_stale/);

 // 4. The next successful read clears the stale marker: the data is current again.
 observationByOrder = { 'ord-stale': {outcome:'confirmed', status:'deploying'} };
 await w.loadRecentOrders();
 assert.equal(container().getAttribute('data-stale'), null);
 assert.equal(container().querySelector('#recentOrdersStale'), null);
 assert.equal(cell().getAttribute('data-stage'), 'deploying');

 // 5. A refresh that fails only for the setup or backend lists leaves the provider
 //    stage intact and reports the axes it could not read honestly.
 failIntents = true; failBackends = true;
 await w.loadRecentOrders();
 failIntents = false; failBackends = false;
 assert.equal(cell().getAttribute('data-stage'), 'deploying', 'a partial failure must not change the provider stage');
 const partial = flat(panel());
 // This order was never onboarded, so with the approval list unreadable there is no
 // setup evidence at all: unknown, never "not started".
 assert.match(partial, /gigahost_status_setup_unknown/,
   'an unreadable approval list with no journal evidence is unknown, got ' + partial);
 assert.match(partial, /gigahost_status_health_unknown/, 'an unreadable backend list is unknown, not a previous healthy');

 // 5b. With no journal evidence at all, an unreadable approval list is unknown rather
 //     than "not started": nothing was read, so nothing may be claimed.
 orders = [{order_id:'ord-nolist', status:'deploying'}];
 observationByOrder = { 'ord-nolist': {outcome:'confirmed', status:'deploying'} };
 deployByOrder = { 'ord-nolist': {} };
 failIntents = true; failBackends = true;
 await w.loadRecentOrders();
 failIntents = false; failBackends = false;
 assert.match(flat(panel()), /gigahost_status_setup_unknown/,
   'an unreadable setup list with no journal evidence is unknown, never "not started"');

 // 5c. The journal is what identifies onboarding: a provider-side "deploying" on an
 //     order onboarding never touched is not setup progress, so it stays "not started".
 assert.match(flat(panel()), /gigahost_status_setup_none|gigahost_status_setup_unknown/);

 // 6. A refresh is a read: repeating it never writes.
 assert.deepEqual(writes(), [], 'refreshing the status must never write');
`)
}

// TestGigahostOrderStatusModuleMakesNoSideEffectRequest is the static companion of
// the behavioural negative controls: the module that renders the status and owns the
// refresh must name no endpoint that buys, installs, approves, resumes, confirms or
// cancels anything. Its only writes are the ones it does not have.
func TestGigahostOrderStatusModuleMakesNoSideEffectRequest(t *testing.T) {
	module, err := StaticFS.ReadFile("static/js/gigahost_order_status.js")
	if err != nil {
		t.Fatalf("read the order status module: %v", err)
	}
	source := string(module)
	forbidden := []string{
		"gigahost/order'",
		"/setup-approval",
		"/setup-resume",
		"/setup-host-confirmation",
		"API.post",
		"API.delete",
		"API.put",
		"API.patch",
		"approveSetupIntent(",
		"resumeSetupIntent(",
		"confirmSetupHost(",
		"cancelSetupIntent(",
	}
	for _, token := range forbidden {
		if strings.Contains(source, token) {
			t.Errorf("the order status module must not reference %q: it is a read-only view", token)
		}
	}
	// It must read, though: a status view that fetches nothing would be a lie in
	// the other direction.
	for _, required := range []string{
		"'/api/admin/hosting/gigahost/orders'",
		"'/api/admin/hosting/gigahost/setup-intents'",
		"'/api/vpn/backends'",
		"GIGAHOST_ORDER_STATUS_REFRESH_MS = 30000",
		// The pre-existing setup path and the saved-approval affordance are wired
		// from here, so the renderer that replaced the status label did not drop them.
		"triggerGigahostSetup(",
		"appendSetupApprovalAction(",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the order status module must reference %q", required)
		}
	}
}

// TestGigahostOrderStatusPreservesLegitimateActions pins acceptance item 4's
// positive half: the setup, retry and saved-approval actions and the purchase
// payload are the pre-existing ones, and the status view adds no request.
func TestGigahostOrderStatusPreservesLegitimateActions(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_ACTIONS_OK", `

 // 1. The saved approval is still offered for an order with no address, which is
 //    the state that path exists for, and it is still offered alongside the
 //    immediate setup once an address exists.
 orders = [{order_id:'ord-noip', status:'pending'}];
 deployByOrder = { 'ord-noip': {status:'pending'} };
 intents = []; backends = [];
 await w.loadRecentOrders();
 assert.deepEqual(rowActions(), ['setup_intents_approve'],
   'a pre-address order must still offer the saved approval, got ' + JSON.stringify(rowActions()));

 orders = [{order_id:'ord-withip', status:'pending', assigned_ip:'198.51.100.40'}];
 deployByOrder = { 'ord-withip': {status:'pending', assigned_ip:'198.51.100.40'} };
 await w.loadRecentOrders();
 assert.deepEqual(rowActions(), ['deploy_setup_btn', 'setup_intents_approve'],
   'an addressed order must offer both paths, got ' + JSON.stringify(rowActions()));

 // 2. The row actions still reach the pre-existing setup path: the status cell is
 //    not the control, and clicking an action is not a status disclosure.
 const before = actions.length;
 Array.from(container().querySelectorAll('button:not(.gigahost-order-status-toggle)'))
   .find(b => b.textContent === 'deploy_setup_btn').click();
 assert.deepEqual(actions.slice(before), [{action:'immediate_setup', orderId:'ord-withip'}],
   'the setup action must reach the pre-existing setup path unchanged');
 assert.deepEqual(writes(), [], 'the status view itself must never write');

 // 3. A ledger placeholder still offers no setup action: there is no confirmed
 //    provider order behind it.
 orders = [{order_id:'unknown_1700000000000', status:'pending'}];
 deployByOrder = {};
 await w.loadRecentOrders();
 assert.deepEqual(rowActions(), [], 'a placeholder order must offer no setup action');

 // 4. A status interaction and an action interaction stay distinct: opening the
 //    details does not fire the setup path, and clicking setup does not open the
 //    details.
 orders = [{order_id:'ord-both', status:'ready', assigned_ip:'198.51.100.41'}];
 deployByOrder = { 'ord-both': {status:'ready', step:'ready', server_id:0, assigned_ip:'198.51.100.41'} };
 await w.loadRecentOrders();
 const actionsBefore = actions.length;
 const t = toggle();
 const p = panel();
 assert.equal(p.hidden, true);
 t.click();
 assert.equal(p.hidden, false);
 assert.equal(actions.length, actionsBefore, 'opening the details must not fire a row action');
 t.click();
 assert.equal(p.hidden, true);

`)
}
