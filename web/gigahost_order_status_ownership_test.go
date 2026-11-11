package web

// Regressions for the status view's refresh/result ownership.
//
// The defect these pin: the manual Refresh control, the initial read and the post-action
// reads called the loader directly, so they could start a second full status read while
// the scheduled one was still outstanding, and the older response could then commit over
// a newer answer. Every case below drives the *shipped* production listener — the manual
// handler block is extracted from settings.html and evaluated, not re-implemented — with
// a deferred API so the ordering is deterministic.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// gigahostOrderStatusOwnershipHarness builds a JSDOM window with the shipped modules, a
// fake clock, and an API whose per-order detail response is held until the scenario
// releases it. `templateBlock` is the actual manual-refresh handler from settings.html.
func gigahostOrderStatusOwnershipHarness(t *testing.T, scenario string) string {
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
	templateBytes, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read the settings template: %v", err)
	}
	// The listener is taken from the template verbatim, so a change to the shipped wiring
	// is exercised rather than described.
	template := string(templateBytes)
	start := strings.Index(template, "    if (btnRefreshCatalog) {")
	end := strings.Index(template, "    if (btnDeployVPS)")
	if start < 0 || end <= start {
		t.Fatalf("the manual refresh handler is not where the template puts it")
	}
	manualHandler := template[start:end]

	encodedModel, _ := json.Marshal(string(modelModule))
	encodedStatus, _ := json.Marshal(string(statusModule))
	encodedIntents, _ := json.Marshal(string(intentsModule))
	encodedHandler, _ := json.Marshal(manualHandler)

	return jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<button id="refresh"></button><div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.triggerGigahostSetup = () => {};

class FakeClock {
  constructor() { this.now = 0; this.timers = []; this.nextId = 1; }
  setTimeout(fn, delay, ...args) { const id = this.nextId++; this.timers.push({id, fn, time: this.now + Math.max(0, delay||0), args}); return id; }
  clearTimeout(id) { this.timers = this.timers.filter(t => t.id !== id); }
  setInterval(fn, delay, ...args) { return this.setTimeout(fn, delay, ...args); }
  clearInterval(id) { this.clearTimeout(id); }
  pending() { return this.timers.length; }
  async tick(ms) {
    const target = this.now + ms;
    for (let guard = 0; guard < 500; guard++) {
      await flush();
      const due = this.timers.filter(t => t.time <= target).sort((a,b)=>a.time-b.time||a.id-b.id);
      if (!due.length) break;
      const next = due[0];
      this.now = next.time;
      this.clearTimeout(next.id);
      next.fn(...next.args);
    }
    this.now = target;
    await flush();
  }
}
const clock = new FakeClock();
['setTimeout','clearTimeout','setInterval','clearInterval'].forEach(m => { w[m] = clock[m].bind(clock); });
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r)); };

// The fake API counts only reads that are still able to complete: a request whose signal
// is aborted stops being concurrent work, which is what an aborted fetch does.
let detailCalls = 0, active = 0, maxConcurrent = 0, aborted = 0;
const held = [];
// A read's provider answer is decided when the read starts, because that is when the list
// request carries the provider observation. readStatuses is consumed one entry per read,
// so a scenario states "the scheduled read sees deploying, the manual read sees ready"
// without depending on request interleaving.
let readStatuses = [];
let announcedStatus = 'deploying';
const nextReadStatus = () => {
  announcedStatus = readStatuses.length ? readStatuses.shift() : 'deploying';
  return announcedStatus;
};
const announce = (status) => { readStatuses.push(status); };
w.API = {
  get: async (url, options) => {
    const signal = options && options.signal;
    if (url === '/api/admin/hosting/gigahost/orders') {
      const status = nextReadStatus();
      return {orders: [{order_id: 'same-order', status: 'pending'}],
              provider_observations: {'same-order': {outcome: 'confirmed', status: status}}};
    }
    if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
    if (url === '/api/vpn/backends') return {backends: []};
    if (url.endsWith('/status')) {
      detailCalls++;
      active++;
      maxConcurrent = Math.max(maxConcurrent, active);
      const status = announcedStatus;
      return await new Promise((resolve, reject) => {
        let settled = false;
        const entry = {
          release: () => { if (settled) return; settled = true; active--; resolve({deploy: {status: status}}); }
        };
        held.push(entry);
        if (signal) {
          signal.addEventListener('abort', () => {
            if (settled) return;
            settled = true;
            active--;
            aborted++;
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }
      });
    }
    throw new Error('unexpected GET ' + url);
  },
  post: async () => { throw new Error('the status view must not POST'); },
  delete: async () => { throw new Error('the status view must not DELETE'); }
};

w.eval(%s);
w.eval(%s);
w.eval(%s);
// Install the shipped manual-refresh listener against this window.
(function(){
  const handlerSource = %s;
  const script = new Function('loadRecentOrders','startGigahostOrderStatusRefresh','loadGigahostCatalog',
    'btnRefreshCatalog', handlerSource);
  w.loadGigahostCatalog = () => {};
  script(w.loadRecentOrders, w.startGigahostOrderStatusRefresh, w.loadGigahostCatalog,
    w.document.getElementById('refresh'));
})();

const stage = () => {
  const el = w.document.querySelector('.gigahost-order-status');
  return el ? el.getAttribute('data-stage') : null;
};
const release = (index) => held[index].release();

(async()=>{
%s
 dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedModel), string(encodedIntents), string(encodedStatus), string(encodedHandler), scenario)
}

func runGigahostOrderStatusOwnership(t *testing.T, marker, scenario string) {
	t.Helper()
	node := requireJSDOM(t)
	out, err := execNodeScript(node, gigahostOrderStatusOwnershipHarness(t, scenario+`
 console.log('`+marker+`');`))
	if err != nil || !strings.Contains(string(out), marker) {
		t.Fatalf("ownership scenario failed: %v\n%s", err, out)
	}
}

// TestGigahostOrderStatusManualRefreshKeepsNewestResult is the F3 regression in the shape
// the reviewer used: a scheduled read is held at the detail request, the operator clicks
// the shipped Refresh control, the newer read completes ready, and then the older response
// is released. The older answer must not replace the newer one, and it must not be able to
// write the DOM at all once superseded.
func TestGigahostOrderStatusManualRefreshKeepsNewestResult(t *testing.T) {
	runGigahostOrderStatusOwnership(t, "GIGAHOST_OWNERSHIP_MANUAL_OK", `
 // 1. A scheduled read starts and is held at the per-order detail request.
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 assert.equal(detailCalls, 1, 'the scheduled read must have reached the detail request');

 // 2. The operator clicks the shipped manual Refresh control. This used to start a second
 //    full read while the scheduled one was still open. The manual read's provider answer
 //    is ready, which is the answer the operator is waiting for.
 announce('ready');
 w.document.getElementById('refresh').click();
 await flush();

 // The held scheduled read was superseded and aborted, so it is no longer work in flight.
 assert.equal(aborted, 1, 'the superseded read must be aborted, saw ' + aborted + ' aborts');
 assert.equal(w.gigahostOrderStatusRefreshState().reading, true,
   'the newer read owns the view, so a read is outstanding');
 assert.equal(maxConcurrent, 1, 'no two full reads may be outstanding, saw ' + maxConcurrent);

 // 3. The newer read answers ready and renders it.
 release(held.length - 1);
 await flush();
 assert.equal(stage(), 'ready', 'the newer read must render its own answer');
 const readyAt = w.gigahostOrderStatusRefreshState().lastSuccessAt;

 // 4. The obsolete scheduled response now arrives late. It must change nothing: not the
 //    stage, not the success time, not the stale state.
 release(0);
 await flush();
 assert.equal(stage(), 'ready', 'an obsolete response must not overwrite newer readiness');
 assert.equal(w.gigahostOrderStatusRefreshState().lastSuccessAt, readyAt,
   'an obsolete response must not move the last successful check');
 assert.equal(w.document.getElementById('recentOrdersContainer').getAttribute('data-stale'), null,
   'an obsolete response must not change the stale state');

 // 5. Exactly one timer is still armed after all of that.
 assert.equal(clock.pending(), 1, 'one refresh timer must remain, saw ' + clock.pending());
 w.stopGigahostOrderStatusRefresh();
`)
}

// TestGigahostOrderStatusTimerDoesNotSupersedeAUserRead pins the other half of the rule:
// polling must not abandon a read the operator triggered. A tick that arrives while a
// manual read is outstanding skips and re-arms; it does not abort the manual read.
func TestGigahostOrderStatusTimerDoesNotSupersedeAUserRead(t *testing.T) {
	runGigahostOrderStatusOwnership(t, "GIGAHOST_OWNERSHIP_TIMER_DEFERS_OK", `
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);

 // The operator's read is outstanding (manual click, no scheduled tick has run yet).
 announce('ready');
 w.document.getElementById('refresh').click();
 await flush();
 assert.equal(aborted, 0, 'no read was outstanding to supersede yet');
 const manualCalls = detailCalls;

 // A scheduled tick arrives while the manual read is held. It must skip, not supersede.
 await clock.tick(30000);
 assert.equal(aborted, 0, 'polling must not abort a read the operator started');
 assert.equal(detailCalls, manualCalls, 'the skipped tick must not start its own detail read');
 assert.equal(clock.pending(), 1, 'the skipped tick must re-arm its timer');

 // The manual read still owns the view and commits normally.
 release(held.length - 1);
 await flush();
 assert.equal(stage(), 'ready', 'the manual read must still commit its answer');
 w.stopGigahostOrderStatusRefresh();
`)
}

// TestGigahostOrderStatusStopRetiresOutstandingRead covers teardown: after an explicit
// stop or a pagehide, a read still in flight cannot commit into the view.
func TestGigahostOrderStatusStopRetiresOutstandingRead(t *testing.T) {
	runGigahostOrderStatusOwnership(t, "GIGAHOST_OWNERSHIP_STOP_OK", `
 // A read renders first, so there is something on screen to be wrongly replaced.
 announce('ready');
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 release(held.length - 1);
 await flush();
 assert.equal(stage(), 'ready');

 // Now start another read and stop the view while it is outstanding.
 announce('failed');
 w.loadRecentOrders();
 await flush();
 assert.equal(w.gigahostOrderStatusRefreshState().reading, true,
   'the read must be outstanding before the stop is asserted');
 w.stopGigahostOrderStatusRefresh();
 const heldIndex = held.length - 1;

 // Releasing the retired answer must not paint a failure over the view.
 release(heldIndex);
 await flush();
 assert.equal(stage(), 'ready', 'a read retired by stop must not commit');

 // The same holds for page teardown.
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 const unloadIndex = held.length - 1;
 assert.equal(w.document.getElementById('recentOrdersContainer').getAttribute('data-stale'), null);
 w.dispatchEvent(new w.Event('pagehide'));
 assert.equal(w.gigahostOrderStatusRefreshState().scheduled, false, 'pagehide must stop the timer');
 assert.ok(aborted >= 2, 'pagehide must abort the outstanding read, saw ' + aborted);
 release(unloadIndex);
 await flush();
 assert.equal(stage(), 'ready', 'a read retired by pagehide must not commit');
`)
}

// TestGigahostOrderStatusPostActionReadOwnsTheResult covers the post-action callers (the
// post-purchase read in the template and the post-setup read in gigahost_setup.js). They
// reach the same loader, so they must obey the same ownership rule rather than racing a
// scheduled read.
func TestGigahostOrderStatusPostActionReadOwnsTheResult(t *testing.T) {
	runGigahostOrderStatusOwnership(t, "GIGAHOST_OWNERSHIP_POST_ACTION_OK", `
 // A scheduled read is held.
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 assert.equal(detailCalls, 1);

 // A post-action read (the call both post-action sites make) supersedes it and answers.
 announce('ready');
 w.loadRecentOrders();
 await flush();
 assert.equal(aborted, 1, 'a post-action read must take ownership, saw ' + aborted + ' aborts');
 release(held.length - 1);
 await flush();
 assert.equal(stage(), 'ready');

 // The superseded scheduled answer arriving late changes nothing.
 release(0);
 await flush();
 assert.equal(stage(), 'ready', 'the post-action answer must survive the older response');
 w.stopGigahostOrderStatusRefresh();
`)
}

// TestGigahostOrderStatusRecoveryAfterProviderFailure is the legitimate completion and
// recovery control: the ownership rule must not prevent a genuinely newer answer from
// being shown, including one that recovers from a failure.
func TestGigahostOrderStatusRecoveryAfterProviderFailure(t *testing.T) {
	runGigahostOrderStatusOwnership(t, "GIGAHOST_OWNERSHIP_RECOVERY_OK", `
 // First read: provider unavailable, so the view says so.
 w.API.get = (function(original){
   return async (url, options) => {
     if (url === '/api/admin/hosting/gigahost/orders') {
       return {orders: [{order_id:'same-order', status:'failed'}],
               provider_observations: {'same-order': {outcome:'unavailable', error:'provider down'}}};
     }
     if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
     if (url === '/api/vpn/backends') return {backends: []};
     if (url.endsWith('/status')) return {deploy: {}};
     throw new Error('unexpected GET ' + url);
   };
 })(w.API.get);
 await w.loadRecentOrders();
 const container = w.document.getElementById('recentOrdersContainer');
 assert.equal(container.getAttribute('data-stale'), 'true', 'a failed provider read must be stale');
 assert.equal(stage(), 'failed', 'the provider failure is the last known state');

 // Second read: the provider answers again. The new owner must be allowed to recover the
 // view, which is the control that proves the ownership rule is not a freeze.
 w.API.get = async (url, options) => {
   if (url === '/api/admin/hosting/gigahost/orders') {
     return {orders: [{order_id:'same-order', status:'ready'}],
             provider_observations: {'same-order': {outcome:'confirmed', status:'ready'}}};
   }
   if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
   if (url === '/api/vpn/backends') return {backends: []};
   if (url.endsWith('/status')) return {deploy: {}};
   throw new Error('unexpected GET ' + url);
 };
 await w.loadRecentOrders();
 assert.equal(container.getAttribute('data-stale'), null, 'recovery must clear the stale state');
 assert.equal(stage(), 'ready', 'recovery must render the confirmed state');
`)
}
