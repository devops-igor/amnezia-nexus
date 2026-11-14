package web

// True read-lifetime serialization regressions for the status view.
//
// These replace the weaker G2 assertions, which counted an abort *notification* as the end of
// a read. Abort only asks a request to stop; the read chain (list, intents, backends, per-order
// details, then the commit) ends when its own await settles. The counters below keep those two
// facts apart on purpose:
//
//   started     a full read began (its list request was issued)
//   settled     a full read chain ran to completion and its promise resolved
//   aborted     an abort event fired — intent to stop, never evidence of settlement
//   overlap     a full read began while an earlier chain had not settled
//
// overlap must be 0 in every scenario. A non-zero aborted with overlap 0 means the request was
// told to stop while the chain was still winding down, which is exactly the state the earlier
// evidence misread as "one authoritative read".

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// gigahostSerializationHarness builds a JSDOM window around the shipped modules with a fake
// clock, abort-aware or abort-ignoring API fixtures, and explicit settlement gates so a test
// decides when a read actually finishes.
//
// mode "abort-aware":   the held request rejects as soon as the signal fires, but the chain's
//
//	settlement still has to unwind (list -> intents -> backends -> detail
//	-> commit), which the test controls.
//
// mode "abort-ignoring": the request never observes the signal and resolves only on release,
//
//	the honest worst case for cancellation.
func gigahostSerializationHarness(t *testing.T, mode, scenario string) string {
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
	encodedMode, _ := json.Marshal(mode)

	return jsdomBootstrapSnippet + fmt.Sprintf(`
const MODE = %s;
const dom = new JSDOM('<button id="refresh"></button><div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.triggerGigahostSetup = () => {};
const flush = async () => { for (let i = 0; i < 14; i++) await new Promise(r => setImmediate(r)); };

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
      const next = due[0]; this.now = next.time; this.clearTimeout(next.id); next.fn(...next.args);
    }
    this.now = target; await flush();
  }
}
const clock = new FakeClock();
['setTimeout','clearTimeout','setInterval','clearInterval'].forEach(m => { w[m] = clock[m].bind(clock); });

// ---- lifetime counters ---------------------------------------------------
let started = 0, settled = 0, aborted = 0, overlap = 0;
// holdPhase selects which request of a read is held: 'list' or 'detail'.
let holdPhase = 'detail';
// holding can be switched off so a scenario can run a read that is expected to complete
// without an explicit release.
let holding = true;
const pending = [];   // {release, reject, phase}
let announcedStatus = 'deploying';
let providerOutage = false;

function beginRead() {
  started++;
  // overlap is judged at the moment a new full read starts: has the previous chain ended?
  if (started - settled > 1) overlap++;
}

// A request that can be released or aborted. In abort-aware mode an abort rejects the promise
// but the caller still has to unwind; in abort-ignoring mode the signal is not observed at all.
// A held request. Both modes hold; they differ only in whether an abort is observed:
//   abort-aware   the promise rejects when the signal fires (but the caller still unwinds)
//   abort-ignoring the promise ignores the signal and resolves only on release
function gate(phase, resolveValue) {
  return new Promise((resolve, reject) => {
    let done = false;
    const entry = {
      phase: phase,
      release: () => { if (done) return; done = true; resolve(resolveValue()); },
      observeAbort: (signal) => {
        if (MODE !== 'abort-aware' || !signal) return;
        signal.addEventListener('abort', () => {
          if (done) return;
          done = true;
          aborted++;
          const e = new Error('aborted');
          e.name = 'AbortError';
          reject(e);
        });
      }
    };
    pending.push(entry);
  });
}

w.API = {
  get: async (url, options) => {
    const signal = options && options.signal;
    if (url === '/api/admin/hosting/gigahost/orders') {
      if (holding && holdPhase === 'list') {
        const p = gate('list', () => ({orders: [{order_id:'same-order', status:'pending'}],
          provider_observations: {'same-order': providerOutage
            ? {outcome:'unavailable', error:'controlled provider unavailable'}
            : {outcome:'confirmed', status: announcedStatus}}}));
        pending[pending.length - 1].observeAbort(signal);
        return await p;
      }
      return {orders: [{order_id:'same-order', status:'pending'}],
              provider_observations: {'same-order': providerOutage
                ? {outcome:'unavailable', error:'controlled provider unavailable'}
                : {outcome:'confirmed', status: announcedStatus}}};
    }
    if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
    if (url === '/api/vpn/backends') return {backends: []};
    if (url.endsWith('/status')) {
      if (holding && holdPhase === 'detail') {
        const p = gate('detail', () => ({deploy: {status: announcedStatus}}));
        pending[pending.length - 1].observeAbort(signal);
        return await p;
      }
      return {deploy: {status: announcedStatus}};
    }
    throw new Error('unexpected GET ' + url);
  },
  post: async () => { throw new Error('the status view must not POST'); },
  delete: async () => { throw new Error('the status view must not DELETE'); }
};

w.eval(%s);
w.eval(%s);
w.eval(%s);
(function(){
  const script = new Function('loadRecentOrders','startGigahostOrderStatusRefresh','loadGigahostCatalog','btnRefreshCatalog', %s);
  w.loadGigahostCatalog = () => {};
  script(w.loadRecentOrders, w.startGigahostOrderStatusRefresh, w.loadGigahostCatalog,
    w.document.getElementById('refresh'));
})();

// Lifetime is measured inside the module's own read sequence, because a follow-up started from
// the settled read's finally is not reachable through a loader wrapper: it is dispatched by the
// module itself. The shipped read counter is therefore the source of truth for "a full read
// began", and a start while another chain has not settled is the overlap this test forbids.
// The module is the authority on overlap, and it records it at the only moment that matters:
// when a full read is admitted. These counters mirror that, so an assertion cannot create
// overlap by observing at an inconvenient time.
function observeLifetime() {
  const state = w.gigahostOrderStatusRefreshState();
  started = state.reads;
  settled = state.settledReads;
  overlap = state.overlapDetected || 0;
}

// announceReady / announceOutage set the provider answer the fixture will serve, so scenarios read
// as intent rather than as string literals.
function announceReady() { announcedStatus = 'ready'; providerOutage = false; }
// announceOutage makes the provider read fail: the list still answers, but with no usable
// provider status, which is the state that must render stale.
function announceOutage() { announcedStatus = 'failed'; providerOutage = true; }
// Live lifetime view: observing first means a scenario can assert the raw names below and see
// the current state rather than a stale snapshot.
const L = new Proxy({}, {get(_, k) {
  observeLifetime();
  if (k === 'started') return started;
  if (k === 'settled') return settled;
  if (k === 'aborted') return aborted;
  if (k === 'overlap') return overlap;
  return undefined;
}});
const stage = () => { const el = w.document.querySelector('.gigahost-order-status'); return el ? el.getAttribute('data-stage') : null; };
const counters = () => { observeLifetime(); return {started, settled, aborted, overlap}; };
const releaseAll = () => { pending.splice(0).forEach(e => e.release()); };
const releaseLast = () => { const e = pending[pending.length-1]; if (e) { pending.pop(); e.release(); } };

(async()=>{
%s
 dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedMode), string(encodedModel), string(encodedIntents), string(encodedStatus), string(encodedHandler), scenario)
}

func runSerializationScenario(t *testing.T, mode, marker, scenario string) {
	t.Helper()
	node := requireJSDOM(t)
	out, err := execNodeScript(node, gigahostSerializationHarness(t, mode, scenario+`
 console.log('`+marker+`');`))
	if err != nil || !strings.Contains(string(out), marker) {
		t.Fatalf("serialization scenario failed: %v\n%s", err, out)
	}
}

// TestGigahostOrderStatusNoFullReadOverlaps pins the original requirement directly: a second
// full read may not begin until the first chain has settled, even though the abort notification
// for the first arrives immediately.
func TestGigahostOrderStatusNoFullReadOverlaps(t *testing.T) {
	runSerializationScenario(t, "abort-aware", "SERIALIZATION_NO_OVERLAP_OK", `
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 assert.equal(L.started, 1, 'the scheduled tick must have started one full read');
 assert.equal(w.gigahostOrderStatusRefreshState().reading, true, 'the read must be live');

 // The operator clicks Refresh while the first read is held at its detail request.
 announceReady();
 w.document.getElementById('refresh').click();
 await flush();

 // The click must not have started a second read, and must not have been lost either.
 assert.equal(L.started, 1, 'a click during a live read must not start a second full read');
 assert.equal(w.gigahostOrderStatusRefreshState().followUp, true,
   'the click must be recorded as a follow-up, not dropped');
 assert.equal(L.overlap, 0, 'no full read may overlap another, saw ' + overlap);

 // Release the held read. It settles, and only then may the follow-up start.
 releaseAll();
 await flush();
 assert.equal(L.started, 2, 'the coalesced follow-up must start after settlement');
 assert.equal(L.overlap, 0, 'the follow-up must not overlap the settled read, saw ' + overlap);

 // Release the follow-up: it carries the current answer and commits it.
 releaseAll();
 await flush();
 assert.equal(stage(), 'ready', 'the follow-up must render current readiness');
 assert.equal(L.overlap, 0, 'overlap must stay 0');
 w.stopGigahostOrderStatusRefresh();
`)
}

// TestGigahostOrderStatusOverlapUnderDelayedSettlement is the same rule with settlement
// delayed well past the abort notification, in both abort-aware and abort-ignoring modes. The
// point is that the abort event count says nothing about whether the chain has finished.
func TestGigahostOrderStatusOverlapUnderDelayedSettlement(t *testing.T) {
	for _, mode := range []string{"abort-aware", "abort-ignoring"} {
		t.Run(mode, func(t *testing.T) {
			runSerializationScenario(t, mode, "SERIALIZATION_DELAYED_OK_"+mode, `
 // Hold the READ's first phase (the list), not its detail: an early phase is the harsher
 // challenge, because the rest of the chain has not even been reached when the click arrives.
 holdPhase = 'list';
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 assert.equal(L.started, 1);

 announceReady();
 w.document.getElementById('refresh').click();
 await flush();

 assert.equal(L.started, 1, 'no second full read while the first is live');
 assert.equal(L.overlap, 0, 'overlap must be 0, saw ' + overlap);

 // Settle the held first read now. In abort-aware mode the abort already fired at the gate,
 // but the chain's settlement is what this release performs — that distinction is the point.
 releaseAll();
 await flush();
 assert.equal(L.settled, 1, 'the first chain must have settled, saw ' + settled);
 assert.equal(L.started, 2, 'the follow-up starts only after settlement');
 assert.equal(L.overlap, 0, 'overlap must remain 0, saw ' + overlap);

 releaseAll();
 await flush();
 assert.equal(stage(), 'ready', 'the follow-up must render current readiness');
 w.stopGigahostOrderStatusRefresh();
`)
		})
	}
}

// TestGigahostOrderStatusCoalescedFollowUps pins that several clicks during one live read
// produce exactly one follow-up, so a slow refresh cannot be turned into a request storm.
func TestGigahostOrderStatusCoalescedFollowUps(t *testing.T) {
	runSerializationScenario(t, "abort-aware", "SERIALIZATION_COALESCE_OK", `
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 assert.equal(L.started, 1);

 announceReady();
 for (let i = 0; i < 5; i++) { w.document.getElementById('refresh').click(); }
 await flush();
 assert.equal(L.started, 1, 'five clicks must not start five reads');
 assert.equal(w.gigahostOrderStatusRefreshState().followUp, true);

 releaseAll();
 await flush();
 assert.equal(L.started, 2, 'five clicks must coalesce into one follow-up, saw ' + started);
 assert.equal(L.overlap, 0);

 releaseAll();
 await flush();
 assert.equal(stage(), 'ready');
 w.stopGigahostOrderStatusRefresh();
`)
}

// TestGigahostOrderStatusStopDropsFollowUp covers stop/pagehide/restart while old work is
// unsettled: the retired read must not paint, and the queued follow-up must not resurrect a
// stopped view.
func TestGigahostOrderStatusStopDropsFollowUp(t *testing.T) {
	runSerializationScenario(t, "abort-ignoring", "SERIALIZATION_STOP_OK", `
 // Land one good read first, so there is something on screen. The provider answer is set
 // before the read begins, because the list response carries the observation for that read.
 announceReady();
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 releaseAll();
 await flush();
 assert.equal(stage(), 'ready');

 // Now start a read, queue a follow-up on it, and stop the view while both are outstanding.
 announceOutage();
 w.loadRecentOrders();
 await flush();
 assert.equal(w.gigahostOrderStatusRefreshState().reading, true, 'a read must be live');
 w.loadRecentOrders();
 await flush();
 assert.equal(w.gigahostOrderStatusRefreshState().followUp, true, 'the second call queued a follow-up');
 assert.equal(w.gigahostOrderStatusRefreshState().reads, 2,
   'the second call must not have started a second read, saw ' + w.gigahostOrderStatusRefreshState().reads);

 w.stopGigahostOrderStatusRefresh();
 assert.equal(w.gigahostOrderStatusRefreshState().scheduled, false);
 assert.equal(w.gigahostOrderStatusRefreshState().followUp, false,
   'stopping must drop the queued follow-up');
 const readsAtStop = w.gigahostOrderStatusRefreshState().reads;

 // Release the retired read. It settles but must not commit, and it must not start a follow-up.
 releaseAll();
 await flush();
 assert.equal(stage(), 'ready', 'a read retired by stop must not paint');
 assert.equal(w.gigahostOrderStatusRefreshState().reads, readsAtStop,
   'no follow-up may start after stop, saw ' + w.gigahostOrderStatusRefreshState().reads);
 assert.ok(w.gigahostOrderStatusRefreshState().settledReads >= 1,
   'the retired chain must still settle (lifetime ends on settle)');

 // Pagehide behaves the same way.
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 announceOutage();
 w.dispatchEvent(new w.Event('pagehide'));
 assert.equal(w.gigahostOrderStatusRefreshState().followUp, false);
 const readsBeforeRelease = w.gigahostOrderStatusRefreshState().reads;
 releaseAll();
 await flush();
 assert.equal(stage(), 'ready', 'a read retired by pagehide must not paint');
 assert.equal(w.gigahostOrderStatusRefreshState().reads, readsBeforeRelease,
   'pagehide must not leave a follow-up to run');
`)
}

// TestGigahostOrderStatusRecoveryAndRetiredProtection keeps both halves honest: a legitimate
// follow-up renders current readiness, and the retired response still cannot move the
// last-success time, the stale state or the backend index.
func TestGigahostOrderStatusRecoveryAndRetiredProtection(t *testing.T) {
	runSerializationScenario(t, "abort-ignoring", "SERIALIZATION_RECOVERY_OK", `
 announceReady();
 w.startGigahostOrderStatusRefresh(w.loadRecentOrders);
 await clock.tick(30000);
 releaseAll();
 await flush();
 assert.equal(stage(), 'ready');
 const goodTime = w.gigahostOrderStatusRefreshState().lastSuccessAt;
 assert.ok(goodTime, 'a confirmed read must record a last-success time');

 // A later read reports the provider unreachable, and a click queues a follow-up. The old
 // (retired) answer must not move the success time even when it settles last.
 announceOutage();
 w.loadRecentOrders();
 await flush();
 w.loadRecentOrders();
 await flush();
 releaseAll();
 await flush();

 // The follow-up's own answer is the current one; state must reflect it, not the retired read.
 assert.equal(stage(), 'failed', 'the follow-up must render the current provider answer');
 assert.equal(w.document.getElementById('recentOrdersContainer').getAttribute('data-stale'), 'true',
   'an unconfirmed provider read must be stale');
 assert.equal(w.gigahostOrderStatusRefreshState().lastSuccessAt, goodTime,
   'an unconfirmed read must not advance the last successful check');

 // And a later confirmed read recovers the view, which is the control proving the serialization
 // rule does not freeze the display.
 // A read is still settling at this point, so the recovery call becomes the coalesced
 // follow-up; release that chain and let the follow-up run without holding.
 announceReady();
 holding = false;
 w.loadRecentOrders();
 await flush();
 releaseAll();          // the outstanding chain settles
 await flush();
 releaseAll();          // the follow-up runs (holding is off, so it may already have)
 await flush();
 assert.equal(stage(), 'ready', 'a confirmed read must recover the view');
 assert.equal(w.document.getElementById('recentOrdersContainer').getAttribute('data-stale'), null,
   'recovery must clear the stale state');
 w.stopGigahostOrderStatusRefresh();
`)
}
