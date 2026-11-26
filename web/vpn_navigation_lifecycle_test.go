package web

import (
	"encoding/json"
	"strings"
	"testing"
)

// requireVPNNavigationRuntime fails closed: a missing optional DOM dependency
// must not silently remove the navigation regression guards from a green run.
func requireVPNNavigationRuntime(t *testing.T, f *VPNTestFixture) string {
	t.Helper()
	if f.NodePath == "" {
		t.Fatal("VPN navigation regressions require Node.js (see CONTRIBUTING.md)")
	}
	out, err := execNodeScript(f.NodePath, jsdomBootstrapSnippet+`console.log('VPN_NAV_RUNTIME_READY');`)
	if err != nil || !strings.Contains(string(out), "VPN_NAV_RUNTIME_READY") {
		t.Fatalf("VPN navigation regressions require jsdom: %v\n%s", err, out)
	}
	return f.NodePath
}

func TestVPNPageSuccessfulActionsKeepTerminalFocus(t *testing.T) {
	f := NewVPNTestFixtureForPage(t, "vpn_backends")
	requireVPNNavigationRuntime(t, f)
	script := f.BuildJSDOMHarness(JSDOMHarnessOptions{IncludeNexusTable: true, IncludeFakeClock: true, ExtraJS: `
(async () => {
 const d = w.document;
 d.body.insertAdjacentHTML('beforeend', '<div id="nexusConfirmModal" class="modal-backdrop"><h2 id="nexusConfirmTitle"></h2><p id="nexusConfirmBody"></p><button id="nexusConfirmOkBtn"></button><button id="nexusConfirmCancelBtn"></button><button id="nexusConfirmCloseBtn"></button></div>');
 addScript(fs.readFileSync('static/js/ui.js', 'utf8'));
 w.UI.toast = () => {};
 let rows = [{id: 77, server_id: 2, enabled: true, status: 'active'}];
 let posts = 0, reads = 0, reject = false;
 w.API = { get: async () => { reads++; return {backends: rows}; }, post: async () => { posts++; if (reject) throw Error('refused'); rows = []; } };
 for (const action of ['delete', 'disable']) {
   rows = [{id: 77, server_id: 2, enabled: true, status: 'active'}];
   await w.vpnLoadBackends();
   const selector = action === 'delete' ? '[data-action="vpn-delete-backend"]' : '[data-action="vpn-toggle-backend"]';
   const opener = d.querySelector(selector);
   opener.focus();
   const pending = action === 'delete' ? w.vpnDeleteBackend(2) : w.vpnToggleBackend(2, 'disable');
   assert(d.getElementById('nexusConfirmModal').classList.contains('active'), 'real confirmation opened');
   fakeClock.tick(80);
   const before = reads;
   d.getElementById('nexusConfirmOkBtn').click();
   assert.strictEqual(d.activeElement, opener, 'confirmation closes before the POST refresh');
   await pending;
   assert.strictEqual(reads, before + 1, 'success really refreshed the owner');
   assert.strictEqual(opener.isConnected, false, 'refresh replaced the activated row');
   assert.strictEqual(d.activeElement.id, 'vpn-backends-title', 'success keeps terminal owner focus');
 }
 const cta = d.querySelector('#vpn-backends-tbody [data-action="vpn-open-add-backend"]');
 cta.focus();
 w.openModal('addBackendModal');
 fakeClock.tick(80);
 d.getElementById('vpnServerSelect').innerHTML = '<option value="2">server</option>';
 await w.vpnSubmitAddBackend();
 assert.strictEqual(cta.isConnected, false, 'Add refreshed the replaceable empty-state opener');
 assert.strictEqual(d.activeElement.id, 'vpn-add-backend-btn', 'Add returns to the permanent opener');
 rows = [{id: 77, server_id: 2, enabled: true, status: 'active'}];
 await w.vpnLoadBackends();
 const opener = d.querySelector('[data-action="vpn-delete-backend"]');
 opener.focus();
 const before = posts;
 let pending = w.vpnDeleteBackend(2);
 fakeClock.tick(80);
 d.getElementById('nexusConfirmCancelBtn').click();
 await pending;
 assert.strictEqual(posts, before, 'cancel has zero writes');
 assert.strictEqual(d.activeElement, opener, 'cancel retains its connected opener');
 reject = true;
 pending = w.vpnDeleteBackend(2);
 fakeClock.tick(80);
 d.getElementById('nexusConfirmOkBtn').click();
 await pending;
 assert.strictEqual(d.activeElement, opener, 'refusal retains its connected opener');
 console.log('TERMINAL_FOCUS_OK');
 dom.window.close();
})().catch(e => { console.error(e); process.exit(1); });
`})
	out := f.RunJSDOM(script)
	if !strings.Contains(out, "TERMINAL_FOCUS_OK") {
		t.Fatal(out)
	}
}

func TestVPNPageDirectModalFragmentsResolveVisibleOpener(t *testing.T) {
	f := NewVPNTestFixtureForPage(t, "vpn_backends")
	requireVPNNavigationRuntime(t, f)
	out := f.RunJSDOM(f.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: `
(() => {
 const d = w.document, modal = d.getElementById('addBackendModal');
 let writes = 0, scrolled = null;
 w.API.post = async () => { writes++; };
 w.HTMLElement.prototype.scrollIntoView = function() { scrolled = this; };
 const opener = d.getElementById('vpn-add-backend-btn');
 const ids = [modal.id, ...Array.from(modal.querySelectorAll('[id]'), el => el.id)];
 for (const id of ids) {
   w.history.replaceState(null, '', '/vpn/backends#' + id);
   assert.strictEqual(w.vpnApplyBackendsLanding(), 'vpn-add-backend-btn', id + ' resolves its opener');
   assert.strictEqual(scrolled, opener, id + ' positions the visible opener');
   assert.strictEqual(d.activeElement, opener, id + ' focuses its opener');
   assert(!modal.classList.contains('active'), 'fragment never opens a modal');
 }
 assert.strictEqual(writes, 0, 'fragments never write');
 console.log('DIRECT_MODAL_OK');
 dom.window.close();
})();
`}))
	if !strings.Contains(out, "DIRECT_MODAL_OK") {
		t.Fatal(out)
	}
}

func TestVPNPageHiddenTooltipPositionsVisibleFallback(t *testing.T) {
	f := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	requireVPNNavigationRuntime(t, f)
	out := f.RunJSDOM(f.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: `
(() => {
 let scrolled = null;
 w.HTMLElement.prototype.scrollIntoView = function() { scrolled = this; };
 w.history.replaceState(null, '', '/vpn/diagnostics#vpn-chart-tooltip');
 w.vpnApplyDiagnosticsAnchor();
 const heading = w.document.getElementById('vpn-traffic-performance-title');
 assert.strictEqual(scrolled, heading, 'hidden tooltip positions its visible heading');
 assert.strictEqual(w.document.activeElement, heading, 'hidden tooltip focuses the same visible heading');
 console.log('TOOLTIP_FALLBACK_OK');
 dom.window.close();
})();
`}))
	if !strings.Contains(out, "TOOLTIP_FALLBACK_OK") {
		t.Fatal(out)
	}
}

func TestVPNPageInspectUsesOnlyItsRequestedDocument(t *testing.T) {
	source := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	dest := NewVPNTestFixtureForPage(t, "vpn_backends")
	requireVPNNavigationRuntime(t, source)
	sourceScript := source.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: `
Object.defineProperty(w, 'sessionStorage', {value: shared.storage});
w.vpnNavigateToBackends = id => { shared.arrival = '/vpn/backends#' + id; };
w.vpnFocusIssueTarget({backendId: 77});
assert(shared.arrival.startsWith('/vpn/backends#vpn-inspect-'), 'Inspect carries an opaque navigation identity');
assert.match(shared.arrival, /^\/vpn\/backends#vpn-inspect-[a-f0-9]{32}$/, 'entity payload stays out of the URL');
dom.window.close();
`})
	destScript := dest.BuildJSDOMHarness(JSDOMHarnessOptions{IncludeNexusTable: true, ExtraJS: `
(async () => {
 Object.defineProperty(w, 'sessionStorage', {value: shared.storage});
 w.history.replaceState(null, '', arrival);
 let reject = true;
 w.API.get = async () => { if (reject && intended) throw Error('read refused'); return {backends: [{id: 77, server_id: 2, status: 'active', enabled: true}]}; };
 await w.vpnLoadBackends();
 if (intended) {
   assert.strictEqual(w.sessionStorage.getItem('vpn.backend-inspect.tunnel'), null, 'matching arrival takes storage before GET');
   reject = false;
   await w.vpnLoadBackends();
   assert.strictEqual(w.document.activeElement.getAttribute('data-backend-name'), '2', 'intended retry focuses tunnel 77 on distinct server 2');
   assert.strictEqual(w.location.hash, '#vpn-backends-title', 'arrival token is removed before retry/reload');
 } else {
   if (arrival === '/vpn/backends') assert.strictEqual(w.document.activeElement, w.document.body, 'bare visit leaves focus untouched');
   assert(!w.document.activeElement.hasAttribute('data-backend-name'), 'unrelated fresh document does not replay abandoned Inspect');
   assert.strictEqual(w.document.getElementById('vpn-backends-announcement').textContent, '', 'unrelated visit announces nothing');
   assert.strictEqual(w.sessionStorage.getItem('vpn.backend-inspect.tunnel'), null, 'unrelated arrival discards stale intent');
 }
 dom.window.close();
})()
`})
	payload, err := json.Marshal([]string{sourceScript, destScript})
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require('vm'); const scripts = ` + string(payload) + `;
const values = new Map();
const shared = {storage: {getItem: k => values.has(k) ? values.get(k) : null, setItem: (k,v) => values.set(k,String(v)), removeItem: k => values.delete(k)}};
function run(script, extras = {}) { return vm.runInNewContext(script, {require, module, console, process, shared, ...extras}); }
(async () => {
 run(scripts[0]);
 const arrival = shared.arrival;
 await run(scripts[1], {arrival, intended: true});
 // A second request never activates its destination (e.g. login/error document).
 run(scripts[0]);
 await run(scripts[1], {arrival: '/vpn/backends', intended: false});
 // A stale bookmark token with no stored request cannot revive it.
 await run(scripts[1], {arrival: shared.arrival, intended: false});
 // A different navigation identity also discards an abandoned request.
 run(scripts[0]);
 await run(scripts[1], {arrival: '/vpn/backends#vpn-inspect-00000000000000000000000000000000', intended: false});
 console.log('FRESH_DOCUMENT_BINDING_OK');
})().catch(e => { console.error(e); process.exit(1); });`
	out, err := execNodeScript(source.NodePath, script)
	if err != nil || !strings.Contains(string(out), "FRESH_DOCUMENT_BINDING_OK") {
		t.Fatalf("fresh-document lifecycle: %v\n%s", err, out)
	}
}
