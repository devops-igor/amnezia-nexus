package web

// Behaviour of the VPN backends document (/vpn/backends), which owns the backend
// inventory, its row actions and the add-backend dialog.
//
// The inventory used to be rendered by the single long VPN document. It now has its
// own document, its own loader and its own table, so the cases that asserted it
// through the shared loader assert it here instead - including the parts that used
// to be side effects of that shared load (the table instance, the row delegation and
// the server-name precache).

import (
	"strings"
	"testing"
)

// TestVPNPageBackendsEmptyAndErrorFallback is the inventory's half of the retired
// single-document fallback case, asserted against the loader that now owns it.
func TestVPNPageBackendsEmptyAndErrorFallback(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    // 1. An empty inventory renders the empty state, with the same delegated Add
    //    action the persistent button uses and no inline handler.
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/backends') return { backends: [] };
            return {};
        }
    };

    await w.vpnLoadBackends();
    const tbody = w.document.getElementById('vpn-backends-tbody');
    assert.ok(tbody.innerHTML.includes('empty-state'), 'empty-state container rendered');
    assert.ok(tbody.innerHTML.includes('data-action="vpn-open-add-backend"'), 'add backend modal trigger button present');
    assert.strictEqual(tbody.innerHTML.includes('onclick='), false, 'empty-state CTA must not use inline onclick');

    // 2. A rejected read enters the error fallback without throwing, and says so in
    //    the table instead of leaving the previous rows in place.
    w.API = {
        get: async () => { throw new Error('Network failure simulation'); }
    };

    await w.vpnLoadBackends();

    assert.ok(tbody.querySelector('tr.table-empty-state'), 'error row rendered in table');
    assert.strictEqual(tbody.querySelector('td').colSpan, 6, 'error row spans 6 columns');

    console.log('PASS_BACKENDS_EMPTY_AND_ERROR');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_BACKENDS_EMPTY_AND_ERROR") {
		t.Fatalf("expected PASS_BACKENDS_EMPTY_AND_ERROR, got:\n%s", out)
	}
}

// TestVPNPageBackendsSecondLoadRefreshesTable keeps the retired case's last assertion:
// a second read refreshes the existing table instead of rebuilding it.
func TestVPNPageBackendsSecondLoadRefreshesTable(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let tableConstructed = 0;
    let tableRefreshed = 0;
    w.NexusTable = function (selector, options) {
        tableConstructed++;
        this.selector = selector;
        this.options = options;
        this.refresh = () => { tableRefreshed++; };
    };

    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/backends') {
                return {
                    backends: [
                        { server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active', latency_ms: 15 }
                    ]
                };
            }
            return {};
        }
    };

    await w.vpnLoadBackends();
    assert.strictEqual(tableConstructed, 1, 'NexusTable constructed on the first render');
    const firstRefresh = tableRefreshed;

    await w.vpnLoadBackends();
    assert.strictEqual(tableConstructed, 1, 'NexusTable not reconstructed on the second load');
    assert.strictEqual(tableRefreshed, firstRefresh + 1, 'the second load refreshed the existing table once');

    console.log('PASS_BACKENDS_TABLE_REUSE');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_BACKENDS_TABLE_REUSE") {
		t.Fatalf("expected PASS_BACKENDS_TABLE_REUSE, got:\n%s", out)
	}
}

// TestVPNPageBackendsPollingAndServerPrecache is the backends half of the retired
// polling case on the merged page: reaching the section starts the inventory poll
// and the one-off server read its rows are named from, and a second reach starts
// neither again.
func TestVPNPageBackendsPollingAndServerPrecache(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
assert.strictEqual(typeof w.vpnLoadBackends, 'function', 'vpnLoadBackends exported on window');

const timers = new Map();
let timerSeq = 0;
w.setTimeout = (fn, ms) => {
    const id = ++timerSeq;
    timers.set(id, { fn, ms });
    return id;
};
w.clearTimeout = (id) => { timers.delete(id); };

const candidatePaths = ['static/js/telemetry.js', 'web/static/js/telemetry.js'];
let telemetryCode = '';
for (const cp of candidatePaths) {
    if (fs.existsSync(cp)) { telemetryCode = fs.readFileSync(cp, 'utf8'); break; }
}
if (!telemetryCode) { throw new Error('telemetry.js not found in candidate paths'); }
const sTel = w.document.createElement('script');
sTel.textContent = telemetryCode;
w.document.body.appendChild(sTel);

assert.ok(w.NexusTelemetry && typeof w.NexusTelemetry.poll === 'function', 'real NexusTelemetry.poll available');

const apiCalls = [];
w.API = {
    get: async (ep) => {
        apiCalls.push(ep);
        if (ep === '/api/servers') return [{ server_id: 1, name: 'primary' }];
        if (ep === '/api/vpn/backends') return { backends: [] };
        if (ep === '/api/vpn/status') return { forwarder_available: true };
        if (ep === '/api/vpn/config') return {};
        return {};
    }
};

(async () => {
    await new Promise(resolve => w.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 20; i++) await Promise.resolve();

    // The inventory is not in the first viewport, so nothing reads it yet.
    assert.ok(!apiCalls.includes('/api/vpn/backends'),
        'an unreached inventory must not be read: ' + JSON.stringify(apiCalls));
    assert.ok(!apiCalls.includes('/api/servers'),
        'the row names are not pre-read for a section nobody has reached: ' + JSON.stringify(apiCalls));
    assert.ok(!w.NexusTelemetry.getActiveStreams().includes('vpn-backends'),
        'an unreached section starts no stream');

    // A jump (or the observer) reaches the section. Activation loads the section's
    // controllers first, so it returns a promise and the test awaits the work it
    // asked for instead of guessing at a number of microtask turns.
    await w.vpnMountSection('backends');
    for (let i = 0; i < 20; i++) await Promise.resolve();

    assert.ok(apiCalls.includes('/api/servers'), 'the reached section pre-reads the server names');
    assert.ok(apiCalls.includes('/api/vpn/backends'), 'the reached section reads its inventory');
    assert.ok(w.NexusTelemetry.getActiveStreams().includes('vpn-backends'),
        'vpn-backends is registered once the section is reached');

    // Reaching it again (a second jump, a fragment, a Back) starts nothing new.
    await w.vpnMountSection('backends');
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.strictEqual(apiCalls.filter(c => c === '/api/vpn/backends').length, 1,
        'a second reach does not start a second inventory read: ' + JSON.stringify(apiCalls));
    assert.strictEqual(apiCalls.filter(c => c === '/api/servers').length, 1,
        'the server list is read once, not on every reach: ' + JSON.stringify(apiCalls));

    const scheduledIntervals = Array.from(timers.values()).map(t => t.ms);
    assert.ok(scheduledIntervals.includes(5000), '5000ms polling cadence scheduled: ' + JSON.stringify(scheduledIntervals));

    // The inventory section owns no status loop.
    assert.strictEqual(apiCalls.filter(c => c === '/api/vpn/status').length, 1,
        'the status is read once per tick by the page boot, not by the section: ' + JSON.stringify(apiCalls));

    dom.window.close();
    console.log('PASS_BACKENDS_POLLING');
})().catch(e => {
    console.error(e);
    if (dom && dom.window) dom.window.close();
    process.exit(1);
});
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_BACKENDS_POLLING") {
		t.Fatalf("expected PASS_BACKENDS_POLLING, got:\n%s", out)
	}
}

// TestVPNPageBackendsDelegatedListeners is the inventory's share of the retired
// all-in-one delegation case: the add dialog's open controls (button, child icon
// and empty-state CTA), its two close controls, its form and server select, the
// quick check, and the row actions rendered into the table.
func TestVPNPageBackendsDelegatedListeners(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	for _, attr := range []string{"onclick=", "onchange=", "onsubmit="} {
		if strings.Contains(fixture.TemplateHTML, attr) {
			t.Fatalf("expected vpn.html to contain 0 %s attributes, found at least one", attr)
		}
	}

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');

    let addBackendModalOpened = 0;
    let quickCheckTriggered = 0;
    let addBackendSubmitted = 0;
    let serverSelectedCalls = 0;
    const modalsClosed = [];

    w.vpnOpenAddBackendModal = () => { addBackendModalOpened++; };
    w.vpnTriggerQuickCheck = () => { quickCheckTriggered++; };
    w.vpnSubmitAddBackend = () => { addBackendSubmitted++; };
    w.vpnOnServerSelected = () => { serverSelectedCalls++; };
    w.closeModal = (modalId) => { modalsClosed.push(modalId); };

    // 1. The add control, including a click on its child icon.
    const addBackendBtn = w.document.getElementById('vpn-add-backend-btn');
    assert.ok(addBackendBtn, '#vpn-add-backend-btn must exist');
    const addIcon = addBackendBtn.querySelector('svg') || addBackendBtn;
    addIcon.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true }));
    assert.strictEqual(addBackendModalOpened, 1, 'vpnOpenAddBackendModal called on child icon click');

    // 1b. The empty-state CTA uses the same delegated action.
    const emptyCtaContainer = w.document.createElement('div');
    emptyCtaContainer.innerHTML = '<button type="button" class="btn btn-primary btn-sm" data-action="vpn-open-add-backend"><span>Add</span></button>';
    w.document.body.appendChild(emptyCtaContainer);
    const emptyCtaBtn = emptyCtaContainer.querySelector('button[data-action="vpn-open-add-backend"]');
    emptyCtaBtn.click();
    assert.strictEqual(addBackendModalOpened, 2, 'vpnOpenAddBackendModal called on empty-state CTA click');

    // 2. The dialog's two close controls.
    const addBackendModal = w.document.getElementById('addBackendModal');
    assert.ok(addBackendModal, '#addBackendModal must exist');
    const addModalCloseBtns = Array.from(addBackendModal.querySelectorAll('button[data-action="vpn-close-modal"]'));
    assert.strictEqual(addModalCloseBtns.length, 2, 'expected 2 close buttons in addBackendModal');
    for (const btn of addModalCloseBtns) {
        btn.click();
    }
    assert.deepStrictEqual(modalsClosed, ['addBackendModal', 'addBackendModal'], 'addBackendModal closed twice');

    // 3. Quick check.
    const quickCheckBtn = w.document.getElementById('vpnQuickCheckBtn');
    assert.ok(quickCheckBtn, '#vpnQuickCheckBtn must exist');
    quickCheckBtn.click();
    assert.strictEqual(quickCheckTriggered, 1, 'vpnTriggerQuickCheck called on click');

    // 4. The add form, and the server select it contains: both are reached through
    //    the document's own listeners, and both must survive a re-render.
    const addBackendForm = w.document.getElementById('addBackendForm');
    assert.ok(addBackendForm, '#addBackendForm must exist');
    const addEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    addBackendForm.dispatchEvent(addEvt);
    assert.strictEqual(addBackendSubmitted, 1, 'vpnSubmitAddBackend called on submit');
    assert.strictEqual(addEvt.defaultPrevented, true, 'addBackendForm submit default prevented');

    // The select is asserted while it is still in the document: it is the form's
    // child, so replacing the form removes it.
    const serverSelect = w.document.getElementById('vpnServerSelect');
    assert.ok(serverSelect, '#vpnServerSelect must exist');
    serverSelect.dispatchEvent(new w.Event('change', { bubbles: true }));
    assert.strictEqual(serverSelectedCalls, 1, 'vpnOnServerSelected called on change');

    // 5. The same form replaced in place: the delegated listener must survive it.
    const replacementAddForm = w.document.createElement('form');
    replacementAddForm.id = 'addBackendForm';
    addBackendForm.parentNode.replaceChild(replacementAddForm, addBackendForm);
    const replSubmitEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    replacementAddForm.dispatchEvent(replSubmitEvt);
    assert.strictEqual(addBackendSubmitted, 2, 'vpnSubmitAddBackend called on replaced form submit');
    assert.strictEqual(replSubmitEvt.defaultPrevented, true, 'replaced addBackendForm submit default prevented');

    // A select that replaces the first one, or a fresh one when the replacement form
    // took the original with it, is still handled.
    let replacementSelect = w.document.getElementById('vpnServerSelect');
    if (replacementSelect && replacementSelect.parentNode) {
        const fresh = w.document.createElement('select');
        fresh.id = 'vpnServerSelect';
        replacementSelect.parentNode.replaceChild(fresh, replacementSelect);
        replacementSelect = fresh;
    } else {
        replacementSelect = w.document.createElement('select');
        replacementSelect.id = 'vpnServerSelect';
        w.document.body.appendChild(replacementSelect);
    }
    replacementSelect.dispatchEvent(new w.Event('change', { bubbles: true }));
    assert.strictEqual(serverSelectedCalls, 2, 'vpnOnServerSelected called on a replaced select');

    // 6. Row actions rendered into the live table.
    const backendToggles = [];
    const backendDeletes = [];
    w.vpnToggleBackend = (srvId, action) => { backendToggles.push({ srvId: String(srvId), action }); };
    w.vpnDeleteBackend = (srvId) => { backendDeletes.push(String(srvId)); };
    w.vpnCachedServers = [
        { id: 101, name: 'Server 101' },
        { id: 102, name: 'Server 102' }
    ];

    const backendRow1 = w.vpnRenderBackendRow({ server_id: 101, enabled: false, status: 'disabled' });
    const backendsTbody = w.document.getElementById('vpn-backends-tbody');
    assert.ok(backendsTbody, '#vpn-backends-tbody must exist');
    backendsTbody.appendChild(backendRow1);
    const backendRow2 = w.vpnRenderBackendRow({ server_id: 102, enabled: true, status: 'running' });
    backendsTbody.appendChild(backendRow2);

    const toggleBackendBtn1 = backendRow1.querySelector('[data-action="vpn-toggle-backend"]');
    assert.ok(toggleBackendBtn1, 'backendRow1 must contain data-action="vpn-toggle-backend" button');
    toggleBackendBtn1.click();
    assert.deepStrictEqual(backendToggles[0], { srvId: '101', action: 'enable' }, 'vpnToggleBackend enable dispatched from real row 1');

    const toggleBackendBtn2 = backendRow2.querySelector('[data-action="vpn-toggle-backend"]');
    assert.ok(toggleBackendBtn2, 'backendRow2 must contain data-action="vpn-toggle-backend" button');
    toggleBackendBtn2.click();
    assert.deepStrictEqual(backendToggles[1], { srvId: '102', action: 'disable' }, 'vpnToggleBackend disable dispatched from real row 2');

    const deleteBackendBtn = backendRow2.querySelector('[data-action="vpn-delete-backend"]');
    assert.ok(deleteBackendBtn, 'backendRow2 must contain data-action="vpn-delete-backend" button');
    const deleteIcon = deleteBackendBtn.querySelector('svg') || deleteBackendBtn;
    deleteIcon.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true }));
    assert.deepStrictEqual(backendDeletes, ['102'], 'vpnDeleteBackend dispatched from real row 2 delete button');

    // 6. A foreign data-action does NOT prevent default.
    const foreignLink = w.document.createElement('a');
    foreignLink.href = '#other';
    foreignLink.setAttribute('data-action', 'foreign-feature-action');
    w.document.body.appendChild(foreignLink);
    const foreignEvt = new w.MouseEvent('click', { bubbles: true, cancelable: true });
    foreignLink.dispatchEvent(foreignEvt);
    assert.strictEqual(foreignEvt.defaultPrevented, false, 'unrecognized data-action must not prevent default');

    // 7. No inline handler anywhere in the rendered document.
    const inlineHandlerEls = w.document.querySelectorAll('[onclick],[onchange],[onsubmit]');
    assert.strictEqual(inlineHandlerEls.length, 0, 'no inline on* attributes allowed in DOM');

    console.log('PASS_BACKENDS_DELEGATION');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_BACKENDS_DELEGATION") {
		t.Fatalf("expected PASS_BACKENDS_DELEGATION, got:\n%s", out)
	}
}
