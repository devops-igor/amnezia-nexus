package web

import (
	"strings"
	"testing"
)

func TestVPNPageLoadDataSuccessAndState(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    const apiCalls = [];
    let forwarderStatus = undefined;
    let sessionsRendered = undefined;
    let tableConstructed = 0;
    let tableRefreshed = 0;

    let parallelInitiated = false;
    const inFlight = new Set();
    let releaseBarrier;
    const barrier = new Promise(resolve => { releaseBarrier = resolve; });
    let firstLoad = true;

    w.API = {
        get: async (endpoint) => {
            apiCalls.push(endpoint);
            if (firstLoad) {
                inFlight.add(endpoint);
                if (['/api/vpn/status', '/api/vpn/config', '/api/vpn/backends', '/api/vpn/sessions'].every(ep => inFlight.has(ep))) {
                    parallelInitiated = true;
                    releaseBarrier();
                }
                await barrier;
            }
            if (endpoint === '/api/vpn/status') {
                return {
                    listener_running: true,
                    connected_sessions: 12,
                    active_tunnels: 3,
                    rx_bytes: 1048576,
                    tx_bytes: 2097152,
                    public_endpoint: 'auto.example.com:51820',
                    forwarder_available: true
                };
            }
            if (endpoint === '/api/vpn/config') {
                return {
                    listen_port: 51820,
                    subnet_cidr: '198.51.100.0/24',
                    public_endpoint: '  vpn.custom.org:51820  '
                };
            }
            if (endpoint === '/api/vpn/backends') {
                return {
                    backends: [
                        { server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active', latency_ms: 15 }
                    ]
                };
            }
            if (endpoint === '/api/vpn/sessions') {
                return {
                    sessions: [
                        { id: 'sess-1', user_id: 'u-1', username: 'alice', status: 'connected' }
                    ]
                };
            }
            return {};
        }
    };

    w.Telemetry = {
        formatBytes: (bytes) => bytes + ' B'
    };

    w.vpnRenderForwarderHealth = (status) => {
        forwarderStatus = status;
    };

    w.renderSessions = (sessions) => {
        sessionsRendered = sessions;
    };

    w.NexusTable = function (selector, options) {
        tableConstructed++;
        this.selector = selector;
        this.options = options;
        this.refresh = () => { tableRefreshed++; };
    };

    // Execute real vpnLoadData()
    await w.vpnLoadData();

    // 1. Parallel data fetching assertions: all 4 endpoints initiated concurrently before settlement
    assert.strictEqual(parallelInitiated, true, 'all 4 endpoints initiated in parallel before settlement');
    for (const ep of ['/api/vpn/status', '/api/vpn/config', '/api/vpn/backends', '/api/vpn/sessions']) {
        assert.ok(apiCalls.includes(ep), 'endpoint fetched: ' + ep);
    }

    // 2. Listener badge and configured public endpoint
    const badge = w.document.getElementById('vpn-listener-badge');
    assert.ok(badge, 'vpn-listener-badge element exists');
    assert.ok(badge.className.includes('badge-success'), 'badge has badge-success class');

    const epElem = w.document.getElementById('vpn-public-endpoint');
    assert.strictEqual(epElem.textContent, 'vpn.custom.org:51820', 'public endpoint is trimmed');

    // 3. Counter and statistics rendering
    assert.strictEqual(w.document.getElementById('vpn-listen-port').textContent, '51820', 'port rendered');
    assert.strictEqual(w.document.getElementById('vpn-subnet').textContent, '198.51.100.0/24', 'subnet rendered');
    assert.strictEqual(w.document.getElementById('vpn-sessions').textContent, '12', 'sessions counter rendered');
    assert.strictEqual(w.document.getElementById('vpn-active-tunnels').textContent, '3', 'active tunnels rendered');
    assert.strictEqual(w.document.getElementById('vpn-rx').textContent, '1048576 B', 'rx bytes rendered');
    assert.strictEqual(w.document.getElementById('vpn-tx').textContent, '2097152 B', 'tx bytes rendered');

    // 4. Delegated sub-component invocations
    assert.ok(forwarderStatus && forwarderStatus.forwarder_available === true, 'forwarder health called with status');
    assert.strictEqual(tableConstructed, 1, 'NexusTable constructed once');
    assert.strictEqual(sessionsRendered.length, 1, 'sessions rendered');
    assert.strictEqual(sessionsRendered[0].username, 'alice', 'session username passed');

    // 5. Subsequent load refreshes table without reconstructing
    firstLoad = false;
    await w.vpnLoadData();
    assert.strictEqual(tableConstructed, 1, 'NexusTable not reconstructed on second load');
    assert.strictEqual(tableRefreshed, 1, 'NexusTable refreshed on second load');

    console.log('PASS_PAGE_LOAD_DATA_SUCCESS');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_PAGE_LOAD_DATA_SUCCESS") {
		t.Fatalf("expected PASS_PAGE_LOAD_DATA_SUCCESS, got:\n%s", out)
	}
}

func TestVPNPageLoadDataConfigFailureFallback(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let forwarderStatus = undefined;
    let renderedSessionsList = null;
    w.Telemetry = { formatBytes: () => '0 B' };
    w.vpnRenderForwarderHealth = (st) => { forwarderStatus = st; };
    w.renderSessions = (sess) => { renderedSessionsList = sess; };
    w.NexusTable = function () { this.refresh = () => {}; };

    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') {
                return {
                    listener_running: true,
                    connected_sessions: 12,
                    active_tunnels: 3,
                    rx_bytes: 1048576,
                    tx_bytes: 2097152,
                    public_endpoint: 'auto.example.com:51820',
                    forwarder_available: true
                };
            }
            if (ep === '/api/vpn/config') {
                throw new Error('Simulated config endpoint failure');
            }
            if (ep === '/api/vpn/backends') {
                return {
                    backends: [
                        { server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active', latency_ms: 15 }
                    ]
                };
            }
            if (ep === '/api/vpn/sessions') {
                return {
                    sessions: [
                        { id: 'sess-1', user_id: 'u-1', username: 'alice', status: 'connected' }
                    ]
                };
            }
            return {};
        }
    };

    // Execute vpnLoadData() - config rejection must NOT throw or trigger outer catch
    await w.vpnLoadData();

    // Assert config values fell back to default '-'
    assert.strictEqual(w.document.getElementById('vpn-listen-port').textContent, '-', 'listen port fallback to -');
    assert.strictEqual(w.document.getElementById('vpn-subnet').textContent, '-', 'subnet fallback to -');

    // Assert status, forwarder health, backends, and sessions rendered normally
    assert.strictEqual(w.document.getElementById('vpn-sessions').textContent, '12', 'sessions counter rendered');
    assert.ok(forwarderStatus && forwarderStatus.forwarder_available === true, 'forwarder health called with status');
    assert.ok(renderedSessionsList && renderedSessionsList.length === 1, 'sessions rendered despite config failure');
    assert.strictEqual(renderedSessionsList[0].username, 'alice', 'session payload preserved');

    const tbody = w.document.getElementById('vpn-backends-tbody');
    assert.ok(!tbody.innerHTML.includes('table-empty-state'), 'backends table rendered rows, not error row');

    console.log('PASS_CONFIG_FAILURE_FALLBACK');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_CONFIG_FAILURE_FALLBACK") {
		t.Fatalf("expected PASS_CONFIG_FAILURE_FALLBACK, got:\n%s", out)
	}
}

func TestVPNPageSessionsRecovery(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let sessionsRendered = null;
    w.Telemetry = { formatBytes: () => '0 B' };
    w.vpnRenderForwarderHealth = () => {};
    w.renderSessions = (s) => { sessionsRendered = s; };
    w.NexusTable = function () { this.refresh = () => {}; };

    let sessionResponseMode = 'success1';

    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: true };
            if (ep === '/api/vpn/config') return {};
            if (ep === '/api/vpn/backends') return { backends: [] };
            if (ep === '/api/vpn/sessions') {
                if (sessionResponseMode === 'success1') {
                    return { sessions: [{ id: 'sess-1', user_id: 'u-1', username: 'alice', status: 'connected' }] };
                }
                if (sessionResponseMode === 'failure') {
                    throw new Error('Simulated network failure on sessions endpoint');
                }
                if (sessionResponseMode === 'success2') {
                    return { sessions: [{ id: 'sess-2', user_id: 'u-2', username: 'bob', status: 'connected' }] };
                }
            }
            return {};
        }
    };

    // Pass 1: Initial success
    sessionResponseMode = 'success1';
    await w.vpnLoadData();
    assert.strictEqual(w.eval('vpnSessionsStale'), false, 'vpnSessionsStale is false on initial success');
    assert.ok(w.eval('vpnLastSessions'), 'vpnLastSessions is populated');
    assert.strictEqual(w.eval('vpnLastSessions.sessions[0].username'), 'alice', 'vpnLastSessions cached alice');
    assert.strictEqual(sessionsRendered.length, 1, 'sessionsRendered has 1 session');
    assert.strictEqual(sessionsRendered[0].username, 'alice', 'rendered alice');

    // Pass 2: Network failure - stale flag set, cached sessions preserved
    sessionResponseMode = 'failure';
    await w.vpnLoadData();
    assert.strictEqual(w.eval('vpnSessionsStale'), true, 'vpnSessionsStale is true after network failure');
    assert.ok(w.eval('vpnLastSessions'), 'vpnLastSessions still cached');
    assert.strictEqual(w.eval('vpnLastSessions.sessions[0].username'), 'alice', 'vpnLastSessions preserved alice');
    assert.strictEqual(sessionsRendered.length, 1, 'sessionsRendered preserved cached session count');
    assert.strictEqual(sessionsRendered[0].username, 'alice', 'sessionsRendered preserved alice on failure');

    // Pass 3: Subsequent success - stale flag cleared, new sessions rendered
    sessionResponseMode = 'success2';
    await w.vpnLoadData();
    assert.strictEqual(w.eval('vpnSessionsStale'), false, 'vpnSessionsStale is cleared to false after recovery');
    assert.strictEqual(w.eval('vpnLastSessions.sessions[0].username'), 'bob', 'vpnLastSessions updated to bob');
    assert.strictEqual(sessionsRendered.length, 1, 'sessionsRendered updated');
    assert.strictEqual(sessionsRendered[0].username, 'bob', 'sessionsRendered bob after recovery');

    console.log('PASS_SESSIONS_RECOVERY');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_SESSIONS_RECOVERY") {
		t.Fatalf("expected PASS_SESSIONS_RECOVERY, got:\n%s", out)
	}
}

func TestVPNPageLoadDataEndpointFallbacks(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    w.Telemetry = { formatBytes: () => '0 B' };
    w.vpnRenderForwarderHealth = () => {};
    w.renderSessions = () => {};
    w.NexusTable = function () { this.refresh = () => {}; };

    // Case A: No configured endpoint, status has auto-detected endpoint
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: true, public_endpoint: '198.51.100.99:51820' };
            if (ep === '/api/vpn/config') return { public_endpoint: '' };
            return {};
        }
    };
    await w.vpnLoadData();
    const epElem = w.document.getElementById('vpn-public-endpoint');
    assert.ok(epElem.textContent.includes('198.51.100.99:51820'), 'auto-detected fallback endpoint rendered: ' + epElem.textContent);

    // Case B: Neither configured nor auto-detected
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: false };
            if (ep === '/api/vpn/config') return { public_endpoint: '' };
            return {};
        }
    };
    await w.vpnLoadData();
    assert.ok(epElem.textContent.length > 0, 'fallback placeholder text rendered');

    console.log('PASS_ENDPOINT_FALLBACKS');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_ENDPOINT_FALLBACKS") {
		t.Fatalf("expected PASS_ENDPOINT_FALLBACKS, got:\n%s", out)
	}
}

func TestVPNPageLoadDataEmptyBackendsAndErrorFallback(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let forwarderStatus = undefined;
    w.Telemetry = { formatBytes: () => '0 B' };
    w.vpnRenderForwarderHealth = (st) => { forwarderStatus = st; };
    w.renderSessions = () => {};

    // 1. Empty backends renders empty state markup
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: true };
            if (ep === '/api/vpn/config') return {};
            if (ep === '/api/vpn/backends') return { backends: [] };
            if (ep === '/api/vpn/sessions') return { sessions: [] };
            return {};
        }
    };

    await w.vpnLoadData();
    const tbody = w.document.getElementById('vpn-backends-tbody');
    assert.ok(tbody.innerHTML.includes('empty-state'), 'empty-state container rendered');
    assert.ok(tbody.innerHTML.includes('data-action="vpn-open-add-backend"'), 'add backend modal trigger button present');
    assert.strictEqual(tbody.innerHTML.includes('onclick='), false, 'empty-state CTA must not use inline onclick');

    // 2. API rejection enters error fallback without throwing
    w.API = {
        get: async () => { throw new Error('Network failure simulation'); }
    };

    forwarderStatus = 'not_null';
    await w.vpnLoadData();

    assert.strictEqual(forwarderStatus, null, 'vpnRenderForwarderHealth called with null on error');
    assert.ok(tbody.querySelector('tr.table-empty-state'), 'error row rendered in table');
    assert.strictEqual(tbody.querySelector('td').colSpan, 6, 'error row spans 6 columns');

    console.log('PASS_EMPTY_AND_ERROR_FALLBACK');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_EMPTY_AND_ERROR_FALLBACK") {
		t.Fatalf("expected PASS_EMPTY_AND_ERROR_FALLBACK, got:\n%s", out)
	}
}

func TestVPNPageToggleShowAllRoutes(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');

    let forwarderRenders = 0;
    w.vpnRenderForwarderHealth = () => { forwarderRenders++; };

    // Initially false
    assert.strictEqual(w.vpnShowAllRoutes, false, 'initially false');
    const btn = w.document.getElementById('vpn-routes-toggle-all-btn');

    // Toggle 1: turns true, but vpnLastStatus is null so no forwarder render
    w.vpnLastStatus = null;
    w.vpnToggleShowAllRoutes();
    assert.strictEqual(w.vpnShowAllRoutes, true, 'toggled to true');
    assert.strictEqual(forwarderRenders, 0, 'no forwarder render when status null');

    // Toggle 2: turns false
    w.vpnToggleShowAllRoutes();
    assert.strictEqual(w.vpnShowAllRoutes, false, 'toggled to false');

    // Toggle 3: with available forwarder status, re-renders forwarder health
    w.vpnLastStatus = { forwarder_available: true };
    w.vpnToggleShowAllRoutes();
    assert.strictEqual(w.vpnShowAllRoutes, true, 'toggled to true with status');
    assert.strictEqual(forwarderRenders, 1, 'vpnRenderForwarderHealth invoked when available');

    console.log('PASS_TOGGLE_SHOW_ALL_ROUTES');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_TOGGLE_SHOW_ALL_ROUTES") {
		t.Fatalf("expected PASS_TOGGLE_SHOW_ALL_ROUTES, got:\n%s", out)
	}
}

func TestVPNPagePollingRegistrationAndTeardown(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
// 1. Export contract assertions
assert.strictEqual(typeof w.vpnLoadData, 'function', 'vpnLoadData exported on window');
assert.strictEqual(typeof w.vpnToggleShowAllRoutes, 'function', 'vpnToggleShowAllRoutes exported on window');
assert.strictEqual(typeof w.vpnStopPolling, 'function', 'vpnStopPolling exported on window');

// 2. Intercept timers to track scheduled intervals and active timeouts
const timers = new Map();
let timerSeq = 0;
w.setTimeout = (fn, ms) => {
    const id = ++timerSeq;
    timers.set(id, { fn, ms });
    return id;
};
w.clearTimeout = (id) => {
    timers.delete(id);
};

// 3. Install real NexusTelemetry engine
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
assert.ok(w.NexusTelemetry && typeof w.NexusTelemetry.stop === 'function', 'real NexusTelemetry.stop available');

const apiCalls = [];
w.API = {
    get: async (ep) => {
        apiCalls.push(ep);
        if (ep === '/api/servers') return [{ server_id: 1, name: 'primary' }];
        if (ep === '/api/vpn/status') {
            return {
                listener_running: true,
                connected_sessions: 3,
                active_tunnels: 1,
                rx_bytes: 512,
                tx_bytes: 1024,
                forwarder_available: true
            };
        }
        if (ep === '/api/vpn/config') {
            return { listen_port: 51820, subnet_cidr: '198.51.100.0/24' };
        }
        if (ep === '/api/vpn/backends') return { backends: [] };
        if (ep === '/api/vpn/sessions') return { sessions: [] };
        return {};
    }
};

(async () => {
    // Await natural readiness of DOMContentLoaded
    await new Promise(resolve => w.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    // Drain microtasks for async vpnLoadData and precache settlements
    for (let i = 0; i < 20; i++) await Promise.resolve();

    // 4. Lifecycle registration assertions
    assert.ok(apiCalls.includes('/api/servers'), 'server metadata precache initiated on DOMContentLoaded');
    assert.ok(apiCalls.includes('/api/vpn/status'), 'initial vpn-status poll executed on DOMContentLoaded');

    const activeStreams = w.NexusTelemetry.getActiveStreams();
    assert.ok(activeStreams.includes('vpn-status'), 'vpn-status actively registered in NexusTelemetry');

    // 5. Cadence verification: check 5000ms timer scheduled
    const scheduledIntervals = Array.from(timers.values()).map(t => t.ms);
    assert.ok(scheduledIntervals.includes(5000), '5000ms polling cadence scheduled: ' + JSON.stringify(scheduledIntervals));

    // 6. Teardown verification: vpnStopPolling actively unregisters stream and clears timers
    w.vpnStopPolling();
    assert.ok(!w.NexusTelemetry.getActiveStreams().includes('vpn-status'), 'vpn-status unregistered after vpnStopPolling');
    assert.strictEqual(timers.size, 0, 'scheduled timer cleared after vpnStopPolling');

    // Verify no subsequent poll invocations occur
    const callsBefore = apiCalls.length;
    for (let i = 0; i < 10; i++) await Promise.resolve();
    assert.strictEqual(apiCalls.length, callsBefore, 'no subsequent poll invocations after stop');

    dom.window.close();
    console.log('PASS_POLLING_AND_TEARDOWN');
})().catch(e => {
    console.error(e);
    if (dom && dom.window) dom.window.close();
    process.exit(1);
});
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_POLLING_AND_TEARDOWN") {
		t.Fatalf("expected PASS_POLLING_AND_TEARDOWN, got:\n%s", out)
	}
}

func TestVPNPageDelegatedEventListeners(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	// Verify template HTML has 0 inline onclick/onchange/onsubmit handlers
	for _, attr := range []string{"onclick=", "onchange=", "onsubmit="} {
		if strings.Contains(fixture.TemplateHTML, attr) {
			t.Fatalf("expected vpn.html to contain 0 %s attributes, found at least one", attr)
		}
	}

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');

    let editEndpointModalOpened = 0;
    let addBackendModalOpened = 0;
    let sessionsProblemFilterToggled = 0;
    let showAllRoutesToggled = 0;
    const historyWindowsCalled = [];
    const modalsClosed = [];
    let quickCheckTriggered = 0;
    let addBackendSubmitted = 0;
    let editEndpointSubmitted = 0;
    let serverSelectedCalls = 0;

    w.vpnOpenEditEndpointModal = () => { editEndpointModalOpened++; };
    w.vpnOpenAddBackendModal = () => { addBackendModalOpened++; };
    w.vpnToggleSessionsProblemFilter = () => { sessionsProblemFilterToggled++; };
    w.vpnToggleShowAllRoutes = () => { showAllRoutesToggled++; };
    w.vpnSetHistoryWindow = (win) => { historyWindowsCalled.push(win); };
    w.closeModal = (modalId) => { modalsClosed.push(modalId); };
    w.vpnTriggerQuickCheck = () => { quickCheckTriggered++; };
    w.vpnSubmitAddBackend = () => { addBackendSubmitted++; };
    w.vpnSubmitEditEndpoint = () => { editEndpointSubmitted++; };
    w.vpnOnServerSelected = () => { serverSelectedCalls++; };

    // 1. Modal open buttons (including child target click)
    const editEpBtn = w.document.getElementById('vpn-edit-endpoint-btn');
    assert.ok(editEpBtn, '#vpn-edit-endpoint-btn must exist');
    editEpBtn.click();
    assert.strictEqual(editEndpointModalOpened, 1, 'vpnOpenEditEndpointModal called on click');

    const addBackendBtn = w.document.getElementById('vpn-add-backend-btn');
    assert.ok(addBackendBtn, '#vpn-add-backend-btn must exist');
    const addIcon = addBackendBtn.querySelector('svg') || addBackendBtn;
    addIcon.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true }));
    assert.strictEqual(addBackendModalOpened, 1, 'vpnOpenAddBackendModal called on child icon click');

    // 1b. Empty-state CTA button click triggers vpnOpenAddBackendModal
    const emptyCtaContainer = w.document.createElement('div');
    emptyCtaContainer.innerHTML = '<button type="button" class="btn btn-primary btn-sm" data-action="vpn-open-add-backend"><span>Add</span></button>';
    w.document.body.appendChild(emptyCtaContainer);
    const emptyCtaBtn = emptyCtaContainer.querySelector('button[data-action="vpn-open-add-backend"]');
    emptyCtaBtn.click();
    assert.strictEqual(addBackendModalOpened, 2, 'vpnOpenAddBackendModal called on empty-state CTA click');

    // 2. Filter & display toggle buttons
    const toggleProblemsBtn = w.document.getElementById('vpn-sessions-toggle-problems-btn');
    assert.ok(toggleProblemsBtn, '#vpn-sessions-toggle-problems-btn must exist');
    toggleProblemsBtn.click();
    assert.strictEqual(sessionsProblemFilterToggled, 1, 'vpnToggleSessionsProblemFilter called on click');

    const toggleRoutesBtn = w.document.getElementById('vpn-routes-toggle-all-btn');
    assert.ok(toggleRoutesBtn, '#vpn-routes-toggle-all-btn must exist');
    const routesEvt = new w.MouseEvent('click', { bubbles: true, cancelable: true });
    toggleRoutesBtn.dispatchEvent(routesEvt);
    assert.strictEqual(showAllRoutesToggled, 1, 'vpnToggleShowAllRoutes called on click');
    assert.strictEqual(routesEvt.defaultPrevented, true, 'show-all-routes click default prevented');

    // 3. History window chips (6 buttons)
    const togglesContainer = w.document.getElementById('vpn-history-window-toggles');
    assert.ok(togglesContainer, '#vpn-history-window-toggles must exist');
    const chips = Array.from(togglesContainer.querySelectorAll('button[data-action="vpn-set-history-window"]'));
    assert.strictEqual(chips.length, 6, 'expected 6 history window chips');
    for (const chip of chips) {
        chip.click();
    }
    assert.deepStrictEqual(historyWindowsCalled, ['1m', '5m', '15m', '1h', '6h', '24h'], 'history window chips called with correct values');

    // 4. Modal close buttons (4 buttons across 2 modals)
    const addBackendModal = w.document.getElementById('addBackendModal');
    assert.ok(addBackendModal, '#addBackendModal must exist');
    const addModalCloseBtns = Array.from(addBackendModal.querySelectorAll('button[data-action="vpn-close-modal"]'));
    assert.strictEqual(addModalCloseBtns.length, 2, 'expected 2 close buttons in addBackendModal');
    for (const btn of addModalCloseBtns) {
        btn.click();
    }
    assert.deepStrictEqual(modalsClosed.slice(0, 2), ['addBackendModal', 'addBackendModal'], 'addBackendModal closed twice');

    const editEndpointModal = w.document.getElementById('editEndpointModal');
    assert.ok(editEndpointModal, '#editEndpointModal must exist');
    const editModalCloseBtns = Array.from(editEndpointModal.querySelectorAll('button[data-action="vpn-close-modal"]'));
    assert.strictEqual(editModalCloseBtns.length, 2, 'expected 2 close buttons in editEndpointModal');
    for (const btn of editModalCloseBtns) {
        btn.click();
    }
    assert.deepStrictEqual(modalsClosed.slice(2, 4), ['editEndpointModal', 'editEndpointModal'], 'editEndpointModal closed twice');

    // 5. Quick check button
    const quickCheckBtn = w.document.getElementById('vpnQuickCheckBtn');
    assert.ok(quickCheckBtn, '#vpnQuickCheckBtn must exist');
    quickCheckBtn.click();
    assert.strictEqual(quickCheckTriggered, 1, 'vpnTriggerQuickCheck called on click');

    // 6. Form submissions
    const addBackendForm = w.document.getElementById('addBackendForm');
    assert.ok(addBackendForm, '#addBackendForm must exist');
    const addEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    addBackendForm.dispatchEvent(addEvt);
    assert.strictEqual(addBackendSubmitted, 1, 'vpnSubmitAddBackend called on submit');
    assert.strictEqual(addEvt.defaultPrevented, true, 'addBackendForm submit default prevented');

    const editEndpointForm = w.document.getElementById('editEndpointForm');
    assert.ok(editEndpointForm, '#editEndpointForm must exist');
    const editEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    editEndpointForm.dispatchEvent(editEvt);
    assert.strictEqual(editEndpointSubmitted, 1, 'vpnSubmitEditEndpoint called on submit');
    assert.strictEqual(editEvt.defaultPrevented, true, 'editEndpointForm submit default prevented');

    // 7. Select change
    const serverSelect = w.document.getElementById('vpnServerSelect');
    assert.ok(serverSelect, '#vpnServerSelect must exist');
    serverSelect.dispatchEvent(new w.Event('change', { bubbles: true }));
    assert.strictEqual(serverSelectedCalls, 1, 'vpnOnServerSelected called on change');

    // 7b. Form & select DOM element replacement survives without reinitializing listeners
    const oldAddForm = w.document.getElementById('addBackendForm');
    const replacementAddForm = w.document.createElement('form');
    replacementAddForm.id = 'addBackendForm';
    oldAddForm.parentNode.replaceChild(replacementAddForm, oldAddForm);
    const replSubmitEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    replacementAddForm.dispatchEvent(replSubmitEvt);
    assert.strictEqual(addBackendSubmitted, 2, 'vpnSubmitAddBackend called on replaced form submit');
    assert.strictEqual(replSubmitEvt.defaultPrevented, true, 'replaced addBackendForm submit default prevented');

    const oldSelect = w.document.getElementById('vpnServerSelect');
    const replacementSelect = w.document.createElement('select');
    replacementSelect.id = 'vpnServerSelect';
    if (oldSelect && oldSelect.parentNode) {
        oldSelect.parentNode.replaceChild(replacementSelect, oldSelect);
    } else {
        w.document.body.appendChild(replacementSelect);
    }
    replacementSelect.dispatchEvent(new w.Event('change', { bubbles: true }));
    assert.strictEqual(serverSelectedCalls, 2, 'vpnOnServerSelected called on replaced select');

    // 8. Dynamically generated real-row controls delegation (vpnRenderBackendRow & vpnRenderSessionRow)
    const backendToggles = [];
    const backendDeletes = [];
    let sessionToggledId = null;
    let sessionToggledTr = null;
    w.vpnToggleBackend = (srvId, action) => { backendToggles.push({ srvId: String(srvId), action }); };
    w.vpnDeleteBackend = (srvId) => { backendDeletes.push(String(srvId)); };
    w.vpnToggleSessionDrilldown = (sessId, tr) => { sessionToggledId = sessId; sessionToggledTr = tr; };

    w.vpnCachedServers = [
        { id: 101, name: 'Server 101' },
        { id: 102, name: 'Server 102' }
    ];

    // Real backend row 1: disabled backend -> enable action
    const backendRow1 = w.vpnRenderBackendRow({ server_id: 101, enabled: false, status: 'disabled' });
    const backendsTbody = w.document.getElementById('vpn-backends-tbody');
    assert.ok(backendsTbody, '#vpn-backends-tbody must exist');
    backendsTbody.appendChild(backendRow1);

    // Real backend row 2: enabled backend -> disable action
    const backendRow2 = w.vpnRenderBackendRow({ server_id: 102, enabled: true, status: 'running' });
    backendsTbody.appendChild(backendRow2);

    // Test clicking enable on real backend row 1
    const toggleBackendBtn1 = backendRow1.querySelector('[data-action="vpn-toggle-backend"]');
    assert.ok(toggleBackendBtn1, 'backendRow1 must contain data-action="vpn-toggle-backend" button');
    toggleBackendBtn1.click();
    assert.deepStrictEqual(backendToggles[0], { srvId: '101', action: 'enable' }, 'vpnToggleBackend enable dispatched from real row 1');

    // Test clicking disable on real backend row 2
    const toggleBackendBtn2 = backendRow2.querySelector('[data-action="vpn-toggle-backend"]');
    assert.ok(toggleBackendBtn2, 'backendRow2 must contain data-action="vpn-toggle-backend" button');
    toggleBackendBtn2.click();
    assert.deepStrictEqual(backendToggles[1], { srvId: '102', action: 'disable' }, 'vpnToggleBackend disable dispatched from real row 2');

    // Test clicking delete button on real backend row 2 (child icon dispatch)
    const deleteBackendBtn = backendRow2.querySelector('[data-action="vpn-delete-backend"]');
    assert.ok(deleteBackendBtn, 'backendRow2 must contain data-action="vpn-delete-backend" button');
    const deleteIcon = deleteBackendBtn.querySelector('svg') || deleteBackendBtn;
    deleteIcon.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true }));
    assert.deepStrictEqual(backendDeletes, ['102'], 'vpnDeleteBackend dispatched from real row 2 delete button');

    // Real session row
    const sessionData = { session_id: 'sess-99', username: 'alice', server_name: 'Server 101', status: 'connected' };
    const sessionRow = w.vpnRenderSessionRow(sessionData);
    const sessionsTbody = w.document.getElementById('vpn-sessions-tbody');
    assert.ok(sessionsTbody, '#vpn-sessions-tbody must exist');
    sessionsTbody.appendChild(sessionRow);

    const toggleSessionTd = sessionRow.querySelector('[data-action="vpn-toggle-session"]');
    assert.ok(toggleSessionTd, 'sessionRow must contain cell with data-action="vpn-toggle-session"');
    toggleSessionTd.click();
    assert.strictEqual(sessionToggledId, 'sess-99', 'vpnToggleSessionDrilldown received session id from real session row');
    assert.strictEqual(sessionToggledTr, sessionRow, 'vpnToggleSessionDrilldown received tr element from real session row');

    // 9. Foreign data-action does NOT prevent default
    const foreignLink = w.document.createElement('a');
    foreignLink.href = '#other';
    foreignLink.setAttribute('data-action', 'foreign-feature-action');
    w.document.body.appendChild(foreignLink);
    const foreignEvt = new w.MouseEvent('click', { bubbles: true, cancelable: true });
    foreignLink.dispatchEvent(foreignEvt);
    assert.strictEqual(foreignEvt.defaultPrevented, false, 'unrecognized data-action must not prevent default');

    // 10. Verify no inline event attributes anywhere in document
    const inlineHandlerEls = w.document.querySelectorAll('[onclick],[onchange],[onsubmit]');
    assert.strictEqual(inlineHandlerEls.length, 0, 'no inline on* attributes allowed in DOM');

    console.log('PASS_DELEGATED_EVENT_LISTENERS');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DELEGATED_EVENT_LISTENERS") {
		t.Fatalf("expected PASS_DELEGATED_EVENT_LISTENERS, got:\n%s", out)
	}
}
