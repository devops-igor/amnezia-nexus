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
    assert.ok(tbody.innerHTML.includes('vpnOpenAddBackendModal()'), 'add backend modal trigger button present');

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
