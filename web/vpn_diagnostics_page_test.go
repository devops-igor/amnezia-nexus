package web

// Behaviour of the VPN diagnostics document (/vpn/diagnostics), which owns
// forwarder health, the Advanced Diagnostics disclosure and the session table.
//
// These cases used to run against the single long VPN document's loader, which
// fetched the status, the configuration, the inventory and the sessions together.
// Each one is asserted here against the loader and the controls that now own it:
// the sessions cache and its stale flag, the show-all-routes toggle, the document's
// own poll and its teardown, and the delegated actions.

import (
	"strings"
	"testing"
)

// TestVPNPageDiagnosticsSessionsRecovery keeps the retired case's contract exactly: a
// failed sessions read keeps the last successful payload and flags the table stale
// instead of faking an empty list, and a later success replaces it and clears the
// flag.
func TestVPNPageDiagnosticsSessionsRecovery(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    w.Telemetry = { formatBytes: () => '0 B' };

    const healthCalls = [];
    const renderedPayloads = [];
    const realRenderSessions = w.renderSessions;
    w.renderSessions = (sessions) => { renderedPayloads.push(sessions); };
    // The loader hands the status to the health renderer, and that renderer
    // re-renders the sessions table from the cached payload. The recorder stands in
    // for the table so the assertions read the payload the operator would see; the
    // real renderer runs once at the end to prove that payload still renders.
    w.vpnRenderForwarderHealth = (status) => {
        healthCalls.push(status);
        const cached = w.eval('vpnLastSessions');
        if (cached) w.renderSessions(cached.sessions);
    };

    let sessionResponseMode = 'success1';
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: true, forwarder_available: true };
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
    await w.vpnLoadDiagnostics();
    assert.strictEqual(w.eval('vpnSessionsStale'), false, 'vpnSessionsStale is false on initial success');
    assert.ok(w.eval('vpnLastSessions'), 'vpnLastSessions is populated');
    assert.strictEqual(w.eval('vpnLastSessions.sessions[0].username'), 'alice', 'vpnLastSessions cached alice');
    assert.strictEqual(renderedPayloads.length, 1, 'the cached payload was rendered once');
    assert.strictEqual(renderedPayloads[0][0].username, 'alice', 'rendered alice');
    assert.strictEqual(healthCalls.length, 1, 'the health renderer ran for the status payload');

    // Pass 2: Network failure - stale flag set, cached sessions preserved
    sessionResponseMode = 'failure';
    await w.vpnLoadDiagnostics();
    assert.strictEqual(w.eval('vpnSessionsStale'), true, 'vpnSessionsStale is true after network failure');
    assert.ok(w.eval('vpnLastSessions'), 'vpnLastSessions still cached');
    assert.strictEqual(w.eval('vpnLastSessions.sessions[0].username'), 'alice', 'vpnLastSessions preserved alice');
    assert.strictEqual(renderedPayloads.length, 2, 'the cached payload was rendered again on failure');
    assert.strictEqual(renderedPayloads[1][0].username, 'alice', 'the renderer was handed the preserved payload, not an empty list');

    // Pass 3: Subsequent success - stale flag cleared, new sessions rendered
    sessionResponseMode = 'success2';
    await w.vpnLoadDiagnostics();
    assert.strictEqual(w.eval('vpnSessionsStale'), false, 'vpnSessionsStale is cleared to false after recovery');
    assert.strictEqual(w.eval('vpnLastSessions.sessions[0].username'), 'bob', 'vpnLastSessions updated to bob');
    assert.strictEqual(renderedPayloads[2][0].username, 'bob', 'the renderer was handed bob after recovery');

    // The payload that is in the module's own state renders into the real table,
    // which is what the operator reads.
    realRenderSessions(w.eval('vpnLastSessions.sessions'));
    const tbody = w.document.getElementById('vpn-sessions-tbody');
    assert.ok(tbody.textContent.includes('bob'), 'the cached payload renders into the session table');

    console.log('PASS_DIAGNOSTICS_SESSIONS_RECOVERY');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DIAGNOSTICS_SESSIONS_RECOVERY") {
		t.Fatalf("expected PASS_DIAGNOSTICS_SESSIONS_RECOVERY, got:\n%s", out)
	}
}

// TestVPNPageDiagnosticsToggleShowAllRoutes keeps the retired case unchanged in
// substance: the toggle flips its own state, re-renders health only when a status
// with an available forwarder is held, and renames its own control.
func TestVPNPageDiagnosticsToggleShowAllRoutes(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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
    assert.ok(btn && btn.textContent.length > 0, 'the toggle names its own state');

    console.log('PASS_DIAGNOSTICS_SHOW_ALL_ROUTES');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DIAGNOSTICS_SHOW_ALL_ROUTES") {
		t.Fatalf("expected PASS_DIAGNOSTICS_SHOW_ALL_ROUTES, got:\n%s", out)
	}
}

// TestVPNPageDiagnosticsPollingAndTeardown is the diagnostics half of the retired
// polling case, and the only half that can keep the teardown assertion: this is the
// document that exposes vpnStopPolling, and it stops its own stream.
func TestVPNPageDiagnosticsPollingAndTeardown(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
assert.strictEqual(typeof w.vpnLoadDiagnostics, 'function', 'vpnLoadDiagnostics exported on window');
assert.strictEqual(typeof w.vpnToggleShowAllRoutes, 'function', 'vpnToggleShowAllRoutes exported on window');
assert.strictEqual(typeof w.vpnStopPolling, 'function', 'vpnStopPolling exported on window');

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
assert.ok(w.NexusTelemetry && typeof w.NexusTelemetry.stop === 'function', 'real NexusTelemetry.stop available');

const apiCalls = [];
w.API = {
    get: async (ep) => {
        apiCalls.push(ep);
        if (ep === '/api/vpn/status') return { listener_running: true, connected_sessions: 3, forwarder_available: true };
        if (ep === '/api/vpn/sessions') return { sessions: [] };
        return {};
    }
};

(async () => {
    await new Promise(resolve => w.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 20; i++) await Promise.resolve();

    assert.ok(apiCalls.includes('/api/vpn/status'), 'initial vpn-status poll executed on DOMContentLoaded');
    assert.ok(apiCalls.includes('/api/vpn/sessions'), 'initial sessions read executed on DOMContentLoaded');
    for (const foreign of ['/api/vpn/config', '/api/vpn/backends', '/api/servers']) {
        assert.ok(!apiCalls.includes(foreign), 'the diagnostics document must not read ' + foreign);
    }

    const activeStreams = w.NexusTelemetry.getActiveStreams();
    assert.ok(activeStreams.includes('vpn-diagnostics'), 'vpn-diagnostics actively registered in NexusTelemetry');

    const scheduledIntervals = Array.from(timers.values()).map(t => t.ms);
    assert.ok(scheduledIntervals.includes(5000), '5000ms polling cadence scheduled: ' + JSON.stringify(scheduledIntervals));

    // Teardown: the document's own stop unregisters its stream and clears timers.
    w.vpnStopPolling();
    assert.ok(!w.NexusTelemetry.getActiveStreams().includes('vpn-diagnostics'), 'vpn-diagnostics unregistered after vpnStopPolling');
    assert.strictEqual(timers.size, 0, 'scheduled timer cleared after vpnStopPolling');

    const callsBefore = apiCalls.length;
    for (let i = 0; i < 10; i++) await Promise.resolve();
    assert.strictEqual(apiCalls.length, callsBefore, 'no subsequent poll invocations after stop');

    dom.window.close();
    console.log('PASS_DIAGNOSTICS_POLLING');
})().catch(e => {
    console.error(e);
    if (dom && dom.window) dom.window.close();
    process.exit(1);
});
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DIAGNOSTICS_POLLING") {
		t.Fatalf("expected PASS_DIAGNOSTICS_POLLING, got:\n%s", out)
	}
}

// TestVPNPageDiagnosticsDelegatedListeners is the diagnostics share of the retired
// all-in-one delegation case: the problems-only filter, the show-all-routes toggle,
// the three history windows and the session drilldown, all through the document's
// own delegated handler.
func TestVPNPageDiagnosticsDelegatedListeners(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	fixture.RequireJSDOM()

	for _, attr := range []string{"onclick=", "onchange=", "onsubmit="} {
		if strings.Contains(fixture.TemplateHTML, attr) {
			t.Fatalf("expected vpn_diagnostics.html to contain 0 %s attributes, found at least one", attr)
		}
	}

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');

    let sessionsProblemFilterToggled = 0;
    let showAllRoutesToggled = 0;
    const historyWindowsCalled = [];
    let sessionToggledId = null;
    let sessionToggledTr = null;

    w.vpnToggleSessionsProblemFilter = () => { sessionsProblemFilterToggled++; };
    w.vpnToggleShowAllRoutes = () => { showAllRoutesToggled++; };
    w.vpnSetHistoryWindow = (win) => { historyWindowsCalled.push(win); };
    w.vpnToggleSessionDrilldown = (sessId, tr) => { sessionToggledId = sessId; sessionToggledTr = tr; };

    // 1. Problems-only filter.
    const toggleProblemsBtn = w.document.getElementById('vpn-sessions-toggle-problems-btn');
    assert.ok(toggleProblemsBtn, '#vpn-sessions-toggle-problems-btn must exist');
    toggleProblemsBtn.click();
    assert.strictEqual(sessionsProblemFilterToggled, 1, 'vpnToggleSessionsProblemFilter called on click');

    // 2. Show-all-routes toggle, reached through the delegated handler.
    const toggleRoutesBtn = w.document.getElementById('vpn-routes-toggle-all-btn');
    assert.ok(toggleRoutesBtn, '#vpn-routes-toggle-all-btn must exist');
    const routesEvt = new w.MouseEvent('click', { bubbles: true, cancelable: true });
    toggleRoutesBtn.dispatchEvent(routesEvt);
    assert.strictEqual(showAllRoutesToggled, 1, 'vpnToggleShowAllRoutes called on click');
    assert.strictEqual(routesEvt.defaultPrevented, true, 'show-all-routes click default prevented');

    // 3. History window chips, with the value each names.
    const togglesContainer = w.document.getElementById('vpn-history-window-toggles');
    assert.ok(togglesContainer, '#vpn-history-window-toggles must exist');
    const chips = Array.from(togglesContainer.querySelectorAll('button[data-action="vpn-set-history-window"]'));
    assert.strictEqual(chips.length, 3, 'expected 3 history window chips (15m/1h/24h)');
    for (const chip of chips) {
        chip.click();
    }
    assert.deepStrictEqual(historyWindowsCalled, ['15m', '1h', '24h'], 'history window chips called with correct values');
    chips.forEach(chip => {
        assert.ok(chip.getAttribute('aria-pressed') === 'true' || chip.getAttribute('aria-pressed') === 'false', 'range chip exposes aria-pressed');
    });

    // 4. The session row's drilldown, rendered into the live table.
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

    // 5. A foreign data-action does NOT prevent default.
    const foreignLink = w.document.createElement('a');
    foreignLink.href = '#other';
    foreignLink.setAttribute('data-action', 'foreign-feature-action');
    w.document.body.appendChild(foreignLink);
    const foreignEvt = new w.MouseEvent('click', { bubbles: true, cancelable: true });
    foreignLink.dispatchEvent(foreignEvt);
    assert.strictEqual(foreignEvt.defaultPrevented, false, 'unrecognized data-action must not prevent default');

    // 6. No inline handler anywhere in the rendered document.
    const inlineHandlerEls = w.document.querySelectorAll('[onclick],[onchange],[onsubmit]');
    assert.strictEqual(inlineHandlerEls.length, 0, 'no inline on* attributes allowed in DOM');

    console.log('PASS_DIAGNOSTICS_DELEGATION');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DIAGNOSTICS_DELEGATION") {
		t.Fatalf("expected PASS_DIAGNOSTICS_DELEGATION, got:\n%s", out)
	}
}
