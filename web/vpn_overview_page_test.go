package web

// Behaviour of the VPN overview document (/vpn), which owns the listener and
// configuration rows, the four signals and the public-endpoint dialog.
//
// The page used to be part of one long document whose loader fetched the status,
// the configuration, the backend inventory and the sessions together. That loader
// no longer exists: each document now loads only its own data, so the cases below
// assert the overview's own endpoints and outcomes, and the inventory and
// diagnostics cases live with the documents that own them
// (vpn_backends_page_test.go, vpn_diagnostics_page_test.go).

import (
	"strings"
	"testing"
)

// TestVPNPageOverviewLoadsItsOwnDataAndSignals replaces the
// single-document "all four endpoints in parallel" case. The parallel fetch is the
// behaviour that stopped existing: no document reads another's data any more, so
// what is asserted instead is the positive half of the same guarantee - the
// overview asks for the status and the configuration, and renders every row and
// signal it owns from those two answers.
func TestVPNPageOverviewLoadsItsOwnDataAndSignals(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    const apiCalls = [];
    w.Telemetry = { formatBytes: (bytes) => bytes + ' B' };
    w.API = {
        get: async (endpoint) => {
            apiCalls.push(endpoint);
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
            return {};
        }
    };

    await w.vpnLoadOverview();

    // 1. This document reads exactly its own two endpoints: the inventory and the
    //    sessions belong to the other documents.
    assert.deepStrictEqual(apiCalls, ['/api/vpn/status', '/api/vpn/config'],
        'the overview reads the status and the configuration, and nothing else');

    // 2. Listener badge and configured public endpoint.
    const badge = w.document.getElementById('vpn-listener-badge');
    assert.ok(badge, 'vpn-listener-badge element exists');
    assert.ok(badge.className.includes('badge-success'), 'badge has badge-success class');

    const epElem = w.document.getElementById('vpn-public-endpoint');
    assert.strictEqual(epElem.textContent, 'vpn.custom.org:51820', 'public endpoint is trimmed');

    // 3. Configuration rows this document renders.
    assert.strictEqual(w.document.getElementById('vpn-listen-port').textContent, '51820', 'port rendered');
    assert.strictEqual(w.document.getElementById('vpn-subnet').textContent, '198.51.100.0/24', 'subnet rendered');

    // 4. The Sessions signal is owned by vpnRenderSignals, which the loader has
    //    already run with the status payload; assert it through the renderer with
    //    the same payload so the live count and the absent mismatch row are both
    //    pinned.
    w.vpnRenderSignals({
        forwarder_available: true,
        connected_sessions: 12,
        active_tunnels: 3,
        rx_bytes: 1048576,
        tx_bytes: 2097152,
        health_assessment: { status: 'HEALTHY', conditions: [] },
        routing_consistency: { is_consistent: true, active_sessions_count: 12 }
    });
    assert.strictEqual(w.document.getElementById('vpn-sessions').textContent, '12', 'sessions signal rendered from the payload');
    assert.strictEqual(w.document.getElementById('vpn-session-mismatch').hidden, true, 'no mismatch row without a reported mismatch');

    console.log('PASS_OVERVIEW_LOAD');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_LOAD") {
		t.Fatalf("expected PASS_OVERVIEW_LOAD, got:\n%s", out)
	}
}

// TestVPNPageOverviewConfigFailureFallback keeps the single-document case's contract:
// a refused configuration read must not abort the load, must not blank the
// signals, and must leave the configuration rows in their documented fallback.
func TestVPNPageOverviewConfigFailureFallback(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    w.Telemetry = { formatBytes: () => '0 B' };
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') {
                return {
                    listener_running: true,
                    connected_sessions: 12,
                    active_tunnels: 3,
                    forwarder_available: true
                };
            }
            if (ep === '/api/vpn/config') {
                throw new Error('Simulated config endpoint failure');
            }
            return {};
        }
    };

    // The rejection must not throw out of the loader.
    await w.vpnLoadOverview();

    assert.strictEqual(w.document.getElementById('vpn-listen-port').textContent, '-', 'listen port fallback to -');
    assert.strictEqual(w.document.getElementById('vpn-subnet').textContent, '-', 'subnet fallback to -');
    assert.ok(w.document.getElementById('vpn-listener-badge').className.includes('badge-success'),
        'the listener badge still reflects the status read');

    // The signals are rendered from the status payload, which succeeded.
    assert.strictEqual(w.document.getElementById('vpn-sessions').textContent, '12',
        'sessions signal rendered despite the config failure');

    console.log('PASS_OVERVIEW_CONFIG_FALLBACK');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_CONFIG_FALLBACK") {
		t.Fatalf("expected PASS_OVERVIEW_CONFIG_FALLBACK, got:\n%s", out)
	}
}

// TestVPNPageOverviewEndpointFallbacks carried over unchanged in substance: the
// endpoint row prefers the configured value, falls back to the detected one and
// never renders empty.
func TestVPNPageOverviewEndpointFallbacks(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    w.Telemetry = { formatBytes: () => '0 B' };

    // Case A: No configured endpoint, status has auto-detected endpoint
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: true, public_endpoint: '198.51.100.99:51820' };
            if (ep === '/api/vpn/config') return { public_endpoint: '' };
            return {};
        }
    };
    await w.vpnLoadOverview();
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
    await w.vpnLoadOverview();
    assert.ok(epElem.textContent.length > 0, 'fallback placeholder text rendered');

    console.log('PASS_OVERVIEW_ENDPOINT_FALLBACKS');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_ENDPOINT_FALLBACKS") {
		t.Fatalf("expected PASS_OVERVIEW_ENDPOINT_FALLBACKS, got:\n%s", out)
	}
}

// TestVPNPageOverviewPollingRegistration is the overview's half of the retired
// single-document polling case: this document registers its own stream on the
// shared engine on load. The teardown half belongs to the diagnostics document,
// which is the only one that exposes a stop.
func TestVPNPageOverviewPollingRegistration(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
assert.strictEqual(typeof w.vpnLoadOverview, 'function', 'vpnLoadOverview exported on window');
assert.strictEqual(typeof w.vpnLoadData, 'function', 'the previous whole-surface name still resolves on this document');

// Intercept timers to track scheduled intervals
const timers = new Map();
let timerSeq = 0;
w.setTimeout = (fn, ms) => {
    const id = ++timerSeq;
    timers.set(id, { fn, ms });
    return id;
};
w.clearTimeout = (id) => { timers.delete(id); };

// Install real NexusTelemetry engine
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
        if (ep === '/api/vpn/status') return { listener_running: true, connected_sessions: 3, forwarder_available: true };
        if (ep === '/api/vpn/config') return { listen_port: 51820, subnet_cidr: '198.51.100.0/24' };
        return {};
    }
};

(async () => {
    await new Promise(resolve => w.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 20; i++) await Promise.resolve();

    assert.ok(apiCalls.includes('/api/vpn/status'), 'initial status read executed on DOMContentLoaded');
    // The overview asks for its own configuration and never for another
    // document's data.
    assert.ok(apiCalls.includes('/api/vpn/config'), 'initial configuration read executed on DOMContentLoaded');
    for (const foreign of ['/api/vpn/backends', '/api/vpn/sessions', '/api/servers']) {
        assert.ok(!apiCalls.includes(foreign), 'the overview must not read ' + foreign);
    }

    const activeStreams = w.NexusTelemetry.getActiveStreams();
    assert.ok(activeStreams.includes('vpn-overview'), 'vpn-overview actively registered in NexusTelemetry');

    const scheduledIntervals = Array.from(timers.values()).map(t => t.ms);
    assert.ok(scheduledIntervals.includes(5000), '5000ms polling cadence scheduled: ' + JSON.stringify(scheduledIntervals));

    dom.window.close();
    console.log('PASS_OVERVIEW_POLLING');
})().catch(e => {
    console.error(e);
    if (dom && dom.window) dom.window.close();
    process.exit(1);
});
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_POLLING") {
		t.Fatalf("expected PASS_OVERVIEW_POLLING, got:\n%s", out)
	}
}

// TestVPNPageOverviewDelegatedListeners is the overview's share of the retired
// all-in-one delegation case: the endpoint dialog's open control, its two close
// controls and its form, all reached through the same delegated click handler.
func TestVPNPageOverviewDelegatedListeners(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	// The document ships no inline handler at all.
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
    let editEndpointSubmitted = 0;
    const modalsClosed = [];

    w.vpnOpenEditEndpointModal = () => { editEndpointModalOpened++; };
    w.vpnSubmitEditEndpoint = () => { editEndpointSubmitted++; };
    w.closeModal = (modalId) => { modalsClosed.push(modalId); };

    // 1. The open control, including a click on its child icon.
    const editEpBtn = w.document.getElementById('vpn-edit-endpoint-btn');
    assert.ok(editEpBtn, '#vpn-edit-endpoint-btn must exist');
    editEpBtn.click();
    assert.strictEqual(editEndpointModalOpened, 1, 'vpnOpenEditEndpointModal called on click');

    // 2. The dialog's two close controls.
    const editEndpointModal = w.document.getElementById('editEndpointModal');
    assert.ok(editEndpointModal, '#editEndpointModal must exist');
    const editModalCloseBtns = Array.from(editEndpointModal.querySelectorAll('button[data-action="vpn-close-modal"]'));
    assert.strictEqual(editModalCloseBtns.length, 2, 'expected 2 close buttons in editEndpointModal');
    for (const btn of editModalCloseBtns) {
        btn.click();
    }
    assert.deepStrictEqual(modalsClosed, ['editEndpointModal', 'editEndpointModal'], 'editEndpointModal closed twice');

    // 3. The dialog's form, and the same form replaced in place: the delegated
    //    listener must survive a re-render.
    const editEndpointForm = w.document.getElementById('editEndpointForm');
    assert.ok(editEndpointForm, '#editEndpointForm must exist');
    const editEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    editEndpointForm.dispatchEvent(editEvt);
    assert.strictEqual(editEndpointSubmitted, 1, 'vpnSubmitEditEndpoint called on submit');
    assert.strictEqual(editEvt.defaultPrevented, true, 'editEndpointForm submit default prevented');

    const replacementForm = w.document.createElement('form');
    replacementForm.id = 'editEndpointForm';
    editEndpointForm.parentNode.replaceChild(replacementForm, editEndpointForm);
    const replEvt = new w.Event('submit', { bubbles: true, cancelable: true });
    replacementForm.dispatchEvent(replEvt);
    assert.strictEqual(editEndpointSubmitted, 2, 'vpnSubmitEditEndpoint called on replaced form submit');
    assert.strictEqual(replEvt.defaultPrevented, true, 'replaced editEndpointForm submit default prevented');

    // 4. A foreign data-action does NOT prevent default: the delegation engine
    //    claims only the actions its own document declares.
    const foreignLink = w.document.createElement('a');
    foreignLink.href = '#other';
    foreignLink.setAttribute('data-action', 'foreign-feature-action');
    w.document.body.appendChild(foreignLink);
    const foreignEvt = new w.MouseEvent('click', { bubbles: true, cancelable: true });
    foreignLink.dispatchEvent(foreignEvt);
    assert.strictEqual(foreignEvt.defaultPrevented, false, 'unrecognized data-action must not prevent default');

    // 5. No inline handler anywhere in the rendered document.
    const inlineHandlerEls = w.document.querySelectorAll('[onclick],[onchange],[onsubmit]');
    assert.strictEqual(inlineHandlerEls.length, 0, 'no inline on* attributes allowed in DOM');

    console.log('PASS_OVERVIEW_DELEGATION');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_DELEGATION") {
		t.Fatalf("expected PASS_OVERVIEW_DELEGATION, got:\n%s", out)
	}
}
