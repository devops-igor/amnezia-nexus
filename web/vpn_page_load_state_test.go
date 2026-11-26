package web

// Load-state honesty for the three VPN documents: what each one says when a read is
// refused, and what it must never claim.
//
// The single long document reported these states in one place. Split, each document
// owns its own, and each case here is driven through the real loader and the real
// renderer of that document:
//
//	backends      a refused first read states the failure instead of staying on
//	              Loading; a refused refresh after a success keeps the last known
//	              rows and says the refresh failed; a mutation that succeeded never
//	              reports an error for the refresh that followed it
//	diagnostics   a refused first sessions read states that sessions could not be
//	              read, rather than an empty list (which would claim there are none)
//	              or a permanent Loading row; a successful read replaces it and a
//	              later failure falls back to the cached rows
//	overview      an unavailable forwarder response is not a measurement: the
//	              signals render not-measured, and a measured zero still renders 0

import (
	"strings"
	"testing"
)

// TestVPNPageBackendsRejectedFirstAfterSuccessAndAfterMutation proves the inventory
// never claims to be current when it is not, and never reports an error for a refresh
// that followed a successful mutation.
func TestVPNPageBackendsRejectedFirstAfterSuccessAndAfterMutation(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let mode = 'reject';
    const toasts = [];
    w.UI = {
        escapeHtml: (s) => (s == null ? '' : String(s)),
        toast: (text, kind) => toasts.push({ text, kind }),
        confirm: async () => true,
    };

    w.API = {
        get: async (ep) => {
            if (ep !== '/api/vpn/backends') return {};
            if (mode === 'reject') throw new Error('inventory refused');
            return { backends: [{ server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active' }] };
        },
        post: async (ep) => {
            if (String(ep).indexOf('/enable') >= 0) return { status: 'ok' };
            return {};
        },
    };

    const tbody = w.document.getElementById('vpn-backends-tbody');

    // 1. A refused FIRST read states the failure instead of leaving Loading behind.
    mode = 'reject';
    await w.vpnLoadBackends();
    assert.ok(tbody.querySelector('tr.table-empty-state'), 'a refused first read renders a stated failure');
    assert.ok(!tbody.querySelector('#vpnBackendsStaleBanner'),
        'nothing was known before the first read, so there is no "last known values" claim');
    assert.ok(!/\.\.\./.test(tbody.textContent), 'the table must not be left on its loading placeholder');

    // 2. A successful read replaces it with the inventory.
    mode = 'ok';
    await w.vpnLoadBackends();
    assert.ok(tbody.querySelector('tr[data-backend-row], tr'), 'the inventory rendered');
    assert.strictEqual(tbody.querySelector('#vpnBackendsStaleBanner'), null, 'a successful read clears the stale statement');

    // 3. A refused REFRESH keeps the last known rows and says the refresh failed.
    mode = 'reject';
    await w.vpnLoadBackends();
    const stale = tbody.querySelector('#vpnBackendsStaleBanner');
    assert.ok(stale, 'a refused refresh states that the list is not current');
    assert.strictEqual(tbody.querySelectorAll('tr').length > 1, true,
        'the last known rows are kept rather than replaced by the failure');
    assert.ok((w.document.getElementById('vpn-backends-announcement') || {}).textContent,
        'the failure is announced to assistive technology');

    // 4. A successful mutation followed by a refused refresh reports the success and
    //    NOT an error: the refresh failure is the table's statement, not a toast.
    toasts.length = 0;
    mode = 'ok';
    await w.vpnToggleBackend('1', 'enable');
    // The mutation's own refresh succeeded here; now the one after a success fails.
    mode = 'reject';
    toasts.length = 0;
    await w.vpnToggleBackend('1', 'enable');

    const kinds = toasts.map(t => t.kind);
    assert.ok(kinds.indexOf('success') >= 0, 'the successful mutation still reports success');
    assert.strictEqual(kinds.indexOf('error'), -1,
        'a refused refresh after a successful mutation must not toast an error: ' + JSON.stringify(toasts));

    console.log('PASS_BACKENDS_LOAD_STATES');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_BACKENDS_LOAD_STATES") {
		t.Fatalf("expected PASS_BACKENDS_LOAD_STATES, got:\n%s", out)
	}
}

// TestVPNPageDiagnosticsNoSnapshotRefusal proves a refused first sessions read states
// the refusal, through the real health renderer, and that it is replaced by a real
// payload and falls back to the cache afterwards.
func TestVPNPageDiagnosticsNoSnapshotRefusal(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    w.Telemetry = { formatBytes: () => '0 B' };
    let mode = 'reject';
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return { listener_running: true, forwarder_available: true };
            if (ep === '/api/vpn/sessions') {
                if (mode === 'reject') throw new Error('sessions refused');
                if (mode === 'one') return { sessions: [{ id: 'sess-1', username: 'alice', status: 'connected' }] };
                return { sessions: [] };
            }
            return {};
        },
    };

    const tbody = w.document.getElementById('vpn-sessions-tbody');
    const badge = w.document.getElementById('vpn-sessions-count-badge');

    // 1. Refused first read, no snapshot: the table states that sessions could not be
    //    read. It must not claim there are none, and must not keep its loading row.
    mode = 'reject';
    await w.vpnLoadDiagnostics();
    assert.ok(tbody.textContent.indexOf(w._('vpn_sessions_unavailable')) >= 0,
        'the table states that sessions could not be read: ' + tbody.textContent);
    assert.ok(tbody.textContent.indexOf(w._('vpn_no_sessions')) < 0,
        'a refused read must not be reported as "no sessions"');
    assert.ok(tbody.querySelector('#vpnSessionsStaleBanner'), 'the stale banner states the failed read');
    assert.strictEqual(badge.textContent, '\u2014', 'the count is not measured, so it is not 0');

    // 2. A successful read replaces the refusal with the rows.
    mode = 'one';
    await w.vpnLoadDiagnostics();
    assert.ok(tbody.textContent.indexOf('alice') >= 0, 'the session rendered after recovery');
    assert.strictEqual(tbody.querySelector('#vpnSessionsStaleBanner'), null, 'a successful read clears the stale banner');
    assert.strictEqual(badge.textContent, '1', 'the count is measured again');

    // 3. A later failure keeps the cached row and states the staleness.
    mode = 'reject';
    await w.vpnLoadDiagnostics();
    assert.ok(tbody.textContent.indexOf('alice') >= 0, 'the last known session is kept');
    assert.ok(tbody.querySelector('#vpnSessionsStaleBanner'), 'the failure is stated beside the cached rows');

    console.log('PASS_DIAGNOSTICS_NO_SNAPSHOT');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DIAGNOSTICS_NO_SNAPSHOT") {
		t.Fatalf("expected PASS_DIAGNOSTICS_NO_SNAPSHOT, got:\n%s", out)
	}
}

// TestVPNPageOverviewUnavailableIsNotMeasuredZero proves an unavailable forwarder
// response renders as not-measured and that a real zero still renders as 0.
func TestVPNPageOverviewUnavailableIsNotMeasuredZero(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    w.Telemetry = { formatBytes: () => '0 B' };
    let statusPayload = {
        forwarder_available: false,
        connected_sessions: 0,
        active_tunnels: 0,
        rx_bytes: 0,
        tx_bytes: 0,
    };
    w.API = {
        get: async (ep) => {
            if (ep === '/api/vpn/status') return statusPayload;
            if (ep === '/api/vpn/config') return {};
            return {};
        },
    };

    const sessionsEl = w.document.getElementById('vpn-sessions');

    // 1. Unavailable: the response carries zeros, but nobody measured them.
    await w.vpnLoadOverview();
    assert.strictEqual(sessionsEl.textContent, w._('vpn_diag_not_measured'),
        'an unavailable response must not render a measured 0: ' + sessionsEl.textContent);
    assert.ok(sessionsEl.classList.contains('vpn-not-measured'), 'the signal carries the not-measured state');

    // 2. Available with a real zero: that IS a measurement and renders as 0.
    statusPayload = {
        forwarder_available: true,
        connected_sessions: 0,
        active_tunnels: 0,
        rx_bytes: 0,
        tx_bytes: 0,
    };
    await w.vpnLoadOverview();
    assert.strictEqual(sessionsEl.textContent, '0', 'a measured zero renders as 0: ' + sessionsEl.textContent);
    assert.ok(!sessionsEl.classList.contains('vpn-not-measured'), 'the measured zero is not marked as not measured');

    console.log('PASS_OVERVIEW_UNAVAILABLE');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_UNAVAILABLE") {
		t.Fatalf("expected PASS_OVERVIEW_UNAVAILABLE, got:\n%s", out)
	}
}
