package web

// Boot-to-effect regressions for the merged VPN page.
//
// Each case here begins where the shipped page begins and asserts the outcome the
// operator sees, rather than calling the helper the outcome happens to live in. That
// distinction is the whole point of the file: the defects these cover were all
// reachable through the real boot and all invisible to a case that mounted a section
// manually, stubbed a navigation seam, or re-implemented the production tick.
//
// The subjects, in the order they were reported:
//
//   - arrival or scroll never activated the inventory, because the observer read a
//     metadata attribute from an element that did not carry it;
//   - a Backend Inspect and a legacy heading alias were resolved by the local
//     fragment resolver, which knew neither the Inspect family nor how to apply a
//     canonical target;
//   - the cumulative transfer totals lost their only writer;
//   - the status tick awaited the sessions read owned by another stream, so a slow
//     sessions request froze the health headline and the next tick;
//   - every controller loaded up front, so the unopened diagnostics blocked the
//     initial essentials.
//
// Every case fails when its fix is reverted. The negative direction is asserted
// alongside the positive one wherever a guard could otherwise pass by doing nothing,
// and boundary stubs live in the harness PRELUDE because the boot takes its first
// sample while the modules are being evaluated.

import (
	"strings"
	"testing"
)

// runVPNBootScript runs an assertion script against the merged page with the whole
// shipped chain, and fails closed: a guard whose only job is to catch a regression
// must not print the same green `ok` as its own absence.
func runVPNBootScript(t *testing.T, opts JSDOMHarnessOptions, assertions, wantToken string) string {
	t.Helper()
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	if fixture.NodePath == "" {
		t.Fatal("VPN boot regressions require Node.js (see CONTRIBUTING.md)")
	}
	opts.ExtraJS = assertions
	out, err := execNodeScript(fixture.NodePath, fixture.BuildJSDOMHarness(opts))
	if err != nil {
		t.Fatalf("boot script failed: %v\nOutput:\n%s", err, out)
	}
	if strings.HasPrefix(string(out), "JSDOM_NOT_AVAILABLE:") {
		t.Fatalf("VPN boot regressions require jsdom; install it and set NODE_PATH (see CONTRIBUTING.md):\n%s", out)
	}
	if strings.Contains(string(out), "no tests to run") {
		t.Fatalf("boot script executed no assertion:\n%s", out)
	}
	if !strings.HasSuffix("\n"+strings.TrimSpace(string(out)), "\n"+wantToken) {
		t.Fatalf("boot script did not report %q\nOutput:\n%s", wantToken, out)
	}
	return string(out)
}

// vpnVisibilityOracleJS (the shared "is it actually painted" predicate) is declared
// once, beside the reveal cases that introduced it; it is reused here so a focus call
// that lands on a display:none cell cannot satisfy an assertion by itself.

// vpnFixturesJS builds the inventory and the reads ledger both classes of case need. It
// is a PRELUDE: the boot's first status tick happens at module evaluation, so a
// boundary installed after that first sample is a boundary the sample never saw.
//
// The inventory deliberately puts the two id spaces on different values: tunnel 43
// lives on server 12, so a case that confused them could not pass by coincidence.
const vpnFixturesJS = `
w.isVisible = function (el) {
    let n = el;
    while (n && n.nodeType === 1) {
        const cs = w.getComputedStyle(n);
        if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
        n = n.parentElement;
    }
    return true;
};
w.vpnTestReads = [];
w.vpnTestStatus = { forwarder_available: true };
w.vpnTestStatusPayload = null;
w.vpnTestStatusReads = 0;
w.vpnTestSessionsGate = null;
w.vpnTestBackendsGate = null;
w.vpnTestBackendsCalls = 0;
w.vpnCachedServers = [{ id: 1, name: 'Alpha Gateway' }, { id: 12, name: 'Beta Relay' }];
w.backendsPayload = function () {
    const rows = [];
    for (let i = 1; i <= 12; i++) {
        rows.push({ id: 40 + i, server_id: i, endpoint: '198.51.100.' + i + ':51820',
            enabled: true, status: 'active', latency_ms: 10 + i, active_connections: 1 });
    }
    rows.push({ id: 60, server_id: 7, endpoint: '203.0.113.7:51820',
        enabled: true, status: 'active', latency_ms: 12, active_connections: 2 });
    return { backends: rows };
};
w.backendRow = function (tunnelId) {
    return Array.from(w.document.getElementById('vpn-backends-tbody').children)
        .find(function (r) { return r && r.getAttribute && r.getAttribute('data-tunnel-id') === tunnelId; }) || null;
};
w.readsOf = function (ep) { return w.vpnTestReads.filter(function (c) { return c === ep; }).length; };
w.API = {
    get: async (ep) => {
        w.vpnTestReads.push(ep);
        if (ep === '/api/vpn/status') {
            w.vpnTestStatusReads++;
            return (typeof w.vpnTestStatusPayload !== 'undefined' && w.vpnTestStatusPayload !== null)
                ? w.vpnTestStatusPayload : w.vpnTestStatus;
        }
        if (ep === '/api/vpn/config') return {};
        if (ep === '/api/vpn/backends') {
            w.vpnTestBackendsCalls++;
            if (w.vpnTestBackendsGate) await w.vpnTestBackendsGate;
            return w.backendsPayload();
        }
        if (ep === '/api/servers') return [{ server_id: 1, name: 'Alpha Gateway' }];
        if (ep === '/api/vpn/sessions') {
            if (w.vpnTestSessionsGate) await w.vpnTestSessionsGate;
            return { sessions: [{ session_id: 'S-1', username: 'alice', status: 'connected' }] };
        }
        return {};
    }
};
`

// vpnBootReadyJS is the small helper every boot case shares: wait for the boot to have
// taken its first tick, and find the element the SHIPPED boot observed for a section.
// Reading the observed target through the recording makes a wrong observer target an
// error rather than a silent pass.
const vpnBootReadyJS = `
w.bootReady = async function () {
    await new Promise(resolve => w.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 40; i++) await Promise.resolve();
};
w.observedSurface = function (id) {
    const observed = w.__vpnObserved.find(el => el && el.id === id);
    if (!observed) throw new Error('the boot never observed #' + id + '; observed: ' +
        JSON.stringify(w.__vpnObserved.map(el => el && el.id)));
    return observed;
};
w.backendsSurface = function () { return w.observedSurface('backends-region'); };
w.diagnosticsSurface = function () { return w.observedSurface('diagnostics-region'); };
`

// TestVPNBackendsActivateOnArrival is the passive-activation regression.
//
// The passive path is the one the reader actually takes: they scroll into Backends
// instead of pressing the jump rail. The case delivers the intersecting entry for the
// element the SHIPPED boot observed, through the callback the boot registered, and
// asserts the inventory was read and its rows exist - without ever calling
// vpnMountSection.
//
// The early-activation half covers the other ordinary arrival: a keyboard reader tabs
// into the section. Focus there must mount through the same idempotent path, once, and
// a press on a control whose controller is still arriving must be replayed rather than
// swallowed.
func TestVPNBackendsActivateOnArrival(t *testing.T) {
	t.Run("PassiveScrollIntoTheInventory", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeNexusTable:    true,
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS:            vpnFixturesJS + vpnBootReadyJS,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    await w.bootReady();

    // PRE-CONDITION: nothing reached the inventory yet, so the fix is not being
    // credited for a read that happened anyway.
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 0,
        'the inventory must not be read before the reader reaches it: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(w.readsOf('/api/servers'), 0,
        'the server names must not be pre-read for an unreached section: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(d.querySelectorAll('#vpn-backends-loading').length, 1,
        'the inventory starts on its loading row');

    // The element the shipped boot OBSERVED. If the boot observed the heading instead
    // of the section, w.observedSurface throws rather than silently passing.
    const observed = w.backendsSurface();
    assert.strictEqual(observed.getAttribute('data-vpn-section'), 'backends',
        'the observed element is the one the section name is read from');

    // Ordinary arrival: the surface scrolls into range.
    w.__vpnIntersect(observed);
    for (let i = 0; i < 60; i++) await Promise.resolve();

    assert.strictEqual(w.readsOf('/api/vpn/backends'), 1,
        'scrolling into the inventory reads it exactly once: ' + JSON.stringify(w.vpnTestReads));

    const rows = d.querySelectorAll('#vpn-backends-tbody tr[data-tunnel-id]');
    assert.strictEqual(rows.length, 13, 'the inventory rendered its rows, not a loading placeholder');
    assert.strictEqual(d.getElementById('vpn-backends-loading'), null,
        'the loading row is gone once the inventory arrived');
    assert.ok(w.vpnTableInstance, 'the table engine was built for the rendered rows');
    assert.ok(w.backendRow('52'), 'a specific tunnel id is present, so the rows carry the identity Inspect needs');

    // The same arrival again - a second entry, a resize, a re-entry - starts nothing new.
    w.__vpnIntersect(observed);
    for (let i = 0; i < 40; i++) await Promise.resolve();
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 1,
        'a second intersecting entry does not read the inventory again: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(w.readsOf('/api/servers'), 1,
        'and does not re-read the server names: ' + JSON.stringify(w.vpnTestReads));

    console.log('VPN_BOOT_PASSIVE_BACKENDS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_PASSIVE_BACKENDS_OK")
	})

	t.Run("EarlyKeyboardEntryActivatesTheSection", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS:            vpnFixturesJS + vpnBootReadyJS,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    await w.bootReady();

    // PRE-CONDITION: the observer has not fired, so only focus can activate here.
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 0,
        'nothing reached the inventory yet: ' + JSON.stringify(w.vpnTestReads));

    // A keyboard reader tabs into the section: focus lands on the Add control, which is
    // focusable and inside the Backends surface.
    const addButton = d.getElementById('vpn-add-backend-btn');
    addButton.focus();
    assert.strictEqual(d.activeElement, addButton, 'focus reached the inventory control');
    for (let i = 0; i < 60; i++) await Promise.resolve();

    assert.strictEqual(w.readsOf('/api/vpn/backends'), 1,
        'focusing into the inventory activates it exactly once: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(d.querySelectorAll('#vpn-backends-tbody tr[data-tunnel-id]').length, 13,
        'the rows the reader tabbed toward are really there');

    // A further focus move inside the same section starts nothing new.
    d.getElementById('backends').focus();
    for (let i = 0; i < 40; i++) await Promise.resolve();
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 1,
        'a second focus inside the section does not re-activate it: ' + JSON.stringify(w.vpnTestReads));

    console.log('VPN_BOOT_EARLY_FOCUS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_EARLY_FOCUS_OK")
	})

	t.Run("PressInsideAnUnactivatedSectionRunsItsActionOnce", func(t *testing.T) {
		// A control in a section the reader has not reached is real markup with a real
		// handler. The press must activate the section exactly as a jump does, and the
		// action itself must run ONCE: a replay that also let the delegated handler fire
		// would open the dialog twice.
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeNexusTable:    true,
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS: vpnFixturesJS + vpnBootReadyJS + `
w.vpnTestOpens = 0;
`,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    await w.bootReady();

    // PRE-CONDITION: the section is untouched, so its read has not happened.
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 0,
        'nothing reached the inventory yet: ' + JSON.stringify(w.vpnTestReads));

    const realOpen = w.vpnOpenAddBackendModal;
    w.vpnOpenAddBackendModal = function () { w.vpnTestOpens++; };

    // The reader presses Add without scrolling to the section first.
    d.getElementById('vpn-add-backend-btn').click();
    for (let i = 0; i < 60; i++) await Promise.resolve();

    assert.strictEqual(w.vpnTestOpens, 1, 'the press ran its action exactly once');
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 1,
        'and activated the section the control belongs to: ' + JSON.stringify(w.vpnTestReads));

    w.vpnOpenAddBackendModal = realOpen;
    console.log('VPN_BOOT_PRESS_ACTIVATES_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_PRESS_ACTIVATES_OK")
	})
}

// TestVPNInspectAndLegacyAliasLandInsideThePage is the Inspect/alias landing regression.
//
// The Inspect control is the real one health renders, with the whole-page scripts
// installed and no replacement of the navigation seam: the click goes through the
// delegated handler, the local resolver, the section mount and the real table reveal.
// The tunnel id (43) differs from the server id (12) on purpose.
func TestVPNInspectAndLegacyAliasLandInsideThePage(t *testing.T) {
	t.Run("BackendInspectRevealsTheRow", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeNexusTable:    true,
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS:            vpnFixturesJS + vpnBootReadyJS,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    await w.bootReady();

    // The inventory has ALREADY loaded through an ordinary arrival. This is the sequence
    // the finding described: the one-time landing flag has been consumed, so an Inspect
    // issued afterwards must still be honoured by its own read.
    w.__vpnIntersect(w.backendsSurface());
    for (let i = 0; i < 60; i++) await Promise.resolve();
    assert.ok(w.vpnTableInstance, 'the inventory and its table exist before the Inspect');
    assert.strictEqual(w.vpnConsumeBackendHandoff(), null, 'no stale request is pending before the Inspect');

    // A backend-scoped active problem carrying tunnel id 43, whose row sits on server 3.
    d.getElementById('vpn-advanced-entry').focus();
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 43, category: 'backend' }]
        }
    });
    const before = w.backendRow('43');
    assert(before, 'tunnel 43 is present');
    const beforeCell = before.querySelector('td[data-backend-name]');
    assert.ok(beforeCell && beforeCell.getAttribute('tabindex') !== null,
        'the row names itself in a focusable cell');
    assert.strictEqual(beforeCell.getAttribute('data-backend-name'), '3',
        'and it belongs to server 3, so the two id spaces differ');

    // The real Inspect button, through the real delegated handler.
    const list = d.getElementById('vpn-fwd-problem-list');
    assert.strictEqual(list.children.length, 1, 'the problem is listed once');
    list.children[0].children[1].click();
    for (let i = 0; i < 80; i++) await Promise.resolve();

    // The Inspect performs its own inventory read, which re-renders the rows: the node
    // is resolved again rather than compared with the detached one.
    const revealed = w.backendRow('43');
    assert(revealed, 'the named row is present after the Inspect read');
    const cell = revealed.querySelector('td[data-backend-name]');
    assert.strictEqual(w.isVisible(cell), true, 'the named backend row is painted');
    assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed backend cell');
    assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '3', 'on the row that owns tunnel 43');

    // One-shot: nothing is left for a later visit to replay.
    assert.strictEqual(w.vpnConsumeBackendHandoff(), null, 'the request is consumed exactly once');
    assert.strictEqual(d.location.hash, '#backends', 'the arrival identity is rewritten to the canonical fragment');

    console.log('VPN_BOOT_INSPECT_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_INSPECT_OK")
	})

	t.Run("InspectAgainstAnUnfinishedReadIsNotReportedMissing", func(t *testing.T) {
		// The negative direction: an inventory read that has NOT completed cannot say the
		// backend is gone. The pre-existing rule is preserved and asserted here because the
		// landing now runs on the read that consumes an Inspect rather than once per arrival.
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeNexusTable:    true,
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS: vpnFixturesJS + vpnBootReadyJS + `
w.vpnTestBackendsGate = null;
w.vpnTestBackendsCalls = 0;
`,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    const nonce = w.vpnStoreBackendHandoff('43');
    w.history.replaceState(null, '', '/vpn#vpn-inspect-' + nonce);

    let release = null;
    w.vpnTestBackendsGate = new Promise(resolve => { release = resolve; });
    w.API.get = async (ep) => {
        if (ep === '/api/vpn/backends') {
            w.vpnTestBackendsCalls++;
            if (w.vpnTestBackendsCalls === 1) await w.vpnTestBackendsGate;
            return { backends: [{ id: 43, server_id: 12, endpoint: '198.51.100.12:51820', enabled: true, status: 'active' }] };
        }
        if (ep === '/api/servers') return [];
        if (ep === '/api/vpn/status') return w.vpnTestStatus;
        if (ep === '/api/vpn/config') return {};
        return {};
    };
    await w.bootReady();

    const announcement = d.getElementById('vpn-backends-announcement');
    assert(w.vpnTestBackendsCalls >= 1, 'the Inspect arrival started its inventory read');
    assert.strictEqual(announcement.textContent, '',
        'an inventory read still in flight must not claim the backend is missing: ' + JSON.stringify(announcement.textContent));

    release();
    for (let i = 0; i < 80; i++) await Promise.resolve();
    assert(w.backendRow('43'), 'once the read completes, the named row exists');
    assert.strictEqual(w.document.getElementById('vpn-backends-loading'), null,
        'and the inventory is no longer on its loading row');
    assert.strictEqual(announcement.textContent, '', 'a successful read never announces a missing backend');

    console.log('VPN_BOOT_INSPECT_INFLIGHT_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_INSPECT_INFLIGHT_OK")
	})

	t.Run("LegacyInventoryHeadingLandsOnTheSectionHeading", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS:            vpnFixturesJS + vpnBootReadyJS,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    await w.bootReady();

    // The retired card title: the id no longer exists as a node, but the resolver still
    // knows which section it meant.
    assert.strictEqual(d.getElementById('vpn-backends-title'), null,
        'the split-era card title is genuinely gone, so a raw-id lookup cannot succeed');
    const resolved = w.vpnResolveFragment('#vpn-backends-title');
    assert(resolved, 'the resolver still knows the legacy id');
    assert.strictEqual(resolved.section, 'backends', 'it belongs to Backends');
    assert.strictEqual(resolved.target, 'backends', 'and it canonicalises to the section heading');

    d.getElementById('vpn-advanced-entry').focus();
    assert.strictEqual(d.activeElement.id, 'vpn-advanced-entry', 'focus starts away from the destination');

    // An ordinary bookmark arrival, through the boot's own fragment path.
    w.history.replaceState(null, '', '/vpn#vpn-backends-title');
    await w.vpnLandOnFragment('#vpn-backends-title', 'fragment');
    for (let i = 0; i < 60; i++) await Promise.resolve();

    assert.strictEqual(d.activeElement.id, 'backends',
        'the legacy heading alias lands on the inventory heading it means: ' + d.activeElement.id);
    assert.strictEqual(d.getElementById('vpn-diagnostics').hidden !== false, true,
        'and it does not open an unrelated disclosure');

    console.log('VPN_BOOT_LEGACY_ALIAS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_LEGACY_ALIAS_OK")
	})
}

// TestVPNCumulativeTotalsFollowTheStatusSample is the cumulative-total writer regression.
//
// The driver is the sample the boot itself took, then explicit ticks through the same
// entry point the registered poll calls. A hand-built tick that called the diagnostics
// loader is exactly what let the orphaned writer look healthy.
func TestVPNCumulativeTotalsFollowTheStatusSample(t *testing.T) {
	runVPNBootScript(t, JSDOMHarnessOptions{
		IncludeFakeClock:     true,
		IncludeRealTelemetry: true,
		PreludeJS: vpnFixturesJS + `
w.vpnTestStatusPayload = { forwarder_available: true, rx_bytes: 1048576, tx_bytes: 2097152 };
`,
	}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    w.API.get = async (ep) => {
        if (ep === '/api/vpn/status') return w.vpnTestStatusPayload;
        if (ep === '/api/vpn/config') return {};
        return {};
    };

    await new Promise(resolve => d.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 60; i++) await Promise.resolve();

    const rx = d.getElementById('vpn-rx');
    const tx = d.getElementById('vpn-tx');
    assert(rx && tx, 'both cumulative totals exist in the template');
    assert.strictEqual(d.getElementById('vpn-diagnostics').hidden !== false, true,
        'the panel is closed throughout: the totals are painted from the sample, not by opening it');

    // The sample the boot read reached the readouts through the shared render.
    assert.notStrictEqual(rx.textContent, '-', 'the receive total was written by the shared status tick');
    assert.strictEqual(rx.textContent, w.Telemetry.formatBytes(1048576), 'and it is the supplied sample');
    assert.strictEqual(tx.textContent, w.Telemetry.formatBytes(2097152), 'as is the transmit total');

    // A measured zero is a measurement and must render as one, not as "not read".
    w.vpnTestStatusPayload = { forwarder_available: true, rx_bytes: 0, tx_bytes: 0 };
    await w.vpnTickOnce();
    for (let i = 0; i < 40; i++) await Promise.resolve();
    assert.strictEqual(rx.textContent, w.Telemetry.formatBytes(0), 'a sampled zero total is a measurement');
    assert.strictEqual(tx.textContent, w.Telemetry.formatBytes(0), 'in both directions');

    // An unavailable forwarder is not a zero: its counters are zeroed on the wire, so
    // reporting 0 B would assert a measurement nobody took.
    w.vpnTestStatusPayload = { forwarder_available: false, rx_bytes: 0, tx_bytes: 0 };
    await w.vpnTickOnce();
    for (let i = 0; i < 40; i++) await Promise.resolve();
    assert.strictEqual(rx.textContent, '-', 'an unavailable sample keeps the placeholder');
    assert.strictEqual(tx.textContent, '-', 'in both directions');

    // Recovery: the next real sample is published again.
    w.vpnTestStatusPayload = { forwarder_available: true, rx_bytes: 3145728, tx_bytes: 524288 };
    await w.vpnTickOnce();
    for (let i = 0; i < 40; i++) await Promise.resolve();
    assert.strictEqual(rx.textContent, w.Telemetry.formatBytes(3145728), 'recovery republishes the receive total');
    assert.strictEqual(tx.textContent, w.Telemetry.formatBytes(524288), 'and the transmit total');

    console.log('VPN_BOOT_TOTALS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_TOTALS_OK")
}

// TestVPNSlowSessionsReadDoesNotStallTheEssentials is the tick-independence regression.
//
// The sessions read is held at the real API boundary while fresh status samples arrive.
// The health headline must publish from its own sample, and further status ticks must
// complete, without waiting for the release.
func TestVPNSlowSessionsReadDoesNotStallTheEssentials(t *testing.T) {
	runVPNBootScript(t, JSDOMHarnessOptions{
		IncludeFakeClock:     true,
		IncludeRealTelemetry: true,
		PreludeJS:            vpnFixturesJS + vpnBootReadyJS,
	}, `
(async () => {
    const assert = require('assert');
    const d = w.document;

    w.vpnTestStatus = {
        forwarder_available: true,
        health_assessment: { status: 'CRITICAL', summary: 'Dataplane impaired' }
    };
    let statusReads = 0;
    w.API.get = async (ep) => {
        if (ep === '/api/vpn/status') { statusReads++; return w.vpnTestStatus; }
        if (ep === '/api/vpn/config') return {};
        if (ep === '/api/vpn/sessions') {
            if (w.vpnTestSessionsGate) await w.vpnTestSessionsGate;
            return { sessions: [] };
        }
        if (ep === '/api/vpn/backends') return { backends: [] };
        if (ep === '/api/servers') return [];
        return {};
    };
    await w.bootReady();

    const badge = d.getElementById('vpn-fwd-status-text');
    assert.strictEqual(badge.textContent, w._('vpn_forwarder_critical'), 'the first sample publishes Critical');

    // Connection Diagnostics is now open: its sessions stream owns a sessions read.
    await w.vpnMountSection('diagnostics');
    for (let i = 0; i < 60; i++) await Promise.resolve();

    // Hold the NEXT sessions read open at the real boundary.
    let release = null;
    w.vpnTestSessionsGate = new Promise(resolve => { release = resolve; });
    const readsBefore = statusReads;

    // A fresh status sample says Healthy, while the sessions read is still pending.
    w.vpnTestStatus = {
        forwarder_available: true,
        health_assessment: { status: 'HEALTHY', summary: 'All clear' }
    };
    const tick = w.vpnTickOnce();
    for (let i = 0; i < 60; i++) await Promise.resolve();

    assert.strictEqual(badge.textContent, w._('vpn_forwarder_healthy'),
        'the headline publishes the fresh status while sessions is still pending; it reads: ' + badge.textContent);
    assert.strictEqual(statusReads, readsBefore + 1, 'the tick read the status exactly once');

    // The tick itself completed: a following tick must be able to run.
    const settled = await Promise.race([
        tick.then(() => 'completed'),
        new Promise(resolve => w.setTimeout(() => resolve('stalled'), 0))
    ]);
    assert.strictEqual(settled, 'completed', 'the status tick must not await the sessions stream');

    // And a second tick proceeds independently while sessions is still pending.
    await w.vpnTickOnce();
    assert.strictEqual(statusReads, readsBefore + 2,
        'a further status tick runs while the sessions read is unresolved: ' + statusReads);
    assert.strictEqual(badge.textContent, w._('vpn_forwarder_healthy'), 'and publishes from its own sample');

    // Releasing sessions changes nothing about the essentials.
    release();
    w.vpnTestSessionsGate = null;
    for (let i = 0; i < 60; i++) await Promise.resolve();
    assert.strictEqual(badge.textContent, w._('vpn_forwarder_healthy'), 'the headline stays on its sample');

    console.log('VPN_BOOT_SESSIONS_INDEPENDENCE_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_SESSIONS_INDEPENDENCE_OK")
}

// TestVPNDeferredControllersDoNotBlockTheEssentials is the deferred-loading regression.
//
// The essential reads are driven while the section controllers and the chart module are
// still not requested. The case asserts the request itself - which deferred module was
// asked for, and when - and the negative direction: no deferred script is requested on
// ordinary arrival, and no chart work happens while the disclosure is closed.
func TestVPNDeferredControllersDoNotBlockTheEssentials(t *testing.T) {
	t.Run("EssentialsProceedWithoutAnySectionController", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS: vpnFixturesJS + `
w.vpnTestRequested = [];
// Record every deferred module the boot asks for, and never deliver one: this is
// "the browser has not yet received charts.js", not a broken load.
w.vpnLoadModuleImpl = function (module) {
    w.vpnTestRequested.push(module.name + '=' + module.url);
    return new Promise(function () {});
};
`,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;

    w.vpnTestStatus = {
        forwarder_available: true,
        connected_sessions: 12,
        health_assessment: { status: 'HEALTHY', conditions: [] },
        historical_series: { window_15m: [{ t: 1, traffic_available: true, rx_bps: 1000, tx_bps: 1000 }] }
    };

    await new Promise(resolve => d.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 60; i++) await Promise.resolve();

    // ESSENTIALS: the first view rendered itself with no section controller present.
    assert.ok(w.vpnTestReads.includes('/api/vpn/status'),
        'the essential status read proceeded: ' + JSON.stringify(w.vpnTestReads));
    assert.ok(w.vpnTestReads.includes('/api/vpn/config'),
        'the essential configuration read proceeded: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(d.getElementById('vpn-sessions').textContent, '12',
        'the headline measurement rendered on the first view');
    assert.strictEqual(d.getElementById('vpn-fwd-status-text').textContent, w._('vpn_forwarder_healthy'),
        'the health headline rendered on the first view');

    // NEGATIVE DIRECTION: nothing deferred was requested, and neither section read
    // anything, because nothing reached them.
    assert.strictEqual(JSON.stringify(w.vpnTestRequested), '[]',
        'an ordinary arrival must request no section controller: ' + JSON.stringify(w.vpnTestRequested));
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 0,
        'the inventory was not read: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(w.readsOf('/api/vpn/sessions'), 0,
        'the sessions were not read: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(d.getElementById('vpn-chart-throughput').innerHTML, '',
        'a closed disclosure performs no chart work');

    console.log('VPN_BOOT_DEFERRED_ESSENTIALS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_DEFERRED_ESSENTIALS_OK")
	})

	t.Run("ChartModuleLoadsOnceOnOpenAndNeverForClosedWork", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS: vpnFixturesJS + `
w.vpnTestRequested = [];
w.vpnLoadModuleImpl = function (module) {
    w.vpnTestRequested.push(module.name + '=' + module.url);
    // A delivered module is one the harness already evaluated; registering it is what
    // a real fetch would do on load.
    w.vpnMarkModule(module.name);
    return Promise.resolve(true);
};
`,
		}, `
(async () => {
    const assert = require('assert');
    const d = w.document;

    w.vpnTestStatus = {
        forwarder_available: true,
        health_assessment: { status: 'HEALTHY', conditions: [] },
        historical_series: { window_15m: [{ t: 1, traffic_available: true, rx_bps: 1000, tx_bps: 1000 }] }
    };

    // The harness evaluated every module, as the shell does for its eager chain. The
    // chart module is the one this page DEFERS, so it is forgotten here: otherwise a
    // page that never asked for it would look correct.
    w.eval("delete VPN_REGISTERED_MODULES.charts");

    await new Promise(resolve => d.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 60; i++) await Promise.resolve();

    // CLOSED: a fresh poll with a full history payload draws no chart.
    assert.strictEqual(d.getElementById('vpn-chart-throughput').innerHTML, '',
        'a poll while the disclosure is closed renders no chart');
    assert.strictEqual(JSON.stringify(w.vpnTestRequested), '[]',
        'and requests no chart module: ' + JSON.stringify(w.vpnTestRequested));

    // OPEN: the chart module is requested once, from the panel's own declaration and
    // under the digest of its bytes.
    assert.strictEqual(w.vpnTechnicalVisible(), false, 'the disclosure starts closed');
    w.vpnSetDiagnosticsOpen(true);
    assert.strictEqual(w.vpnTechnicalVisible(), true, 'opening it makes it visible');
    for (let i = 0; i < 60; i++) await Promise.resolve();
    assert.strictEqual(w.vpnTestRequested.length, 1,
        'opening Advanced requests its module once: ' + JSON.stringify(w.vpnTestRequested));
    const pair = w.vpnTestRequested[0];
    assert.strictEqual(pair.split('=')[0], 'charts', 'and it is the chart module');
    assert(pair.indexOf('=/static/js/vpn/charts.js?v=') !== -1,
        'requested under a content-derived URL, not a bare path or a release version: ' + pair);
    assert.notStrictEqual(d.getElementById('vpn-chart-throughput').innerHTML, '',
        'the opened panel rendered its chart from the sample already held');

    // Open again: no second request, and the chart is still painted.
    w.vpnSetDiagnosticsOpen(false);
    w.vpnSetDiagnosticsOpen(true);
    for (let i = 0; i < 60; i++) await Promise.resolve();
    assert.strictEqual(w.vpnTestRequested.length, 1,
        'a repeat open does not request the module again: ' + JSON.stringify(w.vpnTestRequested));
    assert.notStrictEqual(d.getElementById('vpn-chart-throughput').innerHTML, '',
        'and the reopened panel still shows its chart');

    console.log('VPN_BOOT_DEFERRED_CHARTS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_DEFERRED_CHARTS_OK")
	})

	t.Run("SectionsRequestTheirOwnControllersOnceOnActivation", func(t *testing.T) {
		runVPNBootScript(t, JSDOMHarnessOptions{
			IncludeFakeClock:     true,
			IncludeRealTelemetry: true,
			PreludeJS:            vpnFixturesJS + vpnBootReadyJS + "\nw.vpnTestRequested = [];\n",
		}, `
(async () => {
    const assert = require('assert');
    await w.bootReady();

    // Forget the two sections' controllers so activation has to ask for them, then
    // deliver them immediately. The question under test is WHICH modules a section
    // requests and HOW MANY times.
    ['backends', 'backends_page', 'sessions', 'diagnostics_page'].forEach(function (name) {
        w.eval("delete VPN_REGISTERED_MODULES['" + name + "']");
    });
    w.vpnLoadModuleImpl = function (module) {
        w.vpnTestRequested.push(module.name);
        w.vpnMarkModule(module.name);
        return Promise.resolve(true);
    };

    assert.strictEqual(JSON.stringify(w.vpnTestRequested), '[]',
        'nothing is requested before a section is reached');

    // Reaching Backends requests exactly its own two controllers, in order.
    w.__vpnIntersect(w.backendsSurface());
    for (let i = 0; i < 60; i++) await Promise.resolve();
    assert.strictEqual(JSON.stringify(w.vpnTestRequested), JSON.stringify(['backends', 'backends_page']),
        'the inventory requested its controller then the page that drives it: ' + JSON.stringify(w.vpnTestRequested));

    // Reaching Diagnostics adds only its own.
    w.__vpnIntersect(w.diagnosticsSurface());
    for (let i = 0; i < 60; i++) await Promise.resolve();
    assert.strictEqual(JSON.stringify(w.vpnTestRequested),
        JSON.stringify(['backends', 'backends_page', 'sessions', 'diagnostics_page']),
        'each section requests only what it needs, once: ' + JSON.stringify(w.vpnTestRequested));
    assert.strictEqual(w.vpnTestRequested.indexOf('charts'), -1,
        'and neither section drags the chart module in: ' + JSON.stringify(w.vpnTestRequested));

    // A second activation of either section requests nothing.
    await w.vpnMountSection('backends');
    await w.vpnMountSection('diagnostics');
    assert.strictEqual(w.vpnTestRequested.length, 4,
        'a second activation loads nothing twice: ' + JSON.stringify(w.vpnTestRequested));

    console.log('VPN_BOOT_DEFERRED_SECTIONS_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_BOOT_DEFERRED_SECTIONS_OK")
	})
}
