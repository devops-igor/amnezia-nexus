package web

// Round-three regressions for the merged VPN page (issue #1006).
//
// Two properties, both about ownership rather than about a symptom:
//
//   - LOADING DATA NEVER MOVES THE PAGE. Ordinary navigation belongs to page.js
//     alone. The inventory read is a data path: when it completes it may fill the
//     table, but it may not scroll, focus, or rewrite the fragment. Before this
//     fix the read ended with a landing derived from whatever fragment the URL
//     carried, so an arrival that page.js had already landed in Overview could be
//     pulled down to the Backends heading by a slow inventory response.
//
//   - A PENDING INSPECT STILL COMPLETES. The one position a read may take is a
//     one-shot Inspect request that arrived before the rows existed, because only
//     a completed read can say whether the named backend is there. That is a
//     navigation landing the read finishes, not one it invents, and it must keep
//     working exactly as it did.

import (
	"testing"
)

// vpnRoundThreeJS records every attempt to move the reader. It is installed in the
// PRELUDE, before any module runs, so the boot's own landing and everything after it
// are measured by the same instrument.
//
// JSDOM implements no layout and no scrollIntoView, so the spike is the only way to
// observe a positioning call at all; a landing that used it would otherwise be
// invisible. Focus is observed directly, since JSDOM does implement it.
const vpnRoundThreeJS = `
w.vpnTestMoves = [];
w.HTMLElement.prototype.scrollIntoView = function () { w.vpnTestMoves.push('scroll:' + (this.id || this.tagName)); };
w.vpnTestMovesAt = function (label) {
    return { count: w.vpnTestMoves.length, label: label, moves: w.vpnTestMoves.slice() };
};
`

// TestVPNInventoryCompletionNeverMovesThePage is the reported regression: a cold
// arrival whose fragment names an Overview control, an inventory that loads later,
// and a reader who must still be where page.js put them.
//
// The case is driven through the shipped boot, not through a helper: the first tick
// and the fragment landing both happen at module evaluation, and the inventory is
// activated the way a reader activates it, by scrolling the section into range.
func TestVPNInventoryCompletionNeverMovesThePage(t *testing.T) {
	// The fragment names a node that exists in the merged document but belongs to
	// Overview. The resolver canonicalises it to the control that opens the dialog,
	// so page.js lands on #vpn-edit-endpoint-btn and reveals the configuration.
	const landedID = "vpn-edit-endpoint-btn"

	runVPNBootScript(t, JSDOMHarnessOptions{
		IncludeNexusTable:    true,
		IncludeFakeClock:     true,
		IncludeRealTelemetry: true,
		PreludeJS: vpnFixturesJS + vpnBootReadyJS + vpnRoundThreeJS + `
w.history.replaceState(null, '', '/vpn#editEndpointModal');
`,
	}, `
(async () => {
    const assert = require('assert');
    const d = w.document;
    await w.bootReady();

    // PRE-CONDITION: page.js performed its one landing, on the Overview control the
    // fragment means. Nothing else may move the reader for the rest of this arrival.
    const landed = d.getElementById('`+landedID+`');
    assert.ok(landed, 'the canonical landing target exists');
    assert.strictEqual(d.activeElement, landed,
        'page.js landed on the control the fragment names, not on: ' +
        (d.activeElement && d.activeElement.id));
    assert.strictEqual(d.getElementById('vpn-configuration').open, true,
        'the landing revealed the configuration that holds that control');
    const afterLanding = w.vpnTestMovesAt('after the page landing');
    assert.strictEqual(afterLanding.count, 1, 'the page landed exactly once: ' + JSON.stringify(afterLanding.moves));

    // PRE-CONDITION: the inventory has not been read yet, so what follows is its
    // FIRST load - the one the report names.
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 0,
        'nothing reached the inventory yet: ' + JSON.stringify(w.vpnTestReads));

    // Ordinary arrival at the inventory: the reader scrolls the section into range.
    w.__vpnIntersect(w.backendsSurface());
    for (let i = 0; i < 80; i++) await Promise.resolve();

    // The inventory really did load: the case cannot pass by nothing happening.
    assert.strictEqual(w.readsOf('/api/vpn/backends'), 1,
        'the inventory was read once: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(d.querySelectorAll('#vpn-backends-tbody tr[data-tunnel-id]').length, 13,
        'and its rows were rendered');
    assert.strictEqual(d.getElementById('vpn-backends-loading'), null,
        'and the loading row is gone, so the read completed');

    // THE PROPERTY: completion moved nothing.
    assert.deepStrictEqual(w.vpnTestMoves, afterLanding.moves,
        'loading data must not reposition the document: ' + JSON.stringify(w.vpnTestMoves));
    assert.strictEqual(d.activeElement, landed,
        'and must not steal focus: it is on ' + (d.activeElement && d.activeElement.id));
    assert.strictEqual(w.location.hash, '#editEndpointModal',
        'and must not rewrite the fragment: ' + w.location.hash);

    // The landing promise is still the page's: a subsequent explicit landing works.
    w.vpnApplyBackendsLanding('backends');
    assert.strictEqual(d.activeElement.id, 'backends',
        'an explicit landing still positions the inventory it was asked for');

    console.log('VPN_INVENTORY_LOAD_IS_INERT_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_INVENTORY_LOAD_IS_INERT_OK")
}

// TestVPNPendingInspectResolvesOnceTheInventoryArrives keeps the other half of the
// ownership change honest: an Inspect deep link that arrives BEFORE the rows exist
// must still resolve the moment the read completes.
//
// The read is held at the real API boundary, so the request genuinely predates the
// rows. What is asserted is that the request is honoured by the completed read - the
// named row is revealed and it takes focus - and that it is consumed exactly once.
//
// The focus assertion is recorded rather than sampled, because an Inspect arrival
// takes two inventory reads (the section's immediate poll and the landing's own
// read), so the second render legitimately replaces the focused row and restores
// focus to its heading. That re-render rule is pre-existing and belongs to the
// table, not to this change; asserting a final focus snapshot would be asserting it.
func TestVPNPendingInspectResolvesOnceTheInventoryArrives(t *testing.T) {
	runVPNBootScript(t, JSDOMHarnessOptions{
		IncludeNexusTable:    true,
		IncludeFakeClock:     true,
		IncludeRealTelemetry: true,
		PreludeJS: vpnFixturesJS + vpnBootReadyJS + vpnRoundThreeJS + `
w.vpnTestGateRelease = null;
w.vpnTestBackendsGate = new Promise(resolve => { w.vpnTestGateRelease = resolve; });
`,
	}, `
(async () => {
    const assert = require('assert');
    const d = w.document;

    // Record every focus the arrival performs, so the landing the completed read
    // performs can be observed even though a later render may move focus again.
    w.vpnTestFocused = [];
    const realFocus = w.HTMLElement.prototype.focus;
    w.HTMLElement.prototype.focus = function () {
        w.vpnTestFocused.push(this.id || (this.getAttribute && this.getAttribute('data-backend-name')) || this.tagName);
        return realFocus.apply(this, arguments);
    };

    // The deep link is in place BEFORE the boot reads the fragment, and behind it is
    // a real one-shot request - the arrival an Inspect navigation produces.
    w.history.replaceState(null, '', '/vpn#vpn-inspect-' + w.vpnStoreBackendHandoff('43'));
    await w.bootReady();

    // The arrival is an Inspect: the section mounts and its read starts. The read is
    // HELD, so the request is genuinely pending while the rows do not exist.
    assert.ok(w.readsOf('/api/vpn/backends') >= 1,
        'the Inspect arrival started its read: ' + JSON.stringify(w.vpnTestReads));
    assert.strictEqual(w.backendRow('43'), null,
        'PRE-CONDITION: the named backend row does not exist yet');
    assert.strictEqual(w.eval('vpnPendingInspectTunnelId'), '43',
        'the request is held page-local while the read is in flight');
    assert.deepStrictEqual(w.vpnTestFocused, [],
        'PRE-CONDITION: the pending request has focused nothing: ' + JSON.stringify(w.vpnTestFocused));

    // Completion is what honours it.
    w.vpnTestGateRelease();
    for (let i = 0; i < 120; i++) await Promise.resolve();

    const row = w.backendRow('43');
    assert.ok(row, 'once the read completes, the named row exists');
    assert.strictEqual(w.isVisible(row.querySelector('td[data-backend-name]')), true,
        'and the named backend row is painted');
    assert.ok(w.vpnTestFocused.indexOf('3') !== -1,
        'the request resolved: focus landed on the name cell of the row owning tunnel 43 ' +
        '(server 3, not the neighbouring rows): ' + JSON.stringify(w.vpnTestFocused));
    assert.strictEqual(w.location.hash, '#backends',
        'the one-shot navigation identity was retired: ' + w.location.hash);
    assert.strictEqual(w.eval('vpnPendingInspectTunnelId'), null,
        'the request was consumed exactly once');
    assert.strictEqual(w.vpnConsumeBackendHandoff(), null,
        'and nothing is left in durable storage to replay');

    console.log('VPN_PENDING_INSPECT_COMPLETES_OK');
})().catch(e => { console.error(e); process.exit(1); });
`, "VPN_PENDING_INSPECT_COMPLETES_OK")
}
