package web

import (
	"strings"
	"testing"
)

// Issue #955 round 7: Inspect navigation regressions.
//
// Two navigation defects were reported by the owner and reproduced in source:
//
//   - the backend match compared the problem's backend TUNNEL id (the payload's
//     backend_id, populated from the session/route tunnel id) against the row's
//     SERVER id, so a backend whose two ids differ could never be found;
//   - the no-entity fallback always landed on the sessions card heading, so a
//     backend-scoped global condition put the operator in the sessions table.
//
// These tests assert the observable outcome (where focus actually lands), not the
// internal comparison, and each pair includes a control that must stay green so a
// fix cannot pass by swapping one wrong destination for another.

// runVPNProblemNavigationScript evaluates one JSDOM assertion script against the
// shipped VPN modules and Requires its success token. Missing jsdom fails closed
// through RequireJSDOM rather than silently skipping.
func runVPNProblemNavigationScript(t *testing.T, assertions, wantToken string) {
	t.Helper()
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireJSDOM()
	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: assertions})
	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("navigation script failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), wantToken) {
		t.Fatalf("navigation script did not report %q\nOutput:\n%s", wantToken, string(out))
	}
}

// TestVPN955BackendInspectMatchesBackendIdentity proves Inspect finds the backend
// row the problem names even when the backend's tunnel id and server id differ.
// The ids are deliberately distinct: a test using equal ids would pass on the
// broken comparison, which is why this defect survived every earlier test.
func TestVPN955BackendInspectMatchesBackendIdentity(t *testing.T) {
	t.Run("DistinctTunnelAndServerIds", func(t *testing.T) {
		runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;

w.vpnCachedServers = [{ id: 7, name: 'Alpha Gateway' }, { id: 8, name: 'Beta Relay' }];

// Two backends whose tunnel id and server id are all different from each other.
// Backend 42 lives on server 7; backend 43 lives on server 8.
const tbody = d.getElementById('vpn-backends-tbody');
tbody.textContent = '';
const rowA = w.vpnRenderBackendRow({ id: 42, server_id: 7, endpoint: '198.51.100.7:51820', enabled: true, status: 'active', latency_ms: 12, active_connections: 2 });
const rowB = w.vpnRenderBackendRow({ id: 43, server_id: 8, endpoint: '198.51.100.8:51820', enabled: true, status: 'active', latency_ms: 20, active_connections: 1 });
tbody.appendChild(rowA);
tbody.appendChild(rowB);
const cellA = rowA.querySelector('td[data-backend-name]');
const cellB = rowB.querySelector('td[data-backend-name]');
assert.strictEqual(cellA.getAttribute('data-backend-name'), '7', 'row A still names server 7');
assert.strictEqual(cellB.getAttribute('data-backend-name'), '8', 'row B still names server 8');

// The diagnostics payload carries the TUNNEL id, so this problem is about the
// backend on server 8.
d.getElementById('vpn-advanced-entry').focus();
assert.strictEqual(d.activeElement.id, 'vpn-advanced-entry', 'focus starts on the diagnostics entry');

w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 43, category: 'backend' }]
    }
});
assert.strictEqual(d.getElementById('vpn-diagnostics').hidden, true, 'diagnostics stayed closed');
assert.strictEqual(d.activeElement.id, 'vpn-advanced-entry', 'rendering alone must not move focus');

const summary = d.getElementById('vpn-fwd-headline-summary');
const missingText = 'no longer in the current list';
const summaryBefore = summary ? summary.textContent : '';

d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();
assert.strictEqual(d.activeElement, cellB, 'Inspect focuses the row for tunnel 43 (server 8)');
assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '8', 'and it is that backend, not its neighbour');
if (summary) {
    assert(!summary.textContent.includes(missingText),
        'a backend that is listed must not report itself as missing (summary=' + JSON.stringify(summary.textContent) + ')');
    assert.strictEqual(summary.textContent, summaryBefore, 'a successful Inspect leaves the headline summary alone');
}

// The other backend, addressed by its own tunnel id, resolves to its own row.
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 42, category: 'backend' }]
    }
});
d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();
assert.strictEqual(d.activeElement, cellA, 'Inspect focuses the row for tunnel 42 (server 7)');
assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '7', 'and it is that backend');
console.log('VPN955_R7_BACKEND_DISTINCT_IDS_OK');
})();
`, "VPN955_R7_BACKEND_DISTINCT_IDS_OK")
	})

	t.Run("EqualTunnelAndServerIdsStillFocus", func(t *testing.T) {
		// Control: the behaviour that already worked must keep working.
		runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;
w.vpnCachedServers = [{ id: 9, name: 'Gamma Standby' }];

const tbody = d.getElementById('vpn-backends-tbody');
tbody.textContent = '';
const row = w.vpnRenderBackendRow({ id: 9, server_id: 9, endpoint: '198.51.100.9:51820', enabled: true, status: 'active', latency_ms: 15, active_connections: 0 });
tbody.appendChild(row);
const cell = row.querySelector('td[data-backend-name]');

d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 9, category: 'backend' }]
    }
});
d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();
assert.strictEqual(d.activeElement, cell, 'a backend whose ids are equal still focuses its row');
assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '9', 'and to the reported backend');
console.log('VPN955_R7_BACKEND_EQUAL_IDS_OK');
})();
`, "VPN955_R7_BACKEND_EQUAL_IDS_OK")
	})

	t.Run("AbsentBackendStillReportsMissing", func(t *testing.T) {
		// Negative path: a backend that is genuinely not listed must land on the
		// backends card and say so. This is what the fixed comparison must not lose.
		runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;
w.vpnCachedServers = [{ id: 7, name: 'Alpha Gateway' }];

const tbody = d.getElementById('vpn-backends-tbody');
tbody.textContent = '';
tbody.appendChild(w.vpnRenderBackendRow({ id: 42, server_id: 7, endpoint: '198.51.100.7:51820', enabled: true, status: 'active', latency_ms: 12, active_connections: 2 }));

d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 999, category: 'backend' }]
    }
});
d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();
assert.strictEqual(d.activeElement.id, 'vpn-backends-title', 'an unlisted backend lands on the backends card');
const summary = d.getElementById('vpn-fwd-headline-summary');
assert(summary && summary.textContent.includes('no longer in the current list'),
    'and the operator is told the backend is no longer listed');
console.log('VPN955_R7_BACKEND_ABSENT_OK');
})();
`, "VPN955_R7_BACKEND_ABSENT_OK")
	})
}

// TestVPN955GlobalConditionDestinationIsCategoryAware proves the no-entity
// fallback routes by category: a backend-scoped global condition belongs on the
// backends card, while a non-backend global condition keeps its existing
// connection/routing destination. Both are asserted in one run so the fix cannot
// pass by repointing every global fallback at the backends card.
func TestVPN955GlobalConditionDestinationIsCategoryAware(t *testing.T) {
	runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;
const backendsTitle = d.getElementById('vpn-backends-title');
const sessionsTitle = d.getElementById('vpn-troubleshooting-title');
assert(backendsTitle && sessionsTitle, 'both destination headings exist in the template');
assert.strictEqual(backendsTitle.getAttribute('tabindex'), '-1', 'the backends heading is a real focus target');

// 1. A backend-scoped global condition: no entity id, category backend. This is
// "No healthy backends available to route traffic" from the diagnostics engine.
d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        conditions: [{ severity: 'CRITICAL', category: 'backend', message: 'No healthy backends available to route traffic' }]
    }
});
const list = d.getElementById('vpn-fwd-problem-list');
assert.strictEqual(list.children.length, 1, 'the global condition is listed once');
assert(list.children[0].textContent.includes('No healthy backends available'), 'and it carries the backend explanation');
list.children[0].children[1].click();
assert.strictEqual(d.activeElement, backendsTitle, 'a backend-scoped global condition lands on the backends card');
assert.notStrictEqual(d.activeElement, sessionsTitle, 'and not on the sessions card');

// 2. A non-backend global condition: still no entity id, but the condition is
// about the dataplane/connection surface, so the existing destination stands.
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        conditions: [{ severity: 'CRITICAL', category: 'engine', message: 'Forwarder dataplane is not active' }]
    }
});
const list2 = d.getElementById('vpn-fwd-problem-list');
assert.strictEqual(list2.children.length, 1, 'the second global condition is listed once');
assert(list2.children[0].textContent.includes('Forwarder dataplane is not active'), 'and it carries the engine explanation');
list2.children[0].children[1].click();
assert.strictEqual(d.activeElement, sessionsTitle, 'a non-backend global condition keeps the connection destination');
assert.notStrictEqual(d.activeElement, backendsTitle, 'and does not move to the backends card');
console.log('VPN955_R7_GLOBAL_DESTINATION_OK');
})();
`, "VPN955_R7_GLOBAL_DESTINATION_OK")
}

// TestVPN955GlobalDestinationMappingIsAnAllowList proves the category routing is an
// explicit allow list rather than a default: an unlisted category must keep the
// existing destination, so a future category cannot be silently pulled onto the
// backends card by a fallback that only knows one branch.
func TestVPN955GlobalDestinationMappingIsAnAllowList(t *testing.T) {
	runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
assert.strictEqual(typeof w.vpnIssueDestinationHeading, 'function', 'the mapping is reachable from the page');
// Listed: the backend surface. The payload's category is compared case-insensitively
// because it arrives as a JSON string, but no trimming is claimed: nothing in the
// diagnostics payload pads a category.
['backend', 'BACKEND'].forEach(function (c) {
    assert.strictEqual(w.vpnIssueDestinationHeading(c), 'vpn-backends-title',
        'category ' + JSON.stringify(c) + ' resolves to the backends card');
});
// Unlisted: everything else keeps the connection destination, including the empty
// and missing cases that reach the fallback with no category at all.
['engine', 'routing', 'dataplane', 'peer_sync', 'queue_pressure', 'sessions', '', undefined, null]
    .forEach(function (c) {
        assert.strictEqual(w.vpnIssueDestinationHeading(c), 'vpn-troubleshooting-title',
            'category ' + JSON.stringify(c) + ' keeps the connection destination');
    });
console.log('VPN955_R7_DESTINATION_MAPPING_OK');
})();
`, "VPN955_R7_DESTINATION_MAPPING_OK")
}
