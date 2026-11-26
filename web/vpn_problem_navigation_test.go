package web

import (
	"strings"
	"testing"
)

// Inspect navigation regressions.
//
// Two defects were reported by the owner and reproduced in source:
//
//   - the backend match compared the problem's backend TUNNEL id (the payload's
//     backend_id, populated from the session/route tunnel id) against the row's
//     SERVER id, so a backend whose two ids differ could never be found;
//   - the no-entity fallback always landed on the sessions card heading, so a
//     backend-scoped global condition put the operator in the sessions table.
//
// The backend inventory is its own document now, so a backend Inspect is a
// cross-document handoff. These tests assert what the diagnostics side actually
// does — which id it carries, and where it goes — while the row-level reveal is
// asserted on the backends document (see the reveal tests). Each pair includes a
// control that must stay green so a fix cannot pass by swapping one wrong
// destination for another.

// navigationBindingPrelude records the handoff destination instead of driving a
// real navigation, so the decision is observable without leaving the document.
const navigationBindingPrelude = `
assert.strictEqual(typeof w.vpnFocusIssueTarget, 'function',
    'the JSDOM window must bind vpnFocusIssueTarget from the diagnostics controller');
w.__navDestinations = [];
w.vpnNavigateToBackends = function (targetId) { w.__navDestinations.push('/vpn/backends#' + targetId); };
function lastDestination() {
    return w.__navDestinations.length ? w.__navDestinations[w.__navDestinations.length - 1] : null;
}
`

// runVPNProblemNavigationScript requires the harness to execute, even locally.
// The shared fixture's optional dependency probe can skip before any assertion
// runs, leaving the enclosing test and package green.
func runVPNProblemNavigationScript(t *testing.T, assertions, wantToken string) {
	t.Helper()
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	if fixture.NodePath == "" {
		t.Fatal("Inspect navigation tests require Node.js (see CONTRIBUTING.md)")
	}
	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: navigationBindingPrelude + assertions})
	out, err := execNodeScript(fixture.NodePath, script)
	if err != nil {
		t.Fatalf("navigation script failed: %v\nOutput:\n%s", err, out)
	}
	if strings.HasPrefix(string(out), "JSDOM_NOT_AVAILABLE:") {
		t.Fatalf("Inspect navigation tests require jsdom; install it and set NODE_PATH (see CONTRIBUTING.md):\n%s", out)
	}
	if !strings.HasSuffix("\n"+strings.TrimSpace(string(out)), "\n"+wantToken) {
		t.Fatalf("navigation script did not report %q\nOutput:\n%s", wantToken, out)
	}
}

// TestVPN955BackendInspectMatchesBackendIdentity proves the handoff carries the
// backend's TUNNEL id, never its server id. The ids are deliberately distinct: a
// test using equal ids would pass on the broken comparison.
func TestVPN955BackendInspectMatchesBackendIdentity(t *testing.T) {
	t.Run("DistinctTunnelAndServerIds", func(t *testing.T) {
		runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;

// The diagnostics payload reports backend_id from the session/route tunnel id.
// These two backends sit on servers 7 and 8, so the two id spaces differ.
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
assert.deepStrictEqual(w.__navDestinations, [], 'rendering alone must not navigate');

const summary = d.getElementById('vpn-fwd-headline-summary');
const summaryBefore = summary ? summary.textContent : '';

d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();

assert.strictEqual(w.vpnConsumeBackendHandoff(), '43', 'the handoff carries tunnel 43, not server 8');
assert.strictEqual(lastDestination(), '/vpn/backends#vpn-backends-title', 'and it goes to the inventory heading');
assert.strictEqual(w.vpnConsumeBackendHandoff(), null, 'the one-shot slot is consumed exactly once');
assert.strictEqual(d.getElementById('vpn-diagnostics').hidden, true, 'Inspect never opens Advanced Diagnostics');
if (summary) {
    assert(!summary.textContent.includes('no longer in the current list'),
        'the diagnostics page makes no missing statement about a backend it cannot see');
    assert.strictEqual(summary.textContent, summaryBefore, 'a backend Inspect leaves the headline summary alone');
}
console.log('VPN955_R7_BACKEND_DISTINCT_IDS_OK');
})();
`, "VPN955_R7_BACKEND_DISTINCT_IDS_OK")
	})

	t.Run("EqualTunnelAndServerIdsCarryTheSameId", func(t *testing.T) {
		// Control: the behaviour that already worked must keep working.
		runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 9, category: 'backend' }]
    }
});
d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();
assert.strictEqual(w.vpnConsumeBackendHandoff(), '9', 'a backend whose ids are equal still hands off its id');
assert.strictEqual(lastDestination(), '/vpn/backends#vpn-backends-title', 'and reaches the inventory heading');
console.log('VPN955_R7_BACKEND_EQUAL_IDS_OK');
})();
`, "VPN955_R7_BACKEND_EQUAL_IDS_OK")
	})

	t.Run("UnlistedBackendStillHandsOffRatherThanClaimingMissing", func(t *testing.T) {
		// The diagnostics document cannot know whether the backend exists: it holds no
		// inventory. It hands the id over and says nothing; the destination reports a
		// missing row only after its own successful read.
		runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 999, category: 'backend' }]
    }
});
d.getElementById('vpn-fwd-problem-list').children[0].children[1].click();
assert.strictEqual(w.vpnConsumeBackendHandoff(), '999', 'the unknown id is handed over for the destination to judge');
const summary = d.getElementById('vpn-fwd-headline-summary');
assert(summary && !summary.textContent.includes('no longer in the current list'),
    'the diagnostics page does not claim a backend is missing');
console.log('VPN955_R7_BACKEND_ABSENT_OK');
})();
`, "VPN955_R7_BACKEND_ABSENT_OK")
	})
}

// TestVPN955GlobalConditionDestinationIsCategoryAware proves the no-entity
// fallback routes by category: a backend-scoped global condition belongs on the
// backends document, while a non-backend global condition keeps its existing
// connection/routing destination. Both are asserted in one run so the fix cannot
// pass by repointing every global fallback at the backends page.
func TestVPN955GlobalConditionDestinationIsCategoryAware(t *testing.T) {
	runVPNProblemNavigationScript(t, `
(() => {
const assert = require('assert');
const d = w.document;
const sessionsTitle = d.getElementById('vpn-troubleshooting-title');
assert(sessionsTitle, 'the sessions heading exists in the template');

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
assert.strictEqual(lastDestination(), '/vpn/backends#vpn-backends-title', 'a backend-scoped global condition goes to the inventory');
assert.strictEqual(w.vpnConsumeBackendHandoff(), null, 'with no entity id there is no one-shot handoff to replay');

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
assert.strictEqual(w.__navDestinations.length, 1, 'and never navigates away from diagnostics');
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
        'category ' + JSON.stringify(c) + ' resolves to the backends surface');
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
