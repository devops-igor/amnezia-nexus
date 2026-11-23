package web

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// Issue #955 round 9: Inspect must REVEAL its target before focusing it.
//
// Three review rounds missed this because every earlier navigation test rendered a
// table that never hid anything. The JSDOM fixture did not even install NexusTable,
// so no row was ever display:none and "focus lands on the row" was true for free.
//
// A row can be unreachable in two different ways, needing different handling:
//
//   - the sessions problems-only filter EXCLUDES a session before rendering, so the
//     row does not exist and the old code told the operator the session was gone
//     while it was still in the data — a false statement, not a failed jump;
//   - NexusTable HIDES a backend row with display:none for a search term, a status
//     filter or a page it is not showing, so the row exists and focus() was called
//     on a cell inside an invisible row, which does nothing on screen.
//
// Two harness facts shape every test below:
//
//  1. A regression must establish the hiding state and ASSERT IT before the click.
//  2. JSDOM moves document.activeElement onto a display:none element, so
//     `activeElement === cell` is TRUE for a focus call that does nothing visible.
//     Visibility is therefore read from the computed style of the element and its
//     ancestors. Without that, the assertions hold for the old broken code too —
//     which is how the previous round's guard ended up hollow.

// runVPNRevealScript runs a navigation assertion against the real NexusTable
// controller. It fails rather than skipping when Node or jsdom is missing: a guard
// whose only job is to catch a regression must not print the same green `ok` as its
// own absence.
func runVPNRevealScript(t *testing.T, assertions, wantToken string) {
	t.Helper()
	fixture := NewVPNTestFixture(t)
	if fixture.NodePath == "" {
		t.Fatal("Inspect reveal tests require Node.js (see CONTRIBUTING.md)")
	}
	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{IncludeNexusTable: true, ExtraJS: assertions})
	out, err := execNodeScript(fixture.NodePath, script)
	if err != nil {
		t.Fatalf("reveal script failed: %v\nOutput:\n%s", err, out)
	}
	if strings.HasPrefix(string(out), "JSDOM_NOT_AVAILABLE:") {
		t.Fatalf("Inspect reveal tests require jsdom; install it and set NODE_PATH (see CONTRIBUTING.md):\n%s", out)
	}
	if strings.Contains(string(out), "no tests to run") {
		t.Fatalf("reveal script did not execute any assertion:\n%s", out)
	}
	if !strings.HasSuffix("\n"+strings.TrimSpace(string(out)), "\n"+wantToken) {
		t.Fatalf("reveal script did not report %q\nOutput:\n%s", wantToken, out)
	}
}

// vpnRevealPreconditionsJS installs the visibility oracle and the row lookups. It is
// shared, so each regression differs only in the hiding condition it establishes.
const vpnRevealPreconditionsJS = `
const d = w.document;
// Visible means the browser would paint it: JSDOM still moves activeElement onto a
// display:none node, so focus alone cannot answer this question.
function isVisible(el) {
    let n = el;
    while (n && n.nodeType === 1) {
        const cs = w.getComputedStyle(n);
        if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
        n = n.parentElement;
    }
    return true;
}
function sessionRow(sessionId) {
    return Array.from(d.getElementById('vpn-sessions-tbody').children)
        .find(function (r) { return r && r.getAttribute && r.getAttribute('data-session-id') === sessionId; }) || null;
}
function backendRow(tunnelId) {
    return Array.from(d.getElementById('vpn-backends-tbody').children)
        .find(function (r) { return r && r.getAttribute && r.getAttribute('data-tunnel-id') === tunnelId; }) || null;
}
function inspectProblem(index) {
    d.getElementById('vpn-fwd-problem-list').children[index || 0].children[1].click();
}
`

// vpnRevealBackendsTableJS renders a backend table with tunnel ids 41..52 on server
// ids 1..12 plus one extra backend (tunnel 60 on server 7), so a search term and a
// page each have something real to hide. Tunnel ids are unique: a duplicated id
// would make every row lookup ambiguous and the test would prove nothing.
const vpnRevealBackendsTableJS = `
w.vpnCachedServers = [{ id: 1, name: 'Alpha Gateway' }, { id: 3, name: 'Gamma' }, { id: 7, name: 'Delta' }, { id: 12, name: 'Beta Relay' }];
const btbody = d.getElementById('vpn-backends-tbody');
btbody.textContent = '';
for (let i = 1; i <= 12; i++) {
    btbody.appendChild(w.vpnRenderBackendRow({ id: 40 + i, server_id: i, endpoint: '198.51.100.' + i + ':51820', enabled: true, status: 'active', latency_ms: 10, active_connections: 1 }));
}
// One more backend, named by a tunnel id no other row uses, so it is the only row
// an Inspect for 60 can land on and it is reachable by a distinctive search term.
btbody.appendChild(w.vpnRenderBackendRow({ id: 60, server_id: 7, endpoint: '203.0.113.7:51820', enabled: true, status: 'active', latency_ms: 12, active_connections: 2 }));
w.vpnTableInstance = new w.NexusTable('#vpnBackendsTable', {
    searchable: true, sortable: true, paginate: true, pageSize: 10,
    statusFilters: ['all', 'active', 'degraded', 'disabled'], statusAttribute: 'data-status'
});
`

// vpnRevealSessionsFixtureJS renders two sessions: one whose route is genuinely
// pressured, which the problems-only filter keeps, and one whose route looks clean.
// The health assessment still reports a problem for the second one, which is the
// case the owner described: a real problem row whose session the filter hides. The
// filter only inspects route pressure/drops/stalls, so it excludes a session whose
// route carries no pressure even when the assessment reports a problem for it.
//
// The routes travel ON the health payload: vpnRenderForwarderHealth assigns that
// payload to vpnLastStatus, which is the only place vpnFindRouteForSession reads. A
// fixture that set vpnLastStatus separately would have it replaced by the payload
// and the filter would then judge every session route-less.
const vpnRevealSessionsFixtureJS = `
const sessionRoutes = [
    { session_id: 'S-pressure', traffic: {}, has_pressure: true, queue_full_drops_recent: 4, write_errors_recent: 0, write_stalls_recent: 0 },
    { session_id: 'S-quiet', traffic: {}, queue_full_drops_recent: 0, write_errors_recent: 0, write_stalls_recent: 0 }
];
w.vpnLastSessions = { sessions: [
    { session_id: 'S-pressure', username: 'alice', status: 'connected', server_name: 'Alpha' },
    { session_id: 'S-quiet', username: 'bob', status: 'connected', server_name: 'Alpha' }
] };
w.renderSessions(w.vpnLastSessions.sessions);
function queuePressureProblem() {
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        all_routes: sessionRoutes,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [{ severity: 'DEGRADED', category: 'routing', message: 'Return queue full drops (4 recent) for 10.8.0.4', session_id: 'S-quiet' }]
        }
    });
}
`

// TestVPN955R9BackendReveal proves Inspect reveals a backend row that NexusTable is
// hiding, for each of the three independent reasons a row can be hidden.
func TestVPN955R9BackendReveal(t *testing.T) {
	t.Run("HiddenByPagination", func(t *testing.T) {
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealBackendsTableJS+`
const target = backendRow('52');
assert(target, 'the backend on page 2 is present in the DOM');
const cell = target.querySelector('td[data-backend-name]');
assert(cell && cell.getAttribute('tabindex') !== null, 'its name cell is focusable');
// PRE-CONDITION: pagination really hides it. Without this the rest proves nothing.
assert.strictEqual(target.style.display, 'none', 'the target backend is hidden by pagination before Inspect');
assert.strictEqual(isVisible(cell), false, 'and its name cell is not painted');
assert.strictEqual(w.vpnTableInstance.currentPage, 1, 'and the table is on page 1');

d.getElementById('vpn-advanced-entry').focus();
assert.strictEqual(d.activeElement.id, 'vpn-advanced-entry', 'focus starts away from the table');

w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 52, category: 'backend' }]
    }
});
assert.strictEqual(target.style.display, 'none', 'rendering the problem alone reveals nothing');

inspectProblem();

// OUTCOME: the row is painted, focus is on it, and the table shows its page.
assert.strictEqual(isVisible(cell), true, 'Inspect revealed the paginated backend row');
assert.notStrictEqual(target.style.display, 'none', 'its own row style is no longer hiding it');
assert.strictEqual(w.vpnTableInstance.currentPage, 2, 'the table navigated to the page holding the target');
assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed backend cell');
assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '12', 'and on the reported backend');
console.log('VPN955_R9_BACKEND_PAGE_OK');
})();
`, "VPN955_R9_BACKEND_PAGE_OK")
	})

	t.Run("HiddenBySearch", func(t *testing.T) {
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealBackendsTableJS+`
const target = backendRow('60');
const cell = target.querySelector('td[data-backend-name]');

// PRE-CONDITION: the operator's own search term hides the target.
w.vpnTableInstance.search('nothing-matches-this');
assert.strictEqual(target.style.display, 'none', 'the target backend is hidden by the search box before Inspect');
assert.strictEqual(isVisible(cell), false, 'and its name cell is not painted');
assert.strictEqual(w.vpnTableInstance.searchQuery, 'nothing-matches-this', 'and that search term is what hides it');

d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 60, category: 'backend' }]
    }
});
assert.strictEqual(target.style.display, 'none', 'rendering the problem alone reveals nothing');

inspectProblem();

assert.strictEqual(isVisible(cell), true, 'Inspect revealed the search-hidden backend row');
assert.strictEqual(w.vpnTableInstance.searchQuery, '', 'the conflicting search term was cleared');
assert.strictEqual(w.vpnTableInstance.searchInputEl.value, '', 'and the search box no longer shows it');
assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed backend cell');
console.log('VPN955_R9_BACKEND_SEARCH_OK');
})();
`, "VPN955_R9_BACKEND_SEARCH_OK")
	})

	t.Run("HiddenByStatusFilter", func(t *testing.T) {
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealBackendsTableJS+`
const target = backendRow('60');
const cell = target.querySelector('td[data-backend-name]');

// PRE-CONDITION: the operator's own status chip hides the target. The row is marked
// active, so the "degraded" chip excludes it.
w.vpnTableInstance.setFilter('degraded');
assert.strictEqual(target.style.display, 'none', 'the target backend is hidden by the status chip before Inspect');
assert.strictEqual(isVisible(cell), false, 'and its name cell is not painted');
assert.strictEqual(w.vpnTableInstance.currentStatusFilter, 'degraded', 'and that chip is what hides it');

d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 60, category: 'backend' }]
    }
});
assert.strictEqual(target.style.display, 'none', 'rendering the problem alone reveals nothing');

inspectProblem();

assert.strictEqual(isVisible(cell), true, 'Inspect revealed the status-hidden backend row');
assert.strictEqual(w.vpnTableInstance.currentStatusFilter, 'all', 'the conflicting status filter was cleared');
assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed backend cell');
console.log('VPN955_R9_BACKEND_FILTER_OK');
})();
`, "VPN955_R9_BACKEND_FILTER_OK")
	})

	t.Run("StatusChipMovesWithTheFilter", func(t *testing.T) {
		// The chip is the control the operator reads the filter from, so clearing the
		// filter without moving the chip would make the toolbar lie about the table.
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealBackendsTableJS+`
const wrapper = d.getElementById('vpnBackendsTable').closest('.card') || d.body;
const chips = Array.from(wrapper.querySelectorAll('.filter-chip'));
assert.strictEqual(chips.length, 4, 'the table built its four status chips');
const chipFor = function (status) {
    return chips.find(function (c) { return c.getAttribute('data-status') === status; }) || null;
};
const degradedChip = chipFor('degraded');
const allChip = chipFor('all');
assert(degradedChip && allChip, 'the degraded and all chips exist');

// PRE-CONDITION: the filter is degraded, and the chip says so.
w.vpnTableInstance.setFilter('degraded');
assert(degradedChip.classList.contains('active'), 'the degraded chip is active before Inspect');
assert(!allChip.classList.contains('active'), 'and All is not');
assert.strictEqual(backendRow('60').style.display, 'none', 'the row is hidden');

w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 60, category: 'backend' }]
    }
});
inspectProblem();

// OUTCOME: the row is painted and the toolbar shows the filter the table now uses.
assert.strictEqual(isVisible(backendRow('60')), true, 'the row was revealed');
assert(allChip.classList.contains('active'), 'the All chip is now the active one');
assert(!degradedChip.classList.contains('active'), 'and the stale degraded chip is not');
console.log('VPN955_R9_CHIP_SYNC_OK');
})();
`, "VPN955_R9_CHIP_SYNC_OK")
	})
}

// TestVPN955R9SessionProblemsOnlyReveal covers the sessions path, where the filter
// does not hide the row — it excludes the session before rendering, so the row does
// not exist and the old code reported a session that was present as missing.
func TestVPN955R9SessionProblemsOnlyReveal(t *testing.T) {
	t.Run("ExcludedSessionIsRevealedNotReportedMissing", func(t *testing.T) {
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealSessionsFixtureJS+`
queuePressureProblem();
const summary = d.getElementById('vpn-fwd-headline-summary');

// PRE-CONDITION: the operator turned on problems-only. It does not hide rows; it
// excludes them from rendering, so the target must genuinely be absent from the DOM
// while its neighbour with the pressured route is still listed.
// Turning the filter on through its own handler, so the state and the control agree.
w.vpnToggleSessionsProblemFilter();
assert.strictEqual(w.vpnSessionsFilterOnlyProblems, true, 'problems-only is on before Inspect');
assert(!sessionRow('S-quiet'), 'the target session has NO row while problems-only is on');
assert(sessionRow('S-pressure'), 'while the session with a pressured route is still listed');
assert.strictEqual(d.getElementById('vpn-fwd-problem-list').hidden, false, 'and a problem row is listed');

d.getElementById('vpn-advanced-entry').focus();
assert.strictEqual(d.activeElement.id, 'vpn-advanced-entry', 'focus starts away from the table');

inspectProblem();

// OUTCOME: a row now exists, it is painted, and focus is on it.
const tr = sessionRow('S-quiet');
assert(tr, 'Inspect produced a row for the session that exists in the data');
const cell = tr.querySelector('[data-action="vpn-toggle-session"]');
assert(cell, 'the revealed row carries its action cell');
assert.strictEqual(isVisible(cell), true, 'the revealed session cell is painted');
assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed session cell');
assert.strictEqual(d.activeElement.getAttribute('data-session-id'), 'S-quiet', 'and on the reported session');

// The old code told the operator this session was gone. That statement is false.
assert(!summary.textContent.includes('no longer in the current list'),
    'the operator is not told a session that exists is missing (summary=' + JSON.stringify(summary.textContent) + ')');

// The revealed detail is open, which is what the operator asked to see.
assert(tr.classList.contains('row-expanded'), 'the drill-down for the revealed session is open');
console.log('VPN955_R9_SESSION_REVEAL_OK');
})();
`, "VPN955_R9_SESSION_REVEAL_OK")
	})

	t.Run("ProblemsOnlyChoiceIsLeftClearedAndShownInTheControl", func(t *testing.T) {
		// The declared decision: the problems-only preference is LEFT CLEARED for the
		// reveal, and the toolbar button says so. Restoring it would re-render the
		// list without the row and hide the detail the operator just asked for.
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealSessionsFixtureJS+`
queuePressureProblem();

const btn = d.getElementById('vpn-sessions-toggle-problems-btn');
const label = d.getElementById('vpn-sessions-toggle-problems-text');

// Turning the filter on through its own handler, so the state and the control agree.
w.vpnToggleSessionsProblemFilter();
// PRE-CONDITION: the control shows the filter as ON.
assert.strictEqual(w.vpnSessionsFilterOnlyProblems, true, 'problems-only is on');
assert(btn.classList.contains('btn-primary'), 'the button reads as pressed while the filter is on');
assert(!sessionRow('S-quiet'), 'and the target row does not exist');
const showAllLabel = label.textContent;

inspectProblem();

// OUTCOME: the flag and the control agree, and both now read as cleared.
assert.strictEqual(w.vpnSessionsFilterOnlyProblems, false, 'the problems-only flag was cleared for the reveal');
assert(!btn.classList.contains('btn-primary'), 'the button no longer reads as pressed');
assert(btn.classList.contains('btn-ghost'), 'and it is back to its inactive style');
assert.notStrictEqual(label.textContent, showAllLabel, 'the label changed with the state, so the change is visible');

// And the choice is genuinely cleared, not merely hidden: every session is listed
// again, with the target among them and painted.
assert(sessionRow('S-quiet') && sessionRow('S-pressure'), 'both sessions are listed after the reveal');
assert.strictEqual(isVisible(sessionRow('S-quiet')), true, 'including the target, which is painted');
console.log('VPN955_R9_SESSION_FILTER_DECISION_OK');
})();
`, "VPN955_R9_SESSION_FILTER_DECISION_OK")
	})

	t.Run("RepeatedInspectKeepsTheDetailVisible", func(t *testing.T) {
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealSessionsFixtureJS+`
queuePressureProblem();

// Turning the filter on through its own handler, so the state and the control agree.
w.vpnToggleSessionsProblemFilter();
assert(!sessionRow('S-quiet'), 'PRE-CONDITION: the row does not exist');

inspectProblem();
const first = sessionRow('S-quiet');
assert(first && first.classList.contains('row-expanded'), 'the first Inspect reveals and opens the detail');
assert.strictEqual(isVisible(first.querySelector('[data-action="vpn-toggle-session"]')), true, 'the revealed row is painted');
assert.strictEqual(d.activeElement, first.querySelector('[data-action="vpn-toggle-session"]'), 'the first Inspect focuses it');

// A second Inspect must keep the detail open, not toggle it shut.
inspectProblem();
const second = sessionRow('S-quiet');
assert(second, 'the row is still present after a second Inspect');
assert(second.classList.contains('row-expanded'), 'a second Inspect keeps the drill-down open');
assert.strictEqual(isVisible(second.querySelector('[data-action="vpn-toggle-session"]')), true, 'the row is still painted');
assert.strictEqual(d.activeElement, second.querySelector('[data-action="vpn-toggle-session"]'),
    'a second Inspect keeps focus on the session cell');
assert(!d.getElementById('vpn-fwd-headline-summary').textContent.includes('no longer in the current list'),
    'and still says nothing about a missing session');
console.log('VPN955_R9_SESSION_IDEMPOTENT_OK');
})();
`, "VPN955_R9_SESSION_IDEMPOTENT_OK")
	})

	t.Run("HiddenByPaginationOnTheSessionsTable", func(t *testing.T) {
		// The sessions table paginates at 10 too, so a session on page 2 is the same
		// defect in the other table. The row exists but is display:none.
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+`
// 12 sessions on clean routes: the problems-only filter would keep all of them, so
// this case is purely about pagination.
const routes = [];
const sessions = [];
for (let i = 1; i <= 12; i++) {
    routes.push({ session_id: 'S-' + i, traffic: {}, queue_full_drops_recent: 0, write_errors_recent: 0, write_stalls_recent: 0 });
    sessions.push({ session_id: 'S-' + i, username: 'user' + i, status: 'connected', server_name: 'Alpha' });
}
w.vpnLastSessions = { sessions: sessions };
w.renderSessions(sessions);

// PRE-CONDITION: the sessions table paginates and the target is on page 2.
assert(w.vpnSessionsTableInstance, 'renderSessions built the sessions table from the shipped controller');
const target = sessionRow('S-12');
assert(target, 'the page-2 session exists in the DOM');
assert.strictEqual(target.style.display, 'none', 'and pagination hides it');
assert.strictEqual(w.vpnSessionsTableInstance.currentPage, 1, 'while the table shows page 1');

d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    all_routes: routes,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'No route', session_id: 'S-12', category: 'routing' }]
    }
});
// The health render re-renders the sessions table, so the row captured above is now
// detached. Re-read it: the row an operator sees is the one in the document.
assert.strictEqual(sessionRow('S-12').style.display, 'none', 'rendering the problem alone reveals nothing');

inspectProblem();

const revealedRow = sessionRow('S-12');
assert(revealedRow, 'the session row is in the document after Inspect');
assert.strictEqual(isVisible(revealedRow.querySelector('[data-action="vpn-toggle-session"]')), true,
    'Inspect revealed the session on page 2');
assert.strictEqual(w.vpnSessionsTableInstance.currentPage, 2, 'the sessions table navigated to its page');
assert.strictEqual(d.activeElement, revealedRow.querySelector('[data-action="vpn-toggle-session"]'),
    'focus landed on the revealed session cell');
assert(!d.getElementById('vpn-fwd-headline-summary').textContent.includes('no longer in the current list'),
    'and the session is not reported as missing');
console.log('VPN955_R9_SESSION_PAGE_OK');
})();
`, "VPN955_R9_SESSION_PAGE_OK")
	})

	t.Run("GenuinelyAbsentSessionStillReportsMissing", func(t *testing.T) {
		// The reveal must not turn the fallback into a reveal-everything path.
		runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealSessionsFixtureJS+`
// The problem names a session that is in NO payload at all.
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'No route', session_id: 'S-gone', category: 'routing' }]
    }
});
// PRE-CONDITION: it really is absent from the data and from the DOM.
assert.strictEqual(w.vpnFindSessionById('S-gone'), null, 'the id is absent from the polled sessions');
assert(!sessionRow('S-gone'), 'and no row exists for it');

d.getElementById('vpn-advanced-entry').focus();
inspectProblem();

const summary = d.getElementById('vpn-fwd-headline-summary');
assert(summary && summary.textContent.includes('no longer in the current list'),
    'a genuinely absent session still tells the operator it is gone (summary=' + JSON.stringify(summary && summary.textContent) + ')');
assert.strictEqual(d.activeElement.id, 'vpn-troubleshooting-title', 'and focus lands on the sessions card');
assert(!sessionRow('S-gone'), 'no row was invented for it');
console.log('VPN955_R9_SESSION_ABSENT_OK');
})();
`, "VPN955_R9_SESSION_ABSENT_OK")
	})
}

// TestVPN955R9BackendRevealPreservesIdentity keeps the round 7 fix honest: the
// reveal must resolve the row by TUNNEL id, so revealing cannot pass by matching
// whatever backend it finds first.
func TestVPN955R9BackendRevealPreservesIdentity(t *testing.T) {
	runVPNRevealScript(t, `
(() => {
const assert = require('assert');
`+vpnRevealPreconditionsJS+vpnRevealBackendsTableJS+`
const targetA = backendRow('43');
const targetB = backendRow('52');
assert(targetA && targetB, 'both targets are listed');
assert.strictEqual(targetB.style.display, 'none', 'PRE-CONDITION: the page-2 target is hidden');

d.getElementById('vpn-advanced-entry').focus();
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 52, category: 'backend' }]
    }
});
inspectProblem();
assert.strictEqual(d.activeElement, targetB.querySelector('td[data-backend-name]'), 'Inspect focuses the reported backend');
assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '12', 'which is server 12, its own server id');

// The other target, addressed by its own tunnel id, still resolves to itself.
w.vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 43, category: 'backend' }]
    }
});
inspectProblem();
assert.strictEqual(d.activeElement, targetA.querySelector('td[data-backend-name]'), 'the second Inspect focuses the other backend');
assert.strictEqual(d.activeElement.getAttribute('data-backend-name'), '3', 'and it is backend 43 (server 3), not its neighbour');
console.log('VPN955_R9_IDENTITY_OK');
})();
`, "VPN955_R9_IDENTITY_OK")
}

// TestVPN955R9RevealGoesThroughTheTableController keeps the fix inside the table
// controller: the VPN page must not reach into a row and clear its display itself,
// or the table's own page/filter state would disagree with the DOM.
func TestVPN955R9RevealGoesThroughTheTableController(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatal(err)
	}
	pageJSBytes, err := fs.ReadFile(staticFS, "js/vpn/page.js")
	if err != nil {
		t.Fatal(err)
	}
	pageJS := string(pageJSBytes)
	for _, forbidden := range []string{".style.display = ''", `.style.display = ""`} {
		if strings.Contains(pageJS, forbidden) {
			t.Errorf("page.js must reveal through the table controller, not by assigning row styles (%q)", forbidden)
		}
	}
	if !strings.Contains(pageJS, "revealRow") {
		t.Error("page.js must reveal its target through NexusTable.revealRow")
	}
	// Pagination and filters stay enabled: the fix navigates them, it does not remove
	// the capability the operator uses.
	if !strings.Contains(pageJS, "paginate: true") {
		t.Error("the backends table must keep pagination enabled")
	}
	if !strings.Contains(pageJS, "statusFilters: ['all', 'active', 'degraded', 'disabled']") {
		t.Error("the backends table must keep its status filters")
	}
	tablesBytes, err := fs.ReadFile(staticFS, "js/tables.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tablesBytes), "revealRow(rowEl)") {
		t.Error("NexusTable must expose revealRow so a caller never reimplements its filtering")
	}
}

// TestVPN955R9RevealRegressionsFailWithoutTheFix is the oracle check the previous
// round was missing: the regressions run against bytes that reproduce the OLD
// behaviour and each must fail. A regression that stays green under that variant is
// not testing the fix, which is exactly what happened last round.
func TestVPN955R9RevealRegressionsFailWithoutTheFix(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	if fixture.NodePath == "" {
		t.Fatal("Inspect reveal tests require Node.js (see CONTRIBUTING.md)")
	}
	// The old behaviour, as page.js bytes. Replacing the module in the harness is how
	// the variant reaches the page without touching the reviewed tree.
	reverted := *fixture
	reverted.PageJS = revertPageReveal(t)
	if reverted.PageJS == fixture.PageJS {
		t.Fatal("the reverted page.js is byte-identical to the delivered one, so the variant proves nothing")
	}

	for _, tc := range []struct{ name, token, setup string }{
		{
			name:  "BackendHiddenByPagination",
			token: "VPN955_R9_BACKEND_PAGE_OK",
			setup: `
const target = backendRow('52');
const cell = target.querySelector('td[data-backend-name]');
assert.strictEqual(target.style.display, 'none', 'PRE-CONDITION: the target is hidden by pagination');
assert.strictEqual(isVisible(cell), false, 'and its cell is not painted');
w.vpnRenderForwarderHealth({ forwarder_available: true, health_assessment: { status: 'CRITICAL', actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 52, category: 'backend' }] } });
inspectProblem();
assert.strictEqual(isVisible(cell), true, 'the row is revealed');
assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed backend cell');
`,
		},
		{
			name:  "BackendHiddenBySearch",
			token: "VPN955_R9_BACKEND_SEARCH_OK",
			setup: `
const target = backendRow('60');
const cell = target.querySelector('td[data-backend-name]');
w.vpnTableInstance.search('nothing-matches-this');
assert.strictEqual(target.style.display, 'none', 'PRE-CONDITION: the operator search hides the target');
assert.strictEqual(isVisible(cell), false, 'and its cell is not painted');
w.vpnRenderForwarderHealth({ forwarder_available: true, health_assessment: { status: 'CRITICAL', actionable_problems: [{ severity: 'CRITICAL', message: 'Backend unhealthy', backend_id: 60, category: 'backend' }] } });
inspectProblem();
assert.strictEqual(isVisible(cell), true, 'the row is revealed');
assert.strictEqual(d.activeElement, cell, 'focus landed on the revealed backend cell');
`,
		},
		{
			name:  "SessionHiddenByPagination",
			token: "VPN955_R9_SESSION_PAGE_OK",
			setup: `
const routes = [], pageSessions = [];
for (let i = 1; i <= 12; i++) {
    routes.push({ session_id: 'S-' + i, traffic: {}, queue_full_drops_recent: 0, write_errors_recent: 0, write_stalls_recent: 0 });
    pageSessions.push({ session_id: 'S-' + i, username: 'user' + i, status: 'connected', server_name: 'Alpha' });
}
w.vpnLastSessions = { sessions: pageSessions };
w.renderSessions(pageSessions);
assert.strictEqual(sessionRow('S-12').style.display, 'none', 'PRE-CONDITION: the sessions table hides page 2');
w.vpnRenderForwarderHealth({ forwarder_available: true, all_routes: routes, health_assessment: { status: 'CRITICAL', actionable_problems: [{ severity: 'CRITICAL', message: 'No route', session_id: 'S-12', category: 'routing' }] } });
inspectProblem();
const revealed = sessionRow('S-12');
assert(revealed, 'a row exists for the session');
assert.strictEqual(isVisible(revealed.querySelector('[data-action="vpn-toggle-session"]')), true, 'and it is painted');
`,
		},
		{
			name:  "SessionExcludedByProblemsOnly",
			token: "VPN955_R9_SESSION_REVEAL_OK",
			setup: `
// Turning the filter on through its own handler, so the state and the control agree.
w.vpnToggleSessionsProblemFilter();
assert(!sessionRow('S-quiet'), 'PRE-CONDITION: problems-only excludes the target session entirely');
w.vpnRenderForwarderHealth({ forwarder_available: true, health_assessment: { status: 'DEGRADED', conditions: [{ severity: 'DEGRADED', category: 'routing', message: 'Return queue full drops (4 recent) for 10.8.0.4', session_id: 'S-quiet' }] } });
inspectProblem();
const tr = sessionRow('S-quiet');
assert(tr, 'a row exists for the session');
assert.strictEqual(isVisible(tr.querySelector('[data-action="vpn-toggle-session"]')), true, 'and it is painted');
assert(!d.getElementById('vpn-fwd-headline-summary').textContent.includes('no longer in the current list'),
    'the operator is not told a session that exists is missing');
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := reverted.BuildJSDOMHarness(JSDOMHarnessOptions{IncludeNexusTable: true, ExtraJS: fmt.Sprintf(`
(() => {
const assert = require('assert');
%s
%s
%s
console.log('%s');
})();
`, vpnRevealPreconditionsJS, vpnRevealBackendsTableJS, tsSetup(tc.name)+tc.setup, tc.token)})
			out, err := execNodeScript(fixture.NodePath, script)
			if err == nil {
				t.Fatalf("the regression passed against the OLD behaviour, so it does not test the fix\nOutput:\n%s", out)
			}
			if strings.Contains(string(out), tc.token) {
				t.Fatalf("the old behaviour still reported the success token, so the oracle is hollow\nOutput:\n%s", out)
			}
			if !strings.Contains(string(out), "AssertionError") {
				t.Fatalf("expected an assertion failure, got:\n%s", out)
			}
		})
	}
}

// tsSetup installs the sessions fixture only for the sessions variant, so the
// backend variants are not distracted by a second table's data.
func tsSetup(name string) string {
	// The problems-only variant needs the two-session fixture. The pagination variant
	// builds its own twelve sessions, so the two-session fixture would replace them.
	if name == "SessionExcludedByProblemsOnly" {
		return vpnRevealSessionsFixtureJS + "\n"
	}
	return ""
}

// revertPageReveal returns page.js as it was before the reveal fix: both focus
// functions call focus on whatever the lookup returns without asking the table to
// make the row visible. Every symbol is retained, so the variant is executable.
func revertPageReveal(t *testing.T) string {
	t.Helper()
	fixture := NewVPNTestFixture(t)
	page := fixture.PageJS
	old := strings.Replace(page,
		"    const tr = vpnRevealSessionRow(wanted);",
		"    const tr = vpnFindSessionRow(wanted);", 1)
	if old == page {
		t.Fatal("could not revert the session reveal call; the variant would not reproduce the old behaviour")
	}
	afterBackend := strings.Replace(old,
		"    const found = vpnFindBackendRowByTunnelId(document.getElementById('vpn-backends-tbody'), row.backendId);\n    const tr = vpnRevealBackendRow(found);",
		"    const tr = vpnFindBackendRowByTunnelId(document.getElementById('vpn-backends-tbody'), row.backendId);", 1)
	if afterBackend == old {
		t.Fatal("could not revert the backend reveal call; the variant would not reproduce the old behaviour")
	}
	return afterBackend
}
