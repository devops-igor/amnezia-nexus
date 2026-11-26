package web

import (
	"testing"
)

func TestVPNSummaryHeaderCountsAndProblemCardOnset(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	tmplStr := fixture.CombinedSource()

	assertions := `
const el = id => document.getElementById(id);

// 1. Degraded forwarder with 2 actionable problems across 1 user and 2 connection configs
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Packet loss observed on active connections',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Buffer pressure on forwarder route',
				category: 'routing',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-1',
				connection_name: 'alice-phone',
				assigned_ip: '10.8.0.2',
				first_observed: '2026-10-07T12:30:00Z'
			},
			{
				severity: 'CRITICAL',
				message: 'Buffer full drops active',
				category: 'dataplane',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-2',
				connection_name: 'alice-laptop',
				assigned_ip: '10.8.0.3',
				first_observed: '2026-10-07T12:35:00Z'
			}
		]
	}
});

// The old separate summary strip is folded into one counts line under the summary.
const summaryCounts = el('vpn-fwd-problem-counts');
assert(summaryCounts, 'folded problem counts element must exist');
assert.strictEqual(summaryCounts.hidden, false, 'counts line is visible when problems exist');
assert(summaryCounts.textContent.includes('2 active problems'), 'must show 2 active problems');
assert(summaryCounts.textContent.includes('1 affected users'), 'must show 1 unique affected user');
assert(summaryCounts.textContent.includes('2 client configs'), 'must show 2 unique affected client configs');

// Assert Problem Card Onset Timestamps
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 2, 'must render 2 problem cards');

// Rows sort critical-first, so the CRITICAL problem (12:35) is row 0.
const card0 = problemList.children[0];
assert(card0.className.includes('vpn-issue'), 'card 0 must have the issue row class');
assert(card0.textContent.includes('Onset:'), 'card 0 must render onset label');
assert(card0.textContent.includes('2026-10-07 12:35:00 UTC'), 'card 0 must render its first_observed timestamp');
assert(card0.textContent.includes('Config: alice-laptop'));
assert(card0.textContent.includes('User: alice'));

const card1 = problemList.children[1];
assert(card1.className.includes('vpn-issue'), 'card 1 must have the issue row class');
assert(card1.textContent.includes('Onset:'), 'card 1 must render onset label');
assert(card1.textContent.includes('2026-10-07 12:30:00 UTC'), 'card 1 must render its first_observed timestamp');
assert(card1.textContent.includes('Config: alice-phone'));
assert(card1.textContent.includes('User: alice'));

// 2. Nominal forwarder (0 problems): summary header must be hidden, nominal green badge rendered
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'HEALTHY',
		conditions: []
	},
	peer_sync: { actual_peers: 5, desired_peers: 5 },
	backends: { healthy_count: 2, total_count: 2 }
});

assert.strictEqual(summaryCounts.hidden, true, 'counts line is hidden when healthy (0 problems)');
assert.strictEqual(problemList.children.length, 0, 'healthy renders no problem rows and no nominal banner');

// 3. Unavailable forwarder: summary header must be hidden
vpnRenderForwarderHealth(null);
assert.strictEqual(summaryCounts.hidden, true, 'counts line is hidden when unavailable');

// 4. Degraded forwarder with generic conditions but empty actionable_problems: summary header must display active problems count from conditions
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Fleet degradation detected',
		conditions: [
			{ severity: 'DEGRADED', message: 'High packet loss on gateway', category: 'dataplane' },
			{ severity: 'WARN', message: 'Queue pressure elevated', category: 'routing' },
			{ severity: 'DEGRADED', message: 'Backend latency elevated', category: 'backends' }
		],
		actionable_problems: []
	}
});

assert.strictEqual(summaryCounts.hidden, false, 'counts line is visible for conditions');
assert(summaryCounts.textContent.includes('3 active problems'), 'counts show 3 active problems from conditions');
assert(!summaryCounts.textContent.includes('affected users'), 'no affected-user claim when no actionable problem names a user');
assert(!summaryCounts.textContent.includes('client configs'), 'no client-config claim when no actionable problem names a config');

// 5. Critical forwarder with 1 condition and missing actionable_problems: summary header fallback
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		summary: 'Critical failure',
		conditions: [
			{ severity: 'CRITICAL', message: 'Listener stopped' }
		]
	}
});
assert.strictEqual(summaryCounts.hidden, false, 'counts line is visible for a critical condition');
assert(summaryCounts.textContent.includes('1 active problems'), 'counts show 1 active problem from the condition');

// 6. Warning-only condition with empty actionable_problems: summary header must display active problems count
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'HEALTHY',
		summary: 'Warning condition present',
		conditions: [
			{ severity: 'WARNING', message: 'Cert expiring soon', category: 'cert' }
		],
		actionable_problems: []
	}
});
assert.strictEqual(summaryCounts.hidden, false, 'counts line is visible for a warning condition');
assert(summaryCounts.textContent.includes('1 active problems'), 'counts show 1 active problem from the warning condition');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("summary header counts and onset timestamp test failed: %v\n%s", err, out)
	}
}

func TestVPNForwarderCombinedActionableAndGenericConditions(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	tmplStr := fixture.CombinedSource()

	assertions := `
const el = id => document.getElementById(id);

// Critical backend condition occurring simultaneously with a degraded route
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		summary: 'Active VPN session routing or dataplane issues detected',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Return queue full drops (5 recent) for 10.8.0.2',
				category: 'dataplane',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-1',
				connection_name: 'alice-phone',
				assigned_ip: '10.8.0.2',
				backend_id: 1,
				observed_rate: '2.5 drops/s',
				first_observed: '2026-10-08T10:00:00Z'
			}
		],
		conditions: [
			{
				severity: 'CRITICAL',
				message: 'No healthy backends available to route traffic',
				category: 'backend'
			}
		]
	}
});

// 1. Folded counts cover both classes of problem.
const summaryCounts = el('vpn-fwd-problem-counts');
assert(summaryCounts, 'folded problem counts element must exist');
assert.strictEqual(summaryCounts.hidden, false, 'counts line is visible');
assert(summaryCounts.textContent.includes('2 active problems'), 'counts both classes: 1 actionable + 1 condition = 2 active problems');
assert(summaryCounts.textContent.includes('1 affected users'), 'counts 1 affected user from the actionable problem');
assert(summaryCounts.textContent.includes('1 client configs'), 'counts 1 client config from the actionable problem');

// 2. Assert Both Problem Cards are rendered in #vpn-fwd-problem-list
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 2, 'problem list must render both problem cards');

// Rows are sorted critical-first, so the critical problem is row 0.
const card0 = problemList.children[0];
assert(card0.className.includes('vpn-issue'), 'card 0 must have the issue row class');
assert.strictEqual(card0.getAttribute('data-severity'), 'critical', 'rows sort critical first');
assert(card0.textContent.includes('No healthy backends available to route traffic'), 'card 0 carries the explanation');

const card1 = problemList.children[1];
assert(card1.className.includes('vpn-issue'), 'card 1 must have the issue row class');
assert(card1.textContent.includes('Degraded'), 'card 1 severity is Degraded');
assert(card1.textContent.includes('Return queue full drops (5 recent) for 10.8.0.2'));
assert(card1.textContent.includes('User: alice'));
assert(card1.textContent.includes('Config: alice-phone'));
assert(card1.textContent.includes('IP: 10.8.0.2'));
assert(card1.textContent.includes('2.5 drops/s'));

// 3. Deduplication: exact duplicate condition must not be rendered twice
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Degraded',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Duplicate event message',
				category: 'dataplane'
			}
		],
		conditions: [
			{
				severity: 'DEGRADED',
				message: 'Duplicate event message',
				category: 'dataplane'
			}
		]
	}
});
assert.strictEqual(problemList.children.length, 1, 'duplicate event must not render redundant card');
assert(el('vpn-fwd-problem-counts').textContent.includes('1 active problems'), 'counts line reports 1 active problem when deduplicated');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("combined actionable and generic conditions test failed: %v\n%s", err, out)
	}
}

// The problem card names the affected user, connection, address and backend. The
// vehicle is a surviving problem class (route queue drops); handshake age no
// longer produces a problem row (#964).
func TestVPNForwarderProblemCardIdentitiesDOM(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	tmplStr := fixture.CombinedSource()

	assertions := `
const el = id => document.getElementById(id);

// Supply a status payload containing an actionable problem with user/connection
// identities, as the surviving dataplane synthesiser emits it.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Dataplane drops reported on an active route',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Return queue full drops (5 recent) for 10.8.0.2',
				message_key: 'vpn_problem_route_queue_drops',
				category: 'dataplane',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-1',
				connection_name: 'alice-phone',
				assigned_ip: '10.8.0.2',
				backend_id: 1,
				first_observed: '2026-10-08T12:00:00Z'
			}
		]
	}
});

// 1. Folded counts: 1 active problem, 1 affected user, 1 client config.
const summaryCounts = el('vpn-fwd-problem-counts');
assert(summaryCounts, 'folded problem counts element must exist');
assert.strictEqual(summaryCounts.hidden, false, 'counts line is visible');
assert(summaryCounts.textContent.includes('1 active problems'), 'counts 1 active problem');
assert(summaryCounts.textContent.includes('1 affected users'), 'counts 1 affected user');
assert(summaryCounts.textContent.includes('1 client configs'), 'counts 1 client config');

// 2. Assert Problem Card: rendered with user and connection metadata badges
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 1, 'must render 1 problem card');
const card = problemList.children[0];
assert(card.className.includes('vpn-issue'), 'card must have problem-card class');
assert(card.textContent.includes(_('vpn_problem_route_queue_drops')), 'card must render the localized explanation');
assert(card.textContent.includes('User: alice'), 'card must contain user badge');
assert(card.textContent.includes('Config: alice-phone'), 'card must contain connection config badge');
assert(card.textContent.includes('IP: 10.8.0.2'), 'card must contain IP badge');
assert(card.textContent.includes('Backend 1'), 'card must contain backend badge');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("problem card identity DOM test failed: %v\n%s", err, out)
	}
}

// Issue #457 Rework Round 5: Routing Consistency panel badge and alerts must be severity-aware.
// Sparse/benign return mismatch drops produce WARNING severity and must render badge-warning
// with var(--warning) alert color, while CRITICAL and DEGRADED routing issues retain badge-danger
// and var(--danger).
func TestVPNRoutingConsistencyBadgeSeverityAware(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	tmplStr := fixture.CombinedSource()

	assertions := `
const routBadge = document.getElementById('vpn-diag-routing-badge');
const routAlerts = document.getElementById('vpn-diag-routing-alerts');

// Case 1: Consistent routing -> badge-success
vpnRenderForwarderHealth({
    forwarder_available: true,
    routing_consistency: {
        is_consistent: true,
        active_routes_count: 5,
        active_sessions_count: 5
    },
    health_assessment: {
        status: 'HEALTHY',
        conditions: []
    }
});
assert.strictEqual(routBadge.className, 'badge badge-success', 'consistent routing must have badge-success');
assert.strictEqual(routBadge.textContent, _('vpn_fwd_consistent'), 'consistent routing badge text');
assert.strictEqual(routAlerts.hidden, true, 'alerts hidden when consistent');

// Case 2: Inconsistent with only WARNING routing condition (e.g. sparse return mismatch)
// -> must render badge-warning and alert color var(--warning)
vpnRenderForwarderHealth({
    forwarder_available: true,
    routing_consistency: {
        is_consistent: false,
        ownership_mismatch_drops: 3,
        inconsistency_details: ['Return-direction ownership mismatch: 3 drops']
    },
    health_assessment: {
        status: 'HEALTHY',
        conditions: [
            { category: 'routing', severity: 'WARNING', message: 'Return-direction ownership mismatch' }
        ]
    }
});
assert.strictEqual(routBadge.className, 'badge badge-warning', 'routing with only WARNING condition must use badge-warning');
assert.strictEqual(routBadge.textContent, _('vpn_fwd_inconsistent'), 'inconsistent text preserved');
assert.strictEqual(routAlerts.hidden, false, 'alerts displayed');
assert.strictEqual(routAlerts.style.color, 'var(--warning)', 'alerts text must use var(--warning) for WARNING routing condition');
assert.strictEqual(routAlerts.textContent, 'Return-direction ownership mismatch: 3 drops');

// Case 3: Inconsistent with status.conditions (direct array) having only WARNING routing condition
vpnRenderForwarderHealth({
    forwarder_available: true,
    routing_consistency: {
        is_consistent: false,
        ownership_mismatch_drops: 3,
        inconsistency_details: ['Return-direction ownership mismatch: 3 drops']
    },
    conditions: [
        { category: 'routing', severity: 'WARNING', message: 'Return-direction ownership mismatch' }
    ]
});
assert.strictEqual(routBadge.className, 'badge badge-warning', 'direct status.conditions with only WARNING must use badge-warning');
assert.strictEqual(routAlerts.style.color, 'var(--warning)', 'direct status.conditions alert must use var(--warning)');

// Case 4: Inconsistent with DEGRADED routing condition (e.g. sustained return mismatch)
// -> must retain badge-danger and alert color var(--danger)
vpnRenderForwarderHealth({
    forwarder_available: true,
    routing_consistency: {
        is_consistent: false,
        ownership_mismatch_drops: 10,
        inconsistency_details: ['Sustained return ownership mismatch: 10 drops']
    },
    health_assessment: {
        status: 'DEGRADED',
        conditions: [
            { category: 'routing', severity: 'DEGRADED', message: 'Sustained return ownership mismatch' }
        ]
    }
});
assert.strictEqual(routBadge.className, 'badge badge-danger', 'degraded routing must retain badge-danger');
assert.strictEqual(routAlerts.style.color, 'var(--danger)', 'degraded routing alerts must retain var(--danger)');

// Case 5: Inconsistent with CRITICAL routing condition (e.g. client ownership mismatch)
// -> must retain badge-danger and alert color var(--danger)
vpnRenderForwarderHealth({
    forwarder_available: true,
    routing_consistency: {
        is_consistent: false,
        ownership_mismatch_drops: 1,
        inconsistency_details: ['Client ownership mismatch: 1 drop']
    },
    health_assessment: {
        status: 'CRITICAL',
        conditions: [
            { category: 'routing', severity: 'CRITICAL', message: 'Client ownership mismatch' }
        ]
    }
});
assert.strictEqual(routBadge.className, 'badge badge-danger', 'critical routing must retain badge-danger');
assert.strictEqual(routAlerts.style.color, 'var(--danger)', 'critical routing alerts must retain var(--danger)');

// Case 6: Mixed routing conditions (WARNING + CRITICAL) -> CRITICAL wins, must retain badge-danger
vpnRenderForwarderHealth({
    forwarder_available: true,
    routing_consistency: {
        is_consistent: false,
        ownership_mismatch_drops: 4,
        inconsistency_details: ['Multiple routing anomalies']
    },
    health_assessment: {
        status: 'CRITICAL',
        conditions: [
            { category: 'routing', severity: 'WARNING', message: 'Return ownership mismatch' },
            { category: 'routing', severity: 'CRITICAL', message: 'Client ownership mismatch' }
        ]
    }
});
assert.strictEqual(routBadge.className, 'badge badge-danger', 'mixed routing conditions with CRITICAL must retain badge-danger');
assert.strictEqual(routAlerts.style.color, 'var(--danger)', 'mixed routing alerts must retain var(--danger)');
`

	script, err := vpnDiagnosticsHealthScriptLocale(t, tmplStr, "en", assertions)
	if err != nil {
		t.Fatal(err)
	}
	out, err := execNodeScript(node, script)
	if err != nil {
		t.Fatalf("TestVPNRoutingConsistencyBadgeSeverityAware failed: %v\n%s", err, string(out))
	}
}

// TestVPNSessionRowCarriesNoDropCounter covers the sessions-row consequence of
// issue #976. The forwarder drop counter used to colour a per-session cell; that
// cell is gone from the table and the counters remain available in Advanced
// Diagnostics. What stays true, and is asserted here, is that neither the
// lifetime nor the recent drop count reaches the row, that pressure and recent
// drops still decide the status badge, and that a session whose payload carries
// no traffic counters reports the localized not-measured state rather than a
// number that would read as measured traffic.
func TestVPNSessionRowCarriesNoDropCounter(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	node := fixture.RequireNode()

	assertions := `
const tbody = document.getElementById('vpn-sessions-tbody');

// Route 1: Dan has historical drops (10) and queue pressure (occupancy 95/100,
// has_pressure: true), but ZERO recent drops and ZERO drop rate pps. Those
// counters no longer have a cell; the row must not leak them.
// Route 2: Eve has recent drops (5 recent out of 20 total) and no active rate.
// Recent drops still decide the status badge, and nothing else in the row.
vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.4',
            connection_id: '104',
            session_id: 'sess-dan',
            occupancy: 95,
            capacity: 100,
            drops: 10,
            queue_full_drops_recent: 0,
            queue_full_drop_rate_pps: 0,
            has_pressure: true
        },
        {
            assigned_ip: '10.8.0.5',
            connection_id: '105',
            session_id: 'sess-eve',
            occupancy: 10,
            capacity: 100,
            drops: 20,
            queue_full_drops_recent: 5,
            queue_full_drop_rate_pps: 0,
            has_pressure: false
        }
    ]
};

const sessions = [
    {
        id: 1,
        session_id: 'sess-dan',
        connection_id: '104',
        username: 'dan',
        connection_name: 'dan-phone',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.4',
        status: 'connected'
    },
    {
        id: 2,
        session_id: 'sess-eve',
        connection_id: '105',
        username: 'eve',
        connection_name: 'eve-laptop',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.5',
        status: 'connected'
    }
];

vpnLastSessions = { sessions: sessions };
renderSessions(sessions);

assert.strictEqual(tbody.children.length, 2, 'table must render 2 session rows');

// Row 0: Dan (historical drops + queue pressure)
const rowDan = tbody.children[0];
assert.strictEqual(rowDan.children.length, 5, 'the session row has 5 cells');
assert.strictEqual(rowDan.children[3].textContent, 'Not measured', 'no traffic counters means the explicit not-measured state');
assert(!/drops/i.test(rowDan.textContent), 'the drop counter must not reach the session row: ' + rowDan.textContent);
assert(![rowDan.children[2], rowDan.children[3], rowDan.children[4]].some(c => c.textContent.includes('10')), 'the lifetime drop count must not reach the telemetry or status cells');
assert(!rowDan.innerHTML.includes('text-danger'), 'the row must not colour-carry the drop counter');
assert(rowDan.children[4].innerHTML.includes('badge-warn'), 'queue pressure still drives the degraded status badge');

// Row 1: Eve (recent drops without a pps rate)
const rowEve = tbody.children[1];
assert.strictEqual(rowEve.children.length, 5, 'the session row has 5 cells');
assert.strictEqual(rowEve.children[3].textContent, 'Not measured', 'no traffic counters means the explicit not-measured state');
assert(!/drops/i.test(rowEve.textContent), 'the recent drop counter must not reach the session row: ' + rowEve.textContent);
assert(![rowEve.children[2], rowEve.children[3], rowEve.children[4]].some(c => c.textContent.includes('20')), 'the lifetime drop count must not reach the telemetry or status cells');
assert(!rowEve.innerHTML.includes('text-danger'), 'recent drops no longer paint a danger cell in the row');
assert(rowEve.children[4].innerHTML.includes('badge-warn'), 'recent drops continue to drive the status badge');
`

	script := vpnConnectionTroubleshootingScriptLocale(t, fixture.TemplateHTML, fixture.CompanionScripts(), "en", assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("drop-counter-free session row test (en) failed: %v\n%s", err, out)
	}

	// The not-measured state is a localized string, not an English literal.
	ruAssertions := `
const tbody = document.getElementById('vpn-sessions-tbody');
vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.5',
            connection_id: '105',
            session_id: 'sess-eve',
            occupancy: 10,
            capacity: 100,
            drops: 20,
            queue_full_drops_recent: 5,
            queue_full_drop_rate_pps: 0,
            has_pressure: false
        }
    ]
};
const sessions = [
    {
        id: 1,
        session_id: 'sess-eve',
        connection_id: '105',
        username: 'eve',
        connection_name: 'eve-laptop',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.5',
        status: 'connected'
    }
];
vpnLastSessions = { sessions: sessions };
renderSessions(sessions);

const transferredEve = tbody.children[0].children[3];
assert.strictEqual(transferredEve.textContent, 'Не измерено', 'Russian: the not-measured state must be localized');
assert(!transferredEve.innerHTML.includes('text-danger'), 'Russian: no danger styling without a counter');
`
	ruScript := vpnConnectionTroubleshootingScriptLocale(t, fixture.TemplateHTML, fixture.CompanionScripts(), "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("drop-counter-free session row test (ru) failed: %v\n%s", err, out)
	}
}
