package web

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestVPNSummaryHeaderCountsAndProblemCardOnset(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixture(t)
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

// Assert Summary Header Counts
const summaryHeader = el('vpn-fwd-summary-header');
assert(summaryHeader, 'summary header element must exist');
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when problems exist');
assert(summaryHeader.textContent.includes('2 active problems'), 'must show 2 active problems');
assert(summaryHeader.textContent.includes('1 affected users'), 'must show 1 unique affected user');
assert(summaryHeader.textContent.includes('2 client configs'), 'must show 2 unique affected client configs');
assert(summaryHeader.innerHTML.includes('badge-warn'), 'summary header must have badge styling');

// Assert Problem Card Onset Timestamps
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 2, 'must render 2 problem cards');

const card0 = problemList.children[0];
assert(card0.className.includes('problem-card'), 'card 0 must have problem-card class');
assert(card0.textContent.includes('Onset:'), 'card 0 must render onset label');
assert(card0.textContent.includes('2026-10-07 12:30:00 UTC'), 'card 0 must render first_observed timestamp');
assert(card0.textContent.includes('Config: alice-phone'));
assert(card0.textContent.includes('User: alice'));

const card1 = problemList.children[1];
assert(card1.className.includes('problem-card'), 'card 1 must have problem-card class');
assert(card1.textContent.includes('Onset:'), 'card 1 must render onset label');
assert(card1.textContent.includes('2026-10-07 12:35:00 UTC'), 'card 1 must render first_observed timestamp');
assert(card1.textContent.includes('Config: alice-laptop'));
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

assert.strictEqual(summaryHeader.style.display, 'none', 'summary header must be hidden when healthy (0 problems)');
assert.strictEqual(problemList.children.length, 1);
const greenBadge = problemList.children[0];
assert(greenBadge.className.includes('badge-success'), 'nominal summary must have badge-success class');
assert(greenBadge.textContent.includes('No active problems detected'), 'nominal green badge text must show when 0 problems');

// 3. Unavailable forwarder: summary header must be hidden
vpnRenderForwarderHealth(null);
assert.strictEqual(summaryHeader.style.display, 'none', 'summary header must be hidden when unavailable');

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

assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when conditions exist during degradation');
assert(summaryHeader.textContent.includes('3 active problems'), 'summary header must show 3 active problems from conditions');
assert(summaryHeader.textContent.includes('0 affected users'), 'affected users count must be 0 in conditions fallback');
assert(summaryHeader.textContent.includes('0 client configs'), 'affected client configs count must be 0 in conditions fallback');
assert(summaryHeader.innerHTML.includes('badge-warn'), 'summary header must retain badge styling');

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
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when critical with condition');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must show 1 active problem from condition');
assert(summaryHeader.textContent.includes('0 affected users'), 'affected users count must be 0 in conditions fallback');
assert(summaryHeader.textContent.includes('0 client configs'), 'affected client configs count must be 0 in conditions fallback');

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
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when warning condition exists');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must show 1 active problem from warning condition');
assert(summaryHeader.textContent.includes('0 affected users'), 'affected users count must be 0 in conditions fallback');
assert(summaryHeader.textContent.includes('0 client configs'), 'affected client configs count must be 0 in conditions fallback');
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
	fixture := NewVPNTestFixture(t)
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

// 1. Assert Summary Header Counts both classes of problems
const summaryHeader = el('vpn-fwd-summary-header');
assert(summaryHeader, 'summary header element must exist');
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed');
assert(summaryHeader.textContent.includes('2 active problems'), 'summary header must count both classes: 1 actionable + 1 condition = 2 active problems');
assert(summaryHeader.textContent.includes('1 affected users'), 'summary header must count 1 affected user from actionable problem');
assert(summaryHeader.textContent.includes('1 client configs'), 'summary header must count 1 client config from actionable problem');

// 2. Assert Both Problem Cards are rendered in #vpn-fwd-problem-list
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 2, 'problem list must render both problem cards');

const card0 = problemList.children[0];
assert(card0.className.includes('problem-card'), 'card 0 must have problem-card class');
assert.strictEqual(card0.children[0].textContent, 'Degraded', 'card 0 severity must be Degraded');
assert.strictEqual(card0.children[1].textContent, 'Return queue full drops (5 recent) for 10.8.0.2');
assert(card0.textContent.includes('User: alice'));
assert(card0.textContent.includes('Config: alice-phone'));
assert(card0.textContent.includes('IP: 10.8.0.2'));
assert(card0.textContent.includes('2.5 drops/s'));

const card1 = problemList.children[1];
assert(card1.className.includes('problem-card'), 'card 1 must have problem-card class');
assert.strictEqual(card1.children[0].textContent, 'Critical', 'card 1 severity must be Critical');
assert.strictEqual(card1.children[1].textContent, 'No healthy backends available to route traffic');
assert(card1.textContent.includes('backend'));

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
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must count 1 active problem when deduplicated');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("combined actionable and generic conditions test failed: %v\n%s", err, out)
	}
}

func TestVPNForwarderStaleHandshakeActionableProblemDOM(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixture(t)
	tmplStr := fixture.CombinedSource()

	assertions := `
const el = id => document.getElementById(id);

// Supply a status payload containing an actionable problem with message_key: "vpn_problem_stale_handshake" and user/connection identities
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'HEALTHY',
		summary: 'Operational with 1 warning condition(s)',
		actionable_problems: [
			{
				severity: 'WARNING',
				message: 'Upstream handshake stale (> 3m0s)',
				message_key: 'vpn_problem_stale_handshake',
				category: 'sessions',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-1',
				connection_name: 'alice-phone',
				assigned_ip: '10.8.0.2',
				backend_id: 1,
				first_observed: '2026-10-08T12:00:00Z'
			}
		],
		conditions: [
			{
				severity: 'WARNING',
				message: '1 active live session(s) have stale upstream handshakes (> 3m0s)',
				message_key: 'vpn_problem_stale_handshake',
				category: 'sessions'
			}
		]
	}
});

// 1. Assert Summary Header: displays 1 active problems • 1 affected users • 1 client configs
const summaryHeader = el('vpn-fwd-summary-header');
assert(summaryHeader, 'summary header element must exist');
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must show 1 active problem');
assert(summaryHeader.textContent.includes('1 affected users'), 'summary header must show 1 affected user');
assert(summaryHeader.textContent.includes('1 client configs'), 'summary header must show 1 client config');
assert(summaryHeader.innerHTML.includes('badge-warn'), 'summary header must retain badge styling');

// 2. Assert Problem Card: rendered with user and connection metadata badges
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 1, 'must render 1 problem card');
const card = problemList.children[0];
assert(card.className.includes('problem-card'), 'card must have problem-card class');
assert(card.textContent.includes('Upstream handshake stale'), 'card must render localized message');
assert(card.textContent.includes('User: alice'), 'card must contain user badge');
assert(card.textContent.includes('Config: alice-phone'), 'card must contain connection config badge');
assert(card.textContent.includes('IP: 10.8.0.2'), 'card must contain IP badge');
assert(card.textContent.includes('Backend 1'), 'card must contain backend badge');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("stale handshake DOM test failed: %v\n%s", err, out)
	}
}

func TestVPNForwarderStaleHandshakeEmptySnapshotMatchingCountsDOM(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixture(t)
	tmplStr := fixture.CombinedSource()

	// 1. Synthesize actionable problems with an empty non-nil peer map (0 portal peers snapshot)
	now := time.Now().UTC()
	sess := vpn.Session{
		ID:              "sess-empty-snap",
		UserID:          "usr-bob",
		Username:        "bob",
		ConnectionID:    "conn-bob",
		ConnectionName:  "bob-tablet",
		PeerPublicKey:   "pk-bob",
		AssignedIP:      "10.8.0.22",
		BackendTunnelID: 1,
		Status:          "connected",
	}
	routes := []forwarder.RouteInfo{
		{
			PeerKey:         "pk-bob",
			AssignedIP:      "10.8.0.22",
			SessionID:       "sess-empty-snap",
			ConnectionID:    "conn-bob",
			BackendTunnelID: 1,
		},
	}
	emptyPeerHandshakes := make(map[string]time.Time)
	problems := vpn.SynthesizeActionableProblemsWithHandshakes(routes, []vpn.Session{sess}, emptyPeerHandshakes, now)
	if len(problems) != 1 {
		t.Fatalf("expected 1 problem synthesized from empty peer snapshot, got %d", len(problems))
	}

	payloadJSON, err := json.Marshal(map[string]any{
		"forwarder_available": true,
		"health_assessment": map[string]any{
			"status":              "HEALTHY",
			"summary":             "Operational with 1 warning condition(s)",
			"actionable_problems": problems,
			"conditions": []map[string]any{
				{
					"severity":    "WARNING",
					"message":     "1 active live session(s) have stale upstream handshakes (> 3m0s)",
					"message_key": "vpn_problem_stale_handshake",
					"category":    "sessions",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	assertions := fmt.Sprintf(`
const el = id => document.getElementById(id);

vpnRenderForwarderHealth(%s);

// Verify summary header displays matching non-zero user and config counts:
// 1 active problems • 1 affected users • 1 client configs
const summaryHeader = el('vpn-fwd-summary-header');
assert(summaryHeader, 'summary header element must exist');
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must show 1 active problem');
assert(summaryHeader.textContent.includes('1 affected users'), 'summary header must show 1 affected user');
assert(summaryHeader.textContent.includes('1 client configs'), 'summary header must show 1 client config');
assert(summaryHeader.innerHTML.includes('badge-warn'), 'summary header must retain badge styling');

// Verify problem card renders with user and config badges
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 1, 'must render 1 problem card');
const card = problemList.children[0];
assert(card.textContent.includes('User: bob'), 'card must contain user badge');
assert(card.textContent.includes('Config: bob-tablet'), 'card must contain connection config badge');
assert(card.textContent.includes('IP: 10.8.0.22'), 'card must contain IP badge');
`, string(payloadJSON))

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("empty peer snapshot DOM test failed: %v\n%s", err, out)
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
	fixture := NewVPNTestFixture(t)
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
assert.strictEqual(routAlerts.style.display, 'none', 'alerts hidden when consistent');

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
assert.strictEqual(routAlerts.style.display, 'block', 'alerts displayed');
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

func TestVPNPacketLossCellDecoupledFromQueuePressure(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	node := fixture.RequireNode()
	combinedSource := fixture.CombinedSource()

	assertions := `
const tbody = document.getElementById('vpn-sessions-tbody');

// Route 1: Dan has historical drops (10) and queue pressure (occupancy 95/100, has_pressure: true),
// but ZERO recent drops and ZERO drop rate pps.
// Loss cell MUST NOT be red (no text-danger). Pressure cell MUST have badge-warn.
// Route 2: Eve has recent drops (5 recent out of 20 total, no pps rate).
// Loss cell MUST be red (text-danger) and use localized "recent" word.
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
const lossDan = rowDan.children[3];

// Loss cell MUST NOT be colored red
assert.strictEqual(lossDan.textContent, '10', 'Dan loss cell must display historical drops count 10');
assert(!lossDan.innerHTML.includes('text-danger'), 'Dan loss cell must NOT be red when only historical drops + pressure');

// Row 1: Eve (recent drops without pps rate)
const rowEve = tbody.children[1];
const lossEve = rowEve.children[3];

// Loss cell MUST be colored red with localized format
assert(lossEve.innerHTML.includes('text-danger'), 'Eve loss cell must have text-danger styling for recent drops');
assert(lossEve.textContent.includes('5 recent (20)'), 'Eve loss cell must format as "5 recent (20)"');
`

	script := vpnConnectionTroubleshootingScriptLocale(t, combinedSource, "en", assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("packet loss decoupling test (en) failed: %v\n%s", err, out)
	}

	// Also verify Russian translation of fallback format "5 недавних (20)"
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

const lossEve = tbody.children[0].children[3];
assert(lossEve.innerHTML.includes('text-danger'), 'Russian: Eve loss cell must have text-danger');
assert(lossEve.textContent.includes('5 недавних (20)'), 'Russian: Eve loss cell must use localized "недавних"');
`
	ruScript := vpnConnectionTroubleshootingScriptLocale(t, combinedSource, "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("packet loss decoupling test (ru) failed: %v\n%s", err, out)
	}
}
