package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func TestVPNDiagnosticsHealthAndStructure(t *testing.T) {
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	vpnData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)

	t.Run("RequiredDOMElements", func(t *testing.T) {
		requiredIDs := []string{
			"vpn-health-title",
			"vpn-fwd-status-badge",
			"vpn-fwd-status-text",
			"vpn-fwd-headline-summary",
			"vpn-fwd-problem-list",
			"vpn-advanced-entry",
			"vpn-diagnostics",
			"vpn-diagnostics-title",
			"vpn-traffic-performance",
			"vpn-routing-drops",
			"vpn-runtime-details",
			"vpn-close-diagnostics",
			"vpn-history-window-toggles",
			"vpn-session-mismatch",
			"vpn-signal-backends-value",
			"vpn-signal-throughput-value",
			"vpn-signal-drops-value",
			"vpn-configuration",
			"vpn-diag-throughput",
			"vpn-diag-ewma5m",
			"vpn-diag-ewma1h",
			"vpn-diag-lat-percentiles",
			"vpn-diag-queue-occ",
			"vpn-diag-queue-peak",
			"vpn-diag-drops-client",
			"vpn-diag-drops-return",
			"vpn-diag-drops-total",
			"vpn-diag-drop-reasons",
			"vpn-diag-engine-status",
			"vpn-diag-peers-status",
			"vpn-diag-hs-freshness",
			"vpn-diag-routing-badge",
			"vpn-diag-routing-counts",
			"vpn-diag-routing-alerts",
			"vpn-diag-res-cpu",
			"vpn-diag-res-mem",
			"vpn-diag-res-fd",
			"vpn-diag-be-traffic",
			"vpn-chart-throughput",
			"vpn-chart-queue",
			"vpn-chart-drops",
			"vpn-chart-latency",
			"vpn-troubleshooting-title",
			"vpn-sessions-count-badge",
			"vpn-sessions-toggle-problems-btn",
			"vpn-sessions-toggle-problems-text",
			"vpnSessionsTable",
			"vpn-sessions-tbody",
			"vpn-sessions-loading",
		}
		for _, id := range requiredIDs {
			if !strings.Contains(vpnStr, fmt.Sprintf(`id="%s"`, id)) {
				t.Errorf("vpn.html missing required element ID %q", id)
			}
		}

		// Advanced Diagnostics is one disclosure containing exactly the three
		// ordered regions, and the retired KPI/tech-details hooks are gone.
		if strings.Contains(vpnStr, `id="vpn-fwd-tech-details"`) {
			t.Error("retired #vpn-fwd-tech-details must not remain")
		}
		if strings.Contains(vpnStr, `id="vpn-kpi-`) {
			t.Error("retired #vpn-kpi-* tiles must not remain")
		}
		if strings.Contains(vpnStr, `id="vpn-fwd-summary-header"`) {
			t.Error("retired #vpn-fwd-summary-header must not remain")
		}
		diagStart := strings.Index(vpnStr, `<section class="card vpn-diagnostics" id="vpn-diagnostics"`)
		if diagStart == -1 {
			t.Fatal("missing #vpn-diagnostics region")
		}
		trafficRel := strings.Index(vpnStr[diagStart:], `id="vpn-traffic-performance"`)
		routingRel := strings.Index(vpnStr[diagStart:], `id="vpn-routing-drops"`)
		runtimeRel := strings.Index(vpnStr[diagStart:], `id="vpn-runtime-details"`)
		if trafficRel < 0 || routingRel < 0 || runtimeRel < 0 {
			t.Fatalf("missing diagnostic region: traffic=%d routing=%d runtime=%d", trafficRel, routingRel, runtimeRel)
		}
		if !(trafficRel < routingRel && routingRel < runtimeRel) {
			t.Errorf("diagnostic regions out of order: traffic=%d routing=%d runtime=%d", trafficRel, routingRel, runtimeRel)
		}
		// The health panel must precede the overview, which must precede diagnostics.
		healthIdx := strings.Index(vpnStr, `id="vpn-forwarder-card"`)
		overviewIdx := strings.Index(vpnStr, `class="stats-grid vpn-overview"`)
		if healthIdx < 0 || overviewIdx < 0 {
			t.Fatal("missing health panel or overview grid")
		}
		if !(healthIdx < overviewIdx && overviewIdx < diagStart) {
			t.Errorf("page order must be health < overview < diagnostics (got %d, %d, %d)", healthIdx, overviewIdx, diagStart)
		}
		// Exactly four signals in the overview.
		if got := strings.Count(vpnStr, `data-signal="`); got != 4 {
			t.Errorf("expected exactly 4 [data-signal] entries, got %d", got)
		}

		// The diagnostics panel starts collapsed and its entry says so, so nothing
		// depends on script execution to avoid an auto-opened panel.
		if !strings.Contains(vpnStr, `id="vpn-advanced-entry"`) {
			t.Error("missing #vpn-advanced-entry")
		}
		entryTagStart := strings.Index(vpnStr, `id="vpn-advanced-entry"`)
		entryTagEnd := strings.Index(vpnStr[entryTagStart:], ">")
		entryTag := vpnStr[entryTagStart : entryTagStart+entryTagEnd]
		if !strings.Contains(entryTag, `aria-expanded="false"`) {
			t.Errorf("Advanced Diagnostics entry must default to aria-expanded=\"false\": %s", entryTag)
		}
		if !strings.Contains(entryTag, `aria-controls="vpn-diagnostics"`) {
			t.Errorf("Advanced Diagnostics entry must control #vpn-diagnostics: %s", entryTag)
		}
		if !strings.Contains(vpnStr, `<section class="card vpn-diagnostics" id="vpn-diagnostics" aria-labelledby="vpn-diagnostics-title" hidden>`) {
			t.Error("#vpn-diagnostics must be hidden in the template")
		}
		// The health summary lives inside the single polite live region.
		if !strings.Contains(vpnStr, `id="vpn-fwd-health-live" role="status" aria-atomic="true"`) {
			t.Error("#vpn-fwd-health-live must be a polite atomic status region")
		}
		if !strings.Contains(vpnStr, `id="vpn-fwd-problem-announcement"`) {
			t.Error("the problem announcement sink is missing from the live region")
		}

		// Operational labels that moved into the definition-list shape.
		for _, labelKey := range []string{
			"vpn_diag_avg_5m",
			"vpn_diag_avg_1h",
			"vpn_diag_drops_outbound",
			"vpn_diag_drops_inbound",
			"vpn_diag_route_integrity",
			"vpn_signal_backends",
			"vpn_diag_active_sessions",
			"vpn_signal_drops",
			"vpn_dataplane_drops_scope",
		} {
			expectedTag := fmt.Sprintf(`{{ _ "%s" }}`, labelKey)
			if !strings.Contains(vpnStr, expectedTag) {
				t.Errorf("vpn.html missing label %s", labelKey)
			}
		}
	})

	t.Run("TranslationKeysInAllLanguages", func(t *testing.T) {
		transFS, err := GetTranslationsSubFS()
		if err != nil {
			t.Fatalf("GetTranslationsSubFS failed: %v", err)
		}

		requiredKeys := []string{
			"vpn_fwd_panel_performance",
			"vpn_fwd_panel_integrity",
			"vpn_fwd_panel_resources",
			"vpn_fwd_panel_traffic",
			"vpn_fwd_panel_queue",
			"vpn_fwd_panel_latency",
			"vpn_fwd_panel_drops",
			"vpn_fwd_panel_vtun",
			"vpn_fwd_panel_peer_sync",
			"vpn_fwd_panel_routing",
			"vpn_fwd_panel_backends",
			"vpn_fwd_panel_runtime",
			"vpn_fwd_panel_history",
			"vpn_fwd_panel_problems",
			"vpn_diag_avg_5m",
			"vpn_diag_avg_1h",
			"vpn_diag_drops_outbound",
			"vpn_diag_drops_inbound",
			"vpn_diag_route_integrity",
			"vpn_diag_no_active_drops",
			"vpn_fwd_upstream_to_nexus",
			"vpn_fwd_nexus_to_upstream",
			"vpn_fwd_show_all",
			"vpn_fwd_show_problems",
			"vpn_fwd_kpi_throughput",
			"vpn_fwd_kpi_routes",
			"vpn_fwd_kpi_pressure",
			"vpn_fwd_kpi_loss",
			"vpn_fwd_kpi_client_engine",
			"vpn_fwd_kpi_peer_sync",
			"vpn_fwd_kpi_backends",
			"vpn_fwd_kpi_slow_writes",
			"vpn_fwd_tech_diagnostics",
			"vpn_fwd_no_active_problems",
			"vpn_fwd_nominal_peers",
			"vpn_fwd_nominal_routes",
			"vpn_fwd_nominal_backends",
			"vpn_fwd_onset",
			"vpn_fwd_active_problems_count",
			"vpn_fwd_affected_users_count",
			"vpn_fwd_affected_configs_count",
			"vpn_fwd_loss_rate_format",
			"vpn_fwd_recent",
			"vpn_col_user_device",
			"vpn_col_live_traffic",
			"vpn_col_packet_loss",
			"vpn_col_queue_pressure",
			"vpn_show_all_connections",
			"vpn_show_problems_only",
			"vpn_troubleshooting_title",
			"vpn_drilldown_reservoir",
			"vpn_drilldown_dwell",
			"vpn_drilldown_write_stalls",
			"vpn_drilldown_write_errors",
			"vpn_drilldown_traffic_details",
			"vpn_drilldown_no_telemetry",
			"vpn_forwarder_unroutable",
		}

		languages := []string{"en.json", "ru.json", "fa.json", "fr.json", "zh.json"}
		for _, langFile := range languages {
			data, err := fs.ReadFile(transFS, langFile)
			if err != nil {
				t.Fatalf("failed to read %s: %v", langFile, err)
			}
			var dict map[string]string
			if err := json.Unmarshal(data, &dict); err != nil {
				t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
			}
			for _, k := range requiredKeys {
				val, ok := dict[k]
				if !ok || strings.TrimSpace(val) == "" {
					t.Errorf("%s missing required translation key %q", langFile, k)
				}
				if strings.Contains(val, "\u2014") {
					t.Errorf("%s key %s contains prohibited em dash (\\u2014): %q", langFile, k, val)
				}
			}
		}
	})

	t.Run("ExecutableJSDOMHealthAssessment", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Fatal("Node is required for diagnostics verification")
		}

		fixture := NewVPNTestFixture(t)
		runnerScript := vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + "\n" + fixture.HealthSummaryJS + `
const mockDoc = document;
const el = id => mockDoc.getElementById(id);
const text = id => mockDoc.getElementById(id).textContent;

// Test 1: HEALTHY state -- one quiet status, no nominal banner, no numeric zero
// invented for an unmeasured rate.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: { status: 'HEALTHY', summary: 'All clear and operational' },
    rates: { available: true, rx_bps: 1000000, tx_bps: 2000000 },
    routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
    backends: { eligibility_known: true, healthy_count: 2, enabled_count: 2, total_count: 2 }
});
assert.strictEqual(el('vpn-fwd-status-badge').className, 'badge badge-success');
assert.strictEqual(el('vpn-fwd-status-badge').hidden, false, 'status must become visible');
assert.strictEqual(text('vpn-fwd-status-text'), 'Healthy');
assert.strictEqual(text('vpn-fwd-headline-summary'), 'All clear and operational');
assert.strictEqual(el('vpn-fwd-problem-list').hidden, true, 'healthy renders no problem list at all');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 0, 'no nominal green banner row');
// The overview shows the four measured signals.
assert.strictEqual(text('vpn-signal-backends-value').replace(/\s+/g, ' ').trim(), '2 / 2');
assert.strictEqual(text('vpn-sessions'), '5');
assert.strictEqual(text('vpn-signal-throughput-value').replace(/\s+/g, ' ').trim(), '3.00 Mbps');
assert.strictEqual(el('vpn-session-mismatch').hidden, true);

// Test 2: DEGRADED state with a condition -- one explicit problem row.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'DEGRADED',
        summary: 'Elevated queue pressure',
        conditions: [{ severity: 'DEGRADED', message: 'Queue occupancy > 50%' }]
    }
});
assert.strictEqual(el('vpn-fwd-status-badge').className, 'badge badge-warn');
assert.strictEqual(text('vpn-fwd-status-text'), 'Degraded');
assert.strictEqual(el('vpn-fwd-problem-list').hidden, false);
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const degradedRow = el('vpn-fwd-problem-list').children[0];
assert(degradedRow.className.includes('vpn-issue'), 'problem row uses the issue pattern');
assert.strictEqual(degradedRow.getAttribute('data-severity'), 'degraded');
assert(degradedRow.textContent.includes('Degraded'), 'row carries severity text');
assert(degradedRow.textContent.includes('Queue occupancy > 50%'), 'row carries the human explanation');

// Test 3: CRITICAL state.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'CRITICAL',
        summary: 'Packet drops detected',
        conditions: [{ severity: 'CRITICAL', message: 'Queue full drops' }]
    }
});
assert.strictEqual(el('vpn-fwd-status-badge').className, 'badge badge-danger');
assert.strictEqual(text('vpn-fwd-status-text'), 'Critical');
assert.strictEqual(el('vpn-fwd-problem-list').children[0].getAttribute('data-severity'), 'critical');

// Test 4: UNAVAILABLE -- neutral status, never a healthy badge and never a numeric zero.
mockDoc.reset();
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-fwd-status-badge').className, 'badge', 'unavailable must not be badge-success');
assert(!el('vpn-fwd-status-badge').className.includes('badge-success'), 'unavailable must never read healthy');
assert.strictEqual(text('vpn-fwd-status-text'), 'Not reported');
assert.strictEqual(text('vpn-fwd-headline-summary'), 'Not reported');
assert.strictEqual(text('vpn-signal-throughput-value'), 'Not measured', 'unmeasured throughput is text, not 0');
assert.strictEqual(text('vpn-signal-drops-value'), 'Not measured', 'unmeasured drops are text, not 0');
assert.strictEqual(text('vpn-signal-backends-value'), 'Not measured');
assert.strictEqual(text('vpn-sessions'), 'Not measured');
assert.strictEqual(text('vpn-diag-lat-percentiles'), 'Not measured');

// Test 5: a true sampled zero stays numeric; an unmeasured value does not.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    rates: { available: true, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0 },
    drop_categories: { rates_available: true, total_drops: 0, total_drop_rate_pps: 0 },
    forward_latency: { p95_health_samples: 1, p95_health_ms: 0, p95_health_window_sec: 60 },
    health_assessment: { status: 'HEALTHY', conditions: [] }
});
assert.strictEqual(text('vpn-signal-throughput-value').replace(/\s+/g, ' ').trim(), '0 bps', 'measured zero throughput stays numeric');
assert.strictEqual(text('vpn-signal-drops-value').replace(/\s+/g, ' ').trim(), '0.00 drops/s', 'measured zero drop rate stays numeric');
assert(el('vpn-signal-drops-sub').textContent.includes('0 drops since reset'), 'cumulative total keeps its own label');
assert(!el('vpn-diag-lat-percentiles').textContent.includes('Not measured'), 'a sampled zero percentile is measured');
assert(el('vpn-diag-lat-percentiles').textContent.includes('0.0'), 'sampled zero p95 shows the numeric value');

// Test 6: an unsampled percentile is never a numeric zero, even with sentinel fields.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    forward_latency: { p95_health_samples: 0, p95_health_ms: 0, p50_ms: 1.5, p95_ms: 2.5, p99_ms: 3.5, write_total: 500 },
    health_assessment: { status: 'HEALTHY', conditions: [] }
});
assert.strictEqual(text('vpn-diag-lat-percentiles'), 'Not measured', 'write_total cannot prove a sample');

// Test 7: an unmeasured rate is never zero, and the two drop facts stay distinct.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    rates: { available: false, rx_bps: 0, tx_bps: 0 },
    drop_categories: { rates_available: false, total_drops: 46, total_drop_rate_pps: 0 },
    health_assessment: { status: 'HEALTHY', conditions: [] }
});
assert.strictEqual(text('vpn-signal-throughput-value'), 'Not measured', 'unavailable rate must not be 0');
assert.strictEqual(text('vpn-signal-drops-value'), 'Not measured', 'unavailable drop rate must not be 0');
assert(el('vpn-signal-drops-sub').textContent.includes('46 drops since reset'), 'the cumulative total is still reported independently');

// Test 8: a positive rate is a measurement.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    rates: { available: true, rx_bps: 1000000, tx_bps: 0 },
    drop_categories: { rates_available: true, total_drops: 100, total_drop_rate_pps: 3.5 },
    health_assessment: { status: 'HEALTHY', conditions: [] }
});
assert.strictEqual(text('vpn-signal-drops-value').replace(/\s+/g, ' ').trim(), '3.50 drops/s');
// The throughput signal is measured here, so its supporting line states the
// horizon rather than the no-samples text. This assertion previously read
// "el(...) === null || true", which cannot fail.
assert(el('vpn-signal-throughput-sub') !== null, 'the throughput signal keeps its supporting line');
assert.strictEqual(text('vpn-signal-throughput-sub'), _('vpn_signal_throughput_horizon'), 'a measured throughput states its horizon');
assert.strictEqual(text('vpn-signal-throughput-value').replace(/\s+/g, ' ').trim(), '1.00 Mbps', 'the rate renders from the payload');

// Test 9: disabled backends are not failures; eligibility unknown does not invent a denominator.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    backends: { eligibility_known: true, healthy_count: 1, enabled_count: 1, disabled_count: 2, total_count: 3 }
});
assert.strictEqual(text('vpn-signal-backends-value').replace(/\s+/g, ' ').trim(), '1 / 1', 'disabled backends are excluded from the denominator');
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    backends: { healthy_count: 2, total_count: 3 }
});
assert(el('vpn-signal-backends-value').textContent.includes('2 / 3'), 'unknown eligibility falls back to the configured total');
assert(!text('vpn-signal-backends-sub').includes('enabled'), 'unknown eligibility must not claim an enabled denominator');

// Test 10: a stale idle handshake alone produces no active-user problem row, and a
// route mismatch appears only when routing_consistency reports one.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    peer_sync: { desired_peers: 55, actual_peers: 55 },
    handshake_freshness: { under_2m_count: 24, between_2m_5m_count: 0, over_5m_count: 31, never_count: 0 },
    routing_consistency: { is_consistent: true, active_sessions_count: 0, active_routes_count: 0, sessions_without_route: [] },
    connected_sessions: 0
});
assert.strictEqual(el('vpn-fwd-problem-list').hidden, true, 'idle handshakes alone are not an active-user problem');
assert.strictEqual(el('vpn-session-mismatch').hidden, true, 'no mismatch without a reported one');
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    routing_consistency: { is_consistent: false, active_sessions_count: 16, active_routes_count: 15, sessions_without_route: ['s-1'] }
});
assert.strictEqual(el('vpn-session-mismatch').hidden, false, 'a reported mismatch is shown');
assert(el('vpn-session-mismatch').textContent.includes('1'), 'the mismatch names the reported count');

// Test 11: route pressure renders into the diagnostics route table without opening it.
mockDoc.reset();
// The DOM mock starts from fresh elements and does not copy template attributes, so
// the observable here is that the renderer did NOT open the panel. The template's own
// aria-expanded="false"/hidden markup is asserted in Go.
assert(el('vpn-diagnostics').hidden !== false, 'diagnostics must not be force-opened');
assert(el('vpn-advanced-entry').getAttribute('aria-expanded') !== 'true', 'the entry stays collapsed');
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    problem_routes: [{ peer_key: 'peer', capacity: 100, occupancy: 0, drops: 5, has_pressure: true }],
    all_routes: [{ peer_key: 'peer', capacity: 100, occupancy: 0, drops: 5, has_pressure: true }]
});
assert.strictEqual(typeof el('vpn-fwd-routes-details'), 'object', 'route fold lives inside diagnostics now');
assert(el('vpn-diagnostics').hidden !== false, 'a new problem must NOT open diagnostics');
assert(el('vpn-advanced-entry').getAttribute('aria-expanded') !== 'true', 'the entry stays collapsed on a new problem');
assert.strictEqual(text('vpn-fwd-routes-summary-status'), 'Pressure Detected');
// The route fold is the second disclosure the design names: it is NOT auto-opened by
// a new problem either. The operator opens it (native <details>), and that manual
// open survives polling.
assert(el('vpn-fwd-routes-details').open !== true, 'a new problem must not open the route fold');
el('vpn-fwd-routes-details').open = true;
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    problem_routes: [{ peer_key: 'peer', capacity: 100, occupancy: 0, drops: 5, has_pressure: true }],
    all_routes: [{ peer_key: 'peer', capacity: 100, occupancy: 0, drops: 5, has_pressure: true }]
});
assert.strictEqual(el('vpn-fwd-routes-details').open, true, 'a manual open survives the next poll');
const renderedRouteRow = el('vpn-fwd-routes-tbody').children[0];
assert(renderedRouteRow, 'route row should be rendered');
assert.strictEqual(renderedRouteRow.children[0].style.whiteSpace, 'nowrap', 'peer cell must have white-space: nowrap');
assert.strictEqual(renderedRouteRow.children[1].style.textAlign, 'right', 'queue cell must have text-align: right');
assert.strictEqual(renderedRouteRow.children[2].style.textAlign, 'right', 'peak cell must have text-align: right');
assert.strictEqual(renderedRouteRow.children[3].style.textAlign, 'right', 'drops cell must have text-align: right');
assert.strictEqual(renderedRouteRow.children[4].style.textAlign, 'right', 'writes cell must have text-align: right');

// Test 12: recovery keeps lifetime evidence descriptive and shows current availability.
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,health_assessment:{status:'HEALTHY',summary:'Recovered'},
 drop_categories: {rates_available:true,total_drops:99,total_drop_rate_pps:0},
 forward_latency:{stalls:7,stalls_recent:0,p95_ms:300,p95_health_ms:0,p95_health_samples:0,oldest_in_flight_ms:0},
 backends:{eligibility_known:true,healthy_count:1,enabled_count:1,disabled_count:2,total_count:3}
});
assert(el('vpn-diag-drops-total').textContent.includes('99 cumulative'));
assert(el('vpn-diag-lat-percentiles').textContent.includes('Not measured'), 'no recent samples reads as not measured');

// Test 13: an explicit operator open survives polling, including a new problem.
mockDoc.reset();
vpnSetDiagnosticsOpen(true);
assert.strictEqual(el('vpn-diagnostics').hidden, false);
assert.strictEqual(el('vpn-advanced-entry').getAttribute('aria-expanded'), 'true');
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'CRITICAL', conditions: [{ severity: 'CRITICAL', message: 'New incident' }] }
});
assert.strictEqual(el('vpn-diagnostics').hidden, false, 'a manually opened panel stays open across polls');
assert.strictEqual(el('vpn-advanced-entry').getAttribute('aria-expanded'), 'true');
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-diagnostics').hidden, false, 'a failed poll does not close an operator-opened panel');
vpnSetDiagnosticsOpen(false);
assert.strictEqual(el('vpn-diagnostics').hidden, true);
assert.strictEqual(el('vpn-advanced-entry').getAttribute('aria-expanded'), 'false');

console.log('VPN_HEALTH_PASS');
`

		out, err := execNodeScript(nodePath, runnerScript)
		if err != nil {
			t.Fatalf("VPN health DOM tests failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "VPN_HEALTH_PASS") {
			t.Fatalf("VPN health DOM tests did not output VPN_HEALTH_PASS\nOutput:\n%s", string(out))
		}
	})
}

func TestVPNOperationalDiagnosticsCardsContract(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()
	script := vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + "\n" + fixture.HealthSummaryJS + `
// 1. Nominal / Healthy state with traffic & backends
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1000,
    forwarder_queue_occupancy: 50,
    forwarder_queue_high_water: 120,
    listener_running: true,
    virtual_tun: {
        upstream_to_nexus: { capacity: 100, occupancy: 10, peak: 20, drops: 0 },
        nexus_to_upstream: { capacity: 100, occupancy: 15, peak: 25, drops: 0 }
    },
    rates: {
        available: true,
        rx_bps: 1200000, tx_bps: 800000,
        rx_bps_avg_5m: 1100000, tx_bps_avg_5m: 750000,
        rx_bps_avg_1h: 1000000, tx_bps_avg_1h: 700000
    },
    // The visible percentile is the RECENT forward-write reservoir, gated on its own
    // sample count. The historical global reservoir (p50/p95/p99) is deliberately not
    // rendered by default because its sample presence cannot be proven.
    forward_latency: {
        p50_ms: 1.2, p95_ms: 4.5, p99_ms: 8.9, max_ms: 15,
        p95_health_ms: 4.5, p95_health_samples: 120, p95_health_window_sec: 60
    },
    drop_categories: {
        rates_available: true,
        client_total_drops: 0, client_drop_rate_pps: 0,
        return_total_drops: 0, return_drop_rate_pps: 0,
        total_drops: 0, total_drop_rate_pps: 0,
        reason_rates: {}
    },
    peer_sync: { desired_peers: 10, actual_peers: 10 },
    handshake_freshness: { under_2m_count: 8, between_2m_5m_count: 2, over_5m_count: 0, never_count: 0 },
    routing_consistency: { is_consistent: true, active_sessions_count: 10, active_routes_count: 10, return_owners_count: 10 },
    runtime_resources: {
        cpu_percent: 12.5,
        memory_alloc_bytes: 52428800, memory_limit_bytes: 209715200, memory_usage_pct: 25.0, memory_limit_available: true,
        open_file_desc: 42, max_file_desc: 1024
    },
    backends: {
        backends: [
            { server_name: 'NodeA', rx_bytes_per_sec: 60000, tx_bytes_per_sec: 60000 },
            { server_name: 'NodeB', rx_bytes_per_sec: 40000, tx_bytes_per_sec: 40000 }
        ]
    }
});

// Card 1: Data Plane Performance
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Rx: 1.20 Mbps | Tx: 800.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Rx: 1.10 Mbps | Tx: 750.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Rx: 1.00 Mbps | Tx: 700.00 Kbps');
assert(document.getElementById('vpn-diag-lat-percentiles').textContent.includes('4.5'), 'recent forward-write p95 is rendered');
assert(document.getElementById('vpn-diag-lat-percentiles').textContent.includes('1m'), 'the sample horizon is stated');
assert(!document.getElementById('vpn-diag-lat-percentiles').textContent.includes('1.2'), 'the unprovable historical reservoir is not shown');
assert(document.getElementById('vpn-diag-queue-occ').textContent.includes('50 / 1000'));
assert(document.getElementById('vpn-diag-queue-peak').textContent.includes('120'));

// Card 2: Zero drops shows empty state
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, '0.00 pps (0 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, '0.00 pps (0 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, '0.00 pps (0 cumulative)');
const reasonRows = document.getElementById('vpn-diag-drop-reasons').children;
assert.strictEqual(reasonRows.length, 1);
assert.strictEqual(reasonRows[0].textContent, 'No active drops');

// Card 3: Engine & Route Integrity
assert.strictEqual(document.getElementById('vpn-diag-engine-status').textContent, 'amneziawg-go (active) • VirtualTUN: Healthy');
assert.strictEqual(document.getElementById('vpn-diag-peers-status').textContent, '10 / 10');
assert(document.getElementById('vpn-diag-hs-freshness').textContent.includes('<2m: 8'));
assert(document.getElementById('vpn-diag-routing-counts').textContent.includes('10 sessions • 10 routes • 10 returns'));

// Card 4: System & Fleet Resources
assert.strictEqual(document.getElementById('vpn-diag-res-cpu').textContent, '12.5%');
assert(document.getElementById('vpn-diag-res-mem').textContent.includes('50.0 MiB'));
assert.strictEqual(document.getElementById('vpn-diag-res-fd').textContent, '42 / 1024');

// Fleet Traffic Share percentage distribution
const beTrafficRows = document.getElementById('vpn-diag-be-traffic').children;
assert.strictEqual(beTrafficRows.length, 1);
assert.strictEqual(beTrafficRows[0].textContent, 'NodeA (60%) • NodeB (40%)');

// 2. Filtered Drop Reasons: only non-zero drops shown
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    drop_categories: {
        rates_available: true,
        client_malformed: 5,
        return_queue_full: 12,
        reason_rates: { client_malformed: 1.5, return_queue_full: 3.0 }
    }
});
const activeReasonRows = document.getElementById('vpn-diag-drop-reasons').children;
assert.strictEqual(activeReasonRows.length, 2);
assert(activeReasonRows[0].textContent.includes('3.00 pps (12 cumulative)'));
assert(activeReasonRows[1].textContent.includes('1.50 pps (5 cumulative)'));

// 3. Unmeasured drop reasons: when rates_available is false and no drops, renders Loss rate unavailable
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    drop_categories: {
        rates_available: false,
        client_malformed: 0,
        return_queue_full: 0
    }
});
const unmeasuredReasonRows = document.getElementById('vpn-diag-drop-reasons').children;
assert.strictEqual(unmeasuredReasonRows.length, 1);
assert.strictEqual(unmeasuredReasonRows[0].textContent, 'Loss rate unavailable');

// 4. Fleet traffic share edge cases: filters disabled and unroutable, displays unavailable for unsampled
vpnRenderForwarderHealth({
    forwarder_available: true,
    backends: {
        backends: [
            { server_name: 'NodeActive', enabled: true, routable: true, rx_bytes_per_sec: 100, tx_bytes_per_sec: 100 },
            { server_name: 'NodeUnsampled', enabled: true, routable: true, traffic_available: false },
            { server_name: 'NodeDisabled', enabled: false, routable: true, rx_bytes_per_sec: 900, tx_bytes_per_sec: 900 },
            { server_name: 'NodeUnroutable', enabled: true, routable: false, rx_bytes_per_sec: 900, tx_bytes_per_sec: 900 }
        ]
    }
});
const fleetRows = document.getElementById('vpn-diag-be-traffic').children;
assert.strictEqual(fleetRows.length, 1);
assert.strictEqual(fleetRows[0].textContent, 'NodeActive (100%) • NodeUnsampled (Loss rate unavailable)');
`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("operational diagnostics cards contract: %v\n%s", err, out)
	}
}

func TestVPNForwarderHealthDecouplingAndHorizon(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixture(t)
	source := []byte(fixture.CombinedSource())

	assertions := `
const text = id => document.getElementById(id).textContent;
const el = id => document.getElementById(id);

// 1. Nominal loss with historical drops stays Healthy, and the CURRENT rate is
// distinct from the since-reset total.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 0, total_drops: 109 }
});

assert(el('vpn-fwd-status-badge').className.includes('badge-success'), 'nominal loss rate must stay Healthy');
assert.strictEqual(text('vpn-fwd-status-text'), 'Healthy');
assert.strictEqual(text('vpn-fwd-counters-since'), 'Counters since: 2026-10-07 06:14 UTC', 'counters_since must be formatted');
assert.strictEqual(el('vpn-fwd-counters-since').textContent.includes('Not measured'), false, 'a reported timestamp is shown');
// Overview: the current rate is a rate with a rate unit; the cumulative total is a count.
assert.strictEqual(el('vpn-signal-drops-value').textContent.replace(/\s+/g, ' ').trim(), '0.00 drops/s', 'current rate keeps its rate unit');
assert(el('vpn-signal-drops-sub').textContent.includes('109 drops since reset'), 'cumulative total has its own label and count unit');
assert(!el('vpn-signal-drops-sub').textContent.includes('pps'), 'the cumulative count must not be labelled as a rate');

// 2. Positive active drop rate is a measured value.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DEGRADED', conditions: [{ severity: 'DEGRADED', message: 'Loss active' }] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 3.5, total_drops: 115 }
});
assert.strictEqual(el('vpn-signal-drops-value').textContent.replace(/\s+/g, ' ').trim(), '3.50 drops/s');
assert(el('vpn-signal-drops-sub').textContent.includes('115 drops since reset'));
assert.strictEqual(el('vpn-diag-drops-total').style.color, 'var(--danger)', 'active loss rate is highlighted in diagnostics');

// 3. Status DOWN displays Down badge.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DOWN', conditions: [] }
});
assert(el('vpn-fwd-status-badge').className.includes('badge-danger'), 'DOWN status must have danger badge');
assert.strictEqual(text('vpn-fwd-status-text'), 'Down');

// 4. Unavailable forwarder clears counters_since and every signal.
vpnRenderForwarderHealth(null);
assert.strictEqual(text('vpn-fwd-counters-since'), '-');
assert.strictEqual(text('vpn-signal-drops-value'), 'Not measured');
assert(text('vpn-signal-drops-sub').includes('No drop-rate samples yet'), 'an unavailable poll must not keep a stale count');
assert(text('vpn-signal-drops-sub').includes('not end-to-end packet loss'), 'the dataplane scope is always stated');
assert(!text('vpn-signal-drops-sub').includes('109'), 'the retired count must not survive as stale data');
`
	script := vpnDiagnosticsHealthScript(t, string(source), assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("decoupling test failed: %v\n%s", err, out)
	}

	// 5. Test Russian locale translation for horizon labels and counters_since
	ruAssertions := `
const text = id => document.getElementById(id).textContent;
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 0, total_drops: 109 }
});
assert.strictEqual(text('vpn-fwd-status-text'), 'В норме');
assert.strictEqual(text('vpn-fwd-counters-since'), 'Счетчики с: 2026-10-07 06:14 UTC');
assert.strictEqual(text('vpn-sessions'), 'Не измерено', 'unmeasured copy is localized');
assert(text('vpn-signal-drops-sub').includes('109'), 'cumulative count survives localization');
`
	ruScript, err := vpnDiagnosticsHealthScriptLocale(t, string(source), "ru", ruAssertions)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian decoupling test failed: %v\n%s", err, out)
	}
}

func TestVPNProgressiveDisclosureAndActiveProblems(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	fixture := NewVPNTestFixture(t)
	tmplStr := fixture.CombinedSource()

	// 1. Invariant: the single Advanced Diagnostics disclosure must exist in the
	// template and default to collapsed.
	if !strings.Contains(tmplStr, `id="vpn-diagnostics"`) {
		t.Fatal("vpn.html missing #vpn-diagnostics")
	}
	if !strings.Contains(tmplStr, `id="vpn-advanced-entry"`) {
		t.Fatal("vpn.html missing #vpn-advanced-entry")
	}

	// 2. The OLD tech-details fold must be gone: a new problem must not expand
	// technical telemetry.
	assertions := `
const el = id => document.getElementById(id);
const text = id => document.getElementById(id).textContent;
const diagnosticsClosed = () => el('vpn-diagnostics').hidden !== false && el('vpn-advanced-entry').getAttribute('aria-expanded') !== 'true';

// 1. Healthy: no problem rows at all, and the panel stays closed.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
	peer_sync: { actual_peers: 5, desired_peers: 5 },
	backends: { eligibility_known: true, healthy_count: 2, enabled_count: 2, total_count: 2 }
});
assert(diagnosticsClosed(), 'diagnostics stays closed when healthy');
assert.strictEqual(el('vpn-fwd-problem-list').hidden, true, 'healthy renders no problem list');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 0, 'no nominal banner row exists');

// 2. Degraded with an actionable problem: the problem is surfaced, the panel stays shut.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		actionable_problems: [{
			severity: 'DEGRADED',
			message: 'Backend -> Client packet drops active',
			category: 'dataplane',
			user_id: 'usr-1',
			username: 'alice',
			connection_name: 'alice-phone',
			assigned_ip: '10.8.0.2',
			backend_id: 3,
			observed_rate: '15 drops'
		}]
	}
});
assert(diagnosticsClosed(), 'a new problem must NOT open diagnostics');
assert.strictEqual(el('vpn-fwd-problem-list').hidden, false);
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const problemRow = el('vpn-fwd-problem-list').children[0];
assert(problemRow.className.includes('vpn-issue'));
assert.strictEqual(problemRow.getAttribute('data-severity'), 'degraded');
assert(problemRow.textContent.includes('Degraded'), 'row carries severity text');
assert(problemRow.textContent.includes('Backend -> Client packet drops active'), 'row carries the explanation');
assert(problemRow.children[0].textContent.includes('Backend 3'), 'row names the known entity (backend)');
assert(problemRow.children[0].textContent.includes('alice'), 'row names the affected user');
assert(problemRow.children[0].textContent.includes('alice-phone'), 'row names the affected config');
const action = problemRow.children[1];
assert(action.tagName === undefined || action.tagName.toLowerCase() === 'button', 'row carries a focusable action');
assert(action.textContent.length > 0, 'the action has a label');

// 3. Down.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DOWN', summary: 'WireGuard forwarder daemon down' }
});
assert(diagnosticsClosed(), 'a Down transition must not open diagnostics');
assert.strictEqual(el('vpn-fwd-problem-list').children[0].getAttribute('data-severity'), 'critical');
assert(el('vpn-fwd-problem-list').children[0].textContent.includes('WireGuard forwarder daemon down'));

// 4. Critical with an explicit condition.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		conditions: [{ severity: 'CRITICAL', message: 'Queue full drops critical', category: 'drops' }]
	}
});
assert(diagnosticsClosed(), 'a Critical transition must not open diagnostics');
assert(el('vpn-fwd-problem-list').children[0].textContent.includes('Critical'));

// 5. A problem recurring AFTER a healthy poll must still not open the panel.
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] }
});
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'WARNING',
		conditions: [{ severity: 'WARNING', message: 'Stale upstream handshake', category: 'sessions' }]
	}
});
assert(diagnosticsClosed(), 'a problem recurring from healthy must not open diagnostics');

// 6. An operator-opened panel stays open across polls and problems.
vpnSetDiagnosticsOpen(true);
assert.strictEqual(el('vpn-diagnostics').hidden, false);
assert.strictEqual(el('vpn-advanced-entry').getAttribute('aria-expanded'), 'true');
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		actionable_problems: [{ severity: 'DEGRADED', message: 'Another problem', connection_id: 'c-9' }]
	}
});
assert.strictEqual(el('vpn-diagnostics').hidden, false, 'an already-open panel stays open when a new problem appears');
assert.strictEqual(el('vpn-advanced-entry').getAttribute('aria-expanded'), 'true');
vpnSetDiagnosticsOpen(false);

// 7. Unavailable: panel closed, problem list empty.
vpnRenderForwarderHealth(null);
assert(diagnosticsClosed(), 'an unavailable poll must not open diagnostics');
assert.strictEqual(el('vpn-fwd-problem-list').hidden, true);
assert.strictEqual(el('vpn-fwd-problem-list').textContent, '');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("progressive disclosure & active problems test failed: %v\n%s", err, out)
	}

	// 8. Localized severity labels and titles.
	ruAssertions := `
const el = id => document.getElementById(id);
const text = id => document.getElementById(id).textContent;
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		actionable_problems: [{ severity: 'DEGRADED', message: 'Проблема', connection_id: 'c-1' }]
	}
});
assert.strictEqual(text('vpn-fwd-status-text'), 'Деградировано');
assert(el('vpn-fwd-problem-list').children[0].textContent.includes('Деградировано'), 'severity label is localized');
assert(el('vpn-diagnostics').hidden !== false, 'localized rendering does not open diagnostics');
`
	ruScript, err := vpnDiagnosticsHealthScriptLocale(t, tmplStr, "ru", ruAssertions)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian progressive disclosure test failed: %v\n%s", err, out)
	}
}
