package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
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
			"vpn-fwd-headline-summary",
			"vpn-fwd-problem-list",
			"vpn-fwd-tech-details",
			"vpn-kpi-throughput",
			"vpn-kpi-routes-sessions",
			"vpn-kpi-queue-pressure",
			"vpn-kpi-packet-loss",
			"vpn-kpi-client-engine",
			"vpn-kpi-peer-sync",
			"vpn-kpi-backends",
			"vpn-kpi-slow-writes",
			"vpn-diag-throughput",
			"vpn-diag-ewma5m",
			"vpn-diag-ewma1h",
			"vpn-diag-lat-percentiles",
			"vpn-diag-lat-max",
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

		// 4 operational cards inside #vpn-fwd-tech-details
		techStart := strings.Index(vpnStr, `<details id="vpn-fwd-tech-details"`)
		if techStart == -1 {
			t.Fatal("missing #vpn-fwd-tech-details")
		}
		histStart := strings.Index(vpnStr[techStart:], `<!-- Panel 10: Historical Trends -->`)
		if histStart == -1 {
			t.Fatal("missing Panel 10 after #vpn-fwd-tech-details")
		}
		techCardsContent := vpnStr[techStart : techStart+histStart]
		cardMatches := regexp.MustCompile(`<div class="card"`).FindAllString(techCardsContent, -1)
		if len(cardMatches) != 4 {
			t.Errorf("expected 4 cards inside #vpn-fwd-tech-details grid, got %d", len(cardMatches))
		}

		// Operational labels
		for _, labelKey := range []string{
			"vpn_diag_avg_5m",
			"vpn_diag_avg_1h",
			"vpn_diag_drops_outbound",
			"vpn_diag_drops_inbound",
			"vpn_diag_route_integrity",
		} {
			expectedTag := fmt.Sprintf(`{{ _ "%s" }}`, labelKey)
			if !strings.Contains(techCardsContent, expectedTag) {
				t.Errorf("#vpn-fwd-tech-details missing operational label %s", labelKey)
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
// Test 1: HEALTHY state
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'HEALTHY',
        summary: 'All clear and operational'
    },
    rates: {available:true,rx_bps: 1000000, tx_bps: 2000000 },
    routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
    backends: { healthy_count: 2, total_count: 2 }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-success');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-headline-summary').textContent, 'All clear and operational');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').textContent, '2 / 2 healthy');

// Test 2: DEGRADED state with condition
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
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-warn');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Degraded');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-problem-list').children.length, 1);

// Test 3: CRITICAL state
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
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-danger');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Critical');

// Test 4: UNAVAILABLE state
mockDoc.reset();
vpnRenderForwarderHealth(null);
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Not reported');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-throughput').textContent, '-');

// Current route alarms recover while lifetime totals remain visible.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true, forwarder_queue_capacity:100, forwarder_queue_occupancy:0,
    health_assessment:{status:'HEALTHY',summary:'Recovered',conditions:[]},
    problem_routes:[],
    all_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:false}]
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-tech-details').open, false);

// Fresh loss remains a problem after the queue drains.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true, forwarder_queue_capacity:100,
    problem_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:true}],
    all_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:true}]
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-tech-details').open, true);
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Pressure Detected');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, true);
const renderedRouteRow = mockDoc.getElementById('vpn-fwd-routes-tbody').children[0];
assert(renderedRouteRow, 'route row should be rendered');
assert.strictEqual(renderedRouteRow.children[0].style.whiteSpace, 'nowrap', 'peer cell must have white-space: nowrap');
assert.strictEqual(renderedRouteRow.children[1].style.textAlign, 'right', 'queue cell must have text-align: right');
assert.strictEqual(renderedRouteRow.children[2].style.textAlign, 'right', 'peak cell must have text-align: right');
assert.strictEqual(renderedRouteRow.children[3].style.textAlign, 'right', 'drops cell must have text-align: right');
assert.strictEqual(renderedRouteRow.children[4].style.textAlign, 'right', 'writes cell must have text-align: right');

// Recovered KPIs keep lifetime evidence descriptive and show current availability.
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,health_assessment:{status:'HEALTHY',summary:'Recovered'},
 drop_categories: {rates_available:true,total_drops:99,total_drop_rate_pps:0},
 forward_latency:{stalls:7,stalls_recent:0,p95_ms:300,p95_health_ms:0,p95_health_samples:0,oldest_in_flight_ms:0},
 backends:{eligibility_known:true,healthy_count:1,enabled_count:1,disabled_count:2,total_count:3}
});
assert.strictEqual(mockDoc.getElementById('vpn-kpi-packet-loss').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('cumulative'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-slow-writes').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('unavailable'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-backends').textContent.includes('1 / 1'));
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 drop_categories: {rates_available:true,total_drops:100,total_drop_rate_pps:2},
 forward_latency:{stalls:8,stalls_recent:1,p95_ms:300,p95_health_ms:150,p95_health_samples:1}
});
assert.strictEqual(mockDoc.getElementById('vpn-kpi-packet-loss').style.color,'var(--danger)');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-slow-writes').style.color,'var(--danger)');
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 forward_latency:{p95_health_ms:0,p95_health_samples:1,stalls_recent:0},
 backends:{eligibility_known:true,healthy_count:0,enabled_count:0,disabled_count:3,total_count:3}
});
assert(mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('0.0ms'));
assert(!mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('unavailable'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').style.color,'var(--danger)');

mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 rates:{available:false,rx_bps:0,tx_bps:0},
 drop_categories:{rates_available:false,total_drops:0,total_drop_rate_pps:0}
});
assert(mockDoc.getElementById('vpn-kpi-throughput').textContent.includes('unavailable'));
assert(mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('unavailable'));
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 rates:{available:true,rx_bps:0,tx_bps:0},
 drop_categories:{rates_available:true,total_drops:0,total_drop_rate_pps:0}
});
assert(!mockDoc.getElementById('vpn-kpi-throughput').textContent.includes('unavailable'));
assert(!mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('unavailable'));

console.log('VPN_HEALTH_PASS');
`

		cmd := exec.Command(nodePath, "-e", runnerScript)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
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
    forward_latency: {
        p50_ms: 1.2, p95_ms: 4.5, p99_ms: 8.9, max_ms: 15
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
assert(document.getElementById('vpn-diag-lat-percentiles').textContent.includes('1.2') && document.getElementById('vpn-diag-lat-percentiles').textContent.includes('4.5'));
assert(document.getElementById('vpn-diag-lat-max').textContent.includes('15'));
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

// 1. Nominal loss with historical drops retains HEALTHY green and unhighlighted KPI
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 0, total_drops: 109 }
});

assert(el('vpn-fwd-status-badge').className.includes('badge-success'), 'top banner must remain HEALTHY green when loss rate is nominal');
assert.strictEqual(text('vpn-fwd-status-text'), 'Healthy');
assert.strictEqual(el('vpn-kpi-packet-loss').style.color, '', 'nominal loss rate must not color packet loss KPI card');
assert.strictEqual(text('vpn-fwd-counters-since'), 'Counters since: 2026-10-07 06:14 UTC', 'counters_since must be formatted');
assert.notStrictEqual(el('vpn-fwd-counters-since').style.display, 'none');
assert.strictEqual(text('vpn-kpi-packet-loss-sub'), 'Current / Live: 0.00 pps | Since Startup / Reset: 109');
assert(el('vpn-kpi-packet-loss').title.includes('Current / Live: 0.00 pps'));
assert(el('vpn-kpi-packet-loss').title.includes('Since Startup / Reset: 109'));

// 2. Positive active drop rate activates danger highlight
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DEGRADED', conditions: [{ severity: 'DEGRADED', message: 'Loss active' }] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 3.5, total_drops: 115 }
});
assert.strictEqual(el('vpn-kpi-packet-loss').style.color, 'var(--danger)', 'active loss rate must highlight KPI card');
assert.strictEqual(text('vpn-kpi-packet-loss-sub'), 'Current / Live: 3.50 pps | Since Startup / Reset: 115');

// 3. Status DOWN displays Down badge
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DOWN', conditions: [] }
});
assert(el('vpn-fwd-status-badge').className.includes('badge-danger'), 'DOWN status must have danger badge');
assert.strictEqual(text('vpn-fwd-status-text'), 'Down');

// 4. Unavailable forwarder clears counters_since and sublabel
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-fwd-counters-since').style.display, 'none');
assert.strictEqual(el('vpn-kpi-packet-loss-sub').style.display, 'none');
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
assert.strictEqual(text('vpn-kpi-packet-loss-sub'), 'Текущий / Онлайн: 0.00 pps | С запуска / Сброса: 109');
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

	// 1. Invariant: <details id="vpn-fwd-tech-details"> must be present in template.
	if !strings.Contains(tmplStr, `<details id="vpn-fwd-tech-details"`) {
		t.Fatal("vpn.html missing progressive disclosure container <details id=\"vpn-fwd-tech-details\">")
	}

	assertions := `
const el = id => document.getElementById(id);
const text = id => document.getElementById(id).textContent;

// 1. Nominal / Healthy forwarder:
// - techDetails remains closed (open === false)
// - problem-list renders reassuring green badge with live synced peers, routes, and backends
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
	peer_sync: { actual_peers: 5, desired_peers: 5 },
	backends: { healthy_count: 2, total_count: 2 }
});

assert.strictEqual(el('vpn-fwd-tech-details').open, false, 'tech details must remain closed when healthy');

// Operator manual expansion preserved across healthy poll (#461)
el('vpn-fwd-tech-details').open = true;
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
	peer_sync: { actual_peers: 5, desired_peers: 5 },
	backends: { healthy_count: 2, total_count: 2 }
});
assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must remain open across healthy polling tick when manually opened');
el('vpn-fwd-tech-details').open = false;
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const greenBadge = el('vpn-fwd-problem-list').children[0];
assert(greenBadge.className.includes('badge-success'), 'nominal summary must have badge-success class');
assert.strictEqual(
	greenBadge.textContent,
	'✓ No active problems detected • 5/5 peers synced • All routes consistent • 2/2 backends healthy',
	'nominal green badge text must show live counts'
);

// 2. Degraded forwarder with active issue:
// - techDetails auto-expands (open === true)
// - problem-list renders styled alert card with severity, message, and component/backend
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

assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must auto-expand when degraded');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const problemCard = el('vpn-fwd-problem-list').children[0];
assert(problemCard.className.includes('problem-card'), 'problem card must have problem-card class');
assert.strictEqual(problemCard.children[0].textContent, 'Degraded');
assert(problemCard.children[0].className.includes('badge-warn'));
assert.strictEqual(problemCard.children[1].textContent, 'Backend -> Client packet drops active');
assert(problemCard.children[2].textContent.includes('Backend 3'));
assert(problemCard.children[2].textContent.includes('dataplane'));
assert(problemCard.children[2].textContent.includes('User: alice'));
assert(problemCard.children[2].textContent.includes('Config: alice-phone'));
assert(problemCard.children[2].textContent.includes('IP: 10.8.0.2'));
assert(problemCard.children[2].textContent.includes('15 drops'));

// 3. Down forwarder:
// - techDetails auto-expands (open === true)
// - problem-list renders styled alert card with Down severity
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DOWN',
		summary: 'WireGuard forwarder daemon down'
	}
});

assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must auto-expand when down');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const downCard = el('vpn-fwd-problem-list').children[0];
assert.strictEqual(downCard.children[0].textContent, 'Down');
assert(downCard.children[0].className.includes('badge-danger'));
assert.strictEqual(downCard.children[1].textContent, 'WireGuard forwarder daemon down');

// 4. Critical forwarder with explicit condition:
// - techDetails auto-expands (open === true)
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		conditions: [{
			severity: 'CRITICAL',
			message: 'Queue full drops critical',
			category: 'drops'
		}]
	}
});

assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must auto-expand when critical');
assert.strictEqual(el('vpn-fwd-problem-list').children[0].children[0].textContent, 'Critical');
assert(el('vpn-fwd-problem-list').children[0].children[0].className.includes('badge-danger'));

// 5. Unavailable forwarder:
// - techDetails closed
// - problem-list hidden and empty
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-fwd-tech-details').open, false, 'tech details must close when unavailable');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'none');
assert.strictEqual(el('vpn-fwd-problem-list').textContent, '');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("progressive disclosure & active problems test failed: %v\n%s", err, out)
	}

	// 6. Test Russian locale rendering of nominal badge
	ruAssertions := `
const el = id => document.getElementById(id);
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	peer_sync: { actual_peers: 12, desired_peers: 12 },
	backends: { healthy_count: 3, total_count: 3 }
});

assert.strictEqual(el('vpn-fwd-tech-details').open, false);
assert.strictEqual(
	el('vpn-fwd-problem-list').children[0].textContent,
	'✓ Активных проблем не обнаружено • 12/12 пиров синхронизировано • Все маршруты согласованы • 3/3 бэкендов в норме'
);
`
	ruScript, err := vpnDiagnosticsHealthScriptLocale(t, tmplStr, "ru", ruAssertions)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian progressive disclosure nominal badge test failed: %v\n%s", err, out)
	}
}
