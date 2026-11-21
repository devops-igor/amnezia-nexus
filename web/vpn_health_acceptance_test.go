package web

import (
	"io/fs"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

// Issue #955 acceptance coverage. Each subtest names the design-handover
// acceptance ID it proves and asserts the OBSERVABLE result rather than the
// implementation detail that produces it.

// vpnHealthAcceptanceScript assembles a JSDOM script for the health surfaces.
func vpnHealthAcceptanceScript(t *testing.T, lang, assertions string) string {
	t.Helper()
	fixture := NewVPNTestFixture(t)
	script, err := fixture.AssembleHealthScript(lang, assertions)
	if err != nil {
		t.Fatalf("assemble health script: %v", err)
	}
	return script
}

func runVPNHealthAcceptance(t *testing.T, lang, assertions, wantToken string) {
	t.Helper()
	nodePath := requireNode(t)
	out, err := execNodeScript(nodePath, vpnHealthAcceptanceScript(t, lang, assertions))
	if err != nil {
		t.Fatalf("acceptance script failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), wantToken) {
		t.Fatalf("acceptance script did not report %q\nOutput:\n%s", wantToken, string(out))
	}
}

// VPN955-01: healthy state is one visible status with no duplicated block.
func TestVPN955Acceptance01HealthyIsCompactAndUnduplicated(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	templateHTML := fixture.TemplateHTML

	t.Run("NoRetiredDuplicateSurfaces", func(t *testing.T) {
		for _, retired := range []string{
			`id="vpn-kpi-`,
			`id="vpn-fwd-tech-details"`,
			`id="vpn-fwd-summary-header"`,
			`id="vpn-active-tunnels"`,
		} {
			if strings.Contains(templateHTML, retired) {
				t.Errorf("retired surface still present: %s", retired)
			}
		}
	})

	t.Run("ExactlyFourSignalsAndNoNestedGrid", func(t *testing.T) {
		doc, err := xhtml.Parse(strings.NewReader(templateHTML))
		if err != nil {
			t.Fatalf("parse vpn.html: %v", err)
		}
		if got := len(findHTMLNodesByAttr(doc, "data-signal")); got != 4 {
			t.Errorf("expected exactly 4 [data-signal] entries, got %d", got)
		}
		healthCard := findHTMLNodeByID(doc, "vpn-forwarder-card")
		if healthCard == nil {
			t.Fatal("#vpn-forwarder-card not found")
		}
		if nested := findHTMLElementByClassWithin(healthCard, "stats-grid"); nested != nil {
			t.Error("#vpn-forwarder-card must not contain a nested .stats-grid")
		}
	})

	t.Run("OneStatusAndNoGreenBanner", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    rates: { available: true, rx_bps: 1000, tx_bps: 1000 },
    connected_sessions: 4,
    routing_consistency: { is_consistent: true, active_sessions_count: 4, sessions_without_route: [] },
    backends: { eligibility_known: true, healthy_count: 2, enabled_count: 2, total_count: 2 },
    drop_categories: { rates_available: true, total_drops: 0, total_drop_rate_pps: 0 }
});
// Exactly one visible status element, and it says Healthy.
assert.strictEqual(el('vpn-fwd-status-text').textContent, 'Healthy');
assert.strictEqual(el('vpn-fwd-status-badge').hidden, false);
assert.strictEqual(el('vpn-fwd-status-badge').className, 'badge badge-success');
// No nominal green banner and no problem rows.
assert.strictEqual(el('vpn-fwd-problem-list').hidden, true, 'no nominal banner');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 0);
assert.strictEqual(el('vpn-fwd-problem-list').textContent, '');
// No counts line when there is nothing wrong.
assert.strictEqual(el('vpn-fwd-problem-counts').hidden, true);
console.log('VPN955_01_OK');
`, "VPN955_01_OK")
	})
}

// VPN955-02: problems are surfaced without opening diagnostics.
func TestVPN955Acceptance02ProblemsFirstAndManualDisclosure(t *testing.T) {
	t.Run("WarningAndCriticalRows", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
function closed() {
    return el('vpn-diagnostics').hidden !== false && el('vpn-advanced-entry').getAttribute('aria-expanded') !== 'true';
}

// WARNING: an active session with a stale upstream handshake.
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'WARNING',
        actionable_problems: [{
            severity: 'WARNING',
            message: 'Upstream handshake stale',
            category: 'sessions',
            session_id: 'S-016',
            username: 'alice',
            connection_name: 'alice-phone',
            assigned_ip: '10.8.0.2',
            backend_id: 7
        }]
    }
});
assert(closed(), 'warning must not open diagnostics');
// A reported WARNING assessment must present as Warning, never as an unknown state.
assert.strictEqual(el('vpn-fwd-status-text').textContent, 'Warning', 'a reported warning presents as Warning');
assert(el('vpn-fwd-status-badge').className.includes('badge-warn'), 'and the badge carries the warning tint');
const list = el('vpn-fwd-problem-list');
assert.strictEqual(list.hidden, false, 'problem list visible on warning');
assert.strictEqual(list.children.length, 1);
const row = list.children[0];
assert(row.textContent.includes('Warning'), 'row carries severity text');
assert(row.textContent.includes('Upstream handshake stale'), 'row carries a human explanation');
assert(row.textContent.includes('alice'), 'row names the affected entity');
assert(row.children.length === 2, 'row is [copy][action]');
const action = row.children[1];
assert(action.getAttribute('data-action') === 'vpn-issue-inspect', 'row has a focusable action');

// CRITICAL: an active session with no forwarder route.
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{
            severity: 'CRITICAL',
            message: 'Active session has no forwarder route',
            category: 'routing',
            session_id: 'S-017',
            connection_name: 'ops-laptop'
        }]
    }
});
assert(closed(), 'critical must not open diagnostics');
assert.strictEqual(el('vpn-fwd-problem-list').children[0].getAttribute('data-severity'), 'critical');
console.log('VPN955_02_ROWS_OK');
`, "VPN955_02_ROWS_OK")
	})

	t.Run("NewProblemKeepsDisclosureState", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
function open() { return el('vpn-diagnostics').hidden === false; }

const first = {
    forwarder_available: true,
    health_assessment: {
        status: 'DEGRADED',
        actionable_problems: [{ severity: 'DEGRADED', message: 'Queue drops', connection_id: 'c-1' }]
    }
};
vpnRenderForwarderHealth(first);
assert(!open(), 'closed panel stays closed when the first problem appears');

// A second, DIFFERENT problem while closed must not expand it.
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [
            { severity: 'DEGRADED', message: 'Queue drops', connection_id: 'c-1' },
            { severity: 'CRITICAL', message: 'No route', connection_id: 'c-2' }
        ]
    }
});
assert(!open(), 'a new problem must not expand a collapsed panel');

// If the operator had it open, it stays open through new problems.
vpnSetDiagnosticsOpen(true);
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'Third problem', connection_id: 'c-3' }]
    }
});
assert(open(), 'an already-open panel stays open across new problems');
vpnSetDiagnosticsOpen(false);
console.log('VPN955_02_STATE_OK');
`, "VPN955_02_STATE_OK")
	})

	t.Run("SessionActionFocusesDrilldownNotDiagnostics", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
// A real session row exists in the table, as sessions.js renders it.
const tbody = el('vpn-sessions-tbody');
tbody.textContent = '';
const tr = document.createElement('tr');
tr.setAttribute('data-session-id', 'S-100');
const cell = document.createElement('td');
cell.setAttribute('data-action', 'vpn-toggle-session');
cell.setAttribute('data-session-id', 'S-100');
tr.appendChild(cell);
tbody.appendChild(tr);

let drilldownCalls = 0;
const originalToggle = window.vpnToggleSessionDrilldown;
window.vpnToggleSessionDrilldown = function(id) { drilldownCalls++; window.__lastDrilldown = id; };

vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: {
        status: 'CRITICAL',
        actionable_problems: [{ severity: 'CRITICAL', message: 'No route', session_id: 'S-100', category: 'routing' }]
    }
});
assert(el('vpn-diagnostics').hidden !== false, 'diagnostics stayed closed');
const action = el('vpn-fwd-problem-list').children[0].children[1];
// The DOM mock records no click(), so invoke the row's own handler, which is what
// a real click dispatches.
assert(typeof action._vpnIssueAction === 'function', 'the action carries the inspect handler');
action._vpnIssueAction({ preventDefault() {} });
assert.strictEqual(drilldownCalls, 1, 'the session action opened the matching drilldown');
assert.strictEqual(window.__lastDrilldown, 'S-100', 'it targeted the reported session');
assert(el('vpn-diagnostics').hidden !== false, 'inspect must NOT open diagnostics');
window.vpnToggleSessionDrilldown = originalToggle;
console.log('VPN955_02_FOCUS_OK');
`, "VPN955_02_FOCUS_OK")
	})
}

// VPN955-03: one entry, three ordered sections, three working ranges.
func TestVPN955Acceptance03AdvancedDiagnostics(t *testing.T) {
	fixture := NewVPNTestFixture(t)

	t.Run("SingleEntryThreeOrderedSections", func(t *testing.T) {
		doc, err := xhtml.Parse(strings.NewReader(fixture.TemplateHTML))
		if err != nil {
			t.Fatalf("parse vpn.html: %v", err)
		}
		if got := countHTMLNodesByID(doc, "vpn-diagnostics"); got != 1 {
			t.Fatalf("expected exactly one #vpn-diagnostics, got %d", got)
		}
		panel := findHTMLNodeByID(doc, "vpn-diagnostics")
		sections := []string{"vpn-traffic-performance", "vpn-routing-drops", "vpn-runtime-details"}
		previous := -1
		for _, id := range sections {
			node := findHTMLNodeByID(panel, id)
			if node == nil {
				t.Fatalf("missing diagnostics section #%s", id)
			}
			idx := -1
			for i, candidate := range documentOrder(panel) {
				if candidate == node {
					idx = i
					break
				}
			}
			if idx <= previous {
				t.Errorf("#%s is out of the documented order", id)
			}
			previous = idx
		}
	})

	t.Run("ThreeRangesAndDefaultFifteenMinutes", func(t *testing.T) {
		doc, err := xhtml.Parse(strings.NewReader(fixture.TemplateHTML))
		if err != nil {
			t.Fatalf("parse vpn.html: %v", err)
		}
		container := findHTMLNodeByID(doc, "vpn-history-window-toggles")
		if container == nil {
			t.Fatal("#vpn-history-window-toggles is missing")
		}
		var ranges []string
		var defaultRange string
		var defaultPressed string
		var walk func(*xhtml.Node)
		walk = func(n *xhtml.Node) {
			if n == nil {
				return
			}
			if n.Type == xhtml.ElementNode && n.Data == "button" {
				if w := getHTMLNodeAttr(n, "data-window"); w != "" {
					ranges = append(ranges, w)
					if hasHTMLClass(n, "active") {
						defaultRange = w
						defaultPressed = getHTMLNodeAttr(n, "aria-pressed")
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(container)

		if len(ranges) != 3 {
			t.Fatalf("expected exactly 3 range buttons, got %v", ranges)
		}
		want := []string{"15m", "1h", "24h"}
		for i, r := range want {
			if ranges[i] != r {
				t.Errorf("range %d = %q, want %q (got %v)", i, ranges[i], r, ranges)
			}
		}
		if defaultRange != "15m" {
			t.Errorf("default range = %q, want 15m", defaultRange)
		}
		if defaultPressed != "true" {
			t.Errorf("default range aria-pressed = %q, want true", defaultPressed)
		}
	})

	t.Run("RangeSwitchesAreFunctional", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
const point = { t: 100, rx_bps: 1000, tx_bps: 1000, traffic_available: true, q_pct: 10,
    drop_rates_available: true, drop_rate: 1, fwd_p95_ms: 5, fwd_p95_samples: 1,
    be_p95_ms: 6, be_latency_samples: 1 };
const series = { window_15m: [point], window_1h: [point, point], window_24h: [point, point, point] };
vpnLastStatus = { forwarder_available: true, historical_series: series };

// Each range reads its OWN payload window and redraws the chart.
const seen = [];
const original = vpnGenerateSparklineSVG;
vpnGenerateSparklineSVG = (values, ...rest) => { seen.push(values); return original(values, ...rest); };
for (const [win, expected] of [['1h', 2], ['24h', 3], ['15m', 1]]) {
    seen.length = 0;
    vpnSetHistoryWindow(win);
    assert.strictEqual(vpnHistoryWindow, win, 'range switched to ' + win);
    assert.strictEqual(seen[0].length, expected, win + ' drew its own ' + expected + '-point window');
    assert(el('vpn-chart-throughput').innerHTML.includes('<svg'), 'chart renders for ' + win);
}
vpnGenerateSparklineSVG = original;
console.log('VPN955_03_RANGE_OK');
`, "VPN955_03_RANGE_OK")
	})

	t.Run("ExistingRenderersReached", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { available: true, rx_bps: 1000000, tx_bps: 0 },
    drop_categories: {
        rates_available: true, total_drops: 12, total_drop_rate_pps: 2,
        client_malformed: 12, reason_rates: { client_malformed: 2 }
    },
    routing_consistency: { is_consistent: true, active_sessions_count: 3, active_routes_count: 3, return_owners_count: 3 },
    listener_running: true,
    runtime_resources: { cpu_percent: 5.0, memory_alloc_bytes: 1048576, open_file_desc: 10, max_file_desc: 100 },
    problem_routes: [{ peer_key: 'peer-1', capacity: 10, occupancy: 1, drops: 2, write_count: 5 }],
    all_routes: [{ peer_key: 'peer-1', capacity: 10, occupancy: 1, drops: 2, write_count: 5 }]
});
// Real renderers reach their containers.
assert(el('vpn-diag-drop-reasons').children.length > 0, 'drop reasons render');
assert(el('vpn-diag-routing-counts').textContent.includes('3'), 'route integrity renders');
assert(el('vpn-diag-engine-status').textContent.includes('VirtualTUN'), 'engine state renders');
assert(el('vpn-chart-reasons').children.length >= 0, 'reason history container reachable');
assert(el('vpn-fwd-routes-tbody').children.length === 1, 'per-route row renders');
console.log('VPN955_03_RENDERERS_OK');
`, "VPN955_03_RENDERERS_OK")
	})
}

// VPN955-04: not-measured is never a number, and gaps are never zero.
func TestVPN955Acceptance04NotMeasuredVsMeasuredZero(t *testing.T) {
	t.Run("UnavailableAndMissingFlags", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
// Unavailable response.
vpnRenderForwarderHealth(null);
assert(!el('vpn-fwd-status-badge').className.includes('badge-success'), 'unavailable is never healthy');
assert.strictEqual(el('vpn-fwd-status-text').textContent, 'Not reported');
for (const id of ['vpn-signal-throughput-value', 'vpn-signal-drops-value', 'vpn-signal-backends-value', 'vpn-sessions']) {
    assert.strictEqual(el(id).textContent, 'Not measured', id + ' reads not measured, not 0');
    assert(!/^\d/.test(el(id).textContent), id + ' must not print a number');
}
assert.strictEqual(el('vpn-diag-lat-percentiles').textContent, 'Not measured');

// Missing flags with numeric sentinels present.
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { rx_bps: 5000, tx_bps: 5000 },
    drop_categories: { total_drops: 7, total_drop_rate_pps: 9.5 },
    forward_latency: { p95_health_ms: 0, p95_health_samples: 0, write_total: 900 }
});
assert.strictEqual(el('vpn-signal-throughput-value').textContent, 'Not measured', 'absent rate flag means not measured');
assert.strictEqual(el('vpn-signal-drops-value').textContent, 'Not measured', 'absent drop flag means not measured');
assert.strictEqual(el('vpn-diag-lat-percentiles').textContent, 'Not measured', 'no sample count means not measured');
console.log('VPN955_04_UNAVAILABLE_OK');
`, "VPN955_04_UNAVAILABLE_OK")
	})

	t.Run("SampledZeroStaysNumeric", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { available: true, rx_bps: 0, tx_bps: 0 },
    drop_categories: { rates_available: true, total_drops: 0, total_drop_rate_pps: 0 },
    forward_latency: { p95_health_ms: 0, p95_health_samples: 1, p95_health_window_sec: 60 }
});
assert.strictEqual(el('vpn-signal-throughput-value').textContent.replace(/\\s+/g, ' ').trim(), '0 bps', 'sampled zero throughput stays numeric');
assert.strictEqual(el('vpn-signal-drops-value').textContent.replace(/\\s+/g, ' ').trim(), '0.00 drops/s', 'sampled zero rate stays numeric');
assert(el('vpn-diag-lat-percentiles').textContent.includes('0.0'), 'a sampled zero percentile is a measurement');
console.log('VPN955_04_ZERO_OK');
`, "VPN955_04_ZERO_OK")
	})

	t.Run("SmallPercentileRoundsToZeroButStaysMeasured", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
vpnRenderForwarderHealth({
    forwarder_available: true,
    forward_latency: { p95_health_ms: 0.04, p95_health_samples: 5, p95_health_window_sec: 60 }
});
const text = el('vpn-diag-lat-percentiles').textContent;
assert(text !== 'Not measured', 'a valid sample is measured even when it rounds to 0.0');
assert(text.includes('0.0'), 'it renders the rounded numeric value: ' + text);
console.log('VPN955_04_SMALL_OK');
`, "VPN955_04_SMALL_OK")
	})

	t.Run("TwoLatencySeriesWithDifferentCoverage", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
// Forward-write samples exist only in the first point; backend probes only in the
// second. Neither series may be zero-filled across the gap.
vpnRenderHistoryCharts({ window_15m: [
    { t: 100, fwd_p95_ms: 5, fwd_p95_samples: 1, be_p95_ms: 9, be_latency_samples: 0, traffic_available: false, drop_rates_available: false },
    { t: 160, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 9, be_latency_samples: 1, traffic_available: false, drop_rates_available: false }
]});
const markup = el('vpn-chart-latency').innerHTML;
assert(markup.includes('<svg'), 'the latency chart renders because one series is measured');
// Two isolated single-point series produce dots, not a bridged line.
const dots = (markup.match(/<circle /g) || []).length;
assert.strictEqual(dots, 2, 'each series contributes its own single sample dot, got ' + dots);
const stroke = markup.match(/<path d="([^"]+)" fill="none"/);
assert(stroke && !stroke[1].includes(' L '), 'an unsampled gap must not be bridged as a line');
console.log('VPN955_04_LATENCY_OK');
`, "VPN955_04_LATENCY_OK")
	})
}

// VPN955-05: no conflated populations, no invented failures.
func TestVPN955Acceptance05NoConflatedSignals(t *testing.T) {
	runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);

// 1. A disabled backend is not a failure.
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    backends: { eligibility_known: true, healthy_count: 2, enabled_count: 2, disabled_count: 3, total_count: 5 }
});
assert.strictEqual(el('vpn-signal-backends-value').textContent.replace(/\\s+/g, ' ').trim(), '2 / 2', 'disabled backends are excluded from the denominator');

// 2. A stale idle handshake alone is not an active-user problem.
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    connected_sessions: 0,
    peer_sync: { desired_peers: 55, actual_peers: 55 },
    handshake_freshness: { under_2m_count: 24, between_2m_5m_count: 0, over_5m_count: 31, never_count: 0 },
    routing_consistency: { is_consistent: true, active_sessions_count: 0, active_routes_count: 0, sessions_without_route: [] }
});
assert.strictEqual(el('vpn-fwd-problem-list').hidden, true, 'idle handshakes are not an active-user problem');
assert.strictEqual(el('vpn-fwd-status-badge').className, 'badge badge-success', 'and the page stays healthy');

// 3. Route mismatch appears only when reported.
assert.strictEqual(el('vpn-session-mismatch').hidden, true, 'no mismatch without a report');
vpnRenderForwarderHealth({
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] },
    routing_consistency: { is_consistent: false, active_sessions_count: 16, active_routes_count: 15, sessions_without_route: ['s-9'] }
});
assert.strictEqual(el('vpn-session-mismatch').hidden, false, 'a reported mismatch is shown');

// 4. Current rate and cumulative total have distinct labels and units.
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { available: true, rx_bps: 800000, tx_bps: 0 },
    drop_categories: { rates_available: true, total_drops: 48, total_drop_rate_pps: 1.25 }
});
const rateText = el('vpn-signal-drops-value').textContent.replace(/\\s+/g, ' ').trim();
const totalText = el('vpn-signal-drops-sub').textContent;
assert.strictEqual(rateText, '1.25 drops/s', 'the current rate carries a rate unit');
assert(totalText.includes('48 drops since reset'), 'the cumulative total is labelled as a count since reset');
assert(!totalText.includes('drops/s'), 'the cumulative total is not labelled as a rate');
assert(totalText.includes('not end-to-end'), 'the dataplane scope is stated so it cannot read as end-to-end loss');
console.log('VPN955_05_OK');
`, "VPN955_05_OK")
}

// VPN955-06: locales, themes and accessibility affordances.
func TestVPN955Acceptance06LocalesThemesAndA11y(t *testing.T) {
	fixture := NewVPNTestFixture(t)

	t.Run("AllFiveLocalesCarryTheNewCopy", func(t *testing.T) {
		required := []string{
			"vpn_health_title", "vpn_health_checking", "vpn_health_unavailable",
			"vpn_advanced_diagnostics", "vpn_close_diagnostics",
			"vpn_diagnostics_traffic", "vpn_diagnostics_routing", "vpn_diagnostics_runtime",
			"vpn_signal_backends", "vpn_signal_sessions", "vpn_signal_drops",
			"vpn_signal_drops_since_reset", "vpn_signal_drops_unmeasured",
			"vpn_dataplane_drops_scope", "vpn_diag_not_measured",
			"vpn_diag_forward_p95_value", "vpn_diag_forward_p95_window",
			"vpn_issue_inspect", "vpn_issue_inspect_session",
			"vpn_issue_entity_missing_session", "vpn_issue_entity_missing_backend",
		}
		for _, lang := range []string{"en", "ru", "fr", "zh", "fa"} {
			dict := fixture.Locale(lang)
			for _, key := range required {
				if strings.TrimSpace(dict[key]) == "" {
					t.Errorf("%s missing new key %q", lang, key)
				}
			}
		}
	})

	t.Run("PacketLossRenamedEverywhere", func(t *testing.T) {
		// The scoped name must not read as end-to-end loss in any locale.
		for _, lang := range []string{"en", "ru", "fr", "zh", "fa"} {
			dict := fixture.Locale(lang)
			if got := dict["vpn_col_packet_loss"]; strings.Contains(strings.ToLower(got), "packet loss") {
				t.Errorf("%s still calls the column %q", lang, got)
			}
			if got := dict["vpn_fwd_kpi_loss"]; strings.Contains(strings.ToLower(got), "packet loss") {
				t.Errorf("%s still calls the metric %q", lang, got)
			}
		}
		if got := fixture.Locale("en")["vpn_col_packet_loss"]; got != "Dataplane drops" {
			t.Errorf("en column label = %q, want %q", got, "Dataplane drops")
		}
		if got := fixture.Locale("en")["vpn_fwd_kpi_loss"]; got != "Dataplane Drops" {
			t.Errorf("en metric label = %q, want %q", got, "Dataplane Drops")
		}
	})

	t.Run("KeyboardAndReducedMotionContracts", func(t *testing.T) {
		styleData, err := fs.ReadFile(StaticFS, "static/css/vpn.css")
		if err != nil {
			t.Fatalf("read vpn.css: %v", err)
		}
		css := string(styleData)
		if !strings.Contains(css, "@media (prefers-reduced-motion: reduce)") {
			t.Error("vpn.css must define a reduced-motion block for the redesigned surfaces")
		}
		if !strings.Contains(css, "scroll-behavior: auto !important") {
			t.Error("reduced motion must neutralise smooth scrolling")
		}
		// Interactive controls meet the 44px target.
		if !strings.Contains(css, "min-block-size: 44px") {
			t.Error("controls must meet the 44px minimum target")
		}
		// The route table scrolls inside its own named region.
		if !strings.Contains(css, ".vpn-route-table-region") || !strings.Contains(css, "overflow: auto") {
			t.Error("the route table must scroll inside its own region")
		}
		// Visible focus is declared for the region target and the summary.
		if !strings.Contains(css, ".vpn-region-target:focus") {
			t.Error("the diagnostics heading must show a visible focus ring")
		}
	})

	t.Run("FocusReturnAndAnnouncementDiscipline", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
let focused = [];
const makeFocusable = (id) => {
    const node = el(id);
    node.focus = function() { focused.push(id); };
    return node;
};
makeFocusable('vpn-diagnostics-title');
makeFocusable('vpn-advanced-entry');

// Opening moves focus to the heading; closing returns it to the entry.
vpnToggleDiagnostics();
assert.strictEqual(el('vpn-diagnostics').hidden, false);
assert.deepStrictEqual(focused, ['vpn-diagnostics-title'], 'opening focuses the diagnostics heading');
vpnCloseDiagnostics();
assert.strictEqual(el('vpn-diagnostics').hidden, true);
assert.deepStrictEqual(focused, ['vpn-diagnostics-title', 'vpn-advanced-entry'], 'closing returns focus to the entry');

// An unchanged poll must not rewrite the summary text, so a polite live region
// has nothing to re-announce.
const healthy = {
    forwarder_available: true,
    health_assessment: { status: 'HEALTHY', conditions: [] }
};
vpnRenderForwarderHealth(healthy);
let writes = 0;
const summaryNode = el('vpn-fwd-headline-summary');
const descriptor = Object.getOwnPropertyDescriptor(summaryNode, 'textContent');
Object.defineProperty(summaryNode, 'textContent', {
    configurable: true,
    get() { return descriptor && descriptor.get ? descriptor.get.call(this) : this._text; },
    set(v) { writes++; if (descriptor && descriptor.set) descriptor.set.call(this, v); else this._text = v; }
});
vpnRenderForwarderHealth(healthy);
vpnRenderForwarderHealth(healthy);
assert.strictEqual(writes, 0, 'an unchanged poll must not rewrite the live-region text');
console.log('VPN955_06_A11Y_OK');
`, "VPN955_06_A11Y_OK")
	})

	t.Run("RTLUsesLogicalProperties", func(t *testing.T) {
		styleData, err := fs.ReadFile(StaticFS, "static/css/vpn.css")
		if err != nil {
			t.Fatalf("read vpn.css: %v", err)
		}
		css := string(styleData)
		for _, token := range []string{"border-inline-start", "margin-block", "padding-block"} {
			if !strings.Contains(css, token) {
				t.Errorf("vpn.css must use the logical property %q so RTL mirrors correctly", token)
			}
		}
		if strings.Contains(css, "border-left: 3px") {
			t.Error("the issue row must use border-inline-start, not a physical left border")
		}
	})
}

// TestVPN955NoNewGlobalInfrastructure guards the scope promise: no new global
// token, font, frontend package or navigation route was introduced.
func TestVPN955NoNewGlobalInfrastructure(t *testing.T) {
	tokensData, err := fs.ReadFile(StaticFS, "static/css/tokens.css")
	if err != nil {
		t.Fatalf("read tokens.css: %v", err)
	}
	tokens := string(tokensData)
	// The redesign composes existing tokens; it must not have added VPN-specific
	// global custom properties.
	for _, banned := range []string{"--vpn-health", "--vpn-signal", "--vpn-issue", "--vpn-diag"} {
		if strings.Contains(tokens, banned) {
			t.Errorf("tokens.css must not gain the VPN-specific global property %q", banned)
		}
	}

	fixture := NewVPNTestFixture(t)
	script := fixture.CombinedSource()
	if strings.Contains(script, "<script>") {
		t.Error("no inline script may be introduced")
	}
	for _, handler := range []string{"onclick=", "onchange=", "onsubmit="} {
		if strings.Contains(fixture.TemplateHTML, handler) {
			t.Errorf("no inline event handler (%s) may be introduced", handler)
		}
	}

	// No new chart or UI dependency: the six existing modules stay the whole set.
	for _, path := range canonicalVPNScripts {
		name := strings.TrimPrefix(path, "/")
		if _, err := fs.ReadFile(StaticFS, name); err != nil {
			t.Errorf("expected shipped VPN module %s: %v", path, err)
		}
	}
	if strings.Contains(fixture.TemplateHTML, "chart.js") || strings.Contains(fixture.TemplateHTML, "d3") {
		t.Error("no new chart dependency may be introduced")
	}
}

// TestVPN955ChangedSurfaceStaysWithinSizeCeilings enforces the SG1 size rule on
// the files this issue touched. The CRAP metric itself is NOT measured for this
// delivery and the handover says so: Go's coverage instrumentation attributes
// nothing to JavaScript, CSS or Go-template bytes, so there is no
// cyclomatic-complexity/coverage pair to compute for the changed production
// surface. Reporting a number here would be invented.
func TestVPN955ChangedSurfaceStaysWithinSizeCeilings(t *testing.T) {
	type subject struct {
		name     string
		path     string
		maxLines int
	}
	subjects := []subject{
		{"vpn template", "templates/vpn.html", 600},
		{"vpn stylesheet", "static/css/vpn.css", 1000},
		{"health summary module", "static/js/vpn/health_summary.js", 1000},
		{"health problems module", "static/js/vpn/health_problems.js", 1000},
	}
	for _, s := range subjects {
		root, err := GetTemplatesSubFS()
		if strings.HasPrefix(s.path, "static/") {
			root, err = GetStaticSubFS()
			if err == nil {
				body, readErr := fs.ReadFile(root, strings.TrimPrefix(s.path, "static/"))
				if readErr != nil {
					t.Fatalf("read %s: %v", s.path, readErr)
				}
				if lines := strings.Count(string(body), "\n") + 1; lines > s.maxLines {
					t.Errorf("%s is %d lines, over the %d ceiling", s.name, lines, s.maxLines)
				}
				continue
			}
		}
		if err != nil {
			t.Fatalf("sub-FS for %s: %v", s.path, err)
		}
		body, err := fs.ReadFile(root, strings.TrimPrefix(s.path, "templates/"))
		if err != nil {
			t.Fatalf("read %s: %v", s.path, err)
		}
		if lines := strings.Count(string(body), "\n") + 1; lines > s.maxLines {
			t.Errorf("%s is %d lines, over the %d ceiling", s.name, lines, s.maxLines)
		}
	}
}
