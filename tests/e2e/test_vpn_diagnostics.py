"""Read-only E2E checks for the forwarder health dashboard and diagnostics."""

import math
import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get, assert_response_shape


def _ensure_tech_details_open(page: Page) -> None:
    tech_details = page.locator("#vpn-fwd-tech-details")
    if not tech_details.evaluate("el => el.open"):
        page.locator("#vpn-fwd-tech-details > summary").click()


def _assert_tooltip_hidden(tooltip) -> None:
    expect(tooltip).not_to_be_visible()
    assert tooltip.evaluate(
        "el => el.style.display === \x27none\x27 || window.getComputedStyle(el).display === \x27none\x27"
    )


def _hover_center(page: Page, locator) -> None:
    box = locator.bounding_box()
    assert box is not None
    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)


_HISTORICAL_CHARTS = (
    "#vpn-chart-throughput",
    "#vpn-chart-drops",
    "#vpn-chart-queue",
    "#vpn-chart-latency",
)
_OBSOLETE_CHARTS = (
    "#vpn-chart-directions",
    "#vpn-chart-packets",
    "#vpn-chart-sessions-routes",
    "#vpn-chart-backend-latency",
)


def _chart_badge_re(unit: str) -> re.Pattern[str]:
    v = rf"(?:\d+(?:\.\d+)?\s*{unit}|—)"
    return re.compile(rf"Current:\s*{v}\s*\|\s*Peak:\s*{v}")


_CHART_BADGE_PATTERNS = {
    "#vpn-chart-throughput-badges": _chart_badge_re(r"(?:MB/s|KB/s|B/s)"),
    "#vpn-chart-drops-badges": _chart_badge_re(r"drops/s"),
    "#vpn-chart-queue-badges": re.compile(
        r"Current:\s*(?:\d+(?:\.\d+)?%\s*|—)\s*\|\s*Peak:\s*(?:\d+(?:\.\d+)?%\s*|—)"
    ),
    "#vpn-chart-latency-badges": re.compile(
        r"Current:\s*(?:\d+(?:\.\d+)?\s*ms(?:\s*\(probe\))?|—)\s*\|\s*Peak:\s*(?:\d+(?:\.\d+)?\s*ms|—)"
    ),
}


@pytest.mark.e2e
def test_vpn_dashboard_navigation_and_banner(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> sees headline forwarder health status banner."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Verify not redirected to login
    assert "/login" not in page.url
    assert "/vpn" in page.url

    # Headline status banner elements
    for loc in (
        "#vpn-fwd-status-badge",
        "#vpn-fwd-status-text",
        "#vpn-fwd-headline-summary",
    ):
        expect(page.locator(loc)).to_be_visible()


@pytest.mark.e2e
def test_vpn_kpi_summary_bar(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> verifies 8 KPI summary cards are rendered."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    kpi_keys = (
        "throughput routes-sessions queue-pressure packet-loss "
        "client-engine peer-sync backends slow-writes"
    ).split()
    for loc in [f"#vpn-kpi-{k}" for k in kpi_keys]:
        expect(page.locator(loc)).to_be_visible()

    # The Peer Sync tile reports SYNCHRONIZATION (desired vs actual peers from
    # status.peer_sync), not the handshake peer count it used to render
    # (issue #424 round 4, item H). peer_sync is omitempty, so an absent payload
    # must render an explicit unavailable state, never a misleading '0 / 0'.
    peer_sync_kpi = page.locator("#vpn-kpi-peer-sync")
    status_data = api_get(page, "/api/vpn/status")
    peer_sync = status_data.get("peer_sync")
    if isinstance(peer_sync, dict):
        expected = f"{peer_sync['actual_peers']} / {peer_sync['desired_peers']}"
        expect(peer_sync_kpi).to_have_text(expected)
    else:
        assert peer_sync_kpi.inner_text().strip() not in ("", "0 / 0")


@pytest.mark.e2e
def test_vpn_diagnostic_panels(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> verifies diagnostic telemetry panel fields."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    _ensure_tech_details_open(page)

    cards = page.locator(
        "#vpn-fwd-tech-details > div > div > div.card, #vpn-fwd-tech-details > div > div.card"
    )
    expect(cards).to_have_count(4)

    diag_fields = (
        "throughput ewma5m ewma1h lat-percentiles lat-max queue-occ queue-peak "
        "drops-client drops-return drops-total engine-status peers-status "
        "hs-freshness routing-counts res-cpu res-mem res-fd"
    ).split()
    for f in diag_fields:
        expect(page.locator(f"#vpn-diag-{f}")).to_be_visible()

    for obsolete in (
        "#vpn-diag-packets",
        "#vpn-diag-res-goroutines",
        "#vpn-diag-res-gc",
    ):
        expect(page.locator(obsolete)).to_have_count(0)


@pytest.mark.e2e
def test_vpn_sparklines_window_toggle(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> interactive time window toggle (15m, 1h, 6h, 24h)."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Ensure technical details disclosure is open
    _ensure_tech_details_open(page)

    for chart in _HISTORICAL_CHARTS:
        expect(page.locator(chart)).to_be_visible()
    for obsolete in _OBSOLETE_CHARTS:
        expect(page.locator(obsolete)).to_have_count(0)

    breakdown = page.locator("details:not(#vpn-fwd-tech-details)").filter(
        has=page.locator("#vpn-chart-reasons")
    )
    breakdown.locator("summary").click()
    for chart in ("#vpn-chart-reasons", "#vpn-chart-backends"):
        expect(page.locator(chart)).to_be_visible()
    expect(page.locator("#vpn-history-fleet-note")).to_be_attached()

    toggles = page.locator("#vpn-history-window-toggles")
    expect(toggles).to_be_visible()

    for win in ("1h", "6h", "24h", "15m"):
        btn = toggles.locator(f"button:has-text('{win}')")
        expect(btn).to_be_visible()
        btn.click()
        expect(btn).to_have_class("btn btn-sm btn-primary active")
        for chart in _HISTORICAL_CHARTS + ("#vpn-chart-reasons", "#vpn-chart-backends"):
            expect(page.locator(chart)).to_be_visible()


@pytest.mark.e2e
def test_vpn_historical_charts_interaction_and_kpis(
    authenticated_page: Page, base_url: str
) -> None:
    """Verify consolidated historical charts, KPI badges, time axes, and hover tooltips."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Ensure technical details disclosure is open
    _ensure_tech_details_open(page)

    toggles = page.locator("#vpn-history-window-toggles")
    expect(toggles).to_be_visible()

    for cid in _HISTORICAL_CHARTS:
        chart = page.locator(cid)
        expect(chart).to_be_visible()
        expect(chart.locator("svg")).to_be_visible()
        expect(page.locator(f"{cid}-axis")).to_be_visible()

    for bid, pattern in _CHART_BADGE_PATTERNS.items():
        expect(page.locator(bid)).to_be_visible()
        expect(page.locator(bid)).to_have_text(pattern)

    throughput_svg = page.locator("#vpn-chart-throughput svg")
    expect(throughput_svg).to_be_visible()
    throughput_svg.hover()

    tooltip = page.locator("#vpn-chart-tooltip")
    expect(tooltip).to_be_visible()
    assert tooltip.evaluate("el => el.style.display !== 'none'")
    assert (tooltip.text_content() or "").strip() != ""

    page.mouse.move(0, 0)
    _assert_tooltip_hidden(tooltip)

    btn_1h = toggles.locator("button:has-text('1h')")
    expect(btn_1h).to_be_visible()
    btn_1h.click()
    expect(btn_1h).to_have_class(re.compile(r"\bactive\b"))

    for cid in _HISTORICAL_CHARTS:
        expect(page.locator(f"{cid} svg")).to_be_visible()


@pytest.mark.e2e
def test_vpn_historical_charts_availability_transition_and_tooltip_lifecycle(
    authenticated_page: Page, base_url: str
) -> None:
    """Verify chart availability transition from unavailable to recovered and empty clearing."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Open technical details disclosure if collapsed
    _ensure_tech_details_open(page)

    # Inject an unavailable history series with unavailable flags and zero sample count
    page.evaluate("""() => {
        const u = { t: 36000, rx_bps: 0, tx_bps: 0, traffic_available: false, q_pct: null, drop_rate: 0, drop_rates_available: false, fwd_p95_ms: 0, fwd_p95_samples: 0 };
        vpnRenderHistoryCharts({ window_15m: [u, { ...u, t: 36060 }] });
    }""")

    # Inject recovered series (10.0 MB/s at 23:00:00; 41943040 bps rx/tx)
    page.evaluate("""() => {
        const r = { t: 82800, rx_bps: 41943040, tx_bps: 41943040, traffic_available: true, q_pct: 10, drop_rate: 1, drop_rates_available: true, fwd_p95_ms: 5, fwd_p95_samples: 1 };
        vpnRenderHistoryCharts({ window_15m: [r, r] });
    }""")

    overlay = page.locator("#vpn-chart-throughput svg .chart-overlay")
    expect(overlay).to_be_visible()
    overlay.scroll_into_view_if_needed()
    _hover_center(page, overlay)

    tooltip = page.locator("#vpn-chart-tooltip")
    expect(tooltip).to_be_visible()
    assert tooltip.evaluate("el => el.style.display !== 'none'")
    tip_text = tooltip.text_content() or ""

    # Assert tooltip contains exact recovered rate and timestamp, rejecting placeholders
    assert "23:00" in tip_text
    assert "10.0 MB/s" in tip_text or "10 MB/s" in tip_text
    assert "5.0 MB/s" in tip_text or "5 MB/s" in tip_text
    assert "vpn_unit_mbps" not in tip_text
    assert "—" not in tip_text
    assert "10:00" not in tip_text

    # Render an empty series via vpnRenderHistoryCharts({ window_15m: [] })
    page.evaluate("() => vpnRenderHistoryCharts({ window_15m: [] })")

    # Move the mouse away then back over #vpn-chart-throughput
    page.mouse.move(0, 0)
    _hover_center(page, page.locator("#vpn-chart-throughput"))
    _assert_tooltip_hidden(tooltip)


@pytest.mark.e2e
def test_vpn_problem_routes_toggle(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> Problem Routes details and 'Show all routes' toggle."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    _ensure_tech_details_open(page)

    details = page.locator("#vpn-fwd-routes-details")
    expect(details).to_be_visible()

    toggle_btn = page.locator("#vpn-routes-toggle-all-btn")
    expect(toggle_btn).to_be_visible()

    initial_text = toggle_btn.text_content()
    toggle_btn.click()

    # Text toggles after click
    updated_text = toggle_btn.text_content()
    assert updated_text != initial_text

    # Click again to revert
    toggle_btn.click()
    assert toggle_btn.text_content() == initial_text


@pytest.mark.e2e
def test_vpn_sessions_problems_toggle(authenticated_page: Page, base_url: str) -> None:
    """Verify Connection Troubleshooting problems filter toggle button."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    toggle_btn = page.locator("#vpn-sessions-toggle-problems-btn")
    expect(toggle_btn).to_be_visible()
    initial_text = toggle_btn.text_content()
    toggle_btn.click()
    updated_text = toggle_btn.text_content()
    assert updated_text != initial_text
    toggle_btn.click()
    assert toggle_btn.text_content() == initial_text


@pytest.mark.e2e
def test_vpn_routes_table_mobile_containment_and_scrolling(
    authenticated_page: Page, base_url: str
) -> None:
    """Verify forwarder routes table mobile containment, horizontal scrolling, and RTL behavior."""
    page = authenticated_page
    page.set_viewport_size({"width": 375, "height": 667})
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Open the #vpn-fwd-routes-details disclosure accordion using direct child selector
    page.locator("#vpn-fwd-routes-details > summary").click()

    result = page.evaluate("""() => {
            const table = document.getElementById('vpn-fwd-routes-table');
            if (!table) throw new Error('#vpn-fwd-routes-table not found');
            const wrapper = table.closest('.table-container');
            if (!wrapper) throw new Error('parent .table-container not found');

            // Render sample routes if currently hidden/empty to ensure rows exist
            if (table.style.display === 'none' || !table.querySelector('tbody tr')) {
                if (typeof window.vpnRenderForwarderHealth === 'function') {
                    const sampleRoutes = [
                        { peer_key: 'peer_m1', occupancy: 20, capacity: 100, high_water: 30, drops: 0, write_count: 50 },
                        { peer_key: 'peer_m2', occupancy: 85, capacity: 100, high_water: 90, drops: 5, write_count: 80 }
                    ];
                    window.vpnRenderForwarderHealth({
                        forwarder_available: true,
                        forwarder_queue_capacity: 100,
                        problem_routes: sampleRoutes,
                        all_routes: sampleRoutes
                    });
                } else {
                    table.style.display = '';
                }
            }

            const wrapperComputed = window.getComputedStyle(wrapper);
            const wrapperClientWidth = wrapper.clientWidth;
            const tableScrollWidth = table.scrollWidth;
            const tableStyleMinWidth = table.style.minWidth;
            const wrapperScrollWidth = wrapper.scrollWidth;
            const wrapperOverflowX = wrapperComputed.overflowX;

            // Test horizontal scrolling in LTR
            wrapper.scrollLeft = 50;
            const scrollLeftLTR = wrapper.scrollLeft;

            // Body scrollWidth to verify no page overflow
            const bodyScrollWidthLTR = document.body.scrollWidth;

            // Test Persian RTL
            document.documentElement.dir = 'rtl';
            const tableComputedRTL = window.getComputedStyle(table);
            const tableDirectionRTL = tableComputedRTL.direction;

            wrapper.scrollLeft = -50;
            let scrollLeftRTL = wrapper.scrollLeft;
            if (scrollLeftRTL === 0) {
                wrapper.scrollLeft = 50;
                scrollLeftRTL = wrapper.scrollLeft;
            }
            const rtlScrolled = Math.abs(scrollLeftRTL) > 0;
            const bodyScrollWidthRTL = document.body.scrollWidth;

            // Restore dir
            document.documentElement.dir = '';

            return {
                wrapper_client_width: wrapperClientWidth,
                table_scroll_width: tableScrollWidth,
                table_min_width_style: tableStyleMinWidth,
                wrapper_scroll_width: wrapperScrollWidth,
                wrapper_overflow_x: wrapperOverflowX,
                scroll_left_ltr: scrollLeftLTR,
                body_scroll_width_ltr: bodyScrollWidthLTR,
                table_direction_rtl: tableDirectionRTL,
                rtl_scrolled: rtlScrolled,
                scroll_left_rtl: scrollLeftRTL,
                body_scroll_width_rtl: bodyScrollWidthRTL,
            };
        }""")

    assert result["wrapper_client_width"] <= 375
    assert result["table_scroll_width"] >= 540
    assert result["table_min_width_style"] == "540px"
    assert result["wrapper_scroll_width"] > result["wrapper_client_width"]
    assert result["wrapper_overflow_x"] == "auto"
    assert result["scroll_left_ltr"] > 0
    assert result["body_scroll_width_ltr"] <= 375
    assert result["table_direction_rtl"] == "rtl"
    assert result["rtl_scrolled"]
    assert result["body_scroll_width_rtl"] <= 375


_LOSS_REASONS = set(
    "client_malformed client_unmapped_source client_mismatch client_rejected "
    "client_backend_queue_full client_rate_limited client_no_healthy_backend "
    "client_virtualtun_drops client_backend_device_queue_full "
    "client_backend_device_oversized client_backend_device_shutdown "
    "client_backend_device_external backend_device_unattributed return_malformed "
    "return_unmapped return_mismatch return_injection_errors return_virtualtun_drops "
    "return_queue_full return_packet_too_large return_backend_device_queue_full "
    "return_backend_device_shutdown".split()
)


def _assert_nonnegative_rates(values: dict) -> None:
    """Require numeric, finite current measurements without disclosing payload values."""
    for value in values.values():
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
        assert math.isfinite(value) and value >= 0, "Telemetry rate must be finite and nonnegative"


def _assert_extended_diagnostics(status: dict) -> None:
    """Verify additive backend, route and bounded-history API contracts from #431-#434."""
    drops = status["drop_categories"]
    assert isinstance(drops["rates_available"], bool)
    assert set(drops["reason_rates"]) == _LOSS_REASONS
    _assert_nonnegative_rates(drops["reason_rates"])
    latency = status["forward_latency"]
    assert isinstance(latency["stalls_recent"], int)
    assert isinstance(latency["stalls_window_sec"], (int, float))
    backends = status["backends"]
    assert_response_shape(
        backends,
        {
            "enabled_count": int,
            "disabled_count": int,
            "eligibility_known": bool,
            "latency_samples": int,
            "backends": list,
        },
        "backends_diagnostics",
    )
    assert backends["eligibility_known"] is True
    assert backends["enabled_count"] + backends["disabled_count"] == backends["total_count"]
    assert len(backends["backends"]) == backends["total_count"]
    for backend in backends["backends"]:
        assert_response_shape(
            backend,
            {
                "enabled": bool,
                "routable": bool,
                "traffic_available": bool,
                "traffic_window_sec": (int, float),
                "rx_bytes": int,
                "tx_bytes": int,
                "rx_packets": int,
                "tx_packets": int,
            },
            "backend_telemetry",
        )
        assert not backend["routable"] or backend["enabled"]
        rates = {
            key: backend[key]
            for key in ("rx_bytes_per_sec", "tx_bytes_per_sec", "rx_pps", "tx_pps")
        }
        _assert_nonnegative_rates(rates)
        if backend["traffic_available"]:
            assert backend["traffic_window_sec"] > 0
        else:
            assert backend["traffic_window_sec"] == 0
            assert all(value == 0 for value in rates.values())
    assert backends["healthy_count"] == sum(item["routable"] for item in backends["backends"])
    for route in status.get("problem_routes") or []:
        assert_response_shape(
            route,
            {
                "assigned_ip": str,
                "backend_id": int,
                "occupancy": int,
                "capacity": int,
                "high_water": int,
                "drops": int,
                "utilization_pct": (int, float),
                "high_water_pct": (int, float),
                "write_count": int,
                "write_errors": int,
                "write_stalls": int,
                "writes_in_flight": int,
                "oldest_write_ms": int,
                "max_write_ms": int,
                "p95_write_ms": (int, float),
                "p95_write_samples": int,
                "queue_full_drops_recent": int,
                "write_errors_recent": int,
                "write_stalls_recent": int,
                "traffic": dict,
                "session_age_sec": int,
                "last_traffic_age_sec": int,
            },
            "route_telemetry",
        )
        assert route["session_age_sec"] >= -1 and route["last_traffic_age_sec"] >= -1
        traffic = route["traffic"]
        assert_response_shape(
            traffic,
            {
                "available": bool,
                "window_sec": (int, float),
                "rx_bytes": int,
                "tx_bytes": int,
                "rx_packets": int,
                "tx_packets": int,
            },
            "route_traffic",
        )
        _assert_nonnegative_rates(
            {
                key: traffic[key]
                for key in ("rx_bytes_per_sec", "tx_bytes_per_sec", "rx_pps", "tx_pps")
            }
        )
    history = status["historical_series"]
    for key, bound in (
        ("window_15m", 90),
        ("window_1h", 60),
        ("window_6h", 72),
        ("window_24h", 96),
    ):
        assert isinstance(history[key], list)
        assert len(history[key]) <= bound
        for point in history[key]:
            assert_response_shape(
                point,
                {
                    "t": int,
                    "rx_bps": (int, float),
                    "tx_bps": (int, float),
                    "rx_pps": (int, float),
                    "tx_pps": (int, float),
                    "traffic_available": bool,
                    "q_pct": (int, float),
                    "drop_rate": (int, float),
                    "drop_rates_available": bool,
                    "drop_reason_rates": dict,
                    "fwd_p95_ms": (int, float),
                    "fwd_p95_samples": int,
                    "sessions": int,
                    "routes": int,
                    "be_p95_ms": (int, float),
                    "be_latency_samples": int,
                    "backends": list,
                    "backends_omitted": int,
                },
                "history_point",
            )
            assert set(point["drop_reason_rates"]) == _LOSS_REASONS
            _assert_nonnegative_rates(point["drop_reason_rates"])
            assert len(point["backends"]) <= 128 and point["backends_omitted"] >= 0
            for backend in point["backends"]:
                assert_response_shape(
                    backend,
                    {
                        "id": int,
                        "rx_bps": (int, float),
                        "tx_bps": (int, float),
                        "rx_pps": (int, float),
                        "tx_pps": (int, float),
                        "traffic_available": bool,
                        "probe_latency_ms": int,
                        "probe_available": bool,
                        "routable": bool,
                    },
                    "backend_history",
                )


@pytest.mark.e2e
def test_vpn_status_api(authenticated_page: Page, base_url: str) -> None:
    """GET /api/vpn/status -> validates full JSON telemetry payload."""
    page = authenticated_page
    status_data = api_get(page, "/api/vpn/status")

    assert isinstance(status_data, dict), f"Expected dict, got {type(status_data)}"

    # Top-level status fields
    assert_response_shape(
        status_data,
        {
            "configured_engine": str,
            "active_engine": str,
            "engine_running": bool,
            "listen_port": int,
            "listener_running": bool,
            "active_tunnels": int,
            "connected_sessions": int,
            "health_assessment": dict,
            "rates": dict,
            "queue_pressure": dict,
            "forward_latency": dict,
            "drop_categories": dict,
            "virtual_tun": dict,
            "routing_consistency": dict,
            "backends": dict,
            "runtime_resources": dict,
            "historical_series": dict,
        },
        "vpn_status",
    )

    # Validate health assessment
    health = status_data["health_assessment"]
    assert "status" in health
    assert health["status"] in ("HEALTHY", "DEGRADED", "CRITICAL")
    assert "conditions" in health
    assert isinstance(health["conditions"], list)

    schema_valid = (
        type(status_data.get("status_schema_version")) is int
        and status_data.get("status_schema_version") == 2
    )
    assert schema_valid, "VPN status must use schema version 2"

    # Check privacy before shape helpers can include any response values in failures.
    for inventory in ("problem_routes", "all_routes"):
        problem_routes = status_data.get(inventory)
        routes_valid = problem_routes is None or isinstance(problem_routes, list)
        assert routes_valid, "route inventory must be a list or null"
        for route in problem_routes or []:
            route_valid = isinstance(route, dict)
            assert route_valid, "problem route must be an object"
            peer_key = route.get("peer_key")
            peer_key_valid = isinstance(peer_key, str) and 0 < len(peer_key) <= 9
            assert (
                peer_key_valid
            ), "peer_key must be present, nonempty redacted text (at most 9 characters)"
    queues = status_data.get("forwarder_route_queues")
    queues_valid = queues is None or isinstance(queues, dict)
    assert queues_valid, "route queue inventory must be an object or null"
    for fingerprint, queue in (queues or {}).items():
        fingerprint_valid = isinstance(fingerprint, str) and bool(
            re.fullmatch(r"pk[0-9a-f]{24}-[0-9]+", fingerprint)
        )
        assert fingerprint_valid, "route queue map must use opaque fingerprints"
        queue_valid = isinstance(queue, dict)
        assert queue_valid, "route queue must be an object"
        display = queue.get("peer_key_display")
        display_valid = isinstance(display, str) and 0 < len(display) <= 9
        assert display_valid, "route queue display must be nonempty redacted text"

    _assert_extended_diagnostics(status_data)

    # Validate rates
    rates = status_data["rates"]
    assert "rx_bps" in rates and "tx_bps" in rates and "drop_rate_pps" in rates

    # Validate queue pressure
    queue = status_data["queue_pressure"]
    assert "capacity" in queue and "occupancy" in queue and "utilization_pct" in queue

    # Validate forward latency percentiles
    lat = status_data["forward_latency"]
    assert "p50_ms" in lat and "p95_ms" in lat and "p99_ms" in lat

    # Validate virtualtun
    vtun = status_data["virtual_tun"]
    assert "upstream_to_nexus" in vtun and "nexus_to_upstream" in vtun

    # Validate backends
    backends = status_data["backends"]
    assert "total_count" in backends and "healthy_count" in backends

    # Validate runtime resources
    runtime = status_data["runtime_resources"]
    assert "cpu_percent" in runtime and "goroutines" in runtime
    assert type(runtime.get("memory_limit_available")) is bool

    # Validate the Peer Sync panel source. The panel renders status.peer_sync,
    # so every key it reads must exist there with a compatible type when the
    # payload is present. peer_sync is omitempty, so absence is legal; the
    # panel renders an explicit unavailable state in that case.
    assert "peer_sync" in status_data
    peer_sync = status_data["peer_sync"]
    if peer_sync is not None:
        assert isinstance(peer_sync, dict)
        for key in (
            "desired_peers",
            "actual_peers",
            "invalid_rows",
            "sync_failures",
            "add_failures",
            "update_failures",
            "remove_failures",
            "enqueue_failures",
            "last_successful_reconcile",
            "portal_config_restart_required",
        ):
            assert key in peer_sync, f"peer_sync missing {key}"
        assert isinstance(peer_sync["desired_peers"], int)
        assert isinstance(peer_sync["actual_peers"], int)
        assert isinstance(peer_sync["invalid_rows"], int)
        for key in (
            "sync_failures",
            "add_failures",
            "update_failures",
            "remove_failures",
            "enqueue_failures",
        ):
            assert isinstance(peer_sync[key], int)
        assert isinstance(peer_sync["portal_config_restart_required"], bool)
        # sync_failures is an AGGREGATE of the per-operation counters:
        # peerSynchronizer.fail increments it AND the operation increments its
        # own counter, so a single failed add raises BOTH sync_failures and
        # add_failures. The panel must therefore render them as separate rows
        # and must never sum them (issue #424 round 3, finding 3). A sum would
        # read 2 for one failed add.
        assert peer_sync["sync_failures"] >= max(
            peer_sync["add_failures"],
            peer_sync["update_failures"],
            peer_sync["remove_failures"],
        ), (
            "sync_failures is the aggregate of the per-operation counters and "
            "cannot be smaller than any of them: "
            f"{peer_sync}"
        )
        # Optional omitempty error strings the panel surfaces when set.
        for key in ("last_error", "last_enqueue_error"):
            if key in peer_sync:
                assert isinstance(peer_sync[key], str)

    # Validate the drop categories the panel renders. client_virtualtun_drops
    # is the Upstream -> Nexus VirtualTUN bucket added in round 2; it must be
    # part of client_total_drops so headline loss cannot read zero while the
    # upstream-to-Nexus queue drops.
    drops = status_data["drop_categories"]
    assert "client_virtualtun_drops" in drops
    assert "return_injection_tun_drops" in drops
    client_categories = sum(
        drops[f"client_{r}"]
        for r in (
            "malformed unmapped_source mismatch rejected backend_queue_full "
            "rate_limited no_healthy_backend virtualtun_drops "
            "backend_device_queue_full backend_device_oversized "
            "backend_device_shutdown backend_device_external"
        ).split()
    )
    return_categories = sum(
        drops[f"return_{r}"]
        for r in (
            "malformed unmapped mismatch injection_errors virtualtun_drops "
            "queue_full packet_too_large backend_device_queue_full "
            "backend_device_shutdown"
        ).split()
    )
    assert client_categories == drops["client_total_drops"], (
        f"client categories sum {client_categories} != client_total_drops "
        f"{drops['client_total_drops']}"
    )
    assert return_categories == drops["return_total_drops"], (
        f"return categories sum {return_categories} != return_total_drops "
        f"{drops['return_total_drops']}"
    )
    assert (
        drops["client_total_drops"]
        + drops["return_total_drops"]
        + drops["backend_device_unattributed"]
        == drops["total_drops"]
    ), (
        f"total_drops {drops['total_drops']} != sum of client ({drops['client_total_drops']}), "
        f"return ({drops['return_total_drops']}), and backend_device_unattributed "
        f"({drops['backend_device_unattributed']})"
    )

    # Both queues have independent observations; renderer tests prove their
    # source-to-panel direction. API shape alone cannot prove physical ownership.
    for direction in ("upstream_to_nexus", "nexus_to_upstream"):
        observation = status_data["virtual_tun"][direction]
        observation_valid = isinstance(observation, dict) and set(observation) == {
            "occupancy",
            "capacity",
            "peak",
            "drops",
        }
        assert observation_valid, "VirtualTUN queue observation is incomplete"
        values_valid = all(type(value) is int and value >= 0 for value in observation.values())
        assert values_valid, "VirtualTUN queue observations must be nonnegative integers"

    # Validate routing consistency exposes both the lifetime counter (history)
    # and the windowed delta (current health).
    routing = status_data["routing_consistency"]
    assert "ownership_mismatch_drops" in routing
    assert "ownership_mismatch_drops_recent" in routing
    if routing["ownership_mismatch_drops_recent"] == 0:
        assert routing["is_consistent"] or routing.get("inconsistency_details")


@pytest.mark.e2e
def test_vpn_metrics_api(authenticated_page: Page, base_url: str) -> None:
    """Require an authenticated Prometheus histogram with coherent cumulative counts."""
    response = authenticated_page.request.get(f"{base_url}/api/vpn/metrics")
    assert response.status == 200, "VPN metrics scrape failed"
    assert response.headers.get("content-type", "").startswith("text/plain; version=0.0.4")
    text = response.text()
    name = "nexus_forwarder_write_duration_seconds"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    assert f"# TYPE {name} histogram" in lines
    count_values: list[int] = []
    sum_values: list[float] = []
    buckets: list[tuple[float, int]] = []
    number = r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
    for line in lines:
        if line.startswith("#"):
            continue
        bucket = re.fullmatch(rf'{name}_bucket\{{le="({number}|\+Inf)"\}} (\d+)', line)
        count = re.fullmatch(rf"{name}_count (\d+)", line)
        total = re.fullmatch(rf"{name}_sum ({number})", line)
        assert bucket or count or total, "Unexpected histogram sample or unbounded labels"
        if bucket:
            boundary = float(bucket.group(1))
            assert boundary > 0, "Histogram bucket boundary must be positive"
            buckets.append((boundary, int(bucket.group(2))))
        elif count:
            count_values.append(int(count.group(1)))
        elif total:
            sum_values.append(float(total.group(1)))
    assert len(count_values) == 1 and len(sum_values) == 1
    assert math.isfinite(sum_values[0]) and sum_values[0] >= 0
    assert len(buckets) >= 2, "Histogram buckets are missing"
    boundaries = [boundary for boundary, _ in buckets]
    assert boundaries[-1] == math.inf
    assert all(math.isfinite(boundary) for boundary in boundaries[:-1])
    assert boundaries == sorted(set(boundaries)), "Histogram boundaries must be unique and ordered"
    assert boundaries[0] < 0.001, "Histogram must resolve sub-millisecond writes"
    observations = [count for _, count in buckets]
    assert observations == sorted(observations), "Histogram bucket counts must be cumulative"
    assert observations[-1] == count_values[0], "Infinite bucket and observation count must agree"
    if count_values[0] == 0:
        assert sum_values[0] == 0, "Empty histogram cannot have a duration sum"


@pytest.mark.e2e
def test_vpn_metrics_requires_authentication(page: Page, base_url: str) -> None:
    """An anonymous scrape must be rejected before any histogram is disclosed."""
    response = page.request.get(f"{base_url}/api/vpn/metrics")
    assert response.status == 401
    assert response.json().get("error") == "unauthorized"


@pytest.mark.e2e
def test_vpn_dashboard_sections_visual_order_and_vertical_layout(
    authenticated_page: Page, base_url: str
) -> None:
    """Navigate to /vpn -> assert strictly increasing visual y-order and non-overlapping vertical layout."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Locate the 4 sections
    stats_grid = page.locator(".stats-grid").first
    backends_card = page.locator("#vpnBackendsTable").locator(
        "xpath=ancestor::div[contains(@class, 'card')][1]"
    )
    sessions_card = page.locator("#vpnSessionsTable").locator(
        "xpath=ancestor::div[contains(@class, 'card')][1]"
    )
    forwarder_card = page.locator("#vpn-forwarder-card")

    sections = [
        ("stats-grid", stats_grid),
        ("backends-card", backends_card),
        ("sessions-card", sessions_card),
        ("forwarder-card", forwarder_card),
    ]

    boxes = []
    for name, locator in sections:
        expect(locator).to_be_visible()
        box = locator.bounding_box()
        assert box is not None, f"Bounding box for {name} was not found"
        boxes.append((name, box))

    for i in range(len(boxes) - 1):
        curr_name, curr_box = boxes[i]
        next_name, next_box = boxes[i + 1]
        assert curr_box["y"] < next_box["y"], f"Expected y({curr_name}) < y({next_name})"
        assert (
            next_box["y"] >= curr_box["y"] + curr_box["height"] - 1
        ), f"Expected {next_name} y >= {curr_name} bottom"
