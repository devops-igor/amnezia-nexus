"""Read-only E2E checks for the forwarder health dashboard and diagnostics."""

import math
import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get, assert_response_shape


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
    badge = page.locator("#vpn-fwd-status-badge")
    expect(badge).to_be_visible()

    status_text = page.locator("#vpn-fwd-status-text")
    expect(status_text).to_be_visible()

    headline_summary = page.locator("#vpn-fwd-headline-summary")
    expect(headline_summary).to_be_visible()


@pytest.mark.e2e
def test_vpn_kpi_summary_bar(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> verifies 8 KPI summary cards are rendered."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    kpi_locators = [
        "#vpn-kpi-throughput",
        "#vpn-kpi-routes-sessions",
        "#vpn-kpi-queue-pressure",
        "#vpn-kpi-packet-loss",
        "#vpn-kpi-client-engine",
        "#vpn-kpi-peer-sync",
        "#vpn-kpi-backends",
        "#vpn-kpi-slow-writes",
    ]

    for loc in kpi_locators:
        el = page.locator(loc)
        expect(el).to_be_visible()

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

    diag_fields = [
        # Card 1: Data Plane Performance
        "#vpn-diag-throughput",
        "#vpn-diag-ewma5m",
        "#vpn-diag-ewma1h",
        "#vpn-diag-lat-percentiles",
        "#vpn-diag-lat-max",
        "#vpn-diag-queue-occ",
        "#vpn-diag-queue-peak",
        # Card 2: Traffic Drops & Loss Diagnostics
        "#vpn-diag-drops-client",
        "#vpn-diag-drops-return",
        "#vpn-diag-drops-total",
        # Card 3: Engine & Route Integrity
        "#vpn-diag-engine-status",
        "#vpn-diag-peers-status",
        "#vpn-diag-hs-freshness",
        "#vpn-diag-routing-counts",
        # Card 4: System & Fleet Resources
        "#vpn-diag-res-cpu",
        "#vpn-diag-res-mem",
        "#vpn-diag-res-fd",
    ]

    for loc in diag_fields:
        el = page.locator(loc)
        expect(el).to_be_visible()

    for obsolete in ["#vpn-diag-packets", "#vpn-diag-res-goroutines", "#vpn-diag-res-gc", "#vpn-fwd-routes-details"]:
        expect(page.locator(obsolete)).to_have_count(0)


@pytest.mark.e2e
def test_vpn_sparklines_window_toggle(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> interactive time window toggle (15m, 1h, 6h, 24h)."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Historical trends container and chart containers
    charts = [
        "#vpn-chart-throughput",
        "#vpn-chart-queue",
        "#vpn-chart-drops",
        "#vpn-chart-latency",
        "#vpn-chart-directions",
        "#vpn-chart-packets",
        "#vpn-chart-sessions-routes",
        "#vpn-chart-backend-latency",
    ]
    for chart in charts:
        expect(page.locator(chart)).to_be_visible()

    breakdown = page.locator("details:not(#vpn-fwd-tech-details)").filter(
        has=page.locator("#vpn-chart-reasons")
    )
    breakdown.locator("summary").click()
    for chart in ("#vpn-chart-reasons", "#vpn-chart-backends"):
        expect(page.locator(chart)).to_be_visible()
    expect(page.locator("#vpn-history-fleet-note")).to_be_attached()

    toggles_container = page.locator("#vpn-history-window-toggles")
    expect(toggles_container).to_be_visible()

    windows = ["1h", "6h", "24h", "15m"]
    for win in windows:
        btn = toggles_container.locator(f"button:has-text('{win}')")
        expect(btn).to_be_visible()
        btn.click()
        expect(btn).to_have_class("btn btn-sm btn-primary active")
        for chart in charts + ["#vpn-chart-reasons", "#vpn-chart-backends"]:
            expect(page.locator(chart)).to_be_visible()


@pytest.mark.e2e
def test_vpn_problem_routes_toggle(authenticated_page: Page, base_url: str) -> None:
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


_LOSS_REASONS = {
    "client_malformed",
    "client_unmapped_source",
    "client_mismatch",
    "client_rejected",
    "client_backend_queue_full",
    "client_rate_limited",
    "client_no_healthy_backend",
    "client_virtualtun_drops",
    "client_backend_device_queue_full",
    "client_backend_device_oversized",
    "client_backend_device_shutdown",
    "client_backend_device_external",
    "backend_device_unattributed",
    "return_malformed",
    "return_unmapped",
    "return_mismatch",
    "return_injection_errors",
    "return_virtualtun_drops",
    "return_queue_full",
    "return_packet_too_large",
    "return_backend_device_queue_full",
    "return_backend_device_shutdown",
}


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
    client_categories = (
        drops["client_malformed"]
        + drops["client_unmapped_source"]
        + drops["client_mismatch"]
        + drops["client_rejected"]
        + drops["client_backend_queue_full"]
        + drops["client_rate_limited"]
        + drops["client_no_healthy_backend"]
        + drops["client_virtualtun_drops"]
        + drops["client_backend_device_queue_full"]
        + drops["client_backend_device_oversized"]
        + drops["client_backend_device_shutdown"]
        + drops["client_backend_device_external"]
    )
    return_categories = (
        drops["return_malformed"]
        + drops["return_unmapped"]
        + drops["return_mismatch"]
        + drops["return_injection_errors"]
        + drops["return_virtualtun_drops"]
        + drops["return_queue_full"]
        + drops["return_packet_too_large"]
        + drops["return_backend_device_queue_full"]
        + drops["return_backend_device_shutdown"]
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
