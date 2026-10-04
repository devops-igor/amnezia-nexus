"""E2E tests for VPN subsystem and forwarder health dashboard."""

import math
import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get, api_post, assert_response_shape


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
        # Panel 1: Traffic & Capacity
        "#vpn-diag-throughput",
        "#vpn-diag-packets",
        "#vpn-diag-ewma5m",
        "#vpn-diag-ewma1h",
        # Panel 2: Queue Pressure & High-Water
        "#vpn-diag-queue-occ",
        "#vpn-diag-queue-peak",
        "#vpn-diag-queue-dur50",
        "#vpn-diag-queue-dur80",
        "#vpn-diag-queue-drops",
        # Panel 3: Forwarding Latency & Write Stalls
        "#vpn-diag-lat-percentiles",
        "#vpn-diag-lat-max",
        "#vpn-diag-lat-inflight",
        "#vpn-diag-lat-stalls",
        "#vpn-diag-lat-errors",
        # Panel 4: Drop Diagnostics
        "#vpn-diag-drops-client",
        "#vpn-diag-drops-return",
        "#vpn-diag-drops-total",
        # Panel 5: VirtualTUN Health
        "#vpn-diag-vtun-upstream",
        "#vpn-diag-vtun-nexus",
        # Panel 6: Upstream AWG & Peer Sync
        "#vpn-diag-engine-status",
        "#vpn-diag-peers-status",
        "#vpn-diag-sync-failures",
        "#vpn-diag-peer-sync-invalid",
        "#vpn-diag-peer-sync-enqueue",
        "#vpn-diag-peer-sync-reconcile",
        "#vpn-diag-peer-sync-error",
        "#vpn-diag-peer-sync-restart",
        "#vpn-diag-hs-freshness",
        # Panel 7: Routing Consistency Invariants
        "#vpn-diag-routing-badge",
        "#vpn-diag-routing-counts",
        # Panel 8: Backend Operational Telemetry
        "#vpn-diag-be-counts",
        "#vpn-diag-be-latency",
        "#vpn-diag-be-skew",
        "#vpn-diag-be-drops",
        # Panel 9: Runtime Resources
        "#vpn-diag-res-cpu",
        "#vpn-diag-res-mem",
        "#vpn-diag-res-goroutines",
        "#vpn-diag-res-gc",
        "#vpn-diag-res-fd",
    ]

    for loc in diag_fields:
        el = page.locator(loc)
        expect(el).to_be_visible()


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

    breakdown = page.locator("details").filter(has=page.locator("#vpn-chart-reasons"))
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
    """Navigate to /vpn -> Problem Routes details and 'Show all routes' toggle."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

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
    "client_backend_device_unattributed",
    "client_backend_device_retired_drops",
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

    # Validate problem_routes: peer_key must be PRESENT, non-empty and REDACTED
    # (issue #424 round 4, item E). The API response is the disclosure surface,
    # so a full-length base64 peer key must never appear in it. The redaction
    # convention (ingress.RedactKey) keeps 8 characters plus an ellipsis, or
    # masks shorter values entirely, so a redacted key is at most 9 characters.
    problem_routes = status_data.get("problem_routes")
    routes_valid = problem_routes is None or isinstance(problem_routes, list)
    assert routes_valid, "problem_routes must be a list or null"
    for route in problem_routes or []:
        route_valid = isinstance(route, dict)
        assert route_valid, "problem route must be an object"
        peer_key = route.get("peer_key")
        peer_key_valid = isinstance(peer_key, str) and 0 < len(peer_key) <= 9
        assert (
            peer_key_valid
        ), "peer_key must be present, nonempty redacted text (at most 9 characters)"

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
        + drops["client_backend_device_unattributed"]
        + drops["client_backend_device_retired_drops"]
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
        drops["client_total_drops"] + drops["return_total_drops"] == drops["total_drops"]
    ), "total_drops must be client plus return, with no packet counted twice"

    # Validate the VirtualTUN directions are distinct in the payload, so a
    # swapped mapping cannot pass silently.
    vtun_dirs = status_data["virtual_tun"]["upstream_to_nexus"]
    assert set(vtun_dirs) == {"occupancy", "capacity", "peak", "drops"}

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
def test_vpn_sessions_api(authenticated_page: Page, base_url: str) -> None:
    """GET /api/vpn/sessions -> returns active sessions list."""
    page = authenticated_page
    result = api_get(page, "/api/vpn/sessions")

    assert isinstance(result, dict)
    assert "sessions" in result
    assert isinstance(result["sessions"], list)


@pytest.mark.e2e
def test_vpn_backends_api(authenticated_page: Page, base_url: str) -> None:
    """GET /api/vpn/backends -> returns configured backend tunnels list."""
    page = authenticated_page
    result = api_get(page, "/api/vpn/backends")

    assert isinstance(result, dict)
    assert "backends" in result
    assert isinstance(result["backends"], list)


@pytest.mark.e2e
def test_vpn_tunnels_api(authenticated_page: Page, base_url: str) -> None:
    """GET /api/vpn/tunnels -> returns active tunnels list."""
    page = authenticated_page
    result = api_get(page, "/api/vpn/tunnels")

    assert isinstance(result, dict)
    assert "tunnels" in result
    assert isinstance(result["tunnels"], list)


@pytest.mark.e2e
def test_vpn_config_lifecycle(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """GET and POST /api/vpn/config -> queries and updates configuration."""
    page = authenticated_page

    config_data = api_get(page, "/api/vpn/config")
    assert isinstance(config_data, dict)
    assert_response_shape(
        config_data,
        {
            "algorithm": str,
            "health_threshold_ms": int,
            "listen_port": int,
            "subnet_cidr": str,
        },
        "vpn_config",
    )

    orig_threshold = config_data["health_threshold_ms"]
    new_threshold = 600 if orig_threshold != 600 else 700

    try:
        # Update config via POST
        update_result = api_post(
            page,
            "/api/vpn/config",
            {"health_threshold_ms": new_threshold},
            csrf_token,
        )
        assert update_result["status"] == 200, "VPN config update failed"
        assert update_result["body"].get("status") == "ok"

        # Verify update reflected in GET
        updated_config = api_get(page, "/api/vpn/config")
        assert updated_config.get("health_threshold_ms") == new_threshold

    finally:
        # Restore the original threshold and verify the shared fixture state.
        restored = api_post(
            page,
            "/api/vpn/config",
            {"health_threshold_ms": orig_threshold},
            csrf_token,
        )
        assert restored["status"] == 200, "VPN config restoration failed"
        assert restored["body"].get("status") == "ok"
        restored_config = api_get(page, "/api/vpn/config")
        assert restored_config.get("health_threshold_ms") == orig_threshold


def _backend_for_server(page: Page, server_id: int) -> dict | None:
    """Read backend inventory without accepting a failed or malformed listing."""
    result = api_get(page, "/api/vpn/backends")
    assert isinstance(result, dict)
    assert isinstance(result.get("backends"), list)
    backend = next(
        (item for item in result["backends"] if item.get("server_id") == server_id), None
    )
    if backend is not None:
        assert isinstance(backend.get("enabled"), bool)
    return backend


def _backend_enabled(page: Page, server_id: int) -> bool:
    """Require a registered fixture and read its administrative state."""
    backend = _backend_for_server(page, server_id)
    assert backend is not None, "Provisioned backend is missing"
    return backend["enabled"]


@pytest.mark.e2e
def test_vpn_backend_enable_disable(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Enable a provisioned backend, verify both state transitions, and restore its state."""
    page = authenticated_page
    result = api_get(page, "/api/servers/")
    servers = result if isinstance(result, list) else result.get("servers", [])
    assert servers, "Provisioned server fixture is missing"
    server_id = servers[0]["id"]
    original = _backend_for_server(page, server_id)
    # A newly provisioned backend remains enabled for the subsequent traffic stage.
    original_enabled = original["enabled"] if original is not None else True
    try:
        enabled = api_post(page, f"/api/vpn/backends/{server_id}/enable", {}, csrf_token)
        assert enabled["status"] == 200, "Initial backend enable failed"
        assert enabled["body"].get("status") == "ok"
        assert _backend_enabled(page, server_id), "Backend enable did not persist"
        disabled = api_post(page, f"/api/vpn/backends/{server_id}/disable", {}, csrf_token)
        assert disabled["status"] == 200, "Backend disable failed"
        assert disabled["body"].get("status") == "ok"
        assert not _backend_enabled(page, server_id), "Backend disable did not persist"
        re_enabled = api_post(page, f"/api/vpn/backends/{server_id}/enable", {}, csrf_token)
        assert re_enabled["status"] == 200, "Backend re-enable failed"
        assert re_enabled["body"].get("status") == "ok"
        assert _backend_enabled(page, server_id), "Backend re-enable did not persist"
    finally:
        current = _backend_for_server(page, server_id)
        if current is not None:
            # A failed positive call can have partially changed state. Restore
            # actual differences while preserving the first failure without a
            # redundant retry when the original state is already intact.
            if current["enabled"] != original_enabled:
                action = "enable" if original_enabled else "disable"
                restored = api_post(page, f"/api/vpn/backends/{server_id}/{action}", {}, csrf_token)
                assert restored["status"] == 200, "Backend fixture restoration failed"
            matches = _backend_enabled(page, server_id) == original_enabled
            assert matches, "Original backend enabled state was not restored"
        else:
            assert original is None, "Original backend fixture disappeared during the lifecycle"


@pytest.mark.e2e
def test_vpn_disconnect_session(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """POST /api/vpn/disconnect -> terminates active user or session connection."""
    page = authenticated_page

    disconnect_result = api_post(
        page,
        "/api/vpn/disconnect",
        {"session_id": "nonexistent_session_id"},
        csrf_token,
    )
    assert disconnect_result["status"] == 200, f"Disconnect failed: {disconnect_result}"
    assert disconnect_result["body"].get("status") == "ok"


@pytest.mark.e2e
def test_vpn_user_self_service(authenticated_page: Page, base_url: str) -> None:
    """GET /api/vpn/my-connection and /api/vpn/my-config -> user self-service state."""
    page = authenticated_page

    # User connection state
    conn_state = api_get(page, "/api/vpn/my-connection")
    assert isinstance(conn_state, dict)
    assert "connected" in conn_state
    assert isinstance(conn_state["connected"], bool)

    # User config text
    cfg_data = api_get(page, "/api/vpn/my-config")
    assert isinstance(cfg_data, dict)
    assert_response_shape(
        cfg_data,
        {
            "status": str,
            "config": str,
            "filename": str,
            "vpn_link": str,
        },
        "vpn_my_config",
    )
    assert cfg_data["status"] == "ok"
