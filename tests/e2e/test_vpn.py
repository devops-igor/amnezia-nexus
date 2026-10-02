"""E2E tests for VPN subsystem and forwarder health dashboard."""

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
    ]
    for chart in charts:
        expect(page.locator(chart)).to_be_visible()

    toggles_container = page.locator("#vpn-history-window-toggles")
    expect(toggles_container).to_be_visible()

    windows = ["1h", "6h", "24h", "15m"]
    for win in windows:
        btn = toggles_container.locator(f"button:has-text('{win}')")
        expect(btn).to_be_visible()
        btn.click()
        expect(btn).to_have_class("btn btn-sm btn-primary active")


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

    # Validate rates
    rates = status_data["rates"]
    assert "rx_bps" in rates and "tx_bps" in rates and "total_bps" in rates

    # Validate queue pressure
    queue = status_data["queue_pressure"]
    assert "capacity" in queue and "occupancy" in queue and "pressure_pct" in queue

    # Validate forward latency percentiles
    lat = status_data["forward_latency"]
    assert "p50_ms" in lat and "p95_ms" in lat and "p99_ms" in lat

    # Validate virtualtun
    vtun = status_data["virtual_tun"]
    assert "upstream_to_nexus" in vtun and "nexus_to_upstream" in vtun

    # Validate backends
    backends = status_data["backends"]
    assert "total" in backends and "healthy" in backends

    # Validate runtime resources
    runtime = status_data["runtime_resources"]
    assert "cpu_percent" in runtime and "goroutines" in runtime


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
        assert update_result["status"] == 200, f"Config update failed: {update_result}"
        assert update_result["body"].get("status") == "ok"

        # Verify update reflected in GET
        updated_config = api_get(page, "/api/vpn/config")
        assert updated_config.get("health_threshold_ms") == new_threshold

    finally:
        # Restore original threshold
        api_post(
            page,
            "/api/vpn/config",
            {"health_threshold_ms": orig_threshold},
            csrf_token,
        )


@pytest.mark.e2e
def test_vpn_backend_enable_disable(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """POST /api/vpn/backends/{server_id}/disable and enable -> toggles backend state."""
    page = authenticated_page

    servers_result = api_get(page, "/api/servers/")
    servers = (
        servers_result if isinstance(servers_result, list) else servers_result.get("servers", [])
    )

    if not servers:
        pytest.skip("No servers available to test backend toggle")

    server_id = servers[0]["id"]

    # First enable backend tunnel so it is registered in the pool
    enable_result = api_post(
        page,
        f"/api/vpn/backends/{server_id}/enable",
        {},
        csrf_token,
    )
    assert enable_result["status"] in (200, 400), f"Initial backend enable failed: {enable_result}"

    # Disable backend tunnel
    disable_result = api_post(
        page,
        f"/api/vpn/backends/{server_id}/disable",
        {},
        csrf_token,
    )
    if enable_result["status"] == 200:
        assert disable_result["status"] == 200, f"Backend disable failed: {disable_result}"
        assert disable_result["body"].get("status") == "ok"

        # Re-enable backend tunnel to leave server operational
        re_enable = api_post(
            page,
            f"/api/vpn/backends/{server_id}/enable",
            {},
            csrf_token,
        )
        assert re_enable["status"] in (200, 400), f"Backend re-enable failed: {re_enable}"
    else:
        assert disable_result["status"] in (200, 404, 500)


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
