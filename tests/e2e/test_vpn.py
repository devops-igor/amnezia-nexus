"""E2E checks for VPN platform operations and self-service."""

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import api_get, api_post, assert_response_shape


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
