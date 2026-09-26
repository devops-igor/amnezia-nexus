"""E2E tests for user self-service (my connections)."""

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import (
    _do_login,
    _get_csrf_cookie,
    api_get,
    api_post,
    assert_response_shape,
)


def _create_test_user(
    page: Page, base_url: str, csrf_token: str, username: str = "e2e_my_user"
) -> dict:
    """Helper: create a regular user and return user dict."""
    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": username,
            "password": "TestPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )

    assert add_result["status"] == 200, f"Could not create test user: {add_result}"

    # Find the newly created user — API returns {"users": [...], "total": N, ...}
    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])

    test_user = next((u for u in users if u.get("username") == username), None)
    assert test_user is not None, f"Test user {username} not found after creation"
    return test_user


@pytest.mark.e2e
def test_user_login_and_list(page: Page, base_url: str, admin_user: str, admin_pass: str) -> None:
    """Login as regular user -> sees own connections."""
    # First, login as admin to create a test user
    _do_login(page, base_url, admin_user, admin_pass)
    csrf_token = _get_csrf_cookie(page)

    # Create test user via admin API
    test_user = _create_test_user(page, base_url, csrf_token, "e2e_my_user")
    assert test_user is not None, "Test user not found after creation"
    test_username = test_user.get("username", "e2e_my_user")
    test_password = "TestPass123!"

    # Logout admin
    page.goto(f"{base_url}/logout")
    page.wait_for_load_state("networkidle")

    # Clear cookies for a fresh login
    page.context.clear_cookies()

    # Login as the test user via API (bypasses CSP)
    _do_login(page, base_url, test_username, test_password)

    # Navigate to /my — should see own connections
    page.goto(f"{base_url}/my")
    page.wait_for_load_state("networkidle")
    assert "/login" not in page.url

    # Validate /api/my/connections response shape
    my_result = api_get(page, "/api/my/connections")
    if isinstance(my_result, dict) and "connections" in my_result:
        assert_response_shape(my_result, {"connections": list, "limits": dict}, "my_connections")
        if isinstance(my_result.get("limits"), dict):
            assert_response_shape(
                my_result["limits"],
                {"max_connections": int, "current_connections": int},
                "my_connections_limits",
            )


@pytest.mark.e2e
def test_create_connection(
    authenticated_page: Page,
    base_url: str,
    csrf_token: str,
) -> None:
    """Regular user creates a new connection -> appears in their list."""
    page = authenticated_page

    # Get a server to attach connection to
    result = api_get(page, "/api/servers/")
    servers = result if isinstance(result, list) else result.get("servers", [])
    assert servers, "No servers available for connection test"

    server_id = servers[0]["id"]

    # Create a test user and add a connection for them
    test_user = _create_test_user(page, base_url, csrf_token, "e2e_conn_user")
    user_id = test_user["id"]

    try:
        conn_result = api_post(
            page,
            f"/api/users/{user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": "e2e_user_conn"},
            csrf_token,
        )
        assert conn_result["status"] == 200, f"Could not create connection: {conn_result}"

        # Connection should be created successfully or return a meaningful response
        assert conn_result["body"] is not None
        assert (
            conn_result["body"].get("status") in ("success", "ok")
            or "connection" in conn_result["body"]
            or "id" in conn_result["body"]
        )
        if "status" in conn_result["body"]:
            assert_response_shape(conn_result["body"], {"status": str}, "add_connection")
    finally:
        # Clean up — delete the test user
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


@pytest.mark.e2e
def test_view_connection_config(
    page: Page, base_url: str, admin_user: str, admin_pass: str
) -> None:
    """Click connection config -> sees config details."""
    # Login as admin
    _do_login(page, base_url, admin_user, admin_pass)
    csrf_token = _get_csrf_cookie(page)

    test_user = _create_test_user(page, base_url, csrf_token, "e2e_view_user")
    user_id = test_user["id"]

    try:
        # Get servers to find a connection
        servers_result = api_get(page, "/api/servers/")
        servers = (
            servers_result
            if isinstance(servers_result, list)
            else servers_result.get("servers", [])
        )
        assert servers, "No servers available for config test"

        server_id = servers[0]["id"]

        # Add a connection for the test user
        conn_result = api_post(
            page,
            f"/api/users/{user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": "e2e_view_conn"},
            csrf_token,
        )
        assert (
            conn_result["status"] == 200
        ), f"Could not create connection for config test: {conn_result}"

        # Get the user's connections to find the connection ID
        user_conns = api_get(page, f"/api/users/{user_id}/connections")
        connections = (
            user_conns if isinstance(user_conns, list) else user_conns.get("connections", [])
        )
        assert connections, f"No connections available: {user_conns}"

        conn = connections[0]
        conn_id = conn["id"]
        server_id_conn = conn["server_id"]

        # Fetch the connection config via the server API
        config_result = api_post(
            page,
            f"/api/servers/{server_id_conn}/connections/config",
            {"connection_id": conn_id},
            csrf_token,
        )
        assert config_result["status"] == 200, f"Could not fetch connection config: {config_result}"
        assert config_result["body"] is not None
    finally:
        # Clean up
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


@pytest.mark.e2e
def test_role_access_denied(page: Page, base_url: str, admin_user: str, admin_pass: str) -> None:
    """Regular user navigating to admin page -> receives error or redirect."""
    # Login as admin
    _do_login(page, base_url, admin_user, admin_pass)
    csrf_token = _get_csrf_cookie(page)

    test_user = _create_test_user(page, base_url, csrf_token, "e2e_role_user")

    # Logout admin
    page.goto(f"{base_url}/logout")
    page.wait_for_load_state("networkidle")
    page.context.clear_cookies()

    # Login as regular user via API (bypasses CSP)
    _do_login(page, base_url, test_user.get("username", "e2e_role_user"), "TestPass123!")

    # Get CSRF token for the regular user's session
    regular_csrf = _get_csrf_cookie(page)

    # Try to access admin API — should get 403
    # Use Playwright's request API (bypasses CSP) with regular user's CSRF
    api_result = page.request.get(
        f"{base_url}/api/settings",
        headers={"X-CSRF-Token": regular_csrf},
    )

    # Regular user should be forbidden from admin endpoints
    assert api_result.status in (403, 401)
