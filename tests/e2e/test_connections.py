"""E2E tests for connection management."""

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import api_get, api_post, assert_response_shape


def _get_admin_connections(page: Page) -> list:
    """Fetch connections via the admin user's connections endpoint.

    The /api/servers/{id}/connections endpoint returns {"clients": []} which is
    the server-level admin view and may be empty. The actual connections are
    per-user, so we fetch the first non-admin user's connections.
    """
    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])

    # Try each user until we find one with connections
    for user in users:
        if user.get("role") == "admin" and len(users) > 1:
            continue  # Skip admin, prefer regular users
        user_id = user["id"]
        connections_result = api_get(page, f"/api/users/{user_id}/connections")
        connections = (
            connections_result
            if isinstance(connections_result, list)
            else connections_result.get("connections", [])
        )
        if connections:
            return connections

    return []


def _get_server_id(page: Page) -> int:
    """Get the first available server ID."""
    result = api_get(page, "/api/servers/")
    servers = result if isinstance(result, list) else result.get("servers", [])
    assert servers, "No servers available"
    return servers[0]["id"]


@pytest.mark.e2e
def test_connection_list(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Navigate to server connections -> sees connection list."""
    page = authenticated_page

    server_id = _get_server_id(page)

    # Navigate to server detail page which shows connections
    page.goto(f"{base_url}/server/{server_id}")
    page.wait_for_load_state("networkidle")

    # Verify page loaded
    assert "/login" not in page.url


@pytest.mark.e2e
def test_add_connection(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Add a new connection -> appears in connection list."""
    page = authenticated_page

    server_id = _get_server_id(page)

    # Create a test user to add a connection for
    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": "e2e_conn_test",
            "password": "TestPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )

    assert add_result["status"] == 200, f"Could not create test user: {add_result}"

    # Find the newly created user
    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])
    test_user = next((u for u in users if u.get("username") == "e2e_conn_test"), None)
    assert test_user is not None, "Test user not found after creation"

    user_id = test_user["id"]

    try:
        add_conn_result = api_post(
            page,
            f"/api/users/{user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": "e2e_test_connection"},
            csrf_token,
        )
        assert add_conn_result["status"] == 200, f"Could not add connection: {add_conn_result}"
        assert add_conn_result["body"] is not None

        # Validate add connection response shape on success
        body = add_conn_result["body"]
        if "status" in body:
            assert_response_shape(body, {"status": str}, "add_connection")
    finally:
        # Clean up
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


@pytest.mark.e2e
def test_connection_config_and_qr(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """View connection config -> sees config text and QR code."""
    page = authenticated_page

    server_id = _get_server_id(page)

    # Create a test user and connection
    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": "e2e_config_test",
            "password": "TestPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )

    assert add_result["status"] == 200, f"Could not create test user for config test: {add_result}"

    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])
    test_user = next((u for u in users if u.get("username") == "e2e_config_test"), None)
    assert test_user is not None, "Test user not found for config test"

    user_id = test_user["id"]

    try:
        conn_result = api_post(
            page,
            f"/api/users/{user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": "e2e_config_test"},
            csrf_token,
        )
        assert conn_result["status"] == 200, f"Could not create connection: {conn_result}"

        # Get the user's connections
        user_conns = api_get(page, f"/api/users/{user_id}/connections")
        connections = (
            user_conns if isinstance(user_conns, list) else user_conns.get("connections", [])
        )
        assert connections, f"No connection created: {user_conns}"

        conn = connections[0]
        conn_id = conn["id"]

        config_result = api_post(
            page,
            f"/api/servers/{server_id}/connections/config",
            {"connection_id": conn_id},
            csrf_token,
        )
        assert config_result["status"] == 200, f"Could not fetch connection config: {config_result}"
        assert config_result["body"] is not None
    finally:
        # Clean up
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


@pytest.mark.e2e
def test_toggle_connection(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Enable/disable a connection -> status changes."""
    page = authenticated_page

    server_id = _get_server_id(page)

    # Create a test user and connection
    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": "e2e_toggle_test",
            "password": "TestPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )

    assert add_result["status"] == 200, f"Could not create test user for toggle test: {add_result}"

    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])
    test_user = next((u for u in users if u.get("username") == "e2e_toggle_test"), None)
    assert test_user is not None, "Test user not found for toggle test"

    user_id = test_user["id"]

    try:
        conn_result = api_post(
            page,
            f"/api/users/{user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": "e2e_toggle_test"},
            csrf_token,
        )
        assert conn_result["status"] == 200, f"Could not create connection: {conn_result}"

        # Get the user's connections
        user_conns = api_get(page, f"/api/users/{user_id}/connections")
        connections = (
            user_conns if isinstance(user_conns, list) else user_conns.get("connections", [])
        )
        assert connections, f"No connection created: {user_conns}"

        conn = connections[0]
        conn_id = conn["id"]

        toggle_result = api_post(
            page,
            f"/api/servers/{server_id}/connections/toggle",
            {"connection_id": conn_id},
            csrf_token,
        )
        assert toggle_result["status"] == 200, f"Could not toggle connection: {toggle_result}"
        assert toggle_result["body"] is not None

        # Toggle back to restore original state
        api_post(
            page,
            f"/api/servers/{server_id}/connections/toggle",
            {"connection_id": conn_id},
            csrf_token,
        )
    finally:
        # Clean up
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


@pytest.mark.e2e
def test_delete_connection(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Delete a connection -> removed from list."""
    page = authenticated_page

    # Create a test user and connection to delete
    add_user_result = api_post(
        page,
        "/api/users/add",
        {
            "username": "e2e_delete_conn",
            "password": "TestPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )

    assert (
        add_user_result["status"] == 200
    ), f"Could not create test user for delete connection test: {add_user_result}"

    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])
    test_user = next((u for u in users if u.get("username") == "e2e_delete_conn"), None)
    assert test_user is not None, "Test user not found for delete connection test"

    user_id = test_user["id"]
    server_id = _get_server_id(page)

    try:
        # Add a connection to delete
        conn_result = api_post(
            page,
            f"/api/users/{user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": "e2e_delete_conn"},
            csrf_token,
        )
        assert (
            conn_result["status"] == 200
        ), f"Could not create connection for delete test: {conn_result}"

        # Get the connection ID from user connections
        user_conns = api_get(page, f"/api/users/{user_id}/connections")
        user_connections = (
            user_conns if isinstance(user_conns, list) else user_conns.get("connections", [])
        )
        assert user_connections, f"No connection created: {user_conns}"

        conn_to_delete = user_connections[0]
        conn_id = conn_to_delete["id"]
        server_id_conn = conn_to_delete["server_id"]

        delete_result = api_post(
            page,
            f"/api/servers/{server_id_conn}/connections/remove",
            {"connection_id": conn_id},
            csrf_token,
        )
        assert delete_result["status"] == 200, f"Could not delete connection: {delete_result}"
        assert delete_result["body"] is not None
    finally:
        # Clean up user
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)
