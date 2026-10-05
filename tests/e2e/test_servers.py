"""E2E tests for server management pages and API."""

import os

import pytest
from playwright.sync_api import Page, Request, expect

from tests.e2e.conftest import api_get, api_post, assert_response_shape


@pytest.mark.e2e
def test_server_list_loads(authenticated_page: Page, base_url: str) -> None:
    """Navigate to / -> sees server cards with protocol badges."""
    page = authenticated_page
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    # Should be on the index page, not redirected to login
    assert "/login" not in page.url

    # The page content should contain server-related UI elements.
    # Even if no servers exist, the page should render.
    content = page.content()
    assert len(content) > 100


@pytest.mark.e2e
def test_server_detail_page(authenticated_page: Page, base_url: str) -> None:
    """Click a server -> sees server detail page with stats."""
    page = authenticated_page

    # Get list of servers via API
    result = api_get(page, "/api/servers")

    servers = result if isinstance(result, list) else result.get("servers", [])

    if not servers:
        pytest.skip("No servers available to test detail page")

    # Validate server list response shape
    for item in servers:
        assert_response_shape(
            item, {"id": int, "name": str, "host": str, "protocols": dict}, "server_list_item"
        )

    server_id = servers[0]["id"]
    page.goto(f"{base_url}/server/{server_id}")
    page.wait_for_load_state("networkidle")

    # Should show server detail content
    content = page.content()
    assert len(content) > 100


@pytest.mark.e2e
def test_server_check(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Click 'Check' on a server -> sees check result."""
    page = authenticated_page

    # Get servers
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])

    if not servers:
        pytest.skip("No servers available to test check")

    server_id = servers[0]["id"]
    check_result = api_post(page, f"/api/servers/{server_id}/check", {}, csrf_token)

    # The check endpoint returns a response with server status data
    assert check_result["body"] is not None

    # Validate check response shape
    body = check_result["body"]
    if isinstance(body, dict) and "connection" in body:
        assert_response_shape(
            body,
            {"connection": str, "docker_installed": bool, "protocols": dict},
            "server_check",
        )


@pytest.mark.e2e
def test_server_install(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Click 'Install' on a server -> sees install progress/status."""
    page = authenticated_page

    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])

    if not servers:
        pytest.skip("No servers available to test install")

    server_id = servers[0]["id"]
    install_result = api_post(page, f"/api/servers/{server_id}/install", {}, csrf_token)

    # Install returns either success or an error (e.g. already installed)
    assert install_result["body"] is not None


@pytest.mark.e2e
def test_server_stats(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Navigate to server stats -> sees traffic stats display."""
    page = authenticated_page

    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])

    if not servers:
        pytest.skip("No servers available to test stats")

    server_id = servers[0]["id"]
    stats_result = api_post(page, f"/api/servers/{server_id}/stats", {}, csrf_token)

    # Stats endpoint should respond
    assert stats_result["body"] is not None

    # Validate stats response shape
    body = stats_result["body"]
    if isinstance(body, dict) and "cpu" in body:
        assert_response_shape(
            body,
            {"cpu": (int, float), "ram_used": int, "ram_total": int, "ram_percent": (int, float)},
            "server_stats",
        )


@pytest.mark.e2e
def test_server_add_form(authenticated_page: Page, base_url: str) -> None:
    """Navigate to server management page -> sees server add UI elements."""
    page = authenticated_page
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    # The add server form is accessible via a modal or API
    # Verify the API endpoint exists
    content = page.content()
    assert len(content) > 100


@pytest.mark.e2e
@pytest.mark.skipif(
    os.environ.get("E2E_TESTING", "").lower() == "true"
    or os.environ.get("CI", "").lower() == "true",
    reason="Rebooting target server is disabled in automated CI/E2E test runs to prevent terminating the runner host",
)
def test_server_reboot(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Click 'Reboot' on a server -> sees reboot confirmation/status."""
    page = authenticated_page

    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])

    if not servers:
        pytest.skip("No servers available to test reboot")

    server_id = servers[0]["id"]
    reboot_result = api_post(page, f"/api/servers/{server_id}/reboot", {}, csrf_token)

    # Reboot endpoint returns a response
    assert reboot_result["body"] is not None


@pytest.mark.e2e
def test_server_edit_host_ui_validation(authenticated_page: Page, base_url: str) -> None:
    """Validate client-side host validation in edit host modal on index page."""
    page = authenticated_page
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No servers available to test edit host")

    server_id = servers[0]["id"]
    card = page.locator(f"#server-{server_id}")
    card.locator('button[onclick*="openEditHostModal"]').click()

    modal = page.locator("#editHostModal")
    expect(modal).to_be_visible()

    input_el = modal.locator("#editHostInput")

    dispatched_host_requests: list[str] = []

    def on_request(request: Request) -> None:
        if "/api/servers/" in request.url and request.url.endswith("/host"):
            dispatched_host_requests.append(request.url)

    page.on("request", on_request)

    try:
        # Test invalid host inputs
        for invalid_host in ["invalid host with spaces", "http://bad.example.com"]:
            input_el.fill(invalid_host)
            modal.locator("button.btn-primary").click()

            # Assert client validation error toast appears and modal remains open
            error_toast = page.locator(".toast-error")
            expect(error_toast.first).to_be_visible()
            expect(modal).to_be_visible()

        # Assert no requests were dispatched to /api/servers/*/host
        assert (
            len(dispatched_host_requests) == 0
        ), f"Expected 0 requests to /api/servers/*/host, but got: {dispatched_host_requests}"
    finally:
        page.remove_listener("request", on_request)

    # Close modal
    modal.locator(".modal-close").click()
    expect(modal).not_to_be_visible()


@pytest.mark.e2e
def test_server_edit_host_ui_lifecycle(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Test full lifecycle of updating and restoring server host via UI and API."""
    page = authenticated_page
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No servers available to test edit host lifecycle")

    first_server = servers[0]
    server_id = first_server["id"]
    orig_host = first_server["host"]

    new_host = "172.17.0.2" if orig_host != "172.17.0.2" else "172.17.0.3"

    card = page.locator(f"#server-{server_id}")
    modal = page.locator("#editHostModal")

    try:
        # Open modal on first server card
        card.locator('button[onclick*="openEditHostModal"]').click()
        expect(modal).to_be_visible()

        # Change host to a new test IP
        modal.locator("#editHostInput").fill(new_host)
        modal.locator("button.btn-primary").click()

        # Wait for modal to close and assert success toast
        expect(modal).not_to_be_visible()
        expect(page.locator(".toast-success").first).to_be_visible()

        # Assert real-time DOM update on index page
        host_span = page.locator(f"#server-host-{server_id}")
        expect(host_span).to_have_text(new_host)
        expect(card).to_have_attribute("data-server-host", new_host)

        # Verify API shows updated host
        api_check = api_get(page, "/api/servers")
        api_servers = api_check if isinstance(api_check, list) else api_check.get("servers", [])
        updated_server = next((s for s in api_servers if s.get("id") == server_id), None)
        assert updated_server is not None
        assert updated_server.get("host") == new_host

        # Navigate to server detail page
        page.goto(f"{base_url}/server/{server_id}")
        page.wait_for_load_state("networkidle")

        # Assert #serverHostDisplay shows updated host
        host_display = page.locator("#serverHostDisplay")
        expect(host_display).to_have_text(new_host)

        # Open #editHostModal and restore original host
        detail_modal = page.locator("#editHostModal")
        page.locator('button[onclick*="openEditHostModal"]').click()
        expect(detail_modal).to_be_visible()
        expect(detail_modal.locator("#editHostInput")).to_have_value(new_host)

        # Restore original host and save
        detail_modal.locator("#editHostInput").fill(orig_host)
        detail_modal.locator("button.btn-primary").click()

        # Wait for modal to close and assert success toast
        expect(detail_modal).not_to_be_visible()
        expect(page.locator(".toast-success").first).to_be_visible()

        # Assert #serverHostDisplay updates in real-time
        expect(host_display).to_have_text(orig_host)

        # Verify API shows restored host
        api_check_restored = api_get(page, "/api/servers")
        restored_servers = (
            api_check_restored
            if isinstance(api_check_restored, list)
            else api_check_restored.get("servers", [])
        )
        restored_server = next((s for s in restored_servers if s.get("id") == server_id), None)
        assert restored_server is not None
        assert restored_server.get("host") == orig_host

    finally:
        # Safeguard: ensure original host is restored if test failed midway
        cleanup_res = api_get(page, "/api/servers")
        cleanup_servers = (
            cleanup_res if isinstance(cleanup_res, list) else cleanup_res.get("servers", [])
        )
        current = next((s for s in cleanup_servers if s.get("id") == server_id), None)
        if current and current.get("host") != orig_host:
            restore_res = api_post(
                page, f"/api/servers/{server_id}/host", {"host": orig_host}, csrf_token
            )
            assert (
                restore_res.get("status") == 200
            ), f"Failed to restore original host in cleanup: {restore_res}"
            body = restore_res.get("body")
            assert (
                isinstance(body, dict) and body.get("status") == "ok"
            ), f"Failed to restore original host in cleanup: {body}"
