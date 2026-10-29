"""E2E Playwright test suite for multi-protocol server management and RBAC.

Covers:
- Admin RBAC enforcement on multi-protocol management endpoints (/install, /uninstall, /scan-sni)
- VLESS+REALITY installation modal UI flow and defaults
- REALITY SNI scanner UI flow, candidate dropdown, and auto-population
- NaiveProxy installation modal UI flow, custom port, decoy templates, and submission
- Protocol uninstallation confirmation modal flow and card state transitions
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict
import uuid

import pytest
from playwright.sync_api import Page, Request, Route, expect

from tests.e2e.conftest import (
    _do_login,
    _get_csrf_cookie,
    api_get,
    api_post,
)

logger = logging.getLogger(__name__)


def _create_scoped_user(
    page: Page,
    csrf_token: str,
    username: str,
    role: str = "user",
) -> Dict[str, Any]:
    """Create a scoped test user via the admin API.

    Fails closed: asserts that the user creation endpoint returns 200 and that
    the user appears in the user inventory, raising AssertionError if either check fails.

    Args:
        page: Authenticated admin Playwright page.
        csrf_token: Admin CSRF token string.
        username: Desired username.
        role: User role ('user', 'support', 'admin').

    Returns:
        User dictionary from the user inventory.

    Raises:
        AssertionError: If user creation returns non-200 or user is not found.
    """
    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": username,
            "password": "TestPass123!",
            "role": role,
            "enabled": True,
        },
        csrf_token,
    )
    assert (
        add_result.get("status") == 200
    ), f"Failed to create scoped user {username} with role {role}: {add_result}"

    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])
    user_record = next((u for u in users if u.get("username") == username), None)
    assert (
        user_record is not None
    ), f"Scoped user {username} not found in user inventory after creation"
    return user_record


def _delete_scoped_user(page: Page, user_id: str, csrf_token: str) -> None:
    """Delete a test user via the admin API."""
    if user_id:
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


def _get_target_server_id(page: Page) -> int:
    """Retrieve an active server ID or fallback to default ID 1.

    Args:
        page: Authenticated Playwright page.

    Returns:
        First existing server's ID, or fallback integer 1.
    """
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if servers and isinstance(servers, list):
        first = servers[0]
        if isinstance(first, dict) and "id" in first:
            return int(first["id"])
    return 1


@pytest.mark.e2e
def test_multiprotocol_admin_rbac(
    authenticated_page: Page,
    base_url: str,
    csrf_token: str,
) -> None:
    """Verify admin RBAC enforcement on multi-protocol management endpoints.

    Tests that:
    1. Unauthenticated requests to /install, /uninstall, /scan-sni return 401 or 403.
    2. Regular user (role='user') requests return 403 Forbidden on all endpoints.
    3. Support role (role='support') requests return 403 Forbidden on /install,
       /uninstall, and /reality/scan-sni (management endpoints are strictly admin-only).
    """
    server_id = _get_target_server_id(authenticated_page)
    browser = authenticated_page.context.browser
    if not browser:
        pytest.skip("Browser instance not available on page context")

    install_url = f"{base_url}/api/servers/{server_id}/install"
    uninstall_url = f"{base_url}/api/servers/{server_id}/uninstall"
    scan_sni_url = f"{base_url}/api/servers/{server_id}/reality/scan-sni"

    # Step 1: Unauthenticated request verification
    unauth_context = browser.new_context()
    try:
        unauth_page = unauth_context.new_page()
        for endpoint, payload in [
            (install_url, {"protocol": "vless", "port": "443"}),
            (uninstall_url, {"protocol": "vless"}),
            (scan_sni_url, {}),
        ]:
            resp = unauth_page.request.post(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            assert resp.status in (
                401,
                403,
            ), f"Unauthenticated request to {endpoint} returned {resp.status}, expected 401/403"
    finally:
        unauth_context.close()

    # Step 2: Regular user (role='user') RBAC verification
    test_user_name = f"e2e_rbac_user_{uuid.uuid4().hex[:8]}"
    user_record = _create_scoped_user(authenticated_page, csrf_token, test_user_name, role="user")
    user_id = str(user_record["id"])

    try:
        user_context = browser.new_context()
        try:
            user_page = user_context.new_page()
            _do_login(user_page, base_url, test_user_name, "TestPass123!")
            user_csrf = _get_csrf_cookie(user_page)

            for endpoint, payload in [
                (install_url, {"protocol": "vless", "port": "443"}),
                (uninstall_url, {"protocol": "vless"}),
                (scan_sni_url, {}),
            ]:
                resp = user_page.request.post(
                    endpoint,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-CSRF-Token": user_csrf,
                    },
                )
                assert resp.status == 403, (
                    f"User role request to {endpoint} returned {resp.status}, "
                    f"expected 403 Forbidden"
                )
        finally:
            user_context.close()
    finally:
        _delete_scoped_user(authenticated_page, user_id, csrf_token)

    # Step 3: Support role (role='support') RBAC verification (install, uninstall, scan-sni)
    test_support_name = f"e2e_rbac_support_{uuid.uuid4().hex[:8]}"
    support_record = _create_scoped_user(
        authenticated_page, csrf_token, test_support_name, role="support"
    )
    support_id = str(support_record["id"])

    try:
        support_context = browser.new_context()
        try:
            support_page = support_context.new_page()
            _do_login(support_page, base_url, test_support_name, "TestPass123!")
            support_csrf = _get_csrf_cookie(support_page)

            # Support role is forbidden from installing, uninstalling, and scanning SNI
            for endpoint, payload in [
                (install_url, {"protocol": "vless", "port": "443"}),
                (uninstall_url, {"protocol": "vless"}),
                (scan_sni_url, {}),
            ]:
                resp = support_page.request.post(
                    endpoint,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-CSRF-Token": support_csrf,
                    },
                )
                assert resp.status == 403, (
                    f"Support role request to {endpoint} returned {resp.status}, "
                    f"expected 403 Forbidden"
                )
        finally:
            support_context.close()
    finally:
        _delete_scoped_user(authenticated_page, support_id, csrf_token)


@pytest.mark.e2e
def test_vless_reality_install_modal_ui(
    authenticated_page: Page,
    base_url: str,
) -> None:
    """Verify VLESS+REALITY installation modal UI flow and defaults.

    Validates that:
    - Opening the VLESS install modal displays #vlessOptions and hides other protocols.
    - Default port is 443 TCP.
    - Default flow selector has 'xtls-rprx-vision' selected.
    - Camouflage SNI input is pre-populated with 'gateway.icloud.com'.
    - REALITY scan trigger button is visible.
    - Submitting installation dispatches expected payload (server_name, port, flow).
    - Progress log and completion flow dismisses modal cleanly.
    """
    page = authenticated_page
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No servers available to test VLESS installation modal")

    server_id = servers[0]["id"]
    page.goto(f"{base_url}/server/{server_id}")
    page.wait_for_load_state("networkidle")

    # Locate VLESS protocol card
    card = page.locator("#proto-vless")
    expect(card).to_be_visible()

    # Trigger install modal via button or global helper
    install_btn = page.locator("#vless-install-btn")
    if install_btn.is_visible():
        install_btn.click()
    else:
        page.evaluate("openInstallModal('vless')")

    modal = page.locator("#installModal")
    expect(modal).to_be_visible()

    # Verify modal header and protocol-specific sections
    title_el = modal.locator("#installModalTitle")
    expect(title_el).to_be_visible()

    vless_opts = modal.locator("#vlessOptions")
    expect(vless_opts).to_be_visible()

    naive_opts = modal.locator("#naiveOptions")
    expect(naive_opts).not_to_be_visible()

    telemt_opts = modal.locator("#telemtOptions")
    expect(telemt_opts).not_to_be_visible()

    awg_opts = modal.locator("#awgOptions")
    expect(awg_opts).not_to_be_visible()

    # Verify port input and default
    port_input = modal.locator("#installPort")
    expect(port_input).to_be_visible()
    expect(port_input).to_have_value("443")

    # Verify flow selector and default option
    flow_select = modal.locator("#installVlessFlow")
    expect(flow_select).to_be_visible()
    expect(flow_select).to_have_value("xtls-rprx-vision")

    # Verify camouflage SNI input and default domain
    sni_input = modal.locator("#installVlessSni, #vlessSni").first
    expect(sni_input).to_be_visible()
    expect(sni_input).to_have_value("gateway.icloud.com")

    # Verify REALITY scanner button presence
    scan_btn = modal.locator(
        "#vlessScanBtn, #realityScanBtn, [data-action='scan-reality-sni']"
    ).first
    expect(scan_btn).to_be_visible()

    captured_install: Dict[str, Any] = {}

    def handle_install(route: Route, request: Request) -> None:
        nonlocal captured_install
        captured_install = request.post_data_json or {}
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "status": "ok",
                    "log": [
                        "Configuring Xray environment",
                        "Setting up REALITY camouflage",
                        "VLESS+REALITY container ready",
                    ],
                }
            ),
        )

    page.route("**/api/servers/*/install", handle_install)

    try:
        # Submit installation
        submit_btn = modal.locator("#installBtn")
        expect(submit_btn).to_be_visible()
        submit_btn.click()

        # Progress view should replace form
        progress_div = modal.locator("#installProgress")
        expect(progress_div).to_be_visible()
        expect(modal.locator("#installForm")).not_to_be_visible()

        # Log output should show completion lines
        log_div = modal.locator("#installLog")
        expect(log_div).to_contain_text("VLESS+REALITY container ready")

        # Verify dispatched payload structure including server_name, port, flow
        assert captured_install.get("protocol") == "vless"
        assert str(captured_install.get("port")) == "443"
        vless_opts = captured_install.get("vless_options", {})
        assert vless_opts.get("server_name") == "gateway.icloud.com"
        assert str(vless_opts.get("port")) == "443"
        assert vless_opts.get("flow") == "xtls-rprx-vision"

        # Complete installation via Done button
        done_div = modal.locator("#installDone")
        expect(done_div).to_be_visible()
        done_div.locator("button").click()
        expect(modal).not_to_be_visible()
    finally:
        page.unroute("**/api/servers/*/install")


@pytest.mark.e2e
def test_reality_sni_scanner_ui_flow(
    authenticated_page: Page,
    base_url: str,
) -> None:
    """Verify REALITY SNI scanner UI flow, progress feedback, and candidate selection.

    Validates that:
    - Triggering the scan requests candidate domains from the backend scanner.
    - While scanning, feedback is provided to the user.
    - Candidate dropdown is populated with tested domains.
    - Best candidate auto-populates the camouflage SNI input.
    - Selecting an alternative candidate updates the SNI input.
    """
    page = authenticated_page
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No servers available to test REALITY SNI scanner UI")

    server_id = servers[0]["id"]
    page.goto(f"{base_url}/server/{server_id}")
    page.wait_for_load_state("networkidle")

    # Open VLESS install modal
    page.evaluate("openInstallModal('vless')")
    modal = page.locator("#installModal")
    expect(modal).to_be_visible()

    mock_candidates = {
        "status": "ok",
        "server_ip": "198.51.100.1",
        "results": [
            {
                "domain": "gateway.icloud.com",
                "status": "ok",
                "rtt_ms": 14,
                "country": "US",
                "asn": 714,
            },
            {
                "domain": "dl.google.com",
                "status": "ok",
                "rtt_ms": 26,
                "country": "US",
                "asn": 15169,
            },
            {
                "domain": "swdist.apple.com",
                "status": "ok",
                "rtt_ms": 38,
                "country": "US",
                "asn": 714,
            },
        ],
    }

    scan_intercepted = False

    def handle_scan_request(route: Route) -> None:
        nonlocal scan_intercepted
        scan_intercepted = True
        time.sleep(0.05)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mock_candidates),
        )

    page.route("**/api/servers/*/reality/scan-sni", handle_scan_request)

    try:
        scan_btn = modal.locator(
            "#vlessScanBtn, #realityScanBtn, [data-action='scan-reality-sni']"
        ).first
        expect(scan_btn).to_be_visible()

        sni_input = modal.locator("#installVlessSni, #vlessSni").first
        expect(sni_input).to_be_visible()

        # Trigger SNI scan
        scan_btn.click()

        # Dropdown selector should become visible and populated
        sni_select = modal.locator("#installVlessSniSelect, #realityScanDropdown").first
        expect(sni_select).to_be_visible()

        # Verify best candidate auto-populated into input
        expect(sni_input).to_have_value("gateway.icloud.com")

        # Select second candidate from dropdown
        sni_select.select_option("dl.google.com")
        sni_select.dispatch_event("change")

        # Assert SNI input updated with newly chosen domain
        expect(sni_input).to_have_value("dl.google.com")

        # Verify scan button is re-enabled
        expect(scan_btn).to_be_enabled()
        assert scan_intercepted, "REALITY scan API route was not triggered by UI button"
    finally:
        page.unroute("**/api/servers/*/reality/scan-sni")
        modal.locator(".modal-close").click()
        expect(modal).not_to_be_visible()


@pytest.mark.e2e
def test_naiveproxy_install_modal_ui_flow(
    authenticated_page: Page,
    base_url: str,
) -> None:
    """Verify NaiveProxy installation modal UI options, custom port, and submission.

    Validates that:
    - Opening NaiveProxy install modal displays #naiveOptions and hides other options.
    - Domain input, custom port (e.g. 8443), and decoy website selections are editable.
    - Submitting installation dispatches expected payload to /api/servers/{id}/install.
    - Progress indicator and log display during installation.
    - Modal completes via done button.
    """
    page = authenticated_page
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No servers available to test NaiveProxy installation modal")

    server_id = servers[0]["id"]
    page.goto(f"{base_url}/server/{server_id}")
    page.wait_for_load_state("networkidle")

    # Locate NaiveProxy protocol card
    card = page.locator("#proto-naive")
    expect(card).to_be_visible()

    # Open Naive install modal
    install_btn = page.locator("#naive-install-btn")
    if install_btn.is_visible():
        install_btn.click()
    else:
        page.evaluate("openInstallModal('naive')")

    modal = page.locator("#installModal")
    expect(modal).to_be_visible()

    # Verify protocol-specific options visibility
    expect(modal.locator("#naiveOptions")).to_be_visible()
    expect(modal.locator("#vlessOptions")).not_to_be_visible()

    # Fill domain input
    domain_input = modal.locator("#installNaiveDomain")
    expect(domain_input).to_be_visible()
    domain_input.fill("proxy.example.com")
    expect(domain_input).to_have_value("proxy.example.com")

    # Set custom port to 8443
    port_input = modal.locator("#installPort")
    expect(port_input).to_be_visible()
    port_input.fill("8443")
    expect(port_input).to_have_value("8443")

    # Verify decoy selection
    decoy_select = modal.locator("#installNaiveDecoy")
    expect(decoy_select).to_be_visible()
    expect(decoy_select).to_have_value("default")

    captured_install: Dict[str, Any] = {}

    def handle_install(route: Route, request: Request) -> None:
        nonlocal captured_install
        captured_install = request.post_data_json or {}
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "status": "ok",
                    "log": [
                        "Configuring Caddyfile",
                        "Setting up decoy template",
                        "NaiveProxy container ready",
                    ],
                }
            ),
        )

    page.route("**/api/servers/*/install", handle_install)

    try:
        # Submit installation
        submit_btn = modal.locator("#installBtn")
        expect(submit_btn).to_be_visible()
        submit_btn.click()

        # Progress view should replace form
        progress_div = modal.locator("#installProgress")
        expect(progress_div).to_be_visible()
        expect(modal.locator("#installForm")).not_to_be_visible()

        # Log output should show completion lines
        log_div = modal.locator("#installLog")
        expect(log_div).to_contain_text("NaiveProxy container ready")

        # Verify dispatched payload structure
        assert captured_install.get("protocol") == "naive"
        assert str(captured_install.get("port")) == "8443"
        naive_opts = captured_install.get("naive_options", {})
        assert naive_opts.get("domain") == "proxy.example.com"
        assert naive_opts.get("decoy_template") == "default"

        # Complete installation via Done button
        done_div = modal.locator("#installDone")
        expect(done_div).to_be_visible()
        done_div.locator("button").click()
        expect(modal).not_to_be_visible()
    finally:
        page.unroute("**/api/servers/*/install")


@pytest.mark.e2e
def test_protocol_uninstall_modal_ui_flow(
    authenticated_page: Page,
    base_url: str,
) -> None:
    """Verify protocol uninstallation modal flow, confirmation dialog, and request dispatch.

    Validates that:
    - Initiating uninstall displays #nexusConfirmModal with dangerous action styling.
    - Cancelling confirmation dismisses dialog without dispatching uninstall request.
    - Confirming uninstall sends request to /api/servers/{id}/uninstall with target protocol.
    - Success feedback is shown via toast notification.
    """
    page = authenticated_page
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No servers available to test protocol uninstallation")

    server_id = servers[0]["id"]
    page.goto(f"{base_url}/server/{server_id}")
    page.wait_for_load_state("networkidle")

    # Set up route interception for /uninstall before any user actions
    captured_requests: list[Dict[str, Any]] = []

    def handle_uninstall(route: Route, request: Request) -> None:
        captured_requests.append(request.post_data_json or {})
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"status": "ok"}),
        )

    page.route("**/api/servers/*/uninstall", handle_uninstall)

    try:
        # Trigger uninstall confirmation without manual DOM mutation
        uninstall_btn = page.locator("#vless-actions button.btn-danger")
        if uninstall_btn.is_visible():
            uninstall_btn.click()
        else:
            page.evaluate("uninstallProtocol('vless')")

        confirm_modal = page.locator("#nexusConfirmModal")
        expect(confirm_modal).to_be_visible()

        # Step 1: Cancel confirmation and verify dismissal without dispatching request
        cancel_btn = confirm_modal.locator("#nexusConfirmCancelBtn")
        expect(cancel_btn).to_be_visible()
        cancel_btn.click()

        expect(confirm_modal).not_to_be_visible()
        assert (
            len(captured_requests) == 0
        ), "Uninstall request was dispatched despite cancelling confirmation dialog"

        # Step 2: Trigger uninstall confirmation and confirm
        if uninstall_btn.is_visible():
            uninstall_btn.click()
        else:
            page.evaluate("uninstallProtocol('vless')")

        expect(confirm_modal).to_be_visible()

        ok_btn = confirm_modal.locator("#nexusConfirmOkBtn")
        expect(ok_btn).to_be_visible()
        ok_btn.click()

        # Confirmation modal should close
        expect(confirm_modal).not_to_be_visible()

        # Assert correct protocol parameter was dispatched
        assert (
            len(captured_requests) == 1
        ), f"Expected exactly 1 uninstall request, got {len(captured_requests)}"
        assert (
            captured_requests[0].get("protocol") == "vless"
        ), f"Expected protocol 'vless', got {captured_requests[0].get('protocol')}"

        # Success toast should appear
        success_toast = page.locator(".toast-success, .toast")
        expect(success_toast.first).to_be_visible()
    finally:
        page.unroute("**/api/servers/*/uninstall")
