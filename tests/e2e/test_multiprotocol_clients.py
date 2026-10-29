"""Playwright E2E test suites for multi-protocol client connection lifecycle.

Validates VLESS+REALITY and NaiveProxy client connection management:
- Client credential creation flow (server management and user self-service)
- Configuration display & URI export format validation (vless:// and https://)
- QR code modal generation and interactive dismissal
- Client revocation and zero-client state transitions
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Union
from urllib.parse import parse_qs, urlparse

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import _do_login, api_get, api_post

logger = logging.getLogger(__name__)


# ── URI Validation Helpers ──────────────────────────────────────────


def validate_vless_uri(
    uri: str,
    expected_name: Optional[Union[str, Iterable[str]]] = None,
) -> Dict[str, Any]:
    """Validate a VLESS+REALITY client URI format and parameters.

    Expected format:
    vless://<uuid>@<host>:<port>?security=reality&encryption=none&pbk=<pbk>&headerType=none&fp=chrome&sni=<sni>&sid=<sid>&type=tcp&flow=xtls-rprx-vision#<name>
    """
    assert uri.startswith("vless://"), f"URI must start with vless://, got: {uri[:30]}"
    parsed = urlparse(uri)
    assert parsed.scheme == "vless", f"Expected scheme 'vless', got '{parsed.scheme}'"

    # UUID client credential validation
    assert parsed.username, "VLESS URI must include client UUID as username"
    try:
        val_uuid = uuid.UUID(parsed.username)
        assert str(val_uuid) == parsed.username.lower(), f"Invalid UUID: {parsed.username}"
    except (ValueError, AttributeError) as exc:
        raise AssertionError(f"VLESS client ID must be a valid UUID: {parsed.username}") from exc

    # Host & Port validation
    assert parsed.hostname, "VLESS URI must specify host"
    assert (
        parsed.port is not None and parsed.port > 0
    ), f"VLESS URI must have positive port, got: {parsed.port}"

    # Reality query parameters validation
    qs = parse_qs(parsed.query)
    assert qs.get("security") == [
        "reality"
    ], f"security must be 'reality', got: {qs.get('security')}"
    assert qs.get("flow") == [
        "xtls-rprx-vision"
    ], f"flow must be 'xtls-rprx-vision', got: {qs.get('flow')}"
    assert qs.get("fp") == ["chrome"], f"fp must be 'chrome', got: {qs.get('fp')}"
    assert "sni" in qs and qs["sni"][0], f"sni parameter required, got: {qs.get('sni')}"
    assert "pbk" in qs and qs["pbk"][0], f"pbk (public key) required, got: {qs.get('pbk')}"
    assert "sid" in qs and qs["sid"][0], f"sid (short ID) required, got: {qs.get('sid')}"

    # Name fragment validation: accept display name or reconstructed client UUID/email
    if expected_name:
        expected_set = {expected_name} if isinstance(expected_name, str) else set(expected_name)
        if parsed.username:
            expected_set.add(parsed.username)
        assert (
            parsed.fragment in expected_set
        ), f"Expected fragment in {expected_set}, got '{parsed.fragment}'"

    return {
        "uuid": parsed.username,
        "host": parsed.hostname,
        "port": parsed.port,
        "sni": qs["sni"][0],
        "pbk": qs["pbk"][0],
        "sid": qs["sid"][0],
        "flow": qs["flow"][0],
        "name": parsed.fragment,
    }


def validate_naive_uri(
    uri: str,
    expected_name: Optional[Union[str, Iterable[str]]] = None,
) -> Dict[str, Any]:
    """Validate a NaiveProxy client URI format and basic-auth credentials.

    Expected format:
    https://<username>:<password>@<domain>[:<port>]#<name>
    """
    assert uri.startswith("https://"), f"URI must start with https://, got: {uri[:30]}"
    parsed = urlparse(uri)
    assert parsed.scheme == "https", f"Expected scheme 'https', got '{parsed.scheme}'"

    # Basic auth credential validation
    assert parsed.username, "NaiveProxy URI must include basic-auth username"
    assert parsed.password, "NaiveProxy URI must include basic-auth password"

    # Host & Port validation
    assert parsed.hostname, "NaiveProxy URI must specify host/domain"
    port = parsed.port or 443
    assert port > 0, f"NaiveProxy port must be positive, got: {port}"

    # Name fragment validation: accept display name or reconstructed basic-auth username
    if expected_name:
        expected_set = {expected_name} if isinstance(expected_name, str) else set(expected_name)
        if parsed.username:
            expected_set.add(parsed.username)
        assert (
            parsed.fragment in expected_set
        ), f"Expected fragment in {expected_set}, got '{parsed.fragment}'"

    return {
        "username": parsed.username,
        "password": parsed.password,
        "domain": parsed.hostname,
        "port": port,
        "name": parsed.fragment,
    }


# Backwards-compatible aliases for URI assertion helpers
assert_valid_vless_uri = validate_vless_uri
assert_valid_naive_uri = validate_naive_uri


# ── Portal Navigation & Inventory Helpers ───────────────────────────


def _get_target_server(page: Page) -> Optional[Dict[str, Any]]:
    """Retrieve the first available server from the API."""
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        return None
    return servers[0]


def _is_protocol_installed(server: Dict[str, Any], protocol: str) -> bool:
    """Check whether a specific protocol is installed on the given server."""
    protocols = server.get("protocols", {})
    proto_info = protocols.get(protocol, {})
    if isinstance(proto_info, bool):
        return proto_info
    if isinstance(proto_info, dict):
        return bool(
            proto_info.get("installed", False) or proto_info.get("container_running", False)
        )
    return False


def _is_qualification_mode() -> bool:
    """Return whether running in strict qualification / E2E test mode."""
    return os.environ.get("E2E_TESTING", "").strip().lower() in (
        "true",
        "1",
        "yes",
    ) or os.environ.get("E2E_REQUIRE_DATAPLANE", "").strip().lower() in (
        "true",
        "1",
        "yes",
    )


def _get_server_by_id(page: Page, server_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve server data by ID from the /api/servers endpoint."""
    result = api_get(page, "/api/servers")
    servers = result if isinstance(result, list) else result.get("servers", [])
    for s in servers:
        if s.get("id") == server_id:
            return s
    return None


def _ensure_protocol_installed(page: Page, server_id: int, proto: str, csrf_token: str) -> bool:
    """Ensure that the requested protocol is installed on the target server.

    Checks if proto is present in server protocol inventory. If absent, provisions
    the protocol via POST /api/servers/{server_id}/install with standard parameters:
    - VLESS: port 443, server_name gateway.icloud.com, flow xtls-rprx-vision
    - NaiveProxy: port 8443, domain proxy.example.com, decoy default
    """
    server = _get_server_by_id(page, server_id)
    if server and _is_protocol_installed(server, proto):
        return True

    payload: Dict[str, Any]
    if proto == "vless":
        payload = {
            "protocol": "vless",
            "port": "443",
            "vless_options": {
                "server_name": "gateway.icloud.com",
                "port": "443",
                "flow": "xtls-rprx-vision",
            },
        }
    elif proto == "naive":
        payload = {
            "protocol": "naive",
            "port": "8443",
            "naive_options": {
                "domain": "proxy.example.com",
                "port": "8443",
                "decoy": "default",
            },
        }
    else:
        raise ValueError(f"Unsupported protocol for auto-provisioning: {proto}")

    install_res = api_post(
        page,
        f"/api/servers/{server_id}/install",
        payload,
        csrf_token,
        timeout=120_000,
    )
    status = install_res.get("status")
    assert status in (200, 201), (
        f"Failed to auto-provision {proto} on server {server_id}: "
        f"status={status}, response={install_res}"
    )

    # Validate installed status in server inventory
    updated = _get_server_by_id(page, server_id)
    if updated and _is_protocol_installed(updated, proto):
        return True

    # Allow a short poll window if remote state sync is in-flight
    for _ in range(5):
        time.sleep(1)
        updated = _get_server_by_id(page, server_id)
        if updated and _is_protocol_installed(updated, proto):
            return True

    if _is_qualification_mode():
        assert updated and _is_protocol_installed(
            updated, proto
        ), f"Protocol {proto} not reported as installed on server {server_id} after install"
    return True


def _find_or_create_user(
    page: Page, base_url: str, csrf_token: str, username: str
) -> Dict[str, Any]:
    """Find an existing user or create a new test user."""
    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])
    for u in users:
        if u.get("username") == username:
            return u

    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": username,
            "password": "TestPassword123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )
    assert add_result.get("status") == 200, f"Could not create user {username}: {add_result}"

    users_result2 = api_get(page, "/api/users/?size=100")
    users2 = users_result2 if isinstance(users_result2, list) else users_result2.get("users", [])
    for u in users2:
        if u.get("username") == username:
            return u

    raise RuntimeError(f"User {username} was not found after creation")


def _cleanup_user(page: Page, user_id: str, csrf_token: str) -> None:
    """Safely delete a test user."""
    try:
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)
    except Exception as exc:
        logger.warning("Failed to clean up test user %s: %s", user_id, exc)


def _cleanup_connection(
    page: Page, server_id: int, client_id: str, protocol: str, csrf_token: str
) -> None:
    """Safely remove a server connection."""
    try:
        api_post(
            page,
            f"/api/servers/{server_id}/connections/remove",
            {"client_id": client_id, "protocol": protocol},
            csrf_token,
        )
    except Exception as exc:
        logger.warning("Failed to clean up connection %s (%s): %s", client_id, protocol, exc)


def _verify_user_my_page(
    page: Page,
    base_url: str,
    username: str,
    expected_client_names: Optional[List[str]] = None,
    expect_empty: bool = False,
) -> None:
    """Validate /my under the connection owner's session using an isolated context."""
    browser = page.context.browser
    if not browser:
        return
    user_context = browser.new_context()
    try:
        user_page = user_context.new_page()
        _do_login(user_page, base_url, username, "TestPassword123!")
        user_page.goto(f"{base_url}/my")
        user_page.wait_for_load_state("networkidle")
        if expect_empty:
            empty_state = user_page.locator("#emptyState")
            expect(empty_state).to_be_visible()
            expect(empty_state.locator(".empty-title")).to_be_visible()
        if expected_client_names:
            list_container = user_page.locator("#myConnectionsList")
            expect(list_container).to_be_visible()
            for name in expected_client_names:
                expect(list_container).to_contain_text(name)
    finally:
        user_context.close()


# ── Test Suite 1: Client Credential Creation Flow ────────────────────


@pytest.mark.e2e
def test_multiprotocol_client_creation_flow(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Verify multi-protocol client connection creation and list rendering.

    Validates:
    - Client credential creation for VLESS+REALITY and NaiveProxy protocols
    - Client table row rendering in server management interface
    - Connection count indicators on protocol cards
    - Self-service portal view on /my
    """
    page = authenticated_page
    server = _get_target_server(page)
    if not server:
        if _is_qualification_mode():
            pytest.fail("No servers available for multi-protocol client test in qualification mode")
        pytest.skip("No servers available for multi-protocol client test")
    assert server is not None

    server_id = server["id"]
    for proto in ("vless", "naive"):
        _ensure_protocol_installed(page, server_id, proto, csrf_token)

    server = _get_server_by_id(page, server_id) or server
    installed_protos: List[str] = [
        p for p in ("vless", "naive") if _is_protocol_installed(server, p)
    ]
    if _is_qualification_mode():
        assert (
            "vless" in installed_protos
        ), f"VLESS protocol must be installed on server {server_id} in qualification mode"
        assert (
            "naive" in installed_protos
        ), f"NaiveProxy protocol must be installed on server {server_id} in qualification mode"
    elif not installed_protos:
        pytest.skip(
            f"Neither VLESS nor NaiveProxy installed on server {server_id} "
            "(server installation owned by #643)"
        )

    test_user = _find_or_create_user(page, base_url, csrf_token, "e2e_mp_creator")
    user_id = test_user["id"]
    created_clients: List[Dict[str, Any]] = []

    try:
        page.goto(f"{base_url}/server/{server_id}")
        page.wait_for_load_state("networkidle")
        assert "/login" not in page.url

        for proto in installed_protos:
            client_name = f"e2e_{proto}_{int(time.time())}"

            # 1. Switch to protocol connections section
            page.evaluate(
                """(p) => {
                    if (typeof selectProtocolForConns === 'function') {
                        selectProtocolForConns(p);
                    } else {
                        const sel = document.getElementById('connProtoSelect');
                        if (sel) { sel.value = p; sel.dispatchEvent(new Event('change')); }
                    }
                }""",
                proto,
            )
            page.wait_for_selector("#connectionsSection", state="visible")

            # 2. Open Add Connection modal
            page.locator("#connectionsSection button[onclick*='openAddConnectionModal']").click()
            page.wait_for_selector("#addConnectionModal.active", state="visible")

            # 3. Fill form and submit
            page.locator("#connectionName").fill(client_name)
            page.select_option("#connectionUserId", value=user_id)
            page.locator("#addConnBtn").click()

            # 4. Config modal should open displaying created credentials
            page.wait_for_selector("#configModal.active", state="visible")
            config_text = page.locator("#configText").inner_text()
            assert config_text, f"Expected non-empty config text for {proto}"

            if proto == "vless":
                validate_vless_uri(config_text, expected_name=client_name)
            elif proto == "naive":
                validate_naive_uri(config_text, expected_name=client_name)

            # Close config modal
            page.locator("#configModal .modal-close").click()
            page.wait_for_selector("#configModal.active", state="detached")

            # 5. Verify client row rendering in connections table
            page.wait_for_selector("#connectionsTableContainer", state="visible")
            table_body = page.locator("#connectionsTableBody")
            expect(table_body).to_contain_text(client_name)

            # Record created client for cleanup
            server_conns = api_get(page, f"/api/servers/{server_id}/connections?protocol={proto}")
            clients = server_conns.get("clients", []) if isinstance(server_conns, dict) else []
            matching = [c for c in clients if c.get("name") == client_name]
            if matching:
                cid = matching[0].get("clientId") or matching[0].get("client_id")
                created_clients.append({"id": cid, "protocol": proto, "name": client_name})

            # 6. Verify protocol card connection count indicator
            card_locator = page.locator(f"#proto-{proto}")
            expect(card_locator).to_be_visible()
            info_grid = page.locator(f"#{proto}-info-grid")
            if info_grid.is_visible():
                expect(info_grid).to_contain_text("Connections")

        # 7. Verify user self-service interface (/my) under the connection owner's session
        _verify_user_my_page(
            page,
            base_url,
            username=test_user["username"],
            expected_client_names=[c["name"] for c in created_clients],
        )

    finally:
        for c in created_clients:
            _cleanup_connection(page, server_id, c["id"], c["protocol"], csrf_token)
        _cleanup_user(page, user_id, csrf_token)


# ── Test Suite 2: Configuration Display & URI Export ─────────────────


@pytest.mark.e2e
def test_multiprotocol_config_display_and_uri_export(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Verify URI export format and clipboard copy feedback.

    Validates:
    - vless:// URI structure: scheme, UUID, host, port, SNI, Vision flow, PBK, SID
    - https:// URI structure: scheme, basic auth credentials, host, port
    - Clipboard copy trigger and toast feedback
    """
    page = authenticated_page
    server = _get_target_server(page)
    if not server:
        if _is_qualification_mode():
            pytest.fail("No servers available for URI export test in qualification mode")
        pytest.skip("No servers available for URI export test")
    assert server is not None

    server_id = server["id"]
    for proto in ("vless", "naive"):
        _ensure_protocol_installed(page, server_id, proto, csrf_token)

    server = _get_server_by_id(page, server_id) or server
    installed_protos: List[str] = [
        p for p in ("vless", "naive") if _is_protocol_installed(server, p)
    ]
    if _is_qualification_mode():
        assert (
            "vless" in installed_protos
        ), f"VLESS protocol must be installed on server {server_id} in qualification mode"
        assert (
            "naive" in installed_protos
        ), f"NaiveProxy protocol must be installed on server {server_id} in qualification mode"
    elif not installed_protos:
        pytest.skip(
            f"Neither VLESS nor NaiveProxy installed on server {server_id} "
            "(server installation owned by #643)"
        )

    test_user = _find_or_create_user(page, base_url, csrf_token, "e2e_mp_exporter")
    user_id = test_user["id"]
    created_clients: List[Dict[str, Any]] = []

    try:
        # Grant clipboard permissions for copy feedback testing
        try:
            page.context.grant_permissions(["clipboard-read", "clipboard-write"])
        except Exception as perm_err:
            logger.info("Clipboard permissions not configurable: %s", perm_err)

        for proto in installed_protos:
            client_name = f"e2e_export_{proto}_{int(time.time())}"

            # Provision client connection via API for deterministic setup
            add_resp = api_post(
                page,
                f"/api/servers/{server_id}/connections/add",
                {"protocol": proto, "name": client_name, "user_id": user_id},
                csrf_token,
            )
            assert add_resp.get("status") == 200, f"Failed to provision {proto}: {add_resp}"
            body = add_resp.get("body", {})
            client_id = body.get("client_id")
            assert client_id, f"Expected client_id in response: {body}"
            created_clients.append({"id": client_id, "protocol": proto, "name": client_name})

            # Navigate to server page
            page.goto(f"{base_url}/server/{server_id}")
            page.wait_for_load_state("networkidle")

            page.evaluate(
                """(p) => {
                    if (typeof selectProtocolForConns === 'function') {
                        selectProtocolForConns(p);
                    }
                }""",
                proto,
            )
            page.wait_for_selector("#connectionsSection", state="visible")

            # Locate client row in connections table
            row = page.locator(f"#connectionsTableBody tr:has-text('{client_name}')")
            expect(row).to_be_visible()

            # Click Show Config button
            config_btn = row.locator("button[onclick*='showConnectionConfig']")
            config_btn.click()

            # Wait for config modal
            page.wait_for_selector("#configModal.active", state="visible")
            config_text = page.locator("#configText").inner_text().strip()

            # Format verification
            if proto == "vless":
                details = validate_vless_uri(config_text, expected_name=client_name)
                assert details["flow"] == "xtls-rprx-vision"
                assert details["uuid"]
                assert details["uuid"].lower() == client_id.lower()
                assert details["sni"]
            elif proto == "naive":
                details = validate_naive_uri(config_text, expected_name=client_name)
                assert details["username"]
                assert details["username"] == client_id
                assert details["password"]
                assert details["domain"]

            # Test clipboard copy action and feedback
            copy_btn = page.locator("#panel-conf button[onclick*='UI.copy']")
            copy_btn.click()

            # Verify toast or button copied state
            toast_locator = page.locator(".toast, .toast-success, button.copied")
            expect(toast_locator.first).to_be_visible(timeout=5000)

            # Close modal
            page.locator("#configModal .modal-close").click()
            page.wait_for_selector("#configModal.active", state="detached")

    finally:
        for c in created_clients:
            _cleanup_connection(page, server_id, c["id"], c["protocol"], csrf_token)
        _cleanup_user(page, user_id, csrf_token)


# ── Test Suite 3: QR Code Modal Interaction ──────────────────────────


@pytest.mark.e2e
def test_multiprotocol_qr_code_modal_interaction(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Verify QR code rendering, tab switching, and clean modal dismissal.

    Validates:
    - QR code generation and display for VLESS and NaiveProxy URIs
    - QR hint presence
    - Dismissal via close button
    - Dismissal via backdrop click
    """
    page = authenticated_page
    server = _get_target_server(page)
    if not server:
        if _is_qualification_mode():
            pytest.fail("No servers available for QR code modal test in qualification mode")
        pytest.skip("No servers available for QR code modal test")
    assert server is not None

    server_id = server["id"]
    for proto in ("vless", "naive"):
        _ensure_protocol_installed(page, server_id, proto, csrf_token)

    server = _get_server_by_id(page, server_id) or server
    installed_protos: List[str] = [
        p for p in ("vless", "naive") if _is_protocol_installed(server, p)
    ]
    if _is_qualification_mode():
        assert (
            "vless" in installed_protos
        ), f"VLESS protocol must be installed on server {server_id} in qualification mode"
        assert (
            "naive" in installed_protos
        ), f"NaiveProxy protocol must be installed on server {server_id} in qualification mode"
    elif not installed_protos:
        pytest.skip(
            f"Neither VLESS nor NaiveProxy installed on server {server_id} "
            "(server installation owned by #643)"
        )

    test_user = _find_or_create_user(page, base_url, csrf_token, "e2e_mp_qrmodal")
    user_id = test_user["id"]
    created_clients: List[Dict[str, Any]] = []

    try:
        for proto in installed_protos:
            client_name = f"e2e_qr_{proto}_{int(time.time())}"

            add_resp = api_post(
                page,
                f"/api/servers/{server_id}/connections/add",
                {"protocol": proto, "name": client_name, "user_id": user_id},
                csrf_token,
            )
            assert add_resp.get("status") == 200
            client_id = add_resp.get("body", {}).get("client_id")
            assert client_id
            created_clients.append({"id": client_id, "protocol": proto, "name": client_name})

            page.goto(f"{base_url}/server/{server_id}")
            page.wait_for_load_state("networkidle")

            page.evaluate(
                """(p) => {
                    if (typeof selectProtocolForConns === 'function') {
                        selectProtocolForConns(p);
                    }
                }""",
                proto,
            )
            page.wait_for_selector("#connectionsSection", state="visible")

            row = page.locator(f"#connectionsTableBody tr:has-text('{client_name}')")
            expect(row).to_be_visible()

            # Open config modal
            row.locator("button[onclick*='showConnectionConfig']").click()
            page.wait_for_selector("#configModal.active", state="visible")

            # Switch to QR Code tab
            page.locator("[onclick=\"switchConfigTab('qr')\"], .config-tab:has-text('QR')").click()
            page.wait_for_selector("#panel-qr.active", state="visible")

            # Verify QR code container has rendered visible content (visible img or canvas)
            qr_visible = page.locator(
                "#qrCode img:visible, #qrCode canvas:visible, "
                "#qrCodeContainer img:visible, #qrCodeContainer canvas:visible"
            )
            expect(qr_visible.first).to_be_visible(timeout=5000)

            # Verify QR hint element is present
            qr_hint = page.locator("#qrHint")
            expect(qr_hint).to_be_visible()

            # Dismissal Test 1 (Close Button) for first proto
            # Dismissal Test 2 (Backdrop Click) for subsequent proto
            if proto == installed_protos[0]:
                page.locator("#configModal .modal-close").click()
            else:
                # Click outside the modal card directly on the backdrop
                page.locator("#configModal").click(position={"x": 10, "y": 10})

            page.wait_for_selector("#configModal.active", state="detached")

    finally:
        for c in created_clients:
            _cleanup_connection(page, server_id, c["id"], c["protocol"], csrf_token)
        _cleanup_user(page, user_id, csrf_token)


# ── Test Suite 4: Client Revocation & Zero-Client State ──────────────


@pytest.mark.e2e
def test_multiprotocol_revocation_and_zero_client_state(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Verify client revocation flow and clean zero-client state transitions.

    Validates:
    - Revoking/deleting client connections from the portal
    - Updated protocol cards and connection counts
    - Clean empty state rendering without UI breaking
    """
    page = authenticated_page
    server = _get_target_server(page)
    if not server:
        if _is_qualification_mode():
            pytest.fail("No servers available for revocation test in qualification mode")
        pytest.skip("No servers available for revocation test")
    assert server is not None

    server_id = server["id"]
    for proto in ("vless", "naive"):
        _ensure_protocol_installed(page, server_id, proto, csrf_token)

    server = _get_server_by_id(page, server_id) or server
    installed_protos: List[str] = [
        p for p in ("vless", "naive") if _is_protocol_installed(server, p)
    ]
    if _is_qualification_mode():
        assert (
            "vless" in installed_protos
        ), f"VLESS protocol must be installed on server {server_id} in qualification mode"
        assert (
            "naive" in installed_protos
        ), f"NaiveProxy protocol must be installed on server {server_id} in qualification mode"
    elif not installed_protos:
        pytest.skip(
            f"Neither VLESS nor NaiveProxy installed on server {server_id} "
            "(server installation owned by #643)"
        )

    test_user = _find_or_create_user(page, base_url, csrf_token, "e2e_mp_revoker")
    user_id = test_user["id"]
    leftover_clients: List[Dict[str, Any]] = []

    try:
        for proto in installed_protos:
            client_name = f"e2e_revoke_{proto}_{int(time.time())}"

            add_resp = api_post(
                page,
                f"/api/servers/{server_id}/connections/add",
                {"protocol": proto, "name": client_name, "user_id": user_id},
                csrf_token,
            )
            assert add_resp.get("status") == 200
            client_id = add_resp.get("body", {}).get("client_id")
            assert client_id
            leftover_clients.append({"id": client_id, "protocol": proto})

            page.goto(f"{base_url}/server/{server_id}")
            page.wait_for_load_state("networkidle")

            page.evaluate(
                """(p) => {
                    if (typeof selectProtocolForConns === 'function') {
                        selectProtocolForConns(p);
                    }
                }""",
                proto,
            )
            page.wait_for_selector("#connectionsSection", state="visible")

            row = page.locator(f"#connectionsTableBody tr:has-text('{client_name}')")
            expect(row).to_be_visible()

            # Click delete button on connection row
            del_btn = row.locator("button[onclick*='removeConnection']")
            del_btn.click()

            # Handle confirmation modal or native dialog
            confirm_modal = page.locator("#nexusConfirmModal.active")
            if confirm_modal.is_visible(timeout=3000):
                page.locator("#nexusConfirmOkBtn").click()

            # Verify connection row is removed
            expect(row).to_have_count(0, timeout=5000)
            leftover_clients = [c for c in leftover_clients if c["id"] != client_id]

            # Verify zero-client state on server page
            server_conns = api_get(page, f"/api/servers/{server_id}/connections?protocol={proto}")
            remaining = server_conns.get("clients", []) if isinstance(server_conns, dict) else []
            if len(remaining) == 0:
                empty_state = page.locator("#connectionsEmpty")
                expect(empty_state).to_be_visible()
                expect(empty_state.locator(".empty-title")).to_be_visible()

        # Verify zero-client state on /my under the connection owner's session
        user_conns_resp = api_get(page, f"/api/users/{user_id}/connections")
        user_conns = (
            user_conns_resp.get("connections", [])
            if isinstance(user_conns_resp, dict)
            else user_conns_resp
        )
        if isinstance(user_conns, list) and len(user_conns) == 0:
            _verify_user_my_page(
                page,
                base_url,
                username=test_user["username"],
                expect_empty=True,
            )

    finally:
        for c in leftover_clients:
            _cleanup_connection(page, server_id, c["id"], c["protocol"], csrf_token)
        _cleanup_user(page, user_id, csrf_token)


# ── Oracle Unit Tests for Deterministic Format Verification ─────────


def test_vless_uri_validation_oracle() -> None:
    """Oracle test: verify validate_vless_uri against valid and invalid formats."""
    # Valid VLESS URI with REALITY
    valid_uri = (
        "vless://9f5b2446-2ab9-42b4-8260-2ff0d061c0de@vpn.example.com:443?"
        "security=reality&encryption=none&pbk=1w_PubkeySecret123&headerType=none"
        "&fp=chrome&sni=gateway.icloud.com&sid=abcdef12&type=tcp"
        "&flow=xtls-rprx-vision#MyVlessClient"
    )
    res = validate_vless_uri(valid_uri, expected_name="MyVlessClient")
    assert res["uuid"] == "9f5b2446-2ab9-42b4-8260-2ff0d061c0de"
    assert res["host"] == "vpn.example.com"
    assert res["port"] == 443
    assert res["flow"] == "xtls-rprx-vision"
    assert res["sni"] == "gateway.icloud.com"

    # Valid VLESS URI where fragment is the reconstructed client UUID (H2 contract)
    reconstructed_uri = (
        "vless://9f5b2446-2ab9-42b4-8260-2ff0d061c0de@vpn.example.com:443?"
        "security=reality&encryption=none&pbk=1w_PubkeySecret123&headerType=none"
        "&fp=chrome&sni=gateway.icloud.com&sid=abcdef12&type=tcp"
        "&flow=xtls-rprx-vision#9f5b2446-2ab9-42b4-8260-2ff0d061c0de"
    )
    res_recon = validate_vless_uri(reconstructed_uri, expected_name="MyVlessClient")
    assert res_recon["uuid"] == "9f5b2446-2ab9-42b4-8260-2ff0d061c0de"

    # Reject mismatched fragment when neither expected_name nor UUID matches
    with pytest.raises(AssertionError, match="Expected fragment in"):
        validate_vless_uri(valid_uri, expected_name="DifferentClient")

    # Reject non-vless scheme
    with pytest.raises(AssertionError, match="URI must start with vless://"):
        validate_vless_uri("https://example.com")

    # Reject malformed UUID
    with pytest.raises(AssertionError, match="valid UUID"):
        validate_vless_uri(
            "vless://not-a-valid-uuid@vpn.example.com:443?security=reality&flow=xtls-rprx-vision"
            "&fp=chrome&sni=gateway.icloud.com&pbk=key&sid=123"
        )

    # Reject missing security=reality
    with pytest.raises(AssertionError, match="security must be 'reality'"):
        validate_vless_uri(
            "vless://9f5b2446-2ab9-42b4-8260-2ff0d061c0de@vpn.example.com:443?"
            "security=tls&flow=xtls-rprx-vision&fp=chrome&sni=gateway.icloud.com&pbk=key&sid=123"
        )

    # Reject missing flow=xtls-rprx-vision
    with pytest.raises(AssertionError, match="flow must be 'xtls-rprx-vision'"):
        validate_vless_uri(
            "vless://9f5b2446-2ab9-42b4-8260-2ff0d061c0de@vpn.example.com:443?"
            "security=reality&flow=none&fp=chrome&sni=gateway.icloud.com&pbk=key&sid=123"
        )


def test_naive_uri_validation_oracle() -> None:
    """Oracle test: verify validate_naive_uri against valid and invalid formats."""
    # Valid NaiveProxy URI with basic auth and fragment
    valid_uri = "https://alice:secret-pass_123@proxy.example.com:8443#NaiveWorker"
    res = validate_naive_uri(valid_uri, expected_name="NaiveWorker")
    assert res["username"] == "alice"
    assert res["password"] == "secret-pass_123"
    assert res["domain"] == "proxy.example.com"
    assert res["port"] == 8443

    # Valid default 443 port without explicit port component
    valid_default_port = "https://bob:hunter2@proxy.example.com#DefaultPort"
    res2 = validate_naive_uri(valid_default_port, expected_name="DefaultPort")
    assert res2["port"] == 443

    # Valid NaiveProxy URI where fragment is the reconstructed username (H2 contract)
    reconstructed_naive = "https://alice:secret-pass_123@proxy.example.com:8443#alice"
    res_recon = validate_naive_uri(reconstructed_naive, expected_name="NaiveWorker")
    assert res_recon["username"] == "alice"

    # Reject mismatched fragment when neither expected_name nor username matches
    with pytest.raises(AssertionError, match="Expected fragment in"):
        validate_naive_uri(
            "https://alice:secret-pass_123@proxy.example.com:8443#charlie",
            expected_name="NaiveWorker",
        )

    # Reject non-https scheme
    with pytest.raises(AssertionError, match="URI must start with https://"):
        validate_naive_uri("http://bob:hunter2@proxy.example.com#DefaultPort")

    # Reject missing password / basic auth
    with pytest.raises(AssertionError, match="basic-auth password"):
        validate_naive_uri("https://bob@proxy.example.com#MissingPass")


def test_ensure_protocol_provisioning_and_qualification_oracle() -> None:
    """Oracle test: verify protocol provisioning check logic and qualification mode."""
    # 1. Qualification mode detection
    orig_testing = os.environ.get("E2E_TESTING")
    orig_dataplane = os.environ.get("E2E_REQUIRE_DATAPLANE")
    try:
        os.environ["E2E_TESTING"] = "true"
        os.environ.pop("E2E_REQUIRE_DATAPLANE", None)
        assert _is_qualification_mode() is True

        os.environ["E2E_TESTING"] = "false"
        os.environ["E2E_REQUIRE_DATAPLANE"] = "true"
        assert _is_qualification_mode() is True

        os.environ["E2E_TESTING"] = "false"
        os.environ["E2E_REQUIRE_DATAPLANE"] = "false"
        assert _is_qualification_mode() is False
    finally:
        if orig_testing is not None:
            os.environ["E2E_TESTING"] = orig_testing
        else:
            os.environ.pop("E2E_TESTING", None)
        if orig_dataplane is not None:
            os.environ["E2E_REQUIRE_DATAPLANE"] = orig_dataplane
        else:
            os.environ.pop("E2E_REQUIRE_DATAPLANE", None)

    # 2. Installed protocol check logic (AWG-only vs dual-protocol)
    awg_server: Dict[str, Any] = {
        "id": 1,
        "protocols": {"awg": {"installed": True, "container_running": True}},
    }
    assert _is_protocol_installed(awg_server, "awg") is True
    assert _is_protocol_installed(awg_server, "vless") is False
    assert _is_protocol_installed(awg_server, "naive") is False

    dual_server: Dict[str, Any] = {
        "id": 1,
        "protocols": {
            "vless": {"installed": True},
            "naive": {"container_running": True},
        },
    }
    assert _is_protocol_installed(dual_server, "vless") is True
    assert _is_protocol_installed(dual_server, "naive") is True
