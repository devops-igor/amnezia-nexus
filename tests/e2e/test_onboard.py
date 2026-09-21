"""E2E tests for automated clean-slate server onboarding and AWG installation."""

import os
import time
from typing import Any, Dict

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import api_post


def _get_server_credentials() -> Dict[str, Any]:
    """Read server onboarding connection parameters from environment."""
    host = os.environ.get("E2E_SERVER_HOST", "172.17.0.1")
    ssh_port_raw = os.environ.get("E2E_SERVER_SSH_PORT", "22")
    ssh_port = int(ssh_port_raw) if ssh_port_raw.isdigit() else 22
    username = os.environ.get("E2E_SERVER_SSH_USER", "ubuntu")
    password = os.environ.get("E2E_SERVER_SSH_PASS", "")
    ssh_key_path = os.environ.get("E2E_SERVER_SSH_KEY", "")

    private_key = ""
    # 1. Read from specified key path or inline content
    if ssh_key_path:
        expanded_path = os.path.expanduser(ssh_key_path)
        if os.path.isfile(expanded_path):
            with open(expanded_path, "r", encoding="utf-8") as f:
                private_key = f.read()
        elif "\n" in ssh_key_path or "PRIVATE KEY" in ssh_key_path:
            private_key = ssh_key_path
    elif not password:
        # 2. Check standard default key paths if neither key nor password was set
        for default_path in [
            os.path.expanduser("~/.ssh/id_ed25519"),
            os.path.expanduser("~/.ssh/id_rsa"),
        ]:
            if os.path.isfile(default_path):
                with open(default_path, "r", encoding="utf-8") as f:
                    private_key = f.read()
                break

    return {
        "host": host,
        "ssh_port": ssh_port,
        "username": username,
        "password": password,
        "private_key": private_key,
        "name": "Server 1",
    }


@pytest.mark.e2e
def test_onboard_server_add(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Register Server 1 and verify SSH fingerprint confirmation."""
    creds = _get_server_credentials()

    # Step 1: Add server to initiate SSH connection and capture fingerprint
    add_payload = {
        "host": creds["host"],
        "ssh_port": creds["ssh_port"],
        "username": creds["username"],
        "password": creds["password"],
        "private_key": creds["private_key"],
        "name": creds["name"],
    }
    add_result = api_post(
        authenticated_page, "/api/servers/add", add_payload, csrf_token, timeout=60_000
    )
    assert add_result["status"] == 200, (
        f"POST /api/servers/add returned status {add_result['status']}: "
        f"{add_result.get('body')}"
    )

    add_body = add_result.get("body", {})
    assert isinstance(add_body, dict), f"Expected dict body, got {add_body}"
    assert (
        add_body.get("status") == "pending_fingerprint_confirmation"
    ), f"Unexpected add status: {add_body.get('status')}"

    fingerprint = add_body.get("fingerprint")
    assert fingerprint, f"Missing fingerprint in response: {add_body}"
    server_info = add_body.get("server_info", "")

    # Step 2: Confirm fingerprint and persist server
    confirm_payload = {
        "host": creds["host"],
        "ssh_port": creds["ssh_port"],
        "username": creds["username"],
        "password": creds["password"],
        "private_key": creds["private_key"],
        "name": creds["name"],
        "server_info": server_info,
        "fingerprint": fingerprint,
    }
    confirm_result = api_post(
        authenticated_page,
        "/api/servers/confirm-fingerprint",
        confirm_payload,
        csrf_token,
        timeout=60_000,
    )
    assert confirm_result["status"] == 200, (
        f"POST /api/servers/confirm-fingerprint returned status {confirm_result['status']}: "
        f"{confirm_result.get('body')}"
    )

    confirm_body = confirm_result.get("body", {})
    assert isinstance(confirm_body, dict), f"Expected dict body, got {confirm_body}"
    assert (
        confirm_body.get("status") == "ok"
    ), f"Expected status == 'ok', got {confirm_body.get('status')}"

    server_id = confirm_body.get("server_id")
    assert server_id == 1, f"Expected server_id == 1, got {server_id}"


@pytest.mark.e2e
def test_onboard_server_reachability(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Verify Server 1 reachability and Docker installation via check API."""
    check_result = api_post(
        authenticated_page, "/api/servers/1/check", {}, csrf_token, timeout=60_000
    )
    assert check_result["status"] == 200, (
        f"POST /api/servers/1/check returned status {check_result['status']}: "
        f"{check_result.get('body')}"
    )

    body = check_result.get("body", {})
    assert isinstance(body, dict), f"Expected dict body, got {body}"
    assert (
        body.get("connection") == "ok"
    ), f"Expected connection == 'ok', got {body.get('connection')}"
    assert (
        body.get("docker_installed") is True
    ), f"Expected docker_installed is True, got {body.get('docker_installed')}"


@pytest.mark.e2e
def test_onboard_install_amneziawg(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Deploy AmneziaWG protocol on Server 1."""
    install_payload = {
        "protocol": "awg",
        "port": "51820",
    }
    install_result = api_post(
        authenticated_page,
        "/api/servers/1/install",
        install_payload,
        csrf_token,
        timeout=180_000,
    )
    assert install_result["status"] == 200, (
        f"POST /api/servers/1/install returned status {install_result['status']}: "
        f"{install_result.get('body')}"
    )

    body = install_result.get("body", {})
    assert isinstance(body, dict), f"Expected dict body, got {body}"
    assert body.get("status") == "ok", f"Expected status == 'ok', got {body.get('status')}"
    assert body.get("protocol") == "awg", f"Expected protocol == 'awg', got {body.get('protocol')}"


@pytest.mark.e2e
def test_onboard_verify_awg_container_healthy(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Poll Server 1 status up to 120s until AmneziaWG container is running and healthy."""
    max_wait_seconds = 120
    poll_interval = 3
    deadline = time.time() + max_wait_seconds

    awg_healthy = False
    last_body: dict = {}

    while time.time() < deadline:
        check_result = api_post(
            authenticated_page, "/api/servers/1/check", {}, csrf_token, timeout=60_000
        )
        if check_result["status"] == 200 and isinstance(check_result.get("body"), dict):
            last_body = check_result["body"]
            protocols = last_body.get("protocols", {})
            if isinstance(protocols, dict):
                awg_status = protocols.get("awg", {})
                if isinstance(awg_status, dict) and awg_status.get("container_running") is True:
                    awg_healthy = True
                    break
        time.sleep(poll_interval)

    assert awg_healthy, (
        f"AmneziaWG container did not report container_running=True within {max_wait_seconds}s. "
        f"Last check response: {last_body}"
    )
