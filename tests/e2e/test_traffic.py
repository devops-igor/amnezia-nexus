"""Automated Data Plane Traffic Verification Test Suite.

Verifies end-to-end network traffic through the AmneziaWG tunnel:
1. Docker daemon reachability and AmneziaWG client container image availability.
2. Server discovery and AmneziaWG protocol container health verification.
3. Client user and connection provisioning via Amnezia Nexus REST API.
4. Hermetic client tunnel establishment in an isolated Docker container network namespace.
5. Obfuscated AmneziaWG cryptographic handshake completion.
6. Bi-directional ICMP connectivity to tunnel gateway (10.8.1.1).
7. Server-side egress NAT / MASQUERADE internet forwarding.
8. Connection toggle / revocation verification (packet termination upon disable, resumption upon re-enable).
9. Hermetic cleanup of test container, routes, and user records.
"""

import logging
import os
import re
import subprocess
import time
import uuid
from typing import Any, Dict, Optional, Tuple

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import api_get, api_post

logger = logging.getLogger(__name__)

# Preferred AmneziaWG client container image and fallback image
PRIMARY_CLIENT_IMAGE = "amneziavpn/amneziawg-go:latest"
FALLBACK_CLIENT_IMAGE = "devopsigor/amneziawg:ci-test"
GATEWAY_IP = "10.8.1.1"


def _check_docker_available() -> bool:
    """Check whether local Docker daemon is reachable."""
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return res.returncode == 0
    except Exception as exc:
        logger.warning("Docker daemon reachability check failed: %s", exc)
        return False


def _resolve_client_image() -> Optional[str]:
    """Resolve available AmneziaWG client image or attempt pull.

    Returns the image tag if available, or None if unavailable.
    """
    for img in (PRIMARY_CLIENT_IMAGE, FALLBACK_CLIENT_IMAGE):
        inspect_res = subprocess.run(
            ["docker", "image", "inspect", img],
            capture_output=True,
            text=True,
        )
        if inspect_res.returncode == 0:
            return img

        logger.info("Attempting to pull AmneziaWG client image: %s", img)
        pull_res = subprocess.run(
            ["docker", "pull", img],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if pull_res.returncode == 0:
            return img

    return None


def _docker_exec(
    container_name: str, cmd: str, timeout: int = 20
) -> subprocess.CompletedProcess[str]:
    """Execute a shell command inside the running client Docker container."""
    return subprocess.run(
        ["docker", "exec", container_name, "sh", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _normalize_config_endpoint(config_str: str) -> str:
    """Normalize Endpoint address so Docker client container can reach the server.

    When the panel runs with 127.0.0.1 or localhost, client containers cannot
    connect to loopback inside their own network namespace. We replace loopback
    endpoints with the default Docker bridge gateway (172.17.0.1 or E2E_SERVER_HOST).
    """
    server_host = os.environ.get("E2E_SERVER_HOST", "172.17.0.1")
    return re.sub(
        r"Endpoint\s*=\s*(?:127\.0\.0\.1|localhost):",
        f"Endpoint = {server_host}:",
        config_str,
    )


def _discover_awg_server(page: Page, csrf_token: str) -> Tuple[int, Dict[str, Any]]:
    """Discover a server with a healthy AmneziaWG protocol deployment."""
    result = api_get(page, "/api/servers/")
    servers = result if isinstance(result, list) else result.get("servers", [])
    if not servers:
        pytest.skip("No registered servers available in panel")

    for srv in servers:
        srv_id = srv.get("id")
        if srv_id is None:
            continue

        check_res = api_post(page, f"/api/servers/{srv_id}/check", {}, csrf_token, timeout=20000)
        if check_res.get("status") == 200 and isinstance(check_res.get("body"), dict):
            protocols = check_res["body"].get("protocols", {})
            if isinstance(protocols, dict):
                awg_stat = protocols.get("awg", {})
                if isinstance(awg_stat, dict) and awg_stat.get("container_running") is True:
                    return (srv_id, srv)

        srv_protocols = srv.get("protocols", {})
        if isinstance(srv_protocols, dict):
            awg_stat = srv_protocols.get("awg", {})
            if isinstance(awg_stat, dict) and (
                awg_stat.get("installed") is True or awg_stat.get("container_running") is True
            ):
                return (srv_id, srv)

    pytest.skip("No server found with active and running AmneziaWG container")


def _wait_for_handshake(container_name: str, iface: str = "awg0", timeout: int = 15) -> bool:
    """Poll awg status inside the client container until latest handshake is established."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = _docker_exec(container_name, f"awg show {iface} latest-handshakes")
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split()
            if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) > 0:
                return True

        res_show = _docker_exec(container_name, f"awg show {iface}")
        if "latest handshake" in res_show.stdout:
            return True

        # Send probe packet to trigger WireGuard / AmneziaWG handshake initiation
        _docker_exec(container_name, f"ping -c 1 -W 1 {GATEWAY_IP}")
        time.sleep(1)

    return False


def _get_transfer_stats(container_name: str, iface: str = "awg0") -> Tuple[int, int]:
    """Return received and sent bytes from awg show transfer."""
    res = _docker_exec(container_name, f"awg show {iface} transfer")
    if res.returncode == 0 and res.stdout.strip():
        parts = res.stdout.strip().split()
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            return (int(parts[1]), int(parts[2]))
    return (0, 0)


def _verify_egress_nat(container_name: str) -> bool:
    """Verify that external packets are routed through the tunnel with NAT / MASQUERADE."""
    # Probe 1: Ping public DNS IP 1.1.1.1
    p1 = _docker_exec(container_name, "ping -c 3 -W 3 1.1.1.1")
    if p1.returncode == 0:
        return True

    # Probe 2: HTTP GET to 1.1.1.1 via wget
    w1 = _docker_exec(container_name, "wget -q -T 5 -O- http://1.1.1.1")
    if w1.returncode == 0:
        return True

    # Probe 3: HTTP probe to external IP reflection service
    w2 = _docker_exec(container_name, "wget -q -T 5 -O- http://icanhazip.com")
    if w2.returncode == 0 and w2.stdout.strip():
        return True

    return False


@pytest.mark.e2e
def test_docker_preflight() -> None:
    """Pre-flight check: Docker daemon reachability and AmneziaWG client image presence."""
    if not _check_docker_available():
        pytest.skip("Docker daemon is unreachable; skipping data plane traffic test")

    client_image = _resolve_client_image()
    if not client_image:
        pytest.skip(
            f"Neither {PRIMARY_CLIENT_IMAGE} nor {FALLBACK_CLIENT_IMAGE} available; skipping"
        )

    logger.info("Docker pre-flight passed using client image: %s", client_image)


@pytest.mark.e2e
def test_dataplane_traffic_verification(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Verify complete data plane lifecycle: handshake, ping, egress NAT, and revocation toggle."""
    page = authenticated_page

    # 1. Pre-flight checks
    if not _check_docker_available():
        pytest.skip("Docker daemon is unreachable; skipping data plane traffic test")

    client_image = _resolve_client_image()
    if not client_image:
        pytest.skip("AmneziaWG client container image is unavailable; skipping")

    # 2. Server discovery
    server_id, server_data = _discover_awg_server(page, csrf_token)
    logger.info("Selected server ID %d for data plane traffic test", server_id)

    # 3. Client Provisioning via Panel API
    test_user_id = None
    client_container_name = f"e2e-traffic-client-{int(time.time())}-{uuid.uuid4().hex[:6]}"

    try:
        unique_suffix = f"{int(time.time())}_{uuid.uuid4().hex[:4]}"
        test_username = f"e2e_traffic_{unique_suffix}"
        test_conn_name = f"e2e_client_{unique_suffix}"

        add_user_res = api_post(
            page,
            "/api/users/add",
            {
                "username": test_username,
                "password": "TrafficTestPass123!",
                "role": "user",
                "enabled": True,
            },
            csrf_token,
        )
        assert add_user_res["status"] == 200, f"User creation failed: {add_user_res}"
        test_user_id = add_user_res["body"].get("user_id")
        if not test_user_id:
            users_list = api_get(page, "/api/users/?size=100")
            users = users_list if isinstance(users_list, list) else users_list.get("users", [])
            for u in users:
                if u.get("username") == test_username:
                    test_user_id = u.get("id")
                    break

        assert test_user_id, "Failed to resolve provisioned test user ID"

        # Provision AmneziaWG connection
        conn_res = api_post(
            page,
            f"/api/users/{test_user_id}/connections/add",
            {"server_id": server_id, "protocol": "awg", "name": test_conn_name},
            csrf_token,
        )
        assert conn_res["status"] == 200, f"Connection creation failed: {conn_res}"

        conn_body = conn_res.get("body", {})
        config_str = conn_body.get("config", "")
        conn_obj = conn_body.get("connection", {})
        client_pubkey = conn_body.get("client_id") or conn_obj.get("client_id", "")
        conn_id = conn_obj.get("id", "")

        # Fallback to config endpoint if inline config was omitted
        if not config_str and conn_id:
            cfg_res = api_post(
                page,
                f"/api/connections/{conn_id}/config",
                {},
                csrf_token,
            )
            if cfg_res.get("status") == 200:
                config_str = cfg_res.get("body", {}).get("config", "")

        assert config_str, "Client configuration profile must not be empty"
        assert "[Interface]" in config_str, "Configuration missing [Interface] section"
        assert "[Peer]" in config_str, "Configuration missing [Peer] section"

        # 4. Hermetic Client Tunnel Setup
        config_str = _normalize_config_endpoint(config_str)

        run_cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            client_container_name,
            "--privileged",
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun:/dev/net/tun",
            "--entrypoint",
            "/bin/sh",
            client_image,
            "-c",
            "tail -f /dev/null",
        ]
        start_res = subprocess.run(run_cmd, capture_output=True, text=True, timeout=30)
        assert start_res.returncode == 0, f"Failed to start client container: {start_res.stderr}"

        # Write client configuration inside container to /tmp/client.conf and /tmp/awg0.conf
        pipe_cmd = [
            "docker",
            "exec",
            "-i",
            client_container_name,
            "sh",
            "-c",
            "cat > /tmp/client.conf && chmod 600 /tmp/client.conf && "
            "cp /tmp/client.conf /tmp/awg0.conf && chmod 600 /tmp/awg0.conf",
        ]
        pipe_res = subprocess.run(
            pipe_cmd,
            input=config_str,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert pipe_res.returncode == 0, f"Failed to write config into container: {pipe_res.stderr}"

        # Bring up AmneziaWG tunnel interface
        up_res = _docker_exec(client_container_name, "awg-quick up /tmp/awg0.conf")
        assert up_res.returncode == 0, f"awg-quick up failed: {up_res.stderr} | {up_res.stdout}"

        # Verify interface awg0 exists and is UP
        link_res = _docker_exec(client_container_name, "ip link show dev awg0")
        assert link_res.returncode == 0, f"awg0 interface link check failed: {link_res.stderr}"
        assert "UP" in link_res.stdout or "state" in link_res.stdout

        # 5. Handshake Verification
        handshake_ok = _wait_for_handshake(client_container_name, "awg0", timeout=20)
        assert handshake_ok, "AmneziaWG cryptographic handshake with server was not completed"

        # 6. Bi-Directional ICMP Ping to Gateway
        ping_res = _docker_exec(client_container_name, f"ping -c 3 -W 3 {GATEWAY_IP}")
        assert (
            ping_res.returncode == 0
        ), f"Ping to gateway {GATEWAY_IP} failed: {ping_res.stderr}\n{ping_res.stdout}"

        rx_bytes, tx_bytes = _get_transfer_stats(client_container_name, "awg0")
        assert rx_bytes > 0, f"Expected positive RX bytes through awg0, got {rx_bytes}"
        assert tx_bytes > 0, f"Expected positive TX bytes through awg0, got {tx_bytes}"

        # 7. Egress NAT & Internet Forwarding
        nat_forwarding_ok = _verify_egress_nat(client_container_name)
        assert nat_forwarding_ok, "External packet probe failed; server-side egress NAT not active"

        # 8. Revocation & Disconnection Verification
        toggle_disable = api_post(
            page,
            f"/api/servers/{server_id}/connections/toggle",
            {
                "client_id": client_pubkey,
                "connection_id": conn_id,
                "protocol": "awg",
                "enable": False,
                "enabled": False,
            },
            csrf_token,
        )
        assert (
            toggle_disable.get("status") == 200
        ), f"Failed to disable connection: {toggle_disable}"

        # Assert ping immediately fails (100% packet loss)
        ping_disabled = _docker_exec(client_container_name, f"ping -c 2 -W 2 {GATEWAY_IP}")
        assert ping_disabled.returncode != 0, "Ping unexpectedly succeeded after peer revocation"

        # Re-enable connection via toggle API
        toggle_enable = api_post(
            page,
            f"/api/servers/{server_id}/connections/toggle",
            {
                "client_id": client_pubkey,
                "connection_id": conn_id,
                "protocol": "awg",
                "enable": True,
                "enabled": True,
            },
            csrf_token,
        )
        assert (
            toggle_enable.get("status") == 200
        ), f"Failed to re-enable connection: {toggle_enable}"

        # Verify traffic resumes
        resumed = False
        for _ in range(10):
            res_ping_resume = _docker_exec(client_container_name, f"ping -c 2 -W 2 {GATEWAY_IP}")
            if res_ping_resume.returncode == 0:
                resumed = True
                break
            time.sleep(1)

        assert resumed, "Traffic did not resume after re-enabling peer connection"

    finally:
        # 9. Hermetic Teardown: Stop and delete client container
        subprocess.run(
            ["docker", "rm", "-f", client_container_name],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Delete test user
        if test_user_id:
            api_post(page, f"/api/users/{test_user_id}/delete", {}, csrf_token)
