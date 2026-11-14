"""Protocol provisioning helpers for the multi-protocol E2E module.

Kept free of Playwright imports so the decision logic can be unit-tested
offline. The fixture that uses these lives in
``tests/e2e/test_multiprotocol_clients.py``; only the parts that encode a
*decision* live here, because those are the parts that can silently weaken a
qualification gate.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

# The protocols the multi-protocol client tests need, in install order.
PROTOCOLS = ("vless", "naive")

# The install endpoint is synchronous: it returns only after the container is
# running. This window covers the inventory read that follows, not a retry.
POLL_SECONDS = 30


def install_payload(proto: str) -> Dict[str, Any]:
    """Return the standard install body for a provisioned protocol.

    VLESS: port 443, server_name gateway.icloud.com, flow xtls-rprx-vision.
    NaiveProxy: port 9443, domain proxy.example.com, decoy default.
    """
    if proto == "vless":
        return {
            "protocol": "vless",
            "port": "443",
            "vless_options": {
                "server_name": "gateway.icloud.com",
                "port": "443",
                "flow": "xtls-rprx-vision",
            },
        }
    if proto == "naive":
        return {
            "protocol": "naive",
            "port": "9443",
            "naive_options": {
                "domain": "proxy.example.com",
                "port": "9443",
                "decoy": "default",
            },
        }
    raise ValueError(f"Unsupported protocol for auto-provisioning: {proto}")


def json_or_none(response: Any) -> Any:
    """Return the parsed body, or None when it is not JSON."""
    try:
        return response.json()
    except Exception:
        return None


def server_by_id(payload: Any, server_id: int) -> Optional[Dict[str, Any]]:
    """Return one server from a list response, or None.

    The API only exposes the collection (GET /api/servers); there is no
    single-server route, so callers must select from the list.
    """
    servers = payload if isinstance(payload, list) else (payload or {}).get("servers", [])
    if not isinstance(servers, list):
        return None
    for server in servers:
        if server.get("id") == server_id:
            return server
    return None


def servers_from_inventory(
    ok: bool, status: int, payload: Any, qualification: bool
) -> List[Dict[str, Any]]:
    """Return the server inventory, or raise the correct pytest outcome.

    A failed inventory read is not an empty inventory: the first is a defect and
    must fail. An empty inventory may only skip outside qualification mode --
    in strict qualification a missing DEV server has to fail the gate rather
    than quietly skip the tests that depend on it.
    """
    if not ok:
        pytest.fail(f"GET /api/servers returned {status} while provisioning protocols")

    if payload is None:
        pytest.fail("GET /api/servers returned an unusable body while provisioning protocols")

    servers = payload if isinstance(payload, list) else payload.get("servers", [])
    if not isinstance(servers, list):
        pytest.fail(
            "GET /api/servers returned an unusable server list while provisioning protocols"
        )

    if not servers:
        if qualification:
            pytest.fail("no server available to provision protocols in qualification mode")
        pytest.skip("no server available to provision")

    return servers
