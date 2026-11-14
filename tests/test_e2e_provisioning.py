"""Offline tests for the E2E provisioning decision logic.

The fixture itself needs Playwright and a live panel, so the parts that decide
between failing and skipping live in :mod:`tests.e2e.provisioning` and are
tested here. That distinction matters: a wrong decision silently weakens the
qualification gate instead of failing it.
"""

from __future__ import annotations

import pytest

from tests.e2e import provisioning


def test_failed_inventory_read_fails_even_outside_qualification() -> None:
    """A broken inventory read is a defect, not an empty inventory."""
    with pytest.raises(pytest.fail.Exception, match="returned 500"):
        provisioning.servers_from_inventory(False, 500, None, qualification=False)


def test_unusable_inventory_body_fails() -> None:
    """A 200 with a non-JSON body must not be read as 'no servers'."""
    with pytest.raises(pytest.fail.Exception, match="unusable body"):
        provisioning.servers_from_inventory(True, 200, None, qualification=False)


def test_unusable_server_list_fails() -> None:
    """A body whose servers field is not a list is corrupt, not empty."""
    with pytest.raises(pytest.fail.Exception, match="unusable server list"):
        provisioning.servers_from_inventory(True, 200, {"servers": "nope"}, qualification=False)


def test_missing_server_fails_in_qualification_mode() -> None:
    """The gate must not pass by skipping when a DEV server is required."""
    with pytest.raises(pytest.fail.Exception, match="qualification mode"):
        provisioning.servers_from_inventory(True, 200, [], qualification=True)


def test_missing_server_skips_outside_qualification_mode() -> None:
    """A developer run without a server may skip rather than fail."""
    with pytest.raises(pytest.skip.Exception):
        provisioning.servers_from_inventory(True, 200, [], qualification=False)


@pytest.mark.parametrize(
    "payload",
    [
        [{"id": 1, "name": "dev"}],
        {"servers": [{"id": 1, "name": "dev"}]},
    ],
)
def test_inventory_accepts_list_and_wrapped_shapes(payload) -> None:
    servers = provisioning.servers_from_inventory(True, 200, payload, qualification=True)
    assert servers[0]["id"] == 1


def test_install_payloads_match_the_documented_fixture() -> None:
    vless = provisioning.install_payload("vless")
    assert vless["port"] == "443"
    assert vless["vless_options"]["server_name"] == "gateway.icloud.com"
    assert vless["vless_options"]["flow"] == "xtls-rprx-vision"

    naive = provisioning.install_payload("naive")
    assert naive["port"] == "9443"
    assert naive["naive_options"]["domain"] == "proxy.example.com"


def test_unknown_protocol_is_rejected() -> None:
    with pytest.raises(ValueError):
        provisioning.install_payload("wireguard")


def test_server_by_id_handles_both_shapes_and_absence() -> None:
    assert provisioning.server_by_id([{"id": 1}, {"id": 2}], 2) == {"id": 2}
    assert provisioning.server_by_id({"servers": [{"id": 3}]}, 3) == {"id": 3}
    assert provisioning.server_by_id([{"id": 1}], 9) is None
    assert provisioning.server_by_id(None, 1) is None
    assert provisioning.server_by_id({"servers": "nope"}, 1) is None
