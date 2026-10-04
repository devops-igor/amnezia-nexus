"""Deterministic checks that real E2E fixture operations reject failed responses."""

import ast
import importlib
import inspect
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
from playwright.sync_api import Page

from tests.e2e import test_servers as servers
from tests.e2e import test_share as share
from tests.e2e import test_vpn as vpn


class FixtureAPI:
    """Model provisioned fixtures while injecting an operation failure or a no-op."""

    def __init__(self, fault: str = "", status: int = 500) -> None:
        self.fault = fault
        self.status = status
        self.config = "[Interface]\n# synthetic fixture\n"
        self.original_config = self.config
        self.connection_name = "srv_edit_target"
        self.enabled = True
        self.threshold = 500
        self.running = True
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.request = self

    def api_get(self, page: Any, url: str) -> Any:
        """Return only the fixture inventory and resulting state used by the tests."""
        if url.startswith("/api/servers"):
            return [{"id": 1}]
        if url.startswith("/api/users/?"):
            return [{"id": "user-fixture", "username": "e2e_srv_edit_user"}]
        if url == "/api/vpn/config":
            return {
                "algorithm": "round-robin",
                "health_threshold_ms": self.threshold,
                "listen_port": 51820,
                "subnet_cidr": "<client-network>",
            }
        if url == "/api/vpn/backends":
            return {"backends": [{"server_id": 1, "enabled": self.enabled}]}
        if url.endswith("/connections"):
            return [
                {
                    "id": "connection-fixture",
                    "client_id": "client-fixture",
                    "name": self.connection_name,
                }
            ]
        raise AssertionError("Unexpected fixture GET endpoint")

    def api_post(self, page: Any, url: str, data: dict[str, Any], token: str) -> dict:
        """Return errors at the specified production operation, or update fixture state."""
        self.calls.append((url, deepcopy(data)))
        operation = ""
        if url.endswith("/container/toggle"):
            if data["action"] == "invalid_action":
                return {"status": 400, "body": {"error": "validation_failed"}}
            operation = "restart" if data["action"] == "restart" else "start"
        elif url.endswith("/server_config/save"):
            operation = "save_config"
        elif url.endswith("/server_config"):
            if data["protocol"] == "invalid_protocol":
                return {"status": 400, "body": {"error": "invalid_protocol"}}
            operation = "read_config"
        elif url.endswith("/connections/edit"):
            operation = "edit_connection"
        elif "/api/share/" in url and "/config/" in url:
            operation = "share_config"
        elif url == "/api/vpn/config":
            if data["health_threshold_ms"] == 500 and self.fault == "vpn_config_restore":
                return {"status": 500, "body": {"error": "operation_failed"}}
            self.threshold = data["health_threshold_ms"]
        elif url.endswith("/enable"):
            operation = (
                "initial_enable"
                if not any(c[0].endswith("/disable") for c in self.calls)
                else "re_enable"
            )
        elif url.endswith("/disable"):
            operation = "disable"
        if operation == "initial_enable" and self.fault == "partial_initial_enable":
            self.enabled = True
            return {"status": 500, "body": {"error": "operation_failed"}}
        if operation and self.fault == operation:
            return {"status": self.status, "body": {"error": "operation_failed"}}
        if operation == "read_config":
            config = (
                "# Configuration not found or empty"
                if self.fault == "missing_config"
                else self.config
            )
            return {"status": 200, "body": {"status": "ok", "config": config}}
        if operation == "save_config" and self.fault != "config_noop":
            self.config = data["config"]
        if operation == "edit_connection" and self.fault != "edit_noop":
            self.connection_name = data["name"]
        if operation in ("initial_enable", "re_enable") and self.fault != "enable_noop":
            self.enabled = True
        if operation == "disable" and self.fault != "disable_noop":
            self.enabled = False
        if operation == "share_config":
            config = (
                "" if self.fault == "empty_share_config" else "[Interface]\n# synthetic fixture"
            )
            return {
                "status": 200,
                "body": {"status": "ok", "config": config, "filename": "fixture.conf"},
            }
        if url.endswith("/share/setup"):
            return {"status": 200, "body": {"status": "success", "share_token": "share-fixture"}}
        if url.endswith("/check"):
            return {
                "status": 200,
                "body": {
                    "connection": "ok",
                    "docker_installed": True,
                    "protocols": {
                        "awg": {
                            "container_running": self.fault != "container_stopped"
                            or not any(url.endswith("/container/toggle") for url, _ in self.calls)
                        }
                    },
                },
            }
        return {"status": 200, "body": {"status": "ok", "state": "restart"}}

    def get(self, url: str) -> Any:
        """Provide the public share response without opening a browser."""
        return ShareResponse()


class ShareResponse:
    """Minimal successful public share response."""

    status = 200

    def json(self) -> dict:
        """Return a public share containing the provisioned connection."""
        return {
            "status": "ok",
            "username": "fixture",
            "connections": [{"id": "connection-fixture"}],
        }

    def text(self) -> str:
        """Return a harmless error summary if a real E2E function requests it."""
        return "fixture response"


def install_fixture(monkeypatch: pytest.MonkeyPatch, module: Any, fixture: FixtureAPI) -> None:
    """Replace transport helpers while preserving the real E2E test function."""
    if module is servers:
        monkeypatch.setattr(servers.time, "sleep", lambda _: None)
    monkeypatch.setattr(module, "api_get", fixture.api_get)
    monkeypatch.setattr(module, "api_post", fixture.api_post)
    if module is share:
        monkeypatch.setattr(module, "_find_or_create_user", lambda *args: {"id": "user-fixture"})


@pytest.mark.parametrize(
    ("module", "function", "fault"),
    [
        (servers, servers.test_server_container_toggle, "restart"),
        (servers, servers.test_server_config_get_and_save, "read_config"),
        (servers, servers.test_server_config_get_and_save, "save_config"),
        (servers, servers.test_server_connections_edit, "edit_connection"),
        (share, share.test_share_token_connections_and_config, "share_config"),
        (vpn, vpn.test_vpn_backend_enable_disable, "initial_enable"),
        (vpn, vpn.test_vpn_backend_enable_disable, "re_enable"),
    ],
    ids=[
        "container",
        "config-read",
        "config-save",
        "connection-edit",
        "share-config",
        "backend-enable",
        "backend-reenable",
    ],
)
@pytest.mark.parametrize("status", [400, 500])
def test_positive_operations_reject_errors(
    monkeypatch: pytest.MonkeyPatch, module: Any, function: Any, fault: str, status: int
) -> None:
    """An operation failure must fail the actual provisioned-fixture E2E test."""
    fixture = FixtureAPI(fault, status)
    install_fixture(monkeypatch, module, fixture)
    with pytest.raises(AssertionError):
        function(fixture, "https://panel.example.test", "fixture-csrf")


@pytest.mark.parametrize(
    ("module", "function", "fault"),
    [
        (servers, servers.test_server_container_toggle, "container_stopped"),
        (servers, servers.test_server_config_get_and_save, "missing_config"),
        (servers, servers.test_server_config_get_and_save, "config_noop"),
        (servers, servers.test_server_connections_edit, "edit_noop"),
        (share, share.test_share_token_connections_and_config, "empty_share_config"),
        (vpn, vpn.test_vpn_backend_enable_disable, "disable_noop"),
    ],
    ids=[
        "container-state",
        "config-missing",
        "config-noop",
        "connection-state",
        "share-empty",
        "backend-state",
    ],
)
def test_success_responses_require_resulting_state(
    monkeypatch: pytest.MonkeyPatch, module: Any, function: Any, fault: str
) -> None:
    """HTTP success without the promised fixture state must still fail."""
    fixture = FixtureAPI(fault)
    install_fixture(monkeypatch, module, fixture)
    with pytest.raises(AssertionError):
        function(fixture, "https://panel.example.test", "fixture-csrf")


@pytest.mark.parametrize(
    ("module", "function"),
    [
        (servers, servers.test_server_container_toggle),
        (servers, servers.test_server_config_get_and_save),
        (servers, servers.test_server_connections_edit),
        (share, share.test_share_token_connections_and_config),
        (vpn, vpn.test_vpn_backend_enable_disable),
    ],
    ids=["container", "config", "connection", "share", "backend"],
)
def test_successful_fixture_lifecycle(
    monkeypatch: pytest.MonkeyPatch, module: Any, function: Any
) -> None:
    """Successful real test functions complete and restore mutable fixture state."""
    fixture = FixtureAPI()
    install_fixture(monkeypatch, module, fixture)
    function(fixture, "https://panel.example.test", "fixture-csrf")
    assert fixture.config == fixture.original_config
    assert fixture.enabled is True
    if module is servers and function is servers.test_server_config_get_and_save:
        assert any(url.endswith("/save") for url, _ in fixture.calls)


@pytest.mark.parametrize("original_enabled", [True, False])
def test_backend_restores_original_administrative_state(
    monkeypatch: pytest.MonkeyPatch, original_enabled: bool
) -> None:
    """A successful toggle restores even an originally disabled backend."""
    fixture = FixtureAPI()
    fixture.enabled = original_enabled
    install_fixture(monkeypatch, vpn, fixture)
    vpn.test_vpn_backend_enable_disable(
        cast(Page, fixture), "https://panel.example.test", "fixture-csrf"
    )
    assert fixture.enabled is original_enabled


def test_initial_backend_failure_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the first backend-enable failure intact without retrying it during cleanup."""
    fixture = FixtureAPI("initial_enable", 500)
    install_fixture(monkeypatch, vpn, fixture)
    with pytest.raises(AssertionError, match="Initial backend enable failed"):
        vpn.test_vpn_backend_enable_disable(
            cast(Page, fixture), "https://panel.example.test", "fixture-csrf"
        )
    assert len(fixture.calls) == 1


def test_config_failure_does_not_disclose_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """A persisted-state assertion exposes its reason without printing configuration secrets."""
    fixture = FixtureAPI("config_noop")
    fixture.config += "PrivateKey = synthetic-config-secret\n"
    fixture.original_config = fixture.config
    install_fixture(monkeypatch, servers, fixture)
    with pytest.raises(AssertionError) as failure:
        servers.test_server_config_get_and_save(
            cast(Page, fixture), "https://panel.example.test", "fixture-csrf"
        )
    assert "synthetic-config-secret" not in str(failure.value)
    assert fixture.config == fixture.original_config


class MetricResponse:
    """Synthetic exporter response exercising the real endpoint assertion function."""

    def __init__(self, text: str, status: int = 200) -> None:
        self.status = status
        self.headers = {"content-type": "text/plain; version=0.0.4; charset=utf-8"}
        self.payload = text
        self.request = self

    def get(self, url: str) -> "MetricResponse":
        """Return the synthetic scrape without external transport."""
        return self

    def text(self) -> str:
        """Return a synthetic Prometheus exposition."""
        return self.payload

    def json(self) -> dict:
        """Return the expected anonymous API error."""
        return {"error": "unauthorized"}


def histogram_text() -> str:
    """Return a coherent two-observation, sub-millisecond histogram fixture."""
    name = "nexus_forwarder_write_duration_seconds"
    return (
        f"# HELP {name} Write duration in seconds.\n"
        f"# TYPE {name} histogram\n"
        f'{name}_bucket{{le="0.0001"}} 1\n'
        f'{name}_bucket{{le="0.001"}} 2\n'
        f'{name}_bucket{{le="+Inf"}} 2\n'
        f"{name}_count 2\n"
        f"{name}_sum 0.0002\n"
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("histogram", "gauge"),
        ('le="0.0001"', 'le="0.01"'),
        ('le="+Inf"', 'le="1"'),
        ('le="0.001"} 2', 'le="0.001"} 0'),
        ("_count 2", "_count 3"),
        ("_sum 0.0002", "_sum -1"),
        ('le="0.0001"', 'le="0.0001",peer="synthetic-peer"'),
        ("_count 2", "_count 2\nnexus_forwarder_write_duration_seconds_count 2"),
    ],
    ids=[
        "type",
        "coarse-buckets",
        "missing-infinity",
        "non-cumulative",
        "count",
        "sum",
        "labels",
        "duplicate-count",
    ],
)
def test_metrics_rejects_malformed_histograms(old: str, new: str) -> None:
    """Malformed counts, syntax and sensitive labels fail the actual scrape E2E check."""
    response = MetricResponse(histogram_text().replace(old, new))
    with pytest.raises(AssertionError):
        vpn.test_vpn_metrics_api(cast(Page, response), "https://panel.example.test")


def test_metrics_success_and_unauthorized_contracts() -> None:
    """Both the authenticated exposition and anonymous rejection are verified."""
    vpn.test_vpn_metrics_api(
        cast(Page, MetricResponse(histogram_text())), "https://panel.example.test"
    )
    vpn.test_vpn_metrics_requires_authentication(
        cast(Page, MetricResponse("", 401)), "https://panel.example.test"
    )


@pytest.mark.parametrize("status", [200, 403, 500])
def test_metrics_requires_anonymous_401(status: int) -> None:
    """Anonymous HTTP success or an unexpected error must not pass the auth check."""
    with pytest.raises(AssertionError):
        vpn.test_vpn_metrics_requires_authentication(
            cast(Page, MetricResponse("", status)), "https://panel.example.test"
        )


@pytest.mark.parametrize(
    "function",
    [
        servers.test_server_container_toggle_invalid_action,
        servers.test_server_config_invalid_protocol,
    ],
    ids=["container-action", "config-protocol"],
)
def test_negative_server_cases_are_independent(
    monkeypatch: pytest.MonkeyPatch, function: Any
) -> None:
    """Explicit bad-input tests only perform the expected negative operation."""
    fixture = FixtureAPI()
    install_fixture(monkeypatch, servers, fixture)
    function(fixture, "https://panel.example.test", "fixture-csrf")
    assert len(fixture.calls) == 1


def test_share_fixture_creation_failure_cannot_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken provisioned user setup fails instead of skipping endpoint verification."""
    monkeypatch.setattr(share, "api_get", lambda *args: [])
    monkeypatch.setattr(
        share, "api_post", lambda *args: {"status": 500, "body": {"error": "operation_failed"}}
    )
    with pytest.raises(AssertionError, match="Share user fixture creation failed"):
        share._find_or_create_user(cast(Page, object()), "fixture-csrf")


def test_empty_histogram_is_valid_without_inventing_observations() -> None:
    """An idle exporter has coherent measured zeros, not fabricated positive traffic."""
    text = (
        histogram_text()
        .replace("} 1", "} 0")
        .replace("} 2", "} 0")
        .replace("_count 2", "_count 0")
        .replace("_sum 0.0002", "_sum 0")
    )
    vpn.test_vpn_metrics_api(cast(Page, MetricResponse(text)), "https://panel.example.test")


def extended_status_fixture() -> dict:
    """Return idle yet sampled diagnostics with a route and all four history windows."""
    rates = {"rx_bytes_per_sec": 0.0, "tx_bytes_per_sec": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}
    traffic = {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0, **rates}
    backend = {
        **traffic,
        "enabled": True,
        "routable": True,
        "traffic_available": True,
        "traffic_window_sec": 1.0,
    }
    route: dict[str, Any] = dict.fromkeys(
        [
            "backend_id",
            "occupancy",
            "capacity",
            "high_water",
            "drops",
            "utilization_pct",
            "high_water_pct",
            "write_count",
            "write_errors",
            "write_stalls",
            "writes_in_flight",
            "oldest_write_ms",
            "max_write_ms",
            "p95_write_ms",
            "p95_write_samples",
            "queue_full_drops_recent",
            "write_errors_recent",
            "write_stalls_recent",
            "session_age_sec",
        ],
        0,
    )
    route.update(
        {
            "assigned_ip": "<client-ip>",
            "last_traffic_age_sec": -1,
            "traffic": {**traffic, "available": True, "window_sec": 1.0},
        }
    )
    reasons = dict.fromkeys(vpn._LOSS_REASONS, 0.0)
    backend_history = {
        "id": 1,
        "rx_bps": 0.0,
        "tx_bps": 0.0,
        "rx_pps": 0.0,
        "tx_pps": 0.0,
        "traffic_available": True,
        "probe_latency_ms": 0,
        "probe_available": False,
        "routable": True,
    }
    point = {
        "t": 1,
        "rx_bps": 0.0,
        "tx_bps": 0.0,
        "rx_pps": 0.0,
        "tx_pps": 0.0,
        "traffic_available": True,
        "q_pct": 0.0,
        "drop_rate": 0.0,
        "drop_rates_available": True,
        "drop_reason_rates": reasons,
        "fwd_p95_ms": 0.0,
        "fwd_p95_samples": 0,
        "sessions": 1,
        "routes": 1,
        "be_p95_ms": 0.0,
        "be_latency_samples": 0,
        "backends": [backend_history],
        "backends_omitted": 0,
    }
    return {
        "drop_categories": {"rates_available": True, "reason_rates": reasons},
        "forward_latency": {"stalls_recent": 0, "stalls_window_sec": 1.0},
        "backends": {
            "enabled_count": 1,
            "disabled_count": 0,
            "eligibility_known": True,
            "latency_samples": 0,
            "healthy_count": 1,
            "total_count": 1,
            "backends": [backend],
        },
        "problem_routes": [route],
        "historical_series": {
            window: [deepcopy(point)]
            for window in ("window_15m", "window_1h", "window_6h", "window_24h")
        },
    }


@pytest.mark.parametrize("available", [True, False])
def test_extended_status_distinguishes_unsampled_and_idle(available: bool) -> None:
    """Both measured idle and an explicitly unavailable backend satisfy the API contract."""
    status = extended_status_fixture()
    backend = status["backends"]["backends"][0]
    backend["traffic_available"] = available
    backend["traffic_window_sec"] = 1.0 if available else 0.0
    vpn._assert_extended_diagnostics(status)


@pytest.mark.parametrize(
    "fault",
    [
        "disabled-routable",
        "unavailable-positive-rate",
        "missing-loss-reason",
        "missing-history-core",
        "missing-route-field",
        "unbounded-window",
        "unbounded-backend-context",
        "null-backend-history",
    ],
)
def test_extended_status_rejects_inconsistent_or_incomplete_telemetry(fault: str) -> None:
    """Additive telemetry cannot regress to absent, false-healthy or unbounded output."""
    status = extended_status_fixture()
    if fault == "disabled-routable":
        status["backends"]["backends"][0]["enabled"] = False
    elif fault == "unavailable-positive-rate":
        status["backends"]["backends"][0].update(
            {"traffic_available": False, "traffic_window_sec": 0.0, "rx_pps": 5.0}
        )
    elif fault == "missing-loss-reason":
        del status["drop_categories"]["reason_rates"]["return_queue_full"]
    elif fault == "missing-history-core":
        del status["historical_series"]["window_24h"][0]["routes"]
    elif fault == "missing-route-field":
        del status["problem_routes"][0]["traffic"]
    elif fault == "unbounded-window":
        status["historical_series"]["window_15m"] *= 91
    elif fault == "unbounded-backend-context":
        status["historical_series"]["window_15m"][0]["backends"] *= 129
    elif fault == "null-backend-history":
        status["historical_series"]["window_15m"][0]["backends"] = None
    with pytest.raises(AssertionError):
        vpn._assert_extended_diagnostics(status)


def test_failed_initial_enable_restores_partial_state_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject HTTP 500 and undo an enable that changed an originally-disabled fixture."""
    fixture = FixtureAPI("partial_initial_enable")
    fixture.enabled = False
    install_fixture(monkeypatch, vpn, fixture)
    with pytest.raises(AssertionError, match="Initial backend enable failed"):
        vpn.test_vpn_backend_enable_disable(
            cast(Page, fixture), "https://panel.example.test", "fixture-csrf"
        )
    assert fixture.enabled is False
    assert fixture.calls[-1][0].endswith("/disable")


def test_vpn_config_restoration_failure_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shared threshold restoration failures cannot silently contaminate later tests."""
    fixture = FixtureAPI("vpn_config_restore")
    install_fixture(monkeypatch, vpn, fixture)
    with pytest.raises(AssertionError, match="VPN config restoration failed"):
        vpn.test_vpn_config_lifecycle(
            cast(Page, fixture), "https://panel.example.test", "fixture-csrf"
        )


def test_vpn_config_success_restores_original_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful threshold change restores the preceding shared configuration."""
    fixture = FixtureAPI()
    install_fixture(monkeypatch, vpn, fixture)
    vpn.test_vpn_config_lifecycle(cast(Page, fixture), "https://panel.example.test", "fixture-csrf")
    assert fixture.threshold == 500


PEER_DISCLOSURE_MARKER = "SyntheticPeerDisclosure"
FULL_PEER_IDENTIFIER = PEER_DISCLOSURE_MARKER + "x" * (43 - len(PEER_DISCLOSURE_MARKER)) + "="


def status_api_fixture() -> dict[str, Any]:
    """Complete the sampled diagnostics fixture for the actual status API oracle."""
    status = extended_status_fixture()
    status.update(
        {
            "status_schema_version": 2,
            "configured_engine": "awg",
            "active_engine": "awg",
            "engine_running": True,
            "listen_port": 51820,
            "listener_running": True,
            "active_tunnels": 1,
            "connected_sessions": 1,
            "health_assessment": {"status": "HEALTHY", "conditions": []},
            "rates": {"rx_bps": 0, "tx_bps": 0, "drop_rate_pps": 0},
            "queue_pressure": {"capacity": 1, "occupancy": 0, "utilization_pct": 0},
            "virtual_tun": {
                "upstream_to_nexus": dict.fromkeys(["occupancy", "capacity", "peak", "drops"], 0),
                "nexus_to_upstream": dict.fromkeys(["occupancy", "capacity", "peak", "drops"], 0),
            },
            "runtime_resources": {
                "cpu_percent": 0,
                "goroutines": 1,
                "memory_limit_available": False,
            },
            "peer_sync": None,
            "routing_consistency": {
                "ownership_mismatch_drops": 0,
                "ownership_mismatch_drops_recent": 0,
                "is_consistent": True,
            },
        }
    )
    status["forward_latency"].update(dict.fromkeys(["p50_ms", "p95_ms", "p99_ms"], 0))
    status["drop_categories"].update(dict.fromkeys(vpn._LOSS_REASONS, 0))
    status["drop_categories"].update(
        dict.fromkeys(
            [
                "client_total_drops",
                "return_total_drops",
                "total_drops",
                "return_injection_tun_drops",
            ],
            0,
        )
    )
    status["problem_routes"][0]["peer_key"] = "abcdefgh…"
    status["all_routes"] = deepcopy(status["problem_routes"])
    status["forwarder_route_queues"] = {"pk" + "a" * 24 + "-44": {"peer_key_display": "abcdefgh…"}}
    return status


def run_peer_redaction_status(
    monkeypatch: pytest.MonkeyPatch, status: dict[str, Any], module: Any = vpn
) -> None:
    """Stub only transport and run the complete real status API test."""
    monkeypatch.setattr(module, "api_get", lambda page, url: status)
    module.test_vpn_status_api(cast(Page, object()), "https://panel.example.test")


def assert_peer_redaction_failure_safe(failure: pytest.ExceptionInfo[AssertionError]) -> None:
    """Inspect exception text and pytest's traceback/explanation without dumping payloads."""
    for rendered in (str(failure.value), str(failure.getrepr(style="short", showlocals=False))):
        disclosure_free = (
            FULL_PEER_IDENTIFIER not in rendered and PEER_DISCLOSURE_MARKER not in rendered
        )
        assert disclosure_free, "Peer redaction failure disclosed a synthetic identifier"


@pytest.mark.parametrize("peer_key", ["a", "***", "abcdefgh…", "123456789"])
def test_peer_redaction_accepts_valid_identifiers(
    monkeypatch: pytest.MonkeyPatch, peer_key: str
) -> None:
    """The full oracle accepts nonempty redacted text up to the existing length limit."""
    status = status_api_fixture()
    status["problem_routes"][0]["peer_key"] = peer_key
    run_peer_redaction_status(monkeypatch, status)


@pytest.mark.parametrize("routes", [None, []], ids=["null", "empty"])
def test_peer_redaction_accepts_no_problem_routes(
    monkeypatch: pytest.MonkeyPatch, routes: Any
) -> None:
    """The existing optional/null route inventory remains valid."""
    status = status_api_fixture()
    status["problem_routes"] = routes
    run_peer_redaction_status(monkeypatch, status)


@pytest.mark.parametrize(
    "fault",
    ["missing", "empty", "null", "integer", "boolean", "list", "object", "full-length"],
)
def test_peer_redaction_rejects_invalid_identifiers_safely(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """Missing, wrongly typed and unredacted identifiers fail without exposing route content."""
    status = status_api_fixture()
    route = status["problem_routes"][0]
    route["diagnostic"] = PEER_DISCLOSURE_MARKER
    values = {
        "empty": "",
        "null": None,
        "integer": 7,
        "boolean": True,
        "list": [PEER_DISCLOSURE_MARKER],
        "object": {"value": PEER_DISCLOSURE_MARKER},
        "full-length": FULL_PEER_IDENTIFIER,
    }
    if fault == "missing":
        del route["peer_key"]
    else:
        route["peer_key"] = values[fault]
    with pytest.raises(AssertionError) as failure:
        run_peer_redaction_status(monkeypatch, status)
    assert_peer_redaction_failure_safe(failure)


@pytest.mark.parametrize(
    "routes",
    [
        {"diagnostic": PEER_DISCLOSURE_MARKER},
        7,
        True,
        PEER_DISCLOSURE_MARKER,
        "",
        {},
        [PEER_DISCLOSURE_MARKER],
        [None],
        [7],
        [[PEER_DISCLOSURE_MARKER]],
    ],
    ids=[
        "container-object",
        "container-number",
        "container-boolean",
        "container-text",
        "container-empty-text",
        "container-empty-object",
        "route-text",
        "route-null",
        "route-number",
        "route-list",
    ],
)
def test_peer_redaction_rejects_invalid_route_shapes_safely(
    monkeypatch: pytest.MonkeyPatch, routes: Any
) -> None:
    """Malformed inventories and entries fail before other assertions can render the body."""
    status = status_api_fixture()
    status["problem_routes"] = routes
    with pytest.raises(AssertionError) as failure:
        run_peer_redaction_status(monkeypatch, status)
    assert_peer_redaction_failure_safe(failure)


@pytest.mark.parametrize("mutation", ["raw-message", "raw-operands"])
def test_peer_redaction_privacy_regression_detects_independent_mutations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str
) -> None:
    """Restoring either unsafe message text or introspection independently fails privacy."""
    tree = ast.parse(inspect.getsource(vpn.test_vpn_status_api))
    assertion = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assert)
        and isinstance(node.test, ast.Name)
        and node.test.id == "peer_key_valid"
    )
    if mutation == "raw-message":
        assertion.msg = ast.parse('f"peer_key must be redacted: {peer_key}"', mode="eval").body
    else:
        assertion.test = ast.parse(
            "isinstance(peer_key, str) and 0 < len(peer_key) <= 9", mode="eval"
        ).body
    module_name = "peer_redaction_mutation_" + mutation.replace("-", "_")
    module_path = tmp_path / (module_name + ".py")
    module_path.write_text(
        "from tests.e2e.test_vpn import (Page, pytest, api_get, assert_response_shape, "
        "_assert_extended_diagnostics, re)\n" + ast.unparse(tree) + "\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    pytest.register_assert_rewrite(module_name)
    mutated = importlib.import_module(module_name)
    try:
        status = status_api_fixture()
        status["problem_routes"][0]["peer_key"] = FULL_PEER_IDENTIFIER
        with pytest.raises(AssertionError) as failure:
            run_peer_redaction_status(monkeypatch, status, mutated)
        with pytest.raises(AssertionError, match="disclosed a synthetic identifier"):
            assert_peer_redaction_failure_safe(failure)
    finally:
        sys.modules.pop(module_name, None)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-version",
        "wrong-version",
        "raw-map-key",
        "raw-map-display",
        "raw-all-route",
        "missing-return",
        "missing-return-field",
        "negative-return",
        "nonfinite-return",
        "boolean-return",
    ],
)
def test_status_schema_privacy_and_direction_contract(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """The actual API oracle rejects schema, disclosure and both-direction shape regressions."""
    status = status_api_fixture()
    if fault == "missing-version":
        del status["status_schema_version"]
    elif fault == "wrong-version":
        status["status_schema_version"] = 1
    elif fault == "raw-map-key":
        status["forwarder_route_queues"] = {FULL_PEER_IDENTIFIER: {"peer_key_display": "abcdefgh…"}}
    elif fault == "raw-map-display":
        next(iter(status["forwarder_route_queues"].values()))[
            "peer_key_display"
        ] = FULL_PEER_IDENTIFIER
    elif fault == "raw-all-route":
        status["all_routes"][0]["peer_key"] = FULL_PEER_IDENTIFIER
    elif fault == "missing-return":
        status["virtual_tun"]["nexus_to_upstream"] = {}
    elif fault == "missing-return-field":
        del status["virtual_tun"]["nexus_to_upstream"]["drops"]
    else:
        status["virtual_tun"]["nexus_to_upstream"]["drops"] = {
            "negative-return": -1,
            "nonfinite-return": float("nan"),
            "boolean-return": True,
        }[fault]
    with pytest.raises(AssertionError) as failure:
        run_peer_redaction_status(monkeypatch, status)
    assert_peer_redaction_failure_safe(failure)
