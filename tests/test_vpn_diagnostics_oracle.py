"""Deterministic checks of the published diagnostics and privacy consumers."""

import ast
import importlib
import inspect
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
from playwright.sync_api import Page

from tests.e2e import test_vpn_diagnostics as vpn


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
        "from tests.e2e.test_vpn_diagnostics import (Page, pytest, api_get, assert_response_shape, "
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
