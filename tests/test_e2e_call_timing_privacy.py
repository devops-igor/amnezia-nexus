"""Offline schema/privacy tests for the provider call timing collector.

Every fixture is synthetic. The point of these tests is that a hostile or
corrupted operator log can only ever produce an allowlisted artifact: marker
lines carrying secrets, URLs, ids or unknown fields must be rejected whole, and
the writer must refuse to persist anything that fails validation.
"""

import json
from pathlib import Path

import pytest

from tests.e2e import diagnostics

# Hostile markers that must never reach an artifact.
SECRET_API_KEY = "flux_live_" + "deadbeef" * 8
SECRET_HOST = "panel.internal.example.invalid"
SECRET_ORDER_ID = "987654321"


def timing_line(**overrides: str | None) -> str:
    """Build one logfmt timing line as the panel would emit it."""
    fields = {
        "time": "2026-11-08T05:00:00Z",
        "level": "INFO",
        "msg": "gigahost_call",
        "method": "GET",
        "op": "servers_get",
        "outcome": "client_timeout",
        "status": "0",
        "total_ms": "30001",
        "last_phase": "request_written",
        "reused": "true",
        "proto": "http/1.1",
        "get_conn_ms": "0",
        "dns_ms": "1",
        "connect_ms": "2",
        "tls_ms": "-1",
        "request_written_ms": "5",
        "first_byte_ms": "-1",
    }
    fields.update(overrides)
    return " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)


def test_parses_a_valid_record_into_the_allowlisted_schema():
    payload = diagnostics.parse_call_timing_log(timing_line())
    assert payload is not None
    assert payload["source"] == diagnostics.TIMING_SOURCE
    assert payload["occurrences"] == 1
    assert payload["truncated"] == 0
    assert diagnostics.validate_timing_report(payload) == []
    call = payload["calls"][0]
    assert set(call) == diagnostics._CALL_KEYS
    assert call["op"] == "servers_get"
    assert call["outcome"] == "client_timeout"
    assert call["total_ms"] == 30001
    # The not-reached sentinel survives: "never happened" is not "0 ms".
    assert call["first_byte_ms"] == -1


def test_absent_marker_yields_none_not_an_empty_report():
    assert diagnostics.parse_call_timing_log("") is None
    assert diagnostics.parse_call_timing_log("msg=something_else total_ms=5") is None


def test_marker_line_with_a_secret_is_rejected_whole():
    """A crafted line carrying a live key must contribute nothing."""
    hostile = timing_line(api_key=SECRET_API_KEY, url="https://" + SECRET_HOST + "/x")
    assert diagnostics.parse_call_timing_log(hostile) is None


def test_marker_line_with_unknown_operation_is_rejected():
    assert diagnostics.parse_call_timing_log(timing_line(op="deploy_servers_secret")) is None
    assert diagnostics.parse_call_timing_log(timing_line(op="/deploy/servers")) is None


def test_marker_line_with_unknown_fields_is_dropped_not_passed_through():
    # A line carrying an unexpected key is rejected whole: no partial trust.
    assert diagnostics.parse_call_timing_log(timing_line(order_id=SECRET_ORDER_ID)) is None


def test_marker_line_with_a_missing_field_is_rejected():
    """Partial records are not evidence; the Go side always emits every field."""
    assert diagnostics.parse_call_timing_log(timing_line(proto=None)) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"method": "BREW"},
        {"outcome": "timeout"},
        {"last_phase": "/deploy/servers"},
        {"proto": "spdy"},
        {"reused": "yes"},
        {"status": "999"},
        {"total_ms": "-5"},
        {"first_byte_ms": "-2"},
        {"total_ms": "notanumber"},
    ],
)
def test_out_of_class_values_reject_the_line(overrides):
    assert diagnostics.parse_call_timing_log(timing_line(**overrides)) is None


def test_validator_rejects_tampered_records():
    payload = diagnostics.parse_call_timing_log(timing_line())
    assert diagnostics.validate_timing_report(payload) == []

    tampered = json.loads(json.dumps(payload))
    tampered["calls"][0]["host"] = SECRET_HOST
    assert diagnostics.validate_timing_report(tampered)

    tampered2 = json.loads(json.dumps(payload))
    tampered2["calls"][0]["outcome"] = "crashed"
    assert diagnostics.validate_timing_report(tampered2)

    tampered3 = json.loads(json.dumps(payload))
    tampered3["source"] = "operator-log"
    assert diagnostics.validate_timing_report(tampered3)


def test_writer_refuses_invalid_payload(tmp_path: Path):
    assert diagnostics.write_timing_artifact(tmp_path, {"nope": 1}) is None
    assert list(tmp_path.glob("*.json")) == []


def test_writer_persists_valid_payload(tmp_path: Path):
    payload = diagnostics.parse_call_timing_log(timing_line())
    assert payload is not None
    written = diagnostics.write_timing_artifact(tmp_path, payload)
    assert written is not None
    on_disk = json.loads(written.read_text(encoding="utf-8"))
    assert diagnostics.validate_timing_report(on_disk) == []


def test_collect_reports_counts_and_writes(tmp_path: Path, capsys):
    status = diagnostics.collect_timing_log(timing_line() + "\n" + timing_line(), tmp_path)
    assert status == 0
    assert (tmp_path / "provider-call-timing.json").is_file()
    out = capsys.readouterr().out
    assert "2 record(s)" in out
    # Only counts are printed: never the record content.
    assert SECRET_HOST not in out


def test_collect_with_no_marker_writes_nothing(tmp_path: Path):
    assert diagnostics.collect_timing_log("unrelated log line\n", tmp_path) == 0
    assert not (tmp_path / "provider-call-timing.json").exists()


def test_calls_are_capped_and_truncation_is_counted(tmp_path: Path):
    many = "\n".join(timing_line() for _ in range(diagnostics.MAX_TIMING_CALLS + 5))
    payload = diagnostics.parse_call_timing_log(many)
    assert payload is not None
    assert payload["occurrences"] == diagnostics.MAX_TIMING_CALLS + 5
    assert len(payload["calls"]) == diagnostics.MAX_TIMING_CALLS
    assert payload["truncated"] == 5
    assert diagnostics.validate_timing_report(payload) == []


def test_gate_publishes_a_valid_timing_artifact(tmp_path: Path):
    payload = diagnostics.parse_call_timing_log(timing_line())
    assert payload is not None
    assert diagnostics.write_timing_artifact(tmp_path, payload) is not None
    assert diagnostics.gate(tmp_path) == 0
    assert (tmp_path / "provider-call-timing.json").is_file()


def test_gate_withholds_directory_when_a_timing_artifact_is_tampered(tmp_path: Path):
    payload = diagnostics.parse_call_timing_log(timing_line())
    assert payload is not None
    assert diagnostics.write_timing_artifact(tmp_path, payload) is not None
    path = tmp_path / "provider-call-timing.json"
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["calls"][0]["op"] = "https://" + SECRET_HOST
    path.write_text(json.dumps(tampered), encoding="utf-8")

    assert diagnostics.gate(tmp_path) == 1
    # All-or-nothing: the whole directory is gone, so nothing can be uploaded.
    assert not tmp_path.exists()


def test_cli_collects_timing_from_an_operator_log(tmp_path: Path):
    log = tmp_path / "operator.log"
    log.write_text(
        "ordinary line that must be ignored\n" + timing_line() + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "diagnostics"
    assert diagnostics.main(["--validate-dir", str(out_dir), "--call-timing-log", str(log)]) == 0
    written = out_dir / "provider-call-timing.json"
    assert written.is_file()
    report = json.loads(written.read_text(encoding="utf-8"))
    assert diagnostics.validate_timing_report(report) == []


def test_cli_tolerates_a_missing_log(tmp_path: Path):
    out_dir = tmp_path / "diagnostics"
    missing = tmp_path / "absent.log"
    assert diagnostics.main(["--validate-dir", str(out_dir), "--call-timing-log", str(missing)]) == 0
    assert not (out_dir / "provider-call-timing.json").exists()


def test_gitignored_raw_log_is_never_the_artifact(tmp_path: Path):
    """The artifact is the reduced report, never a copy of the operator log."""
    log = tmp_path / "operator.log"
    log.write_text(timing_line(api_key=SECRET_API_KEY) + "\n" + timing_line(), encoding="utf-8")
    out_dir = tmp_path / "diagnostics"
    assert diagnostics.main(["--validate-dir", str(out_dir), "--call-timing-log", str(log)]) == 0
    for artifact in out_dir.glob("*.json"):
        text = artifact.read_text(encoding="utf-8")
        assert SECRET_API_KEY not in text
        assert "2026-11-08T05:00:00Z" not in text  # even the timestamp is dropped
