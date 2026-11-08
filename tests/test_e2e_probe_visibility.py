"""Privacy and behaviour tests for the failed-probe log collector (#724).

Every test drives the real artifact seam used by the lifecycle script
(``main --validate-dir ... --probe-log ...``) rather than a private helper, so a
regression in argument wiring, gate routing or artifact naming fails here.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.e2e import diagnostics

# A realistic slog text-handler line produced by internal/handlers/docker_probe.go.
PROBE_LINE = (
    'time=2026-11-07T19:31:04.123+00:00 level=WARN '
    'msg="ServerCheckHandler: docker CLI probe failed" server_id=1 exit_code=127 '
    'transport_error= stdout_len=0 stdout_state=empty stderr_len=42'
)

# A captured operator log: unrelated noise, the probe line, and more noise.
LOG_WITH_PROBE = "\n".join(
    [
        'time=2026-11-07T19:30:58.000+00:00 level=INFO msg="Starting Amnezia Nexus"',
        'time=2026-11-07T19:31:03.900+00:00 level=WARN msg="falling back to the provisioning '
        'AmneziaWG public key artifact" container=amnezia-awg2 server_id=1',
        PROBE_LINE,
        'time=2026-11-07T19:31:05.000+00:00 level=INFO msg="ServerCheckHandler: ok"',
        "",
    ]
)


def _run(tmp_path: Path, log_text: str | None, capsys) -> tuple[int, Path]:
    """Invoke the real CLI seam; return (exit code, artifact directory)."""
    directory = tmp_path / "e2e-diagnostics"
    argv = ["--validate-dir", str(directory)]
    if log_text is not None:
        log_path = tmp_path / "panel-operator.log"
        log_path.write_text(log_text, encoding="utf-8")
        argv += ["--probe-log", str(log_path)]
    code = diagnostics.main(argv)
    capsys.readouterr()
    return code, directory


# ── Positive evidence ────────────────────────────────────────────────


def test_failure_path_emits_bounded_probe_artifact(tmp_path: Path, capsys) -> None:
    code, directory = _run(tmp_path, LOG_WITH_PROBE, capsys)
    assert code == 0

    artifact = directory / "docker-probe.json"
    assert artifact.is_file(), "failed-probe evidence must be published"

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert set(payload) == {"schema_version", "source", "occurrences", "observations"}
    assert payload["source"] == diagnostics.PROBE_SOURCE
    assert payload["occurrences"] == 1

    assert payload["observations"] == [
        {
            "server_id": 1,
            "exit_code": 127,
            "transport_error": "",
            "stdout_state": "empty",
            "stdout_len": 0,
            "stderr_len": 42,
        }
    ]
    # The artifact is upload-safe by the module's own gate.
    assert diagnostics.validate_probe_report(payload) == []


def test_repeated_occurrences_are_grouped_and_counted(tmp_path: Path, capsys) -> None:
    log_text = "\n".join([PROBE_LINE, PROBE_LINE, PROBE_LINE])
    code, directory = _run(tmp_path, log_text, capsys)
    assert code == 0

    payload = json.loads((directory / "docker-probe.json").read_text(encoding="utf-8"))
    assert payload["occurrences"] == 3
    assert len(payload["observations"]) == 1, "identical lines must collapse to one observation"


def test_distinct_observations_are_kept_apart(tmp_path: Path, capsys) -> None:
    timeout_line = PROBE_LINE.replace("exit_code=127", "exit_code=-1").replace(
        "transport_error=", "transport_error=timeout"
    )
    code, directory = _run(tmp_path, "\n".join([PROBE_LINE, timeout_line]), capsys)
    assert code == 0

    payload = json.loads((directory / "docker-probe.json").read_text(encoding="utf-8"))
    assert payload["occurrences"] == 2
    assert len(payload["observations"]) == 2
    exit_codes = sorted(obs["exit_code"] for obs in payload["observations"])
    assert exit_codes == [-1, 127]


# ── Missing source / no evidence ─────────────────────────────────────


def test_clean_run_publishes_no_probe_artifact(tmp_path: Path, capsys) -> None:
    log_text = 'time=2026-11-07T19:31:05.000+00:00 level=INFO msg="all good"'
    code, directory = _run(tmp_path, log_text, capsys)
    assert code == 0
    assert not (directory / "docker-probe.json").exists(), (
        "a run without probe failures must not publish probe evidence"
    )


def test_absent_log_source_is_tolerated(tmp_path: Path, capsys) -> None:
    """A missing log must not fail the lifecycle nor fabricate evidence."""
    directory = tmp_path / "e2e-diagnostics"
    missing = tmp_path / "does-not-exist.log"
    code = diagnostics.main(["--validate-dir", str(directory), "--probe-log", str(missing)])
    capsys.readouterr()
    assert code == 0
    assert not (directory / "docker-probe.json").exists()


def test_no_probe_log_argument_preserves_previous_behaviour(tmp_path: Path, capsys) -> None:
    """Without --probe-log the gate behaves exactly as before this change."""
    directory = tmp_path / "e2e-diagnostics"
    code = diagnostics.main(["--validate-dir", str(directory)])
    capsys.readouterr()
    assert code == 0
    assert not directory.exists()


def test_unreadable_source_is_tolerated(tmp_path: Path, capsys) -> None:
    directory = tmp_path / "e2e-diagnostics"
    unreadable = tmp_path / "a-directory-not-a-file"
    unreadable.mkdir()  # read_text on a directory raises OSError
    code = diagnostics.main(["--validate-dir", str(directory), "--probe-log", str(unreadable)])
    out = capsys.readouterr().out
    assert code == 0
    assert "unreadable" in out
    assert not (directory / "docker-probe.json").exists()


def test_oversized_log_is_not_read(tmp_path: Path, capsys) -> None:
    """The byte bound must prevent unbounded reads, not merely truncate output."""
    directory = tmp_path / "e2e-diagnostics"
    log_path = tmp_path / "panel-operator.log"
    log_path.write_text(LOG_WITH_PROBE, encoding="utf-8")

    original = diagnostics.MAX_LOG_BYTES
    diagnostics.MAX_LOG_BYTES = 1
    try:
        # A file larger than the bound is skipped entirely; no artifact appears
        # and the gate still sees an empty directory.
        code = diagnostics.main(["--validate-dir", str(directory), "--probe-log", str(log_path)])
    finally:
        diagnostics.MAX_LOG_BYTES = original
    capsys.readouterr()
    assert code == 0
    assert not (directory / "docker-probe.json").exists()


def test_log_at_exactly_the_bound_is_accepted(tmp_path: Path, capsys) -> None:
    """The bound is inclusive: a log at the limit is still collected."""
    directory = tmp_path / "e2e-diagnostics"
    log_path = tmp_path / "panel-operator.log"
    log_path.write_text(LOG_WITH_PROBE, encoding="utf-8")
    size = log_path.stat().st_size

    original = diagnostics.MAX_LOG_BYTES
    diagnostics.MAX_LOG_BYTES = size
    try:
        code = diagnostics.main(["--validate-dir", str(directory), "--probe-log", str(log_path)])
    finally:
        diagnostics.MAX_LOG_BYTES = original
    capsys.readouterr()
    assert code == 0
    assert (directory / "docker-probe.json").is_file()


# ── Hostile input / privacy controls ─────────────────────────────────


HOSTILE_FIELDS = (
    'password=hunter2 passwd=letmein cookie=session%3Dabc token=eyJhbGciOi '
    'authorization="Bearer abc.def" secret=topsecret ip=10.9.8.7 '
    'host=internal-host.example.com user=ubuntu path=/home/ubuntu/.ssh/id_ed25519 '
    'url="https://panel.invalid/login?token=x" key="-----BEGIN OPENSSH PRIVATE KEY-----"'
)


def test_hostile_fields_on_probe_line_never_reach_artifact(tmp_path: Path, capsys) -> None:
    hostile_line = PROBE_LINE + " " + HOSTILE_FIELDS
    code, directory = _run(tmp_path, hostile_line, capsys)
    assert code == 0

    artifact = directory / "docker-probe.json"
    assert artifact.is_file()
    text = artifact.read_text(encoding="utf-8")

    for leaked in (
        "hunter2", "letmein", "eyJhbGciOi", "Bearer", "topsecret",
        "10.9.8.7", "internal-host", "ubuntu", "id_ed25519",
        "panel.invalid", "PRIVATE KEY", "OPENSSH", "password", "cookie",
        "token", "secret", "authorization",
    ):
        assert leaked not in text, f"artifact leaked {leaked!r}"

    # Only the allowlisted facts survive.
    payload = json.loads(text)
    assert set(payload) == {"schema_version", "source", "occurrences", "observations"}
    assert set(payload["observations"][0]) == {
        "server_id", "exit_code", "transport_error", "stdout_state", "stdout_len", "stderr_len"
    }


def test_unknown_logfmt_key_is_dropped(tmp_path: Path, capsys) -> None:
    line = PROBE_LINE + " unexpected_field=surprise-value"
    code, directory = _run(tmp_path, line, capsys)
    assert code == 0

    payload = json.loads((directory / "docker-probe.json").read_text(encoding="utf-8"))
    assert "surprise-value" not in json.dumps(payload)
    assert set(payload["observations"][0]) == {
        "server_id", "exit_code", "transport_error", "stdout_state", "stdout_len", "stderr_len"
    }


def test_out_of_schema_category_is_rejected_not_passed_through(tmp_path: Path, capsys) -> None:
    """A crafted category value must drop the line, never be published verbatim."""
    crafted = PROBE_LINE.replace("stdout_state=empty", "stdout_state=evil_payload")
    code, directory = _run(tmp_path, crafted, capsys)
    assert code == 0
    assert not (directory / "docker-probe.json").exists(), (
        "a line with a non-allowlisted category must not produce evidence"
    )
    assert "evil_payload" not in json.dumps(
        json.loads((directory / "docker-probe.json").read_text(encoding="utf-8"))
    ) if (directory / "docker-probe.json").exists() else True


def test_non_numeric_bounded_field_drops_line(tmp_path: Path, capsys) -> None:
    for field in ("exit_code", "stdout_len", "stderr_len", "server_id"):
        crafted = PROBE_LINE
        for existing in (f"{field}=127", f"{field}=0", f"{field}=42", f"{field}=1"):
            crafted = crafted.replace(existing, f'{field}="1; rm -rf /"')
        case_dir = tmp_path / field
        case_dir.mkdir()
        code, directory = _run(case_dir, crafted, capsys)
        assert code == 0, field
        assert not (directory / "docker-probe.json").exists(), (
            f"non-numeric {field} must drop the line, not publish it"
        )


def test_marker_without_fields_drops_line(tmp_path: Path, capsys) -> None:
    code, directory = _run(tmp_path, f'msg="{diagnostics.PROBE_LOG_MARKER}"', capsys)
    assert code == 0
    assert not (directory / "docker-probe.json").exists()


def test_hostile_line_never_printed_to_stdout(tmp_path: Path, capsys) -> None:
    """The console summary reports counts only — never log content."""
    hostile_line = PROBE_LINE + " " + HOSTILE_FIELDS
    directory = tmp_path / "e2e-diagnostics"
    log_path = tmp_path / "panel-operator.log"
    log_path.write_text(hostile_line, encoding="utf-8")
    diagnostics.main(["--validate-dir", str(directory), "--probe-log", str(log_path)])
    out = capsys.readouterr().out

    for leaked in ("hunter2", "10.9.8.7", "internal-host", "ubuntu", "PRIVATE KEY", "panel.invalid"):
        assert leaked not in out, f"stdout leaked {leaked!r}: {out}"


# ── Gate integration ─────────────────────────────────────────────────


def test_gate_accepts_probe_artifact_without_withholding(tmp_path: Path, capsys) -> None:
    """The probe artifact must not be mistaken for a version report by the gate."""
    code, directory = _run(tmp_path, LOG_WITH_PROBE, capsys)
    assert code == 0
    assert (directory / "docker-probe.json").is_file()

    # Re-running the gate alone (as finalize does) must keep the artifact.
    assert diagnostics.gate(directory) == 0
    assert (directory / "docker-probe.json").is_file()
    capsys.readouterr()


def test_gate_withholds_tampered_probe_artifact(tmp_path: Path, capsys) -> None:
    code, directory = _run(tmp_path, LOG_WITH_PROBE, capsys)
    assert code == 0

    artifact = directory / "docker-probe.json"
    tampered = json.loads(artifact.read_text(encoding="utf-8"))
    tampered["observations"][0]["stdout_state"] = "leaked /home/ubuntu/.ssh"
    artifact.write_text(json.dumps(tampered), encoding="utf-8")

    assert diagnostics.gate(directory) == 1
    assert not directory.exists(), "a tampered probe artifact must withhold the whole directory"


def test_probe_artifact_and_browser_payload_coexist(tmp_path: Path, capsys) -> None:
    """Both artifact kinds in one directory must both validate."""
    directory = tmp_path / "e2e-diagnostics"
    log_path = tmp_path / "panel-operator.log"
    log_path.write_text(LOG_WITH_PROBE, encoding="utf-8")

    browser_payload = {
        "schema_version": diagnostics.SCHEMA_VERSION,
        "test": "tests.e2e.test_onboard::test_x",
        "events": [],
        "dropped": 0,
        "browser": {"name": "chromium", "version": "141.0"},
    }
    assert diagnostics.write_failure_artifact(directory, browser_payload) is not None

    code = diagnostics.main(["--validate-dir", str(directory), "--probe-log", str(log_path)])
    capsys.readouterr()
    assert code == 0
    assert (directory / "docker-probe.json").is_file()
    assert len(list(directory.glob("*.json"))) == 2


def test_probe_report_rejects_unexpected_top_level_field() -> None:
    valid = diagnostics.parse_probe_log(LOG_WITH_PROBE)
    assert valid is not None
    for extra in ("raw_logs", "stderr", "host"):
        bad = dict(valid)
        bad[extra] = "x"
        assert diagnostics.validate_probe_report(bad) != [], extra


def test_parse_probe_log_returns_none_without_marker() -> None:
    assert diagnostics.parse_probe_log("") is None
    assert diagnostics.parse_probe_log('level=INFO msg="unrelated"') is None


def test_quoted_logfmt_values_are_unquoted_before_validation(tmp_path: Path, capsys) -> None:
    quoted = PROBE_LINE.replace("transport_error=", 'transport_error="timeout"')
    code, directory = _run(tmp_path, quoted, capsys)
    assert code == 0
    payload = json.loads((directory / "docker-probe.json").read_text(encoding="utf-8"))
    assert payload["observations"][0]["transport_error"] == "timeout"
