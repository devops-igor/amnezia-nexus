"""Offline tests for the client-creation failure collector (issue #744).

Every fixture is synthetic. The suite drives the real artifact seam used by the
lifecycle script (``main --validate-dir ... --add-client-failure-log ...``)
rather than a private helper, so a regression in flag wiring, gate routing or
artifact naming fails here.

Two properties are load-bearing and asserted throughout:

* **The cause is never guessed.** Only a wrapper the producer actually emits maps
  to a named step; anything else is ``other``.
* **Nothing but the closed schema leaves.** A hostile log line -- credentials,
  host names, paths, ids, stderr -- can only produce an allowlisted record or
  nothing at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e import add_client_failure, diagnostics

# Synthetic markers that must never reach a console sink or an artifact.
SECRET_TOKEN = "ghp_" + "synthetic" * 4
PRIVATE_HOST = "panel.internal.example.invalid"
PRIVATE_KEY_PATH = "/opt/amnezia/private/client.key"
REMOTE_STDERR = "fatal: could not read from remote repository"


def failure_line(
    err: str = "failed to save clients table: database is locked",
    *,
    server_id: str = "1",
    protocol: str = "awg",
    fields: str = "",
) -> str:
    """Build one logfmt line as the panel's text handler emits it."""
    return (
        "time=2026-11-14T09:15:55.000+00:00 level=ERROR "
        f'msg="failed to add client" server_id={server_id} protocol={protocol} '
        f"error={json.dumps(err)}{fields}"
    )


def operator_log(*lines: str) -> str:
    """Return a synthetic operator log with unrelated noise around the marker."""
    return "\n".join(
        [
            'time=2026-11-14T09:15:50.000+00:00 level=INFO msg="Starting Amnezia Web Panel" port=8000',
            'time=2026-11-14T09:15:54.000+00:00 level=INFO msg="ServerCheckHandler: ok" server_id=1',
            *lines,
            'time=2026-11-14T09:15:56.000+00:00 level=INFO msg="shutting down"',
            "",
        ]
    )


def run_collector(tmp_path: Path, log_text: str | None, capsys) -> tuple[int, Path]:
    """Invoke the real CLI seam; return (exit code, artifact directory)."""
    directory = tmp_path / "e2e-diagnostics"
    argv = ["--validate-dir", str(directory)]
    if log_text is not None:
        log_path = tmp_path / "panel-operator.log"
        log_path.write_text(log_text, encoding="utf-8")
        argv += ["--add-client-failure-log", str(log_path)]
    code = diagnostics.main(argv)
    capsys.readouterr()
    return code, directory


# ── Positive evidence: the failing lifecycle path ────────────────────


def test_add_client_failure_emits_bounded_artifact(tmp_path: Path, capsys) -> None:
    """A real client-creation failure line becomes one allowlisted record."""
    code, directory = run_collector(tmp_path, operator_log(failure_line()), capsys)
    assert code == 0

    artifact = directory / "add-client-failure.json"
    assert artifact.is_file(), "client-creation evidence must be published"

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert set(payload) == {"schema_version", "source", "occurrences", "add_client_failures"}
    assert payload["schema_version"] == diagnostics.SCHEMA_VERSION
    assert payload["source"] == "client-creation-failure-log"
    assert payload["occurrences"] == 1
    assert payload["add_client_failures"] == [
        {
            "server_id": 1,
            "protocol": "awg",
            "step": "clients_table_save",
            "occurrences": 1,
        }
    ]


def test_gate_routes_the_new_artifact_to_its_own_validator(
    tmp_path: Path, capsys
) -> None:
    """A valid report survives the pre-upload gate.

    The gate's catch-all validator rejects any key set it does not know, so a
    green gate over this artifact is what proves the dispatch branch exists and
    runs the closed-schema validator instead of ``validate_versions``.
    """
    code, directory = run_collector(tmp_path, operator_log(failure_line()), capsys)
    assert code == 0

    gate = diagnostics.main(["--validate-dir", str(directory)])
    capsys.readouterr()
    assert gate == 0
    assert (directory / "add-client-failure.json").is_file()


@pytest.mark.parametrize(
    ("err", "step"),
    [
        ("failed to acquire remote server lock: busy", "remote_lock"),
        ("failed to generate client keypair: entropy exhausted", "client_keys"),
        ("failed to get AmneziaWG server public key: empty", "server_key"),
        ("failed to read clientsTable: exit status 1", "clients_table_read"),
        ("failed to allocate non-conflicting IP on server 1", "ip_alloc"),
        ("failed to adopt AWG client IP lease: stale", "ip_alloc"),
        ("failed to ensure backend NAT rules: iptables missing", "nat_rules"),
        ("failed to save clients table: database is locked", "clients_table_save"),
        ("failed to upsert peer in config: sftp write failed", "config_upsert"),
        ("failed to fetch remote config for CAS check: EOF", "config_conflict"),
        ("failed to commit remote config: CAS retry limit exceeded", "config_conflict"),
        ("failed to get server config from containers: amnezia-awg2", "server_config_read"),
        ("download xray config: permission denied", "config_read"),
        ("parse xray config: unexpected EOF", "config_parse"),
        ("add client to xray config: duplicate id", "config_upsert"),
        ("derive reality public key: bad key", "reality_key"),
        ("download Caddyfile: no such file", "config_read"),
        ("generate credentials: rand failed", "credentials"),
        ("add client to Caddyfile: parse error", "config_upsert"),
        ("validate updated Caddyfile: exit status 1", "config_validate"),
        ("failed to reload caddy container (code 1): denied", "container_restart"),
        ("pool failed to dial server:1:host:22:ubuntu: ssh: handshake failed", "ssh_client"),
        ("ssh pool is not configured", "ssh_client"),
        ("something else entirely", "other"),
        ("", "other"),
    ],
)
def test_step_classification_is_closed(err: str, step: str) -> None:
    """Only producer wrappers name a step; everything else is ``other``."""
    assert add_client_failure.classify_step(err) == step
    assert step in add_client_failure.STEPS


def test_repeated_identical_failures_are_counted_not_duplicated(
    tmp_path: Path, capsys
) -> None:
    """Identical failures collapse to one record with a distinct count."""
    log = operator_log(
        failure_line(),
        failure_line(),
        failure_line("failed to acquire remote server lock: busy"),
    )
    code, directory = run_collector(tmp_path, log, capsys)
    assert code == 0

    payload = json.loads((directory / "add-client-failure.json").read_text(encoding="utf-8"))
    assert payload["occurrences"] == 3
    assert len(payload["add_client_failures"]) == 2
    assert sorted(
        (f["step"], f["occurrences"]) for f in payload["add_client_failures"]
    ) == [("clients_table_save", 2), ("remote_lock", 1)]


def test_protocol_aliases_normalise_to_the_canonical_name() -> None:
    """Legacy protocol spellings recorded in the log are reduced to one name."""
    for alias in ("awg2", "awg_legacy"):
        payload = add_client_failure.parse_add_client_failure_log(
            operator_log(failure_line(protocol=alias))
        )
        assert payload is not None
        assert payload["add_client_failures"][0]["protocol"] == "awg"


# ── Absence must not read as success, and a clean run stays silent ───


def test_missing_failure_line_writes_no_artifact(tmp_path: Path, capsys) -> None:
    """A log without the marker yields no artifact and no failure claim."""
    code, directory = run_collector(
        tmp_path,
        operator_log('time=2026-11-14T09:15:55Z level=INFO msg="ServerCheckHandler: ok"'),
        capsys,
    )
    assert code == 0
    assert not (directory / "add-client-failure.json").exists()


def test_clean_lifecycle_emits_no_misleading_failure_artifact(
    tmp_path: Path, capsys
) -> None:
    """A successful run produces no failure evidence and no stdout claim."""
    log_path = tmp_path / "panel-operator.log"
    log_path.write_text(operator_log(), encoding="utf-8")
    directory = tmp_path / "e2e-diagnostics"

    code = diagnostics.main(
        ["--validate-dir", str(directory), "--add-client-failure-log", str(log_path)]
    )
    assert code == 0
    assert not (directory / "add-client-failure.json").exists()

    emitted = capsys.readouterr()
    assert "0 failed-request line(s)" in emitted.out + emitted.err


def test_absent_log_is_tolerated(tmp_path: Path, capsys) -> None:
    """A lifecycle run with no operator log collects nothing and stays green."""
    directory = tmp_path / "e2e-diagnostics"
    code = diagnostics.main(
        [
            "--validate-dir",
            str(directory),
            "--add-client-failure-log",
            str(tmp_path / "missing.log"),
        ]
    )
    capsys.readouterr()
    assert code == 0
    assert not (directory / "add-client-failure.json").exists()


# ── Hostile logs: nothing but the closed schema leaves ──────────────


def test_error_text_and_remote_output_never_reach_the_artifact(
    tmp_path: Path, capsys
) -> None:
    """Credentials, host names, paths and stderr in error= are never published."""
    hostile = (
        "failed to upsert peer in config: "
        f"ssh {PRIVATE_HOST} with {SECRET_TOKEN} key {PRIVATE_KEY_PATH}: {REMOTE_STDERR}"
    )
    code, directory = run_collector(tmp_path, operator_log(failure_line(hostile)), capsys)
    assert code == 0

    text = (directory / "add-client-failure.json").read_text(encoding="utf-8")
    payload = json.loads(text)
    assert payload["add_client_failures"][0]["step"] == "config_upsert"
    for marker in (SECRET_TOKEN, PRIVATE_HOST, PRIVATE_KEY_PATH, REMOTE_STDERR):
        assert marker not in text
    assert "error" not in text


def test_unknown_error_is_other_not_a_guessed_step() -> None:
    """An unrecognised error text is recorded as ``other``, never labelled."""
    payload = add_client_failure.parse_add_client_failure_log(
        operator_log(failure_line("kaboom: something new broke"))
    )
    assert payload is not None
    assert payload["add_client_failures"][0]["step"] == "other"


def test_unknown_protocol_rejects_the_line() -> None:
    """A protocol outside the closed set is not evidence and is dropped."""
    assert (
        add_client_failure.parse_add_client_failure_log(
            operator_log(failure_line(protocol="wireguard"))
        )
        is None
    )


def test_unexpected_extra_field_rejects_the_whole_line() -> None:
    """A line carrying an unknown key is rejected whole, not partially trusted."""
    line = failure_line(fields=" user_id=42")
    assert add_client_failure.parse_add_client_failure_log(operator_log(line)) is None


def test_non_numeric_server_id_rejects_the_line() -> None:
    """A malformed id drops the line entirely."""
    assert (
        add_client_failure.parse_add_client_failure_log(
            operator_log(failure_line(server_id="one"))
        )
        is None
    )


def test_injected_marker_inside_error_text_cannot_forge_a_line() -> None:
    """An error string that embeds the marker cannot contribute a second record."""
    injected = (
        "something else\r"
        'time=2026-11-14T09:15:55Z level=ERROR msg="failed to add client" '
        "server_id=9 protocol=awg error=failed to save clients table"
    )
    payload = add_client_failure.parse_add_client_failure_log(
        operator_log(failure_line(injected))
    )
    assert payload is not None
    assert payload["occurrences"] == 1
    assert payload["add_client_failures"][0]["step"] == "other"


def test_marker_survives_log_handler_requoting() -> None:
    """The collector does not depend on the handler's exact quoting style."""
    for quoted in (
        'msg="failed to add client"',
        "msg=failed to add client",
        'msg="failed to add client; masked for the client"',
    ):
        line = failure_line().replace('msg="failed to add client"', quoted, 1)
        payload = add_client_failure.parse_add_client_failure_log(operator_log(line))
        assert payload is not None, quoted
        assert payload["add_client_failures"][0]["step"] == "clients_table_save"


# ── Writer and gate boundaries ──────────────────────────────────────


def _report(step: str = "clients_table_save") -> dict:
    return {
        "schema_version": diagnostics.SCHEMA_VERSION,
        "source": "client-creation-failure-log",
        "occurrences": 1,
        "add_client_failures": [
            {"server_id": 1, "protocol": "awg", "step": step, "occurrences": 1}
        ],
    }


def test_writer_refuses_a_report_with_a_non_allowlisted_step(tmp_path: Path) -> None:
    """A report naming an invented step is never persisted."""
    payload = _report(step="probably_the_database")
    assert add_client_failure.validate_add_client_failure_report(payload) == [
        "client-creation failure step not allowlisted"
    ]
    assert add_client_failure.write_add_client_failure_artifact(tmp_path, payload) is None
    assert not any(tmp_path.iterdir())


def test_writer_refuses_a_report_with_an_unexpected_key(tmp_path: Path) -> None:
    """A report carrying an extra field is refused whole."""
    payload = _report()
    payload["add_client_failures"][0]["error"] = "leaked cause"
    assert add_client_failure.validate_add_client_failure_report(payload) == [
        "client-creation failure keys are not the allowlisted set"
    ]
    assert add_client_failure.write_add_client_failure_artifact(tmp_path, payload) is None


def test_gate_withholds_a_tampered_report(tmp_path: Path) -> None:
    """A tampered artifact withholds the whole evidence directory."""
    directory = tmp_path / "e2e-diagnostics"
    directory.mkdir()
    payload = _report(step="invented")
    (directory / "add-client-failure.json").write_text(json.dumps(payload), encoding="utf-8")

    assert diagnostics.main(["--validate-dir", str(directory)]) == 1
    assert not directory.exists()
