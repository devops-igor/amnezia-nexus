"""Offline tests for the AWG install-failure collector.

Every fixture is synthetic. The suite drives the real artifact seam used by the
lifecycle script (``main --validate-dir ... --install-failure-log ...``) rather
than a private helper, so a regression in flag wiring, gate routing or artifact
naming fails here.

Two properties are load-bearing and asserted throughout:

* **Causality is never guessed.** Only a prefix the producer actually emits maps
  to a named step; anything else is ``other``.
* **Nothing but the closed schema leaves.** A hostile log line — credentials,
  host names, paths, ids, stderr — can only produce an allowlisted record or
  nothing at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e import diagnostics, install_failure

# Synthetic markers that must never reach a console sink or an artifact.
SECRET_TOKEN = "ghp_" + "synthetic" * 4
PRIVATE_HOST = "panel.internal.example.invalid"
PRIVATE_KEY_PATH = "/etc/amnezia/private/client.key"
REMOTE_STDERR = "fatal: could not read from remote repository"


def failure_line(
    err: str = "failed to acquire remote server lock on resource iface_51820 (exit code 1): busy",
    *,
    server_id: str = "1",
    protocol: str = "awg",
    port: str | None = "51820",
    fields: str = "",
) -> str:
    """Build one logfmt line as the panel's text handler emits it."""
    port_field = "" if port is None else f" port={port}"
    return (
        "time=2026-11-10T04:05:55.000+00:00 level=ERROR "
        f'msg="protocol install failed" server_id={server_id} protocol={protocol}'
        f"{port_field} err={json.dumps(err)}{fields}"
    )


def operator_log(*lines: str) -> str:
    """Return a synthetic operator log with unrelated noise around the marker."""
    return "\n".join(
        [
            'time=2026-11-10T04:05:50.000+00:00 level=INFO msg="Starting Amnezia Web Panel" port=8000',
            'time=2026-11-10T04:05:54.000+00:00 level=INFO msg="ServerCheckHandler: ok" server_id=1',
            *lines,
            'time=2026-11-10T04:05:56.000+00:00 level=INFO msg="shutting down"',
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
        argv += ["--install-failure-log", str(log_path)]
    code = diagnostics.main(argv)
    capsys.readouterr()
    return code, directory


# ── Positive evidence: the failing lifecycle path ────────────────────


def test_install_failure_emits_bounded_artifact(tmp_path: Path, capsys) -> None:
    """A real install-failure line becomes one allowlisted record."""
    code, directory = run_collector(tmp_path, operator_log(failure_line()), capsys)
    assert code == 0

    artifact = directory / "install-failure.json"
    assert artifact.is_file(), "install-failure evidence must be published"

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert set(payload) == {"schema_version", "source", "occurrences", "failures"}
    assert payload["schema_version"] == diagnostics.SCHEMA_VERSION
    assert payload["source"] == "protocol-install-failure-log"
    assert payload["occurrences"] == 1
    assert payload["failures"] == [
        {
            "server_id": 1,
            "protocol": "awg",
            "port": 51820,
            "step": "lock_acquire",
            "reason": "other",
            "exit_code": 1,
            "duration_ms": -1,
        }
    ]


@pytest.mark.parametrize(
    ("err", "step"),
    [
        ("failed to acquire remote server lock on resource x (exit code 1): busy", "lock_acquire"),
        ("failed to generate AWG params: bad profile", "awg_params"),
        ("failed to prepare host: dial tcp: timeout", "prepare_host"),
        (
            "UDP port 51820 is already in use on the server — choose a different port "
            "for the AWG backend",
            "udp_port_in_use",
        ),
        ("failed to upload Dockerfile: sftp: permission denied", "dockerfile_upload"),
        ("failed to pull AWG base image img:v1 (code 1): denied, exit status 1", "image_pull"),
        ("failed to build amnezia-awg2 image (code 1): apk failed, exit status 1", "image_build"),
        ("failed to run container (code 125): port is already allocated", "container_run"),
        ("pool failed to dial server:1:host:22:ubuntu: ssh: handshake failed", "ssh_client"),
        ("ssh pool is not configured", "ssh_client"),
        ("something else entirely", "other"),
        ("", "other"),
    ],
)
def test_step_classification_is_closed(err: str, step: str) -> None:
    """Only producer prefixes name a step; everything else is "other"."""
    assert install_failure.classify_step(err) == step
    assert step in install_failure.STEPS


@pytest.mark.parametrize(
    ("err", "exit_code"),
    [
        ("failed to run container (code 125): denied", 125),
        ("failed to build x image (exit code 2): apk failed", 2),
        ("failed to acquire remote server lock on resource x (exit code 1): busy", 1),
        ("failed to generate AWG params: bad profile", -1),
        ("failed to prepare host: (code notanumber)", -1),
    ],
)
def test_exit_code_is_bounded_and_optional(err: str, exit_code: int) -> None:
    """The stated exit status is recorded as a bounded integer, else -1."""
    payload = install_failure.parse_install_failure_log(operator_log(failure_line(err)))
    assert payload is not None
    assert payload["failures"][0]["exit_code"] == exit_code


def test_repeated_identical_failures_are_counted_not_duplicated(tmp_path: Path, capsys) -> None:
    """Identical failures collapse to one record with a distinct count."""
    log = operator_log(failure_line(), failure_line(), failure_line("failed to build x image"))
    code, directory = run_collector(tmp_path, log, capsys)
    assert code == 0

    payload = json.loads((directory / "install-failure.json").read_text(encoding="utf-8"))
    assert payload["occurrences"] == 3
    assert len(payload["failures"]) == 2
    counts = sorted(f["step"] for f in payload["failures"])
    assert counts == ["image_build", "lock_acquire"]


def test_protocol_aliases_normalise_to_the_canonical_name() -> None:
    """Legacy protocol spellings recorded in the log are reduced to one name."""
    for alias in ("awg2", "awg_legacy"):
        payload = install_failure.parse_install_failure_log(
            operator_log(failure_line(protocol=alias))
        )
        assert payload is not None
        assert payload["failures"][0]["protocol"] == "awg"


# ── Reason: the cause inside the phase, still closed ────────────────


@pytest.mark.parametrize(
    ("err", "reason"),
    [
        (
            "failed to build caddy image (code 1): Get "
            '"https://proxy.golang.org/github.com/caddyserver/forwardproxy/@v/caddy2.info": '
            "dial tcp 10.0.0.1:443: i/o timeout: exit status 1",
            "network_timeout",
        ),
        (
            'failed to build caddy image (code 1): go.mod:5: replace '
            'github.com/caddyserver/forwardproxy: version "caddy2" invalid: unknown revision '
            "caddy2: exit status 1",
            "module_resolution",
        ),
        (
            "failed to pull AWG base image amneziawg:local (code 1): toomanyrequests: "
            "You have reached your pull rate limit",
            "registry_rate_limit",
        ),
        (
            "failed to pull AWG base image img:v1 (code 1): pull access denied for img, "
            "repository does not exist",
            "registry_denied",
        ),
        (
            "failed to pull AWG base image img:v1 (code 1): manifest unknown: manifest unknown",
            "image_not_found",
        ),
        (
            "failed to build caddy image (code 1): write /var/lib/docker/tmp/x: "
            "no space left on device",
            "disk_full",
        ),
        ("failed to upload Dockerfile: sftp: permission denied", "permission_denied"),
        (
            "failed to build caddy image (code -1): : context canceled",
            "caller_cancel",
        ),
        (
            "failed to run container (code 125): cannot connect to the Docker daemon at "
            "unix:///var/run/docker.sock. Is the docker daemon running?",
            "docker_unavailable",
        ),
        (
            "failed to build caddy image (code 1): a failure nobody has seen before",
            "other",
        ),
    ],
)
def test_reason_classification_is_closed(err: str, reason: str) -> None:
    """A producer subprocess cause maps to one allowlisted reason, else "other"."""
    assert install_failure.classify_reason(err) == reason
    assert reason in install_failure.REASONS


def test_reason_is_not_guessed_outside_a_subprocess_step() -> None:
    """Text that merely looks like a cause is not labelled outside build/pull/run."""
    err = "failed to acquire remote server lock on resource x (exit code 1): i/o timeout"
    assert install_failure.classify_step(err) == "lock_acquire"
    assert install_failure.classify_reason(err) == "other"


def test_artifact_records_the_build_reason(tmp_path: Path, capsys) -> None:
    """The retained artifact explains why the build failed, not only that it did."""
    err = (
        "failed to build caddy image (code 1): Get "
        '"https://proxy.golang.org/x/@v/caddy2.info": dial tcp 10.0.0.1:443: '
        "i/o timeout: exit status 1"
    )
    code, directory = run_collector(tmp_path, operator_log(failure_line(err)), capsys)
    assert code == 0

    payload = json.loads((directory / "install-failure.json").read_text(encoding="utf-8"))
    assert payload["failures"][0]["step"] == "image_build"
    assert payload["failures"][0]["reason"] == "network_timeout"


def test_same_step_with_different_reason_is_a_distinct_failure() -> None:
    """Two builds that failed for different causes are not merged into one record."""
    payload = install_failure.parse_install_failure_log(
        operator_log(
            failure_line("failed to build caddy image (code 1): dial tcp: i/o timeout"),
            failure_line("failed to build caddy image (code 1): unknown revision caddy2"),
        )
    )
    assert payload is not None
    assert payload["occurrences"] == 2
    assert sorted(f["reason"] for f in payload["failures"]) == [
        "module_resolution",
        "network_timeout",
    ]


# ── Duration: separate a slow attempt from a fast failure ───────────


def test_duration_is_recorded_when_the_producer_states_it() -> None:
    """A handler that states how long the install ran is recorded as given."""
    payload = install_failure.parse_install_failure_log(
        operator_log(failure_line(fields=" duration_ms=4321"))
    )
    assert payload is not None
    assert payload["failures"][0]["duration_ms"] == 4321


def test_duration_is_not_stated_by_default() -> None:
    """An older handler that logs no duration is not credited with one."""
    payload = install_failure.parse_install_failure_log(operator_log(failure_line()))
    assert payload is not None
    assert payload["failures"][0]["duration_ms"] == -1


@pytest.mark.parametrize(
    "value",
    ["fast", "-5", str(install_failure.MAX_INSTALL_DURATION_MS + 1), "1.5"],
)
def test_unusable_duration_rejects_the_whole_line(value: str) -> None:
    """A malformed duration is corruption, not evidence, and drops the line."""
    line = failure_line(fields=f" duration_ms={value}")
    assert install_failure.parse_install_failure_log(operator_log(line)) is None


def test_repeated_failures_keep_the_longest_observed_duration() -> None:
    """Deduplication keeps the slowest attempt so a timeout stays visible."""
    payload = install_failure.parse_install_failure_log(
        operator_log(
            failure_line(fields=" duration_ms=1000"),
            failure_line(fields=" duration_ms=9000"),
        )
    )
    assert payload is not None
    assert payload["occurrences"] == 2
    assert len(payload["failures"]) == 1
    assert payload["failures"][0]["duration_ms"] == 9000


# ── Absence must not read as success, and a clean run stays silent ───


def test_missing_install_failure_line_writes_no_artifact(tmp_path: Path, capsys) -> None:
    """A log without the marker yields no artifact and no failure claim."""
    code, directory = run_collector(
        tmp_path,
        operator_log('time=2026-11-10T04:05:55Z level=INFO msg="ServerCheckHandler: ok"'),
        capsys,
    )
    assert code == 0
    assert not (directory / "install-failure.json").exists()


def test_clean_install_emits_no_misleading_failure_artifact(tmp_path: Path, capsys) -> None:
    """A successful install produces no failure evidence and no stdout claim."""
    log_path = tmp_path / "panel-operator.log"
    log_path.write_text(operator_log(), encoding="utf-8")
    directory = tmp_path / "e2e-diagnostics"

    code = diagnostics.main(
        ["--validate-dir", str(directory), "--install-failure-log", str(log_path)]
    )
    assert code == 0
    assert not (directory / "install-failure.json").exists()

    emitted = capsys.readouterr()
    assert "0 failed-install line(s)" in emitted.out + emitted.err


def test_absent_log_is_tolerated(tmp_path: Path, capsys) -> None:
    """A lifecycle run with no operator log collects nothing and stays green."""
    directory = tmp_path / "e2e-diagnostics"
    missing = tmp_path / "missing.log"
    code = diagnostics.main(
        ["--validate-dir", str(directory), "--install-failure-log", str(missing)]
    )
    capsys.readouterr()
    assert code == 0
    assert not (directory / "install-failure.json").exists()


# ── Hostile logs: nothing but the closed schema leaves ──────────────


def test_error_text_and_remote_output_never_reach_the_artifact(tmp_path: Path, capsys) -> None:
    """Credentials, host names, paths and stderr in err= are never published."""
    hostile = (
        "failed to build amnezia-awg2 image (code 1): "
        f"cannot pull {SECRET_TOKEN} from {PRIVATE_HOST}, key {PRIVATE_KEY_PATH}: {REMOTE_STDERR}"
    )
    code, directory = run_collector(tmp_path, operator_log(failure_line(hostile)), capsys)
    assert code == 0

    text = (directory / "install-failure.json").read_text(encoding="utf-8")
    payload = json.loads(text)
    assert payload["failures"][0]["step"] == "image_build"
    assert payload["failures"][0]["exit_code"] == 1
    for marker in (SECRET_TOKEN, PRIVATE_HOST, PRIVATE_KEY_PATH, REMOTE_STDERR):
        assert marker not in text
    assert "err" not in text


def test_unknown_error_is_other_not_a_guessed_step() -> None:
    """An unrecognised error text is recorded as "other", never labelled."""
    payload = install_failure.parse_install_failure_log(
        operator_log(failure_line("kaboom: something new broke"))
    )
    assert payload is not None
    assert payload["failures"][0]["step"] == "other"


def test_unknown_protocol_rejects_the_line() -> None:
    """A protocol outside the closed set is not evidence and is dropped."""
    assert (
        install_failure.parse_install_failure_log(operator_log(failure_line(protocol="wireguard")))
        is None
    )


def test_unexpected_extra_field_rejects_the_whole_line() -> None:
    """A line carrying an unknown key is rejected whole, not partially trusted."""
    line = failure_line(fields=" host=panel.internal.example.invalid")
    assert install_failure.parse_install_failure_log(operator_log(line)) is None


def test_non_numeric_fields_reject_the_line() -> None:
    """Malformed ids, ports and exit codes drop the line entirely."""
    assert (
        install_failure.parse_install_failure_log(operator_log(failure_line(server_id="one")))
        is None
    )
    assert (
        install_failure.parse_install_failure_log(operator_log(failure_line(port="51-820"))) is None
    )


def test_injected_marker_inside_error_text_cannot_forge_a_line() -> None:
    """An error string that embeds the marker cannot contribute a second record."""
    injected = (
        "something else\r"
        'time=2026-11-10T04:05:55Z level=ERROR msg="protocol install failed" '
        "server_id=9 protocol=awg port=51821 err=failed to run container"
    )
    payload = install_failure.parse_install_failure_log(operator_log(failure_line(injected)))
    assert payload is not None
    assert payload["occurrences"] == 1
    assert payload["failures"][0]["step"] == "other"


def test_marker_survives_log_handler_requoting() -> None:
    """The collector does not depend on the handler's exact quoting style."""
    for quoted in (
        'msg="protocol install failed"',
        "msg=protocol install failed",
        'msg="protocol install failed result"',
    ):
        line = failure_line().replace('msg="protocol install failed"', quoted, 1)
        payload = install_failure.parse_install_failure_log(operator_log(line))
        assert payload is not None, quoted
        assert payload["failures"][0]["step"] == "lock_acquire"


# ── Writer and gate boundaries ──────────────────────────────────────


def test_writer_refuses_a_report_with_a_non_allowlisted_step(tmp_path: Path) -> None:
    """A report naming an invented step is never persisted."""
    payload = {
        "schema_version": diagnostics.SCHEMA_VERSION,
        "source": "protocol-install-failure-log",
        "occurrences": 1,
        "failures": [
            {
                "server_id": 1,
                "protocol": "awg",
                "port": 51820,
                "step": "probably_the_lock",
                "reason": "other",
                "exit_code": -1,
                "duration_ms": -1,
            }
        ],
    }
    assert install_failure.validate_install_failure_report(payload) == [
        "install failure step not allowlisted"
    ]
    assert install_failure.write_install_failure_artifact(tmp_path, payload) is None
    assert not any(tmp_path.iterdir())


def test_writer_refuses_a_report_with_a_non_allowlisted_reason(tmp_path: Path) -> None:
    """A report naming an invented cause is never persisted."""
    payload = {
        "schema_version": diagnostics.SCHEMA_VERSION,
        "source": "protocol-install-failure-log",
        "occurrences": 1,
        "failures": [
            {
                "server_id": 1,
                "protocol": "naive",
                "port": 9443,
                "step": "image_build",
                "reason": "because_the_network_was_grumpy",
                "exit_code": 1,
                "duration_ms": -1,
            }
        ],
    }
    assert install_failure.validate_install_failure_report(payload) == [
        "install failure reason not allowlisted"
    ]
    assert install_failure.write_install_failure_artifact(tmp_path, payload) is None
    assert not any(tmp_path.iterdir())


def test_writer_refuses_a_report_with_an_unbounded_duration(tmp_path: Path) -> None:
    """A duration longer than the install budget is refused, not published."""
    payload = {
        "schema_version": diagnostics.SCHEMA_VERSION,
        "source": "protocol-install-failure-log",
        "occurrences": 1,
        "failures": [
            {
                "server_id": 1,
                "protocol": "naive",
                "port": 9443,
                "step": "image_build",
                "reason": "network_timeout",
                "exit_code": 1,
                "duration_ms": install_failure.MAX_INSTALL_DURATION_MS + 1,
            }
        ],
    }
    assert install_failure.validate_install_failure_report(payload) == [
        "install failure duration_ms not bounded"
    ]
    assert install_failure.write_install_failure_artifact(tmp_path, payload) is None
    assert not any(tmp_path.iterdir())


def test_writer_refuses_report_carrying_a_raw_error_string(tmp_path: Path) -> None:
    """An artifact that somehow carries err text is refused at the writer."""
    payload = install_failure.parse_install_failure_log(operator_log(failure_line()))
    assert payload is not None
    payload["err"] = f"{SECRET_TOKEN} {PRIVATE_HOST}"
    assert install_failure.write_install_failure_artifact(tmp_path, payload) is None


def test_gate_routes_install_failure_artifacts_to_its_own_validator(tmp_path: Path) -> None:
    """A malformed install-failure artifact withholds the whole directory."""
    directory = tmp_path / "e2e-diagnostics"
    directory.mkdir()
    (directory / "install-failure.json").write_text(
        json.dumps({"schema_version": 1, "source": "protocol-install-failure-log", "failures": []}),
        encoding="utf-8",
    )
    assert diagnostics.main(["--validate-dir", str(directory)]) == 1
    assert not directory.exists()


def test_gate_keeps_a_valid_install_failure_artifact(tmp_path: Path, capsys) -> None:
    """A validated install-failure artifact survives the pre-upload gate."""
    code, directory = run_collector(tmp_path, operator_log(failure_line()), capsys)
    assert code == 0
    assert (directory / "install-failure.json").is_file()
    assert diagnostics.main(["--validate-dir", str(directory)]) == 0
    assert (directory / "install-failure.json").is_file()


# ── Wiring: the lifecycle finalizer must actually collect this ───────


def test_lifecycle_finalizer_passes_the_install_failure_flag() -> None:
    """Both operator-log sources must hand the collector the same log."""
    repo_root = Path(__file__).resolve().parents[1]
    script = (repo_root / "scripts" / "run_e2e_lifecycle.sh").read_text(encoding="utf-8")
    assert "--install-failure-log" in script
    assert (
        script.count("--install-failure-log") == 2
    ), "both E2E_PANEL_LOG_CONTAINER and E2E_PANEL_LOG_PATH must wire the collector"
