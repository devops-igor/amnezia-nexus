"""End-to-end proof of the finalizer -> collector -> artifact retention slice.

Runs the REAL ``scripts/run_e2e_lifecycle.sh`` with a stub ``docker`` binary and a
stub ``pytest`` on PATH, so the actual ``finalize()`` shell path executes:

  docker logs <container>   -> synthetic operator log with one install failure
  python3 -m tests.e2e.diagnostics --validate-dir ... --probe-log ...
      --call-timing-log ... --install-failure-log ...
  rm -f <temp log>          -> raw log destroyed
  exit $OVERALL_STATUS      -> original nonzero lifecycle result preserved

Both the failure slice and the clean (positive) slice run against the same real
script. Nothing here contacts a host, container, provider or network.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "run_e2e_lifecycle.sh"

SECRET_TOKEN = "ghp_" + "synthetic" * 4
PRIVATE_HOST = "panel.internal.example.invalid"
REMOTE_STDERR = "bash: line 1: docker: not found"

# The exact slog text-handler line internal/handlers/servers.go emits, with the
# real AWG error wrapper from internal/manager/awg/awg_lock.go.
FAILURE_LOG = "\n".join(
    [
        'time=2026-11-10T04:05:50.000+00:00 level=INFO msg="Starting Amnezia Web Panel"',
        'time=2026-11-10T04:05:54.000+00:00 level=INFO msg="ServerCheckHandler: ok" server_id=1',
        'time=2026-11-10T04:05:55.000+00:00 level=ERROR msg="protocol install failed" '
        "server_id=1 protocol=awg port=51820 "
        'err="failed to build amnezia-awg2 image (code 1): '
        f'pull {SECRET_TOKEN} from {PRIVATE_HOST} denied: {REMOTE_STDERR}"',
        'time=2026-11-10T04:05:56.000+00:00 level=INFO msg="shutting down"',
        "",
    ]
)
CLEAN_LOG = "\n".join(
    [
        'time=2026-11-10T04:05:50.000+00:00 level=INFO msg="Starting Amnezia Web Panel"',
        'time=2026-11-10T04:05:54.000+00:00 level=INFO msg="ServerCheckHandler: ok" server_id=1',
        'time=2026-11-10T04:05:55.000+00:00 level=INFO msg="protocol install complete" '
        "server_id=1 protocol=awg",
        "",
    ]
)


def _write_stub(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def run_lifecycle(
    tmp_path: Path, log_text: str, stage2_passes: bool, docker_logs_ok: bool = True
) -> subprocess.CompletedProcess:
    """Execute the real lifecycle script against stubbed external binaries."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log_file = tmp_path / "container.log"
    log_file.write_text(log_text, encoding="utf-8")

    # `docker logs <container>` prints the captured operator log, or fails.
    logs_body = f'cat "{log_file}"' if docker_logs_ok else "exit 1"
    _write_stub(
        bindir / "docker",
        f"""\
        #!/bin/sh
        case "$1" in
          logs) {logs_body} ;;
          *) exit 0 ;;
        esac
        """,
    )
    # Stage 1 passes; Stage 2 fails on the failure slice and passes on the clean one.
    stage1_rc, stage2_rc = 0, 0 if stage2_passes else 1
    _write_stub(
        bindir / "pytest",
        f"""\
        #!/bin/sh
        for arg in "$@"; do
          case "$arg" in
            *test_setup.py) echo "stage1=pass"; exit {stage1_rc} ;;
            *test_onboard.py) echo "stage2"; exit {stage2_rc} ;;
          esac
        done
        exit 0
        """,
    )
    _write_stub(bindir / "curl", "#!/bin/sh\nexit 0\n")

    diagnostics_dir = tmp_path / "e2e-diagnostics"
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "E2E_DIAGNOSTICS_DIR": str(diagnostics_dir),
        "E2E_PANEL_LOG_CONTAINER": "amnezia-panel",
        "TMPDIR": str(tmp_path),
    }
    return subprocess.run(
        [str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=120,
        check=False,
    )


def test_failing_lifecycle_retains_category_and_preserves_nonzero_result(
    tmp_path: Path,
) -> None:
    """The real finalizer keeps the safe category and the original exit status."""
    result = run_lifecycle(tmp_path, FAILURE_LOG, stage2_passes=False)

    # 1. The original nonzero lifecycle result is preserved, not masked.
    assert result.returncode == 1, result.stdout + result.stderr
    assert "LIFECYCLE VERIFICATION FAILED" in result.stdout

    # 2. The failure category survived teardown as a validated artifact.
    artifact = tmp_path / "e2e-diagnostics" / "install-failure.json"
    assert artifact.is_file(), result.stdout + result.stderr
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["source"] == "protocol-install-failure-log"
    assert payload["occurrences"] == 1
    assert payload["failures"] == [
        {"server_id": 1, "protocol": "awg", "port": 51820, "step": "image_build", "exit_code": 1}
    ]

    # 3. The whole artifact set still passes the existing pre-upload gate.
    gate = subprocess.run(
        [sys.executable, "-m", "tests.e2e.diagnostics", "--validate-dir", str(artifact.parent)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert gate.returncode == 0, gate.stdout + gate.stderr
    assert artifact.is_file()

    # 4. Hostile material never reached the console or the artifact.
    sinks = result.stdout + result.stderr + artifact.read_text(encoding="utf-8")
    for marker in (SECRET_TOKEN, PRIVATE_HOST, REMOTE_STDERR):
        assert marker not in sinks, f"leaked {marker!r}"

    # 5. The raw operator log was destroyed, not retained for upload.
    assert not list(tmp_path.glob("panel-operator-*.log"))


def test_clean_lifecycle_publishes_no_failure_evidence(tmp_path: Path) -> None:
    """A passing run keeps a zero result and emits no misleading failure claim."""
    result = run_lifecycle(tmp_path, CLEAN_LOG, stage2_passes=True)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL STAGES PASSED" in result.stdout
    assert not (tmp_path / "e2e-diagnostics" / "install-failure.json").exists()
    assert "0 failed-install line(s)" in result.stdout + result.stderr


def test_failure_evidence_absent_when_docker_logs_fails(tmp_path: Path) -> None:
    """Unavailable operator log yields no artifact and never flips the verdict."""
    result = run_lifecycle(tmp_path, FAILURE_LOG, stage2_passes=False, docker_logs_ok=False)

    # The failing lifecycle result is still preserved...
    assert result.returncode == 1
    # ...but nothing claims a cause it could not read.
    assert "unavailable; no diagnostics collected" in result.stdout + result.stderr
    assert not (tmp_path / "e2e-diagnostics" / "install-failure.json").exists()
    assert not list(tmp_path.glob("panel-operator-*.log"))
