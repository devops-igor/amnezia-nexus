"""Execute the real durability driver with file-only subject and client doubles."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest


def rehearsal_fixture(tmp_path: Path, sqlite_mode: str | None) -> tuple[Path, dict[str, str]]:
    """Copy the driver into a private layout; every process is an unprivileged double."""
    root = tmp_path / "fixture"
    (root / "scripts").mkdir(parents=True)
    (root / "bin").mkdir()
    shutil.copy2(
        Path("scripts/run_upstream_restart_durability.sh"),
        root / "scripts/run_upstream_restart_durability.sh",
    )
    tool_dir = root / "tools"
    tool_dir.mkdir()
    for name in (
        "bash",
        "dirname",
        "mkdir",
        "rm",
        "date",
        "sha256sum",
        "awk",
        "seq",
        "sleep",
        "cp",
        "python3",
        "cat",
        "sed",
    ):
        executable = shutil.which(name)
        assert executable is not None, "local oracle tool unavailable"
        (tool_dir / name).symlink_to(executable)
    subject = root / "bin/qualification-subject"
    subject.write_text("""#!/usr/bin/env bash
set -eu
while [[ $# -gt 0 ]]; do
 case "$1" in
 --db-path) db="$2";shift 2;;
 --config-path) config="$2";shift 2;;
 --ready-path) ready="$2";shift 2;;
 --reuse-db) shift;;
 *) shift 2;;
 esac
done
echo started >> "$ORACLE_EVENTS"
echo database > "$db"
echo frozen-config > "$config"
touch "$ready"
exec sleep 300
""")
    # touch is deliberately used only by the file-only subject double.
    touch = shutil.which("touch")
    assert touch is not None, "local oracle tool unavailable"
    (tool_dir / "touch").symlink_to(touch)
    subject.chmod(0o755)
    client = root / "scripts/run_non_netstack_client_qualification.sh"
    client.write_text(r"""#!/usr/bin/env bash
set -eu
dry=false
while [[ $# -gt 0 ]]; do
 case "$1" in
 --output-dir) output="$2";shift 2;;
 --dry-run) dry=true;shift;;
 *) shift 2;;
 esac
done
status=PASS
[[ "$dry" != true ]] || status=SKIPPED
echo "{\"status\":\"$status\",\"handshake_verified\":true,\"tcp_echo_verified\":true,\"udp_echo_verified\":true,\"reconnect_resilience_verified\":true}" > "$output/non_netstack_qualification.json"
""")
    client.chmod(0o755)
    if sqlite_mode is not None:
        sqlite = tool_dir / "sqlite3"
        sqlite.write_text("""#!/usr/bin/env bash
set -eu
[[ "$2" == "PRAGMA integrity_check;" ]] || exit 9
echo checked >> "$ORACLE_CHECKS"
count=$(awk 'END {print NR}' "$ORACLE_CHECKS")
if [[ "$count" == "$ORACLE_FAIL_LEG" ]]; then
 [[ "$ORACLE_SQLITE_MODE" != error ]] || exit 7
 echo "synthetic-private-db-detail"
else
 echo ok
fi
""")
        sqlite.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tool_dir),
        "ORACLE_EVENTS": str(root / "events"),
        "ORACLE_CHECKS": str(root / "checks"),
        "ORACLE_SQLITE_MODE": sqlite_mode or "",
        "ORACLE_FAIL_LEG": "0",
    }
    return root, env


def run_rehearsal(
    root: Path, env: dict[str, str], *, dry_run: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run the unchanged script without network, sudo, Docker or an actual database."""
    args = [
        str(root / "scripts/run_upstream_restart_durability.sh"),
        "--runtime-dir",
        str(root / "runtime"),
        "--output-dir",
        str(root / "output"),
    ]
    if dry_run:
        args.append("--dry-run")
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=15, check=False)


def test_restart_requires_sqlite_before_subject_start(tmp_path: Path) -> None:
    """An absent prerequisite rejects qualification before any subject or report exists."""
    root, env = rehearsal_fixture(tmp_path, None)
    result = run_rehearsal(root, env)
    assert result.returncode != 0
    assert "sqlite3 CLI is required" in result.stderr
    assert not (root / "events").exists()
    assert not (root / "output/upstream_restart_durability.json").exists()


@pytest.mark.parametrize("mode", ["bad-result", "error"])
@pytest.mark.parametrize("leg", [1, 2, 3])
def test_restart_rejects_failed_integrity(tmp_path: Path, mode: str, leg: int) -> None:
    """Every stopped leg must succeed; neither failed SQL nor non-ok output qualifies."""
    root, env = rehearsal_fixture(tmp_path, mode)
    env["ORACLE_FAIL_LEG"] = str(leg)
    result = run_rehearsal(root, env)
    assert result.returncode != 0
    assert "integrity" in result.stderr
    assert "synthetic-private-db-detail" not in result.stdout + result.stderr
    assert len((root / "checks").read_text().splitlines()) == leg
    assert not (root / "output/upstream_restart_durability.json").exists()


def test_restart_reports_three_actual_integrity_checks(tmp_path: Path) -> None:
    """A real-mode PASS derives its integrity claim from three executed successful queries."""
    root, env = rehearsal_fixture(tmp_path, "ok")
    result = run_rehearsal(root, env)
    assert result.returncode == 0, "file-only restart oracle failed"
    report: dict[str, Any] = json.loads(
        (root / "output/upstream_restart_durability.json").read_text()
    )
    assert report["verdict"] == "PASS"
    assert report["db_integrity_verified"] is True
    assert report["db_integrity_checks"] == 3
    assert report["config_hash_matched"] is True
    assert len((root / "checks").read_text().splitlines()) == 3


def test_restart_dry_run_cannot_claim_integrity(tmp_path: Path) -> None:
    """Simulation remains runnable without sqlite but never publishes a real PASS."""
    root, env = rehearsal_fixture(tmp_path, None)
    result = run_rehearsal(root, env, dry_run=True)
    assert result.returncode == 0, "file-only dry-run oracle failed"
    report = json.loads((root / "output/upstream_restart_durability.json").read_text())
    assert report["verdict"] == "SKIPPED"
    assert report["db_integrity_verified"] is False
    assert report["db_integrity_checks"] == 0
    assert not (root / "checks").exists()


def qualification_fixture(tmp_path: Path) -> dict[str, Any]:
    """Write the smallest valid full-qualification reports consumed by the real verifier."""
    run_mode = "unaccelerated_10_rekey"
    live = {
        "status": "PASS",
        "handshake_verified": True,
        "tcp_echo_verified": True,
        "udp_echo_verified": True,
        "reconnect_resilience_verified": True,
    }
    restart = {
        "verdict": "PASS",
        "dry_run": False,
        "config_hash_matched": True,
        "db_integrity_verified": True,
        "db_integrity_checks": 3,
        "legs": {f"leg{leg}_upstream": {"engine": "upstream", **live} for leg in (1, 2, 3)},
    }
    reports = {
        "evidence_manifest.json": {
            "environment": {
                "upstream_awg_module": "github.com/amnezia-vpn/amneziawg-go/v3",
                "upstream_awg_version": "v3.1.20260828",
                "nexus_commit": "a" * 40,
            },
            "frozen_client_configuration": {"rendered_config_sha256": "b" * 64},
        },
        "qualification_summary.json": {
            "status": "PASS",
            "passed_suites": ["matrix", "lifecycle", "soak"],
            "privacy_violations_count": 0,
        },
        "non_netstack_qualification.json": {**live, "teardown_requested": True},
        "upstream_restart_durability.json": restart,
    }
    base_soak = {
        "tcp_continuity_passed": True,
        "idle_phase_passed": True,
        "completed_rekeys": 10,
    }
    for side in ("reference", "subject"):
        reports[f"soak_report_{side}_{run_mode}.json"] = {
            **base_soak,
            "server_type": side,
            "run_mode": run_mode,
            "sequenced_udp_stats": {
                "packets_sent": 20000,
                "packets_received": 19990,
                "packets_lost": 10,
                "loss_rate_percent": 0.05,
            },
        }
    for name, report in reports.items():
        (tmp_path / name).write_text(json.dumps(report))
    return restart


def run_qualification_verifier(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Execute the real verifier with synthetic reports only."""
    return subprocess.run(
        [
            "bash",
            "scripts/verify_issue392_qualification.sh",
            "--artifacts-dir",
            str(tmp_path),
            "--expected-commit",
            "a" * 40,
            "--mode",
            "full",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_qualification_accepts_complete_live_restart_proof(tmp_path: Path) -> None:
    """Complete valid evidence still qualifies after the fail-closed correction."""
    qualification_fixture(tmp_path)
    result = run_qualification_verifier(tmp_path)
    assert result.returncode == 0, "synthetic qualification oracle failed"
    summary = json.loads((tmp_path / "issue392_qualification_summary.json").read_text())
    assert summary["overall"] == "PASS"
    assert summary["rollback_rehearsal_verified"] is True
    assert summary["issue392_closure_eligible"] is True


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "null",
        "empty",
        "dry-run",
        "missing-dry-run",
        "unverified",
        "missing-check-count",
        "two-checks",
        "boolean-check-count",
        "missing-leg",
        "extra-leg",
        "skipped-leg",
        "wrong-engine",
        "missing-handshake",
        "false-tcp",
        "false-udp",
        "false-reconnect",
    ],
)
def test_qualification_rejects_incomplete_restart_proof(tmp_path: Path, fault: str) -> None:
    """Executed report mutations cannot turn missing/skipped or fabricated legs into FULL PASS."""
    restart = qualification_fixture(tmp_path)
    report = tmp_path / "upstream_restart_durability.json"
    if fault == "missing":
        report.unlink()
    elif fault in ("null", "empty"):
        report.write_text(json.dumps(None if fault == "null" else {}))
    else:
        if fault == "dry-run":
            restart["dry_run"] = True
        elif fault == "missing-dry-run":
            del restart["dry_run"]
        elif fault == "unverified":
            restart["db_integrity_verified"] = False
        elif fault == "missing-check-count":
            del restart["db_integrity_checks"]
        elif fault == "two-checks":
            restart["db_integrity_checks"] = 2
        elif fault == "boolean-check-count":
            restart["db_integrity_checks"] = True
        elif fault == "missing-leg":
            del restart["legs"]["leg3_upstream"]
        elif fault == "extra-leg":
            restart["legs"]["extra"] = restart["legs"]["leg3_upstream"]
        else:
            leg = restart["legs"]["leg2_upstream"]
            if fault == "skipped-leg":
                leg["status"] = "SKIPPED"
            elif fault == "wrong-engine":
                leg["engine"] = "netstack"
            elif fault == "missing-handshake":
                del leg["handshake_verified"]
            else:
                field = {
                    "false-tcp": "tcp_echo_verified",
                    "false-udp": "udp_echo_verified",
                    "false-reconnect": "reconnect_resilience_verified",
                }[fault]
                leg[field] = False
        report.write_text(json.dumps(restart))
    result = run_qualification_verifier(tmp_path)
    assert result.returncode != 0, "incomplete restart evidence incorrectly qualified"
    assert not (tmp_path / "issue392_qualification_summary.json").exists()
