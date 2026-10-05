"""Permanent regressions for the real Issue #392 qualification verifier script.

Every test runs ``scripts/verify_issue392_qualification.sh`` as a subprocess against
synthetic evidence only. The mutation matrix mutates exactly one condition from an
otherwise valid fixture; no fixture claims real full qualification.
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Optional

import pytest

EXPECTED_COMMIT = "a" * 40
BOUNDED_RUN_MODE = "bounded_verification"
FULL_RUN_MODE = "unaccelerated_10_rekey"
SUMMARY_NAME = "issue392_qualification_summary.json"
# Internally consistent synthetic threshold evidence: 10 / 20000 == 0.05 percent.
THRESHOLD_STATS = {
    "packets_sent": 20000,
    "packets_received": 19990,
    "packets_lost": 10,
    "loss_rate_percent": 0.05,
}


def run_mode_for(mode: str) -> str:
    """Return the producer run_mode string the verifier requires for a mode."""
    return FULL_RUN_MODE if mode == "full" else BOUNDED_RUN_MODE


def rekeys_for(mode: str) -> int:
    """Return the rekey count the fixture needs to satisfy the mode threshold."""
    return 10 if mode == "full" else 1


def valid_soak_report(side: str, mode: str) -> dict[str, Any]:
    """Build one internally consistent, measured soak report for a side."""
    return {
        "server_type": side,
        "run_mode": run_mode_for(mode),
        "completed_rekeys": rekeys_for(mode),
        "tcp_continuity_passed": True,
        "idle_phase_passed": True,
        "sequenced_udp_stats": dict(THRESHOLD_STATS),
    }


def write_fixture(artifacts: Path, mode: str) -> Path:
    """Write the smallest valid evidence set consumed by the real verifier."""
    live = {
        "status": "PASS",
        "handshake_verified": True,
        "tcp_echo_verified": True,
        "udp_echo_verified": True,
        "reconnect_resilience_verified": True,
    }
    reports: dict[str, Any] = {
        "evidence_manifest.json": {
            "environment": {
                "upstream_awg_module": "github.com/amnezia-vpn/amneziawg-go/v3",
                "upstream_awg_version": "v3.1.20260828",
                "nexus_commit": EXPECTED_COMMIT,
            },
            "frozen_client_configuration": {"rendered_config_sha256": "b" * 64},
        },
        "qualification_summary.json": {
            "status": "PASS",
            "passed_suites": ["matrix", "lifecycle", "soak"],
            "privacy_violations_count": 0,
        },
        "non_netstack_qualification.json": {**live, "teardown_requested": True},
        "upstream_restart_durability.json": {
            "verdict": "PASS",
            "dry_run": False,
            "config_hash_matched": True,
            "db_integrity_verified": True,
            "db_integrity_checks": 3,
            "legs": {f"leg{leg}_upstream": {"engine": "upstream", **live} for leg in (1, 2, 3)},
        },
    }
    for side in ("reference", "subject"):
        reports[soak_report_name(side, mode)] = valid_soak_report(side, mode)
    for name, report in reports.items():
        (artifacts / name).write_text(json.dumps(report))
    return artifacts


def soak_report_name(side: str, mode: str) -> str:
    """Return the producer's canonical soak report file name for a side and mode."""
    return f"soak_report_{side}_{run_mode_for(mode)}.json"


def run_verifier(
    artifacts: Path,
    mode: str,
    output: Optional[Path] = None,
    non_netstack: str = "true",
) -> subprocess.CompletedProcess[str]:
    """Execute the real verifier against synthetic evidence only."""
    args = [
        "bash",
        "scripts/verify_issue392_qualification.sh",
        "--artifacts-dir",
        str(artifacts),
        "--expected-commit",
        EXPECTED_COMMIT,
        "--mode",
        mode,
        "--require-non-netstack",
        non_netstack,
    ]
    if output is not None:
        args += ["--output", str(output)]
    return subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)


def rewrite_soak(artifacts: Path, side: str, mode: str, mutate) -> None:
    """Apply a single mutation to one side's soak report, leaving the other valid."""
    path = artifacts / soak_report_name(side, mode)
    report = json.loads(path.read_text())
    mutate(report)
    path.write_text(json.dumps(report))


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_accepts_measured_threshold_evidence(tmp_path: Path, mode: str, side: str) -> None:
    """Exact-budget measured loss on both sides and in both modes still qualifies."""
    write_fixture(tmp_path, mode)
    result = run_verifier(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / SUMMARY_NAME).read_text())
    assert summary["overall"] == "PASS"
    assert summary["issue392_closure_eligible"] is (mode == "full")


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_accepts_measured_zero_loss(tmp_path: Path, mode: str, side: str) -> None:
    """A real observed stream with zero loss is valid proof, not missing evidence."""
    write_fixture(tmp_path, mode)

    def zero_loss(report: dict[str, Any]) -> None:
        report["sequenced_udp_stats"] = {
            "packets_sent": 20000,
            "packets_received": 20000,
            "packets_lost": 0,
            "loss_rate_percent": 0.0,
        }

    rewrite_soak(tmp_path, side, mode, zero_loss)
    result = run_verifier(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_accepts_below_budget_loss(tmp_path: Path, mode: str, side: str) -> None:
    """Loss strictly inside the budget qualifies."""
    write_fixture(tmp_path, mode)

    def below_budget(report: dict[str, Any]) -> None:
        report["sequenced_udp_stats"] = {
            "packets_sent": 20000,
            "packets_received": 19999,
            "packets_lost": 1,
            "loss_rate_percent": 0.005,
        }

    rewrite_soak(tmp_path, side, mode, below_budget)
    result = run_verifier(tmp_path, mode)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_missing_side_file(tmp_path: Path, mode: str, side: str) -> None:
    """Absent soak evidence for either side fails closed."""
    write_fixture(tmp_path, mode)
    (tmp_path / soak_report_name(side, mode)).unlink()
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize(
    "payload",
    ["not-json", "[]", '"text"', "null", "42"],
    ids=["garbage", "array", "string", "null", "number"],
)
def test_verifier_rejects_non_object_soak_report(
    tmp_path: Path, mode: str, side: str, payload: str
) -> None:
    """A soak report must be a JSON object; no other JSON shape is evidence."""
    write_fixture(tmp_path, mode)
    (tmp_path / soak_report_name(side, mode)).write_text(payload)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_duplicate_side_reports(tmp_path: Path, mode: str, side: str) -> None:
    """Two reports for one side are ambiguous; no arbitrary last-match is selected."""
    write_fixture(tmp_path, mode)
    stale = json.loads((tmp_path / soak_report_name(side, mode)).read_text())
    stale["completed_rekeys"] = 0
    (tmp_path / f"soak_report_{side}_stale_run.json").write_text(json.dumps(stale))
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_wrong_side_declaration(tmp_path: Path, mode: str, side: str) -> None:
    """A report filed under one side must not claim the other side."""
    write_fixture(tmp_path, mode)
    other = "subject" if side == "reference" else "reference"
    rewrite_soak(tmp_path, side, mode, lambda report: report.update(server_type=other))
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_missing_side_declaration(tmp_path: Path, mode: str, side: str) -> None:
    """Side and run mode must be declared, not inferred from the file name."""
    write_fixture(tmp_path, mode)

    def drop_declarations(report: dict[str, Any]) -> None:
        del report["server_type"]
        del report["run_mode"]

    rewrite_soak(tmp_path, side, mode, drop_declarations)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_wrong_run_mode(tmp_path: Path, side: str) -> None:
    """Full qualification may not consume bounded-mode reports and vice versa."""
    write_fixture(tmp_path, "bounded")
    rewrite_soak(tmp_path, side, "bounded", lambda r: r.update(run_mode=FULL_RUN_MODE))
    result = run_verifier(tmp_path, "bounded")
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize(
    "replacement",
    [None, True, False, "0.05", [0.05], {"value": 0.05}],
    ids=["null", "true", "false", "string", "list", "object"],
)
def test_verifier_rejects_wrong_rate_types(
    tmp_path: Path, mode: str, side: str, replacement: Any
) -> None:
    """loss_rate_percent must be an actual number; bools and containers are not."""
    write_fixture(tmp_path, mode)
    rewrite_soak(
        tmp_path,
        side,
        mode,
        lambda r: r["sequenced_udp_stats"].update(loss_rate_percent=replacement),
    )
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_missing_rate_key(tmp_path: Path, mode: str, side: str) -> None:
    """An absent loss_rate_percent key must fail instead of defaulting to zero."""
    write_fixture(tmp_path, mode)

    def drop_rate(report: dict[str, Any]) -> None:
        del report["sequenced_udp_stats"]["loss_rate_percent"]

    rewrite_soak(tmp_path, side, mode, drop_rate)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_verifier_rejects_non_finite_rate(
    tmp_path: Path, mode: str, side: str, literal: str
) -> None:
    """NaN and infinities are not measurements and cannot be coerced or compared."""
    write_fixture(tmp_path, mode)
    path = tmp_path / soak_report_name(side, mode)
    report = json.loads(path.read_text())
    text = json.dumps(report).replace(
        '"loss_rate_percent": 0.05', f'"loss_rate_percent": {literal}'
    )
    path.write_text(text)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize(
    "rate",
    [-0.01, -1, 100.01, 101, 1e9],
    ids=["negative", "negative-int", "over", "over-int", "huge"],
)
def test_verifier_rejects_out_of_range_rate(
    tmp_path: Path, mode: str, side: str, rate: float
) -> None:
    """A percentage outside 0..100 is malformed evidence."""
    write_fixture(tmp_path, mode)
    rewrite_soak(
        tmp_path, side, mode, lambda r: r["sequenced_udp_stats"].update(loss_rate_percent=rate)
    )
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize("field", ["packets_sent", "packets_received", "packets_lost"])
def test_verifier_rejects_missing_counter(tmp_path: Path, mode: str, side: str, field: str) -> None:
    """Every packet counter must be present by actual key presence."""
    write_fixture(tmp_path, mode)

    def drop(report: dict[str, Any], field: str = field) -> None:
        del report["sequenced_udp_stats"][field]

    rewrite_soak(tmp_path, side, mode, drop)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize("field", ["packets_sent", "packets_received", "packets_lost"])
@pytest.mark.parametrize(
    "replacement", [True, "10", 10.5, None, [10]], ids=["bool", "string", "float", "null", "list"]
)
def test_verifier_rejects_invalid_counter_types(
    tmp_path: Path, mode: str, side: str, field: str, replacement: Any
) -> None:
    """Counters must be integers; bools, floats, strings and containers are rejected."""
    write_fixture(tmp_path, mode)
    rewrite_soak(
        tmp_path, side, mode, lambda r: r["sequenced_udp_stats"].update({field: replacement})
    )
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize(
    "stats",
    [
        {"packets_sent": 0, "packets_received": 0, "packets_lost": 0, "loss_rate_percent": 0.0},
        {"packets_sent": 20000, "packets_received": 0, "packets_lost": 0, "loss_rate_percent": 0.0},
    ],
    ids=["no-observed-stream", "nothing-received"],
)
def test_verifier_rejects_zero_loss_without_observed_stream(
    tmp_path: Path, mode: str, side: str, stats: dict[str, Any]
) -> None:
    """An explicit zero loss with no observed stream is not evidence of health."""
    write_fixture(tmp_path, mode)
    rewrite_soak(tmp_path, side, mode, lambda r: r.update(sequenced_udp_stats=stats))
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
@pytest.mark.parametrize(
    "stats",
    [
        {"packets_sent": 100, "packets_received": 200, "packets_lost": 0, "loss_rate_percent": 0.0},
        {
            "packets_sent": 100,
            "packets_received": 100,
            "packets_lost": 150,
            "loss_rate_percent": 0.0,
        },
    ],
    ids=["received-exceeds-sent", "lost-exceeds-sent"],
)
def test_verifier_rejects_counters_exceeding_sent(
    tmp_path: Path, mode: str, side: str, stats: dict[str, Any]
) -> None:
    """received and lost may each be at most sent; nothing may exceed it."""
    write_fixture(tmp_path, mode)
    rewrite_soak(tmp_path, side, mode, lambda r: r.update(sequenced_udp_stats=stats))
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_inconsistent_percentage(tmp_path: Path, mode: str, side: str) -> None:
    """loss_rate_percent must equal 100 * lost / sent within the producer tolerance."""
    write_fixture(tmp_path, mode)
    rewrite_soak(
        tmp_path,
        side,
        mode,
        lambda r: r["sequenced_udp_stats"].update(loss_rate_percent=0.04),
    )
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_zero_reported_loss_with_lost_counters(
    tmp_path: Path, mode: str, side: str
) -> None:
    """Reporting zero percent while counters show loss is a consistency failure."""
    write_fixture(tmp_path, mode)
    rewrite_soak(
        tmp_path,
        side,
        mode,
        lambda r: r["sequenced_udp_stats"].update(loss_rate_percent=0.0),
    )
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_over_budget_loss(tmp_path: Path, mode: str, side: str) -> None:
    """Internally consistent loss above 0.05 percent fails the qualification budget."""
    write_fixture(tmp_path, mode)

    def over_budget(report: dict[str, Any]) -> None:
        report["sequenced_udp_stats"] = {
            "packets_sent": 20000,
            "packets_received": 19980,
            "packets_lost": 20,
            "loss_rate_percent": 0.1,
        }

    rewrite_soak(tmp_path, side, mode, over_budget)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_total_loss_as_budget_violation(
    tmp_path: Path, mode: str, side: str
) -> None:
    """100 percent loss is in range but far above budget, and must not qualify."""
    write_fixture(tmp_path, mode)

    def total_loss(report: dict[str, Any]) -> None:
        report["sequenced_udp_stats"] = {
            "packets_sent": 20000,
            "packets_received": 1,
            "packets_lost": 20000,
            "loss_rate_percent": 100.0,
        }

    rewrite_soak(tmp_path, side, mode, total_loss)
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
def test_verifier_does_not_require_received_plus_lost_equals_sent(
    tmp_path: Path, mode: str
) -> None:
    """Late and duplicate echo accounting may leave received + lost below sent."""
    write_fixture(tmp_path, mode)

    def late_duplicates(report: dict[str, Any]) -> None:
        report["sequenced_udp_stats"] = {
            "packets_sent": 20000,
            "packets_received": 19990,
            "packets_lost": 5,
            "loss_rate_percent": 0.025,
        }

    rewrite_soak(tmp_path, "reference", mode, late_duplicates)
    result = run_verifier(tmp_path, mode)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mode", ["bounded", "full"])
def test_verifier_removes_stale_pass_summary_on_failing_rerun(tmp_path: Path, mode: str) -> None:
    """A failed rerun must not leave a previous PASS summary behind as evidence."""
    write_fixture(tmp_path, mode)
    assert run_verifier(tmp_path, mode).returncode == 0
    summary = tmp_path / SUMMARY_NAME
    assert json.loads(summary.read_text())["overall"] == "PASS"

    rewrite_soak(tmp_path, "subject", mode, lambda r: r["sequenced_udp_stats"].clear())
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not summary.exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_rejects_output_colliding_with_input(tmp_path: Path, mode: str, side: str) -> None:
    """The summary may not overwrite a consumed input report."""
    write_fixture(tmp_path, mode)
    target = tmp_path / soak_report_name(side, mode)
    result = run_verifier(tmp_path, mode, output=target)
    assert result.returncode != 0
    assert json.loads(target.read_text())["server_type"] == side


@pytest.mark.parametrize("mode", ["bounded", "full"])
def test_verifier_reports_output_write_failure_as_nonzero(tmp_path: Path, mode: str) -> None:
    """An unwritable output path is a failure and publishes no success evidence."""
    write_fixture(tmp_path, mode)
    output = tmp_path / "readonly" / SUMMARY_NAME
    output.parent.mkdir()
    output.parent.chmod(0o500)
    try:
        result = run_verifier(tmp_path, mode, output=output)
    finally:
        output.parent.chmod(0o700)
    assert result.returncode != 0
    assert not output.exists()
    assert not (tmp_path / SUMMARY_NAME).exists()


@pytest.mark.parametrize("mode", ["bounded", "full"])
@pytest.mark.parametrize("side", ["reference", "subject"])
def test_verifier_errors_do_not_echo_report_values(tmp_path: Path, mode: str, side: str) -> None:
    """Diagnostics name the side and field only; hostile report values stay out."""
    write_fixture(tmp_path, mode)
    hostile = "synthetic-hostile-value-marker"
    path = tmp_path / soak_report_name(side, mode)
    report = json.loads(path.read_text())
    report["sequenced_udp_stats"]["loss_rate_percent"] = hostile
    path.write_text(json.dumps(report))
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert hostile not in combined
    assert "ERROR: [verify_issue392]" in result.stderr


@pytest.mark.parametrize("mode", ["bounded", "full"])
def test_verifier_preserves_sha_continuity_and_idle_requirements(tmp_path: Path, mode: str) -> None:
    """Pre-existing gates stay enforced alongside the new UDP evidence contract."""
    write_fixture(tmp_path, mode)
    manifest = json.loads((tmp_path / "evidence_manifest.json").read_text())
    manifest["environment"]["upstream_awg_version"] = "v0.0.0"
    (tmp_path / "evidence_manifest.json").write_text(json.dumps(manifest))
    assert run_verifier(tmp_path, mode).returncode != 0

    write_fixture(tmp_path, mode)
    rewrite_soak(tmp_path, "reference", mode, lambda r: r.update(tcp_continuity_passed=False))
    assert run_verifier(tmp_path, mode).returncode != 0

    write_fixture(tmp_path, mode)
    rewrite_soak(tmp_path, "subject", mode, lambda r: r.update(idle_phase_passed=False))
    assert run_verifier(tmp_path, mode).returncode != 0


@pytest.mark.parametrize("mode", ["bounded", "full"])
def test_verifier_preserves_privacy_audit(tmp_path: Path, mode: str) -> None:
    """A privacy violation in evidence still fails the run and publishes nothing."""
    write_fixture(tmp_path, mode)
    soak = tmp_path / soak_report_name("subject", mode)
    report = json.loads(soak.read_text())
    report["leaked_detail"] = "/home/synthetic-user/secret"
    soak.write_text(json.dumps(report))
    result = run_verifier(tmp_path, mode)
    assert result.returncode != 0
    assert not (tmp_path / SUMMARY_NAME).exists()


def test_bounded_mode_remains_closure_ineligible(tmp_path: Path) -> None:
    """Bounded evidence passes verification but never grants closure eligibility."""
    write_fixture(tmp_path, "bounded")
    result = run_verifier(tmp_path, "bounded")
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / SUMMARY_NAME).read_text())
    assert summary["qualification_mode"] == "bounded"
    assert summary["issue392_closure_eligible"] is False
