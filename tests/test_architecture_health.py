"""Unit tests for Architecture Health Size and Churn Report with Ratchet."""

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from scripts.architecture_health import (
    BINARY_EXTENSIONS,
    EXCLUDED_DIRS,
    EXCLUDED_FILES,
    calculate_risk_metrics,
    classify_component,
    compute_git_churn,
    count_file_lines_and_bytes,
    find_repo_root,
    generate_baseline,
    generate_json_report,
    generate_markdown_summary,
    get_commit_metadata,
    get_tracked_files,
    is_excluded,
    load_baseline,
    save_baseline,
    scan_repository,
    update_downward_ratchet,
)


def test_find_repo_root() -> None:
    """Verify repository root discovery returns a valid existing directory."""
    root = find_repo_root()
    assert root.exists()
    assert (root / "go.mod").exists() or (root / "pyproject.toml").exists()

    # Custom root override
    custom = find_repo_root("/tmp")
    assert custom == Path("/tmp").resolve()


def test_get_tracked_files_real_repo() -> None:
    """Verify git ls-files discovery returns tracked repository files with forward slashes."""
    repo_root = find_repo_root()
    tracked = get_tracked_files(repo_root)

    assert isinstance(tracked, list)
    assert len(tracked) > 50
    assert "go.mod" in tracked
    assert "scripts/generate_captcha_assets.py" in tracked
    for f in tracked:
        assert "\\" not in f
        assert not f.startswith("/")


def test_get_tracked_files_mocked() -> None:
    """Verify git ls-files output parsing handles whitespace and sorts cleanly."""
    mock_stdout = "  internal/vpn/vpn.go \n\n web/templates/vpn.html\r\ncmd/server/main.go\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_stdout, returncode=0)
        files = get_tracked_files(Path("/fake/repo"))
        assert files == [
            "cmd/server/main.go",
            "internal/vpn/vpn.go",
            "web/templates/vpn.html",
        ]


def test_exclusion_filtering_directories() -> None:
    """Verify paths within excluded directories are properly identified."""
    for excluded_dir in EXCLUDED_DIRS:
        sample_path = f"{excluded_dir}/some_module/file.py"
        assert is_excluded(sample_path) is True, f"Failed to exclude {sample_path}"
        nested_path = f"subdir/{excluded_dir}/deep/file.go"
        assert is_excluded(nested_path) is True, f"Failed to exclude {nested_path}"


def test_exclusion_filtering_files() -> None:
    """Verify exact excluded files are rejected while non-excluded files pass."""
    for excluded_file in EXCLUDED_FILES:
        assert is_excluded(excluded_file) is True
        assert is_excluded(f"nested/{excluded_file}") is True

    # Standard production files should never be excluded
    assert is_excluded("internal/vpn/vpn.go") is False
    assert is_excluded("web/static/js/vpn/page.js") is False
    assert is_excluded("web/templates/vpn.html") is False
    assert is_excluded("scripts/architecture_health.py") is False


def test_exclusion_filtering_binary_extensions() -> None:
    """Verify binary file extensions are excluded from line count evaluation."""
    for ext in BINARY_EXTENSIONS:
        sample_path = f"web/static/assets/image{ext}"
        assert is_excluded(sample_path) is True, f"Failed to exclude binary extension {ext}"


def test_count_file_lines_and_bytes(tmp_path: Path) -> None:
    """Verify newline counting and byte calculations across various file structures."""
    # Empty file
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")
    counts = count_file_lines_and_bytes(empty_file)
    assert counts == (0, 0)

    # File with trailing newline
    with_newline = tmp_path / "newline.txt"
    with_newline.write_bytes(b"alpha\nbeta\ngamma\n")
    counts = count_file_lines_and_bytes(with_newline)
    assert counts == (3, len(b"alpha\nbeta\ngamma\n"))

    # File without trailing newline
    no_newline = tmp_path / "no_newline.txt"
    no_newline.write_bytes(b"alpha\nbeta\ngamma")
    counts = count_file_lines_and_bytes(no_newline)
    assert counts == (3, len(b"alpha\nbeta\ngamma"))

    # Single line without newline
    single_line = tmp_path / "single.txt"
    single_line.write_bytes(b"hello world")
    counts = count_file_lines_and_bytes(single_line)
    assert counts == (1, 11)

    # Binary file containing null byte
    binary_file = tmp_path / "binary.dat"
    binary_file.write_bytes(b"hello\x00world\n")
    counts = count_file_lines_and_bytes(binary_file)
    assert counts is None

    # Missing file returns None
    missing_file = tmp_path / "non_existent.txt"
    assert count_file_lines_and_bytes(missing_file) is None


def test_classify_component() -> None:
    """Verify architectural component categorization logic."""
    assert classify_component("internal/vpn/forwarder/forwarder.go") == "Packet Forwarder"
    assert classify_component("internal/vpn/vpn.go") == "Go Core VPN"
    assert classify_component("internal/vpn/vpn_test.go") == "Test Suites"
    assert classify_component("tests/e2e/test_traffic.py") == "Test Suites"
    assert classify_component("web/templates/vpn.html") == "Web Templates"
    assert classify_component("web/static/css/style.css") == "CSS Styles"
    assert classify_component("web/static/js/vpn/backends.js") == "Frontend JavaScript"
    assert classify_component("web/translations/en.json") == "Translations"
    assert classify_component("cmd/server/main.go") == "Go Production (CLI & Entrypoints)"
    assert (
        classify_component("internal/service/orchestrator/orchestrator.go")
        == "Go Production (Services)"
    )
    assert classify_component("internal/manager/awg/awg.go") == "Go Production (WireGuard Manager)"
    assert classify_component("internal/handlers/servers.go") == "Go Production (Handlers & Router)"
    assert classify_component("internal/database/db.go") == "Go Production (Database & Infra)"
    assert classify_component("scripts/architecture_health.py") == "Scripts & Tooling"
    assert classify_component("docs/architecture/overview.md") == "Documentation"
    assert classify_component("unrecognized/path.xyz") == "Other"


def test_calculate_risk_metrics() -> None:
    """Verify risk score formula and risk tier boundaries."""
    # Low risk
    score_low, tier_low = calculate_risk_metrics(
        lines=100, churn_30d=0, churn_90d=0, ceiling_lines=1000
    )
    assert score_low == 0.1
    assert tier_low == "LOW"

    # Medium risk (500 lines)
    score_med, tier_med = calculate_risk_metrics(
        lines=500, churn_30d=1, churn_90d=2, ceiling_lines=1000
    )
    assert tier_med == "MEDIUM"

    # High risk (1000 lines)
    score_high, tier_high = calculate_risk_metrics(
        lines=1000, churn_30d=2, churn_90d=5, ceiling_lines=1000
    )
    assert tier_high == "HIGH"

    # Critical risk (>4000 lines or high score)
    score_crit, tier_crit = calculate_risk_metrics(
        lines=4500, churn_30d=10, churn_90d=20, ceiling_lines=1000
    )
    assert tier_crit == "CRITICAL"


def test_deterministic_window_boundary_inclusion() -> None:
    """Verify churn calculation strictly respects inclusive boundary conditions."""
    ref_epoch = 1_800_000_000
    sec_30 = 30 * 86400  # 2,592,000
    sec_90 = 90 * 86400  # 7,776,000

    # Build simulated git log stream with commits at key boundary timestamps
    commits_payload = [
        # Exactly at T (inclusive: both 30d and 90d)
        f"COMMIT:c_exact_t:{ref_epoch}",
        "file_exact_t.go",
        # Exactly at T - 30d (inclusive: both 30d and 90d)
        f"COMMIT:c_exact_30d:{ref_epoch - sec_30}",
        "file_exact_30d.go",
        # At T - 30d - 1 second (excluded from 30d, included in 90d)
        f"COMMIT:c_past_30d:{ref_epoch - sec_30 - 1}",
        "file_past_30d.go",
        # Exactly at T - 90d (inclusive: in 90d, excluded from 30d)
        f"COMMIT:c_exact_90d:{ref_epoch - sec_90}",
        "file_exact_90d.go",
        # At T - 90d - 1 second (excluded from both)
        f"COMMIT:c_past_90d:{ref_epoch - sec_90 - 1}",
        "file_past_90d.go",
        # At T + 1 second (excluded from both: beyond tip)
        f"COMMIT:c_future:{ref_epoch + 1}",
        "file_future.go",
    ]
    mock_log_output = "\n".join(commits_payload)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_log_output, returncode=0)
        c30, c90 = compute_git_churn(
            repo_root=Path("/fake/repo"),
            baseline_commit="base_sha_123",
            reference_epoch=ref_epoch,
            days_short=30,
            days_long=90,
        )

        # file_exact_t should be in both
        assert c30.get("file_exact_t.go") == 1
        assert c90.get("file_exact_t.go") == 1

        # file_exact_30d should be in both
        assert c30.get("file_exact_30d.go") == 1
        assert c90.get("file_exact_30d.go") == 1

        # file_past_30d should be ONLY in 90d
        assert c30.get("file_past_30d.go") is None
        assert c90.get("file_past_30d.go") == 1

        # file_exact_90d should be ONLY in 90d
        assert c30.get("file_exact_90d.go") is None
        assert c90.get("file_exact_90d.go") == 1

        # file_past_90d should be in NEITHER
        assert c30.get("file_past_90d.go") is None
        assert c90.get("file_past_90d.go") is None

        # file_future should be in NEITHER
        assert c30.get("file_future.go") is None
        assert c90.get("file_future.go") is None


def test_downward_ratchet_drops_below_baseline_ceiling() -> None:
    """Verify that when a legacy oversized file shrinks, its ceiling ratchets downward."""
    baseline = {
        "ceilings": {
            "internal/vpn/vpn.go": 4950,
            "web/templates/vpn.html": 3758,
            "cmd/server/main.go": 1000,
        },
        "files": {
            "internal/vpn/vpn.go": {"lines": 4950, "ceiling": 4950},
            "web/templates/vpn.html": {"lines": 3758, "ceiling": 3758},
            "cmd/server/main.go": {"lines": 350, "ceiling": 1000},
        },
    }

    current_files = [
        {
            "path": "internal/vpn/vpn.go",
            "lines": 4200,
            "bytes": 100000,
            "component": "Go Core VPN",
            "language": "Go",
            "churn_30d": 5,
            "churn_90d": 10,
        },
        {
            "path": "web/templates/vpn.html",
            "lines": 2500,
            "bytes": 80000,
            "component": "Web Templates",
            "language": "HTML",
            "churn_30d": 3,
            "churn_90d": 8,
        },
        {
            "path": "cmd/server/main.go",
            "lines": 380,
            "bytes": 9000,
            "component": "Go Production (CLI & Entrypoints)",
            "language": "Go",
            "churn_30d": 1,
            "churn_90d": 2,
        },
    ]

    updated, applied, unauthorized = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
        allow_ceiling_increase=False,
    )

    assert len(unauthorized) == 0
    assert len(applied) == 2

    # vpn.go ratcheted down to 4200
    assert updated["ceilings"]["internal/vpn/vpn.go"] == 4200
    assert updated["files"]["internal/vpn/vpn.go"]["ceiling"] == 4200

    # vpn.html ratcheted down to 2500
    assert updated["ceilings"]["web/templates/vpn.html"] == 2500

    # cmd/server/main.go grew from 350 to 380 but remains <= 1000 ceiling: no ratchet change
    assert updated["ceilings"]["cmd/server/main.go"] == 1000


def test_downward_ratchet_locks_at_ceiling_threshold() -> None:
    """Verify that an oversized file dropping below ceiling threshold locks permanently at 1,000 lines."""
    baseline = {
        "ceilings": {"internal/manager/awg/awg.go": 1400},
        "files": {"internal/manager/awg/awg.go": {"lines": 1400, "ceiling": 1400}},
    }

    # Shrinks to 750 lines (below 1000 ceiling threshold)
    current_files = [
        {
            "path": "internal/manager/awg/awg.go",
            "lines": 750,
            "bytes": 20000,
            "component": "Go Production (WireGuard Manager)",
            "language": "Go",
            "churn_30d": 2,
            "churn_90d": 5,
        },
    ]

    updated, applied, _ = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
        allow_ceiling_increase=False,
    )

    # Ratcheted down to 1000 (not 750)
    assert updated["ceilings"]["internal/manager/awg/awg.go"] == 1000
    assert updated["files"]["internal/manager/awg/awg.go"]["ceiling"] == 1000
    assert applied[0]["reduction"] == 400


def test_upward_ratchet_rejected_without_review_flag() -> None:
    """Verify that expanding beyond baseline ceiling is rejected unless explicit review flag is supplied."""
    baseline = {
        "ceilings": {"internal/vpn/vpn.go": 2000},
        "files": {"internal/vpn/vpn.go": {"lines": 2000, "ceiling": 2000}},
    }

    # File expanded from 2000 to 2100 lines
    current_files = [
        {
            "path": "internal/vpn/vpn.go",
            "lines": 2100,
            "bytes": 70000,
            "component": "Go Core VPN",
            "language": "Go",
            "churn_30d": 1,
            "churn_90d": 1,
        },
    ]

    with pytest.raises(
        ValueError, match="Cannot ratchet ceilings upward.*without --allow-ceiling-increase"
    ):
        update_downward_ratchet(
            current_files_data=current_files,
            baseline_data=baseline,
            ceiling_lines=1000,
            allow_ceiling_increase=False,
        )

    # With allow_ceiling_increase=True, the ceiling update is accepted
    updated, applied, unauthorized = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
        allow_ceiling_increase=True,
    )
    assert len(unauthorized) == 0
    assert updated["ceilings"]["internal/vpn/vpn.go"] == 2100


def test_generate_json_report_schema_and_zero_leak() -> None:
    """Verify structured JSON report schema compliance and guarantee zero local path leaks."""
    summary: Dict[str, Any] = {
        "total_files": 10,
        "total_lines": 5000,
        "total_bytes": 150000,
        "ceiling_lines": 1000,
        "warning_lines": 500,
        "ceiling_violations_count": 0,
        "warning_count": 2,
        "ratchet_opportunities_count": 1,
        "tier_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 7},
        "component_stats": {
            "Go Core VPN": {
                "file_count": 5,
                "total_lines": 3000,
                "total_bytes": 90000,
                "ceiling_violations": 0,
                "warning_count": 1,
                "max_lines": 800,
                "max_file": "internal/vpn/vpn.go",
                "total_churn_30d": 10,
                "total_churn_90d": 20,
            }
        },
    }

    files_data = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "language": "Go",
            "lines": 800,
            "bytes": 24000,
            "ceiling": 1000,
            "churn_30d": 10,
            "churn_90d": 20,
            "risk_score": 8.0,
            "risk_tier": "MEDIUM",
            "ceiling_violation": False,
            "warning_threshold": True,
        }
    ]

    baseline_meta = {
        "repository": "amnezia-nexus",
        "baseline_commit": "1810775edb75a1b0b3239087bd5e8b30b72de610",
        "reference_timestamp": "2026-10-19T12:33:29Z",
        "churn_windows_days": [30, 90],
    }

    report_json = generate_json_report(
        files_data=files_data,
        summary=summary,
        ceiling_violations=[],
        ratchet_opportunities=[],
        baseline_metadata=baseline_meta,
        scan_commit="1810775edb75a1b0b3239087bd5e8b30b72de610",
    )

    data = json.loads(report_json)
    assert "scan_metadata" in data
    assert "summary" in data
    assert "ceiling_violations" in data
    assert "ratchet_opportunities" in data
    assert "top_hotspots" in data

    meta = data["scan_metadata"]
    assert meta["repository"] == "amnezia-nexus"
    assert meta["baseline_commit"] == "1810775edb75a1b0b3239087bd5e8b30b72de610"
    assert meta["warning_lines"] == 500
    assert meta["ceiling_lines"] == 1000

    # Leak security audit: no absolute /home or user paths
    assert "/home/" not in report_json
    assert "127.0.0.1" not in report_json


def test_generate_markdown_summary() -> None:
    """Verify Markdown summary rendering meets GitHub step summary formatting."""
    summary: Dict[str, Any] = {
        "total_files": 2,
        "total_lines": 1800,
        "total_bytes": 50000,
        "ceiling_lines": 1000,
        "warning_lines": 500,
        "ceiling_violations_count": 1,
        "warning_count": 1,
        "ratchet_opportunities_count": 1,
        "tier_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
        "component_stats": {
            "Go Core VPN": {
                "file_count": 2,
                "total_lines": 1800,
                "total_bytes": 50000,
                "ceiling_violations": 1,
                "warning_count": 1,
                "max_lines": 1200,
                "max_file": "internal/vpn/vpn.go",
                "total_churn_30d": 5,
                "total_churn_90d": 12,
            }
        },
    }

    files_data = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "lines": 1200,
            "churn_30d": 5,
            "churn_90d": 12,
            "risk_score": 15.0,
            "risk_tier": "HIGH",
        }
    ]

    violations = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "lines": 1200,
            "ceiling": 1000,
            "excess_lines": 200,
        }
    ]

    ratchets = [
        {
            "path": "internal/vpn/shrink.go",
            "component": "Go Core VPN",
            "previous_ceiling": 1500,
            "current_lines": 1100,
            "new_ceiling": 1100,
            "reduction": 400,
        }
    ]

    md = generate_markdown_summary(
        files_data=files_data,
        summary=summary,
        ceiling_violations=violations,
        ratchet_opportunities=ratchets,
    )

    assert "## Architecture Health & Churn Report" in md
    assert "Ceiling Violation(s) Detected" in md
    assert "### ❌ Ceiling Violations" in md
    assert "internal/vpn/vpn.go" in md
    assert "### 📉 Downward Ratchet Opportunities" in md
    assert "internal/vpn/shrink.go" in md
    assert "### 🔥 Top" in md
    assert "### 📦 Component Distribution" in md


def test_baseline_save_and_load(tmp_path: Path) -> None:
    """Verify serialization and deserialization fidelity for architecture baseline."""
    baseline_file = tmp_path / "test_baseline.json"
    data = {
        "metadata": {
            "repository": "amnezia-nexus",
            "baseline_commit": "abcdef123456",
            "reference_timestamp": "2026-10-19T12:00:00Z",
            "reference_timestamp_epoch": 1792411200,
            "warning_threshold": 500,
            "ceiling_threshold": 1000,
            "churn_windows_days": [30, 90],
        },
        "ceilings": {"file.go": 1000},
        "files": {"file.go": {"lines": 100, "ceiling": 1000}},
    }

    save_baseline(baseline_file, data)
    assert baseline_file.exists()

    loaded = load_baseline(baseline_file)
    assert loaded == data


def test_scan_repository_detects_violations_and_ratchets(tmp_path: Path) -> None:
    """Verify scan_repository properly detects ceiling breaches and ratchet opportunities."""
    repo_root = tmp_path / "mock_repo"
    repo_root.mkdir()

    # Create tracked files
    file_a = repo_root / "oversized.go"
    file_a.write_text("\n" * 1500, encoding="utf-8")  # 1500 lines

    file_b = repo_root / "shrunk.go"
    file_b.write_text("\n" * 1100, encoding="utf-8")  # 1100 lines

    file_c = repo_root / "nominal.go"
    file_c.write_text("\n" * 200, encoding="utf-8")  # 200 lines

    mock_tracked = ["oversized.go", "shrunk.go", "nominal.go"]

    baseline_ceilings = {
        "oversized.go": 1000,  # current lines 1500 > 1000 -> violation!
        "shrunk.go": 1400,  # current lines 1100 < 1400 -> ratchet down to 1100!
        "nominal.go": 1000,  # current lines 200 <= 1000 -> ok
    }

    with patch("scripts.architecture_health.get_tracked_files", return_value=mock_tracked):
        files_data, summary, violations, ratchets = scan_repository(
            repo_root=repo_root,
            baseline_ceilings=baseline_ceilings,
            ceiling_lines=1000,
            warning_lines=500,
        )

        assert summary["total_files"] == 3
        assert len(violations) == 1
        assert violations[0]["path"] == "oversized.go"
        assert violations[0]["excess_lines"] == 500

        assert len(ratchets) == 1
        assert ratchets[0]["path"] == "shrunk.go"
        assert ratchets[0]["new_ceiling"] == 1100
        assert ratchets[0]["reduction"] == 300


def test_get_commit_metadata_real_repo() -> None:
    """Verify commit metadata extraction against real repository HEAD."""
    repo_root = find_repo_root()
    sha, iso_ts, epoch = get_commit_metadata(repo_root, "HEAD")
    assert len(sha) == 40
    assert iso_ts.endswith("Z")
    assert epoch > 1_700_000_000


def test_generate_baseline_in_temp_repo(tmp_path: Path) -> None:
    """Verify baseline generation correctly sets ceilings and metadata."""
    repo_root = tmp_path / "baseline_repo"
    repo_root.mkdir()

    file_a = repo_root / "small.go"
    file_a.write_text("package main\nfunc main() {}\n", encoding="utf-8")
    file_b = repo_root / "large.go"
    file_b.write_text("\n" * 1250, encoding="utf-8")

    mock_tracked = ["small.go", "large.go"]
    mock_meta = ("abcdef1234567890abcdef1234567890abcdef12", "2026-10-19T12:00:00Z", 1792411200)

    with (
        patch("scripts.architecture_health.get_tracked_files", return_value=mock_tracked),
        patch("scripts.architecture_health.get_commit_metadata", return_value=mock_meta),
        patch("scripts.architecture_health.compute_git_churn", return_value=({}, {})),
    ):
        baseline = generate_baseline(repo_root=repo_root, commit_ref="HEAD")

        assert baseline["metadata"]["baseline_commit"] == mock_meta[0]
        assert baseline["metadata"]["reference_timestamp"] == mock_meta[1]
        assert baseline["metadata"]["reference_timestamp_epoch"] == mock_meta[2]
        assert baseline["ceilings"]["small.go"] == 1000
        assert baseline["ceilings"]["large.go"] == 1250
        assert baseline["files"]["small.go"]["lines"] == 2
        assert baseline["files"]["large.go"]["lines"] == 1250


def test_cli_generate_baseline_and_check(tmp_path: Path) -> None:
    """Verify main() CLI execution across baseline generation, checking, and ratcheting."""
    from scripts.architecture_health import main

    test_baseline = tmp_path / "baseline.json"
    test_report = tmp_path / "report.json"
    test_summary = tmp_path / "summary.md"

    # Step 1: Generate baseline
    with patch(
        "sys.argv",
        [
            "architecture_health.py",
            "--baseline-file",
            str(test_baseline),
            "--generate-baseline",
        ],
    ):
        code = main()
        assert code == 0
        assert test_baseline.exists()

    # Step 2: Run check against generated baseline
    with patch(
        "sys.argv",
        [
            "architecture_health.py",
            "--baseline-file",
            str(test_baseline),
            "--report-json",
            str(test_report),
            "--summary-md",
            str(test_summary),
            "--check",
        ],
    ):
        code = main()
        assert code == 0
        assert test_report.exists()
        assert test_summary.exists()

    # Step 3: Run check when baseline is missing
    missing_baseline = tmp_path / "does_not_exist.json"
    with patch(
        "sys.argv",
        [
            "architecture_health.py",
            "--baseline-file",
            str(missing_baseline),
            "--check",
        ],
    ):
        assert main() == 1

    # Nonblocking mode when baseline missing exits 0
    with patch(
        "sys.argv",
        [
            "architecture_health.py",
            "--baseline-file",
            str(missing_baseline),
            "--check",
            "--nonblocking",
        ],
    ):
        assert main() == 0
