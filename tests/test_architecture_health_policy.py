"""Unit tests for architecture health policies, ceiling evaluations, and ratchets."""

import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from scripts.architecture_health import (
    calculate_risk_metrics,
    find_repo_root,
    generate_baseline,
    rebase_ceilings,
    rebase_churn,
    rebase_files_map,
    scan_repository,
    update_downward_ratchet,
)


def test_calculate_risk_metrics() -> None:
    """Verify composite risk score calculation and tier boundaries."""
    # Low risk nominal file
    score, tier = calculate_risk_metrics(lines=200, churn_30d=1, churn_90d=2, ceiling_lines=1000)
    assert tier == "LOW"
    assert score < 5.0

    # Medium risk file
    score, tier = calculate_risk_metrics(lines=550, churn_30d=5, churn_90d=10, ceiling_lines=1000)
    assert tier == "MEDIUM"

    # High risk file
    score, tier = calculate_risk_metrics(lines=1050, churn_30d=10, churn_90d=20, ceiling_lines=1000)
    assert tier == "HIGH"

    # Critical risk file
    score, tier = calculate_risk_metrics(lines=4500, churn_30d=20, churn_90d=50, ceiling_lines=1000)
    assert tier == "CRITICAL"


def test_rebase_ceilings_move_semantics() -> None:
    """Verify authoritative move semantics: old path is pruned, new path inherits ceiling."""
    ceilings = {
        "internal/vpn/vpn.go": 2400,
        "nominal.go": 1000,
    }
    renames = {
        "internal/vpn/vpn_legacy.go": "internal/vpn/vpn.go",
    }
    rebased = rebase_ceilings(ceilings, renames)

    assert "internal/vpn/vpn_legacy.go" in rebased
    assert rebased["internal/vpn/vpn_legacy.go"] == 2400
    assert "internal/vpn/vpn.go" not in rebased
    assert rebased["nominal.go"] == 1000

    # Self-rename does not delete
    assert rebase_ceilings({"a.go": 1200}, {"a.go": "a.go"}) == {"a.go": 1200}


def test_rebase_files_map_and_churn() -> None:
    """Verify move semantics for baseline files map and historical churn."""
    files_map = {
        "old.go": {"lines": 1500, "ceiling": 1500},
        "stable.go": {"lines": 200, "ceiling": 1000},
    }
    churn = {"old.go": 12, "stable.go": 3}
    renames = {"new.go": "old.go"}

    rebased_map = rebase_files_map(files_map, renames)
    assert "new.go" in rebased_map
    assert rebased_map["new.go"]["lines"] == 1500
    assert "old.go" not in rebased_map

    rebased_churn = rebase_churn(churn, renames)
    assert rebased_churn["new.go"] == 12
    assert "old.go" not in rebased_churn


def test_downward_ratchet_drops_below_baseline_ceiling() -> None:
    """Verify downward ratchet locks in line reduction when file shrinks."""
    baseline = {
        "metadata": {"baseline_commit": "abc"},
        "ceilings": {"shrunk.go": 2400},
        "files": {"shrunk.go": {"lines": 2400, "ceiling": 2400}},
    }
    current_files = [{"path": "shrunk.go", "lines": 1800}]

    updated, applied, unauth = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
    )
    assert len(unauth) == 0
    assert updated["ceilings"]["shrunk.go"] == 1800
    assert updated["files"]["shrunk.go"]["ceiling"] == 1800
    assert len(applied) == 1
    assert applied[0]["action"] == "ratcheted_down"
    assert applied[0]["reduction"] == 600


def test_downward_ratchet_locks_at_ceiling_threshold() -> None:
    """Verify downward ratchet floor never drops below the strict ceiling threshold."""
    baseline = {
        "metadata": {"baseline_commit": "abc"},
        "ceilings": {"oversized.go": 1500},
        "files": {"oversized.go": {"lines": 1500, "ceiling": 1500}},
    }
    current_files = [{"path": "oversized.go", "lines": 400}]

    updated, applied, _ = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
    )
    assert updated["ceilings"]["oversized.go"] == 1000
    assert len(applied) == 1
    assert applied[0]["reduction"] == 500


def test_upward_ratchet_rejected_without_review_flag() -> None:
    """Verify upward ratchet throws ValueError unless allow_ceiling_increase is passed."""
    baseline = {
        "metadata": {"baseline_commit": "abc"},
        "ceilings": {"grown.go": 1200},
        "files": {"grown.go": {"lines": 1200, "ceiling": 1200}},
    }
    current_files = [{"path": "grown.go", "lines": 1500}]

    with pytest.raises(ValueError, match="Cannot ratchet ceilings upward"):
        update_downward_ratchet(
            current_files_data=current_files,
            baseline_data=baseline,
            ceiling_lines=1000,
            allow_ceiling_increase=False,
        )

    updated, applied, unauth = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
        allow_ceiling_increase=True,
    )
    assert len(unauth) == 0
    assert updated["ceilings"]["grown.go"] == 1500
    assert applied[0]["action"] == "increased"


def test_update_downward_ratchet_prunes_deleted_paths() -> None:
    """Verify update_downward_ratchet prunes deleted paths from ceilings and files_map."""
    baseline = {
        "metadata": {"baseline_commit": "abc"},
        "ceilings": {"deleted.go": 1500, "active.go": 1000},
        "files": {
            "deleted.go": {"lines": 1500, "ceiling": 1500},
            "active.go": {"lines": 800, "ceiling": 1000},
        },
    }
    current_files = [{"path": "active.go", "lines": 800}]

    updated, applied, unauth = update_downward_ratchet(
        current_files_data=current_files,
        baseline_data=baseline,
        ceiling_lines=1000,
    )
    assert "deleted.go" not in updated["ceilings"]
    assert "deleted.go" not in updated["files"]
    pruned = [a for a in applied if a["action"] == "pruned_deleted"]
    assert len(pruned) == 1
    assert pruned[0]["path"] == "deleted.go"


def test_scan_repository_detects_violations_and_ratchets(tmp_path: Path) -> None:
    """Verify scan_repository detects ceiling violations and ratchet opportunities."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    (repo_root / "oversized.go").write_text("\n" * 1500, encoding="utf-8")
    (repo_root / "shrunk.go").write_text("\n" * 1100, encoding="utf-8")
    (repo_root / "nominal.go").write_text("\n" * 200, encoding="utf-8")

    mock_tracked = ["oversized.go", "shrunk.go", "nominal.go"]
    baseline_ceilings = {
        "oversized.go": 1000,
        "shrunk.go": 1400,
        "nominal.go": 1000,
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


def test_scan_repository_generated_assets_exempt(tmp_path: Path) -> None:
    """Verify generated and vendor assets are excluded from violations and ratchets."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    css_path = repo_root / "web/static/css/style.css"
    css_path.parent.mkdir(parents=True, exist_ok=True)
    css_path.write_text("\n" * 3001, encoding="utf-8")

    js_path = repo_root / "web/static/js/qrcode.min.js"
    js_path.parent.mkdir(parents=True, exist_ok=True)
    js_path.write_text("\n" * 1500, encoding="utf-8")

    mock_tracked = ["web/static/css/style.css", "web/static/js/qrcode.min.js"]
    baseline_ceilings = {
        "web/static/css/style.css": 2991,
        "web/static/js/qrcode.min.js": 1000,
    }

    with patch("scripts.architecture_health.get_tracked_files", return_value=mock_tracked):
        files_data, summary, violations, ratchets = scan_repository(
            repo_root=repo_root,
            baseline_ceilings=baseline_ceilings,
            ceiling_lines=1000,
            warning_lines=500,
        )

        assert len(violations) == 0
        assert len(ratchets) == 0
        assert summary["ceiling_violations_count"] == 0
        assert summary["ratchet_opportunities_count"] == 0

        for f in files_data:
            assert f["is_generated"] is True
            assert f["ceiling_violation"] is False
            assert f["risk_tier"] == "GENERATED"
            assert f["risk_score"] == 0.0


def test_scan_repository_1000_lines_boundary_partitioning(tmp_path: Path) -> None:
    """Verify clean range partitioning around the exact 1,000-line boundary."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    (repo_root / "file_999.go").write_text("\n" * 999, encoding="utf-8")
    (repo_root / "file_1000.go").write_text("\n" * 1000, encoding="utf-8")
    (repo_root / "file_1001.go").write_text("\n" * 1001, encoding="utf-8")
    (repo_root / "file_1500.go").write_text("\n" * 1500, encoding="utf-8")

    mock_tracked = ["file_999.go", "file_1000.go", "file_1001.go", "file_1500.go"]
    baseline_ceilings = {
        "file_999.go": 1000,
        "file_1000.go": 1000,
        "file_1001.go": 1000,
        "file_1500.go": 2000,
    }

    with patch("scripts.architecture_health.get_tracked_files", return_value=mock_tracked):
        files_data, summary, violations, ratchets = scan_repository(
            repo_root=repo_root,
            baseline_ceilings=baseline_ceilings,
            ceiling_lines=1000,
            warning_lines=500,
        )

        f_map = {f["path"]: f for f in files_data}

        # 999 lines: [500, 1000) -> warning
        assert f_map["file_999.go"]["warning_threshold"] is True
        assert f_map["file_999.go"]["grandfathered"] is False
        assert f_map["file_999.go"]["ceiling_violation"] is False

        # 1000 lines: [1000, 1000] -> grandfathered/at-ceiling, no warning
        assert f_map["file_1000.go"]["warning_threshold"] is False
        assert f_map["file_1000.go"]["grandfathered"] is True
        assert f_map["file_1000.go"]["ceiling_violation"] is False

        # 1001 lines: > 1000 -> violation
        assert f_map["file_1001.go"]["warning_threshold"] is False
        assert f_map["file_1001.go"]["grandfathered"] is False
        assert f_map["file_1001.go"]["ceiling_violation"] is True

        # 1500 lines: [1000, 2000] -> grandfathered
        assert f_map["file_1500.go"]["warning_threshold"] is False
        assert f_map["file_1500.go"]["grandfathered"] is True
        assert f_map["file_1500.go"]["ceiling_violation"] is False


def test_scan_repository_line_delta_and_growing_files(tmp_path: Path) -> None:
    """Verify per-file line delta relative to baseline and top growing files identification."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    (repo_root / "growing.go").write_text("\n" * 300, encoding="utf-8")
    (repo_root / "shrunk.go").write_text("\n" * 150, encoding="utf-8")
    (repo_root / "new.go").write_text("\n" * 80, encoding="utf-8")

    mock_tracked = ["growing.go", "shrunk.go", "new.go"]
    baseline_files = {
        "growing.go": {"lines": 200, "ceiling": 1000},
        "shrunk.go": {"lines": 200, "ceiling": 1000},
    }

    with patch("scripts.architecture_health.get_tracked_files", return_value=mock_tracked):
        files_data, summary, _, _ = scan_repository(
            repo_root=repo_root,
            baseline_files=baseline_files,
            ceiling_lines=1000,
            warning_lines=500,
        )

        f_map = {f["path"]: f for f in files_data}
        assert f_map["growing.go"]["line_delta"] == 100
        assert f_map["shrunk.go"]["line_delta"] == -50
        assert f_map["new.go"]["line_delta"] is None

        top_growing = summary["top_growing_files"]
        assert len(top_growing) == 1
        assert top_growing[0]["path"] == "growing.go"
        assert top_growing[0]["line_delta"] == 100

        # Newly added files verification
        assert "newly_added_files" in summary
        newly_added = summary["newly_added_files"]
        assert len(newly_added) == 1
        assert newly_added[0]["path"] == "new.go"
        assert newly_added[0]["lines"] == 80
        assert newly_added[0]["bytes"] == 80
        assert newly_added[0]["component"] == "Other"
        assert summary["newly_added_files_count"] == 1


def test_generate_baseline_upward_ratchet_refusal(tmp_path: Path) -> None:
    """Verify generate_baseline rejects increases on existing baseline without review flag."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "file.go").write_text("\n" * 1500, encoding="utf-8")

    existing_baseline = {
        "ceilings": {"file.go": 1200},
        "files": {"file.go": {"lines": 1200, "ceiling": 1200}},
    }

    mock_meta = ("abcdef1234567890abcdef1234567890abcdef12", "2026-10-19T12:00:00Z", 1792411200)
    with (
        patch("scripts.architecture_health.get_tracked_files", return_value=["file.go"]),
        patch("scripts.architecture_health.get_commit_metadata", return_value=mock_meta),
        patch("scripts.architecture_health.compute_git_churn", return_value=({}, {})),
    ):
        with pytest.raises(ValueError, match="Cannot increase ceilings"):
            generate_baseline(
                repo_root=repo_root,
                existing_baseline=existing_baseline,
                allow_ceiling_increase=False,
            )

        baseline = generate_baseline(
            repo_root=repo_root,
            existing_baseline=existing_baseline,
            allow_ceiling_increase=True,
        )
        assert baseline["ceilings"]["file.go"] == 1500


def test_generate_baseline_carries_renames(tmp_path: Path) -> None:
    """Verify generate_baseline honors renames when validating against existing baseline."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "moved.go").write_text("\n" * 1500, encoding="utf-8")

    existing_baseline = {
        "ceilings": {"old.go": 1500},
        "files": {"old.go": {"lines": 1500, "ceiling": 1500}},
    }

    mock_meta = ("abcdef1234567890abcdef1234567890abcdef12", "2026-10-19T12:00:00Z", 1792411200)
    with (
        patch("scripts.architecture_health.get_tracked_files", return_value=["moved.go"]),
        patch("scripts.architecture_health.get_commit_metadata", return_value=mock_meta),
        patch("scripts.architecture_health.compute_git_churn", return_value=({}, {})),
    ):
        # Renamed file inherits 1500 ceiling, so 1500 lines is not an increase
        baseline = generate_baseline(
            repo_root=repo_root,
            existing_baseline=existing_baseline,
            allow_ceiling_increase=False,
            renames={"moved.go": "old.go"},
        )
        assert baseline["ceilings"]["moved.go"] == 1500
        assert "old.go" not in baseline["ceilings"]


def test_scan_repository_newly_added_files_sorting_and_normal_ceiling(tmp_path: Path) -> None:
    """Verify newly added files are sorted by lines descending and receive normal ceiling check."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    # Small new file (under ceiling)
    (repo_root / "small.go").write_text("\n" * 50, encoding="utf-8")
    # Medium new file (under ceiling)
    (repo_root / "medium.go").write_text("\n" * 300, encoding="utf-8")
    # Huge new file (exceeds default 1000 ceiling -> violation)
    (repo_root / "huge.go").write_text("\n" * 1200, encoding="utf-8")

    mock_tracked = ["small.go", "medium.go", "huge.go"]
    # Empty baseline files/ceilings -> all 3 are newly added
    with patch("scripts.architecture_health.get_tracked_files", return_value=mock_tracked):
        files_data, summary, violations, _ = scan_repository(
            repo_root=repo_root,
            baseline_ceilings={},
            baseline_files={},
            ceiling_lines=1000,
            warning_lines=500,
        )

        # Newly added files should be sorted by lines descending
        newly_added = summary["newly_added_files"]
        assert len(newly_added) == 3
        assert [f["path"] for f in newly_added] == ["huge.go", "medium.go", "small.go"]
        assert newly_added[0]["lines"] == 1200
        assert newly_added[1]["lines"] == 300
        assert newly_added[2]["lines"] == 50

        # Newly added huge.go must still receive normal ceiling check (1200 > 1000)
        assert len(violations) == 1
        assert violations[0]["path"] == "huge.go"
        assert violations[0]["lines"] == 1200
        assert violations[0]["ceiling"] == 1000
        assert violations[0]["excess_lines"] == 200


def test_architecture_baseline_files_exist_at_baseline_commit() -> None:
    """Verify every file in scripts/architecture_baseline.json exists in git at baseline_commit."""
    repo_root = find_repo_root()
    baseline_path = repo_root / "scripts" / "architecture_baseline.json"
    assert baseline_path.exists(), f"Baseline file missing at {baseline_path}"

    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    baseline_commit = data["metadata"]["baseline_commit"]
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", baseline_commit],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    tracked_at_commit = set(proc.stdout.splitlines())

    ceilings = data.get("ceilings", {})
    files = data.get("files", {})

    missing_ceilings = set(ceilings.keys()) - tracked_at_commit
    missing_files = set(files.keys()) - tracked_at_commit

    assert (
        not missing_ceilings
    ), f"Ceiling files not tracked at {baseline_commit}: {missing_ceilings}"
    assert not missing_files, f"Files map entries not tracked at {baseline_commit}: {missing_files}"
