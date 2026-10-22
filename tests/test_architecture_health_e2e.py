"""Hermetic end-to-end and CLI tests for architecture health and ratchet enforcement."""

import json
from pathlib import Path
import subprocess

import pytest

from scripts.architecture_health import (
    load_baseline,
    main,
    save_baseline,
    validate_baseline,
)


@pytest.fixture(autouse=True)
def isolate_github_step_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate GITHUB_STEP_SUMMARY environment variable in E2E tests."""
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)


def test_e2e_pure_git_mv_no_violation(tmp_path: Path) -> None:
    """Probe P1: Verify pure git mv transfers ceiling without false violations."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    content = "\n".join(f"func BigFunc{i}() {{}}" for i in range(1500)) + "\n"
    (repo / "big.go").write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "big.go"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--generate-baseline",
            ]
        )
        == 0
    )

    # Move file
    subprocess.run(["git", "mv", "big.go", "moved.go"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "move big to moved"], cwd=repo, check=True, capture_output=True
    )

    # Check must pass: moved.go inherited 1500 ceiling
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--check",
            ]
        )
        == 0
    )


def test_e2e_git_mv_and_new_file_at_old_path(tmp_path: Path) -> None:
    """Probe P2: Verify moving a file and creating new code at the old path enforces default ceiling."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    old_content = "\n".join(f"func OldFunc{i}() {{}}" for i in range(1500)) + "\n"
    (repo / "big.go").write_text(old_content, encoding="utf-8")
    subprocess.run(["git", "add", "big.go"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--generate-baseline",
            ]
        )
        == 0
    )

    # Move big.go to moved.go, and create a brand new big.go with 1400 lines of different code
    subprocess.run(["git", "mv", "big.go", "moved.go"], cwd=repo, check=True)
    new_content = "\n".join(f"func BrandNewFunc{i}() {{}}" for i in range(1400)) + "\n"
    (repo / "big.go").write_text(new_content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "move and replace"], cwd=repo, check=True, capture_output=True
    )

    report_path = repo / "report.json"
    summary_path = repo / "summary.md"
    # Check should FAIL because new big.go exceeds the 1000 default ceiling
    rc = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--report-json",
            str(report_path),
            "--summary-md",
            str(summary_path),
            "--check",
        ]
    )
    assert rc == 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    viols = report["ceiling_violations"]
    assert len(viols) == 1
    # Only the new big.go is in violation (1400 > 1000)
    assert viols[0]["path"] == "big.go"
    assert viols[0]["ceiling"] == 1000
    assert viols[0]["excess_lines"] == 400

    # Newly added file reporting in JSON and Markdown
    assert "newly_added_files" in report
    assert any(f["path"] == "big.go" for f in report["newly_added_files"])
    assert report["summary"]["newly_added_files_count"] >= 1
    md_summary = summary_path.read_text(encoding="utf-8")
    assert "Newly Added Files" in md_summary
    assert "big.go" in md_summary


def test_e2e_decomposition_mv_and_rewrite(tmp_path: Path) -> None:
    """Probe Q2: Verify canonical decomposition flow (mv to legacy + small new file)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    vpn_dir = repo / "internal/vpn"
    vpn_dir.mkdir(parents=True, exist_ok=True)
    vpn_file = vpn_dir / "vpn.go"
    legacy_content = "\n".join(f"func LegacyVPNFunc{i}() {{}}" for i in range(2400)) + "\n"
    vpn_file.write_text(legacy_content, encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init vpn"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--generate-baseline",
            ]
        )
        == 0
    )

    # Decompose: move vpn.go -> vpn_legacy.go, and create a fresh 200-line vpn.go
    subprocess.run(
        ["git", "mv", "internal/vpn/vpn.go", "internal/vpn/vpn_legacy.go"],
        cwd=repo,
        check=True,
    )
    new_vpn_content = "\n".join(f"func NewOrchestrator{i}() {{}}" for i in range(200)) + "\n"
    vpn_file.write_text(new_vpn_content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "decompose vpn"], cwd=repo, check=True, capture_output=True
    )

    # Both files pass cleanly: legacy gets 2400, new gets default 1000
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--check",
            ]
        )
        == 0
    )

    # Now grow new vpn.go to 1200 lines: must trigger violation against 1000 ceiling
    grown_content = "\n".join(f"func GrownOrchestrator{i}() {{}}" for i in range(1200)) + "\n"
    vpn_file.write_text(grown_content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "grow new vpn"], cwd=repo, check=True, capture_output=True
    )

    report_path = repo / "report.json"
    rc = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--report-json",
            str(report_path),
            "--check",
        ]
    )
    assert rc == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["ceiling_violations_count"] == 1
    assert report["ceiling_violations"][0]["path"] == "internal/vpn/vpn.go"
    assert report["ceiling_violations"][0]["ceiling"] == 1000


def test_e2e_cli_fail_closed_on_corrupt_baseline(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Probe P5b: Verify fail-closed behavior on corrupted baseline file."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    (repo / "main.go").write_text("\n" * 100, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    # Write corrupted baseline with merge conflict markers
    base_file.write_text(
        "<<<<<<< HEAD\n{\n  'ceilings': {}\n}\n=======\n>>>>>>> branch\n", encoding="utf-8"
    )

    # 1. generate-baseline without --allow-ceiling-increase MUST fail closed with exit code 1
    rc_gen = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--generate-baseline",
        ]
    )
    assert rc_gen == 1

    # 2. generate-baseline WITH --allow-ceiling-increase overwrites and returns 0
    rc_gen_allowed = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--generate-baseline",
            "--allow-ceiling-increase",
        ]
    )
    assert rc_gen_allowed == 0
    assert base_file.exists()
    loaded = load_baseline(base_file)
    assert "ceilings" in loaded

    # 3. Check scan on corrupt baseline MUST fail closed with exit code 1 even with --nonblocking
    base_file.write_text("not json at all", encoding="utf-8")
    rc_check = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--check",
            "--nonblocking",
        ]
    )
    assert rc_check == 1


def test_e2e_downward_ratchet_warning_annotations(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Probe P7: Verify downward ratchet emits ::warning annotations and updates baseline."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    vpn_file = repo / "vpn.go"
    vpn_file.write_text("\n" * 2400, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--generate-baseline",
            ]
        )
        == 0
    )

    # Shrink file from 2400 to 1800
    vpn_file.write_text("\n" * 1800, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "shrink"], cwd=repo, check=True, capture_output=True)

    caplog.clear()
    rc = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--check",
        ]
    )
    assert rc == 0
    assert any(
        "::warning file=vpn.go::Downward ratchet pending" in rec.message for rec in caplog.records
    )

    # Run --ratchet to lock in the reduction
    rc_ratchet = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--ratchet",
        ]
    )
    assert rc_ratchet == 0
    updated = load_baseline(base_file)
    assert updated["ceilings"]["vpn.go"] == 1800


def test_e2e_nonblocking_operational_vs_advisory_exit_codes(tmp_path: Path) -> None:
    """Verify nonblocking returns 0 on advisory violations but 1 on operational errors."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    (repo / "oversized.go").write_text("\n" * 1500, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    # Save baseline with 1000 ceiling
    save_baseline(
        base_file,
        {
            "metadata": {
                "baseline_commit": "HEAD",
                "reference_timestamp": "2026-10-22T00:00:00Z",
                "reference_timestamp_epoch": 1792627200,
            },
            "ceilings": {"oversized.go": 1000},
            "files": {"oversized.go": {"lines": 1000, "ceiling": 1000}},
        },
    )

    # Blocking scan returns 1
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--check",
            ]
        )
        == 1
    )

    # Nonblocking scan returns 0 on advisory violations
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--check",
                "--nonblocking",
            ]
        )
        == 0
    )

    # Operational error (corrupt baseline) returns 1 even with --nonblocking
    base_file.write_text("corrupted json", encoding="utf-8")
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--check",
                "--nonblocking",
            ]
        )
        == 1
    )

    # Operational error (missing baseline) returns 1 even with --nonblocking
    missing_file = repo / "nonexistent.json"
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(missing_file),
                "--check",
                "--nonblocking",
            ]
        )
        == 1
    )

    # Operational error during scan (unknown commit) returns 1 even with --nonblocking
    save_baseline(
        base_file,
        {
            "metadata": {
                "baseline_commit": "0000000000000000000000000000000000000000",
                "reference_timestamp": "2026-10-22T00:00:00Z",
                "reference_timestamp_epoch": 100000,
            },
            "ceilings": {"oversized.go": 1000},
            "files": {"oversized.go": {"lines": 1000, "ceiling": 1000}},
        },
    )
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--check",
                "--nonblocking",
            ]
        )
        == 1
    )


def test_baseline_save_and_load(tmp_path: Path) -> None:
    """Verify save_baseline and load_baseline persistence fidelity."""
    p = tmp_path / "nested" / "dir" / "baseline.json"
    data = {
        "metadata": {
            "repository": "amnezia-nexus",
            "baseline_commit": "3eea2b6fe0381d8dfe1ec693a9b12bacb1738e6f",
            "reference_timestamp": "2026-10-22T09:42:52Z",
            "reference_timestamp_epoch": 1792662172,
        },
        "ceilings": {"a.go": 1000},
        "files": {"a.go": {"lines": 10, "ceiling": 1000}},
    }
    save_baseline(p, data)
    assert p.exists()
    loaded = load_baseline(p)
    assert loaded == data

    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "nonexistent.json")


def test_validate_baseline_structural_completeness(tmp_path: Path) -> None:
    """Verify structural completeness validation on baseline load."""
    # Empty baseline object
    with pytest.raises(ValueError, match="Baseline data is empty"):
        validate_baseline({})

    # None or non-dict
    with pytest.raises(ValueError, match="Baseline data is empty"):
        validate_baseline(None)

    # Missing metadata
    with pytest.raises(ValueError, match="missing or has empty 'metadata'"):
        validate_baseline({"ceilings": {"a.go": 1000}, "files": {"a.go": {}}})

    # Empty metadata dict
    with pytest.raises(ValueError, match="missing or has empty 'metadata'"):
        validate_baseline({"metadata": {}, "ceilings": {"a.go": 1000}, "files": {"a.go": {}}})

    # Missing baseline_commit
    with pytest.raises(ValueError, match="missing a valid 'baseline_commit'"):
        validate_baseline(
            {
                "metadata": {
                    "repository": "amnezia-nexus",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                    "reference_timestamp_epoch": 1792662172,
                },
                "ceilings": {"a.go": 1000},
                "files": {"a.go": {}},
            }
        )

    # Whitespace baseline_commit
    with pytest.raises(ValueError, match="missing a valid 'baseline_commit'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "   ",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                    "reference_timestamp_epoch": 1792662172,
                },
                "ceilings": {"a.go": 1000},
                "files": {"a.go": {}},
            }
        )

    # Missing reference_timestamp_epoch
    with pytest.raises(ValueError, match="missing a valid 'reference_timestamp_epoch'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "3eea2b6fe0",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                },
                "ceilings": {"a.go": 1000},
                "files": {"a.go": {}},
            }
        )

    # Invalid reference_timestamp_epoch (non-positive / boolean / non-numeric)
    for invalid_epoch in [0, -100, True, False, "1792662172", None]:
        with pytest.raises(ValueError, match="missing a valid 'reference_timestamp_epoch'"):
            validate_baseline(
                {
                    "metadata": {
                        "baseline_commit": "3eea2b6fe0",
                        "reference_timestamp": "2026-10-22T09:42:52Z",
                        "reference_timestamp_epoch": invalid_epoch,
                    },
                    "ceilings": {"a.go": 1000},
                    "files": {"a.go": {}},
                }
            )

    # Missing reference_timestamp
    with pytest.raises(ValueError, match="missing a valid 'reference_timestamp'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "3eea2b6fe0",
                    "reference_timestamp_epoch": 1792662172,
                },
                "ceilings": {"a.go": 1000},
                "files": {"a.go": {}},
            }
        )

    # Whitespace or invalid reference_timestamp
    for invalid_ts in ["", "   ", 12345, None]:
        with pytest.raises(ValueError, match="missing a valid 'reference_timestamp'"):
            validate_baseline(
                {
                    "metadata": {
                        "baseline_commit": "3eea2b6fe0",
                        "reference_timestamp_epoch": 1792662172,
                        "reference_timestamp": invalid_ts,
                    },
                    "ceilings": {"a.go": 1000},
                    "files": {"a.go": {}},
                }
            )

    # Missing ceilings
    with pytest.raises(ValueError, match="missing or has empty 'ceilings'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "3eea2b6fe0",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                    "reference_timestamp_epoch": 1792662172,
                },
                "files": {"a.go": {"lines": 100, "ceiling": 1000}},
            }
        )

    # Empty ceilings dict
    with pytest.raises(ValueError, match="missing or has empty 'ceilings'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "3eea2b6fe0",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                    "reference_timestamp_epoch": 1792662172,
                },
                "ceilings": {},
                "files": {"a.go": {"lines": 100, "ceiling": 1000}},
            }
        )

    # Missing files
    with pytest.raises(ValueError, match="missing or has empty 'files'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "3eea2b6fe0",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                    "reference_timestamp_epoch": 1792662172,
                },
                "ceilings": {"a.go": 1000},
            }
        )

    # Empty files dict
    with pytest.raises(ValueError, match="missing or has empty 'files'"):
        validate_baseline(
            {
                "metadata": {
                    "baseline_commit": "3eea2b6fe0",
                    "reference_timestamp": "2026-10-22T09:42:52Z",
                    "reference_timestamp_epoch": 1792662172,
                },
                "ceilings": {"a.go": 1000},
                "files": {},
            }
        )

    # Valid baseline structure
    valid = {
        "metadata": {
            "baseline_commit": "3eea2b6fe0381d8dfe1ec693a9b12bacb1738e6f",
            "reference_timestamp": "2026-10-22T09:42:52Z",
            "reference_timestamp_epoch": 1792662172,
        },
        "ceilings": {"a.go": 1000},
        "files": {"a.go": {"lines": 100, "ceiling": 1000}},
    }
    validate_baseline(valid)

    # Valid baseline structure with float epoch
    valid_float = dict(valid)
    valid_float["metadata"] = dict(valid["metadata"])
    valid_float["metadata"]["reference_timestamp_epoch"] = 1792662172.5
    validate_baseline(valid_float)

    # File-level load_baseline failure on empty object
    empty_file = tmp_path / "empty_baseline.json"
    empty_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Baseline data is empty"):
        load_baseline(empty_file)


def test_e2e_cli_fail_closed_on_empty_or_incomplete_baseline(tmp_path: Path) -> None:
    """Verify CLI fails closed with exit code 1 on empty or incomplete baseline."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    (repo / "main.go").write_text("\n" * 100, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"

    # 1. Baseline is literally {}
    base_file.write_text("{}", encoding="utf-8")

    # --check blocking must exit 1
    rc_check = main(["--repo-root", str(repo), "--baseline-file", str(base_file), "--check"])
    assert rc_check == 1

    # --check nonblocking must exit 1 (fails closed)
    rc_check_nb = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--check",
            "--nonblocking",
        ]
    )
    assert rc_check_nb == 1

    # --generate-baseline without --allow-ceiling-increase must exit 1
    rc_gen = main(
        ["--repo-root", str(repo), "--baseline-file", str(base_file), "--generate-baseline"]
    )
    assert rc_gen == 1

    # --generate-baseline with --allow-ceiling-increase succeeds and creates valid baseline
    rc_gen_allowed = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--generate-baseline",
            "--allow-ceiling-increase",
        ]
    )
    assert rc_gen_allowed == 0
    assert base_file.exists()
    loaded = load_baseline(base_file)
    assert "metadata" in loaded
    assert "baseline_commit" in loaded["metadata"]
    assert "reference_timestamp" in loaded["metadata"]
    assert "reference_timestamp_epoch" in loaded["metadata"]
    assert "ceilings" in loaded
    assert "files" in loaded

    # Re-generating over an existing valid baseline exercises load_baseline validation path
    rc_gen_existing = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--generate-baseline",
        ]
    )
    assert rc_gen_existing == 0

    # 2. Baseline is incomplete: {"metadata": {"baseline_commit": ""}, "ceilings": {}}
    base_file.write_text(
        json.dumps({"metadata": {"baseline_commit": ""}, "ceilings": {}}),
        encoding="utf-8",
    )
    rc_incomplete = main(
        [
            "--repo-root",
            str(repo),
            "--baseline-file",
            str(base_file),
            "--check",
            "--nonblocking",
        ]
    )
    assert rc_incomplete == 1


def test_e2e_cli_fail_closed_on_missing_timestamp_or_files_map(tmp_path: Path) -> None:
    """Verify CLI --check --nonblocking fails closed (exit code 1) on missing timestamp or files map."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    (repo / "main.go").write_text("\n" * 100, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    base_file = repo / "baseline.json"
    cmd_check = [
        "--repo-root",
        str(repo),
        "--baseline-file",
        str(base_file),
        "--check",
        "--nonblocking",
    ]

    incomplete_baselines = [
        # Missing reference_timestamp_epoch
        {
            "metadata": {"baseline_commit": "HEAD", "reference_timestamp": "2026-10-22T09:42:52Z"},
            "ceilings": {"main.go": 1000},
            "files": {"main.go": {"lines": 100, "ceiling": 1000}},
        },
        # Invalid reference_timestamp_epoch (<= 0)
        {
            "metadata": {
                "baseline_commit": "HEAD",
                "reference_timestamp": "2026-10-22T09:42:52Z",
                "reference_timestamp_epoch": 0,
            },
            "ceilings": {"main.go": 1000},
            "files": {"main.go": {"lines": 100, "ceiling": 1000}},
        },
        # Missing reference_timestamp string
        {
            "metadata": {"baseline_commit": "HEAD", "reference_timestamp_epoch": 1792662172},
            "ceilings": {"main.go": 1000},
            "files": {"main.go": {"lines": 100, "ceiling": 1000}},
        },
        # Missing files map
        {
            "metadata": {
                "baseline_commit": "HEAD",
                "reference_timestamp": "2026-10-22T09:42:52Z",
                "reference_timestamp_epoch": 1792662172,
            },
            "ceilings": {"main.go": 1000},
        },
        # Empty files map
        {
            "metadata": {
                "baseline_commit": "HEAD",
                "reference_timestamp": "2026-10-22T09:42:52Z",
                "reference_timestamp_epoch": 1792662172,
            },
            "ceilings": {"main.go": 1000},
            "files": {},
        },
        # Sample incomplete baseline from finding
        {"metadata": {"baseline_commit": "HEAD"}, "ceilings": {"main.go": 1000}},
    ]

    for payload in incomplete_baselines:
        base_file.write_text(json.dumps(payload), encoding="utf-8")
        assert main(cmd_check) == 1

    # Also verify --generate-baseline fails closed over incomplete baseline without --allow-ceiling-increase
    cmd_gen = ["--repo-root", str(repo), "--baseline-file", str(base_file), "--generate-baseline"]
    assert main(cmd_gen) == 1


def test_e2e_renamed_grandfathered_file_satisfies_invariant_after_ratchet(tmp_path: Path) -> None:
    """Verify that a renamed grandfathered file after --ratchet satisfies baseline invariants."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    # 1. Create grandfathered file with 1500 lines (> 1000 ceiling threshold)
    content = "\n".join(f"func BigFunc{i}() {{}}" for i in range(1500)) + "\n"
    (repo / "grandfathered.go").write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "grandfathered.go"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init baseline commit"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    base_file = repo / "scripts" / "architecture_baseline.json"
    base_file.parent.mkdir(parents=True, exist_ok=True)

    # 2. Generate initial baseline at commit B
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--generate-baseline",
            ]
        )
        == 0
    )

    data_initial = json.loads(base_file.read_text(encoding="utf-8"))
    initial_commit = data_initial["metadata"]["baseline_commit"]
    assert "grandfathered.go" in data_initial["ceilings"]
    assert data_initial["ceilings"]["grandfathered.go"] == 1500

    # 3. Rename grandfathered file and commit the rename
    subprocess.run(["git", "mv", "grandfathered.go", "renamed_service.go"], cwd=repo, check=True)
    content_reduced = "\n".join(f"func BigFunc{i}() {{}}" for i in range(1450)) + "\n"
    (repo / "renamed_service.go").write_text(content_reduced, encoding="utf-8")
    subprocess.run(["git", "add", "renamed_service.go"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "rename grandfathered file and reduce lines"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    # 4. Run --ratchet to update ceiling for renamed path
    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--baseline-file",
                str(base_file),
                "--ratchet",
            ]
        )
        == 0
    )

    data_ratcheted = json.loads(base_file.read_text(encoding="utf-8"))

    # Confirm baseline_commit remained at initial_commit B
    assert data_ratcheted["metadata"]["baseline_commit"] == initial_commit
    assert "renamed_service.go" in data_ratcheted["ceilings"]
    assert data_ratcheted["ceilings"]["renamed_service.go"] == 1450
    assert "grandfathered.go" not in data_ratcheted["ceilings"]

    # 5. Invariant check MUST pass on the ratcheted baseline
    from tests.test_architecture_health_policy import check_baseline_invariants

    stray_ceilings, stray_files = check_baseline_invariants(data_ratcheted, repo)
    assert not stray_ceilings
    assert not stray_files

    # 6. Verify an unreviewed new file (ceiling <= 1000) added to baseline is caught
    corrupt_data = json.loads(json.dumps(data_ratcheted))
    corrupt_data["ceilings"]["unreviewed_branch_tool.py"] = 1000
    corrupt_data["files"]["unreviewed_branch_tool.py"] = {"lines": 50, "ceiling": 1000}

    stray_c, stray_f = check_baseline_invariants(corrupt_data, repo)
    assert "unreviewed_branch_tool.py" in stray_c
    assert "unreviewed_branch_tool.py" in stray_f
