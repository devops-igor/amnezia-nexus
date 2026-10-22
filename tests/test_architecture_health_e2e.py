"""Hermetic end-to-end and CLI tests for architecture health and ratchet enforcement."""

import json
from pathlib import Path
import subprocess

import pytest

from scripts.architecture_health import (
    load_baseline,
    main,
    save_baseline,
)


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
    # Check should FAIL because new big.go exceeds the 1000 default ceiling
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
    viols = report["ceiling_violations"]
    assert len(viols) == 1
    # Only the new big.go is in violation (1400 > 1000)
    assert viols[0]["path"] == "big.go"
    assert viols[0]["ceiling"] == 1000
    assert viols[0]["excess_lines"] == 400


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
            "metadata": {"baseline_commit": "HEAD"},
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


def test_baseline_save_and_load(tmp_path: Path) -> None:
    """Verify save_baseline and load_baseline persistence fidelity."""
    p = tmp_path / "nested" / "dir" / "baseline.json"
    data = {"metadata": {"repository": "amnezia-nexus"}, "ceilings": {"a.go": 1000}}
    save_baseline(p, data)
    assert p.exists()
    loaded = load_baseline(p)
    assert loaded == data

    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "nonexistent.json")
