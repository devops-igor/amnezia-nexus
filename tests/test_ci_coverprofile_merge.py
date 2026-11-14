"""Offline tests for the coverage merge used by the sharded CI job (#761).

A merge that silently drops a shard would publish a coverage number that looks
complete while measuring less than the run did, so the merge is tested rather
than trusted.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MERGE_SCRIPT = REPO_ROOT / "scripts" / "merge_coverprofiles.py"


def _load():
    spec = importlib.util.spec_from_file_location("merge_coverprofiles", MERGE_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_disjoint_shards_are_concatenated_under_one_header(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.out", "mode: atomic\nexample.com/a/a.go:1.0,2.0 1 1\n")
    b = _write(tmp_path, "b.out", "mode: atomic\nexample.com/b/b.go:1.0,2.0 1 1\n")

    merged = _load().merge([a, b])

    assert merged.count("mode: atomic") == 1
    assert "example.com/a/a.go" in merged
    assert "example.com/b/b.go" in merged


def test_blocks_on_the_same_line_keep_their_columns(tmp_path: Path) -> None:
    """Two blocks on one line are distinct regions and must both survive.

    Dropping columns rewrites 42.10,42.25 to 42.0,42.0 and merges the two blocks,
    which corrupts both the statistics and any per-line highlighting.
    """
    source = _write(
        tmp_path,
        "a.out",
        "mode: atomic\n"
        "example.com/a/a.go:42.10,42.25 1 1\n"
        "example.com/a/a.go:42.30,42.40 1 0\n",
    )

    merged = _load().merge([source])

    assert "example.com/a/a.go:42.10,42.25 1 1" in merged
    assert "example.com/a/a.go:42.30,42.40 1 0" in merged
    assert "42.0," not in merged, "column information was discarded"


def test_overlapping_blocks_keep_the_highest_count(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.out", "mode: atomic\nexample.com/a/a.go:1.0,2.0 1 0\n")
    b = _write(tmp_path, "b.out", "mode: atomic\nexample.com/a/a.go:1.0,2.0 1 3\n")

    merged = _load().merge([a, b])

    assert "example.com/a/a.go:1.0,2.0 1 3" in merged


def test_mixed_modes_are_rejected(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.out", "mode: atomic\nexample.com/a/a.go:1.0,2.0 1 1\n")
    b = _write(tmp_path, "b.out", "mode: set\nexample.com/b/b.go:1.0,2.0 1 1\n")

    with pytest.raises(ValueError, match="mixed coverage modes"):
        _load().merge([a, b])


def test_missing_profile_is_reported_not_ignored(tmp_path: Path, capsys) -> None:
    module = _load()
    present = _write(tmp_path, "a.out", "mode: atomic\nexample.com/a/a.go:1.0,2.0 1 1\n")
    absent = tmp_path / "missing.out"

    code = module.main([str(tmp_path / "out.out"), str(present), str(absent)])

    assert code == 1
    assert "missing coverage profiles" in capsys.readouterr().err
    assert not (tmp_path / "out.out").exists(), "a partial merge must not be published"


# ── Completeness of the aggregate's inputs ──────────────────────────

CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SHARD_COUNT = 3


def test_aggregate_names_every_shard_profile_explicitly() -> None:
    """A wildcard would silently merge two of three profiles and still succeed."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    for shard in range(1, SHARD_COUNT + 1):
        expected = f"coverage-shards/coverage-shard-{shard}/coverage-shard-{shard}.out"
        assert expected in text, f"aggregate does not require shard {shard} coverage"
    assert "coverage-shards/*" not in text, (
        "the aggregate must not discover coverage with a wildcard"
    )


def test_shard_upload_fails_when_no_profile_is_produced() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "if-no-files-found: error" in text, (
        "a shard that produces no coverage must fail its upload, not upload nothing"
    )
