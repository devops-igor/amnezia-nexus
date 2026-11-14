"""Guards for the Go test shard assignment (issue #761).

Sharding is only safe if it cannot lose a package. These tests assert that the
assignment covers every package exactly once, that the measured split is
actually balanced, and that the workflow runs the assignment rather than a
hand-written list.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SHARD_SCRIPT = REPO_ROOT / "scripts" / "ci_go_shards.py"
WEIGHTS_FILE = REPO_ROOT / "scripts" / "ci_go_shard_weights.json"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SHARD_COUNT = 3


def _load_module():
    spec = importlib.util.spec_from_file_location("ci_go_shards", SHARD_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _shards():
    module = _load_module()
    return module, module.assign(module.go_packages(), module.load_weights(), SHARD_COUNT)


def test_every_package_is_assigned_exactly_once() -> None:
    module, buckets = _shards()
    assigned = [package for bucket in buckets for package in bucket]
    expected = set(module.go_packages())

    assert len(assigned) == len(set(assigned)), "a package is assigned to more than one shard"
    missing = sorted(expected - set(assigned))
    assert not missing, f"packages assigned to no shard: {missing}"
    unexpected = sorted(set(assigned) - expected)
    assert not unexpected, f"shards reference unknown packages: {unexpected}"


def test_shards_are_balanced_by_measured_weight() -> None:
    """An unbalanced split would leave one shard as the critical path."""
    module, buckets = _shards()
    weights = module.load_weights()
    loads = [sum(weights.get(p, module.DEFAULT_WEIGHT) for p in bucket) for bucket in buckets]

    assert min(loads) > 0
    ratio = max(loads) / min(loads)
    assert ratio <= 1.25, f"shard loads are unbalanced ({[round(x, 1) for x in loads]})"


def test_weights_only_reference_known_packages() -> None:
    """A stale weight is a package that was renamed or removed; fail loudly."""
    module = _load_module()
    weights = module.load_weights()
    packages = set(module.go_packages())
    stale = sorted(set(weights) - packages)
    assert not stale, f"weights reference packages that no longer exist: {stale}"


def test_weights_are_measured_not_guessed() -> None:
    data = json.loads(WEIGHTS_FILE.read_text(encoding="utf-8"))
    assert "note" in data and "Measured" in data["note"], (
        "the weights file must record which run and step it was measured from"
    )
    assert data["weights"], "the weights file must not be empty"


def test_workflow_runs_the_shard_assignment() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/ci_go_shards.py" in text, (
        "the workflow must derive its package list from the shard script, not a "
        "hand-written list that can drift from go list"
    )
    assert f"--shards {SHARD_COUNT}" in text
