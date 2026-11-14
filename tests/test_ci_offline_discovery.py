"""Every test suite must be wired to a workflow, or explicitly excused.

Issue #762: two offline suites — and the guards protecting them — were merged
into the repository but referenced by no workflow, so they never ran. A green
check on a job that does not collect a file is indistinguishable from a passing
file, which is how a guard can look like protection while protecting nothing.

This inventory fails when a suite is added without being wired to a workflow.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Suites deliberately not wired to a workflow. An entry here is a recorded gap,
# not a permission: each one must name the issue that tracks closing it.
EXCUSED: dict[str, str] = {}


def _tracked(paths: list[str]) -> set[str] | None:
    """Return git-tracked paths, or None when git is unavailable."""
    result = subprocess.run(
        ["git", "ls-files", *paths], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return None
    return set(result.stdout.split())


def _referenced_patterns() -> set[str]:
    """Every test path or glob named by a workflow or a script it invokes.

    The DEV lifecycle names its suites in scripts/run_e2e_lifecycle.sh rather
    than in the workflow, so scanning YAML alone would report those as unwired.
    """
    patterns: set[str] = set()
    sources = sorted(WORKFLOWS.glob("*.yml")) + sorted((REPO_ROOT / "scripts").glob("*.sh"))
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for match in re.findall(r"tests/(?:e2e/)?test_[\w*.]+\.py", text):
            patterns.add(Path(match).name)
    return patterns


def _suites():
    """Yield tracked suite files from tests/ and tests/e2e/."""
    tracked = _tracked(["tests", "tests/e2e"])
    candidates = sorted((REPO_ROOT / "tests").glob("test_*.py"))
    candidates += sorted((REPO_ROOT / "tests" / "e2e").glob("test_*.py"))
    for path in candidates:
        rel = path.relative_to(REPO_ROOT).as_posix()
        if tracked is not None and rel not in tracked:
            continue
        yield path


def test_every_suite_is_wired_or_explicitly_excused() -> None:
    patterns = _referenced_patterns()
    unwired = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _suites()
        if not any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns)
        and path.name not in EXCUSED
    ]
    assert not unwired, (
        "these suites are not run by any workflow, so they cannot fail CI: "
        + ", ".join(unwired)
    )


def test_excused_suites_are_still_unwired() -> None:
    """An excuse that is no longer true must be deleted, not left to rot."""
    patterns = _referenced_patterns()
    stale = [
        name
        for name in EXCUSED
        if any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
    ]
    assert not stale, "these suites are now wired; remove their excuse: " + ", ".join(stale)


def test_every_excuse_names_a_tracking_issue() -> None:
    for name, reason in EXCUSED.items():
        assert re.search(r"#\d+", reason), f"excuse for {name} must name a tracking issue"
