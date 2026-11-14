"""Every test suite must be wired to a workflow, or explicitly excused.

Issue #762: two offline suites — and the guards protecting them — were merged
into the repository but referenced by no workflow, so they never ran. A green
check on a job that does not collect a file is indistinguishable from a passing
file, which is how a guard can look like protection while protecting nothing.

A mention is not coverage. This inventory only counts repository-relative test
paths that appear on a line selecting tests (a ``pytest`` invocation, with shell
line-continuations joined and comments removed), and it compares full paths so
two suites sharing a basename cannot alias each other.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCRIPTS = REPO_ROOT / "scripts"

# Suites deliberately not wired to a workflow. An entry here is a recorded gap,
# not a permission: each one must name the issue that tracks closing it.
EXCUSED: dict[str, str] = {}

_TEST_PATH_RE = re.compile(r"tests/(?:e2e/)?test_[\w*.]+\.py")
# A comment is not a test selection. Strip from the first unquoted-looking '#'
# that starts a comment (preceded by whitespace or at the start of the line).
_COMMENT_RE = re.compile(r"(^|\s)#.*$")


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop comments."""
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = _COMMENT_RE.sub(r"\1", raw).rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        lines.append(buffer)
        buffer = ""
    if buffer:
        lines.append(buffer)
    return lines


def selections_from_text(text: str) -> set[str]:
    """Return the repository-relative test paths this text actually selects.

    Only a line that invokes pytest counts. A path mentioned in a comment, an
    echo, an artifact upload path or prose is not a selection.
    """
    found: set[str] = set()
    for line in _logical_lines(text):
        if "pytest" not in line:
            continue
        found.update(_TEST_PATH_RE.findall(line))
    return found


def _tracked(paths: list[str]) -> set[str] | None:
    """Return git-tracked paths, or None when git is unavailable."""
    result = subprocess.run(
        ["git", "ls-files", *paths], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return None
    return set(result.stdout.split())


def _selected_patterns() -> set[str]:
    """Every test path or glob selected by a workflow or an invoked script.

    Scripts are included because the DEV lifecycle names its suites in
    scripts/run_e2e_lifecycle.sh rather than in the workflow.
    """
    patterns: set[str] = set()
    sources = sorted(WORKFLOWS.glob("*.yml")) + sorted(SCRIPTS.glob("*.sh"))
    for source in sources:
        patterns |= selections_from_text(source.read_text(encoding="utf-8"))
    return patterns


def _suites():
    """Yield tracked suite files from tests/ and tests/e2e/ as repo-relative paths."""
    tracked = _tracked(["tests", "tests/e2e"])
    candidates = sorted((REPO_ROOT / "tests").glob("test_*.py"))
    candidates += sorted((REPO_ROOT / "tests" / "e2e").glob("test_*.py"))
    for path in candidates:
        rel = path.relative_to(REPO_ROOT).as_posix()
        if tracked is not None and rel not in tracked:
            continue
        yield rel


def test_every_suite_is_wired_or_explicitly_excused() -> None:
    patterns = _selected_patterns()
    unwired = [
        rel
        for rel in _suites()
        if not any(fnmatch.fnmatch(rel, pattern) for pattern in patterns)
        and Path(rel).name not in EXCUSED
    ]
    assert not unwired, (
        "these suites are not run by any workflow, so they cannot fail CI: "
        + ", ".join(unwired)
    )


def test_excused_suites_are_still_unwired() -> None:
    """An excuse that is no longer true must be deleted, not left to rot."""
    patterns = _selected_patterns()
    stale = [
        name
        for name in EXCUSED
        if any(fnmatch.fnmatch(f"tests/{name}", pattern) for pattern in patterns)
    ]
    assert not stale, "these suites are now wired; remove their excuse: " + ", ".join(stale)


def test_every_excuse_names_a_tracking_issue() -> None:
    for name, reason in EXCUSED.items():
        assert re.search(r"#\d+", reason), f"excuse for {name} must name a tracking issue"


# ── The selection parser itself ─────────────────────────────────────


def test_a_comment_mention_is_not_coverage() -> None:
    """The exact false positive the review found: a TODO must not count."""
    text = "# TODO: run tests/test_new_contract.py\n"
    assert selections_from_text(text) == set()


def test_an_echo_mention_is_not_coverage() -> None:
    assert selections_from_text('echo "remember tests/test_new_contract.py"\n') == set()


def test_a_pytest_selection_is_coverage() -> None:
    assert selections_from_text("pytest tests/test_new_contract.py -q\n") == {
        "tests/test_new_contract.py"
    }


def test_a_multiline_selection_is_coverage() -> None:
    text = "python -m pytest -p no:cacheprovider \\\n  tests/test_one.py \\\n  tests/test_two.py\n"
    assert selections_from_text(text) == {"tests/test_one.py", "tests/test_two.py"}


def test_shell_variable_prefix_is_coverage() -> None:
    text = 'if pytest "$REPO_ROOT/tests/e2e/test_auth.py" -m e2e; then\n'
    assert selections_from_text(text) == {"tests/e2e/test_auth.py"}


def test_same_basename_in_two_directories_is_not_aliased() -> None:
    """A suite in tests/e2e must not be covered by selecting tests/."""
    text = "pytest tests/test_shared_name.py\n"
    selected = selections_from_text(text)
    assert not any(fnmatch.fnmatch("tests/e2e/test_shared_name.py", p) for p in selected)


def test_globs_are_preserved() -> None:
    assert selections_from_text("python -m pytest tests/test_arch*.py\n") == {
        "tests/test_arch*.py"
    }
