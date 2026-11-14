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
import shlex
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
# Shell command separators: a selection only counts in the segment that runs it.
_SEGMENT_RE = re.compile(r"&&|\|\||;|\|")
# Words that may precede the command without changing which command runs.
_COMMAND_PREFIXES = frozenset({"if", "then", "elif", "else", "do", "while", "until", "!", "time"})
# Wrappers that run their argument as the command.
_COMMAND_WRAPPERS = frozenset({"sudo", "command", "exec", "env"})
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# A YAML step key ("run:" or "- run:") precedes the shell command.
_RUN_KEY_RE = re.compile(r"^\s*(?:-\s*)?run:\s*")
# The panel harness selects suites through E2E_PATHS and forwards them to pytest.
# That is a real selection, but only where the same job executes the harness, so
# the value is read only from text whose command segment runs the script.
_E2E_PATHS_RE = re.compile(r"^\s*E2E_PATHS:\s*(.+)$", re.MULTILINE)
# A top-level job key, used to keep E2E_PATHS and its invocation in one job.
_JOB_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)


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


def _command_tokens(segment: str) -> list[str]:
    """Return tokens from the command word onward.

    Control-flow words, variable assignments, wrappers and leading flags are
    consumed first, so ``sudo -E FOO=1 python3 -m pytest`` resolves to
    ``python3``. An unreadable segment yields no tokens, which the callers treat
    as "not an invocation" — the safe direction.
    """
    try:
        tokens = shlex.split(segment, comments=False)
    except ValueError:
        return []

    index = 0
    while index < len(tokens) and tokens[index] in _COMMAND_PREFIXES:
        index += 1
    while index < len(tokens) and (
        tokens[index] in _COMMAND_WRAPPERS
        or _ASSIGNMENT_RE.match(tokens[index])
        or tokens[index].startswith("-")
    ):
        index += 1
    return tokens[index:]


def _segments(text: str):
    """Yield the command segments of a text, with run keys and continuations handled."""
    for line in _logical_lines(text):
        # A workflow step writes `run: pytest ...`; the key is not the command.
        line = _RUN_KEY_RE.sub("", line, count=1)
        yield from _SEGMENT_RE.split(line)


def _invokes_pytest(segment: str) -> bool:
    """Return whether this command segment actually runs pytest.

    Substring presence is not enough: ``echo "pytest tests/x.py"`` mentions
    pytest but runs echo. The command word is resolved past control-flow words,
    variable assignments and wrappers, then checked directly.

    A line this parser cannot read is treated as *not* a selection. That is the
    safe direction: an unparsed real invocation shows up as an unwired suite and
    fails the guard, whereas a parsed mention would hide one.
    """
    tokens = _command_tokens(segment)
    if not tokens:
        return False
    if tokens[0] == "pytest":
        return True
    return tokens[0] in ("python", "python3") and tokens[1:3] == ["-m", "pytest"]


def _runs_script(segment: str, script: str) -> bool:
    """Return whether this command segment executes ``script``.

    Executes, not mentions: ``echo ./scripts/run_e2e.sh`` runs echo. A shell
    wrapper is accepted (``bash -e ./scripts/run_e2e.sh``) because it still runs
    the script, and its own exit status is the segment's.
    """
    tokens = _command_tokens(segment)
    if not tokens:
        return False
    if tokens[0].endswith(script):
        return True
    if tokens[0] in ("bash", "sh"):
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            return token.endswith(script)
    return False


def invokes_script(text: str, script: str = "scripts/run_e2e.sh") -> bool:
    """Return whether this text executes ``script`` anywhere."""
    return any(_runs_script(segment, script) for segment in _segments(text))


def selections_from_text(text: str) -> set[str]:
    """Return the repository-relative test paths this text actually selects.

    Only the command segment that runs pytest contributes paths, so a path in an
    echo, a comment, an artifact upload or prose is not a selection.
    """
    found: set[str] = set()
    for segment in _segments(text):
        if _invokes_pytest(segment):
            found.update(_TEST_PATH_RE.findall(segment))
    return found


def _job_blocks(text: str) -> list[str]:
    """Split a workflow into its top-level job blocks.

    E2E_PATHS is job-scoped, so the harness invocation that gives it meaning has
    to be in the same job; otherwise a mention in one job would cover a
    selection declared in another.
    """
    matches = list(_JOB_KEY_RE.finditer(text))
    if not matches:
        return [text]
    blocks = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks.append(text[match.start() : end])
    return blocks


def harness_selections_from_text(text: str) -> set[str]:
    """Return suites a workflow hands to the shared harness via E2E_PATHS.

    An E2E_PATHS value on its own is a mention: it selects nothing unless the
    same job actually runs ``scripts/run_e2e.sh``, which is what forwards it to
    pytest. Both facts are read from the text, so neither has to be trusted.
    """
    found: set[str] = set()
    for block in _job_blocks(text):
        if not invokes_script(block):
            continue
        for match in _E2E_PATHS_RE.finditer(block):
            found.update(_TEST_PATH_RE.findall(match.group(1)))
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
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        patterns |= selections_from_text(text)
        patterns |= harness_selections_from_text(text)
    for source in sorted(SCRIPTS.glob("*.sh")):
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


def test_an_echo_of_a_pytest_command_is_not_coverage() -> None:
    """The reported case: the word pytest inside a quoted argument is not a run."""
    assert selections_from_text('echo "pytest tests/test_unwired.py"\n') == set()


def test_a_mention_after_the_command_is_not_coverage() -> None:
    assert selections_from_text("true && echo pytest tests/test_unwired.py\n") == set()


def test_a_pytest_selection_is_coverage() -> None:
    assert selections_from_text("pytest tests/test_new_contract.py -q\n") == {
        "tests/test_new_contract.py"
    }


def test_pytest_behind_control_flow_assignments_and_wrappers_is_coverage() -> None:
    for text in (
        "if pytest tests/test_new_contract.py; then\n",
        "FOO=1 BAR=2 pytest tests/test_new_contract.py\n",
        "sudo -E python3 -m pytest tests/test_new_contract.py\n",
        "cd repo && pytest tests/test_new_contract.py\n",
    ):
        assert selections_from_text(text) == {"tests/test_new_contract.py"}, text


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


def test_harness_env_selection_counts_only_when_the_harness_runs() -> None:
    """E2E_PATHS is a selection only where run_e2e.sh consumes it."""
    selection = "E2E_PATHS: tests/e2e/test_auth.py tests/e2e/test_settings.py\n"
    assert harness_selections_from_text(selection) == set()

    with_harness = selection + "run: ./scripts/run_e2e.sh\n"
    assert harness_selections_from_text(with_harness) == {
        "tests/e2e/test_auth.py",
        "tests/e2e/test_settings.py",
    }


def test_a_mention_of_the_harness_is_not_an_invocation() -> None:
    """`echo ./scripts/run_e2e.sh` names the harness but runs echo."""
    assert not invokes_script("run: echo ./scripts/run_e2e.sh\n")
    assert not invokes_script("run: true && echo scripts/run_e2e.sh\n")
    assert invokes_script("run: ./scripts/run_e2e.sh\n")
    assert invokes_script("run: bash -e scripts/run_e2e.sh\n")


def test_harness_env_selection_requires_an_invocation_in_the_same_job() -> None:
    """E2E_PATHS in one job is not covered by a harness mention in another."""
    mentioned = """\
jobs:
  e2e-hosted:
    steps:
      - run: |
          E2E_PATHS: tests/e2e/test_auth.py
      - run: echo ./scripts/run_e2e.sh
"""
    assert harness_selections_from_text(mentioned) == set()

    executed = mentioned.replace("echo ./scripts/run_e2e.sh", "./scripts/run_e2e.sh")
    assert harness_selections_from_text(executed) == {"tests/e2e/test_auth.py"}
