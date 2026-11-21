"""Tests for the pull-request SG1 size gate.

Every size case builds a real git repository with exact physical line counts at
the merge base and at the head, because an off-by-one at the 1,000-line boundary
is the most likely defect in this comparison and a fixture that is "about a
thousand lines" cannot detect one.
"""

import json
import os
import shutil
import sys
import textwrap
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional

import pytest

from scripts.architecture_health import (
    PrSizeGateError,
    evaluate_pull_request,
    main,
    size_transition,
)
from scripts.architecture_health.pull_request import CROSSED_TRANSITION, GREW_TRANSITION

CEILING = 1000

WORKFLOW_REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = WORKFLOW_REPO_ROOT / ".github" / "workflows" / "architecture-health.yml"
GATE_STEP_NAME = "Enforce SG1 size rule for this pull request"

BRANCH_POINT = "5b1e0c0ffee0deadbeef0123456789abcdef0123"


@pytest.fixture(autouse=True)
def isolate_github_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test independent of the ambient Actions environment.

    This module runs inside the pull-request workflow itself, so GITHUB_* is
    normally populated. Each test sets only the variables it is about.
    """
    for name in (
        "GITHUB_EVENT_NAME",
        "GITHUB_BASE_REF",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_HEAD_REF",
        "GITHUB_EVENT_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


def _lines(count: int, tag: str = "line") -> str:
    """Content with exactly `count` physical lines, newline terminated."""
    return "".join(f"{tag} {i}\n" for i in range(count))


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@test.com")
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "commit.gpgsign", "false")


def _commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _write(repo: Path, rel_path: str, content: str) -> None:
    target = repo / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _build_pr(
    tmp_path: Path,
    base_files: Dict[str, str],
    head_files: Dict[str, str],
    removed: Optional[List[str]] = None,
    renamed: Optional[Dict[str, str]] = None,
) -> Path:
    """Create a repository whose `main` is the merge base and HEAD is the PR head."""
    repo = tmp_path / "repo"
    _init_repo(repo)
    for rel_path, content in base_files.items():
        _write(repo, rel_path, content)
    _commit_all(repo, "base")

    _git(repo, "checkout", "-b", "pr")
    if renamed:
        for old_path, new_path in renamed.items():
            _git(repo, "mv", old_path, new_path)
    for rel_path in removed or []:
        _git(repo, "rm", "-q", rel_path)
    for rel_path, content in head_files.items():
        _write(repo, rel_path, content)
    _commit_all(repo, "head")
    return repo


def _physical_line_count(path: Path) -> int:
    content = path.read_bytes()
    return content.count(b"\n") + (1 if content and not content.endswith(b"\n") else 0)


def _run_gate(repo: Path, *extra: str) -> int:
    return main(["--repo-root", str(repo), "--check-pr-size", "--base-ref", "main", *extra])


# --------------------------------------------------------------------------- #
# Unit-level boundary table. Each row is one case the assignment names.
# --------------------------------------------------------------------------- #


def test_size_transition_boundary_table() -> None:
    """Every permitted and prohibited transition, stated as exact counts."""
    assert size_transition(999, 1000, CEILING) == "crossed ceiling"
    assert size_transition(998, 1000, CEILING) == "crossed ceiling"
    assert size_transition(0, 1000, CEILING) == "crossed ceiling"

    assert size_transition(1000, 1000, CEILING) is None
    assert size_transition(999, 999, CEILING) is None
    assert size_transition(500, 999, CEILING) is None

    assert size_transition(1000, 1001, CEILING) == "grew above ceiling"
    assert size_transition(1400, 1401, CEILING) == "grew above ceiling"

    assert size_transition(1400, 1400, CEILING) is None
    assert size_transition(1400, 1399, CEILING) is None
    assert size_transition(1200, 1000, CEILING) is None


# --------------------------------------------------------------------------- #
# Exact-line-count repository fixtures, one per named case.
# --------------------------------------------------------------------------- #


def test_below_ceiling_to_exactly_ceiling_fails(tmp_path: Path) -> None:
    """999 lines at the merge base growing to 1000 fails: the crossing case."""
    repo = _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1000, "func")},
    )
    assert _physical_line_count(repo / "grow.go") == 1000

    result = evaluate_pull_request(repo, "main")
    assert result["violations"] == [
        {
            "path": "grow.go",
            "base_path": "grow.go",
            "base_lines": 999,
            "head_lines": 1000,
            "transition": "crossed ceiling",
        }
    ]
    assert _run_gate(repo) == 1


def test_at_ceiling_unchanged_passes(tmp_path: Path) -> None:
    """A 1000-line file modified in place, still 1000 lines, passes.

    The content must change while the count stays put, otherwise git reports no
    modification and the transition is never evaluated at all.
    """
    repo = _build_pr(
        tmp_path,
        base_files={"same.go": _lines(1000, "func")},
        head_files={"same.go": _lines(1000, "func").replace("func 0\n", "func zero\n")},
    )
    assert _physical_line_count(repo / "same.go") == 1000

    result = evaluate_pull_request(repo, "main")
    assert result["checked_count"] == 1, "fixture must modify the file, not leave it untouched"
    assert result["violations"] == []
    assert _run_gate(repo) == 0


def test_at_ceiling_plus_one_unchanged_passes(tmp_path: Path) -> None:
    """1001 lines modified in place, still 1001, passes."""
    repo = _build_pr(
        tmp_path,
        base_files={"same.go": _lines(1001, "func")},
        head_files={"same.go": _lines(1001, "func").replace("func 0\n", "func zero\n")},
    )
    assert _physical_line_count(repo / "same.go") == 1001

    result = evaluate_pull_request(repo, "main")
    assert result["checked_count"] == 1
    assert result["violations"] == []
    assert _run_gate(repo) == 0


def test_already_above_ceiling_growing_fails(tmp_path: Path) -> None:
    """A file already above the ceiling that grows by one line fails."""
    repo = _build_pr(
        tmp_path,
        base_files={"big.go": _lines(1400, "func")},
        head_files={"big.go": _lines(1401, "func")},
    )

    result = evaluate_pull_request(repo, "main")
    assert len(result["violations"]) == 1
    assert result["violations"][0]["base_lines"] == 1400
    assert result["violations"][0]["head_lines"] == 1401
    assert result["violations"][0]["transition"] == "grew above ceiling"
    assert _run_gate(repo) == 1


def test_exactly_at_ceiling_growing_fails(tmp_path: Path) -> None:
    """1000 to 1001 is the second clause: at or above the ceiling, and larger."""
    repo = _build_pr(
        tmp_path,
        base_files={"edge.go": _lines(1000, "func")},
        head_files={"edge.go": _lines(1001, "func")},
    )

    result = evaluate_pull_request(repo, "main")
    assert [
        (v["path"], v["base_lines"], v["head_lines"], v["transition"]) for v in result["violations"]
    ] == [("edge.go", 1000, 1001, GREW_TRANSITION)]
    assert _run_gate(repo) == 1


def test_already_above_ceiling_shrinking_passes(tmp_path: Path) -> None:
    """Shrinking an above-ceiling file is the fix, not the breach."""
    repo = _build_pr(
        tmp_path,
        base_files={"big.go": _lines(1400, "func")},
        head_files={"big.go": _lines(1200, "func")},
    )

    assert evaluate_pull_request(repo, "main")["violations"] == []
    assert _run_gate(repo) == 0


def test_new_file_at_exactly_ceiling_fails(tmp_path: Path) -> None:
    """A new file counts from zero, so 1000 lines is a crossing."""
    repo = _build_pr(
        tmp_path,
        base_files={"keep.go": _lines(10)},
        head_files={"brand_new.go": _lines(1000, "func")},
    )
    assert _physical_line_count(repo / "brand_new.go") == 1000

    result = evaluate_pull_request(repo, "main")
    assert [
        (v["path"], v["base_lines"], v["head_lines"], v["transition"]) for v in result["violations"]
    ] == [("brand_new.go", 0, 1000, "crossed ceiling")]
    assert _run_gate(repo) == 1


def test_new_file_at_999_passes(tmp_path: Path) -> None:
    """One line under the boundary is permitted, and the fixture proves the count."""
    repo = _build_pr(
        tmp_path,
        base_files={"keep.go": _lines(10)},
        head_files={"brand_new.go": _lines(999, "func")},
    )
    assert _physical_line_count(repo / "brand_new.go") == 999

    assert evaluate_pull_request(repo, "main")["violations"] == []
    assert _run_gate(repo) == 0


def test_new_file_at_1200_fails(tmp_path: Path) -> None:
    """A new oversized file fails on the crossing, not on the excess."""
    repo = _build_pr(
        tmp_path,
        base_files={"keep.go": _lines(10)},
        head_files={"brand_new.go": _lines(1200, "func")},
    )

    result = evaluate_pull_request(repo, "main")
    assert result["violations"][0]["base_lines"] == 0
    assert result["violations"][0]["head_lines"] == 1200
    assert _run_gate(repo) == 1


def test_modification_stays_below_ceiling_passes(tmp_path: Path) -> None:
    """Growing inside the permitted zone is not an SG1 transition."""
    repo = _build_pr(
        tmp_path,
        base_files={"mid.go": _lines(400)},
        head_files={"mid.go": _lines(999)},
    )
    assert _physical_line_count(repo / "mid.go") == 999

    assert evaluate_pull_request(repo, "main")["violations"] == []
    assert _run_gate(repo) == 0


def test_deleted_file_passes(tmp_path: Path) -> None:
    """A deleted file cannot introduce a size transition."""
    repo = _build_pr(
        tmp_path,
        base_files={"doomed.go": _lines(1500, "func"), "keep.go": _lines(10)},
        head_files={"keep.go": _lines(11)},
        removed=["doomed.go"],
    )
    assert not (repo / "doomed.go").exists()

    assert evaluate_pull_request(repo, "main")["violations"] == []
    assert _run_gate(repo) == 0


def test_unchanged_file_passes(tmp_path: Path) -> None:
    """An untouched file is not the PR's responsibility, even at 1400 lines."""
    repo = _build_pr(
        tmp_path,
        base_files={"untouched.go": _lines(1400, "func")},
        head_files={"untouched.go": _lines(1400, "func"), "note.md": _lines(3)},
    )

    assert evaluate_pull_request(repo, "main")["violations"] == []
    assert _run_gate(repo) == 0


def test_rename_of_above_ceiling_file_passes(tmp_path: Path) -> None:
    """A move is judged at the new path against its old count, not as a new file."""
    repo = _build_pr(
        tmp_path,
        base_files={"internal/vpn/old_name.go": _lines(1400, "func")},
        head_files={},
        renamed={"internal/vpn/old_name.go": "internal/vpn/new_name.go"},
    )

    result = evaluate_pull_request(repo, "main")
    assert result["violations"] == []
    assert result["checked_count"] == 1
    assert _run_gate(repo) == 0


def test_rename_that_grows_fails_at_new_path(tmp_path: Path) -> None:
    """The rename exemption is not a hole: growing during a move still fails."""
    repo = _build_pr(
        tmp_path,
        base_files={"internal/vpn/old_name.go": _lines(1400, "func")},
        head_files={"internal/vpn/new_name.go": _lines(1401, "func")},
        renamed={"internal/vpn/old_name.go": "internal/vpn/new_name.go"},
    )

    result = evaluate_pull_request(repo, "main")
    assert [
        (v["path"], v["base_path"], v["base_lines"], v["head_lines"]) for v in result["violations"]
    ] == [("internal/vpn/new_name.go", "internal/vpn/old_name.go", 1400, 1401)]
    assert _run_gate(repo) == 1


def test_generated_or_vendor_path_is_skipped_and_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An excluded path cannot fail the gate, and the skip is stated in the log."""
    repo = _build_pr(
        tmp_path,
        base_files={"keep.go": _lines(10)},
        head_files={"web/static/css/style.css": _lines(3000, ".x"), "keep.go": _lines(11)},
    )

    result = evaluate_pull_request(repo, "main")
    assert result["violations"] == []
    assert result["skipped"] == [
        {"path": "web/static/css/style.css", "reason": "generated or vendor path"}
    ]

    caplog.set_level("INFO")
    caplog.clear()
    assert _run_gate(repo) == 0
    assert "skipped web/static/css/style.css (generated or vendor path)" in caplog.text


def test_excluded_path_is_skipped(tmp_path: Path) -> None:
    """Paths the scanner excludes outright are not judged by the gate either."""
    repo = _build_pr(
        tmp_path,
        base_files={"keep.go": _lines(10)},
        head_files={"tasks/huge.md": _lines(2000), "keep.go": _lines(11)},
    )

    result = evaluate_pull_request(repo, "main")
    assert result["violations"] == []
    assert result["skipped"] == [
        {"path": "tasks/huge.md", "reason": "excluded from the architecture scan"}
    ]
    assert _run_gate(repo) == 0


# --------------------------------------------------------------------------- #
# Invocation context and failure modes.
# --------------------------------------------------------------------------- #


def test_non_pull_request_invocation_does_not_block(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a push or dispatch there is no base, so the gate stands down and says so."""
    repo = _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1200, "func")},
    )
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    caplog.set_level("INFO")

    for event in ("push", "workflow_dispatch"):
        monkeypatch.setenv("GITHUB_EVENT_NAME", event)
        caplog.clear()
        assert main(["--repo-root", str(repo), "--check-pr-size"]) == 0
        assert "not applicable" in caplog.text

    monkeypatch.delenv("GITHUB_EVENT_NAME")
    caplog.clear()
    assert main(["--repo-root", str(repo), "--check-pr-size"]) == 0
    assert "no base ref available" in caplog.text


def test_pull_request_event_reads_base_ref_from_environment(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In CI the base comes from GITHUB_BASE_REF, so the workflow step stays thin.

    The head is supplied the way the workflow now supplies it: the event's own
    pull request head, passed through --head-ref.
    """
    repo = _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1000, "func")},
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    pr_head = _git(repo, "rev-parse", "HEAD").strip()
    caplog.set_level("INFO")

    assert main(["--repo-root", str(repo), "--check-pr-size", "--head-ref", pr_head]) == 1
    # Exit 1 must come from the crossing, not from the missing-head guard.
    assert "no head reference was supplied" not in caplog.text
    assert "grow.go is 999 line(s) at the merge base and 1000 line(s) at the head" in caplog.text


def test_pull_request_without_head_ref_fails_loudly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pull request run with no head reference is an error, never a merge-head verdict.

    Defaulting to HEAD here is exactly defect F952-01: on a pull_request checkout
    HEAD is the synthetic merge, whose merge base with the base branch is the base
    tip. The gate must refuse to judge instead of judging the wrong commit.
    """
    repo = _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1000, "func")},
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    caplog.set_level("INFO")

    assert main(["--repo-root", str(repo), "--check-pr-size"]) == 1
    assert "no head reference was supplied" in caplog.text
    assert "synthetic merge" in caplog.text
    assert "FAILED" in caplog.text
    assert "PASSED" not in caplog.text


def test_merge_base_not_base_tip_is_used(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A file that crossed the boundary on main after branching is not blamed on the PR."""
    repo = _build_pr(
        tmp_path,
        base_files={"shared.go": _lines(900), "pr_file.go": _lines(5)},
        head_files={"pr_file.go": _lines(6)},
    )

    # main moves on: someone else pushes shared.go across the boundary.
    _git(repo, "checkout", "main")
    _write(repo, "shared.go", _lines(1000))
    _commit_all(repo, "main advances separately")
    _git(repo, "checkout", "pr")

    result = evaluate_pull_request(repo, "main")
    assert result["violations"] == []
    assert "shared.go" not in [s["path"] for s in result["skipped"]]
    assert _run_gate(repo) == 0


def test_unreadable_git_data_fails_closed(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A base ref that does not exist is an operational failure, never a pass."""
    repo = _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1000, "func")},
    )

    with pytest.raises(PrSizeGateError):
        evaluate_pull_request(repo, "no-such-branch")

    assert main(["--repo-root", str(repo), "--check-pr-size", "--base-ref", "no-such-branch"]) == 1
    assert "Failing closed rather than reporting a pass" in caplog.text


def test_failure_output_names_file_counts_and_transition(
    repo_real: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The red check must be readable without opening the log, and annotate the file."""
    caplog.clear()
    with caplog.at_level("ERROR"):
        assert _run_gate(repo_real) == 1

    text = caplog.text
    assert "::error file=oversized.py::" in text
    assert "oversized.py is 999 lines at the merge base" in text
    assert "1200 lines at the head of this pull request" in text
    assert "crossed ceiling at 1000 lines" in text


@pytest.fixture
def repo_real(tmp_path: Path) -> Path:
    """One repository holding two independent violations, for output rendering."""
    return _build_pr(
        tmp_path,
        base_files={"oversized.py": _lines(999), "big.go": _lines(1500, "func")},
        head_files={"oversized.py": _lines(1200), "big.go": _lines(1501, "func")},
    )


def test_both_transitions_reported_together(repo_real: Path) -> None:
    """Two violations produce two annotations and a non-zero exit."""
    result = evaluate_pull_request(repo_real, "main")
    assert len(result["violations"]) == 2
    assert {v["transition"] for v in result["violations"]} == {
        "crossed ceiling",
        "grew above ceiling",
    }
    assert _run_gate(repo_real) == 1


def _pr_with_remote_only_base(tmp_path: Path) -> Path:
    """A checkout where the base branch exists only as `origin/main`.

    This is the shape GitHub Actions produces: a detached head and a
    remote-tracking base, with no local branch of that name.
    """
    origin = tmp_path / "origin.git"
    origin.mkdir()
    _git(origin, "init", "--bare", "-b", "main")

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@test.com")
    _git(repo, "config", "user.name", "test")
    _write(repo, "grow.go", _lines(999, "func"))
    _commit_all(repo, "base")

    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")

    _git(repo, "checkout", "-q", "-b", "pr")
    _write(repo, "grow.go", _lines(1000, "func"))
    _commit_all(repo, "grow past the boundary")

    _git(repo, "checkout", "-q", "--detach", "pr")
    _git(repo, "branch", "-q", "-D", "main")
    return repo


def test_base_ref_available_only_as_remote_tracking_ref(tmp_path: Path) -> None:
    """`main` is absent locally, so resolution must fall back to `origin/main`."""
    repo = _pr_with_remote_only_base(tmp_path)

    local = _git(repo, "branch", "-a", "--format=%(refname:short)").split()
    assert "refs/heads/main" not in _git(repo, "for-each-ref", "refs/heads/main")
    assert "main" not in local, "fixture must not leave a local base branch"
    assert "origin/main" in _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/remotes")

    result = evaluate_pull_request(repo, "main")
    assert result["violations"][0]["head_lines"] == 1000
    assert _run_gate(repo) == 1


def test_missing_base_ref_still_fails_closed(tmp_path: Path) -> None:
    """The remote-tracking fallback must not turn a missing base into a pass."""
    repo = _pr_with_remote_only_base(tmp_path)
    assert main(["--repo-root", str(repo), "--check-pr-size", "--base-ref", "nope"]) == 1


def test_actions_merge_checkout_gives_the_same_answer_as_the_pr_head(tmp_path: Path) -> None:
    """Disjoint-file case: main and the PR touch different files, so both refs agree.

    actions/checkout on pull_request builds a synthetic two-parent merge of the
    base tip and the PR head. Here main adds `other.go` while the PR changes
    `grow.go`, so merging main's work in adds no line to any path the PR
    touched, and merge-base(main, merge) is the base tip. Both comparisons
    therefore agree, and the merge checkout contributes no base-branch work.

    That equivalence is a property of disjoint edits, not of the merge ref. When
    both sides edit the same file it breaks in both directions; see
    `test_same_file_divergent_merge_does_not_falsely_reject_the_pr` and
    `test_same_file_divergent_merge_does_not_falsely_accept_the_pr`, which is why
    the workflow now passes the event's own head SHA through --head-ref instead
    of letting the CLI default to the checkout.
    """
    repo = _pr_with_remote_only_base(tmp_path)
    head_sha = _git(repo, "rev-parse", "pr").strip()

    # The base branch moves after the PR branched, and violates SG1 itself.
    _git(repo, "checkout", "-q", "-b", "advanced", "origin/main")
    _write(repo, "other.go", _lines(1200, "func"))
    _commit_all(repo, "main advances and overshoots separately")
    advanced_sha = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "branch", "-q", "-f", "main", advanced_sha)

    _git(repo, "checkout", "-q", "-b", "merge-sim", advanced_sha)
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", head_sha)
    merge_sha = _git(repo, "rev-parse", "HEAD").strip()
    parents = _git(repo, "rev-list", "--parents", "-n1", merge_sha).split()
    assert parents[1:] == [advanced_sha, head_sha], "fixture must be a two-parent merge"

    via_merge = evaluate_pull_request(repo, "main", head_ref="HEAD")
    via_head = evaluate_pull_request(repo, "main", head_ref=head_sha)

    # main's own 1200-line file is not blamed on the PR, and the PR's own
    # crossing is reported identically either way.
    assert "other.go" not in {v["path"] for v in via_merge["violations"]}
    assert [(v["path"], v["base_lines"], v["head_lines"]) for v in via_merge["violations"]] == [
        ("grow.go", 999, 1000)
    ]
    assert via_merge["violations"] == via_head["violations"]

    # With the PR's own crossing reverted, the merge-commit shape reports clean
    # even though main still carries a 1200-line file.
    _git(repo, "checkout", "-q", "pr")
    _write(repo, "grow.go", _lines(999, "func"))
    _commit_all(repo, "drop the crossing")
    clean_head = _git(repo, "rev-parse", "pr").strip()
    _git(repo, "checkout", "-q", "merge-sim")
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", clean_head)
    assert evaluate_pull_request(repo, "main", head_ref="HEAD")["violations"] == []


# --------------------------------------------------------------------------- #
# Mutation control: `size_transition` is mutated in the live module and the two
# boundary tests are re-run against it. A mutant that no boundary test kills
# would mean those tests are not measuring the boundary at all.
# --------------------------------------------------------------------------- #


def _run_boundary_tests() -> subprocess.CompletedProcess:
    """Run the two boundary tests in a subprocess so the mutation is observed live."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"{Path(__file__).resolve()}::test_below_ceiling_to_exactly_ceiling_fails",
            f"{Path(__file__).resolve()}::test_at_ceiling_unchanged_passes",
            f"{Path(__file__).resolve()}::test_exactly_at_ceiling_growing_fails",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "replace, mutant, killed_by",
    [
        (
            "base_lines < ceiling_lines <= head_lines",
            "base_lines < ceiling_lines < head_lines",
            "test_below_ceiling_to_exactly_ceiling_fails",
        ),
        (
            "base_lines < ceiling_lines <= head_lines",
            "base_lines <= ceiling_lines <= head_lines",
            "test_at_ceiling_unchanged_passes",
        ),
        (
            "base_lines >= ceiling_lines and head_lines > base_lines",
            "base_lines > ceiling_lines and head_lines > base_lines",
            "test_exactly_at_ceiling_growing_fails",
        ),
    ],
)
def test_boundary_mutations_are_killed_by_the_boundary_tests(
    replace: str, mutant: str, killed_by: str
) -> None:
    """Each one-character mutation of the live comparison must fail a boundary test.

    The mutation is applied to the real module source in place, and the two
    boundary tests are run in a subprocess, so the assertion sees the mutated
    function rather than a copy of it. A surviving mutant would prove the
    boundary test is not discriminating.
    """
    source_path = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "architecture_health"
        / ("pull_request.py")
    )
    original = source_path.read_text(encoding="utf-8")
    assert replace in original, "mutation anchor no longer present in size_transition"
    try:
        source_path.write_text(original.replace(replace, mutant, 1), encoding="utf-8")
        result = _run_boundary_tests()
    finally:
        source_path.write_text(original, encoding="utf-8")

    assert result.returncode != 0, f"mutant {mutant!r} survived the boundary tests"
    assert killed_by in result.stdout


def test_mutation_control_leaves_source_intact() -> None:
    """The mutation tests restore the module, so the rest of the suite sees real code."""
    source_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "architecture_health" / "pull_request.py"
    )
    assert "base_lines < ceiling_lines <= head_lines" in source_path.read_text(encoding="utf-8")
    assert size_transition(999, 1000, CEILING) == CROSSED_TRANSITION
    assert size_transition(1000, 1000, CEILING) is None


# --------------------------------------------------------------------------- #
# F952-01: same-file contention, and the invocation the workflow actually runs.
#
# Round 1 established that the Actions merge checkout agrees with the PR head
# only for edits to DIFFERENT files. When main and the PR both edit the same
# file, merge-base(main, merge) is main's tip rather than the branch point, and
# because the threshold predicate is not linear that substitution inverts the
# verdict in both directions. These two tests build real two-parent merges with
# contention on one file, and drive the workflow's own shell body against them.
# --------------------------------------------------------------------------- #


def _gate_step_block() -> str:
    """The workflow text of the SG1 gate step, isolated from its neighbours."""
    lines = WORKFLOW_PATH.read_text(encoding="utf-8").splitlines()
    marker = f"- name: {GATE_STEP_NAME}"
    start = next((i for i, line in enumerate(lines) if line.strip() == marker), None)
    assert start is not None, f"workflow no longer defines the step {GATE_STEP_NAME!r}"

    step_indent = len(lines[start]) - len(lines[start].lstrip())
    block: List[str] = [lines[start]]
    for line in lines[start + 1 :]:
        if line.lstrip().startswith("- ") and len(line) - len(line.lstrip()) <= step_indent:
            break
        block.append(line)
    return "\n".join(block)


def _gate_run_body() -> str:
    """The shell body of the gate step, dedented to a standalone script."""
    block = _gate_step_block()
    head, _, body = block.partition("run: |\n")
    assert body, "gate step no longer has a run block"

    # The workflow must take the head from the event, not from the checkout: the
    # checkout on pull_request is the synthetic merge, which is the defect.
    assert "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in head
    assert '--head-ref "${PR_HEAD_SHA}"' in body
    # The maintainer's label and the justification statement both come from the
    # event payload, so the step needs no token and no API call.
    assert "GITHUB_EVENT_PATH: ${{ github.event_path }}" in head
    return textwrap.dedent(body)


def _run_gate_via_workflow(
    repo: Path,
    pr_head_sha: Optional[str],
    payload: Optional[Dict[str, Any]] = None,
) -> subprocess.CompletedProcess:
    """Execute the workflow's gate body in the fixture repo, as the runner does.

    Actions runs a `run` block with the default shell `bash -e {0}`, which is
    what this reproduces: an unset PR_HEAD_SHA expands to an empty string and
    reaches the gate as an empty --head-ref, so the gate itself is the thing that
    must refuse to judge.

    `payload` is written where the runner puts the event JSON and passed as
    GITHUB_EVENT_PATH, so the maintainer's label is read exactly as production
    reads it.
    """
    body = _gate_run_body()
    assert "python3 scripts/architecture_health.py" in body
    body = body.replace(
        "python3 scripts/architecture_health.py", f"{sys.executable} scripts/architecture_health.py"
    )

    # The runner checks out the repository, so the gate's own entrypoint is
    # present in the working tree next to the code under measurement. Bytecode
    # is excluded so the fixture cannot execute a stale cache of the gate.
    shutil.copytree(
        WORKFLOW_REPO_ROOT / "scripts",
        repo / "scripts",
        dirs_exist_ok=True,
        symlinks=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    env = dict(os.environ)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["GITHUB_BASE_REF"] = "main"
    env.pop("GITHUB_HEAD_REF", None)
    env.pop("PR_HEAD_SHA", None)
    env.pop("GITHUB_EVENT_PATH", None)
    if pr_head_sha is not None:
        env["PR_HEAD_SHA"] = pr_head_sha
    if payload is not None:
        event_file = repo.parent / "event.json"
        event_file.write_text(json.dumps(payload), encoding="utf-8")
        env["GITHUB_EVENT_PATH"] = str(event_file)
    return subprocess.run(
        ["bash", "-e", "-c", body], cwd=repo, capture_output=True, text=True, env=env
    )


def _same_file_contention_checkout(
    tmp_path: Path, branch_point_lines: str, main_side: str, pr_side: str
) -> Dict[str, Any]:
    """A pull_request checkout where main and the PR both edit the same file.

    Reproduces the runner's shape: `main` exists only as `origin/main` at its own
    advanced tip, HEAD is detached at a synthetic two-parent merge of that tip
    and the PR head, and one file carries an edit from each side.
    """
    origin = tmp_path / "origin.git"
    origin.mkdir()
    _git(origin, "init", "--bare", "-b", "main")

    repo = tmp_path / "repo"
    _init_repo(repo)
    _write(repo, "hot.go", branch_point_lines)
    _commit_all(repo, "branch point")
    base_sha = _git(repo, "rev-parse", "HEAD").strip()

    _git(repo, "checkout", "-q", "-b", "pr")
    _write(repo, "hot.go", pr_side)
    _commit_all(repo, "pr edits the file")
    head_sha = _git(repo, "rev-parse", "HEAD").strip()

    _git(repo, "checkout", "-q", "main")
    _write(repo, "hot.go", main_side)
    _commit_all(repo, "main edits the same file")
    main_sha = _git(repo, "rev-parse", "HEAD").strip()

    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")

    _git(repo, "checkout", "-q", "-b", "merge-sim", main_sha)
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", head_sha)
    merge_sha = _git(repo, "rev-parse", "HEAD").strip()
    parents = _git(repo, "rev-list", "--parents", "-n1", merge_sha).split()
    assert parents[1:] == [main_sha, head_sha], "fixture must be a two-parent merge"
    assert _git(repo, "diff", "--name-only", base_sha, merge_sha).split().count("hot.go") == 1

    _git(repo, "checkout", "-q", "--detach", merge_sha)
    _git(repo, "branch", "-q", "-D", "main", "merge-sim")
    assert "main" not in _git(repo, "branch", "--format=%(refname:short)").split()

    return {
        "repo": repo,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "main_sha": main_sha,
        "merge_sha": merge_sha,
    }


def test_same_file_divergent_merge_does_not_falsely_reject_the_pr(tmp_path: Path) -> None:
    """998 at the branch point, main and PR add a line each: the PR must pass.

    The PR's own transition is 998 -> 999, which is below the ceiling. Judging
    the synthetic merge instead reports 999 -> 1000 and reddens a compliant pull
    request. The workflow invocation is the assertion: it exits 0.
    """
    fixture = _same_file_contention_checkout(
        tmp_path,
        branch_point_lines=_lines(998, "func"),
        main_side="main was here\n" + _lines(998, "func"),
        pr_side=_lines(998, "func") + "pr was here\n",
    )
    repo = fixture["repo"]
    assert _physical_line_count(repo / "hot.go") == 1000, "the merge itself is at 1000 lines"

    # The checkout's HEAD is the merge, so its merge base is main's tip: this is
    # the wrong input, and it is what the round 1 workflow actually fed the gate.
    via_merge = evaluate_pull_request(repo, "main", head_ref="HEAD")
    assert via_merge["merge_base"] == fixture["main_sha"]
    assert [(v["path"], v["base_lines"], v["head_lines"]) for v in via_merge["violations"]] == [
        ("hot.go", 999, 1000)
    ], "the merge checkout inverts this case into a violation"

    # With the event's head SHA the same comparison is branch point -> PR head.
    via_head = evaluate_pull_request(repo, "main", head_ref=fixture["head_sha"])
    assert via_head["merge_base"] == fixture["base_sha"]
    assert via_head["checked"] == [{"path": "hot.go", "base_lines": 998, "head_lines": 999}]
    assert via_head["violations"] == []

    run = _run_gate_via_workflow(repo, fixture["head_sha"])
    assert run.returncode == 0, run.stdout + run.stderr
    assert (
        f"comparing 1 changed path(s) between merge base {fixture['base_sha'][:10]} of main "
        f"and head {fixture['head_sha']}"
    ) in run.stdout
    assert "hot.go is 998 line(s) at the merge base and 999 line(s) at the head." in run.stdout
    assert "PASSED" in run.stdout


def test_same_file_divergent_merge_does_not_falsely_accept_the_pr(tmp_path: Path) -> None:
    """999 at the branch point, PR appends to 1000, main removes a line: must fail.

    The PR crosses the ceiling, so the gate has to fail. Judging the synthetic
    merge instead sees 998 -> 999, which passes silently. The workflow
    invocation exits 1 and names both counts.
    """
    fixture = _same_file_contention_checkout(
        tmp_path,
        branch_point_lines=_lines(999, "func"),
        main_side=_lines(999, "func").replace("func 0\n", ""),
        pr_side=_lines(999, "func") + "pr was here\n",
    )
    repo = fixture["repo"]
    assert _physical_line_count(repo / "hot.go") == 999, "the merge itself is at 999 lines"

    via_merge = evaluate_pull_request(repo, "main", head_ref="HEAD")
    assert via_merge["merge_base"] == fixture["main_sha"]
    assert via_merge["violations"] == [], "the merge checkout hides a real crossing"

    via_head = evaluate_pull_request(repo, "main", head_ref=fixture["head_sha"])
    assert via_head["merge_base"] == fixture["base_sha"]
    assert [
        (v["path"], v["base_lines"], v["head_lines"], v["transition"])
        for v in via_head["violations"]
    ] == [("hot.go", 999, 1000, CROSSED_TRANSITION)]

    run = _run_gate_via_workflow(repo, fixture["head_sha"])
    assert run.returncode == 1, run.stdout + run.stderr
    assert "hot.go is 999 line(s) at the merge base and 1000 line(s) at the head." in run.stdout
    assert (
        "::error file=hot.go::SG1 size rule violated (crossed ceiling at 1000 lines)" in run.stdout
    )
    assert "FAILED with 1 size violation(s)" in run.stdout


def test_workflow_gate_without_the_head_sha_fails_instead_of_judging_the_merge(
    tmp_path: Path,
) -> None:
    """The fail-loud half: no event head means no verdict, because the fallback is the bug.

    On the false-acceptance fixture the merge checkout passes. If the head SHA
    were missing and the gate silently fell back to HEAD, this PR would ship a
    crossing. It must exit 1 and say why.
    """
    fixture = _same_file_contention_checkout(
        tmp_path,
        branch_point_lines=_lines(999, "func"),
        main_side=_lines(999, "func").replace("func 0\n", ""),
        pr_side=_lines(999, "func") + "pr was here\n",
    )

    run = _run_gate_via_workflow(fixture["repo"], None)
    assert run.returncode == 1, run.stdout + run.stderr
    assert "no head reference was supplied" in run.stdout
    assert "synthetic merge" in run.stdout
    assert "PASSED" not in run.stdout
