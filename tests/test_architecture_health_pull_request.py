"""Tests for the pull-request SG1 size gate.

Every size case builds a real git repository with exact physical line counts at
the merge base and at the head, because an off-by-one at the 1,000-line boundary
is the most likely defect in this comparison and a fixture that is "about a
thousand lines" cannot detect one.
"""

import sys
from pathlib import Path
import subprocess
from typing import Dict, List, Optional

import pytest

from scripts.architecture_health import (
    PrSizeGateError,
    evaluate_pull_request,
    main,
    size_transition,
)
from scripts.architecture_health.pull_request import CROSSED_TRANSITION, GREW_TRANSITION

CEILING = 1000


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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In CI the base comes from GITHUB_BASE_REF, so the workflow step stays thin."""
    repo = _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1000, "func")},
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    assert main(["--repo-root", str(repo), "--check-pr-size"]) == 1


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
