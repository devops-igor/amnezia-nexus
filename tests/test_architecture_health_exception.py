"""Tests for the SG1 exception path section 4.3 permits.

Section 4.3 forbids a size transition only "without a stated per-PR responsibility
justification", so the gate must accept the permitted case as well as reject the
prohibited one. Two halves make the exception, and both are required:

  * the `sg1-size-exception` pull-request label, which a maintainer applies and a
    contributor cannot, because labelling needs triage or write access; and
  * a statement under a "SG1 responsibility justification" heading in the pull
    request body, which is the per-PR justification the rule names.

Either half alone is a half-exception and must fail. These tests drive both the
resolved decision and the production invocation: the workflow's own shell body is
executed in a fixture repository with the event payload the runner writes, so the
assertions are on what a maintainer actually sees in the job output.

The fixtures mirror `test_architecture_health_pull_request.py`, which owns the
size comparison itself and every round 1 and round 2 control.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from scripts.architecture_health import (
    EXCEPTION_LABEL,
    JUSTIFICATION_HEADING,
    PrSizeGateError,
    evaluate_pull_request,
    load_pull_request_context,
    main,
    parse_justification,
    report_excused_result,
    resolve_exception,
)
from scripts.architecture_health.pull_request import CROSSED_TRANSITION, GREW_TRANSITION
from tests.test_architecture_health_pull_request import (
    _build_pr,
    _git,
    _lines,
    _run_gate,
    _run_gate_via_workflow,
)

# --------------------------------------------------------------------------- #
# Round 3: the exception section 4.3 permits.
#
# The rule forbids a size transition only "without a stated per-PR responsibility
# justification", so the gate must accept the permitted case as well as reject the
# prohibited one. The control is a pull-request label, because applying a label
# needs triage or write access and a branch cannot grant itself that. The
# statement is the heading section 4.3 asks for, in the pull request body. Both
# are required: either half alone is a half-exception and must fail.
# --------------------------------------------------------------------------- #

JUSTIFIED_BODY = (
    "## Summary\n\nAdds the retry guard.\n\n"
    f"## {JUSTIFICATION_HEADING}\n\n"
    "internal/vpn/sessions.go stays one file because the new guard mutates the session\n"
    "registry under the same lock as the existing paths; splitting it would export the\n"
    "lock and the registry to a second package.\n"
)


def _event_payload(labels: Optional[List[str]] = None, body: str = "") -> Dict[str, Any]:
    """A GitHub pull_request event payload, shaped as the runner writes it."""
    return {
        "pull_request": {
            "labels": [{"name": name} for name in labels or []],
            "body": body,
        }
    }


@pytest.fixture(autouse=True)
def isolate_exception_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test independent of the ambient Actions environment.

    The payload path in particular: a stray GITHUB_EVENT_PATH would leak a label
    from the workflow that is running these tests into the fixture repository.
    """
    for name in ("GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repo_real(tmp_path: Path) -> Path:
    """The two-violation repository the round 2 output tests also use.

    Rebuilt here through the shared builder rather than imported, because a
    pytest fixture is not a plain importable helper.
    """
    return _build_pr(
        tmp_path,
        base_files={"oversized.py": _lines(999), "big.go": _lines(1500, "func")},
        head_files={"oversized.py": _lines(1200), "big.go": _lines(1501, "func")},
    )


def test_exception_label_is_a_maintainer_control_not_a_cli_flag() -> None:
    """The gate has no flag that could request an exception from the branch.

    A workflow input or CLI flag is settable by the contributor's own branch, so
    the only route to the exception is the label, which needs write access. This
    asserts the shape of the interface rather than a message about it.
    """
    with pytest.raises(SystemExit):
        main(["--check-pr-size", "--force"])

    source = (
        Path(__file__).resolve().parents[1] / "scripts" / "architecture_health" / "cli.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("--allow-transition", "--force", "--waive", "--exception"):
        assert forbidden not in source


def test_parse_justification_requires_the_named_heading() -> None:
    """The statement is found under the heading, not from anywhere in the body."""
    assert parse_justification(None) == ""
    assert parse_justification("") == ""
    assert parse_justification(f"## {JUSTIFICATION_HEADING}\n\n") == ""
    assert parse_justification("## Summary\n\nnice change\n") == ""
    # Bare text outside the heading is not a statement, however it is phrased.
    assert parse_justification(f"Justification: {JUSTIFICATION_HEADING} because\n") == ""

    assert parse_justification(JUSTIFIED_BODY).startswith("internal/vpn/sessions.go stays")
    # The heading is matched without case sensitivity and at any level.
    for heading in (
        f"## {JUSTIFICATION_HEADING}",
        f"# {JUSTIFICATION_HEADING}",
        f"### {JUSTIFICATION_HEADING.lower()}",
    ):
        assert parse_justification(f"{heading}\n\nreason\n") == "reason"

    # The statement stops at the next heading.
    assert (
        parse_justification(f"## {JUSTIFICATION_HEADING}\nreason\n## Notes\nignored\n") == "reason"
    )


def test_resolve_exception_requires_both_halves() -> None:
    """Label alone and statement alone are both incomplete; only both together is valid."""
    neither = resolve_exception(labels=[], body="")
    assert neither["valid"] is False and neither["requested"] is False

    label_only = resolve_exception(labels=[EXCEPTION_LABEL], body="## Summary\n\nno statement\n")
    assert label_only["requested"] is True
    assert label_only["justification_present"] is False
    assert label_only["valid"] is False

    body_only = resolve_exception(labels=["bug"], body=JUSTIFIED_BODY)
    assert body_only["requested"] is False
    assert body_only["justification_present"] is True
    assert body_only["valid"] is False, "the statement alone is author-controlled"

    both = resolve_exception(labels=["bug", EXCEPTION_LABEL], body=JUSTIFIED_BODY)
    assert both["requested"] is True and both["justification_present"] is True
    assert both["valid"] is True


def _crossing_repo(tmp_path: Path) -> Path:
    """One fixture, one crossing: 999 lines at the merge base, 1000 at the head."""
    return _build_pr(
        tmp_path,
        base_files={"grow.go": _lines(999, "func")},
        head_files={"grow.go": _lines(1000, "func")},
    )


def test_crossing_without_exception_still_fails(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The unlabelled path is untouched: the same annotation and the same exit code."""
    repo = _crossing_repo(tmp_path)
    caplog.set_level("INFO")

    assert _run_gate(repo) == 1
    assert (
        "::error file=grow.go::SG1 size rule violated (crossed ceiling at 1000 lines)"
        in caplog.text
    )
    assert "FAILED with 1 size violation(s)" in caplog.text
    assert "excused" not in caplog.text


def test_exception_with_justification_passes_and_names_the_excused_path(
    tmp_path: Path,
) -> None:
    """Label plus statement passes, and the excused path is printed with both counts."""
    repo = _crossing_repo(tmp_path)
    head_sha = _git(repo, "rev-parse", "HEAD").strip()

    result = evaluate_pull_request(
        repo,
        "main",
        exception=resolve_exception(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY),
    )
    assert result["violations"] == []
    assert [(v["path"], v["base_lines"], v["head_lines"]) for v in result["excused"]] == [
        ("grow.go", 999, 1000)
    ]

    run = _run_gate_via_workflow(
        repo, head_sha, payload=_event_payload(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY)
    )
    assert run.returncode == 0, run.stdout + run.stderr

    # The observable proof: an exception never passes silently. The excused path
    # is in the job output with both counts, and as a warning annotation.
    assert f"excused grow.go by the {EXCEPTION_LABEL} label" in run.stdout
    assert "999 line(s) at the merge base and 1000 line(s) at the head" in run.stdout
    assert (
        f"::warning file=grow.go::SG1 size transition excused by the {EXCEPTION_LABEL} label"
        " (crossed ceiling at 1000 lines): grow.go is 999 lines at the merge base and"
        " 1000 lines at the head of this pull request." in run.stdout
    )
    assert "PASSED WITH EXCEPTION" in run.stdout
    assert "excused 1 transition(s)" in run.stdout


def test_exception_label_without_justification_fails(tmp_path: Path) -> None:
    """A label with no statement must fail, naming exactly what is missing."""
    repo = _crossing_repo(tmp_path)

    run = _run_gate_via_workflow(
        repo,
        _git(repo, "rev-parse", "HEAD").strip(),
        payload=_event_payload(labels=[EXCEPTION_LABEL], body="## Summary\n\njust a change\n"),
    )
    assert run.returncode == 1, run.stdout + run.stderr

    assert f"the {EXCEPTION_LABEL} label is applied" in run.stdout
    assert f"no statement under a '{JUSTIFICATION_HEADING}' heading" in run.stdout
    assert "the exception is incomplete" in run.stdout
    assert "PASSED" not in run.stdout


def test_justification_without_label_fails(tmp_path: Path) -> None:
    """The statement alone is author-controlled, so it must not pass."""
    repo = _crossing_repo(tmp_path)

    run = _run_gate_via_workflow(
        repo,
        _git(repo, "rev-parse", "HEAD").strip(),
        payload=_event_payload(labels=["enhancement"], body=JUSTIFIED_BODY),
    )
    assert run.returncode == 1, run.stdout + run.stderr

    # The size rule's own refusal, not the half-exception message.
    assert "FAILED with 1 size violation(s)" in run.stdout
    assert "::error file=grow.go::" in run.stdout
    assert "excused" not in run.stdout
    assert "PASSED" not in run.stdout


def test_exception_present_but_unused_passes_without_claiming_an_excusal(
    tmp_path: Path,
) -> None:
    """A labelled PR with no transition passes, and says nothing was excused."""
    repo = _build_pr(
        tmp_path,
        base_files={"small.go": _lines(400)},
        head_files={"small.go": _lines(401)},
    )

    run = _run_gate_via_workflow(
        repo,
        _git(repo, "rev-parse", "HEAD").strip(),
        payload=_event_payload(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY),
    )
    assert run.returncode == 0, run.stdout + run.stderr

    assert "was not needed" in run.stdout
    assert "Nothing was excused" in run.stdout
    assert "transition(s) excused" not in run.stdout
    assert "::warning file=" not in run.stdout


def test_two_violations_are_both_reported_as_excused(repo_real: Path) -> None:
    """Every excused path is named, not just the first."""
    result = evaluate_pull_request(
        repo_real,
        "main",
        exception=resolve_exception(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY),
    )
    assert result["violations"] == []
    # Sorted by transition then path, as violations always are.
    assert [(v["path"], v["base_lines"], v["head_lines"]) for v in result["excused"]] == [
        ("oversized.py", 999, 1200),
        ("big.go", 1500, 1501),
    ]

    run = _run_gate_via_workflow(
        repo_real,
        _git(repo_real, "rev-parse", "HEAD").strip(),
        payload=_event_payload(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY),
    )
    assert run.returncode == 0, run.stdout + run.stderr

    for path, before, after in (("big.go", "1500", "1501"), ("oversized.py", "999", "1200")):
        assert f"excused {path} by the {EXCEPTION_LABEL} label" in run.stdout
        assert f"{before} line(s) at the merge base and {after} line(s) at the head" in run.stdout
        assert f"::warning file={path}::SG1 size transition excused" in run.stdout
    assert "excused 2 transition(s)" in run.stdout


def test_exception_does_not_excuse_a_different_kind_of_violation(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Exclusions are decided before the exception, so it cannot widen them.

    A generated or vendor path is still skipped and reported as skipped rather
    than excused, and an unmeasurable path is still not measurable.
    """
    repo = _build_pr(
        tmp_path,
        base_files={"keep.go": _lines(10)},
        head_files={"web/static/css/style.css": _lines(3000, ".x"), "keep.go": _lines(11)},
    )
    result = evaluate_pull_request(
        repo,
        "main",
        exception=resolve_exception(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY),
    )
    assert result["excused"] == []
    assert result["skipped"] == [
        {"path": "web/static/css/style.css", "reason": "generated or vendor path"}
    ]


def test_missing_event_payload_means_no_exception_and_still_fails(tmp_path: Path) -> None:
    """No payload is not an exception: enforcement stays exactly as it was."""
    repo = _crossing_repo(tmp_path)
    assert _run_gate_via_workflow(repo, _git(repo, "rev-parse", "HEAD").strip()).returncode == 1


def test_non_pull_request_payload_means_no_exception(tmp_path: Path) -> None:
    """A payload without a pull_request object cannot request an exception."""
    repo = _crossing_repo(tmp_path)
    run = _run_gate_via_workflow(
        repo,
        _git(repo, "rev-parse", "HEAD").strip(),
        payload={"ref": "refs/heads/main"},
    )
    assert run.returncode == 1
    assert "FAILED with 1 size violation(s)" in run.stdout


def test_unreadable_event_payload_fails_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A payload that exists but cannot be parsed is an error, never "no labels"."""
    repo = _crossing_repo(tmp_path)
    broken = tmp_path / "event.json"
    broken.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(broken))
    caplog.set_level("INFO")

    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--check-pr-size",
                "--head-ref",
                _git(repo, "rev-parse", "HEAD").strip(),
            ]
        )
        == 1
    )
    assert "FAILED to read the pull request event payload" in caplog.text
    assert "Failing closed" in caplog.text


# --------------------------------------------------------------------------- #
# Mutation control for the exception guards. Each mutation is a single-line
# change to the live module, and the test that is supposed to discriminate
# against it is re-run in a subprocess against the mutated code. A mutant that
# survives means the guard is not what the test is measuring.
# --------------------------------------------------------------------------- #


def _run_named_tests(*node_ids: str) -> subprocess.CompletedProcess:
    """Run named tests in a subprocess so an in-place mutation is observed live."""
    path = Path(__file__).resolve()
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        + [f"{path}::{node}" for node in node_ids],
        cwd=path.parents[1],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "replace, mutant, killed_by",
    [
        # The label check: pretend the maintainer applied it to every PR.
        (
            "label_present = EXCEPTION_LABEL in label_names",
            "label_present = True",
            "test_justification_without_label_fails",
        ),
        # The justification check: accept the label as sufficient on its own.
        (
            '"valid": label_present and bool(justification),',
            '"valid": label_present,',
            "test_exception_label_without_justification_fails",
        ),
    ],
)
def test_exception_guard_mutations_are_killed(replace: str, mutant: str, killed_by: str) -> None:
    """Each guard, broken on its own, must turn its own test red."""
    source_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "architecture_health" / "pull_request.py"
    )
    original = source_path.read_text(encoding="utf-8")
    assert replace in original, "mutation anchor no longer present in the exception guards"
    try:
        source_path.write_text(original.replace(replace, mutant, 1), encoding="utf-8")
        result = _run_named_tests(killed_by)
    finally:
        source_path.write_text(original, encoding="utf-8")

    assert result.returncode != 0, f"mutant {mutant!r} survived {killed_by}"
    assert killed_by in result.stdout


def test_exception_mutation_control_leaves_source_intact() -> None:
    """The mutation tests restore the module, so the rest of the suite sees real code."""
    source_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "architecture_health" / "pull_request.py"
    )
    text = source_path.read_text(encoding="utf-8")
    assert "label_present = EXCEPTION_LABEL in label_names" in text
    assert '"valid": label_present and bool(justification),' in text
    assert resolve_exception(labels=[EXCEPTION_LABEL], body="")["valid"] is False


def test_report_excused_result_names_every_path_with_both_counts() -> None:
    """The renderer itself: one warning per excused path, plus a stated total."""
    exception = resolve_exception(labels=[EXCEPTION_LABEL], body=JUSTIFIED_BODY)
    result = {
        "ceiling_lines": 1000,
        "exception": exception,
        "excused": [
            {
                "path": "internal/vpn/new_name.go",
                "base_path": "internal/vpn/old_name.go",
                "base_lines": 1400,
                "head_lines": 1401,
                "transition": GREW_TRANSITION,
            },
            {
                "path": "brand_new.go",
                "base_path": None,
                "base_lines": 0,
                "head_lines": 1200,
                "transition": CROSSED_TRANSITION,
            },
        ],
    }
    lines = report_excused_result(result)

    assert len(lines) == 3
    # A rename names the merge-base path it came from.
    assert lines[0].startswith("::warning file=internal/vpn/new_name.go::")
    assert "1400 lines from internal/vpn/old_name.go at the merge base" in lines[0]
    assert "1401 lines at the head" in lines[0]
    # A new file reads as a comparison from zero, with no phantom base path.
    assert lines[1].startswith("::warning file=brand_new.go::")
    assert "0 lines at the merge base and 1200 lines at the head" in lines[1]
    assert lines[2] == (
        f"SG1 size rule excused 2 transition(s) under the {EXCEPTION_LABEL} label and the "
        f"'{JUSTIFICATION_HEADING}' statement in this pull request."
    )
    assert (
        report_excused_result({"excused": [], "exception": exception, "ceiling_lines": 1000}) == []
    )


def test_load_pull_request_context_handles_payload_shapes(tmp_path: Path) -> None:
    """Payload reading is defensive about shape but strict about unreadable input."""
    assert load_pull_request_context(None) == {"available": False, "labels": [], "body": ""}

    # A payload with no pull_request object is a "no" rather than an error.
    no_pr = tmp_path / "event.json"
    no_pr.write_text(json.dumps({"ref": "refs/heads/main"}), encoding="utf-8")
    assert load_pull_request_context(str(no_pr))["available"] is False

    # A non-object payload is treated the same way.
    array_payload = tmp_path / "array.json"
    array_payload.write_text("[]", encoding="utf-8")
    assert load_pull_request_context(str(array_payload))["available"] is False

    # Entries that are not label objects, and an absent body, do not break it.
    odd = tmp_path / "odd.json"
    odd.write_text(
        json.dumps(
            {
                "pull_request": {
                    "labels": [{"name": EXCEPTION_LABEL}, {"no_name": True}, "plain-string", {}],
                    "body": None,
                }
            }
        ),
        encoding="utf-8",
    )
    context = load_pull_request_context(str(odd))
    assert context == {"available": True, "labels": [EXCEPTION_LABEL], "body": ""}

    # A payload that exists but cannot be read is an operational failure.
    with pytest.raises(PrSizeGateError, match="could not read the pull request event payload"):
        load_pull_request_context(str(tmp_path / "does-not-exist.json"))


# --------------------------------------------------------------------------- #
# The same four verdicts through the CLI itself, so the logging branches are
# covered in-process and not only through the workflow subprocess. Each test
# writes the event payload where the runner puts it and calls main().
# --------------------------------------------------------------------------- #


def _run_gate_with_payload(repo: Path, monkeypatch: pytest.MonkeyPatch, labels, body: str) -> int:
    """Call the CLI as the runner does, with a real event payload file."""
    event = repo.parent / "event.json"
    event.write_text(json.dumps(_event_payload(labels=labels, body=body)), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    return main(
        [
            "--repo-root",
            str(repo),
            "--check-pr-size",
            "--head-ref",
            _git(repo, "rev-parse", "HEAD").strip(),
        ]
    )


def test_cli_excuses_a_crossing_and_states_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Exit 0, with the excused path and both counts in the log."""
    repo = _crossing_repo(tmp_path)
    caplog.set_level("INFO")

    assert _run_gate_with_payload(repo, monkeypatch, [EXCEPTION_LABEL], JUSTIFIED_BODY) == 0
    assert f"excused grow.go by the {EXCEPTION_LABEL} label" in caplog.text
    assert "999 line(s) at the merge base and 1000 line(s) at the head" in caplog.text
    assert "PASSED WITH EXCEPTION" in caplog.text
    assert "::error file=" not in caplog.text


def test_cli_fails_a_half_exception_and_still_shows_the_size_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The missing half is named, and the transition it failed to cover is printed."""
    repo = _crossing_repo(tmp_path)
    caplog.set_level("INFO")

    assert _run_gate_with_payload(repo, monkeypatch, [EXCEPTION_LABEL], "## Summary\n\nok\n") == 1
    assert "the exception is incomplete" in caplog.text
    assert "::error file=grow.go::SG1 size rule violated" in caplog.text
    assert "PASSED" not in caplog.text


def test_cli_states_that_a_valid_exception_was_not_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No transition, exception present: pass and say nothing was excused."""
    repo = _build_pr(
        tmp_path,
        base_files={"small.go": _lines(400)},
        head_files={"small.go": _lines(401)},
    )
    caplog.set_level("INFO")

    assert _run_gate_with_payload(repo, monkeypatch, [EXCEPTION_LABEL], JUSTIFIED_BODY) == 0
    assert "was not needed" in caplog.text
    assert "Nothing was excused" in caplog.text
