"""Guards for the Go test timing report (issue #801).

A timing report is only useful if it cannot invent a measurement: an empty
selection must fail, a parent test and its subtests must not be added into one
duration, and package totals must come from the package event rather than a sum
of the tests inside it. These tests pin those properties, and the workflow
guard at the end fails if CI stops collecting the JSON the report reads.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "rank_go_test_times.py"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
MODULE = "example.com/measured"


def _load():
    spec = importlib.util.spec_from_file_location("rank_go_test_times", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # A dataclass resolves its module through sys.modules; registering it is
    # part of the documented dynamic-import idiom, not an optional step.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _event(action: str, package: str = f"{MODULE}/pkg", test: str | None = None, elapsed: float | None = None) -> dict:
    event = {"Time": "2026-11-15T00:00:00Z", "Action": action, "Package": package}
    if test is not None:
        event["Test"] = test
    if elapsed is not None:
        event["Elapsed"] = elapsed
    return event


def _write(tmp_path: Path, events: list[dict | str], name: str = "run.json") -> Path:
    path = tmp_path / name
    lines = [
        event if isinstance(event, str) else json.dumps(event)
        for event in events
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _report(paths: list[Path], facts: Path | None = None):
    module = _load()
    return module.build_report(paths, facts)


def test_top_level_tests_are_ranked_by_elapsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestSlow", elapsed=12.5),
            _event("pass", test="TestFast", elapsed=0.25),
            _event("pass", elapsed=13.0),
        ],
    )

    ranked = sorted(_report([path]).top_level_tests(), key=lambda item: -item.elapsed)

    assert [item.test for item in ranked] == ["TestSlow", "TestFast"]
    assert ranked[0].elapsed == 12.5


def test_parent_and_subtest_durations_are_not_summed(tmp_path: Path) -> None:
    """A parent's Elapsed already contains its subtests; adding both double-counts."""
    path = _write(
        tmp_path,
        [
            _event("run", test="TestParent"),
            _event("run", test="TestParent/one"),
            _event("pass", test="TestParent/one", elapsed=4.0),
            _event("run", test="TestParent/two"),
            _event("pass", test="TestParent/two", elapsed=6.0),
            _event("pass", test="TestParent", elapsed=10.0),
            _event("pass", elapsed=10.2),
        ],
    )

    report = _report([path])

    assert len(report.top_level_tests()) == 1
    assert report.top_level_tests()[0].elapsed == 10.0, "the parent must not absorb its subtests a second time"
    assert report.top_level_tests()[0].elapsed != 20.0


def test_top_level_row_attributes_its_slowest_subtest_without_summing(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestParent/quick", elapsed=1.0),
            _event("pass", test="TestParent/slow", elapsed=6.0),
            _event("pass", test="TestParent", elapsed=10.0),
            _event("pass", elapsed=10.2),
        ],
    )

    output = _load().render(_report([path]), 20)

    assert "`slow` (6.000)" in output, "the parent row must name its slowest subtest"
    assert "16.000" not in output, "the parent and its subtest were added together"


def test_slowest_subtests_are_ranked_separately(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestParent/quick", elapsed=0.1),
            _event("pass", test="TestParent/slow", elapsed=9.0),
            _event("pass", test="TestParent", elapsed=9.2),
            _event("pass", elapsed=9.5),
        ],
    )

    subtests = sorted(_report([path]).subtests(), key=lambda item: -item.elapsed)

    assert [item.test for item in subtests] == ["TestParent/slow", "TestParent/quick"]


def test_package_total_comes_from_the_package_event(tmp_path: Path) -> None:
    """Summing test durations would understate setup and parallel wall time."""
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestOne", elapsed=1.0),
            _event("pass", test="TestTwo", elapsed=2.0),
            _event("pass", elapsed=7.5),
        ],
    )

    report = _report([path])

    assert report.package_elapsed_sum() == 7.5
    assert report.package_counts() == {"pass": 1, "fail": 0, "skip": 0}


def test_zero_collected_tests_fails(tmp_path: Path) -> None:
    path = _write(tmp_path, [_event("start")])

    code = _load().main([str(path)])

    assert code == 1, "an empty table must not be reported as a successful measurement"


def test_an_empty_file_fails(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")

    assert _load().main([str(path)]) == 1


def test_started_but_unfinished_tests_are_surfaced_and_fail(tmp_path: Path) -> None:
    """A timeout kills a test between `run` and its terminal event."""
    path = _write(tmp_path, [_event("run", test="TestHung"), _event("start")])

    module = _load()
    report = module.build_report([path], None)

    assert report.incomplete_tests() == [(f"{MODULE}/pkg", "TestHung")]
    assert "TestHung" in module.render(report, 20)
    assert module.main([str(path)]) == 1


def test_non_json_lines_are_tolerated_but_reported(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            "FAIL\texample.com/measured/pkg [build failed]",
            _event("pass", test="TestOne", elapsed=0.1),
            _event("pass", elapsed=0.2),
        ],
    )

    module = _load()
    report = module.build_report([path], None)

    assert len(report.non_json_lines) == 1
    assert module.main([str(path)]) == 0
    assert "build failed" in module.render(report, 20)


def test_missing_input_file_fails(tmp_path: Path) -> None:
    assert _load().main([str(tmp_path / "absent.json")]) == 2


def test_pass_fail_skip_counts_are_separate_for_tests_and_subtests(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestPass", elapsed=1.0),
            _event("fail", test="TestFail", elapsed=2.0),
            _event("skip", test="TestSkip"),
            _event("pass", test="TestPass/sub", elapsed=0.5),
            _event("skip", test="TestSkip/sub"),
            _event("fail", elapsed=2.5),
        ],
    )

    report = _report([path])

    assert report.counts(report.top_level_tests()) == {"pass": 1, "fail": 1, "skip": 1}
    assert report.counts(report.subtests()) == {"pass": 1, "fail": 0, "skip": 1}
    assert report.package_counts() == {"pass": 0, "fail": 1, "skip": 0}


def test_a_repeated_result_is_counted_once_and_keeps_the_slowest_observation(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestRepeat", elapsed=1.0),
            _event("pass", test="TestRepeat", elapsed=3.0),
            _event("pass", elapsed=3.1),
        ],
    )

    report = _report([path])

    assert len(report.top_level_tests()) == 1
    assert report.top_level_tests()[0].elapsed == 3.0


def test_runner_facts_and_wall_time_separate_setup_from_test_binary_time(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _event("pass", test="TestOne", elapsed=2.0),
            _event("pass", elapsed=2.5),
        ],
    )
    facts = tmp_path / "facts.txt"
    facts.write_text(
        "commit=abc123\ncpus=4\ngo_version=go1.26.11\ngomaxprocs=4\nwall_ms=10000\n",
        encoding="utf-8",
    )

    module = _load()
    report = module.build_report([path], facts)
    output = module.render(report, 20)

    assert ("commit", "abc123") in report.runner_facts
    assert "measured step wall time: 10.000 s" in output
    assert "sum of package test-binary elapsed: 2.500 s" in output
    assert "difference: 7.500 s" in output


def test_multiple_shard_files_are_aggregated(tmp_path: Path) -> None:
    one = _write(tmp_path, [_event("pass", test="TestA", elapsed=1.0), _event("pass", elapsed=1.1)], "one.json")
    two = _write(
        tmp_path,
        [_event("pass", package=f"{MODULE}/other", test="TestB", elapsed=5.0), _event("pass", package=f"{MODULE}/other", elapsed=5.2)],
        "two.json",
    )

    report = _report([one, two])

    assert report.files == ["one.json", "two.json"]
    assert len(report.top_level_tests()) == 2
    assert report.package_elapsed_sum() == pytest.approx(6.3)


# ── Workflow wiring: the report is only evidence if CI feeds it ─────

_STEP_RE = re.compile(r"^      - name: (?P<name>.+)$", re.MULTILINE)


def _step_block(name_prefix: str) -> str:
    """Return the workflow text of the step whose name starts with the prefix."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    matches = list(_STEP_RE.finditer(text))
    for index, match in enumerate(matches):
        if match.group("name").startswith(name_prefix):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            return text[match.start() : end]
    raise AssertionError(f"workflow has no step named {name_prefix!r}")


def test_workflow_collects_json_without_masking_a_failure() -> None:
    block = _step_block("Run Tests with Race Detector")

    assert "go test -race -cover -count=1 -timeout=15m" in block
    assert "-json" in block, "the race step must emit the per-test events the report reads"
    assert "set -euo pipefail" in block, "a tee without pipefail would hide a failing go test"
    assert 'status="${PIPESTATUS[0]}"' in block
    assert 'exit "$status"' in block, "the step must end with the go test status, not tee's"


def test_workflow_runs_the_ranking_script_and_uploads_its_evidence() -> None:
    rank = _step_block("Rank Go test timings")
    assert "if: always()" in rank, "the report must run when the race step failed"
    assert "scripts/rank_go_test_times.py" in rank

    upload = _step_block("Upload Go test timing evidence")
    assert "if: always()" in upload, "raw JSON must be retained when the run failed"
    assert "go-test-timings-shard-" in upload

    combined = _step_block("Rank combined Go test timings")
    assert "if: always()" in combined
    assert "scripts/rank_go_test_times.py" in combined
