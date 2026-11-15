#!/usr/bin/env python3
"""Rank Go test runtimes from ``go test -json`` output (issue #801).

Usage:
    python3 scripts/rank_go_test_times.py run.json [run2.json ...]
    python3 scripts/rank_go_test_times.py --runner-facts facts.txt run.json

The report contains the slowest top-level tests, the slowest subtests, package
totals, and pass/fail/skip counts. Parent tests and their subtests are ranked in
separate tables and are never added into one duration: a parent's ``Elapsed``
already contains its subtests, so summing both would double-count.

Exit status:

* ``0`` -- at least one terminal test result was collected; the report is
  evidence, even if some tests failed. Test failure is reported in the output
  and owns the exit status of the ``go test`` step, not of this report.
* ``1`` -- no terminal test result was collected (empty selection, broken
  ``-skip``, or a run that only started tests). An empty table is not a result.
* ``2`` -- an input file is missing or unreadable, so nothing could be measured.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

MODULE_PREFIX = "github.com/devops-igor/amnezia-nexus/"
TERMINAL_ACTIONS = frozenset({"pass", "fail", "skip"})
DEFAULT_TOP = 20


@dataclass
class TestResult:
    package: str
    test: str
    action: str
    elapsed: float

    @property
    def top_level(self) -> bool:
        return "/" not in self.test

    def short_package(self) -> str:
        return self.package.removeprefix(MODULE_PREFIX)


@dataclass
class PackageResult:
    package: str
    action: str
    elapsed: float

    def short_package(self) -> str:
        return self.package.removeprefix(MODULE_PREFIX)


@dataclass
class Report:
    files: List[str] = field(default_factory=list)
    tests: Dict[Tuple[str, str], TestResult] = field(default_factory=dict)
    started: set[Tuple[str, str]] = field(default_factory=set)
    packages: Dict[str, PackageResult] = field(default_factory=dict)
    non_json_lines: List[str] = field(default_factory=list)
    runner_facts: List[Tuple[str, str]] = field(default_factory=list)

    def add_event(self, event: dict) -> None:
        package = event.get("Package")
        if not package:
            return
        action = event.get("Action", "")
        test = event.get("Test")
        key = (package, test) if test else None

        if test and action == "run" and key is not None:
            self.started.add(key)
            return
        if test and action in TERMINAL_ACTIONS and key is not None:
            # A repeated -count or an appended run reports the same test again.
            # Keep the slowest observation so a rerun cannot hide a slow test,
            # but count the test once.
            elapsed = float(event.get("Elapsed") or 0.0)
            previous = self.tests.get(key)
            if previous is None or elapsed > previous.elapsed:
                self.tests[key] = TestResult(package, test, action, elapsed)
            return
        if not test and action in TERMINAL_ACTIONS:
            self.packages[package] = PackageResult(
                package, action, float(event.get("Elapsed") or 0.0)
            )

    # -- measurements -------------------------------------------------

    def finished_tests(self) -> List[TestResult]:
        return list(self.tests.values())

    def incomplete_tests(self) -> List[Tuple[str, str]]:
        return sorted(self.started - set(self.tests))

    def top_level_tests(self) -> List[TestResult]:
        return [item for item in self.finished_tests() if item.top_level]

    def subtests(self) -> List[TestResult]:
        return [item for item in self.finished_tests() if not item.top_level]

    def counts(self, results: Iterable[TestResult]) -> Dict[str, int]:
        counts = {"pass": 0, "fail": 0, "skip": 0}
        for item in results:
            counts[item.action] = counts.get(item.action, 0) + 1
        return counts

    def package_counts(self) -> Dict[str, int]:
        counts = {"pass": 0, "fail": 0, "skip": 0}
        for item in self.packages.values():
            counts[item.action] = counts.get(item.action, 0) + 1
        return counts

    def package_elapsed_sum(self) -> float:
        return sum(item.elapsed for item in self.packages.values())

    def measured_wall_seconds(self) -> Optional[float]:
        for key, value in self.runner_facts:
            if key == "wall_ms":
                try:
                    return int(value) / 1000.0
                except ValueError:
                    return None
        return None


def parse_lines(lines: Iterable[str], report: Report) -> None:
    """Fold ``go test -json`` lines into ``report``.

    A non-JSON line is not fatal: build diagnostics and output written directly
    to a file descriptor are interleaved with the JSON stream, and discarding
    the whole run because of them would hide the measurements that did parse.
    They are counted and sampled in the report instead.
    """
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            report.non_json_lines.append(line)
            continue
        if isinstance(event, dict):
            report.add_event(event)


def read_json_file(path: Path, report: Report) -> None:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        parse_lines(handle, report)


def read_runner_facts(path: Path) -> List[Tuple[str, str]]:
    facts: List[Tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        facts.append((key.strip(), value.strip()))
    return facts


def _seconds(value: float) -> str:
    return f"{value:.3f}"


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> List[str]:
    lines = ["| " + " | ".join(header) + " |"]
    lines.append("|" + "|".join(["---"] * len(header)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def render(report: Report, top: int) -> str:
    lines: List[str] = ["# Go test timing report", ""]

    top_tests = sorted(
        report.top_level_tests(), key=lambda item: (-item.elapsed, item.package, item.test)
    )
    subtests = sorted(
        report.subtests(), key=lambda item: (-item.elapsed, item.package, item.test)
    )
    test_counts = report.counts(top_tests)
    sub_counts = report.counts(subtests)
    package_counts = report.package_counts()
    incomplete = report.incomplete_tests()

    lines += [
        "## Collected",
        "",
        f"- input files: {len(report.files)} (`{'`, `'.join(report.files)}`)",
        f"- top-level tests: {len(top_tests)} "
        f"(pass {test_counts['pass']} / fail {test_counts['fail']} / skip {test_counts['skip']})",
        f"- subtests: {len(subtests)} "
        f"(pass {sub_counts['pass']} / fail {sub_counts['fail']} / skip {sub_counts['skip']})",
        f"- packages: {len(report.packages)} "
        f"(pass {package_counts['pass']} / fail {package_counts['fail']}"
        f" / skip {package_counts['skip']})",
        f"- incomplete tests (started, no terminal result): {len(incomplete)}",
        f"- non-JSON lines: {len(report.non_json_lines)}",
        "",
    ]

    if incomplete:
        lines += [
            "Incomplete tests are the signature of a timeout or a panic; they were"
            " started but never reported a result:",
            "",
        ]
        lines += [
            f"- `{package.removeprefix(MODULE_PREFIX)}` `{test}`"
            for package, test in incomplete[:top]
        ]
        lines.append("")

    lines += ["## Slowest top-level tests", ""]
    if top_tests:
        # A parent's Elapsed already contains its subtests, so the subtest is
        # shown as attribution for the parent row, never added to it.
        slowest_subtest: Dict[Tuple[str, str], TestResult] = {}
        for item in subtests:
            key = (item.package, item.test.split("/", 1)[0])
            previous = slowest_subtest.get(key)
            if previous is None or item.elapsed > previous.elapsed:
                slowest_subtest[key] = item
        rows = []
        for index, item in enumerate(top_tests[:top], start=1):
            subtest = slowest_subtest.get((item.package, item.test))
            attribution = (
                f"`{subtest.test.split('/', 1)[1]}` ({_seconds(subtest.elapsed)})"
                if subtest is not None
                else "-"
            )
            rows.append(
                [
                    str(index),
                    f"`{item.test}`",
                    f"`{item.short_package()}`",
                    _seconds(item.elapsed),
                    item.action,
                    attribution,
                ]
            )
        lines += _table(
            ["#", "Test", "Package", "Elapsed s", "Result", "Slowest subtest (s)"], rows
        )
    else:
        lines.append("_No completed top-level test was collected._")
    lines.append("")

    lines += ["## Slowest subtests", ""]
    if subtests:
        rows = [
            [
                str(index),
                f"`{item.test}`",
                f"`{item.short_package()}`",
                _seconds(item.elapsed),
                item.action,
            ]
            for index, item in enumerate(subtests[:top], start=1)
        ]
        lines += _table(["#", "Subtest", "Package", "Elapsed s", "Result"], rows)
    else:
        lines.append("_No completed subtest was collected._")
    lines.append("")

    lines += ["## Package totals (test-binary elapsed)", ""]
    if report.packages:
        by_package: Dict[str, List[TestResult]] = {}
        for item in report.top_level_tests():
            by_package.setdefault(item.package, []).append(item)
        rows = []
        for package in sorted(report.packages, key=lambda name: -report.packages[name].elapsed):
            result = report.packages[package]
            tests = by_package.get(package, [])
            failures = sum(1 for item in tests if item.action == "fail")
            skips = sum(1 for item in tests if item.action == "skip")
            rows.append(
                [
                    f"`{result.short_package()}`",
                    _seconds(result.elapsed),
                    str(len(tests)),
                    str(failures),
                    str(skips),
                    result.action,
                ]
            )
        lines += _table(
            ["Package", "Elapsed s", "Top-level tests", "Failures", "Skips", "Result"], rows
        )
    else:
        lines.append(
            "_No package result was collected; a build failure or timeout leaves"
            " no package total._"
        )
    lines.append("")

    if report.runner_facts:
        lines += ["## Runner facts", ""]
        lines += [f"- `{key}`: {value}" for key, value in report.runner_facts]
        lines.append("")

    wall = report.measured_wall_seconds()
    lines += ["## Test-binary time versus measured wall time", ""]
    if wall is not None:
        package_sum = report.package_elapsed_sum()
        lines.append(f"- measured step wall time: {_seconds(wall)} s")
        lines.append(f"- sum of package test-binary elapsed: {_seconds(package_sum)} s")
        lines.append(
            f"- difference: {_seconds(wall - package_sum)} s"
            " (build/setup/scheduling when positive; package-level parallel execution"
            " overlaps, so a negative value is expected when `-p` > 1)"
        )
    else:
        lines.append(
            "_No `wall_ms` runner fact was supplied, so compile/setup time is not"
            " separated from test-binary time._"
        )
    lines.append("")

    if report.non_json_lines:
        lines += ["## Non-JSON output (sampled)", ""]
        lines += ["```"] + report.non_json_lines[:10] + ["```", ""]

    return "\n".join(lines)


def build_report(
    paths: Sequence[Path], facts_path: Optional[Path]
) -> Report:
    report = Report(files=[path.name for path in paths])
    if facts_path is not None:
        report.runner_facts = read_runner_facts(facts_path)
    for path in paths:
        read_json_file(path, report)
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Rank Go test runtimes from go test -json output")
    parser.add_argument("files", nargs="+", type=Path, help="one or more go test -json files")
    parser.add_argument("--top", type=int, default=DEFAULT_TOP, help="rows per table (default: 20)")
    parser.add_argument(
        "--runner-facts", type=Path, help="key=value file with runner and wall-clock facts"
    )
    args = parser.parse_args(argv)

    if args.top < 1:
        print("--top must be >= 1", file=sys.stderr)
        return 2
    missing = [str(path) for path in args.files if not path.is_file()]
    if args.runner_facts is not None and not args.runner_facts.is_file():
        missing.append(str(args.runner_facts))
    if missing:
        print(f"cannot read measurement input: {', '.join(missing)}", file=sys.stderr)
        return 2

    report = build_report(args.files, args.runner_facts)
    print(render(report, args.top))

    if not report.tests:
        started = len(report.incomplete_tests())
        print(
            "::error::the run collected zero test results "
            f"(started but unfinished: {started}, non-JSON lines: {len(report.non_json_lines)}); "
            "an empty table is not a measurement",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
