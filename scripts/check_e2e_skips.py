#!/usr/bin/env python3
"""Fail closed on skipped E2E tests.

A skip is an outcome someone declared, not a silent pass. A job that runs zero
tests, or that lets an unexpected test skip, looks green while proving nothing —
the same defect class as a workflow that never collects a suite (#762).

Two questions are asked of the JUnit report:

* which tests skipped, and is every one of them declared by the caller
  (``--allowed``)?
* which tests must have run and passed (``--require-passed``)?

Anything else is a failure with a precise message.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List, NamedTuple


class Case(NamedTuple):
    name: str
    classname: str
    skipped: bool
    failed: bool


def read_cases(junit: Path) -> List[Case]:
    """Return every test case in the report."""
    root = ET.parse(junit).getroot()
    cases: List[Case] = []
    for case in root.iter("testcase"):
        cases.append(
            Case(
                name=case.get("name", ""),
                classname=case.get("classname", ""),
                skipped=case.find("skipped") is not None,
                failed=case.find("failure") is not None or case.find("error") is not None,
            )
        )
    return cases


def _matches(name: str, prefix: str) -> bool:
    """Match a test name, allowing for pytest's parametrisation suffix."""
    return name == prefix or name.startswith(prefix + "[")


def _split(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def evaluate(cases: Iterable[Case], allowed: str, required: str) -> List[str]:
    """Return the problems with this run. An empty list means it proved something."""
    cases = list(cases)
    problems: List[str] = []

    if not cases:
        problems.append(
            "no tests were collected; a run that selects nothing cannot fail, so it proves nothing"
        )
        return problems

    declared = _split(allowed)
    undeclared = [
        f"{case.classname}::{case.name}"
        for case in cases
        if case.skipped and not any(_matches(case.name, entry) for entry in declared)
    ]
    if undeclared:
        problems.append(
            "these tests skipped without being declared in E2E_ALLOWED_SKIPS: "
            + ", ".join(sorted(undeclared))
        )

    for prefix in _split(required):
        matching = [case for case in cases if _matches(case.name, prefix)]
        if not matching:
            problems.append(f"{prefix} was required to run but is not in the report")
            continue
        for case in matching:
            if case.skipped:
                problems.append(f"{prefix} was required to pass but skipped")
            elif case.failed:
                problems.append(f"{prefix} was required to pass but failed")

    return problems


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", required=True, type=Path, help="pytest JUnit XML report")
    parser.add_argument(
        "--allowed",
        default="",
        help="comma separated test names permitted to skip (parametrisation suffix allowed)",
    )
    parser.add_argument(
        "--require-passed",
        default="",
        help="comma separated test names that must appear and pass",
    )
    args = parser.parse_args(argv)

    if not args.junit.is_file():
        print(f"ERROR: no JUnit report at {args.junit}", file=sys.stderr)
        return 1

    cases = read_cases(args.junit)
    skipped = sum(1 for case in cases if case.skipped)
    failed = sum(1 for case in cases if case.failed)
    print(
        f"==> E2E report: {len(cases)} test(s), {skipped} skipped, {failed} failed; "
        f"declared skips: {_split(args.allowed) or 'none'}"
    )

    problems = evaluate(cases, args.allowed, args.require_passed)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
