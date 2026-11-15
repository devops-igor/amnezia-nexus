"""Guards for the E2E skip policy (issue #763 review).

A skip count is not a policy: "at most one skip" accepts any skip, including a
real test hiding behind a missing prerequisite. The policy is identity-based —
the caller names the tests that may skip — and the rate-limit rerun must prove
the test ran rather than skipped.

These tests drive the real checker with synthetic JUnit reports, and then assert
the workflow asks the right questions of it.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = REPO_ROOT / "scripts" / "check_e2e_skips.py"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _load():
    spec = importlib.util.spec_from_file_location("check_e2e_skips", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _case(name: str, skipped: bool = False, failed: bool = False):
    checker = _load()
    return checker.Case(
        name=name, classname="tests.e2e.test_auth", skipped=skipped, failed=failed
    )


def _problems(cases, allowed: str = "", required: str = "") -> list[str]:
    return _load().evaluate(cases, allowed, required)


# ── The policy itself ───────────────────────────────────────────────


def test_a_declared_skip_is_accepted() -> None:
    cases = [_case("test_login_page_loads[chromium]"), _case("test_login_rate_limiting[chromium]", skipped=True)]
    assert _problems(cases, allowed="test_login_rate_limiting") == []


def test_an_undeclared_skip_is_rejected_even_when_only_one() -> None:
    """The previous policy allowed one skip of any identity."""
    cases = [_case("test_login_page_loads[chromium]", skipped=True)]
    problems = _problems(cases, allowed="test_login_rate_limiting")
    assert problems, "a skip that was never declared must fail the run"
    assert "test_login_page_loads" in problems[0]


def test_a_skip_with_no_declaration_at_all_is_rejected() -> None:
    assert _problems([_case("test_settings_page_loads[chromium]", skipped=True)])


def test_a_run_that_collects_nothing_is_rejected() -> None:
    """A job that selects nothing is green without proving anything."""
    assert _problems([], allowed="test_login_rate_limiting")


def test_a_required_test_that_passed_is_accepted() -> None:
    assert _problems([_case("test_login_rate_limiting[chromium]")], required="test_login_rate_limiting") == []


def test_a_required_test_that_skipped_is_rejected() -> None:
    problems = _problems(
        [_case("test_login_rate_limiting[chromium]", skipped=True)],
        required="test_login_rate_limiting",
    )
    assert problems and "skipped" in problems[0]


def test_a_required_test_that_did_not_run_is_rejected() -> None:
    problems = _problems([_case("test_login_page_loads[chromium]")], required="test_login_rate_limiting")
    assert problems and "not in the report" in problems[0]


def test_a_required_test_that_failed_is_rejected() -> None:
    problems = _problems(
        [_case("test_login_rate_limiting[chromium]", failed=True)],
        required="test_login_rate_limiting",
    )
    assert problems and "failed" in problems[0]


def test_prefixes_do_not_match_other_tests() -> None:
    """`test_login` must not declare `test_login_rate_limiting` as covered."""
    cases = [_case("test_login_rate_limiting[chromium]", skipped=True)]
    assert _problems(cases, allowed="test_login")


# ── The workflow asks the right questions ───────────────────────────


def _hosted_job() -> str:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    key = re.search(r"^  e2e-hosted:\s*$", text, re.MULTILINE)
    assert key, "ci.yml has no e2e-hosted job"
    rest = text[key.end() :]
    following = re.search(r"^  [A-Za-z0-9_-]+:\s*$", rest, re.MULTILINE)
    return rest[: following.start()] if following else rest


def test_hosted_job_declares_the_only_skip_it_expects() -> None:
    job = _hosted_job()
    assert "E2E_ALLOWED_SKIPS: test_login_rate_limiting" in job, (
        "the hosted job must name the one test allowed to skip, not a count"
    )
    assert "MAX_EXPECTED_SKIPS" not in job, "a count budget accepts any skip of any identity"


def test_hosted_job_requires_the_rate_limit_rerun_to_pass() -> None:
    script = (REPO_ROOT / "scripts" / "run_e2e.sh").read_text(encoding="utf-8")
    rerun = script.split("Verifying login rate-limiting test", 1)[1]
    assert "--require-passed test_login_rate_limiting" in rerun, (
        "the rerun exists to prove the test runs; without this it may skip and still pass"
    )
    assert "--junitxml" in rerun, "the rerun must produce evidence the checker can read"


def test_first_run_reports_a_junit_file_to_the_policy() -> None:
    script = (REPO_ROOT / "scripts" / "run_e2e.sh").read_text(encoding="utf-8")
    first_run = script.split("Running Playwright E2E tests", 1)[1].split("Verifying skips", 1)[0]
    assert "--junitxml" in first_run
    assert "check_e2e_skips.py" in script.split("Verifying skips", 1)[1]
