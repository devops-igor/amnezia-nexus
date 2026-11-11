"""Offline contract for the Naive admission consumer steps in ci.yml.

The two steps this covers exist because a Naive consumer proof can silently
degrade in two ways that both look like success in a remote log: it can skip
because the native binary or the forwardproxy Caddy build is missing, and it can
run green while the payload never left the client. The steps therefore add a
fail-closed prerequisite gate and a skip detector.

A skip detector that is never exercised is the specific risk here. A first draft
matched two greps with a `&&` between them, so a single skip satisfied neither
and the guard could not fire. These tests execute the step blocks verbatim, with
shell stubs in place of the commands that would touch this machine, and assert
the guard's behaviour in both directions: a fully green run passes, and each
skip/failure shape exits non-zero.

Every block is extracted from the workflow, so the file cannot drift from what
GitHub executes. Nothing here runs Go, Caddy, the native binary or the network.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

PREREQ_STEP = "Verify Automatic Naive Consumer Prerequisites"
RUN_STEP = "Run Automatic Naive Admission Consumers"
AWG_RUN_STEP = "Run Automatic AWG Admission Consumers"
NATIVE_INSTALL_STEP = "Install musl loader and libgcc for Native NaiveProxy Tests"

LOADER = "/lib/ld-musl-x86_64.so.1"
INSTALLED_LIBGCC = "/usr/lib/x86_64-linux-musl/libgcc_s.so.1"

# The consumer tests this step must select, by the exact names registered in the
# handlers package. The negative ones are what prove the proof can fail.
CONSUMER_TESTS = (
    "TestAutomaticSetupAdmitsAfterAuthenticNaivePayload",
    "TestAutomaticSetupRefusesWhenTheNaivePayloadIsNeverAnswered",
    "TestAutomaticSetupRefusesWhenNaiveAuthenticationIsRejected",
    "TestNaiveConsumerFixturesAreNotHandshakeOnly",
)

pytestmark = pytest.mark.skipif(
    not CI_WORKFLOW.is_file(), reason="repository workflows not present"
)


def workflow_text() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


def step_run_block(name: str) -> str:
    """Return the dedented ``run:`` script of the named step, verbatim."""
    lines = workflow_text().splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == f"- name: {name}"), None)
    assert start is not None, f"step not found in ci.yml: {name}"

    # A step ends at the next line indented no deeper than a step key (6).
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and len(line) - len(line.lstrip()) <= 6:
            end = index
            break

    for index in range(start + 1, end):
        if lines[index].strip() == "run: |":
            body = []
            for line in lines[index + 1 : end]:
                if line.strip() and len(line) - len(line.lstrip()) <= 8:
                    break
                body.append(line[10:] if len(line) > 10 else "")
            return "\n".join(body)
    raise AssertionError(f"step has no 'run: |' block: {name}")


class Run(NamedTuple):
    """Outcome of executing a step block under stubbed commands."""

    status: int
    calls: list[str]
    output: str


def stub(command: str, body: str) -> str:
    """Bash function shadowing ``command``; records each call's argv in $MARKS."""
    record = "  printf '%s %s\\n' '" + command + "' \"$*\" >> \"$MARKS\""
    body_lines = ["  " + line for line in body.splitlines()]
    return "\n".join(["function " + command + " {", record, *body_lines, "}", "", ""])


# A caddy binary that advertises forward_proxy, as the CI build does.
CADDY_WITH_FORWARD_PROXY = "echo 'http.handlers.forward_proxy'"
# A caddy binary without it: the build silently lost the plugin.
CADDY_WITHOUT_FORWARD_PROXY = "echo 'http.handlers.reverse_proxy'"

# A loader that resolves libgcc; and one that fails, so the gate must fail.
USABLE_LOADER = "return 0"
UNUSABLE_LOADER = "return 126"

# A green go test run: every selected test passed, no skip.
GREEN_RESULTS = "\n".join(f"--- PASS: {name} (0.14s)" for name in CONSUMER_TESTS) + "\nPASS"
# One test skipped, the rest passing: the case the guard exists to catch.
SKIPPED_RESULTS = (
    GREEN_RESULTS.replace(
        f"--- PASS: {CONSUMER_TESTS[0]} (0.14s)",
        f"--- SKIP: {CONSUMER_TESTS[0]} (0.00s)",
    )
)
# A real assertion failure.
FAILING_RESULTS = GREEN_RESULTS.replace(
    f"--- PASS: {CONSUMER_TESTS[1]} (0.14s)",
    f"--- FAIL: {CONSUMER_TESTS[1]} (3.16s)",
)


def run_block(
    tmp_path: Path,
    block: str,
    *,
    results: str = GREEN_RESULTS,
    go_status: int = 0,
    caddy: str = CADDY_WITH_FORWARD_PROXY,
    loader: str = USABLE_LOADER,
) -> Run:
    """Execute ``block`` with go, caddy, the loader and grep stubbed out."""
    marks = tmp_path / "marks"
    marks.write_text("", encoding="utf-8")
    results_file = tmp_path / "results"
    results_file.write_text(results, encoding="utf-8")

    # ``go`` covers both `go test` and `go env GOPATH`; the stub prints the
    # recorded results and exits with the requested status so `tee` sees real
    # output exactly as it would from the tool.
    go_stub = f"cat {results_file}\nreturn {go_status}"
    # The step resolves caddy through `command -v` and then executes the path, so
    # the stub has to be a real executable file whose `list-modules` output is the
    # case under test.
    caddy_path = tmp_path / "caddy"
    caddy_path.write_text("#!/bin/sh\n" + caddy + "\n", encoding="utf-8")
    caddy_path.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(
        "".join(
            [
                stub("go", go_stub),
                stub(LOADER, loader),
                "function command {\n"
                f'  if [ "$1" = "-v" ] && [ "$2" = "caddy" ]; then echo {caddy_path}; return 0; fi\n'
                '  builtin command "$@"\n'
                "}\n\n",
                block,
            ]
        ),
        encoding="utf-8",
    )
    env = {**os.environ, "MARKS": str(marks), "TMPDIR": str(tmp_path)}
    result = subprocess.run(
        ["bash", str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return Run(result.returncode, marks.read_text(encoding="utf-8").splitlines(),
               result.stdout + result.stderr)


def test_both_steps_exist_and_precede_the_coverage_upload():
    text = workflow_text()
    upload = text.index("Upload Test Coverage")
    assert text.index(PREREQ_STEP) < text.index(RUN_STEP) < upload


def test_run_step_selects_exactly_the_four_consumer_names():
    block = step_run_block(RUN_STEP)
    selector = re.search(r"-run '([^']+)'", block)
    assert selector, block
    for name in CONSUMER_TESTS:
        assert name in selector.group(1), name
    # Anchored, so a future near-miss name cannot be swept in silently.
    assert selector.group(1).startswith("^(") and selector.group(1).endswith(")$")


def test_steps_keep_the_bounded_execution_settings():
    block = step_run_block(RUN_STEP)
    for flag in ("-race", "-count=1", "-p 2", "-parallel 2", "-timeout 10m", "-v"):
        assert flag in block, flag
    assert "./internal/handlers/" in block


def executable_lines(block: str) -> str:
    """The block without comments: a token in a comment is not a command."""
    return "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))


def test_no_escape_hatch_can_hide_a_missing_dependency():
    for step in (PREREQ_STEP, RUN_STEP):
        # Comments are excluded deliberately: an explanatory "no `|| true` here"
        # is not an escape hatch, and matching it would make this check vacuous
        # in the other direction by flagging its own documentation.
        code = executable_lines(step_run_block(step))
        for token in ("continue-on-error", "|| true", "set +e"):
            assert token not in code, f"{step}: {token}"
    # The run step deliberately uses `set -uo pipefail`: `-e` would end the block
    # at the test failure before the skip guard could inspect the log, and the
    # explicit `exit "$status"` is what preserves a real failure.
    run = step_run_block(RUN_STEP)
    assert "set -uo pipefail" in run
    assert 'exit "$status"' in run
    assert "PIPESTATUS[0]" in run


def test_scripts_parse():
    for step in (PREREQ_STEP, RUN_STEP):
        subprocess.run(["bash", "-n"], input=step_run_block(step), text=True, check=True)


def test_prerequisite_step_passes_when_both_dependencies_are_present(tmp_path):
    result = run_block(tmp_path, step_run_block(PREREQ_STEP))
    assert result.status == 0, result.output
    # The caddy stub is resolved through `command -v` and then executed, so it
    # records nothing itself; its output proves list-modules was called.
    assert any(c.startswith(LOADER) and "--list" in c for c in result.calls), result.calls
    assert any(INSTALLED_LIBGCC in c for c in result.calls), result.calls


def test_prerequisite_step_fails_when_caddy_lacks_forward_proxy(tmp_path):
    result = run_block(tmp_path, step_run_block(PREREQ_STEP), caddy=CADDY_WITHOUT_FORWARD_PROXY)
    assert result.status != 0, result.output
    assert not any(c.startswith(LOADER) for c in result.calls), "loader check ran anyway"


def test_prerequisite_step_fails_when_the_loader_cannot_resolve_libgcc(tmp_path):
    result = run_block(tmp_path, step_run_block(PREREQ_STEP), loader=UNUSABLE_LOADER)
    assert result.status == 126, result.output


def test_run_step_passes_a_fully_green_consumer_run(tmp_path):
    result = run_block(tmp_path, step_run_block(RUN_STEP))
    assert result.status == 0, result.output
    for name in CONSUMER_TESTS:
        assert f"--- PASS: {name}" in result.output, name


def test_run_step_fails_when_one_consumer_skips(tmp_path):
    """The guard this file exists for: a skip must not look like a pass."""
    result = run_block(tmp_path, step_run_block(RUN_STEP), results=SKIPPED_RESULTS)
    assert result.status != 0, result.output
    assert "no traffic proof was produced" in result.output, result.output


def test_run_step_propagates_a_real_assertion_failure(tmp_path):
    result = run_block(tmp_path, step_run_block(RUN_STEP), results=FAILING_RESULTS, go_status=1)
    assert result.status == 1, result.output
    assert f"--- FAIL: {CONSUMER_TESTS[1]}" in result.output


def test_skip_guard_is_not_vacuous_on_an_all_skip_run(tmp_path):
    all_skip = "\n".join(f"--- SKIP: {name} (0.00s)" for name in CONSUMER_TESTS)
    result = run_block(tmp_path, step_run_block(RUN_STEP), results=all_skip)
    assert result.status != 0, result.output


def test_prerequisite_step_is_wired_before_the_existing_native_install():
    """The consumer steps must not depend on a loader CI installs later."""
    text = workflow_text()
    assert text.index(NATIVE_INSTALL_STEP) < text.index(PREREQ_STEP)


def test_existing_awg_step_is_untouched():
    block = step_run_block(AWG_RUN_STEP)
    assert "TestAutomaticSetupAdmitsAfterAuthenticAWGTraffic" in block
    assert "TestAutomaticSetupRefusesWhenTheAWGPeerNeverAnswers" in block
    # The AWG step predates this change and must not have gained a guard.
    assert "no traffic proof was produced" not in block
