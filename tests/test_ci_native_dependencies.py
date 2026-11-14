"""Offline contract for the native-test dependency step in ci.yml.

The step used to install Ubuntu's ``musl`` package, so every native CI run
depended on an Ubuntu mirror before a single assertion ran. The replacement
takes the loader and libgcc from one digest-pinned Alpine image, leaving Docker
and the signed Alpine index as the only acquisition path.

Every test extracts the step block from the workflow verbatim, so this file
cannot drift from what GitHub executes. Every command that could install,
download or resolve a library is shadowed by a shell function of the same name:
nothing here touches the network or writes a loader to this machine.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Callable, NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

STEP_NAME = "Install musl loader and libgcc for Native NaiveProxy Tests"
NATIVE_TEST_STEP = "Run Authentic Native Caddy Integration Tests"

LOADER = "/lib/ld-musl-x86_64.so.1"
INSTALLED_LIBGCC = "/usr/lib/x86_64-linux-musl/libgcc_s.so.1"

# Anything that would turn a broken dependency into a green or skipped run.
FALSE_GREEN = ("continue-on-error", "|| true", "|| :", "set +e", "2>/dev/null")

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
                body.append(line[10:].lstrip("\n") if len(line) > 10 else "")
            return "\n".join(body)
    raise AssertionError(f"step has no 'run: |' block: {name}")


def executable_lines(block: str) -> str:
    """The block without comments: a token in a comment is not a command."""
    return "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))


class Run(NamedTuple):
    """Outcome of executing a step block under stubbed commands."""

    status: int
    calls: list[str]
    output: str


def calls(run: Run, name: str | None = None) -> list[str]:
    """Stubbed calls in execution order, optionally only those to ``name``."""
    return [c for c in run.calls if name is None or c.split()[0] == name]


# The Docker stand-in honours the step's extraction contract: the staging
# directory arrives as ``<path>:/out`` and both artifacts must land in it.
COPY_ARTIFACTS = (
    'for arg in "$@"; do case "$arg" in *:/out) out="${arg%%:/out}";; esac; done\n'
    '[ -n "${out:-}" ] || return 8\n'
    'printf loader > "$out/ld-musl-x86_64.so.1"\n'
    'printf libgcc > "$out/libgcc_s.so.1"\n'
    "return 0"
)

# A working loader resolves libgcc and exits 0; a partial copy omits libgcc.
USABLE_LOADER = "return 0"
LOADER_ONLY_ARTIFACTS = "\n".join(COPY_ARTIFACTS.splitlines()[:-2] + ["return 0"])

# A broken install still prints the banner the rejected banner-grep matched, on
# stderr. The shell must fail anyway.
UNUSABLE_LOADER = 'echo "musl libc (x86_64) Version 1.2.5" >&2\nreturn 77'


def stub(command: str, body: str) -> str:
    """Bash function shadowing ``command``; records each call's argv in $MARKS."""
    record = "  printf '%s %s\\n' '" + command + "' \"$*\" >> \"$MARKS\""
    body_lines = ["  " + line for line in body.splitlines()]
    return "\n".join(["function " + command + " {", record, *body_lines, "}", "", ""])


def run_script(
    tmp_path: Path, block: str, *, loader: str = USABLE_LOADER, docker: str = COPY_ARTIFACTS
) -> Run:
    """Execute ``block`` with docker, sudo, the loader and grep stubbed out."""
    marks = tmp_path / "marks"
    marks.write_text("", encoding="utf-8")
    script = tmp_path / "step.sh"
    script.write_text(
        "".join(
            [
                stub("docker", docker),
                stub("sudo", "return 0"),
                stub(LOADER, loader),
                stub("grep", "return 0"),
                block,
            ]
        ),
        encoding="utf-8",
    )
    env = {**os.environ, "MARKS": str(marks), "TMPDIR": str(tmp_path)}  # mktemp stays inside
    env.pop("GITHUB_PATH", None)
    result = subprocess.run(
        ["bash", str(script)], cwd=tmp_path, env=env, capture_output=True, text=True,
        timeout=120, check=False,
    )
    calls = marks.read_text(encoding="utf-8").splitlines()
    return Run(result.returncode, calls, result.stdout + result.stderr)


def assert_complete_success(tmp_path: Path, block: str) -> None:
    """A healthy install must run loader validation, then both helper checks."""
    healthy = run_script(tmp_path, block)
    assert healthy.status == 0, healthy.output
    assert calls(healthy, "sudo"), healthy.calls
    names = [c.split()[0] for c in healthy.calls]
    assert names.count(LOADER) == 1, healthy.calls
    at = names.index(LOADER)
    assert "--list" in healthy.calls[at], healthy.calls
    assert INSTALLED_LIBGCC in healthy.calls[at], healthy.calls
    helpers = [i for i, name in enumerate(names) if name == "grep"]
    assert helpers and helpers[0] > at, "helpers must follow validation"
    greps = " ".join(healthy.calls[i] for i in helpers)
    assert "__umodti3" in greps and "__udivti3" in greps, healthy.calls


def assert_unusable_loader_stops_shell(tmp_path: Path, block: str) -> None:
    """An unusable but noisy loader must fail the block before the helper checks."""
    broken = run_script(tmp_path, block, loader=UNUSABLE_LOADER)
    assert calls(broken, LOADER), "loader usability validation never ran"
    assert broken.status == 77, broken.output  # the loader's own status propagates
    assert "musl libc" in broken.output, "fixture banner was not printed"
    assert not calls(broken, "grep"), f"helper checks ran anyway: {broken.calls}"


def test_step_is_wired_before_the_native_tests():
    text = workflow_text()
    assert text.index(STEP_NAME) < text.index(NATIVE_TEST_STEP)


def test_no_ubuntu_package_mirror_dependency_remains():
    assert not re.search(r"\bapt-get\b|\bapt\b|\bdpkg\b", step_run_block(STEP_NAME))
    # The Ubuntu musl package also shipped the loader; nothing may restore it.
    assert "install -y musl" not in workflow_text()


def test_image_is_digest_pinned_and_block_fails_fast():
    block = step_run_block(STEP_NAME)
    assert re.search(r"alpine:3\.\d+@sha256:[0-9a-f]{64}\b", block)
    assert "set -euo pipefail" in block
    subprocess.run(["bash", "-n"], input=block, text=True, check=True)


def test_no_escape_hatch_can_hide_a_broken_dependency():
    for token in FALSE_GREEN:
        assert token not in step_run_block(STEP_NAME), token


def test_usability_check_resolves_dependencies_with_the_loader():
    code = executable_lines(step_run_block(STEP_NAME))
    assert "--list" in code, "usability must be proven by resolving dependencies"
    # The loader exits 1 and prints its banner even when the load fails, so a
    # banner/--version grep passes on a broken install and must not be used.
    assert "--version" not in code
    assert "__umodti3" in code and "__udivti3" in code


ACQUISITION_FAILURES = {
    "registry-failure": ("echo 'simulated registry failure' >&2\nexit 9", 9),
    # apk/docker succeed but copy nothing: the silent-partial case that the
    # native tests would otherwise absorb as SKIP.
    "empty-staging": ("return 0", None),
    "loader-only-staging": (LOADER_ONLY_ARTIFACTS, None),
}


@pytest.mark.parametrize("case", sorted(ACQUISITION_FAILURES))
def test_bad_acquisition_fails_closed_before_install(tmp_path, case):
    docker, expected = ACQUISITION_FAILURES[case]
    result = run_script(tmp_path, step_run_block(STEP_NAME), docker=docker)
    assert result.status != 0, result.output
    assert expected in (None, result.status), result.output
    assert not calls(result, LOADER), "a broken acquisition reached validation"


def test_complete_success_runs_the_loader_and_helper_checks(tmp_path):
    assert_complete_success(tmp_path, step_run_block(STEP_NAME))


def test_unusable_loader_with_a_banner_stops_the_shell(tmp_path):
    assert_unusable_loader_stops_shell(tmp_path, step_run_block(STEP_NAME))


def _is_loader_validation(line: str) -> bool:
    """True for the executable loader validation line, not a comment about it."""
    return not line.lstrip().startswith("#") and LOADER in line


MUTATIONS: dict[str, Callable[[str], str]] = {
    "validation command deleted": lambda block: "\n".join(
        line for line in block.splitlines() if not _is_loader_validation(line)
    ),
    "validation failure swallowed": lambda block: re.sub(
        rf"^{re.escape(LOADER)} --list.*$", r"\g<0> || true", block, flags=re.M
    ),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_oracle_rejects_a_crippled_validation_command(tmp_path, mutation):
    """Deleting or swallowing the real validation must break this file's oracle."""
    block = step_run_block(STEP_NAME)
    crippled = MUTATIONS[mutation](block)
    assert crippled != block, "mutation did not apply"
    detected, missed = [], []
    for probe in (assert_complete_success, assert_unusable_loader_stops_shell):
        try:
            probe(tmp_path, crippled)
        except AssertionError:
            detected.append(probe.__name__)
        else:
            missed.append(probe.__name__)
    assert detected, f"crippled validation passed every probe; missed by {missed}"


def test_staging_directory_is_private_and_cleaned_up():
    block = step_run_block(STEP_NAME)
    assert "mktemp -d" in block and re.search(r"trap\s+'?rm -rf", block)
