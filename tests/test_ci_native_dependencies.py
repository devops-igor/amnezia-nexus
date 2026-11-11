"""Offline contract for the native-test dependency step in ci.yml.

The step used to install Ubuntu's ``musl`` package, so every native CI run
depended on an Ubuntu package mirror before a single assertion ran. The
replacement takes the loader and libgcc from the same digest-pinned Alpine
image, leaving Docker and the signed Alpine index as the only acquisition path.

Each test extracts the step block from the workflow verbatim, so this file
cannot drift from what GitHub executes. Nothing here touches the network or
writes a loader to the machine running it.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

STEP_NAME = "Install musl loader and libgcc for Native NaiveProxy Tests"
NATIVE_TEST_STEP = "Run Authentic Native Caddy Integration Tests"

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
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == f"- name: {name}"), None
    )
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


def run_block(tmp_path: Path, **shims: str) -> subprocess.CompletedProcess:
    """Execute the real step block with stub ``docker``/``sudo`` shims."""
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name, body in shims.items():
        path = binaries / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    script = tmp_path / "step.sh"
    script.write_text(step_run_block(STEP_NAME), encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{binaries}{os.pathsep}{env.get('PATH', '')}"
    env.pop("GITHUB_PATH", None)
    return subprocess.run(
        ["bash", str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


# The shim that satisfies the step's extraction contract: it receives the
# staging directory as ``<path>:/out`` and must place both artifacts there.
COPY_ARTIFACTS = (
    'for arg in "$@"; do case "$arg" in *:/out) t="${arg%%:/out}";; esac; done\n'
    '[ -n "${t:-}" ] || exit 8\n'
    'printf loader > "$t/ld-musl-x86_64.so.1"\n'
    'printf libgcc > "$t/libgcc_s.so.1"\n'
    "exit 0"
)


def test_step_is_wired_before_the_native_tests():
    text = workflow_text()
    assert STEP_NAME in text
    assert text.index(STEP_NAME) < text.index(NATIVE_TEST_STEP)


def test_no_ubuntu_package_mirror_dependency_remains():
    block = step_run_block(STEP_NAME)
    assert not re.search(r"\bapt-get\b|\bapt\b|\bdpkg\b", block), block
    # The Ubuntu musl package also shipped the loader; nothing may restore it.
    assert "install -y musl" not in workflow_text()


def test_image_is_digest_pinned():
    assert re.search(
        r"alpine:3\.\d+@sha256:[0-9a-f]{64}\b", step_run_block(STEP_NAME)
    )


def test_block_is_valid_bash_and_fails_fast():
    block = step_run_block(STEP_NAME)
    assert "set -euo pipefail" in block
    subprocess.run(["bash", "-n"], input=block, text=True, check=True)


def test_no_escape_hatch_can_hide_a_broken_dependency():
    block = step_run_block(STEP_NAME)
    for token in FALSE_GREEN:
        assert token not in block, token


def test_usability_check_resolves_dependencies_with_the_loader():
    block = step_run_block(STEP_NAME)
    assert "--list" in block, "usability must be proven by resolving dependencies"
    # The loader exits 1 and prints its banner even when the load fails, so a
    # banner/--version grep passes on a broken install and must not be used.
    assert "--version" not in block
    assert "__umodti3" in block and "__udivti3" in block


def test_registry_failure_fails_closed(tmp_path):
    result = run_block(tmp_path, docker="echo 'simulated registry failure' >&2\nexit 9")
    assert result.returncode != 0, result.stdout + result.stderr


def test_silently_empty_staging_directory_fails_closed(tmp_path):
    # apk/docker succeed but copy nothing: the classic silent-partial case,
    # which the native tests would otherwise absorb as SKIP.
    result = run_block(tmp_path, docker="exit 0")
    assert result.returncode != 0, result.stdout + result.stderr


def test_partial_copy_of_only_one_artifact_fails_closed(tmp_path):
    result = run_block(
        tmp_path,
        docker=(
            'for arg in "$@"; do case "$arg" in *:/out) t="${arg%%:/out}";; esac; done\n'
            'printf loader > "$t/ld-musl-x86_64.so.1"\n'
            "exit 0"
        ),
    )
    assert result.returncode != 0, result.stdout + result.stderr


def test_positive_path_reaches_the_install_invocation(tmp_path):
    # Reaching sudo proves every pre-install assertion passed. 97 keeps the
    # test from ever writing a loader to the machine running it.
    result = run_block(tmp_path, docker=COPY_ARTIFACTS, sudo="exit 97")
    assert result.returncode == 97, result.stdout + result.stderr


def test_staging_directory_is_private_and_cleaned_up():
    block = step_run_block(STEP_NAME)
    assert "mktemp -d" in block
    assert re.search(r"trap\s+'?rm -rf", block)
