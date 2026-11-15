"""Guards for the shipped Caddy binary used by the naive fixtures (issue #766).

The fixtures need a Caddy binary with ``forward_proxy``. The product already
ships one as a digest-pinned image, so CI extracts that binary instead of
compiling a second one with a second forwardproxy pin. These guards keep it that
way: one artifact, one pin, verified before use.

The step block is executed verbatim with stubbed ``docker``, so the happy path
and both failure paths are exercised rather than described.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

from tests.test_ci_native_dependencies import executable_lines, step_run_block

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
NAIVE_SOURCE = REPO_ROOT / "internal" / "manager" / "naive" / "naive.go"

STEP = "Provide the shipped Caddy binary for Naive fixtures"
MODULE = "http.handlers.forward_proxy"


def _workflow() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


def _step_span(text: str, name: str) -> tuple[int, int]:
    start = text.index(f"- name: {name}")
    end = text.find("\n      - name:", start + 1)
    return start, len(text) if end == -1 else end


# ── One artifact, one pin ───────────────────────────────────────────


def test_the_reference_is_read_from_the_go_source() -> None:
    """A second hardcoded digest is the drift this replaces."""
    start, end = _step_span(_workflow(), STEP)
    step = _workflow()[start:end]

    assert "internal/manager/naive/naive.go" in step, (
        "the step must read the pinned reference from the Go source"
    )
    assert "NaiveImageRepository" in step and "NaiveImageDigest" in step
    assert "NaiveForwardProxyCommit" in step, (
        "the reported plugin version must be checked against the binary"
    )
    assert "sha256:" not in step, "the digest must not be repeated in the workflow"


def test_no_second_caddy_build_remains() -> None:
    workflow = _workflow()
    assert "xcaddy" not in workflow, (
        "CI must not compile a second Caddy now that the shipped binary is used"
    )
    assert "actions/cache" not in workflow, (
        "the image is already content-addressed; a second cache is another thing to poison"
    )


def test_the_go_source_still_declares_both_constants() -> None:
    """The step's sed patterns are only correct while these names exist."""
    source = NAIVE_SOURCE.read_text(encoding="utf-8")
    assert re.search(r'NaiveImageRepository\s*=\s*"[^"]+"', source)
    assert re.search(r'NaiveImageDigest\s*=\s*"sha256:[0-9a-f]{64}"', source)
    assert re.search(r'NaiveForwardProxyCommit\s*=\s*"[0-9a-f]{40}"', source)


# ── Verified before use, never fail open ────────────────────────────


def test_the_binary_is_verified_before_it_is_used() -> None:
    block = executable_lines(step_run_block(STEP))
    assert "list-modules | grep -qx" in block, (
        "a binary that cannot advertise forward_proxy must not reach the tests"
    )
    assert block.index("list-modules") < block.index("GITHUB_PATH"), (
        "verification must happen before the binary is published on PATH"
    )


def test_the_plugin_revision_is_read_from_build_metadata() -> None:
    """A module name does not say which forwardproxy revision is inside."""
    block = executable_lines(step_run_block(STEP))
    assert "go version -m" in block, (
        "the pinned forwardproxy revision must be verified from the binary's build info"
    )
    assert "github.com/klzgrad/forwardproxy" in block
    assert block.index("go version -m") < block.index("GITHUB_PATH")


def test_the_step_cannot_fail_open() -> None:
    start, end = _step_span(_workflow(), STEP)
    step = _workflow()[start:end]
    assert "continue-on-error" not in step
    assert "if: false" not in step

    # `|| true` is only allowed on cleanup: a failed container removal must not
    # replace the real exit status, and it gates nothing.
    for line in executable_lines(step_run_block(STEP)).splitlines():
        if "|| true" in line:
            assert "docker rm" in line, f"fail-open marker on a gate line: {line.strip()}"


# ── Behaviour, executed with stubs ──────────────────────────────────


PINNED_COMMIT = "e747854e78743dba85c039b38ed185fb11d93667"


def _build_info(commit: str | None) -> str:
    """Go build metadata as `go version -m` prints it for the shipped binary."""
    lines = [
        "caddy: go1.27.4",
        "\tpath\tcaddy",
        "\tmod\tcaddy\t(devel)\t",
        "\tdep\tgithub.com/caddyserver/caddy/v2\tv2.11.9\th1:bhZtcRKQOq0fuLvEgCdPYvUxXyGn9kzjG4lh2332DTE=",
        "\tdep\tgithub.com/caddyserver/forwardproxy\tv0.0.0-20240212043213-bf7eb3105151",
    ]
    if commit is not None:
        lines.append(
            "\t=>\tgithub.com/klzgrad/forwardproxy\tv0.0.0-20261022172731-"
            f"{commit}\th1:mPxEAShMwwnq1AC2kVYxzYlcPkchA7qLGK7mLgx8XtY="
        )
    return "\n".join(lines) + "\n"


def _run_step(
    tmp: Path,
    module_present: bool = True,
    pull_ok: bool = True,
    constants: bool = True,
    built_commit: str | None = PINNED_COMMIT,
) -> subprocess.CompletedProcess:
    """Execute the real step with stubbed docker and go.

    ``built_commit`` is the forwardproxy revision the extracted binary records;
    ``None`` means the binary records no replacement at all.
    """
    (tmp / "internal" / "manager" / "naive").mkdir(parents=True)
    source = tmp / "internal" / "manager" / "naive" / "naive.go"
    if constants:
        source.write_text(
            "package naive\n\nconst (\n"
            '\tNaiveImageRepository = "ghcr.io/example/naive-caddy"\n'
            '\tNaiveImageDigest = "sha256:' + "a" * 64 + '"\n'
            f'\tNaiveForwardProxyCommit = "{PINNED_COMMIT}"\n)\n',
            encoding="utf-8",
        )
    else:
        source.write_text("package naive\n", encoding="utf-8")

    build_info = tmp / "build-info.txt"
    build_info.write_text(_build_info(built_commit), encoding="utf-8")

    bindir = tmp / "bin"
    bindir.mkdir()
    modules = MODULE if module_present else "http.handlers.file_server"
    (bindir / "docker").write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            case "$1" in
              pull) [ {1 if pull_ok else 0} -eq 1 ] || exit 1 ;;
              create) echo fake-container ;;
              cp)
                dest="$3"
                mkdir -p "$(dirname "$dest")"
                printf '#!/bin/sh\ncase "$1" in\n  version) echo "v2.11.9 h1:stub" ;;\n  list-modules) echo "{modules}" ;;\nesac\n' > "$dest"
                chmod 755 "$dest"
                ;;
              rm) exit 0 ;;
            esac
            """
        ),
        encoding="utf-8",
    )
    (bindir / "docker").chmod(0o755)

    # `go version -m <binary>` is answered from the fixture above.
    (bindir / "go").write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            if [ "$1" = "version" ] && [ "$2" = "-m" ]; then cat "{build_info}"; exit 0; fi
            exit 1
            """
        ),
        encoding="utf-8",
    )
    (bindir / "go").chmod(0o755)

    runner_temp = tmp / "runner-temp"
    runner_temp.mkdir()
    github_path = tmp / "github_path"
    github_path.touch()
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_PATH": str(github_path),
    }
    return subprocess.run(
        ["bash", "-c", step_run_block(STEP)],
        capture_output=True,
        text=True,
        cwd=tmp,
        env=env,
        timeout=120,
        check=False,
    )


def test_the_shipped_binary_is_extracted_and_published(tmp_path: Path) -> None:
    result = _run_step(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    binary = tmp_path / "runner-temp" / "caddy" / "caddy"
    assert binary.is_file(), "the binary must be extracted from the image"
    published = (tmp_path / "github_path").read_text(encoding="utf-8")
    assert "runner-temp/caddy" in published, "the binary must land on PATH"
    assert "Using shipped Caddy" in result.stdout


def test_a_binary_without_forward_proxy_fails_the_step(tmp_path: Path) -> None:
    result = _run_step(tmp_path, module_present=False)

    assert result.returncode != 0, "an image without forward_proxy must not pass"


def test_a_failed_pull_fails_the_step(tmp_path: Path) -> None:
    result = _run_step(tmp_path, pull_ok=False)

    assert result.returncode != 0, "a registry failure must not be swallowed"


def test_a_missing_reference_fails_the_step(tmp_path: Path) -> None:
    result = _run_step(tmp_path, constants=False)

    assert result.returncode != 0
    assert "could not read the pinned naive-caddy reference" in result.stdout + result.stderr


def test_the_wrong_plugin_revision_is_rejected(tmp_path: Path) -> None:
    """The gap this closes: right Caddy version and module, wrong forwardproxy.

    `caddy list-modules` says only that the handler registered. A binary built
    from a different forwardproxy commit would pass that check while the panel
    reports NaiveForwardProxyCommit as the installed plugin version.
    """
    result = _run_step(tmp_path, built_commit="c096d6a00cb28e019cc1995b04bdc6a9311d8024")

    assert result.returncode != 0, "a different forwardproxy revision must fail the step"
    combined = result.stdout + result.stderr
    assert "does not record forwardproxy" in combined
    assert PINNED_COMMIT in combined, "the failure must name the pinned commit"


def test_a_binary_without_a_forwardproxy_replacement_is_rejected(tmp_path: Path) -> None:
    result = _run_step(tmp_path, built_commit=None)

    assert result.returncode != 0, "a binary with no recorded replacement must not pass"


def test_the_pinned_revision_is_accepted(tmp_path: Path) -> None:
    result = _run_step(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "forwardproxy e747854e7874" in result.stdout
