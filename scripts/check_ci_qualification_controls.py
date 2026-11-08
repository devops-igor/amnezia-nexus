#!/usr/bin/env python3
"""Offline regression controls for the #726 CI qualification preflight and collector.

The bodies under test are extracted verbatim from .github/workflows/ci.yml, not
reimplemented, so the assertions track the shipped shell. No container, no network, no
host mutation: everything runs inside a temporary sandbox that stands in for $RUNNER_TEMP
and $GITHUB_WORKSPACE.

Covered control:
  P1  failure after the pre-test step created its evidence directory and published its
      pointer, but before it finished writing the baseline (the observed shape of run
      42252613084 / job 128011401032). Must be NOT RUN and must not error out.
  P0  no pointer at all (initialization never ran).
  P2  pointer that is not this invocation's mktemp basename (absolute path / traversal).
  P3  pointer present, baseline directory present, completeness marker absent.
  X0  complete baseline, no container evidence, tests failed -> no masking error.
  X1  complete baseline, no container evidence, tests succeeded -> hard error.
  G0  pre-test step acquires Git trust for exactly the workspace via GIT_CONFIG_GLOBAL
      inside its own invocation directory, with an empty HOME, and never touches a
      user-global config.

Known limitation, stated rather than papered over: the "dubious ownership" refusal itself
needs a workspace owned by a different uid, which requires root or a chown. That is out of
the authorised scope for this repair, so G0 proves the trust file is invocation-local,
exact-path and sufficient without any user-global configuration instead of reproducing the
uid mismatch.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"

PREFLIGHT_STEP = "Record pre-test runner ownership and workspace state"
COLLECTOR_STEP = "Record post-test runner ownership and workspace state"

PREFLIGHT_INDENT = " " * 10


def extract_container_body() -> str:
    """Return the shell script fed to `docker run` as a heredoc, exactly as shipped.

    The test step pipes a quoted heredoc (`<<'SCRIPT' ... SCRIPT`) into the container, so
    the body is reproduced verbatim between the heredoc opener and its terminator. This is
    what actually executes as root inside the job image, including the evidence-directory
    setup whose ownership the host collector depends on.
    """
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if "<<'SCRIPT'" in line)
    except StopIteration:  # pragma: no cover - guards a rewritten step
        raise SystemExit(f"container heredoc not found in {WORKFLOW}") from None
    end = next(
        i for i in range(start + 1, len(lines)) if lines[i].strip() == "SCRIPT"
    )
    return "\n".join(line.strip() for line in lines[start + 1 : end])


def extract_step_body(step_name: str) -> str:
    """Return the `run:` script of the named step, exactly as shipped."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    try:
        start = next(
            i for i, line in enumerate(lines) if line.strip() == f"- name: {step_name}"
        )
    except StopIteration:  # pragma: no cover - guards a renamed step
        raise SystemExit(f"step not found in {WORKFLOW}: {step_name}") from None
    run_header = next(
        i
        for i in range(start, len(lines))
        if lines[i].rstrip() == " " * 8 + "run: |"
    )
    body: list[str] = []
    for line in lines[run_header + 1 :]:
        if line.strip() and not line.startswith(PREFLIGHT_INDENT):
            break
        body.append(line[len(PREFLIGHT_INDENT) :] if line.strip() else "")
    if not body:  # pragma: no cover - guards an indent change
        raise SystemExit(f"empty body extracted for step: {step_name}")
    return "\n".join(body) + "\n"


class Sandbox:
    """A throwaway stand-in for one runner invocation."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="nexus-qual-control-"))
        self.runner_temp = self.root / "runner_temp"
        self.workspace = self.root / "workspace"
        self.home = self.root / "home"
        self.summary = self.root / "step_summary.md"
        # The container hand-off must live under /tmp: that is the only host-visible mount the
        # job container writes to, and the shipped collector accepts only that shape. Using a
        # private directory here would test a contract the workflow does not have.
        self.shared_tmp = Path("/tmp")
        for path in (self.runner_temp, self.workspace, self.home):
            path.mkdir(parents=True)
        self.summary.write_text("", encoding="utf-8")
        git = shutil.which("git")
        if git is None:  # pragma: no cover - environment guard
            raise SystemExit("git is required to run these controls")
        subprocess.run([git, "init", "-q", str(self.workspace)], check=True)
        subprocess.run(
            [
                git, "-C", str(self.workspace), "-c", "user.name=control",
                "-c", "user.email=control@example.invalid",
                "commit", "-q", "--allow-empty", "-m", "control",
            ],
            check=True,
        )

    @property
    def ident(self) -> str:
        return "run-1-attempt-1-job-test"

    @property
    def pointer(self) -> Path:
        return self.runner_temp / f"nexus-qual-path.{self.ident}.txt"

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": "test",
            "GITHUB_REPOSITORY": "example/example",
            "GITHUB_WORKSPACE": str(self.workspace),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "RUNNER_TEMP": str(self.runner_temp),
            "NEXUS_QUAL_OUT_FILE": str(self.shared_tmp / f"nexus-qual-out-{self.root.name}" / "1-1-test.txt"),
        }
        env.update(extra)
        return env

    def run(self, body: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", body],
            env=self.env(**extra),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def partial_init(self, *, files: tuple[str, ...] = (), with_marker: bool = False) -> None:
        """Reproduce death after directory creation, before the baseline is finished.

        `files` names the baseline files that did get written before the step died; the
        completeness marker is only present when `with_marker` is set.
        """
        qual_dir = Path(tempfile.mkdtemp(prefix="nexus-qual-host.", dir=self.runner_temp))
        host = qual_dir / "host"
        host.mkdir()
        for name in files:
            (host / name).write_text("", encoding="utf-8")
        if with_marker:
            (host / "baseline.state").write_text(
                "baseline_files=identity.txt\n", encoding="utf-8"
            )
        self.pointer.write_text(qual_dir.name + "\n", encoding="utf-8")

    def complete_baseline(self) -> Path:
        host = Path(tempfile.mkdtemp(prefix="nexus-qual-host.", dir=self.runner_temp)) / "host"
        host.mkdir()
        head = subprocess.run(
            ["git", "-C", str(self.workspace), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        (host / "identity.txt").write_text(f"head={head}\n", encoding="utf-8")
        (host / "workspace-pre-test.ls").write_text("", encoding="utf-8")
        (host / "workspace-pre-test.names").write_text("", encoding="utf-8")
        (host / "unwritable-pre-test.txt").write_text("", encoding="utf-8")
        (host / "tasks-pre-test.txt").write_text(
            "inherited_repo_task_area=absent\n", encoding="utf-8"
        )
        (host / "baseline.state").write_text("baseline_files=all\n", encoding="utf-8")
        self.pointer.write_text(host.parent.name + "\n", encoding="utf-8")
        return host

    def cleanup(self) -> None:
        for path in self.root.rglob("*"):
            try:
                path.chmod(0o755 if path.is_dir() else 0o644)
            except OSError:  # pragma: no cover - best effort teardown
                pass
        shutil.rmtree(self.root, ignore_errors=True)
        # Remove only this sandbox's own hand-off directory, named after its own root.
        shutil.rmtree(self.shared_tmp / f"nexus-qual-out-{self.root.name}", ignore_errors=True)


CASES: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str) -> None:
    CASES.append((name, passed, detail))
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")


def main() -> int:
    preflight = extract_step_body(PREFLIGHT_STEP)
    collector = extract_step_body(COLLECTOR_STEP)
    # The container's own shell is the heredoc fed to `docker run` inside the test step.
    # O4 asserts against it verbatim, so the ownership hand-over is checked on the shipped
    # script rather than on a paraphrase.
    container_body = extract_container_body()

    for label, body in (("preflight", preflight), ("collector", collector)):
        parsed = subprocess.run(
            ["bash", "-n", "-c", body], capture_output=True, text=True
        )
        check(f"shell-syntax/{label}", parsed.returncode == 0, parsed.stderr.strip() or "ok")

    # G0 -- the pre-test step itself, against a real repository.
    sandbox = Sandbox()
    try:
        result = sandbox.run(preflight)
        check("G0/preflight-exit", result.returncode == 0, f"exit {result.returncode}")
        check(
            "G0/pointer-basename-only",
            sandbox.pointer.is_file()
            and "/" not in sandbox.pointer.read_text(encoding="utf-8").strip(),
            sandbox.pointer.read_text(encoding="utf-8").strip() or "<missing>",
        )
        qual_dir = sandbox.runner_temp / sandbox.pointer.read_text(encoding="utf-8").strip()
        gitcfg = qual_dir / "gitconfig"
        trust = gitcfg.read_text(encoding="utf-8") if gitcfg.is_file() else ""
        check(
            "G0/exact-workspace-trust",
            trust == f"[safe]\n\tdirectory = {sandbox.workspace}\n",
            trust.replace("\n", "\\n") or "<missing>",
        )
        check(
            "G0/no-wildcard-or-root-trust",
            "*" not in trust and "/**" not in trust and trust.count("directory") == 1,
            "wildcard-free, single entry",
        )
        check(
            "G0/no-user-global-config-written",
            not any(sandbox.home.rglob("gitconfig")) and not (sandbox.home / ".gitconfig").exists(),
            "HOME untouched",
        )
        marker = qual_dir / "host" / "baseline.state"
        check("G0/completeness-marker", marker.is_file(), marker.name)
        check(
            "G0/baseline-set-complete",
            all(
                (qual_dir / "host" / name).is_file()
                for name in (
                    "identity.txt",
                    "workspace-pre-test.ls",
                    "workspace-pre-test.names",
                    "unwritable-pre-test.txt",
                    "tasks-pre-test.txt",
                )
            ),
            "all five baseline files present",
        )
        # The publisher must not leak the host layout into the uploaded pointer or summary.
        summary = sandbox.summary.read_text(encoding="utf-8")
        check(
            "G0/no-absolute-paths-in-summary",
            str(sandbox.runner_temp) not in summary and str(sandbox.root) not in summary,
            "summary carries no host paths",
        )
        # Trust resolves through the invocation file with an empty HOME even when the
        # repository is legitimately owned; the ownership refusal needs root to reproduce.
        resolved = subprocess.run(
            ["git", "config", "--get", "safe.directory"],
            env=sandbox.env(GIT_CONFIG_GLOBAL=str(gitcfg)),
            capture_output=True, text=True,
        )
        check(
            "G0/trust-resolves-with-empty-home",
            resolved.stdout.strip() == str(sandbox.workspace),
            resolved.stdout.strip() or "<empty>",
        )
    finally:
        sandbox.cleanup()

    # F0 -- a workspace whose revision cannot be resolved must not produce a baseline, and
    # must not publish a pointer that a later collector could mistake for a partial init it
    # caused. This covers the guard around the trust acquisition itself.
    sandbox = Sandbox()
    try:
        shutil.rmtree(sandbox.workspace / ".git", ignore_errors=True)
        result = sandbox.run(preflight)
        stream = result.stdout + result.stderr
        check("F0/no-revision-exit", result.returncode == 1, f"exit {result.returncode}")
        check(
            "F0/clear-diagnosis",
            "cannot resolve the workspace revision" in stream,
            "explicit error, not a bare git failure",
        )
        check(
            "F0/no-pointer-published",
            not sandbox.pointer.exists(),
            "no baseline claimed",
        )
    finally:
        sandbox.cleanup()

    # Collector controls. The first case is the exact shape of the deployed failure: the
    # pre-test step created its directory, wrote identity.txt, then died at the Git call, so
    # the pointer existed while workspace-pre-test.names never did.
    scenarios = [
        (
            "P1/partial-init-after-pointer",
            lambda s: s.partial_init(files=("identity.txt",)),
            {},
            0,
            "pre_test_baseline_incomplete",
        ),
        ("P0/no-initialization", lambda s: None, {}, 0, "pre_test_step_did_not_complete"),
        (
            "P2/pointer-not-shape",
            lambda s: (
                s.partial_init(),
                s.pointer.write_text(
                    "/opt/runner-3/_work/_temp/nexus-qual-host.evil\n", encoding="utf-8"
                ),
            ),
            {},
            0,
            "pointer_not_usable",
        ),
        (
            "P3/pointer-without-marker",
            lambda s: s.partial_init(
                files=(
                    "identity.txt",
                    "workspace-pre-test.ls",
                    "workspace-pre-test.names",
                    "unwritable-pre-test.txt",
                    "tasks-pre-test.txt",
                )
            ),
            {},
            0,
            "no_completeness_marker",
        ),
        (
            "P4/marker-but-file-missing",
            lambda s: s.partial_init(files=("identity.txt",), with_marker=True),
            {},
            0,
            "missing:",
        ),
        (
            "X0/complete-baseline-tests-failed",
            lambda s: s.complete_baseline(),
            {"TESTS_OUTCOME": "failed"},
            0,
            None,
        ),
        (
            "X1/complete-baseline-tests-succeeded",
            lambda s: s.complete_baseline(),
            {"TESTS_OUTCOME": "success"},
            1,
            "produced no complete qualification evidence",
        ),
    ]
    for name, setup, extra, want_exit, want_text in scenarios:
        sandbox = Sandbox()
        try:
            setup(sandbox)
            result = sandbox.run(collector, **extra)
            stream = result.stdout + result.stderr + sandbox.summary.read_text(encoding="utf-8")
            check(
                f"{name}/exit",
                result.returncode == want_exit,
                f"exit {result.returncode}, want {want_exit}",
            )
            if want_text is not None:
                check(f"{name}/verdict", want_text in stream, want_text)
            if name.startswith("P"):
                check(
                    f"{name}/not-run",
                    "qualification=NOT_RUN" in stream,
                    "NOT RUN recorded",
                )
                check(
                    f"{name}/no-masking-error",
                    "##[error]" not in stream,
                    "originating failure not masked",
                )
                # A partial baseline must never be promoted to a qualification verdict.
                check(
                    f"{name}/never-complete",
                    "qualification=COMPLETE" not in stream,
                    "no false COMPLETE",
                )
        finally:
            sandbox.cleanup()

    passed = sum(1 for _, ok, _ in CASES if ok)
    print(f"\n{passed}/{len(CASES)} assertions passed")

    # Positive control: a completed baseline plus this invocation's own COMPLETE container
    # evidence must still reach COMPLETE, with the uploaded copy redacted of host paths and
    # the verdict-relevant binding fields intact. Without this, every check above could pass
    # on a collector that simply never succeeds.
    sandbox = Sandbox()
    try:
        host = sandbox.complete_baseline()
        head = subprocess.run(
            ["git", "-C", str(sandbox.workspace), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        qual_dir = Path(tempfile.mkdtemp(prefix="nexus-qualified.", dir=sandbox.shared_tmp))
        (qual_dir / "identity.txt").write_text(
            "state=complete\n"
            f"run_id=1\nrun_attempt=1\njob=test\nrepository=example/example\nhead={head}\n"
            "container_uid=0 container_gid=0\n"
            "job_tmp=/tmp/nexus-tests.abc123\nqual_dir=/tmp/nexus-qualified.abc123\n"
            "gocache=/tmp/nexus-tests.abc123/cache\n"
            "gomodcache=/tmp/nexus-tests.abc123/mod\n"
            f"repo_root={sandbox.workspace}\n"
            "gocache_invocation_owned=true\nexport_invocation_owned=true\n"
            "predecessor_replaced=true\nrepo_task_area_absent=true\n",
            encoding="utf-8",
        )
        out_file = Path(sandbox.shared_tmp / f"nexus-qual-out-{sandbox.root.name}" / "1-1-test.txt")
        out_file.parent.mkdir(parents=True)
        out_file.write_text(f"{qual_dir}\n", encoding="utf-8")
        result = sandbox.run(collector, TESTS_OUTCOME="success")
        stream = result.stdout + result.stderr + sandbox.summary.read_text(encoding="utf-8")
        check("A0/completed->COMPLETE", "qualification=COMPLETE" in stream, "positive control")
        check("A0/exit", result.returncode == 0, f"exit {result.returncode}")
        check("A0/own-dir-removed", not qual_dir.exists(), "own evidence dir removed")
        redacted = sandbox.runner_temp / f"nexus-qual-container.{sandbox.ident}.txt"
        body = redacted.read_text(encoding="utf-8") if redacted.is_file() else ""
        check(
            "A0/uploaded-copy-exists",
            bool(body),
            redacted.name if body else "<missing>",
        )
        check(
            "A0/uploaded-copy-keeps-binding",
            all(key in body for key in ("repository=example/example", f"head={head}",
                                        "state=complete", "gocache_invocation_owned=true")),
            "run/attempt/job/repo/head/state preserved",
        )
        check(
            "A0/uploaded-copy-redacts-host-paths",
            "/tmp/nexus-" not in body and str(sandbox.workspace) not in body
            and "job_tmp=" not in body and "repo_root=" not in body,
            "no absolute container or host paths",
        )
        # The inherited-baseline comparison must still work on the same files.
        check(
            "A0/baseline-comparison-ran",
            (host / "workspace-post-test.names").is_file(),
            "post-test snapshot written",
        )
    finally:
        sandbox.cleanup()

    # ---- ownership boundary between the root container and the host collector ----------
    #
    # The observed failure: the container created /tmp/nexus-qualified.XXXXXX as root with
    # mode 0700, so the non-root collector could neither read identity.txt (it reported
    # container_identity_missing and lost the real qualification) nor remove the directory
    # (rm: Operation not permitted), which failed the step.
    #
    # These controls exercise the real collector body against real directories in a
    # disposable sandbox. The root-owned case cannot be reproduced without root or a chown,
    # which is out of scope here, so it is modelled by a directory owned by another uid when
    # the test user can create one; otherwise the ownership branch is asserted structurally
    # and the limitation is stated rather than papered over.
    sandbox = Sandbox()
    try:
        host = sandbox.complete_baseline()
        head = subprocess.run(
            ["git", "-C", str(sandbox.workspace), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        out_dir = Path(sandbox.shared_tmp / f"nexus-qual-out-{sandbox.root.name}")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "1-1-test.txt"

        def seed_container_dir(complete: bool = True) -> Path:
            d = Path(tempfile.mkdtemp(prefix="nexus-qualified.", dir=sandbox.shared_tmp))
            (d / "identity.txt").write_text(
                (("state=complete\n") if complete else "")
                + "run_id=1\nrun_attempt=1\njob=test\nrepository=example/example\n"
                f"head={head}\ncontainer_uid=0 container_gid=0\n"
                "gocache_invocation_owned=true\nexport_invocation_owned=true\n"
                "predecessor_replaced=true\nrepo_task_area_absent=true\n",
                encoding="utf-8",
            )
            out_file.write_text(f"{d}\n", encoding="utf-8")
            return d

        # O1: a readable directory owned by this user is removed and the step succeeds.
        owned = seed_container_dir()
        result = sandbox.run(collector, TESTS_OUTCOME="success")
        stream = result.stdout + result.stderr + sandbox.summary.read_text(encoding="utf-8")
        check("O1/exit", result.returncode == 0, f"exit {result.returncode}")
        check("O1/removed-own-dir", not owned.exists(), "own evidence dir removed")
        check("O1/verdict-kept", "qualification=COMPLETE" in stream, "COMPLETE preserved")
        if owned.exists():  # pragma: no cover - defensive cleanup
            shutil.rmtree(owned, ignore_errors=True)

        # O2: a directory this user does NOT own must not fail the step. It is reported and
        # left untouched, because rm on a foreign-owned directory in sticky /tmp is EPERM and
        # is not this step's contract to force.
        foreign = seed_container_dir()
        foreign_uid = None
        try:
            other = os.getuid() + 1 if os.getuid() != 0 else 1
            os.chown(foreign, other, os.getgid())
            foreign_uid = other
        except (PermissionError, OSError):
            foreign_uid = None
        if foreign_uid is None:
            check(
                "O2/foreign-owner-skipped",
                True,
                "cannot create a foreign-owned directory without root; ownership branch "
                "asserted structurally (see O4)",
            )
        else:
            result = sandbox.run(collector, TESTS_OUTCOME="success")
            stream = result.stdout + result.stderr + sandbox.summary.read_text(encoding="utf-8")
            check("O2/exit", result.returncode == 0, f"exit {result.returncode}")
            check(
                "O2/not-owned-reported",
                "container_evidence_dir_not_owned" in stream,
                "foreign ownership reported, not failed",
            )
            check("O2/left-untouched", foreign.exists(), "foreign dir not removed")
        if foreign.exists():  # pragma: no cover - defensive cleanup
            try:
                os.chown(foreign, os.getuid(), os.getgid())
            except OSError:
                pass
            shutil.rmtree(foreign, ignore_errors=True)

        # O3: a symlink at the announced path must never be followed or removed.
        target = Path(tempfile.mkdtemp(prefix="nexus-target.", dir=sandbox.shared_tmp))
        link = Path(sandbox.shared_tmp) / f"nexus-qualified.link{sandbox.root.name}"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)
        out_file.write_text(f"{link}\n", encoding="utf-8")
        result = sandbox.run(collector, TESTS_OUTCOME="success")
        stream = result.stdout + result.stderr + sandbox.summary.read_text(encoding="utf-8")
        # A refused handoff means no usable evidence. With TESTS_OUTCOME=success that is the
        # documented fail-closed X1 contract (exit 1, explicit error), not a cleanup failure:
        # the step must never report success for a run whose qualification it could not collect.
        check("O3/exit", result.returncode == 1, f"exit {result.returncode}, want 1 (fail-closed)")
        check("O3/symlink-refused", "handoff_path_is_symlink" in stream, "symlink refused")
        check("O3/target-intact", target.exists(), "symlink target untouched")
        check(
            "O3/no-misleading-cleanup-error",
            "Operation not permitted" not in stream,
            "failure is the explicit evidence error, not a raw rm error",
        )
        link.unlink(missing_ok=True)
        shutil.rmtree(target, ignore_errors=True)

        # O4: the shipped container body must hand the directory to the host identity, and the
        # collector must treat a non-owned directory as a report rather than a hard failure.
        # Asserted on the real extracted bodies, so this tracks the shipped shell.
        check(
            "O4/container-hands-ownership",
            "chown \"$NEXUS_HOST_UID:$NEXUS_HOST_GID\" \"$qual\"" in container_body
            and "NEXUS_HOST_UID" in container_body,
            "container chowns its evidence dir to the host uid",
        )
        check(
            "O4/host-uid-exported",
            '--env NEXUS_HOST_UID="$(id -u)"' in WORKFLOW.read_text(encoding="utf-8"),
            "host uid/gid passed into the container",
        )
        check(
            "O4/collector-ownership-aware",
            "-O \"$d\"" in collector and "container_evidence_dir_not_owned" in collector,
            "collector checks ownership before removing",
        )
        check(
            "O4/no-silent-swallow",
            "|| true" not in collector.split("removed_own_evidence_dir")[0][-400:],
            "cleanup is not silenced with || true",
        )
    finally:
        sandbox.cleanup()

    passed = sum(1 for _, ok, _ in CASES if ok)
    print(f"\n{passed}/{len(CASES)} assertions passed")
    print(f"ALL_CASES_OK={passed == len(CASES)}")
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
