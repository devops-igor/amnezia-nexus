"""Guards that keep live DEV verification exclusive and its setup fail-fast.

Issue #764. The DEV host is one machine running destructive, non-idempotent
operations: ``docker compose down -v``, database resets, ``awg0`` teardown and
container replacement. Making the rest of CI parallel must not put a second job
on that host, and it must not let a failed shared prerequisite produce a cascade
of duplicate failures that hides the cause.

The runner that executes that lifecycle is now a GitHub-hosted one (the
self-hosted ARM board it replaced stalled under load, issue 928). The
exclusivity boundary is unchanged, so the runner guard asserts an explicit
GitHub-hosted specification rather than the retired self-hosted label set.

These are static and stub-driven checks; they need no host, container or
network. The fail-fast behaviour itself is proven by running the real lifecycle
script in ``tests/test_e2e_install_failure_finalizer.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
DEV_WORKFLOW = WORKFLOWS / "e2e-dev.yml"
E2E_DIR = REPO_ROOT / "tests" / "e2e"

# Operations that change the host rather than the runner that owns the job.
DESTRUCTIVE = (
    "compose down -v",
    "ip link del awg0",
    "system prune",
    "ip link del awg-client0",
    "ip netns del nexus-client-ns",
)


def _dev_text() -> str:
    return DEV_WORKFLOW.read_text(encoding="utf-8")


def _on_block(text: str) -> str:
    """Return the workflow's trigger block, up to the next top-level key."""
    match = re.search(r"^'?on'?:\s*$", text, re.MULTILINE)
    assert match, "workflow has no trigger block"
    rest = text[match.end() :]
    for line in rest.splitlines(keepends=True):
        if line and not line[0].isspace():
            return rest[: rest.index(line)]
    return rest


# ── One host, one run at a time ─────────────────────────────────────

# The lifecycle gate used to pin a self-hosted `[self-hosted, linux, arm64, dev]`
# board. That four-core ARM SBC stalled under load and produced false failures
# (issue 928), while the same suite finished in 7m47s on a GitHub-hosted runner,
# so the owner moved the gate there. The guard keeps its original strength: an
# absent, empty, expression-based or self-hosted runner still fails, so the
# workflow cannot silently drift onto a runner nobody chose.
#
# The approved image is enumerated, not pattern-matched. A prefix rule accepted
# `ubuntu-anything` and `ubuntu-999.99`, which is exactly the drift this test
# exists to catch: a label nobody chose would have passed. Add an image here
# deliberately when it is the one the gate should run on.
APPROVED_HOSTED_LABELS = frozenset({
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
})

# A declaration, not a mention: `^[ \t]*runs-on:` cannot match a line whose
# first non-space character is `#`, so a commented-out runner requests nothing.
# The character class, not `\s*`, keeps the value on one line: with `\s*` an
# empty `runs-on:` swallows the following line and reads its key as the runner.
RUNS_ON = re.compile(r"^[ \t]*runs-on:[ \t]*(.*?)[ \t]*$", re.MULTILINE)


def _declared_runner_labels(text: str) -> list[list[str]]:
    """Return the label list of every ``runs-on:`` declaration in the workflow."""
    declarations: list[list[str]] = []
    for raw in RUNS_ON.findall(text):
        value = raw.split("#", 1)[0].strip()
        if value.startswith("[") and value.endswith("]"):
            labels = [label.strip().strip("'\"") for label in value[1:-1].split(",")]
            declarations.append([label for label in labels if label])
        else:
            declarations.append([value] if value else [])
    return declarations


def _hosted_runner_problem(labels: list[str]) -> str | None:
    """Return why these labels are not an explicit GitHub-hosted runner, or None."""
    if not labels:
        return "declares no runner: the specification is absent or empty"
    if any("${{" in label for label in labels):
        return f"uses an expression instead of an explicit label: {labels}"
    if "self-hosted" in labels:
        return f"requests a self-hosted runner: {labels}"
    if len(labels) != 1 or labels[0] not in APPROVED_HOSTED_LABELS:
        return (
            "expected one approved GitHub-hosted label "
            f"({', '.join(sorted(APPROVED_HOSTED_LABELS))}), got {labels}"
        )
    return None


def test_dev_workflow_declares_an_explicit_hosted_runner() -> None:
    declarations = _declared_runner_labels(_dev_text())
    assert declarations, "e2e-dev.yml declares no runs-on at all"
    for labels in declarations:
        problem = _hosted_runner_problem(labels)
        assert problem is None, f"e2e-dev.yml {problem}"


def test_the_hosted_runner_guard_still_rejects_drift() -> None:
    """The guard above must keep failing on every drift it exists to catch."""
    assert _hosted_runner_problem(["ubuntu-latest"]) is None
    assert _hosted_runner_problem(["ubuntu-24.04"]) is None
    for drifted in (
        [],
        ["${{ matrix.os }}"],
        ["self-hosted", "linux", "arm64", "dev"],
        ["linux", "arm64"],
        ["ubuntu-latest", "self-hosted"],
        ["ubuntu-latest", "large"],
        ["windows-latest"],
        ["macos-14"],
        # Ubuntu-shaped but not approved: a prefix rule used to accept these,
        # which would have let an image nobody chose run a privileged,
        # destructive lifecycle against a real host.
        ["ubuntu-anything"],
        ["ubuntu-999.99"],
        ["ubuntu-dev"],
    ):
        assert _hosted_runner_problem(drifted) is not None, drifted
    assert _declared_runner_labels("jobs:\n  a:\n    steps: []\n") == []
    # An empty declaration must not borrow the next line's key as its runner,
    # and a commented-out line is not a declaration at all.
    assert _declared_runner_labels("    runs-on:\n    timeout-minutes: 90\n") == [[]]
    assert _declared_runner_labels("    # runs-on: ubuntu-latest\n") == []


def test_dev_workflow_serialises_runs_without_cancelling() -> None:
    text = _dev_text()
    assert re.search(r"^\s+group:\s*dev-server-deployment\s*$", text, re.MULTILINE), (
        "the cross-run concurrency group is what keeps two deployments off the host"
    )
    assert re.search(r"^\s+cancel-in-progress:\s*false\s*$", text, re.MULTILINE), (
        "cancelling an in-flight run would interrupt a destructive operation "
        "mid-teardown, leaving the host in an unknown state"
    )


def test_dev_workflow_cannot_be_triggered_by_a_pull_request() -> None:
    triggers = _on_block(_dev_text())
    assert "pull_request" not in triggers, (
        "a pull request must never reach the DEV host; the hosted panel-only job "
        "covers browser contracts per PR instead"
    )


def test_no_other_workflow_runs_on_the_dev_host() -> None:
    """Read the runs-on labels, not every mention: comments may name the host."""
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        if workflow.name == DEV_WORKFLOW.name:
            continue
        text = workflow.read_text(encoding="utf-8")
        for line in re.findall(r"^\s*runs-on:\s*(.+)$", text, re.MULTILINE):
            assert "self-hosted" not in line, (
                f"{workflow.name} requests a self-hosted runner ({line.strip()}); "
                "only e2e-dev.yml may touch the DEV host"
            )


def test_destructive_host_operations_live_only_in_the_dev_workflow() -> None:
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        if workflow.name == DEV_WORKFLOW.name:
            continue
        text = workflow.read_text(encoding="utf-8")
        for operation in DESTRUCTIVE:
            assert operation not in text, (
                f"{workflow.name} performs {operation!r}, which belongs to the DEV "
                "workflow that owns the concurrency group"
            )


# ── Shared prerequisites are provisioned once ───────────────────────


def test_multi_protocol_install_runs_once_per_module() -> None:
    """The module installs its protocols in a module-scoped fixture, not per test.

    Four separate install attempts turned one slow install into four identical
    failures; the fixture keeps one attempt and one precise error.
    """
    text = (E2E_DIR / "test_multiprotocol_clients.py").read_text(encoding="utf-8")

    fixture = re.search(
        r'@pytest\.fixture\(scope="module"\)\s*\ndef provisioned_protocols', text
    )
    assert fixture, "provisioned_protocols must stay module-scoped"
    assert text.count('/install"') == 1, (
        "the install POST must appear once, inside the provisioning fixture"
    )


def test_no_suite_repeats_a_real_protocol_install_per_test() -> None:
    """A suite may assert install behaviour once; it may not provision per test.

    Route-mocked suites are exempt: they intercept the request to assert the
    payload, so they never provision anything.
    """
    offenders: list[str] = []
    for suite in sorted(E2E_DIR.glob("test_*.py")):
        text = suite.read_text(encoding="utf-8")
        if 'page.route("**/api/servers/*/install"' in text:
            continue
        if text.count('"/install"') > 1:
            offenders.append(suite.name)
    assert not offenders, (
        "these suites POST install more than once and will duplicate a single "
        f"installation failure: {offenders}"
    )
