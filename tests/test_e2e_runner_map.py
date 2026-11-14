"""Guards for the E2E test-to-runner map (issue #763).

The DEV runner is a single self-hosted machine and the hosted jobs are cheap, so
the split between them is a correctness boundary, not a preference:

* a suite must not be dropped from both sides (omission),
* a suite must not be selected by two runners (duplication),
* a hosted selection must not quietly acquire a live-only dependency,
* a runner must not claim paths its workflow or script does not actually run.

``tests/e2e/runner_map.toml`` is the single declaration; this module holds it to
account against the files on disk and the CI definitions.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
E2E_DIR = REPO_ROOT / "tests" / "e2e"
MAP_FILE = E2E_DIR / "runner_map.toml"

# Signals that a suite needs a real deployment, SSH, protocol installation or
# the dataplane. A hosted selection may not contain any of them: a local fixture
# cannot prove remote install, client creation or packet traversal.
LIVE_ONLY_SIGNALS = (
    "E2E_SERVER_HOST",
    "E2E_SERVER_SSH_KEY",
    "E2E_REQUIRE_DATAPLANE",
    "tests.e2e.provisioning",
    "tests.e2e.install_failure",
)


def _map() -> dict:
    return tomllib.loads(MAP_FILE.read_text(encoding="utf-8"))


def _runners() -> list[dict]:
    runners = _map().get("runner", [])
    assert runners, "runner_map.toml declares no runners"
    return runners


def _by_name(name: str) -> dict:
    for runner in _runners():
        if runner["name"] == name:
            return runner
    raise AssertionError(f"runner {name!r} is not declared in runner_map.toml")


def _suite_files() -> set[str]:
    return {f"tests/e2e/{path.name}" for path in E2E_DIR.glob("test_*.py")}


def _declared_paths() -> list[str]:
    return [path for runner in _runners() for path in runner["paths"]]


def _workflow_text(runner: dict) -> str:
    return (REPO_ROOT / runner["workflow"]).read_text(encoding="utf-8")


def _job_block(text: str, job_id: str) -> str:
    """Return the YAML block of one job, up to the next top-level job key."""
    marker = f"\n  {job_id}:\n"
    start = text.index(marker)
    rest = text[start + len(marker) :]
    end = len(rest)
    for line in rest.splitlines(keepends=True):
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            end = rest.index(line)
            break
    return rest[:end]


# ── Completeness ─────────────────────────────────────────────────────


def test_every_suite_is_assigned_to_exactly_one_runner() -> None:
    declared = _declared_paths()
    duplicates = {path for path in declared if declared.count(path) > 1}
    assert not duplicates, f"suites assigned to more than one runner: {sorted(duplicates)}"

    on_disk = _suite_files()
    assert on_disk == set(declared), (
        "runner_map.toml and tests/e2e disagree; "
        f"unassigned: {sorted(on_disk - set(declared))}, "
        f"declared but missing: {sorted(set(declared) - on_disk)}"
    )


def test_declared_paths_exist() -> None:
    for path in _declared_paths():
        assert (REPO_ROOT / path).is_file(), f"{path} is declared but does not exist"


# ── The declarations match the CI definitions ───────────────────────


def test_hosted_panel_job_runs_exactly_the_declared_paths() -> None:
    runner = _by_name("hosted-panel")
    block = _job_block(_workflow_text(runner), runner["job"])

    assert "E2E_PATHS:" in block, "the hosted job does not select tests via E2E_PATHS"
    selection = block.split("E2E_PATHS:", 1)[1].splitlines()[0].split()
    assert sorted(selection) == sorted(runner["paths"]), (
        "the hosted job and runner_map.toml select different suites: "
        f"job={sorted(selection)} map={sorted(runner['paths'])}"
    )
    assert "./scripts/run_e2e.sh" in block, (
        "the hosted job must reuse the shared panel harness, not a private copy"
    )


def test_dev_runner_runs_every_declared_live_suite() -> None:
    runner = _by_name("dev-lifecycle")
    script = (REPO_ROOT / runner["script"]).read_text(encoding="utf-8")

    for path in runner["paths"]:
        assert path in script, f"{path} is assigned to the DEV runner but never runs there"

    # The DEV job must execute the script, otherwise the paths above prove nothing.
    assert runner["script"] in _workflow_text(runner), (
        "e2e-dev.yml does not invoke the lifecycle script"
    )


def test_dev_runner_does_not_duplicate_hosted_suites() -> None:
    hosted = set(_by_name("hosted-panel")["paths"]) | set(_by_name("hosted-css")["paths"])
    dev_script = (REPO_ROOT / _by_name("dev-lifecycle")["script"]).read_text(encoding="utf-8")

    for path in sorted(hosted):
        assert path not in dev_script, (
            f"{path} runs on both a hosted runner and the DEV runner; "
            "move it in runner_map.toml instead of running it twice"
        )


def test_css_workflow_runs_its_declared_suite() -> None:
    runner = _by_name("hosted-css")
    text = _workflow_text(runner)

    assert f"\n  {runner['job']}:\n" in text
    for path in runner["paths"]:
        assert path in text, f"{path} is assigned to {runner['name']} but never runs there"


# ── Classification boundary ─────────────────────────────────────────


def test_hosted_selection_has_no_live_only_dependency() -> None:
    for runner in _runners():
        if runner["name"] != "hosted-panel":
            continue
        for path in runner["paths"]:
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            for signal in LIVE_ONLY_SIGNALS:
                assert signal not in text, (
                    f"{path} is hosted but references {signal}; a local fixture cannot "
                    "exercise that contract"
                )


def test_hosted_job_is_labelled_as_panel_only() -> None:
    """The check name must say which kind of run it is, per the issue."""
    runner = _by_name("hosted-panel")
    block = _job_block(_workflow_text(runner), runner["job"])
    name_line = next(line for line in block.splitlines() if line.strip().startswith("name:"))
    assert "panel-only" in name_line, (
        "the hosted browser job must be labelled as panel-only so it cannot be "
        "mistaken for live DEV/dataplane qualification"
    )
