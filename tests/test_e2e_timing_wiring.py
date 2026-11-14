"""Wiring regressions for the timing diagnostic: activation and CI coverage.

These exist because the first delivery's retention path was wrong in a way no
unit test caught: the panel runs in a container, so a variable exported in the
host shell never reaches the process that reads it. A collector that finds
nothing is indistinguishable from a provider that was fast, so this wiring is
asserted rather than assumed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEV_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "e2e-dev.yml"
LIFECYCLE = REPO_ROOT / "scripts" / "run_e2e_lifecycle.sh"
PANEL_HANDLER = REPO_ROOT / "internal" / "handlers" / "gigahost.go"
TIMING_GO = REPO_ROOT / "internal" / "provider" / "gigahost" / "timing.go"
COLLECTOR = REPO_ROOT / "tests" / "e2e" / "diagnostics.py"

pytestmark = pytest.mark.skipif(
    not CI_WORKFLOW.is_file(), reason="repository workflows not present"
)


def test_panel_reads_the_documented_timing_variable():
    """The Go side must gate the sink on the same variable the workflow sets.

    Reading the variable is not enough: it has to actually attach the timing
    sink, otherwise the collector can only ever find nothing and a missing
    report stays indistinguishable from a fast provider.
    """
    handler = PANEL_HANDLER.read_text(encoding="utf-8")
    assert "GIGAHOST_CALL_TIMING" in handler
    assert "timingEnabled()" in handler, "the flag must be read through one gate"
    assert "gigahost.CallTimingMarker" in handler, (
        "the gate must attach the sink that emits the collector's marker"
    )


def test_dev_workflow_passes_the_flag_into_the_container():
    """A host-shell export does not cross into Docker; it must be in the override."""
    text = DEV_WORKFLOW.read_text(encoding="utf-8")
    override = re.search(r"docker-compose\.override\.yaml(.*?)EOF", text, re.S)
    assert override, "DEV workflow must define a compose override for the panel"
    block = override.group(1)
    assert "GIGAHOST_CALL_TIMING" in block, (
        "GIGAHOST_CALL_TIMING must be passed through the container environment, "
        "not exported in the host shell"
    )


def test_dev_workflow_asserts_the_flag_inside_the_container():
    """Activation must be verified in the container, like E2E_TESTING is."""
    text = DEV_WORKFLOW.read_text(encoding="utf-8")
    assert "printenv GIGAHOST_CALL_TIMING" in text, (
        "the workflow must prove the flag reached the panel process, otherwise a "
        "missing collector report is indistinguishable from a fast provider"
    )


def test_lifecycle_collector_receives_the_timing_log():
    """The pre-teardown collector must be told to extract these records."""
    text = LIFECYCLE.read_text(encoding="utf-8")
    assert "--call-timing-log" in text
    # Collection must stay before teardown, i.e. inside finalize().
    finalize = re.search(r"^finalize\(\)\s*\{(.*?)^\}", text, re.S | re.M)
    assert finalize, "finalize() must exist"
    assert "--call-timing-log" in finalize.group(1)


def test_privacy_gate_runs_the_offline_timing_suite():
    """The pure-Python timing schema tests must be enforced on ordinary PRs."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "tests/test_e2e_call_timing_privacy.py" in text


def test_subprocess_proof_runs_in_a_go_enabled_job():
    """The real-binary collector proof needs Go, so it needs its own job."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "tests/test_e2e_call_timing_subprocess.py" in text
    job = re.search(
        r"diagnostics-timing-collector:(.*?)(?=^\s{2}[a-z0-9-]+:\s*$|\Z)", text, re.S | re.M
    )
    assert job, "a dedicated job must run the subprocess proof"
    block = job.group(1)
    assert "setup-go" in block, "the subprocess job needs Go"
    assert "TIMING_COLLECTOR_REQUIRE_GO=1" in block, (
        "the subprocess job must require Go, so a missing toolchain fails the job "
        "instead of silently skipping the only real-output proof"
    )


def test_collector_requires_go_explicitly_when_asked():
    """The enforcement switch must exist in the test module itself."""
    text = (REPO_ROOT / "tests" / "test_e2e_call_timing_subprocess.py").read_text(encoding="utf-8")
    assert "TIMING_COLLECTOR_REQUIRE_GO" in text
    assert "pytest.fail" in text


def test_collector_marker_matches_the_go_marker():
    """A drifted marker would make the collector silently find nothing."""
    go_text = TIMING_GO.read_text(encoding="utf-8")
    go_match = re.search(r'CallTimingMarker\s*=\s*"([^"]+)"', go_text)
    assert go_match, "the Go marker constant must exist"
    marker = go_match.group(1)
    py_text = COLLECTOR.read_text(encoding="utf-8")
    assert f"CALL_TIMING_MARKER = \"msg={marker}\"" in py_text, (
        f"collector marker must match the Go marker {marker!r}"
    )


def test_collector_closed_sets_match_the_go_outcome_classes():
    """Outcome drift would silently reject real records at collection time."""
    go_text = TIMING_GO.read_text(encoding="utf-8")
    go_outcomes = set(re.findall(r'Outcome\w+\s+CallOutcome\s*=\s*"([a-z_]+)"', go_text))
    assert go_outcomes, "expected outcome constants in timing.go"
    py_text = COLLECTOR.read_text(encoding="utf-8")
    block = re.search(r"_TIMING_OUTCOMES = frozenset\((.*?)\)\n", py_text, re.S)
    assert block, "collector must declare the closed outcome set"
    py_outcomes = set(re.findall(r'"([a-z_]+)"', block.group(1)))
    missing = go_outcomes - py_outcomes
    assert not missing, f"collector is missing Go outcome classes: {sorted(missing)}"
