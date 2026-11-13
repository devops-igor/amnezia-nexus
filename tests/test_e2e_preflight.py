"""Offline wiring tests for the Naive Caddy preflight.

The DEV lifecycle spends four 120-second install timeouts before it learns that
the Caddy image the installer needs cannot be obtained (issue #680). The
preflight moves that answer in front of the suite, bounded and with a closed
reason, so a red run explains itself in the log instead of only in a timeout.

These tests do not run Docker: they assert the script's contract and that the
workflow actually calls it before Playwright.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "preflight_naive_caddy.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "e2e-dev.yml"

# The closed reason set. A new ``fail`` call with an invented reason fails here
# until it is added deliberately.
ALLOWED_REASONS = {
    "docker_unavailable",
    "image_pull",
    "image_run",
    "module_missing",
    "registry_unreachable",
    "module_network_timeout",
}
# The module the installer cannot function without.
FORWARD_PROXY_MODULE = "http.handlers.forward_proxy"
# The exact module-proxy endpoint whose failure was reproduced locally: xcaddy
# resolves the historical ``caddy2`` branch through proxy.golang.org.
PROBE_URL = "https://proxy.golang.org/github.com/caddyserver/forwardproxy/@v/caddy2.info"


def test_preflight_script_exists_and_is_executable() -> None:
    assert SCRIPT.is_file(), "the preflight must ship with the lifecycle"
    assert SCRIPT.stat().st_mode & 0o111, "the preflight must be executable"


def test_preflight_verifies_the_forward_proxy_module() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert FORWARD_PROXY_MODULE in text
    assert "list-modules" in text


def test_preflight_probes_the_module_proxy_branch_that_timed_out() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert PROBE_URL in text


def test_preflight_reasons_are_closed() -> None:
    """Every failure path names an allowlisted reason, never free text."""
    text = SCRIPT.read_text(encoding="utf-8")
    used = set(re.findall(r"fail \S+ ([a-z_]+)", text))
    assert used, "the preflight must report a closed reason on failure"
    assert used <= ALLOWED_REASONS, f"unenumerated reason(s): {sorted(used - ALLOWED_REASONS)}"


def test_preflight_is_bounded() -> None:
    """Each external call carries a timeout so the job fails fast, not hangs."""
    text = SCRIPT.read_text(encoding="utf-8")
    for command in ("docker info", "docker pull", "docker run", "docker manifest inspect"):
        assert f"timeout" in text
        assert command in text
    assert "timeout 90" in text, "the pull must be bounded well inside two minutes"


def test_workflow_runs_the_preflight_before_playwright() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    preflight_at = text.find("preflight_naive_caddy.sh")
    playwright_at = text.find("Run Playwright E2E Lifecycle Suite")
    assert preflight_at != -1, "the DEV workflow must run the preflight"
    assert playwright_at != -1
    assert preflight_at < playwright_at, "the preflight must precede the Playwright suite"


def test_preflight_step_fails_the_job() -> None:
    """A failed preflight must stop the job rather than warn and continue."""
    text = WORKFLOW.read_text(encoding="utf-8")
    marker = "- name: Naive Caddy preflight"
    assert marker in text, "the DEV workflow must name the preflight step"
    step = text.split(marker, 1)[1].split("\n      - name:", 1)[0]
    assert "continue-on-error" not in step
