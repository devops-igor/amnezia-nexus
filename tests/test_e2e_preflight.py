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
    "host_network_unreachable",
    "dns_failure",
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
    for bounded in (
        "timeout 15 docker info",
        "timeout 30 docker manifest inspect",
        "timeout 60 docker pull",
        "timeout 20 docker run",
    ):
        assert bounded in text, f"missing bound: {bounded}"
    # A single probe attempt: busybox wget retries by default, which would
    # silently consume the whole budget and hide which layer failed.
    assert "-t 1" in text


def test_host_egress_is_measured_before_the_container_probe() -> None:
    """The run must show whether the host or the container is the blocked side."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "host_egress" in text
    host_at = text.find("host_egress")
    container_at = text.find("module_probe")
    assert host_at < container_at, "host egress must be measured before the container probe"


def test_container_dns_is_separated_from_reachability() -> None:
    """A resolver failure and a blocked TCP path must not share one reason."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "nslookup" in text
    assert "dns_failure" in text
    assert "module_network_timeout" in text
    dns_at = text.find("module_dns")
    probe_at = text.find("module_probe")
    assert dns_at != -1 and dns_at < probe_at


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
