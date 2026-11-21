"""Read-only E2E checks for the VPN health surface and its diagnostics disclosure.

The problem-first summary, the four overview signals and the single Advanced
Diagnostics entry belong together: they are one rendering contract, and a check
of any of them opens the same disclosure to read it. The neighbouring
``test_vpn_diagnostics.py`` suite keeps the lifecycle, historical-chart and API
coverage, and supplies the disclosure opener used here.
"""

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get
from tests.e2e.test_vpn_diagnostics import _ensure_diagnostics_open

@pytest.mark.e2e
def test_vpn_dashboard_navigation_and_banner(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> sees headline forwarder health status banner."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Verify not redirected to login
    assert "/login" not in page.url
    assert "/vpn" in page.url

    # One visible health status plus the four essential signals.
    for loc in ("#vpn-fwd-status-badge", "#vpn-fwd-status-text", "#vpn-fwd-headline-summary"):
        expect(page.locator(loc)).to_be_visible()
    expect(page.locator("#vpn-forwarder-card #vpn-kpi-throughput")).to_have_count(0)
    expect(page.locator("#vpn-fwd-tech-details")).to_have_count(0)
    expect(page.locator("#vpn-fwd-summary-header")).to_have_count(0)
    expect(page.locator("#vpn-active-tunnels")).to_have_count(0)


@pytest.mark.e2e
def test_vpn_overview_signals(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> exactly four overview signals, no duplicated KPI tiles."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    signals = page.locator("[data-signal]")
    expect(signals).to_have_count(4)
    assert ["backends", "sessions", "throughput", "drops"] == [
        signals.nth(i).get_attribute("data-signal") for i in range(4)
    ]

    # No retired KPI tile survives.
    for key in (
        "throughput routes-sessions queue-pressure packet-loss "
        "client-engine peer-sync backends slow-writes"
    ).split():
        expect(page.locator(f"#vpn-kpi-{key}")).to_have_count(0)

    # The Sessions signal is the LIVE count; configured/synchronized peers are a
    # different population and must never be substituted for it.
    status_data = api_get(page, "/api/vpn/status")
    live = status_data.get("connected_sessions")
    sessions_value = page.locator("#vpn-sessions")
    if isinstance(live, int):
        expect(sessions_value).to_have_text(str(live))
    else:
        expect(sessions_value).to_have_text("Not measured")

    # An unmeasured value reads as text, never a numeric zero or a healthy badge.
    throughput_text = page.locator("#vpn-signal-throughput-value").inner_text().strip()
    rates = status_data.get("rates") or {}
    if rates.get("available") is not True:
        assert throughput_text == "Not measured"
    drops_text = page.locator("#vpn-signal-drops-value").inner_text().strip()
    drops = status_data.get("drop_categories") or {}
    if drops.get("rates_available") is not True:
        assert drops_text == "Not measured"

    # The dataplane scope is stated so the number cannot read as end-to-end loss.
    assert "not end-to-end" in page.locator("#vpn-signal-drops-sub").inner_text()


@pytest.mark.e2e
def test_vpn_diagnostic_panels(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /vpn -> verifies diagnostic telemetry panel fields."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    # Closed by default: nothing opens it for the operator.
    expect(page.locator("#vpn-diagnostics")).to_be_hidden()
    expect(page.locator("#vpn-advanced-entry")).to_have_attribute("aria-expanded", "false")
    _ensure_diagnostics_open(page)

    # One disclosure with three ordered sections.
    for section in ("#vpn-traffic-performance", "#vpn-routing-drops", "#vpn-runtime-details"):
        expect(page.locator(section)).to_be_visible()
    boxes = [page.locator(s).bounding_box() for s in (
        "#vpn-traffic-performance", "#vpn-routing-drops", "#vpn-runtime-details")]
    assert all(b is not None for b in boxes)
    assert boxes[0]["y"] < boxes[1]["y"] < boxes[2]["y"]

    # #vpn-diag-lat-max is retired: the default percentile is the recent
    # forward-write reservoir, not the unprovable historical one.
    expect(page.locator("#vpn-diag-lat-max")).to_have_count(0)

    diag_fields = (
        "throughput ewma5m ewma1h lat-percentiles queue-occ queue-peak "
        "drops-client drops-return drops-total engine-status peers-status "
        "hs-freshness routing-counts res-cpu res-mem res-fd write-stalls-recent"
    ).split()
    for f in diag_fields:
        expect(page.locator(f"#vpn-diag-{f}")).to_be_visible()

    # The retired slow-write tile's raw value survives here: an aggregate recent
    # stall count with the horizon it covers. A bare label is not a value, so the
    # copy must carry a number (or the explicit not-measured text).
    stall_text = page.locator("#vpn-diag-write-stalls-recent").inner_text().strip()
    stall_window = (api_get(page, "/api/vpn/status").get("forward_latency") or {}).get("stalls_window_sec")
    if isinstance(stall_window, (int, float)) and stall_window > 0:
        assert re.search(r"\d", stall_text), f"aggregate stall count missing a value: {stall_text!r}"
    else:
        assert stall_text == "Not measured", f"stall count with no horizon must read not measured: {stall_text!r}"

    # An unsampled percentile must read as not measured, never 0.0 ms.
    lat_text = page.locator("#vpn-diag-lat-percentiles").inner_text().strip()
    p95_samples = (api_get(page, "/api/vpn/status").get("forward_latency") or {}).get("p95_health_samples")
    if not isinstance(p95_samples, int) or p95_samples <= 0:
        assert lat_text == "Not measured"

    for obsolete in (
        "#vpn-diag-packets",
        "#vpn-diag-res-goroutines",
        "#vpn-diag-res-gc",
    ):
        expect(page.locator(obsolete)).to_have_count(0)
