"""In-page navigation of the Settings page (#887).

Kept in its own module because the behaviour suite that used to hold it already sits
above the repository's 1,000-line ceiling, so any growth there fails the size gate.
Every case here is the one that used to run from that file: the same two widths, the
same sticky expectation and the same interactions.

The probe it uses is shared with the layout cases through tests.e2e.settings_surface,
so a page whose groups lose their ids fails both suites rather than one.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

from tests.e2e.settings_surface import SETTINGS_NAV_PROBE

@pytest.mark.e2e
@pytest.mark.parametrize("width,sticky", [(1440, True), (390, False)])
def test_settings_subnav_names_and_moves_between_groups(
    authenticated_page: Page, base_url: str, width: int, sticky: bool
) -> None:
    """The sub-navigation names every group, marks the one in view and hands focus over."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function("document.querySelectorAll('.settings-group').length === 4")

    probe = page.evaluate(SETTINGS_NAV_PROBE)
    # Presence first, and positively: the probe reports it on every path, so this is
    # the assertion that names a missing navigation instead of raising KeyError on the
    # fields below, which only exist when there is one.
    assert probe["navPresent"] is True, probe
    assert probe["label"].strip(), probe
    assert len(probe["links"]) == 4, probe
    for link in probe["links"]:
        assert link["href"].startswith("#"), link
        assert page.evaluate("sel => !!document.querySelector(sel)", link["href"]), link
        assert link["text"], link
        # The link is navigation, not a filled control: nothing paints a fill,
        # no side carries a border, and the only border is the current group's
        # 2 px accent underline. A reintroduced button surface fails here.
        assert link["background"] in ("rgba(0, 0, 0, 0)", "transparent"), link
        for side in ("top", "right", "left"):
            assert link["borders"][side] == "0px", link
        underline = "2px" if link["current"] == "true" else "0px"
        assert link["borders"]["bottom"] == underline, link
        # The 40 px target holds at both widths; at 390 it must also stay fully
        # inside the viewport, because the row wraps instead of clipping.
        assert link["height"] >= 40, link
        if width == 390:
            assert link["width"] > 0, link
            assert link["right"] <= probe["clientWidth"] + 0.5, link
    if width == 390:
        assert probe["scrollWidth"] == probe["clientWidth"], probe

    # At the top of the page the first group is the current one, exactly once.
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_function(
        "document.querySelectorAll('[aria-current=\"true\"]').length === 1"
    )
    assert (
        page.evaluate(
            "() => document.querySelector('[aria-current=\"true\"]').getAttribute('href')"
        )
        == "#group-portal"
    )

    # Following a link moves focus into the group it names, and the state follows.
    page.click("a[href='#group-network']")
    page.wait_for_function(
        "document.activeElement && document.activeElement.id === 'group-network-title'"
    )
    # Wait for the requested group's OWN link to become the unique current link.
    # Waiting on a count of current links is satisfied by the previous group's mark,
    # so a click whose mark never moved would pass that wait and then fail on the
    # assertion below for the wrong reason. This predicate names the group, so it
    # waits for exactly the state the design requires - the marker moves once the
    # group is in view, not before - and a marker that stays put never satisfies it.
    page.wait_for_function(
        """() => {
            const current = [...document.querySelectorAll('[aria-current="true"]')];
            return current.length === 1
                && current[0].getAttribute('href') === '#group-network';
        }"""
    )
    after = page.evaluate(SETTINGS_NAV_PROBE)
    assert after["activeTag"] == "H2", after
    assert after["currentHref"] == "#group-network", after

    # Stuck to the top from the width where the sidebar is in flow, and scrolled
    # away below it: a third sticky band would eat a phone's viewport.
    page.evaluate("window.scrollTo(0, 1200)")
    page.wait_for_function("Math.abs(window.scrollY - 1200) < 2")
    page.wait_for_timeout(200)
    nav_top = page.evaluate(
        "() => document.querySelector('.app-main nav').getBoundingClientRect().top"
    )
    if sticky:
        assert abs(nav_top) < 1, nav_top
    else:
        assert nav_top < 0, nav_top
