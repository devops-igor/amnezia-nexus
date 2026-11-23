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
        # No link is a filled control: the link's own background colour stays
        # transparent and no side carries a border, so the row reads as navigation
        # rather than as buttons. The current group's pill is a background IMAGE
        # layer, asserted below, not a card fill.
        assert link["background"] in ("rgba(0, 0, 0, 0)", "transparent"), link
        for side in ("top", "right", "left", "bottom"):
            assert link["borders"][side] == "0px", link
        # The old per-link underline is gone; the current state must not be a
        # decoration on one edge either way.
        assert "underline" not in link["textDecorationLine"], link
        # Exactly one link carries the current mark, and it is distinguished by
        # more than a text colour: the sidebar's pill (gradient image + shadow)
        # plus the heavier white label. Every other link paints no image and no
        # shadow, and keeps the secondary hue at normal weight.
        if link["current"] == "true":
            assert "linear-gradient" in link["backgroundImage"], link
            assert link["boxShadow"] not in ("none", ""), link
            assert link["color"] == "rgb(255, 255, 255)", link
            assert link["fontWeight"] == "600", link
        else:
            assert link["backgroundImage"] == "none", link
            assert link["boxShadow"] == "none", link
            assert link["fontWeight"] == "500", link
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

    # SET2-16, read where it can be told apart from the mark: the shared focus
    # ring must appear on a link that is NOT current. That link carries no pill
    # and no shadow, so a non-`none` shadow could not be mistaken for the ring,
    # and the ring cannot be mistaken for the current state.
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_function(
        """() => {
            const c = [...document.querySelectorAll('[aria-current="true"]')];
            return c.length === 1 && c[0].getAttribute('href') === '#group-portal';
        }"""
    )
    page.keyboard.press("Tab")  # keyboard modality, so :focus-visible follows keys
    focus = page.evaluate(
        """() => {
      const a = [...document.querySelectorAll('.app-main nav a')]
          .find(l => l.getAttribute('aria-current') !== 'true');
      a.focus();
      const s = getComputedStyle(a);
      return {href: a.getAttribute('href'), current: a.getAttribute('aria-current'),
              focused: document.activeElement === a,
              focusVisible: a.matches(':focus-visible'),
              outlineStyle: s.outlineStyle, outlineWidth: s.outlineWidth,
              outlineOffset: s.outlineOffset, boxShadow: s.boxShadow,
              backgroundImage: s.backgroundImage};
    }"""
    )
    assert focus["focused"] and focus["focusVisible"], focus
    assert focus["href"], focus
    assert focus["current"] != "true", focus
    assert focus["outlineStyle"] == "solid", focus
    assert focus["outlineWidth"] == "2px", focus
    assert focus["outlineOffset"] == "2px", focus
    assert focus["boxShadow"] == "none", focus
    assert focus["backgroundImage"] == "none", focus
