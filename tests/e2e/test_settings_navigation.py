"""In-page navigation of the Settings page (#887).

Kept in its own module because the behaviour suite that used to hold it already sits
above the repository's 1,000-line ceiling, so any growth there fails the size gate.
Every case here is the one that used to run from that file: the same two widths, the
same sticky expectation and the same interactions.

The probe it uses is shared with the layout cases through tests.e2e.settings_surface,
so a page whose groups lose their ids fails both suites rather than one.

The last two cases cover the move of the policy surface to its own page (#987): the
old Settings fragments hand off to /routing in a real browser, Back is not trapped
by the handoff, and the sidebar marks the page the reader is actually on.
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
    page.wait_for_function("document.querySelectorAll('.settings-group').length === 3")

    probe = page.evaluate(SETTINGS_NAV_PROBE)
    # Presence first, and positively: the probe reports it on every path, so this is
    # the assertion that names a missing navigation instead of raising KeyError on the
    # fields below, which only exist when there is one.
    assert probe["navPresent"] is True, probe
    assert probe["label"].strip(), probe
    assert len(probe["links"]) == 3, probe
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
    page.click("a[href='#group-notifications']")
    page.wait_for_function(
        "document.activeElement && document.activeElement.id === 'group-notifications-title'"
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
                && current[0].getAttribute('href') === '#group-notifications';
        }"""
    )
    after = page.evaluate(SETTINGS_NAV_PROBE)
    assert after["activeTag"] == "H2", after
    assert after["currentHref"] == "#group-notifications", after

    # Stuck to the top from the width where the sidebar is in flow, and scrolled
    # away below it: a third sticky band would eat a phone's viewport. The offset is
    # bounded by what the document can actually scroll, so a page that got shorter
    # with the move does not make this case depend on a scroll that never happens.
    page.evaluate(
        "() => { const y = Math.min(1200, document.documentElement.scrollHeight - window.innerHeight - 5);"
        " window.__scrolledTo = y; window.scrollTo(0, y); }"
    )
    page.wait_for_function("Math.abs(window.scrollY - window.__scrolledTo) < 2")
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


def _wait_for_routing(page: Page) -> None:
    """Wait for the real navigation and the page's own load, not for a fixed delay."""
    page.wait_for_url("**/routing*")
    page.wait_for_function("!!document.getElementById('policyRoutingCard')")


@pytest.mark.e2e
@pytest.mark.parametrize(
    "fragment,expected_path,expected_hash",
    [
        # The old group anchor is consumed: the group does not exist on the new page,
        # and forwarding the fragment would land on nothing a second time.
        ("#group-network", "/routing", ""),
        ("#group-network-title", "/routing", ""),
        # The two card anchors keep their ids, so they are forwarded as fragments.
        ("#policyRoutingCard", "/routing", "#policyRoutingCard"),
        ("#policyClientCard", "/routing", "#policyClientCard"),
    ],
)
def test_old_policy_fragment_hands_off_to_the_routing_page(
    authenticated_page: Page, base_url: str, fragment: str, expected_path: str, expected_hash: str
) -> None:
    """A Settings bookmark written before the move reaches the page that owns it."""
    page = authenticated_page
    page.goto(f"{base_url}/settings{fragment}")
    _wait_for_routing(page)

    from urllib.parse import urlparse

    landed = urlparse(page.url)
    assert landed.path == expected_path, page.url
    actual_hash = f"#{landed.fragment}" if landed.fragment else ""
    assert actual_hash == expected_hash, page.url
    # The destination is the real page, not a stub: the whole policy card renders.
    assert page.evaluate("!!document.getElementById('policyRoutingCard')")
    assert page.evaluate("!!document.getElementById('policyClientCard')")


@pytest.mark.e2e
@pytest.mark.parametrize(
    "suffix",
    [
        "#group-portal",
        "#group-system",
        "#not-a-known-anchor",
        "",
        "?still=settings",
    ],
)
def test_ordinary_settings_urls_are_not_redirected(
    authenticated_page: Page, base_url: str, suffix: str
) -> None:
    """Only the four literal old policy fragments hand off; everything else stays."""
    page = authenticated_page
    page.goto(f"{base_url}/settings{suffix}")
    page.wait_for_function("document.querySelectorAll('.settings-group').length === 3")
    # Give a handoff the chance to happen before asserting that it did not.
    page.wait_for_timeout(300)
    from urllib.parse import urlparse

    landed = urlparse(page.url)
    assert landed.path == "/settings", page.url
    assert page.evaluate("!!document.getElementById('settingsSubnav')")


@pytest.mark.e2e
def test_a_card_handoff_lands_focused_and_clear_of_the_sticky_bar(
    authenticated_page: Page, base_url: str
) -> None:
    """The card anchor lands on the card itself, in view and with a destination focus."""
    page = authenticated_page
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{base_url}/settings#policyRoutingCard")
    _wait_for_routing(page)

    state = page.evaluate(
        """() => {
      const card = document.getElementById('policyRoutingCard');
      const r = card.getBoundingClientRect();
      const bar = document.querySelector('.mobile-topbar');
      const barBottom = bar ? bar.getBoundingClientRect().bottom : 0;
      return {top: r.top, barBottom: barBottom,
              focused: document.activeElement === card,
              activeId: document.activeElement ? document.activeElement.id : ''};
    }"""
    )
    # The card is the reason the fragment exists, so it is what the reader lands on:
    # focus is on the card itself, its top edge is on screen, and that edge is clear
    # of the sticky bar rather than tucked underneath it. The band below the bar is
    # 120 px, which is where a fragment target with a scroll margin lands; it is not
    # a request that the card be tall.
    assert state["focused"], state
    assert state["activeId"] == "policyRoutingCard", state
    assert state["top"] >= -1, state
    assert state["top"] >= state["barBottom"] - 1, state
    assert state["top"] <= state["barBottom"] + 120, state


@pytest.mark.e2e
def test_back_after_a_handoff_does_not_bounce(
    authenticated_page: Page, base_url: str
) -> None:
    """The handoff replaces its history entry, so Back reaches the page before it."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")
    page.goto(f"{base_url}/settings#group-network")
    _wait_for_routing(page)

    page.go_back()
    page.wait_for_load_state("networkidle")
    from urllib.parse import urlparse

    landed = urlparse(page.url)
    assert landed.path == "/vpn", f"Back landed on {page.url}, so the handoff pushed a history entry"


@pytest.mark.e2e
@pytest.mark.parametrize("width", [1440, 390])
def test_sidebar_marks_the_routing_page_only_where_it_is(
    authenticated_page: Page, base_url: str, width: int
) -> None:
    """Routing is a peer of VPN and the sidebar entry is current only on its own page."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})

    def sidebar_state() -> dict:
        return page.evaluate(
            """() => {
          const link = document.querySelector('.app-sidebar a[href="/routing"]');
          const settings = document.querySelector('.app-sidebar a[href="/settings"]');
          const vpn = document.querySelector('.app-sidebar a[href="/vpn"]');
          return {
            routing: link ? {current: link.getAttribute('aria-current'),
                             active: link.classList.contains('active'),
                             text: (link.textContent || '').trim()} : null,
            settingsActive: settings ? settings.classList.contains('active') : null,
            vpnActive: vpn ? vpn.classList.contains('active') : null,
          };
        }"""
        )

    page.goto(f"{base_url}/routing")
    _wait_for_routing(page)
    on_routing = sidebar_state()
    assert on_routing["routing"] is not None, on_routing
    assert on_routing["routing"]["current"] == "page", on_routing
    assert on_routing["routing"]["active"] is True, on_routing
    assert on_routing["routing"]["text"], on_routing
    assert on_routing["vpnActive"] is False, on_routing
    assert on_routing["settingsActive"] is False, on_routing

    page.goto(f"{base_url}/settings")
    page.wait_for_function("document.querySelectorAll('.settings-group').length === 3")
    on_settings = sidebar_state()
    assert on_settings["routing"] is not None, on_settings
    assert on_settings["routing"]["current"] is None, on_settings
    assert on_settings["routing"]["active"] is False, on_settings
    assert on_settings["settingsActive"] is True, on_settings

    # The routing page has no Settings sub-navigation and no second sticky band.
    page.goto(f"{base_url}/routing")
    _wait_for_routing(page)
    assert page.evaluate("!document.getElementById('settingsSubnav')")
