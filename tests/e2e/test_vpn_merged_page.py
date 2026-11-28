"""The merged VPN page: one document, three sections, one jump rail.

#1006 reversed the #993 split. These checks are the panel-side contract of that
reversal, and they need a real browser because every one of them is about
geometry or about a real navigation:

* the four signals and the health headline are above the fold at 1440x900 and at
  390x844, in both themes, with the disclosures closed;
* the sticky jump rail still offers all three sections deep inside an expanded
  page, at both widths, and lands on the section it names;
* the retired child routes redirect into the matching section by request.

Everything else about the page - the signals' own values, the health renderer, the
problem rows, the inventory and the sessions tables - is asserted in
``test_vpn_health_surface.py`` and ``test_vpn_diagnostics.py``, which run against
the same document now.
"""

import pytest
from playwright.sync_api import Page, expect

# The fold's promise is stated against the unobscured viewport, not against the
# full page: the sections below it are allowed to be long.
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}

# The phone shell spends these on its own sticky bars.
PHONE_TOP_BAR = 60
PHONE_BOTTOM_BAR = 60

THEMES = ("dark", "light")

# The four signals, in source order, and the headline that follows them.
SIGNAL_IDS = (
    "#vpn-signal-backends-value",
    "#vpn-sessions",
    "#vpn-signal-throughput-value",
    "#vpn-signal-drops-value",
)


def _set_theme(page: Page, theme: str) -> None:
    page.evaluate("theme => document.documentElement.setAttribute('data-theme', theme)", theme)


def _open(page: Page, base_url: str, width: int, height: int, theme: str, hash_fragment: str = "") -> None:
    page.set_viewport_size({"width": width, "height": height})
    page.goto(f"{base_url}/vpn{hash_fragment}")
    page.wait_for_load_state("networkidle")
    _set_theme(page, theme)
    page.evaluate("window.scrollTo(0, 0)")
    expect(page.locator("#overview")).to_be_visible()


def _wait_for_scroll_settled(page: Page) -> None:
    """Block until the scroll position stops changing.

    A jump is animated unless the reader asked for reduced motion, so the only
    correct readiness signal is that scrolling has finished - not a fixed delay,
    and not a positional bound, which a mid-animation frame can already satisfy.
    """
    page.evaluate(
        """() => new Promise(resolve => {
            let last = window.scrollY;
            let stable = 0;
            const step = () => {
                if (window.scrollY === last) {
                    stable += 1;
                    if (stable >= 3) { resolve(true); return; }
                } else {
                    stable = 0;
                    last = window.scrollY;
                }
                requestAnimationFrame(step);
            };
            requestAnimationFrame(step);
        })"""
    )


def _bottom(locator) -> float:
    box = locator.bounding_box()
    assert box is not None, "a folded surface has no box"
    return box["y"] + box["height"]


@pytest.mark.e2e
@pytest.mark.parametrize("theme", THEMES)
def test_vpn_fold_desktop_signals_and_headline(authenticated_page: Page, base_url: str, theme: str) -> None:
    """At 1440x900 the four readouts and the health headline are above the fold.

    The design's desktop promise is stronger than the phone's: the Backends section
    heading and its Add Backend control are above the fold as well, so the inventory
    is clearly the next thing rather than something the reader has to discover.
    """
    page = authenticated_page
    _open(page, base_url, DESKTOP["width"], DESKTOP["height"], theme)

    # Canonical arrival: no hash, scroll at zero, both disclosures closed.
    assert "#" not in page.url
    assert page.locator("#vpn-diagnostics").is_hidden()
    assert page.locator("#vpn-configuration").evaluate("el => el.open") is False

    fold = DESKTOP["height"]
    for signal in SIGNAL_IDS:
        expect(page.locator(signal)).to_be_visible()
        assert _bottom(page.locator(signal)) <= fold, f"{signal} is below the {fold}px fold"

    headline = page.locator("#vpn-forwarder-card")
    expect(headline).to_be_visible()
    assert _bottom(headline) <= fold, "the health headline is below the fold"

    # The endpoint summary is a collapsed row above the fold, and Backends' heading
    # and its action are both in the first viewport.
    assert _bottom(page.locator("#vpn-configuration")) <= fold, "the collapsed endpoint summary is below the fold"
    assert _bottom(page.locator("#backends")) <= fold, "the Backends heading is below the fold"
    assert _bottom(page.locator("#vpn-add-backend-btn")) <= fold, "Add Backend is below the fold"


@pytest.mark.e2e
@pytest.mark.parametrize("theme", THEMES)
def test_vpn_fold_phone_signals_and_headline(authenticated_page: Page, base_url: str, theme: str) -> None:
    """At 390x844 the four readouts and the headline fit between the shell bars.

    The phone measure is the visible band the two sticky bars leave, not the whole
    viewport height: a readout under the bottom bar is not above the fold in any
    sense the reader experiences. The jump rail has to be inside that band too, or
    the page loses the one control that reaches a section further down.
    """
    page = authenticated_page
    _open(page, base_url, PHONE["width"], PHONE["height"], theme)

    band_bottom = PHONE["height"] - PHONE_BOTTOM_BAR
    band_top = PHONE_TOP_BAR

    for signal in SIGNAL_IDS:
        expect(page.locator(signal)).to_be_visible()
        box = page.locator(signal).bounding_box()
        assert box is not None
        assert box["y"] + box["height"] <= band_bottom, (
            f"{signal} falls under the bottom bar: bottom {box['y'] + box['height']:.0f} > {band_bottom}"
        )
        assert box["y"] >= band_top, f"{signal} starts under the top bar: {box['y']:.0f} < {band_top}"

    headline = page.locator("#vpn-forwarder-card")
    assert _bottom(headline) <= band_bottom, "the health headline falls under the bottom bar"

    # The rail itself is reachable, in the band, and does not pan sideways.
    rail = page.locator("#vpnSubnav")
    expect(rail).to_be_visible()
    rail_box = rail.bounding_box()
    assert rail_box is not None
    assert rail_box["y"] >= band_top - 1 and rail_box["y"] + rail_box["height"] <= band_bottom
    overflow = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 0, f"the document pans sideways by {overflow}px"

    # The four readouts are a two-by-two grid here, in source order.
    first, second = (page.locator(s).bounding_box() for s in SIGNAL_IDS[:2])
    third, fourth = (page.locator(s).bounding_box() for s in SIGNAL_IDS[2:])
    assert first and second and third and fourth
    assert abs(first["y"] - second["y"]) < 4, "the first row of readouts is not a row"
    assert third["y"] > first["y"], "the second row of readouts does not sit below the first"
    assert abs(third["y"] - fourth["y"]) < 4, "the second row of readouts is not a row"


@pytest.mark.e2e
@pytest.mark.parametrize("theme", THEMES)
def test_vpn_jump_rail_reaches_every_section_from_deep_in_the_page(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """Deep inside an expanded page the rail still offers all three jumps.

    This is the case the split could not have: a long document whose only route
    back is a control that has to stay stuck. The test expands the diagnostics
    panel (the longest surface on the page), scrolls to the very bottom, and then
    uses the rail to go back up - at both widths.
    """
    page = authenticated_page
    for width, height in ((DESKTOP["width"], DESKTOP["height"]), (PHONE["width"], PHONE["height"])):
        _open(page, base_url, width, height, theme)
        page.locator("#vpn-advanced-entry").click()
        expect(page.locator("#vpn-diagnostics")).to_be_visible()

        # Jump-and-verify uses an explicit readiness predicate, never a fixed sleep:
        # the page honours reduced motion with an instant jump and animates otherwise,
        # so a duration-based wait would test the machine's speed, not the product.
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        _wait_for_scroll_settled(page)

        rail = page.locator("#vpnSubnav")
        expect(rail).to_be_visible()
        rail_box = rail.bounding_box()
        assert rail_box is not None
        assert rail_box["y"] >= 0, "the stuck rail is above the viewport top"
        assert rail_box["y"] < height / 2, (
            f"the rail is not stuck near the top at the end of the page: y={rail_box['y']:.0f}"
        )
        for link in ("#vpnSubnav a[href='#overview']", "#vpnSubnav a[href='#backends']", "#vpnSubnav a[href='#diagnostics']"):
            expect(page.locator(link)).to_be_visible()

        # Jumping up: the section lands clear of the stuck rail, and the rail's
        # marker follows without the URL being rewritten by the scroll.
        page.locator("#vpnSubnav a[href='#overview']").click()
        _wait_for_scroll_settled(page)
        # The landing must be complete, not merely started: the page animates the
        # jump unless the reader asked for reduced motion, so a predicate that only
        # bounded the destination would pass on a mid-animation frame.
        rail_box = page.locator("#vpnSubnav").bounding_box()
        assert rail_box is not None
        overview_box = page.locator("#overview").bounding_box()
        assert overview_box is not None
        # The section's top edge sits at the scroll margin the page reserved for it,
        # and that margin is at least the height of the stuck rail: a landing that
        # ignored the rail would leave the heading under it.
        scroll_margin = page.evaluate(
            "() => parseFloat(getComputedStyle(document.getElementById('overview')).scrollMarginTop) || 0"
        )
        assert scroll_margin >= rail_box["height"] - 1, (
            f"the landing margin {scroll_margin} does not clear the {rail_box['height']}-tall rail"
        )
        assert overview_box["y"] >= rail_box["height"] - 2, (
            f"the jump landed under the stuck rail: heading top {overview_box['y']:.1f}, rail bottom {rail_box['height']:.1f}"
        )
        expect(page.locator("#vpnSubnav a[href='#overview']")).to_have_attribute("aria-current", "true")
        expect(page.locator("#vpnSubnav a[href='#diagnostics']")).not_to_have_attribute("aria-current", "true")

        # Back down again, then a jump to the middle section.
        page.locator("#vpnSubnav a[href='#backends']").click()
        _wait_for_scroll_settled(page)
        backends_box = page.locator("#backends").bounding_box()
        assert backends_box is not None
        assert backends_box["y"] >= rail_box["height"] - 2, "the jump to Backends landed under the stuck rail"
        expect(page.locator("#vpnSubnav a[href='#backends']")).to_have_attribute("aria-current", "true")
        assert page.url.endswith("/vpn#backends")


@pytest.mark.e2e
def test_vpn_retired_routes_redirect_into_their_section(authenticated_page: Page, base_url: str) -> None:
    """The retired child routes answer with a redirect into the merged page.

    Proven by request: the redirect status and its Location are read from the
    response, not from where the browser settles afterwards, because a fragment is
    never sent to the server and a browser would hide the difference.
    """
    page = authenticated_page
    cases = (
        ("/vpn/backends", "/vpn?section=backends"),
        ("/vpn/diagnostics", "/vpn?section=diagnostics"),
    )
    for path, expected in cases:
        response = page.request.get(f"{base_url}{path}", max_redirects=0)
        assert response.status == 302, f"{path} answered {response.status}, want a 302"
        location = response.headers["location"]
        assert location == expected, f"{path} redirects to {location!r}, want {expected!r}"
        assert "#" not in location, "the redirect must not restate a fragment the browser would replace"

        # Following it lands on the section, and the query marker is consumed: the
        # address bar becomes the canonical shareable URL.
        page.goto(f"{base_url}{path}")
        page.wait_for_load_state("networkidle")
        assert "/vpn" in page.url
        assert "section=" not in page.url, f"{path} left its transient marker in the URL: {page.url}"
        section = expected.rsplit("=", 1)[1]
        assert page.url.endswith(f"#{section}"), f"{path} landed at {page.url}, want the {section} section"
        expect(page.locator(f"#{section}")).to_be_visible()

    # A legacy deep link inherited from the retired route still resolves to its
    # block: the fragment the browser carried wins over the section marker.
    page.goto(f"{base_url}/vpn/diagnostics#vpnSessionsTable")
    page.wait_for_load_state("networkidle")
    expect(page.locator("#vpnSessionsTable")).to_be_visible()
    assert page.url.endswith("#vpnSessionsTable"), f"the legacy deep link was not preserved: {page.url}"


@pytest.mark.e2e
def test_vpn_shell_offers_one_entry_and_no_retired_link(authenticated_page: Page, base_url: str) -> None:
    """The shell has exactly one VPN entry, and nothing links a retired route."""
    page = authenticated_page
    page.goto(f"{base_url}/vpn")
    page.wait_for_load_state("networkidle")

    sidebar = page.locator(".sidebar-nav a[href^='/vpn']")
    expect(sidebar).to_have_count(1)
    expect(sidebar.first).to_have_attribute("href", "/vpn")
    expect(sidebar.first).to_have_attribute("aria-current", "page")

    for retired in ("a[href='/vpn/backends']", "a[href='/vpn/diagnostics']"):
        expect(page.locator(retired)).to_have_count(0)

    # The tab title uses the normal site-title format: "<site title> - VPN".
    import re as _re

    expect(page).to_have_title(_re.compile(r".*\bVPN$"))
