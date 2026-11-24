"""Routing page cases that used to run inside the Settings suite (#987).

The policy surface moved out of Settings onto its own page, so the browser cases
that measure it moved with it. Two of them were inline blocks at the end of a
Settings case, where they had been added because the surface was still a Settings
section; the third is the focus indicator of a field that no longer renders on the
Settings page. Nothing was weakened in the move:

* the button scale is the same 40 px step, measured on the page that renders the
  button;
* the one-commit-inside-itself model is asserted here, and its label is compared
  against the label a Settings card carries rather than against a copy of the
  string, so the two pages cannot drift apart;
* the focus ring is the same shared rule, probed with the same query and the same
  token lookup as the Settings suite.

The probe, the reduced-motion stylesheet and the colour helper are imported from
the Settings suite instead of being copied here: one definition is what keeps the
two suites measuring the same thing.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

from tests.e2e import contrast
from tests.e2e import test_settings as settings_cases
from tests.e2e.settings_surface import token_px

ROUTING = "/routing"
CARD = "#policyRoutingCard"
REFRESH_BTN = "#policyClientRefreshBtn"
EXCEPTIONS = "#policy_proxy_exceptions"


def _open_routing(page: Page, base_url: str) -> None:
    """Open the routing page and wait until its controller has read the record.

    The runtime badge is the visible half of that answer, so it is what the wait
    names: a page that has not read the record yet still renders the card.
    """
    page.goto(f"{base_url}{ROUTING}")
    page.wait_for_load_state("networkidle")
    page.wait_for_selector(CARD, state="visible")
    expect(page.locator("#policyStatusBadge")).to_have_attribute("data-enabled", "false")


@pytest.mark.e2e
def test_routing_card_button_height_matches_the_settings_scale(
    authenticated_page: Page, base_url: str
) -> None:
    """A button inside a card is the 40 px step here too.

    The scale is built from the pinned spacing tokens, never from a copy of the
    computed value, and the card's refresh button is the one this page renders.
    """
    page = authenticated_page
    page.set_viewport_size({"width": 1440, "height": 900})

    large = token_px("space-xl") + token_px("space-sm")
    assert large == 40

    _open_routing(page, base_url)
    page.locator(REFRESH_BTN).wait_for(state="visible")
    height = page.evaluate(
        "sel => document.querySelector(sel).getBoundingClientRect().height", REFRESH_BTN
    )
    assert abs(height - large) <= 0.5, (REFRESH_BTN, height, large)


@pytest.mark.e2e
def test_routing_card_commits_from_inside_itself_with_the_shared_label(
    authenticated_page: Page, base_url: str
) -> None:
    """One commit control inside the card, carrying the label every card carries.

    The label is read from a Settings card rather than written here: a second copy
    of the string would pass after one page changed its wording, which is the
    drift this case exists to catch.
    """
    page = authenticated_page

    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    reference = page.locator("#appearanceCard [data-commit]")
    assert reference.count() == 1, "appearanceCard"
    shared_label = " ".join(reference.inner_text().split())
    assert shared_label, "the Settings commit control has no label to compare against"

    _open_routing(page, base_url)
    commit = page.locator(f"{CARD} [data-commit]")
    assert commit.count() == 1, "policyRoutingCard"
    assert " ".join(commit.inner_text().split()) == shared_label


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_focused_policy_control_has_a_visible_outline(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """The moved policy field keeps the shared focus ring on its own page.

    The exceptions field was asserted on the Settings page before #987. It is the
    same control with the same rule, on the page that now renders it, so it is the
    same assertion — otherwise the move would silently drop the one control on
    this surface an operator has to reach by keyboard.
    """
    page = authenticated_page
    page.set_viewport_size({"width": 1440, "height": 900})
    _open_routing(page, base_url)
    page.wait_for_selector(EXCEPTIONS, state="visible")
    page.add_style_tag(content=settings_cases.NO_TRANSITIONS)
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
    page.keyboard.press("Tab")

    got = page.evaluate(settings_cases.FOCUS_PROBE, [EXCEPTIONS, EXCEPTIONS])
    assert got["focused"] and got["focusVisible"], got
    accent = contrast.resolve("accent", contrast.theme_tokens(theme))
    assert got["style"] == "solid", (theme, got)
    assert got["width"] == "2px", (theme, got)
    assert got["color"] == settings_cases._rgb(accent), (theme, got, accent)
    assert got["offset"] == "2px", (theme, got)
