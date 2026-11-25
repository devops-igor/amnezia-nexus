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
from tests.e2e.settings_surface import SETTINGS_PROBE, geometry, token_px

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


# Roles Chromium gives an SVG glyph. The finding was an "unnamed image" under the
# link and the heading, so those are the roles the assertion refuses.
GRAPHIC_ROLES = {"image", "img", "graphics-symbol"}


def _ax_nodes(page: Page) -> list[dict]:
    """Chromium's accessibility tree for the loaded document.

    Read through CDP rather than from the markup: an attribute in the source says
    what the author intended, and this says what the browser actually exposes.
    """
    cdp = page.context.new_cdp_session(page)
    try:
        cdp.send("Accessibility.enable")
        return cdp.send("Accessibility.getFullAXTree")["nodes"]
    finally:
        cdp.detach()


def _descendants(nodes: list[dict], root_id: str) -> list[dict]:
    """Every node below root_id, following the tree's own parent links."""
    children: dict[str, list[dict]] = {}
    for node in nodes:
        parent = node.get("parentId")
        if parent:
            children.setdefault(parent, []).append(node)
    found, stack = [], list(children.get(root_id, []))
    while stack:
        node = stack.pop()
        found.append(node)
        stack.extend(children.get(node.get("nodeId"), []))
    return found


def _ax_named(nodes: list[dict], role: str, name: str) -> dict | None:
    """The first unignored node with this role and accessible name."""
    for node in nodes:
        if node.get("ignored"):
            continue
        if node.get("role", {}).get("value") != role:
            continue
        if ((node.get("name") or {}).get("value") or "").strip() == name:
            return node
    return None


def _exposed_graphics(nodes: list[dict], root_id: str) -> list[str]:
    """The unignored graphic roles below a node, described for the failure message."""
    return [
        f"{d.get('role', {}).get('value')!s}:{((d.get('name') or {}).get('value') or '<unnamed>')!s}"
        for d in _descendants(nodes, root_id)
        if not d.get("ignored") and d.get("role", {}).get("value") in GRAPHIC_ROLES
    ]


def _glyph_paint(page: Page) -> list[dict]:
    """Where the two glyphs paint and how, so "no visual change" can be measured.

    Geometry and the properties a stylesheet could key on are read from the same
    two elements the finding names.
    """
    return page.evaluate(
        """() => [...document.querySelectorAll(
        '.app-sidebar a[href="/routing"] svg, .app-main h1 svg')].map(svg => {
      const box = svg.getBoundingClientRect();
      const style = getComputedStyle(svg);
      return {x: box.x, y: box.y, width: box.width, height: box.height,
              color: style.color, display: style.display, visibility: style.visibility,
              opacity: style.opacity, transform: style.transform, fill: style.fill};
    })"""
    )


def _reveal_globe(page: Page) -> None:
    """Control: take the hiding off the two glyphs so the query can be shown to see them."""
    page.evaluate(
        """() => {
      for (const svg of document.querySelectorAll(
          '.app-sidebar a[href="/routing"] svg, .app-main h1 svg')) {
        svg.removeAttribute('aria-hidden');
      }
    }"""
    )


@pytest.mark.e2e
def test_routing_globes_are_decorative_in_the_accessibility_tree(
    authenticated_page: Page, base_url: str
) -> None:
    """The two globes the move introduced are hidden from assistive technology.

    The sidebar entry and the page heading are named by their own text, so a glyph
    inside either must not appear as an image in Chromium's accessibility tree and
    must not take focus. Both halves are asserted: the names are the visible
    labels, and neither node has an exposed graphic child. The control then removes
    the hiding at runtime and requires the same query to see the images — an
    assertion that passes when the query finds nothing would prove nothing.
    """
    page = authenticated_page
    page.set_viewport_size({"width": 1440, "height": 900})
    _open_routing(page, base_url)

    label = page.evaluate(
        "() => document.querySelector('.app-sidebar a[href=\"/routing\"] .nav-label')"
        ".textContent.trim()"
    )
    heading_text = page.evaluate("() => document.querySelector('.app-main h1').textContent.trim()")
    assert label, "the sidebar entry has no visible label to compare its name against"
    assert heading_text, "the page heading has no text of its own"

    nodes = _ax_nodes(page)
    entry = _ax_named(nodes, "link", label)
    heading = _ax_named(nodes, "heading", heading_text)
    assert entry is not None, f"no link named {label!r} in the accessibility tree"
    assert heading is not None, f"no heading named {heading_text!r} in the accessibility tree"

    # The name comes from the visible text, so it cannot be coming from the icon.
    assert (entry["name"]["value"] or "").strip() == label
    assert (heading["name"]["value"] or "").strip() == heading_text

    assert not _exposed_graphics(nodes, entry["nodeId"]), (
        "the sidebar entry exposes a graphic to assistive technology: "
        f"{_exposed_graphics(nodes, entry['nodeId'])}"
    )
    assert not _exposed_graphics(nodes, heading["nodeId"]), (
        "the page heading exposes a graphic to assistive technology: "
        f"{_exposed_graphics(nodes, heading['nodeId'])}"
    )

    # The glyphs are also not reachable by keyboard: neither is in the tab order.
    reachable = page.evaluate(
        """() => [...document.querySelectorAll(
        '.app-sidebar a[href="/routing"] svg, .app-main h1 svg')]
        .filter(svg => svg.getAttribute('focusable') !== 'false'
                    || svg.tabIndex >= 0).length"""
    )
    assert reachable == 0, "a decorative glyph is still focusable"

    painted = _glyph_paint(page)
    assert len(painted) == 2, f"expected two glyphs to measure, found {len(painted)}"

    # Control: with the hiding removed, the same query finds the images. This is
    # what makes the assertions above meaningful rather than vacuous.
    _reveal_globe(page)
    revealed = _ax_nodes(page)
    for role, name in (("link", label), ("heading", heading_text)):
        node = _ax_named(revealed, role, name)
        assert node is not None, (role, name)
        assert _exposed_graphics(revealed, node["nodeId"]), (
            f"the control did not expose an image under the {role}: the assertion above could be "
            "passing because the query sees nothing at all"
        )

    # "No visual change" is measured, not claimed: with the hiding off, the two
    # glyphs paint in the same place and the same way.
    revealed_paint = _glyph_paint(page)
    for hidden_attrs, exposed_attrs in zip(painted, revealed_paint):
        for edge in ("x", "y", "width", "height"):
            assert abs(hidden_attrs[edge] - exposed_attrs[edge]) <= 0.5, (edge, painted, revealed_paint)
        for prop in ("color", "display", "visibility", "opacity", "transform", "fill"):
            assert hidden_attrs[prop] == exposed_attrs[prop], (prop, painted, revealed_paint)

    # The entry is also the navigation on a phone, where it lives in the drawer.
    page.goto(f"{base_url}{ROUTING}")
    page.wait_for_load_state("networkidle")
    page.wait_for_selector(CARD, state="visible")
    page.set_viewport_size({"width": 390, "height": 844})
    page.click("#drawerToggle")
    page.wait_for_function(
        "() => !document.getElementById('appSidebar').hasAttribute('inert')"
    )
    drawer_nodes = _ax_nodes(page)
    drawer_entry = _ax_named(drawer_nodes, "link", label)
    assert drawer_entry is not None, "the drawer entry is missing from the accessibility tree"
    assert not _exposed_graphics(drawer_nodes, drawer_entry["nodeId"]), (
        "the drawer's sidebar entry exposes a graphic to assistive technology: "
        f"{_exposed_graphics(drawer_nodes, drawer_entry['nodeId'])}"
    )


ROUTING_CARDS = ["policyRoutingCard", "policyClientCard"]


@pytest.mark.e2e
@pytest.mark.parametrize("width,columns", [(1440, 2), (1024, 2), (390, 1)])
def test_routing_cards_span_the_grid(
    authenticated_page: Page, base_url: str, width: int, columns: int
) -> None:
    """Both policy cards take the whole grid, measured on the rendered page.

    While the two cards were a Settings group, the Settings geometry case required
    both of them among its spanning rows. The move left their rows unmeasured, so a
    card that lost the spanning rule would render at one track and nothing would
    fail. The property is read from rectangles, not from a class name: at the
    desktop widths the grid has two tracks, and a card that spans both is exactly
    the grid's content box wide.

    1440 and 1024 are the two two-track widths; 390 is single-track by design, where
    the same assertion becomes "one column, and both cards fill it". The theme is not
    varied because grid placement has no themed rule: settings.css contains no
    data-theme rule at all, and its only two grid-column declarations are
    width-driven.
    """
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    _open_routing(page, base_url)

    probe = page.evaluate(SETTINGS_PROBE)
    assert len(probe["grids"]) == 1, (
        f"the routing page renders {len(probe['grids'])} .settings-grid containers, "
        f"want exactly one: {[g['id'] for g in probe['grids']]}"
    )
    grid = probe["grids"][0]
    assert len(grid["tracks"]) == columns, (
        f"the grid has {len(grid['tracks'])} track(s) at {width}px, want {columns}: {grid['tracks']}"
    )

    ids = [card["id"] for card in grid["cards"]]
    assert ids == ROUTING_CARDS, f"the grid directly owns {ids} in order, want {ROUTING_CARDS}"

    expected = geometry(probe["clientWidth"], columns, probe["mainMaxWidth"])

    # The property under test, per card, so a failure names the card and the width:
    # in a two-track grid a card that spans is exactly the content box wide, and a
    # card that lost the hook is one track (half of it) wide.
    for card in grid["cards"]:
        assert abs(card["width"] - expected["content"]) <= 1, (
            f"{card['id']} is {card['width']:.1f}px wide at {width}px viewport; the grid's "
            f"content box is {expected['content']:.1f}px across {columns} track(s) with a "
            f"{expected['gap']:.0f}px gap, so this card is no longer spanning the grid"
        )

    # And both in the same column: a card can be full width without being aligned
    # with its neighbour, which would still be a layout change worth failing.
    first = grid["cards"][0]
    for card in grid["cards"][1:]:
        assert abs(card["left"] - first["left"]) <= 0.5 and abs(card["right"] - first["right"]) <= 0.5, (
            f"{card['id']} does not share the column of {first['id']} at {width}px: "
            f"its box is {card['left']:.1f}..{card['right']:.1f}, the first card's is "
            f"{first['left']:.1f}..{first['right']:.1f}"
        )


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
