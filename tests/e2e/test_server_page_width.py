"""The server page must fit the viewport it is rendered in (#975).

At 390 px the three page tabs kept a single line, so the row measured wider than
the page and the document scrolled sideways with the last label wholly off
screen. The Management panel added a second, independent overflow: its grid track
had an unconditional 400 px minimum, wider than the 358 px content area.

This suite measures the document the browser laid out — every panel, both themes,
the phone widths (390 and a narrower 320 where labels take extra lines), the five
shipped locales, and the desktop widths — because a stylesheet or selector
assertion cannot show that the labels are on screen, that the row stopped
scrolling, or that the desktop treatment is still the one the page shipped with.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast

PHONE = (390, 844)
SHORT_PHONE = (390, 568)
NARROW_PHONE = (320, 640)
WIDE = [(1024, 768), (1440, 900)]
VIEWPORTS = [PHONE, NARROW_PHONE, *WIDE]

PANELS = ("protocols", "services", "management")
THEMES = ("dark", "light")
LOCALES = ("en", "ru", "fr", "zh", "fa")

TRANSLATIONS_DIR = Path(__file__).resolve().parents[2] / "web" / "translations"

# The target floor the phone treatment keeps: the measured current height and
# the Settings in-page navigation's resolved control step, not a reduction.
MIN_TARGET = 40
# Two 4 px focus envelopes must not overlap, so boxes keep at least 8 px.
MIN_GAP = 8
# The desktop row is unchanged by this work: its gaps and control paddings.
WIDE_GAP = 16
WIDE_PADDING_INLINE = 16
# Outline (2 px) plus its offset (2 px), the envelope a focus ring paints.
FOCUS_ENVELOPE = 4

RECT_TOLERANCE = 0.5

# One probe for every measurement the cases need. It reports the laid-out
# document, the row the tabs live in and each button's own box, text-node
# rectangles (so a label counts as visible only where it is painted), icon box,
# computed state and a hit test at each button's centre. The caller scrolls the
# row into view first, because a hit test outside the viewport answers nothing.
ROW_PROBE = r"""() => {
  const docEl = document.documentElement;
  const body = document.body;
  const firstTab = document.getElementById('tab-protocols');
  if (!firstTab) return { error: 'the page has no #tab-protocols button' };
  const row = firstTab.parentElement;

  const countIds = new Set([...row.querySelectorAll('[id$="-count"]')].map(el => el.id));
  const textRects = (el) => {
    const out = [];
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const text = (node.nodeValue || '').trim();
      if (!text) continue;
      const parent = node.parentElement;
      const range = document.createRange();
      range.selectNodeContents(node);
      for (const rect of range.getClientRects()) {
        if (rect.width === 0 && rect.height === 0) continue;
        out.push({
          text: text,
          count: !!(parent && countIds.has(parent.id)),
          left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
        });
      }
    }
    return out;
  };

  const buttons = [...row.querySelectorAll('button')].map(btn => {
    const rect = btn.getBoundingClientRect();
    const style = getComputedStyle(btn);
    const icon = btn.querySelector('svg.icon');
    const iconRect = icon ? icon.getBoundingClientRect() : null;
    let labelText = '';
    const labelWalker = document.createTreeWalker(btn, NodeFilter.SHOW_TEXT);
    let labelNode;
    while ((labelNode = labelWalker.nextNode())) {
      if (labelNode.parentElement && countIds.has(labelNode.parentElement.id)) continue;
      labelText += labelNode.nodeValue || '';
    }
    return {
      id: btn.id,
      active: btn.classList.contains('active'),
      ariaCurrent: btn.getAttribute('aria-current'),
      labelText: labelText.replace(/\s+/g, ' ').trim(),
      left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
      width: rect.width, height: rect.height,
      fontWeight: style.fontWeight,
      color: style.color,
      backgroundImage: style.backgroundImage,
      boxShadow: style.boxShadow,
      borderRadius: style.borderRadius,
      borderBottomWidth: style.borderBottomWidth,
      borderBottomColor: style.borderBottomColor,
      paddingLeft: style.paddingLeft,
      paddingRight: style.paddingRight,
      texts: textRects(btn),
      icon: iconRect
        ? { left: iconRect.left, right: iconRect.right, top: iconRect.top,
            bottom: iconRect.bottom, width: iconRect.width, height: iconRect.height }
        : null,
    };
  });

  const hits = buttons.map(b => {
    const x = (b.left + b.right) / 2;
    const y = (b.top + b.bottom) / 2;
    const el = document.elementFromPoint(x, y);
    const owner = el && el.closest ? el.closest('button') : null;
    return { id: b.id, hit: !!(owner && owner.id === b.id) };
  });

  const rowRect = row.getBoundingClientRect();
  const rowStyle = getComputedStyle(row);

  let grid = null;
  const management = document.getElementById('management-grid');
  if (management && !management.classList.contains('hidden')) {
    const gRect = management.getBoundingClientRect();
    const card = management.querySelector('.card');
    const cRect = card ? card.getBoundingClientRect() : null;
    grid = {
      left: gRect.left, right: gRect.right, width: gRect.width,
      clientWidth: management.clientWidth, scrollWidth: management.scrollWidth,
      tracks: getComputedStyle(management).gridTemplateColumns,
      card: cRect
        ? { left: cRect.left, right: cRect.right, width: cRect.width }
        : null,
    };
  }

  return {
    viewport: docEl.clientWidth,
    innerWidth: window.innerWidth,
    scrollX: window.scrollX,
    docClient: docEl.clientWidth,
    docScroll: docEl.scrollWidth,
    bodyClient: body.clientWidth,
    bodyScroll: body.scrollWidth,
    theme: docEl.getAttribute('data-theme'),
    dir: docEl.getAttribute('dir') || 'ltr',
    row: {
      left: rowRect.left, right: rowRect.right, width: rowRect.width,
      flexWrap: rowStyle.flexWrap, gap: rowStyle.gap,
      borderBottomWidth: rowStyle.borderBottomWidth,
      paddingBottom: rowStyle.paddingBottom,
      clientWidth: row.clientWidth, scrollWidth: row.scrollWidth,
    },
    buttons: buttons,
    hits: hits,
    grid: grid,
    activeCount: row.querySelectorAll('button.active').length,
    currentCount: row.querySelectorAll('[aria-current="true"]').length,
    visiblePanels: ['protocols-grid', 'services-grid', 'management-grid']
      .filter(id => {
        const el = document.getElementById(id);
        return el && !el.classList.contains('hidden');
      }),
  };
}"""


def open_server_page(page: Page, base_url: str, lang: str = "") -> None:
    """Log in (through the fixture) and load the seeded server's own page."""
    suffix = f"?lang={lang}" if lang else ""
    page.goto(f"{base_url}/server/1{suffix}")
    page.wait_for_selector("#tab-protocols")
    page.wait_for_function(
        "() => document.styleSheets.length >= 8 && document.getElementById('tab-protocols')"
        " && getComputedStyle(document.getElementById('tab-protocols')).display !== 'none'"
    )


def select_panel(page: Page, panel: str) -> None:
    """Activate one panel the way an operator does, and wait for the switch."""
    page.click(f"#tab-{panel}")
    page.wait_for_function(
        "panel => {"
        "  const grid = document.getElementById(panel + '-grid');"
        "  const tab = document.getElementById('tab-' + panel);"
        "  return !!grid && !grid.classList.contains('hidden')"
        "    && tab.classList.contains('active');"
        "}",
        arg=panel,
    )


def apply_theme(page: Page, theme: str) -> None:
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)


def measure(page: Page) -> dict:
    """Scroll the tab row into view without panning, then measure the page."""
    page.evaluate(
        "() => document.getElementById('tab-protocols').parentElement"
        ".scrollIntoView({block: 'center', inline: 'nearest'})"
    )
    # A tab carries the shared 0.15 s transition, so a sample taken while a
    # selection fades reports a style no reader ever rests on. Wait for the
    # transitions the layout owns to finish instead of sleeping for them.
    page.wait_for_function("() => document.getAnimations().every(a => a.playState !== 'running')")
    return page.evaluate(ROW_PROBE)


def translations(locale: str) -> dict[str, str]:
    """The shipped tab labels, read from the locale bundle rather than pinned here."""
    bundle = json.loads((TRANSLATIONS_DIR / f"{locale}.json").read_text(encoding="utf-8"))
    return {name: bundle[name] for name in PANELS}


def rgb(hex_colour: str) -> str:
    value = hex_colour.lstrip("#")
    vertices = [int(value[i:i + 2], 16) for i in (0, 2, 4)]
    return "rgb({}, {}, {})".format(*vertices)


def darken(hex_colour: str, factor: float) -> str:
    """A hex colour with every channel scaled, as an 8% black layer does."""
    value = hex_colour.lstrip("#")
    vertices = [int(int(value[i:i + 2], 16) * factor) for i in (0, 2, 4)]
    return "#{:02x}{:02x}{:02x}".format(*vertices)


def accent_gradient_stops(theme: str) -> tuple[dict[str, str], list[str]]:
    tokens = contrast.theme_tokens(theme)
    stops = re.findall(r"#[0-9a-fA-F]{6}", tokens["accent-gradient"])
    assert len(stops) == 2, f"{theme}: the accent gradient no longer has two stops: {stops}"
    return tokens, stops


def horizontal_offsets(buttons: list[dict]) -> list[float]:
    """The space between the boxes of each pair of neighbours, in DOM order.

    Direction-agnostic: a row laid out right to left puts the next button on the
    other side, so the distance is the larger of the two edges' separations.
    """
    offsets = []
    for first, second in zip(buttons, buttons[1:]):
        same_line = abs(first["top"] - second["top"]) <= RECT_TOLERANCE
        if same_line:
            offsets.append(
                max(second["left"] - first["right"], first["left"] - second["right"])
            )
        else:
            offsets.append(
                max(second["top"] - first["bottom"], first["top"] - second["bottom"])
            )
    return offsets


def overflow_row(measurement: dict) -> dict:
    """The parts of a measurement that describe a document wider than its viewport."""
    return {
        "theme": measurement["theme"],
        "panels": measurement["visiblePanels"],
        "docClient": measurement["docClient"],
        "docScroll": measurement["docScroll"],
        "bodyScroll": measurement["bodyScroll"],
        "rowClient": measurement["row"]["clientWidth"],
        "rowScroll": measurement["row"]["scrollWidth"],
        "scrollX": measurement["scrollX"],
    }


@pytest.mark.e2e
@pytest.mark.parametrize("width,height", VIEWPORTS)
def test_server_page_has_no_horizontal_overflow(
    authenticated_page: Page, base_url: str, width: int, height: int
) -> None:
    """No selected panel, in either theme, may make the document wider than the page."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": height})
    open_server_page(page, base_url)

    failures = []
    for theme in THEMES:
        apply_theme(page, theme)
        for panel in PANELS:
            select_panel(page, panel)
            measurement = measure(page)
            if measurement["docScroll"] > measurement["docClient"] + RECT_TOLERANCE:
                failures.append(overflow_row(measurement))
            if measurement["bodyScroll"] > measurement["docClient"] + RECT_TOLERANCE:
                failures.append(overflow_row(measurement))
            if measurement["row"]["scrollWidth"] > measurement["row"]["clientWidth"] + RECT_TOLERANCE:
                failures.append(overflow_row(measurement))
            if width <= PHONE[0]:
                # Nothing may pan: an operator who scrolls sideways finds one
                # label and loses another, so fit is not a substitute here.
                page.evaluate("() => window.scrollTo(120, window.scrollY)")
                if page.evaluate("() => window.scrollX") != 0:
                    failures.append(overflow_row(measure(page)))
    assert not failures, f"the document is wider than its {width} px viewport: {failures}"


@pytest.mark.e2e
def test_server_tabs_keep_every_label_visible_and_switchable(
    authenticated_page: Page, base_url: str
) -> None:
    """At 390 the three tabs stay readable, target-sized and operable as buttons."""
    page = authenticated_page
    page.set_viewport_size({"width": PHONE[0], "height": PHONE[1]})
    open_server_page(page, base_url)

    for theme in THEMES:
        apply_theme(page, theme)
        for panel in PANELS:
            select_panel(page, panel)
            m = measure(page)
            where = f"{theme}/{panel}"
            assert m.get("error") is None, m
            assert m["scrollX"] == 0, f"{where}: measuring must not pan the page: {m['scrollX']}"
            assert len(m["buttons"]) == 3, f"{where}: expected three tabs: {m['buttons']}"
            assert m["visiblePanels"] == [f"{panel}-grid"], (
                f"{where}: exactly the selected panel renders: {m['visiblePanels']}"
            )

            # Exactly one current tab, painted and announced the same way.
            assert m["activeCount"] == 1, f"{where}: {m['activeCount']} buttons carry .active"
            assert m["currentCount"] == 1, f"{where}: {m['currentCount']} buttons carry aria-current"
            active = [b for b in m["buttons"] if b["active"]]
            current = [b for b in m["buttons"] if b["ariaCurrent"] == "true"]
            assert active and current and active[0]["id"] == current[0]["id"], where

            for button in m["buttons"]:
                label = f"{where}/{button['id']}"
                # The target floor and the space between neighbours.
                assert button["height"] >= MIN_TARGET, f"{label}: height {button['height']}"
                assert button["width"] >= MIN_TARGET, f"{label}: width {button['width']}"
                assert button["right"] <= m["docClient"] + RECT_TOLERANCE, (
                    f"{label}: the button ends at {button['right']} on a {m['docClient']} px page"
                )
                assert button["left"] >= -RECT_TOLERANCE, f"{label}: the button starts at {button['left']}"

                # Every painted part of the button is inside its own box and on
                # screen: nothing here is clipped, ellipsised or pushed aside.
                assert button["texts"], f"{label}: no label text is rendered"
                assert button["icon"] and button["icon"]["width"] > 0, f"{label}: no icon"
                for part in (*button["texts"], button["icon"]):
                    assert part["left"] >= button["left"] - RECT_TOLERANCE, f"{label}: clipped at start"
                    assert part["right"] <= button["right"] + RECT_TOLERANCE, f"{label}: clipped at end"
                    assert part["top"] >= button["top"] - RECT_TOLERANCE, f"{label}: clipped at top"
                    assert part["bottom"] <= button["bottom"] + RECT_TOLERANCE, f"{label}: clipped at bottom"
                    assert part["left"] >= -RECT_TOLERANCE, f"{label}: off screen at start"
                    assert part["right"] <= m["docClient"] + RECT_TOLERANCE, (
                        f"{label}: {part['text']!r} ends at {part['right']} on a "
                        f"{m['docClient']} px page"
                    )
                counts = [part for part in button["texts"] if part["count"]]
                for count in counts:
                    assert count["text"], f"{label}: a count renders no text"

            for offset in horizontal_offsets(m["buttons"]):
                assert offset >= MIN_GAP - RECT_TOLERANCE, (
                    f"{where}: the boxes are {offset} px apart, under the {MIN_GAP} px floor"
                )
            for hit in m["hits"]:
                assert hit["hit"], f"{where}: {hit['id']} is not hit-testable at its centre"

            # The current tab is told apart by shape and weight, not by hue.
            for button in m["buttons"]:
                label = f"{where}/{button['id']}"
                if button["active"]:
                    assert "linear-gradient" in button["backgroundImage"], label
                    assert button["boxShadow"] not in ("none", ""), label
                    assert button["color"] == "rgb(255, 255, 255)", label
                    assert button["fontWeight"] == "600", label
                else:
                    assert button["backgroundImage"] == "none", label
                    assert button["boxShadow"] == "none", label
                    assert button["fontWeight"] == "500", label

    # The labels are read against the surfaces the tokens paint behind them.
    for theme in THEMES:
        tokens, stops = accent_gradient_stops(theme)
        assert contrast.ratio("#ffffff", darken(stops[0], 0.92)) >= contrast.AA_TEXT, theme
        assert contrast.ratio("#ffffff", darken(stops[1], 0.92)) >= contrast.AA_TEXT, theme
        assert contrast.ratio(tokens["text-secondary"], tokens["bg-primary"]) >= contrast.AA_TEXT, theme


@pytest.mark.e2e
def test_server_management_panel_fits_its_container(authenticated_page: Page, base_url: str) -> None:
    """The Management grid is bounded by the column it sits in, not by a 400 px floor."""
    page = authenticated_page
    page.set_viewport_size({"width": PHONE[0], "height": PHONE[1]})
    open_server_page(page, base_url)

    for theme in THEMES:
        apply_theme(page, theme)
        select_panel(page, "management")
        m = measure(page)
        assert m["grid"] is not None, f"{theme}: the Management grid is not rendered"
        grid = m["grid"]
        assert grid["right"] <= m["docClient"] + RECT_TOLERANCE, f"{theme}: {grid}"
        assert grid["card"] and grid["card"]["right"] <= m["docClient"] + RECT_TOLERANCE, (
            f"{theme}: the card ends at {grid['card']} on a {m['docClient']} px page"
        )
        assert grid["scrollWidth"] <= grid["clientWidth"] + RECT_TOLERANCE, f"{theme}: {grid}"
        assert grid["tracks"].strip(), f"{theme}: the grid declares no track"


@pytest.mark.e2e
@pytest.mark.parametrize("locale", LOCALES)
def test_server_tabs_fit_a_phone_in_every_locale(
    authenticated_page: Page, base_url: str, locale: str
) -> None:
    """Longer translations take another line instead of widening the page."""
    page = authenticated_page
    page.set_viewport_size({"width": PHONE[0], "height": PHONE[1]})
    open_server_page(page, base_url, lang=locale)
    labels = translations(locale)

    assert page.evaluate("() => document.documentElement.getAttribute('dir')") == (
        "rtl" if locale == "fa" else None
    )

    for panel in PANELS:
        select_panel(page, panel)
        m = measure(page)
        assert m["docScroll"] <= m["docClient"] + RECT_TOLERANCE, f"{locale}/{panel}: {overflow_row(m)}"
        assert m["bodyScroll"] <= m["docClient"] + RECT_TOLERANCE, f"{locale}/{panel}: {overflow_row(m)}"
        for button in m["buttons"]:
            name = button["id"].replace("tab-", "")
            label = f"{locale}/{panel}/{name}"
            # The shipped translation, not a shortened copy of it.
            assert button["labelText"] == labels[name], f"{label}: {button['labelText']!r}"
            assert button["height"] >= MIN_TARGET, label
            for part in (*button["texts"], button["icon"]):
                assert part["left"] >= button["left"] - RECT_TOLERANCE, f"{label}: clipped at start"
                assert part["right"] <= button["right"] + RECT_TOLERANCE, f"{label}: clipped at end"
                assert part["left"] >= -RECT_TOLERANCE, f"{label}: off screen"
                assert part["right"] <= m["docClient"] + RECT_TOLERANCE, f"{label}: off screen"
        for offset in horizontal_offsets(m["buttons"]):
            assert offset >= MIN_GAP - RECT_TOLERANCE, f"{locale}/{panel}: {offset} px apart"


@pytest.mark.e2e
@pytest.mark.parametrize("width,height", WIDE)
def test_server_tab_row_keeps_the_desktop_treatment(
    authenticated_page: Page, base_url: str, width: int, height: int
) -> None:
    """At 1024 and 1440 the row is still the single line of underlined tabs."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": height})
    open_server_page(page, base_url)

    tokens = contrast.theme_tokens("dark")
    accent = rgb(tokens["accent"])

    for theme in THEMES:
        apply_theme(page, theme)
        select_panel(page, "protocols")
        m = measure(page)
        where = f"{width}/{theme}"
        assert m["docScroll"] <= m["docClient"] + RECT_TOLERANCE, f"{where}: {overflow_row(m)}"
        buttons = m["buttons"]
        assert len(buttons) == 3, where

        # One line: every button shares the row's baseline and height.
        tops = {round(button["top"], 2) for button in buttons}
        assert len(tops) == 1, f"{where}: the row wrapped to {tops}"
        for button in buttons:
            assert button["height"] >= MIN_TARGET, f"{where}/{button['id']}: {button['height']}"
            assert button["paddingLeft"] == f"{WIDE_PADDING_INLINE}px", f"{where}/{button['id']}"
            assert button["paddingRight"] == f"{WIDE_PADDING_INLINE}px", f"{where}/{button['id']}"
        for offset in horizontal_offsets(buttons):
            assert abs(offset - WIDE_GAP) <= RECT_TOLERANCE, (
                f"{where}: the desktop gap became {offset} px"
            )

        # The desktop current state is the underline, not the phone pill.
        for button in buttons:
            label = f"{where}/{button['id']}"
            assert button["borderRadius"] == "0px", f"{label}: radius {button['borderRadius']}"
            assert button["backgroundImage"] == "none", label
            if button["active"]:
                assert button["borderBottomWidth"] == "2px", label
                assert button["borderBottomColor"] == accent, f"{label}: {button['borderBottomColor']}"
                assert button["fontWeight"] == "600", label
            else:
                assert button["borderBottomWidth"] == "2px", label
                assert button["fontWeight"] == "500", label
            for part in (*button["texts"], button["icon"]):
                assert part["right"] <= m["docClient"] + RECT_TOLERANCE, f"{label}: off screen"


@pytest.mark.e2e
def test_server_focused_tab_stays_clear_of_the_shell_bars(
    authenticated_page: Page, base_url: str
) -> None:
    """On a short phone viewport focus brings each tab clear of both shell bars."""
    page = authenticated_page
    page.set_viewport_size({"width": SHORT_PHONE[0], "height": SHORT_PHONE[1]})
    open_server_page(page, base_url)

    bars = page.evaluate(
        "() => {"
        "  const top = document.querySelector('.mobile-topbar');"
        "  const bottom = document.querySelector('.mobile-bottom-bar');"
        "  return {"
        "    top: top ? top.getBoundingClientRect().bottom : 0,"
        "    bottom: bottom ? bottom.getBoundingClientRect().top : window.innerHeight,"
        "  };"
        "}"
    )
    assert bars["top"] > 0 and bars["bottom"] < SHORT_PHONE[1], f"the shell bars are not rendered: {bars}"

    for tab in PANELS:
        page.focus(f"#tab-{tab}")
        page.wait_for_function(
            "id => document.activeElement && document.activeElement.id === id",
            arg=f"tab-{tab}",
        )
        box = page.evaluate(
            "id => {"
            "  const r = document.getElementById(id).getBoundingClientRect();"
            "  return {top: r.top, bottom: r.bottom, left: r.left, right: r.right};"
            "}",
            f"tab-{tab}",
        )
        assert box["top"] - FOCUS_ENVELOPE >= bars["top"], f"{tab}: under the top bar: {box} vs {bars}"
        assert box["bottom"] + FOCUS_ENVELOPE <= bars["bottom"], (
            f"{tab}: under the bottom bar: {box} vs {bars}"
        )

    # Enter and Space select the focused tab and leave focus on the control.
    for key, expected in (("Enter", "services"), (" ", "management")):
        page.focus(f"#tab-{expected}")
        page.keyboard.press(key)
        page.wait_for_function(
            "panel => {"
            "  const grid = document.getElementById(panel + '-grid');"
            "  return !!grid && !grid.classList.contains('hidden');"
            "}",
            arg=expected,
        )
        assert page.evaluate("() => document.activeElement.id") == f"tab-{expected}"
        assert page.evaluate(
            "() => document.querySelectorAll('[aria-current=\"true\"]').length"
        ) == 1
