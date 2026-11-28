"""Page-shape probes and expectations for the Settings surface.

The layout and navigation tests read the page the browser received, not the sheet
under test: every number they compare against is derived from the design tokens and
the app shell, so a wrong value in web/static/css/settings.css fails a test instead
of matching a copy of itself.

These live outside the test modules because two of them need the same probe: the
behaviour suite measures the geometry of each group's grid, and the navigation suite
asks the same page which group is in view. One definition means the two cannot
drift, and neither module has to reach into the other for it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOKENS_CSS = REPO_ROOT / "web" / "static" / "css" / "tokens.css"

# The approved spacing values these expectations are derived from. Pinned so a
# retuned scale is a visible edit here rather than a silent change of meaning.
APPROVED_SPACING = {
    "space-sm": 8,
    "space-md": 16,
    "space-lg": 24,
    "space-xl": 32,
    "sidebar-width": 250,
}


def token_px(name: str) -> float:
    match = re.search(rf"--{re.escape(name)}:\s*([\d.]+)px;", TOKENS_CSS.read_text(encoding="utf-8"))
    assert match, f"token --{name} not found in tokens.css"
    return float(match.group(1))


# Viewport width, expected columns. 1023 and 1024 straddle the min-width
# breakpoint, 390 and 320 are the phone cases the issue names.
SETTINGS_LAYOUT_CASES = [(1440, 2), (1024, 2), (1023, 1), (390, 1), (320, 1)]
SETTINGS_PROBE = """() => {
  const de = document.documentElement;
  const main = document.querySelector('.app-main');
  const ms = getComputedStyle(main);
  const grids = [...document.querySelectorAll('.settings-grid')].map(grid => {
    const gs = getComputedStyle(grid);
    const cards = [...grid.children].filter(c => c.classList.contains('settings-section-card')).map(c => {
      const r = c.getBoundingClientRect();
      return {id: c.id, left: r.left, right: r.right, top: r.top + window.scrollY, bottom: r.bottom + window.scrollY, width: r.width, height: r.height};
    });
    const parent = grid.closest('.settings-group');
    return {
      id: parent ? parent.id : null,
      columnGap: gs.columnGap, rowGap: gs.rowGap,
      tracks: gs.gridTemplateColumns.split(' ').map(parseFloat),
      gridWidth: grid.getBoundingClientRect().width,
      cards,
    };
  });
  return {
    clientWidth: de.clientWidth, scrollWidth: de.scrollWidth,
    mainWidth: main.getBoundingClientRect().width,
    mainMaxWidth: parseFloat(ms.maxWidth),
    mainPadding: [parseFloat(ms.paddingLeft), parseFloat(ms.paddingRight)],
    grids,
  };
}"""

# The card ids the Settings page renders, in DOM order, grouped as the page groups
# them. These are the ids the templates give their `.settings-section-card` elements.
#
# The count is not a constant to wait for. It used to be stated as "at least 9 cards",
# and when the hosting card moved out of Settings to the Servers page that number
# described a page that no longer exists: every test that waited on it timed out
# against a page that had rendered completely, which reads as a missing page rather
# than as a stale expectation. The list below is the page's own content, so a card that
# leaves or arrives is a visible edit here instead of a silent timeout, and the two
# assertions built on it fail with the card named.
SETTINGS_CARD_IDS = [
    "appearanceCard", "sslCard", "captchaCard", "limitsCard",
    "telegramCard", "notificationsCard", "upstreamCard", "backupCard",
]

# The readiness predicate every Settings measurement waits on. It is one definition
# because the wait was previously copied at three call sites and each copy is a place
# the condition can drift from the page.
SETTINGS_READY_JS = (
    "() => [" + ", ".join(f'"{card}"' for card in SETTINGS_CARD_IDS) + "]"
    ".every(id => document.getElementById(id))"
)


def wait_for_settings(page) -> None:
    """Wait until every Settings card the page is made of is in the DOM."""
    page.wait_for_function(SETTINGS_READY_JS)


# The three groups the accepted information architecture leaves on the page, in DOM
# order. The enumeration reads them from the page and compares, so a group that
# loses its grid fails here instead of reducing what is checked. The Network policy
# group is not one of them: it is the Routing page since #987.
SETTINGS_GROUP_IDS = ["group-portal", "group-notifications", "group-system"]


# The groups whose last row holds one card, which is what the span rule exists for.
#
# Empty, and that is a fact about the page rather than a disabled check: every group now
# holds an even number of cards (Portal 4, Notifications 2, System 2), so no grid ends on
# a lone card. It held System while Settings carried a ninth card; when the hosting card
# moved to the Servers page the page became even and this list described a page that no
# longer exists. The span rule itself is still exercised, from the other direction: the
# paired-last-row branch asserts the rule does not misfire, and the rule's own odd-count
# case is covered by the CSS contract test that reads the parity predicate.
LONE_LAST_CARD_GROUPS: list[str] = []


def app_main_max_width(fallback: float = 1300.0) -> float:
    """The app shell's max content width, read from the stylesheet that declares it.

    The browser reports the same value in SETTINGS_PROBE, but a caller that needs the
    geometry without a page (a fixture imposing a card width) reads it here instead of
    pinning a number that would then be independent of the layout.
    """
    layout = (REPO_ROOT / "web" / "static" / "css" / "layout.css").read_text(encoding="utf-8")
    match = re.search(r"\.app-main\s*\{[^}]*max-width:\s*([\d.]+)px", layout, re.S)
    return float(match.group(1)) if match else fallback


def rows(cards: list[dict]) -> list[list[dict]]:
    rows: dict[float, list[dict]] = {}
    for card in cards:
        rows.setdefault(round(card["top"], 1), []).append(card)
    return [rows[top] for top in sorted(rows)]


def geometry(client: float, columns: int, max_width: float) -> dict[str, float]:
    """Content width and track width of a columns-wide grid inside the app shell.

    Derived from the shell and the spacing scale, never from settings.css: from
    1024 px the sidebar is in flow and the main column is padded by --space-xl,
    below it the sidebar is off-canvas and the padding is --space-md.
    """
    gap = token_px("space-lg")
    sidebar = token_px("sidebar-width") if columns == 2 else 0.0
    padding = token_px("space-xl") if columns == 2 else token_px("space-md")
    main = min(client - sidebar, max_width)
    content = main - 2 * padding
    return {
        "gap": gap,
        "main": main,
        "padding": padding,
        "content": content,
        "track": (content - gap * (columns - 1)) / columns,
    }


SETTINGS_NAV_PROBE = """() => {
  const de = document.documentElement;
  const nav = document.querySelector('.app-main nav');
  // Every field is reported on both paths. Absence is navPresent === false, never a
  // different object: a probe that returns a second shape for the failing case turns
  // the assertion that should report "there is no navigation" into a KeyError, which
  // is a fault in the oracle rather than a statement about the page.
  const r = nav ? nav.getBoundingClientRect() : null;
  const links = nav ? [...nav.querySelectorAll('a')].map(a => {
    const lr = a.getBoundingClientRect();
    // The resting paint of the link itself and the marks that carry the current
    // group: a navigation link that kept a filled background or a full border box
    // would read as a button, and a current group marked by a text hue alone
    // would be indistinguishable to a reader who cannot separate the hues. The
    // suite states the values it requires rather than trusting the sheet.
    const s = getComputedStyle(a);
    return {href: a.getAttribute('href'), text: (a.textContent || '').trim(),
            current: a.getAttribute('aria-current'),
            background: s.backgroundColor,
            backgroundImage: s.backgroundImage,
            boxShadow: s.boxShadow,
            color: s.color,
            fontWeight: s.fontWeight,
            textDecorationLine: s.textDecorationLine,
            borders: {top: s.borderTopWidth, right: s.borderRightWidth,
                      bottom: s.borderBottomWidth, left: s.borderLeftWidth},
            width: lr.width, height: lr.height, left: lr.left, right: lr.right};
  }) : [];
  const current = document.querySelector('[aria-current="true"]');
  const active = document.activeElement;
  return {
    navPresent: !!nav,
    label: nav ? (nav.getAttribute('aria-label') || '') : '',
    links,
    navTop: r ? r.top : null, navHeight: r ? r.height : null,
    clientWidth: de.clientWidth, scrollWidth: de.scrollWidth,
    activeId: active ? (active.id || '') : '',
    activeTag: active ? active.tagName : '',
    currentHref: current ? current.getAttribute('href') : null,
    currentCount: document.querySelectorAll('[aria-current="true"]').length,
  };
}"""
