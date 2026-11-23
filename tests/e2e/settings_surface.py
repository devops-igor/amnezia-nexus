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

# The four groups the accepted information architecture puts on the page, in DOM
# order. The enumeration reads them from the page and compares, so a group that
# loses its grid fails here instead of reducing what is checked.
SETTINGS_GROUP_IDS = ["group-portal", "group-notifications", "group-network", "group-system"]


# The groups whose last row holds one card, which is what the span rule exists
# for: Network policy's two cards span by design, and System ends on the backup
# card after one pair. The other two groups end on a pair.
LONE_LAST_CARD_GROUPS = ["group-network", "group-system"]


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
    // The resting paint of the link itself: a navigation link that kept a
    // filled background or a full border box would read as a button, so the
    // suite states the value it must have rather than trusting the sheet.
    const s = getComputedStyle(a);
    return {href: a.getAttribute('href'), text: (a.textContent || '').trim(),
            current: a.getAttribute('aria-current'),
            background: s.backgroundColor,
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
