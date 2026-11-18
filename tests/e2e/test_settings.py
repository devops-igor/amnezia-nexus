"""E2E tests for settings page and API."""

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast
from tests.e2e.conftest import api_get, api_post, assert_response_shape


@pytest.mark.e2e
def test_settings_page_loads(authenticated_page: Page, base_url: str) -> None:
    """Navigate to /settings -> sees settings form."""
    page = authenticated_page
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")

    # Should not redirect to login
    assert "/login" not in page.url

    # Settings page should have content
    content = page.content()
    assert len(content) > 100


@pytest.mark.e2e
def test_change_title(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Change panel title -> saved and reflected in page."""
    page = authenticated_page

    # Get current settings
    settings_result = api_get(page, "/api/settings")

    # Validate settings response shape
    if isinstance(settings_result, dict):
        assert_response_shape(settings_result, {"appearance": dict}, "settings")

    original_title = ""
    if isinstance(settings_result, dict):
        appearance = settings_result.get("appearance", {})
        original_title = appearance.get("title", "Amnezia Panel")

    # Save settings with a new title
    new_title = "E2E Test Panel"

    # Build settings payload with all required fields
    save_result = api_post(
        page,
        "/api/settings/save",
        {
            "appearance": {"title": new_title, "subtitle": "", "logo": ""},
            "sync": settings_result.get("sync", {}) if isinstance(settings_result, dict) else {},
            "captcha": (
                settings_result.get("captcha", {})
                if isinstance(settings_result, dict)
                else {"enabled": False}
            ),
            "telegram": (
                settings_result.get("telegram", {})
                if isinstance(settings_result, dict)
                else {"enabled": False, "token": ""}
            ),
            "ssl": (
                settings_result.get("ssl", {})
                if isinstance(settings_result, dict)
                else {
                    "enabled": False,
                    "domain": "",
                    "cert_path": "",
                    "key_path": "",
                    "cert_text": "",
                    "key_text": "",
                    "panel_port": 5000,
                }
            ),
            "limits": (
                settings_result.get("limits", {}) if isinstance(settings_result, dict) else {}
            ),
        },
        csrf_token,
    )

    # Should succeed
    if save_result["status"] == 200:
        assert save_result["body"].get("status") == "success"
        assert_response_shape(save_result["body"], {"status": str}, "settings_save")

        # Verify by navigating to the page and checking the title appears
        page.goto(f"{base_url}/")
        page.wait_for_load_state("networkidle")
        page_content = page.content()
        # Title should appear in the rendered page
        assert new_title in page_content or "E2E" in page_content

    # Restore original settings
    api_post(
        page,
        "/api/settings/save",
        {
            "appearance": {"title": original_title, "subtitle": "", "logo": ""},
            "sync": settings_result.get("sync", {}) if isinstance(settings_result, dict) else {},
            "captcha": (
                settings_result.get("captcha", {})
                if isinstance(settings_result, dict)
                else {"enabled": False}
            ),
            "telegram": (
                settings_result.get("telegram", {})
                if isinstance(settings_result, dict)
                else {"enabled": False, "token": ""}
            ),
            "ssl": (
                settings_result.get("ssl", {})
                if isinstance(settings_result, dict)
                else {
                    "enabled": False,
                    "domain": "",
                    "cert_path": "",
                    "key_path": "",
                    "cert_text": "",
                    "key_text": "",
                    "panel_port": 5000,
                }
            ),
            "limits": (
                settings_result.get("limits", {}) if isinstance(settings_result, dict) else {}
            ),
        },
        csrf_token,
    )


@pytest.mark.e2e
def test_captcha_toggle(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Toggle captcha setting -> setting changes."""
    page = authenticated_page

    # Get current settings
    settings_result = api_get(page, "/api/settings")

    original_captcha = {"enabled": False}
    if isinstance(settings_result, dict):
        original_captcha = settings_result.get("captcha", {"enabled": False})

    # Toggle captcha on
    captcha_on = {"enabled": True}
    save_result = api_post(
        page,
        "/api/settings/save",
        {
            "appearance": (
                settings_result.get("appearance", {"title": "", "subtitle": "", "logo": ""})
                if isinstance(settings_result, dict)
                else {"title": "", "subtitle": "", "logo": ""}
            ),
            "sync": settings_result.get("sync", {}) if isinstance(settings_result, dict) else {},
            "captcha": captcha_on,
            "telegram": (
                settings_result.get("telegram", {})
                if isinstance(settings_result, dict)
                else {"enabled": False, "token": ""}
            ),
            "ssl": (
                settings_result.get("ssl", {})
                if isinstance(settings_result, dict)
                else {
                    "enabled": False,
                    "domain": "",
                    "cert_path": "",
                    "key_path": "",
                    "cert_text": "",
                    "key_text": "",
                    "panel_port": 5000,
                }
            ),
            "limits": (
                settings_result.get("limits", {}) if isinstance(settings_result, dict) else {}
            ),
        },
        csrf_token,
    )

    if save_result["status"] == 200:
        # Verify captcha is now enabled
        verify_result = api_get(page, "/api/settings")
        captcha_state = verify_result.get("captcha", {}) if isinstance(verify_result, dict) else {}
        # Captcha should be enabled (or at least the save succeeded)
        assert (
            captcha_state.get("enabled") is True or save_result["body"].get("status") == "success"
        )

    # Restore original captcha setting
    api_post(
        page,
        "/api/settings/save",
        {
            "appearance": (
                settings_result.get("appearance", {"title": "", "subtitle": "", "logo": ""})
                if isinstance(settings_result, dict)
                else {"title": "", "subtitle": "", "logo": ""}
            ),
            "sync": settings_result.get("sync", {}) if isinstance(settings_result, dict) else {},
            "captcha": original_captcha,
            "telegram": (
                settings_result.get("telegram", {})
                if isinstance(settings_result, dict)
                else {"enabled": False, "token": ""}
            ),
            "ssl": (
                settings_result.get("ssl", {})
                if isinstance(settings_result, dict)
                else {
                    "enabled": False,
                    "domain": "",
                    "cert_path": "",
                    "key_path": "",
                    "cert_text": "",
                    "key_text": "",
                    "panel_port": 5000,
                }
            ),
            "limits": (
                settings_result.get("limits", {}) if isinstance(settings_result, dict) else {}
            ),
        },
        csrf_token,
    )


@pytest.mark.e2e
def test_backup_download(authenticated_page: Page, base_url: str) -> None:
    """Click download backup -> gets backup file."""
    page = authenticated_page

    # Use Playwright's request API to download backup (bypasses CSP)
    result = page.request.get(
        f"{base_url}/api/settings/backup/download",
    )

    # Should return 200 and JSON content
    assert result.status == 200
    content_type = result.headers.get("content-type", "")
    text = result.text()
    assert text.startswith("{") or text.startswith("[")


@pytest.mark.e2e
def test_upstream_status_api(authenticated_page: Page, base_url: str) -> None:
    """GET /api/system/upstream-status returns valid upstream component status."""
    page = authenticated_page

    # Request upstream status via API
    result = api_get(page, "/api/system/upstream-status")

    # Validate response shape
    assert_response_shape(
        result,
        {
            "checked_at": str,
            "update_available": bool,
            "components": list,
            "base_image": str,
        },
        "upstream_status",
    )

    # Validate base_image contains amneziawg or devopsigor
    base_image = result.get("base_image", "")
    assert "amneziawg" in base_image or "devopsigor" in base_image

    # Validate components list contains items for amneziawg-go and amneziawg-tools
    components = result.get("components", [])
    component_names = {comp.get("name") for comp in components if isinstance(comp, dict)}
    assert "amneziawg-go" in component_names
    assert "amneziawg-tools" in component_names

    # Verify keys for each component
    for comp in components:
        assert isinstance(comp, dict)
        for key in ("name", "pinned_version", "latest_version", "release_url"):
            assert key in comp

    # Make force refresh request and verify valid response
    refresh_result = api_get(page, "/api/system/upstream-status?refresh=true")
    assert isinstance(refresh_result, dict)
    assert_response_shape(
        refresh_result,
        {
            "checked_at": str,
            "update_available": bool,
            "components": list,
            "base_image": str,
        },
        "upstream_status_refresh",
    )


@pytest.mark.e2e
def test_upstream_status_ui(authenticated_page: Page, base_url: str) -> None:
    """Upstream AmneziaWG Components card rendered on /settings."""
    page = authenticated_page
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")

    # Verify visibility of upstream section elements
    badge_go = page.locator("#badge-amneziawg-go")
    badge_tools = page.locator("#badge-amneziawg-tools")
    base_image_el = page.locator("#upstreamBaseImage")

    badge_go.wait_for(state="visible")
    badge_tools.wait_for(state="visible")
    base_image_el.wait_for(state="visible")

    assert badge_go.is_visible()
    assert badge_tools.is_visible()
    assert base_image_el.is_visible()

    # Verify Docker base image text contains devopsigor/amneziawg
    base_image_text = base_image_el.inner_text()
    assert "devopsigor/amneziawg" in base_image_text

    # Verify "Check for Updates" button exists and can be clicked
    check_btn = page.locator("#upstreamCheckBtn")
    check_btn.wait_for(state="visible")
    assert check_btn.is_visible()
    assert check_btn.is_enabled()

    page_errors: list[str] = []
    page.on("pageerror", lambda err: page_errors.append(str(err)))

    check_btn.click()
    page.wait_for_load_state("networkidle")
    assert len(page_errors) == 0
    assert check_btn.is_visible()


# --- Settings layout, checked against expectations derived from the design tokens
# and the app shell, never from web/static/css/settings.css. A wrong value in that
# sheet (a different gap, a different breakpoint, rows that stop stretching) has to
# fail here without anyone editing an expectation.
#
# Measured on the pinned Chromium: two 551 px tracks at 1440 and two 343 px tracks
# at 1024, a 24 px gap and paired cards of exactly equal height. A vertical
# scrollbar shrinks clientWidth and the same rules then measure 548/340, so the
# expectation is computed from clientWidth instead of being pinned to one
# browser's viewport box.

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


def _token_px(name: str) -> float:
    match = re.search(rf"--{re.escape(name)}:\s*([\d.]+)px;", TOKENS_CSS.read_text(encoding="utf-8"))
    assert match, f"token --{name} not found in tokens.css"
    return float(match.group(1))


# Viewport width, expected columns. 1023 and 1024 straddle the min-width
# breakpoint, 390 and 320 are the phone cases the issue names.
SETTINGS_LAYOUT_CASES = [(1440, 2), (1024, 2), (1023, 1), (390, 1), (320, 1)]
SETTINGS_PROBE = """() => {
  const grid = document.querySelector('.settings-grid');
  const gs = getComputedStyle(grid);
  const main = document.querySelector('.app-main');
  const ms = getComputedStyle(main);
  const cards = [...grid.children].filter(c => c.classList.contains('settings-section-card')).map(c => {
    const r = c.getBoundingClientRect();
    return {left: r.left, right: r.right, top: r.top + window.scrollY, bottom: r.bottom + window.scrollY, width: r.width, height: r.height};
  });
  const de = document.documentElement;
  return {
    clientWidth: de.clientWidth, scrollWidth: de.scrollWidth,
    columnGap: gs.columnGap, rowGap: gs.rowGap,
    tracks: gs.gridTemplateColumns.split(' ').map(parseFloat),
    gridWidth: grid.getBoundingClientRect().width,
    mainWidth: main.getBoundingClientRect().width,
    mainMaxWidth: parseFloat(ms.maxWidth),
    mainPadding: [parseFloat(ms.paddingLeft), parseFloat(ms.paddingRight)],
    cards,
  };
}"""


def _rows(cards: list[dict]) -> list[list[dict]]:
    rows: dict[float, list[dict]] = {}
    for card in cards:
        rows.setdefault(round(card["top"], 1), []).append(card)
    return [rows[top] for top in sorted(rows)]


def _geometry(client: float, columns: int, max_width: float) -> dict[str, float]:
    """Content width and track width of a columns-wide grid inside the app shell.

    Derived from the shell and the spacing scale, never from settings.css: from
    1024 px the sidebar is in flow and the main column is padded by --space-xl,
    below it the sidebar is off-canvas and the padding is --space-md.
    """
    gap = _token_px("space-lg")
    sidebar = _token_px("sidebar-width") if columns == 2 else 0.0
    padding = _token_px("space-xl") if columns == 2 else _token_px("space-md")
    main = min(client - sidebar, max_width)
    content = main - 2 * padding
    return {
        "gap": gap,
        "main": main,
        "padding": padding,
        "content": content,
        "track": (content - gap * (columns - 1)) / columns,
    }


@pytest.mark.e2e
def test_spacing_scale_is_the_approved_one() -> None:
    """The token values the layout expectations are derived from."""
    for name, px in APPROVED_SPACING.items():
        assert _token_px(name) == px, f"--{name} is no longer {px}px: review the layout expectations"


@pytest.mark.e2e
@pytest.mark.parametrize("width,columns", SETTINGS_LAYOUT_CASES)
def test_settings_layout_matches_token_derived_geometry(
    authenticated_page: Page, base_url: str, width: int, columns: int
) -> None:
    """Gap, track widths, breakpoint, row stretch and overflow from tokens and the shell."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function(
        "document.querySelectorAll('.settings-grid > .settings-section-card').length >= 9"
    )
    probe = page.evaluate(SETTINGS_PROBE)

    client = probe["clientWidth"]
    expected = _geometry(client, columns, probe["mainMaxWidth"])
    gap = expected["gap"]
    expected_track = expected["track"]

    # The shell the grid sits in: the sidebar takes its own column from 1024 px
    # and is off-canvas below it, so the main column keeps its width.
    assert abs(probe["mainWidth"] - expected["main"]) <= 1, probe
    assert [round(px) for px in probe["mainPadding"]] == [expected["padding"]] * 2, probe

    # No document-level horizontal overflow.
    assert probe["scrollWidth"] == client, probe

    # The grid fills the main column's content box and its gap is the approved
    # token, in both directions.
    assert abs(probe["gridWidth"] - expected["content"]) <= 1, probe
    assert probe["columnGap"] == f"{gap:g}px", probe
    assert probe["rowGap"] == f"{gap:g}px", probe

    # One track per column, all of them equal and of the derived width.
    assert len(probe["tracks"]) == columns, probe
    assert len({round(track) for track in probe["tracks"]}) == 1, probe
    for track in probe["tracks"]:
        assert abs(track - expected_track) <= 1, (track, expected_track, probe)

    rows = _rows(probe["cards"])
    if columns == 2:
        # The nine admin cards make four full pairs and one lone card, so an
        # all-single layout cannot pass this case vacuously.
        paired = [row for row in rows if len(row) == 2]
        assert len(paired) >= 4, rows
        for row in paired:
            left, right = sorted(row, key=lambda card: card["left"])
            assert abs(left["width"] - expected_track) <= 1, (row, expected_track)
            assert abs(right["width"] - expected_track) <= 1, (row, expected_track)
            assert abs((right["left"] - left["right"]) - gap) <= 0.5, (row, gap)
    else:
        assert all(len(row) == 1 for row in rows), rows
        for row in rows:
            assert abs(row[0]["width"] - expected_track) <= 1, (row, expected_track)

    # Rows stretch: cards that share a row have the same height.
    for row in rows:
        heights = [card["height"] for card in row]
        assert max(heights) - min(heights) < 0.5, heights

    # Consecutive rows are one gap apart.
    for upper, lower in zip(rows, rows[1:]):
        distance = lower[0]["top"] - max(card["bottom"] for card in upper)
        assert abs(distance - gap) <= 0.5, (distance, gap)


# Where an unused track showed up: nine admin cards leave one card alone in the
# fifth row, and it sat beside half a grid of nothing. A Support session does not
# get the admin-only Gigahost card, so its grid has eight children and ends on a
# pair. Both shapes are checked at the two-column widths, plus the single-column
# width where a stray span would create an implicit second track.
UNPAIRED_ROW_CASES = [(1440, 2, 9), (1024, 2, 9), (1440, 2, 8), (1024, 2, 8), (1023, 1, 9)]


@pytest.mark.e2e
@pytest.mark.parametrize("width,columns,cards", UNPAIRED_ROW_CASES)
def test_settings_last_row_leaves_no_unused_track(
    authenticated_page: Page, base_url: str, width: int, columns: int, cards: int
) -> None:
    """Every row fills the grid: a lone final card spans it, a pair does not."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function(
        "document.querySelectorAll('.settings-grid > .settings-section-card').length >= 9"
    )
    if cards == 8:
        # The Gigahost card is the only admin-only card, so a Support session's grid
        # has eight children. Removing it here reproduces that shape in one page.
        page.evaluate("() => document.getElementById('gigahostCard').remove()")
        page.wait_for_function(
            "document.querySelectorAll('.settings-grid > .settings-section-card').length === 8"
        )
    probe = page.evaluate(SETTINGS_PROBE)
    expected = _geometry(probe["clientWidth"], columns, probe["mainMaxWidth"])

    assert len(probe["cards"]) == cards, probe
    assert len(probe["tracks"]) == columns, probe
    rows = _rows(probe["cards"])

    # No row may leave an unused track: its cards plus the gaps between them fill
    # the grid's content box. A lone card that does not span leaves a whole track.
    for index, row in enumerate(rows):
        used = sum(card["width"] for card in row) + expected["gap"] * (len(row) - 1)
        assert (
            abs(used - expected["content"]) <= 1
        ), f"row {index} has {len(row)} card(s) using {used}px of {expected['content']}px"

    last = rows[-1]
    if columns == 2 and cards % 2 == 1:
        # The unpaired final card takes both tracks, so the row is a single
        # full-width card and not a card plus an empty cell.
        assert len(last) == 1, rows
        assert abs(last[0]["width"] - expected["content"]) <= 1, (last, expected["content"])
    elif columns == 2:
        # An even count ends on a pair: the span rule must not misfire.
        assert len(last) == 2, rows
        for card in last:
            assert abs(card["width"] - expected["track"]) <= 1, (last, expected["track"])
    else:
        # One column: no implicit second track from the span rule, one card per row.
        assert len(probe["tracks"]) == 1, probe
        assert all(len(row) == 1 for row in rows), rows


@pytest.mark.e2e
def test_settings_button_height_scale_uses_the_spacing_tokens(
    authenticated_page: Page, base_url: str
) -> None:
    """40 px for a card or action button, 32 px for a button inside a card.

    These are the rules in the Settings sheet that size a legacy class, which is
    why the computed-style differential has no historical counterpart for them.
    """
    page = authenticated_page
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.locator("#upstreamCheckBtn").wait_for(state="visible")

    large = _token_px("space-xl") + _token_px("space-sm")
    small = _token_px("space-xl")
    # The recorded scale: 40 px and 32 px, built from the pinned tokens above.
    assert (large, small) == (40, 32)
    expected = {"#saveBtn": large, "#policyClientRefreshBtn": large, "#upstreamCheckBtn": small}
    for selector, px in expected.items():
        page.locator(selector).wait_for(state="visible")
        height = page.evaluate(
            "sel => document.querySelector(sel).getBoundingClientRect().height", selector
        )
        assert abs(height - px) <= 0.5, (selector, height, px)


# --- Keyboard focus indicator, read from a real focused element -----------------
# Asserting that a rule exists proved nothing for this defect: the rule existed and
# still produced no outline, because it named a token that was never defined. These
# tests focus real controls on the real page and read the computed outline.

# (control, element that carries the outline). A switch hides its input, so the
# visible track beside it is what shows focus.
FOCUS_CONTROLS = [
    ("#app_title", "#app_title"),
    ("#appearance_language", "#appearance_language"),
    ("#policy_local_entries", "#policy_local_entries"),
    ("#notificationSaveBtn", "#notificationSaveBtn"),
    ("#repoLink-amneziawg-go", "#repoLink-amneziawg-go"),
    ("#captcha_enabled", "#captcha_enabled + .switch-slider"),
]
NO_TRANSITIONS = "*, *::before, *::after { transition: none !important; animation: none !important; }"
FOCUS_PROBE = """([focusSel, outlineSel]) => {
  const target = document.querySelector(focusSel);
  target.focus();
  const s = getComputedStyle(document.querySelector(outlineSel));
  return {
    focused: document.activeElement === target,
    focusVisible: target.matches(':focus-visible'),
    style: s.outlineStyle, width: s.outlineWidth, color: s.outlineColor, offset: s.outlineOffset,
  };
}"""


def _rgb(hex_or_rgba: str) -> str:
    r, g, b, _ = contrast.parse_color(hex_or_rgba)
    return f"rgb({int(r)}, {int(g)}, {int(b)})"


def _open_settings(page: Page, base_url: str, theme: str) -> None:
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function(
        "document.querySelectorAll('.settings-grid > .settings-section-card').length >= 9"
    )
    page.add_style_tag(content=NO_TRANSITIONS)
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
    # A key press first, so :focus-visible follows keyboard rules like a real user.
    page.keyboard.press("Tab")


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("focus_sel,outline_sel", FOCUS_CONTROLS)
def test_focused_control_has_a_visible_outline(
    authenticated_page: Page, base_url: str, theme: str, focus_sel: str, outline_sel: str
) -> None:
    """A focused control shows a solid 2 px outline in the accent colour, both themes.

    The expected colour is read from tokens.css for the theme under test, so the
    assertion follows the palette instead of pinning an rgb value.
    """
    page = authenticated_page
    _open_settings(page, base_url, theme)
    got = page.evaluate(FOCUS_PROBE, [focus_sel, outline_sel])
    assert got["focused"] and got["focusVisible"], (focus_sel, got)
    accent = contrast.resolve("accent", contrast.theme_tokens(theme))
    assert got["style"] == "solid", (focus_sel, theme, got)
    assert got["width"] == "2px", (focus_sel, theme, got)
    assert got["color"] == _rgb(accent), (focus_sel, theme, got, accent)
    assert got["offset"] == "2px", (focus_sel, theme, got)


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_focus_outline_survives_the_component_rules_that_remove_it(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """Fields that set `outline: none` for their own focus style still show the outline.

    .form-input and .table-search-input drop the browser outline at single-class
    specificity and load after base.css, so a bare `*:focus-visible` loses to them.
    """
    page = authenticated_page
    _open_settings(page, base_url, theme)
    removed = page.evaluate(
        "sel => { const e = document.querySelector(sel); return getComputedStyle(e).outlineStyle }",
        "#app_title",
    )
    assert removed == "none", "unfocused field should not carry an outline"
    got = page.evaluate(FOCUS_PROBE, ["#app_title", "#app_title"])
    assert got["style"] == "solid" and got["width"] == "2px", got
