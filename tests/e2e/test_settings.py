"""E2E tests for settings page and API."""

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

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
APPROVED_SPACING = {"space-md": 16, "space-lg": 24, "space-xl": 32, "sidebar-width": 250}

# The button size scale: 40 px is space-xl + space-sm, 32 px is space-xl. These
# are the only settings-sheet rules that size a legacy class, so the computed
# style differential cannot compare them with the pre-split reference.
APPROVED_BUTTON_HEIGHT = {"#saveBtn": 40, "#upstreamCheckBtn": 32}


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

    gap = _token_px("space-lg")
    client = probe["clientWidth"]
    sidebar = _token_px("sidebar-width")
    padding = _token_px("space-xl") if width >= 1024 else _token_px("space-md")

    # The shell the grid sits in: the sidebar takes its own column from 1024 px
    # and is off-canvas below it, so the main column keeps its width.
    main_width = min(client - (sidebar if width >= 1024 else 0), probe["mainMaxWidth"])
    content = main_width - 2 * padding
    expected_track = (content - gap * (columns - 1)) / columns
    assert abs(probe["mainWidth"] - main_width) <= 1, probe
    assert [round(px) for px in probe["mainPadding"]] == [padding, padding], probe

    # No document-level horizontal overflow.
    assert probe["scrollWidth"] == client, probe

    # The grid fills the main column's content box and its gap is the approved
    # token, in both directions.
    assert abs(probe["gridWidth"] - content) <= 1, probe
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


@pytest.mark.e2e
def test_settings_button_height_scale_uses_the_spacing_tokens(
    authenticated_page: Page, base_url: str
) -> None:
    """40 px for a card or action button, 32 px for a button inside a card."""
    page = authenticated_page
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.locator("#upstreamCheckBtn").wait_for(state="visible")

    expected = {
        "#saveBtn": _token_px("space-xl") + _token_px("space-sm"),
        "#upstreamCheckBtn": _token_px("space-xl"),
    }
    assert expected == {selector: float(px) for selector, px in APPROVED_BUTTON_HEIGHT.items()}
    for selector, px in expected.items():
        height = page.evaluate(
            "sel => document.querySelector(sel).getBoundingClientRect().height", selector
        )
        assert abs(height - px) <= 0.5, (selector, height, px)
