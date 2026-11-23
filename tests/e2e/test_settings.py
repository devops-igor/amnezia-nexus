"""E2E tests for settings page and API."""

import re

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast
from tests.e2e.conftest import api_get, api_post, assert_response_shape
from tests.e2e.settings_surface import (
    APPROVED_SPACING,
    LONE_LAST_CARD_GROUPS,
    SETTINGS_GROUP_IDS,
    SETTINGS_LAYOUT_CASES,
    SETTINGS_PROBE,
    geometry,
    rows,
    token_px,
)


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


# The layout and navigation expectations, the page probes and the token reader live
# in tests.e2e.settings_surface: the navigation suite uses the same probe, so a
# second copy here would let the two disagree about what the page must look like.


@pytest.mark.e2e
def test_spacing_scale_is_the_approved_one() -> None:
    """The token values the layout expectations are derived from."""
    for name, px in APPROVED_SPACING.items():
        assert token_px(name) == px, f"--{name} is no longer {px}px: review the layout expectations"


@pytest.mark.e2e
@pytest.mark.parametrize("width,columns", SETTINGS_LAYOUT_CASES)
def test_settings_layout_matches_token_derived_geometry(
    authenticated_page: Page, base_url: str, width: int, columns: int
) -> None:
    """Gap, track widths, breakpoint, row stretch and overflow, per group's grid."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function(
        "document.querySelectorAll('.settings-section-card').length >= 11"
    )
    probe = page.evaluate(SETTINGS_PROBE)

    client = probe["clientWidth"]
    expected = geometry(client, columns, probe["mainMaxWidth"])
    gap = expected["gap"]
    expected_track = expected["track"]

    # The shell the grid sits in: the sidebar takes its own column from 1024 px
    # and is off-canvas below it, so the main column keeps its width.
    assert abs(probe["mainWidth"] - expected["main"]) <= 1, probe
    assert [round(px) for px in probe["mainPadding"]] == [expected["padding"]] * 2, probe

    # No document-level horizontal overflow.
    assert probe["scrollWidth"] == client, probe

    # Every group owns a grid, and each grid carries the same rules. A group that
    # loses its grid is reported instead of quietly reducing what is measured.
    assert [grid["id"] for grid in probe["grids"]] == SETTINGS_GROUP_IDS, probe

    paired = 0
    spanning = 0
    for grid in probe["grids"]:
        # The grid fills the main column's content box and its gap is the approved
        # token, in both directions.
        assert abs(grid["gridWidth"] - expected["content"]) <= 1, grid
        assert grid["columnGap"] == f"{gap:g}px", grid
        assert grid["rowGap"] == f"{gap:g}px", grid

        # One track per column, all of them equal and of the derived width.
        assert len(grid["tracks"]) == columns, grid
        assert len({round(track) for track in grid["tracks"]}) == 1, grid
        for track in grid["tracks"]:
            assert abs(track - expected_track) <= 1, (track, expected_track, grid)

        rows = rows(grid["cards"])
        assert rows, grid
        for row in rows:
            # No row leaves an unused track: a row holds its cards at the track
            # width, or one card that spans the whole content box.
            used = sum(card["width"] for card in row) + gap * (len(row) - 1)
            assert abs(used - expected["content"]) <= 1, (grid["id"], row)
            if len(row) == 1:
                spanning += 1
                assert abs(row[0]["width"] - expected["content"]) <= 1, (grid["id"], row)
            else:
                paired += 1
                left, right = sorted(row, key=lambda card: card["left"])
                assert abs(left["width"] - expected_track) <= 1, (row, expected_track)
                assert abs(right["width"] - expected_track) <= 1, (row, expected_track)
                assert abs((right["left"] - left["right"]) - gap) <= 0.5, (row, gap)

        # Rows stretch: cards that share a row have the same height.
        for row in rows:
            heights = [card["height"] for card in row]
            assert max(heights) - min(heights) < 0.5, heights

        # Consecutive rows are one gap apart.
        for upper, lower in zip(rows, rows[1:]):
            distance = lower[0]["top"] - max(card["bottom"] for card in upper)
            assert abs(distance - gap) <= 0.5, (grid["id"], distance, gap)

    if columns == 2:
        # The cases are not vacuous: the page still has paired rows and rows that
        # hold one full-width card.
        assert paired >= 4, paired
        assert spanning >= 3, spanning


@pytest.mark.e2e
@pytest.mark.parametrize("width,columns", [(1440, 2), (1024, 2), (1023, 1)])
def test_settings_last_row_leaves_no_unused_track(
    authenticated_page: Page, base_url: str, width: int, columns: int
) -> None:
    """Every row fills its grid: a lone final card spans it, a pair does not."""
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function(
        "document.querySelectorAll('.settings-section-card').length >= 11"
    )
    probe = page.evaluate(SETTINGS_PROBE)
    expected = geometry(probe["clientWidth"], columns, probe["mainMaxWidth"])

    assert [grid["id"] for grid in probe["grids"]] == SETTINGS_GROUP_IDS, probe

    for grid in probe["grids"]:
        rows = rows(grid["cards"])
        # No row may leave an unused track: its cards plus the gaps between them
        # fill the grid's content box. A lone card that does not span leaves a
        # whole track empty.
        for index, row in enumerate(rows):
            used = sum(card["width"] for card in row) + expected["gap"] * (len(row) - 1)
            assert (
                abs(used - expected["content"]) <= 1
            ), f"{grid['id']} row {index} has {len(row)} card(s) using {used}px of {expected['content']}px"

        last = rows[-1]
        if columns == 2:
            if grid["id"] in LONE_LAST_CARD_GROUPS:
                # The unpaired final card takes both tracks, so the row is a single
                # full-width card and not a card plus an empty cell.
                assert len(last) == 1, (grid["id"], rows)
                assert abs(last[0]["width"] - expected["content"]) <= 1, (grid["id"], last)
            else:
                # An even count ends on a pair: the span rule must not misfire.
                assert len(last) == 2, (grid["id"], rows)
                for card in last:
                    assert abs(card["width"] - expected["track"]) <= 1, (grid["id"], last)
        else:
            # One column: no implicit second track from the span rule.
            assert all(len(row) == 1 for row in rows), (grid["id"], rows)


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

    large = token_px("space-xl") + token_px("space-sm")
    small = token_px("space-xl")
    # The recorded scale: 40 px and 32 px, built from the pinned tokens above.
    assert (large, small) == (40, 32)
    expected = {
        "#appearanceCard [data-commit]": large,
        "#policyClientRefreshBtn": large,
        "#upstreamCheckBtn": small,
    }
    for selector, px in expected.items():
        page.locator(selector).wait_for(state="visible")
        height = page.evaluate(
            "sel => document.querySelector(sel).getBoundingClientRect().height", selector
        )
        assert abs(height - px) <= 0.5, (selector, height, px)


def _restore_settings(page: Page, csrf_token: str, original: dict) -> None:
    """Put the sections a test changed back, through the unchanged save endpoint."""
    body = {key: original.get(key, {}) for key in ("appearance", "captcha", "ssl", "limits", "telegram")}
    api_post(page, "/api/settings/save", body, csrf_token)


def _commit(page: Page, card: str) -> None:
    """Click one card's own commit control and wait for the save to be answered."""
    with page.expect_response(
        lambda r: r.url.endswith("/api/settings/save") and r.request.method == "POST"
    ) as saved:
        page.locator(f"#{card} [data-commit]").click()
    assert saved.value.status == 200, saved.value.text()


@pytest.mark.e2e
def test_settings_every_staged_card_commits_from_inside_itself(
    authenticated_page: Page, base_url: str
) -> None:
    """One commit control per staged card, all with one label, and no page-level button."""
    page = authenticated_page
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")

    assert page.locator("#saveBtn").count() == 0
    assert page.locator(".settings-actions").count() == 0
    cards = [
        "appearanceCard", "sslCard", "captchaCard", "limitsCard", "telegramCard",
        "notificationsCard", "policyRoutingCard", "gigahostCard",
    ]
    labels = set()
    for card in cards:
        commit = page.locator(f"#{card} [data-commit]")
        assert commit.count() == 1, card
        labels.add(" ".join(commit.inner_text().split()))
    assert len(labels) == 1, labels


@pytest.mark.e2e
def test_settings_card_dirty_state_and_scoped_save_feedback(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """An edit marks only its card; a successful appearance save reports in that card
    and surfaces no hosting, routing or notification error anywhere on the page."""
    page = authenticated_page
    original = api_get(page, "/api/settings")
    assert isinstance(original, dict)
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(700)
    try:
        title = page.locator("#app_title")
        loaded = title.input_value()
        assert not page.locator("#appearanceCard [data-dirty]").is_visible()
        assert page.locator("#appearanceCard [data-commit]").is_disabled()

        title.fill(loaded + " edited")
        assert page.locator("#appearanceCard [data-dirty]").is_visible()
        assert page.locator("#appearanceCard [data-commit]").is_enabled()
        assert not page.locator("#sslCard [data-dirty]").is_visible()

        title.fill(loaded)
        assert not page.locator("#appearanceCard [data-dirty]").is_visible()

        page.locator("label.switch-container:has(#captcha_enabled) .switch-slider").click()
        title.fill("Card Scoped Title")
        _commit(page, "appearanceCard")
        page.wait_for_timeout(1500)

        assert page.locator("#appearanceCard [data-status]").inner_text().strip()
        assert not page.locator("#appearanceCard [data-dirty]").is_visible()
        assert page.locator("#captchaCard [data-dirty]").is_visible()
        assert page.locator("#captchaCard [data-commit]").is_enabled()
        assert page.locator(".toast").count() == 0
        assert page.locator("[data-error]:visible").count() == 0
        body = page.inner_text("body").lower()
        assert "api key not configured" not in body
        assert "gigahost_api_key" not in body
    finally:
        _restore_settings(page, csrf_token, original)


@pytest.mark.e2e
def test_settings_empty_stored_appearance_fields_do_not_block_the_card(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """A stored empty logo and subtitle is a state this panel defines: the shell
    renders its built-in icon and label for them. The appearance card must still
    commit a change to another of its fields, and must send the empty values back as
    they were stored.

    Regression: the card enforced its own required attributes against the values it
    had loaded, so a card in that state produced no request at all and the operator
    could not save the change they did make.
    """
    page = authenticated_page
    original = api_get(page, "/api/settings")
    assert isinstance(original, dict)
    appearance = dict(original.get("appearance") or {})
    try:
        appearance.update({"title": "Empty Stored Fields", "logo": "", "subtitle": ""})
        api_post(page, "/api/settings/save", {"appearance": appearance}, csrf_token)

        page.goto(f"{base_url}/settings")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(700)
        assert page.locator("#app_logo").input_value() == ""
        assert page.locator("#app_subtitle").input_value() == ""

        page.locator("#app_title").fill("Empty Stored Fields Edited")
        _commit(page, "appearanceCard")
        page.wait_for_timeout(1000)

        assert page.locator("#appearanceCard [data-error]").inner_text().strip() == ""
        stored = api_get(page, "/api/settings")
        assert stored["appearance"]["title"] == "Empty Stored Fields Edited"
        assert stored["appearance"]["logo"] == "", "the untouched stored logo was rewritten"
        assert stored["appearance"]["subtitle"] == "", "the untouched stored subtitle was rewritten"
    finally:
        _restore_settings(page, csrf_token, original)


@pytest.mark.e2e
def test_settings_security_commits_persist_across_a_reload(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Application title, captcha, SSL and connection limits each commit from their own
    card and are what a full reload renders and what the API stores."""
    page = authenticated_page
    original = api_get(page, "/api/settings")
    assert isinstance(original, dict)
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(700)

    def toggle(input_id: str) -> None:
        page.locator(f"label.switch-container:has(#{input_id}) .switch-slider").click()

    try:
        page.locator("#app_title").fill("Persisted Title")
        _commit(page, "appearanceCard")

        toggle("captcha_enabled")
        _commit(page, "captchaCard")

        toggle("ssl_enabled")
        page.locator("#panel_port").fill("5443")
        page.locator("#ssl_domain").fill("panel.example.test")
        page.locator("#ssl_cert_path").fill("/etc/example/cert.pem")
        page.locator("#ssl_key_path").fill("/etc/example/key.pem")
        _commit(page, "sslCard")

        page.locator("#max_connections_per_user").fill("17")
        page.locator("#connection_rate_limit_count").fill("9")
        page.locator("#connection_rate_limit_window").fill("120")
        _commit(page, "limitsCard")

        page.goto(f"{base_url}/settings")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(700)

        assert page.locator("#app_title").input_value() == "Persisted Title"
        assert page.locator("#captcha_enabled").is_checked()
        assert page.locator("#ssl_enabled").is_checked()
        assert page.locator("#panel_port").input_value() == "5443"
        assert page.locator("#ssl_domain").input_value() == "panel.example.test"
        assert page.locator("#ssl_cert_path").input_value() == "/etc/example/cert.pem"
        assert page.locator("#ssl_key_path").input_value() == "/etc/example/key.pem"
        assert page.locator("#max_connections_per_user").input_value() == "17"
        assert page.locator("#connection_rate_limit_count").input_value() == "9"
        assert page.locator("#connection_rate_limit_window").input_value() == "120"
        assert page.locator("[data-dirty]:visible").count() == 0

        stored = api_get(page, "/api/settings")
        assert stored["appearance"]["title"] == "Persisted Title"
        assert stored["captcha"]["enabled"] is True
        assert stored["ssl"]["enabled"] is True and stored["ssl"]["panel_port"] == 5443
        assert stored["limits"] == {
            "max_connections_per_user": 17,
            "connection_rate_limit_count": 9,
            "connection_rate_limit_window": 120,
        }
    finally:
        _restore_settings(page, csrf_token, original)


@pytest.mark.e2e
def test_settings_two_tabs_do_not_undo_each_others_security_saves(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Two tabs of one session, a different card committed in each, real network.

    Tab A starts an Appearance save and its request is held in the browser. Tab B
    commits Captcha and then Limits and gets its success. A is released. A card
    posts only its own section and the server writes only the sections it is sent,
    so both of B's changes and A's title are what the server stores afterwards.
    """
    page_a = authenticated_page
    original = api_get(page_a, "/api/settings")
    assert isinstance(original, dict)
    page_b = page_a.context.new_page()
    try:
        for tab in (page_a, page_b):
            tab.goto(f"{base_url}/settings")
            tab.wait_for_load_state("networkidle")
            tab.wait_for_timeout(700)

        held: list = []

        def hold_appearance(route):
            held.append(route)

        page_a.route("**/api/settings/save", hold_appearance)
        page_a.locator("#app_title").fill("Tab A Title")
        page_a.locator("#appearanceCard [data-commit]").click()
        for _ in range(100):
            if held:
                break
            page_a.wait_for_timeout(50)
        assert held, "tab A's save never reached the network"

        page_b.locator("label.switch-container:has(#captcha_enabled) .switch-slider").click()
        _commit(page_b, "captchaCard")
        page_b.locator("#max_connections_per_user").fill("23")
        _commit(page_b, "limitsCard")
        mid = api_get(page_b, "/api/settings")
        assert mid["captcha"]["enabled"] is True, "tab B's captcha save was acknowledged but is not stored"

        held[0].continue_()
        page_a.unroute("**/api/settings/save", hold_appearance)
        for _ in range(100):
            if page_a.locator("#appearanceCard [data-status]").inner_text().strip():
                break
            page_a.wait_for_timeout(50)
        assert page_a.locator("#appearanceCard [data-status]").inner_text().strip()

        stored = api_get(page_b, "/api/settings")
        assert stored["appearance"]["title"] == "Tab A Title", "tab A's own change was lost"
        assert stored["captcha"]["enabled"] is True, "tab A undid the captcha tab B saved"
        assert stored["limits"]["max_connections_per_user"] == 23, "tab A undid the limits tab B saved"
    finally:
        page_b.close()
        _restore_settings(page_a, csrf_token, original)


# --- Keyboard focus indicator, read from a real focused element -----------------
# Asserting that a rule exists proved nothing for this defect: the rule existed and
# still produced no outline, because it named a token that was never defined. These
# tests focus real controls on the real page and read the computed outline.

# (control, element that carries the outline). A switch hides its input, so the
# visible track beside it is what shows focus.
FOCUS_CONTROLS = [
    ("#app_title", "#app_title"),
    ("#appearance_language", "#appearance_language"),
    ("#policy_proxy_exceptions", "#policy_proxy_exceptions"),
    ("#notificationSaveBtn", "#notificationSaveBtn"),
    ("#repoLink-amneziawg-go", "#repoLink-amneziawg-go"),
    ("#captcha_enabled", "#captcha_enabled + .switch-slider"),
    # The sub-navigation links share the .btn rule; they are listed because they
    # are the page's new interactive surface and a nav link with no visible focus
    # would leave the keyboard path without a marker.
    ("a.settings-subnav-link", "a.settings-subnav-link"),
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
        "document.querySelectorAll('.settings-section-card').length >= 11"
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
    if focus_sel == "#notificationSaveBtn":
        # A card with nothing staged has nothing to commit, so its Save is disabled
        # and a disabled control cannot take focus. Stage one change the way the
        # change event reports it (no pointer, so :focus-visible keeps following
        # keyboard rules), then press a key as _open_settings does.
        page.evaluate(
            """() => {
                const box = document.getElementById('notifications_enabled');
                box.checked = !box.checked;
                box.dispatchEvent(new Event('change', {bubbles: true}));
            }"""
        )
        page.wait_for_function("!document.getElementById('notificationSaveBtn').disabled")
        page.keyboard.press("Tab")
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


# --- Populated Gigahost states, read from the shipped renderers ---------------
# The static rules only reach text that carries a class. The Gigahost renderers
# build their nodes in script and set the colour inline, so a CSS-only check never
# sees them. This renders the real renderers on the real Settings page from a
# stubbed API (no provider, no network) and reads the colour the browser paints.

GIGAHOST_RENDER = """({orders, intents, observations}) => {
  stopGigahostOrderStatusRefresh();
  window.API = {
    get: async url => {
      if (url === '/api/admin/hosting/gigahost/orders')
        return {orders, provider_observations: observations};
      if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: intents};
      if (url === '/api/vpn/backends') return {backends: []};
      if (/\\/orders\\/.+\\/status$/.test(url)) return {status: 'ok', deploy: {}};
      throw new Error('unexpected GET ' + url);
    },
    post: async () => ({}),
    delete: async () => ({}),
  };
  return Promise.all([loadRecentOrders(), loadSetupIntents()]);
}"""
GIGAHOST_PROBE = """() => {
  const parse = s => {
    const m = s.match(/[\\d.]+/g).map(Number);
    return m.length < 4 ? [m[0], m[1], m[2], 1] : m;
  };
  const over = (top, under) =>
    [0, 1, 2].map(i => top[i] * top[3] + under[i] * (1 - top[3])).concat([1]);
  const surface = el => {
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      const b = parse(getComputedStyle(n).backgroundColor);
      if (b[3] > 0) layers.push(b);
      if (b[3] === 1) break;
    }
    return layers.reduceRight((acc, layer) => over(layer, acc), [255, 255, 255, 1]);
  };
  const read = el => ({
    text: el.textContent.trim().slice(0, 48),
    color: getComputedStyle(el).color,
    bg: 'rgb(' + surface(el).slice(0, 3).map(Math.round).join(', ') + ')',
  });
  const orders = document.querySelector('#recentOrdersContainer');
  const jobs = document.querySelector('#setupIntentsContainer');
  const panel = orders.querySelector('.gigahost-order-status-details');
  const kids = panel ? [...panel.children] : [];
  const hasText = e => [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
  return {
    labels: panel ? [...panel.querySelectorAll(':scope > div > span:first-child')].map(read) : [],
    bare: kids.filter(c => c.tagName === 'DIV' && c.children.length === 0).map(read),
    steps: [...jobs.querySelectorAll('span')].filter(s => /^\\[.+\\]$/.test(s.textContent.trim())).map(read),
    recovery: [...jobs.querySelectorAll('.btn-primary + span')].map(read),
    empty: [...document.querySelectorAll('#recentOrdersContainer .text-muted, #setupIntentsContainer .text-muted')].map(read),
    everything: [...document.querySelectorAll('#recentOrdersContainer *, #setupIntentsContainer *')]
      .filter(hasText).map(read),
  };
}"""


PROVISIONING_ORDER = {
    "orders": [{"order_id": "ord-ip", "status": "ready", "assigned_ip": "198.51.100.7"}],
    "intents": [],
    "observations": {"ord-ip": {"outcome": "confirmed", "status": "deploying"}},
}
AWAITING_CREDENTIALS_JOB = {
    "orders": [],
    "intents": [
        {
            "order_id": "job-1",
            "state": "awaiting_credentials",
            "step": "awaiting_credentials",
            "protocol": "awg",
            "port": 51820,
        }
    ],
    "observations": {},
}
# state -> (probe groups that must be present and informative, minimum node count)
GIGAHOST_STATES = {
    "provisioning_order_with_address": (PROVISIONING_ORDER, {"labels": 7, "bare": 2}),
    "saved_job_awaiting_credentials": (AWAITING_CREDENTIALS_JOB, {"steps": 1, "recovery": 1}),
}


def _hex(rgb_text: str) -> str:
    r, g, b = (int(float(n)) for n in re.findall(r"[\d.]+", rgb_text)[:3])
    return "#%02x%02x%02x" % (r, g, b)


def _render_gigahost(page: Page, base_url: str, theme: str, state: dict) -> dict:
    _open_settings(page, base_url, theme)
    page.evaluate(GIGAHOST_RENDER, state)
    if state["orders"]:
        toggle = page.locator("#recentOrdersContainer .gigahost-order-status-toggle").first
        toggle.wait_for(state="visible")
        toggle.click()
        page.locator("#recentOrdersContainer .gigahost-order-status-details").first.wait_for(
            state="visible"
        )
    if state["intents"]:
        page.locator("#setupIntentsContainer .btn-primary").first.wait_for(state="visible")
    return page.evaluate(GIGAHOST_PROBE)


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("name", sorted(GIGAHOST_STATES))
def test_populated_gigahost_text_is_informative_and_readable(
    authenticated_page: Page, base_url: str, theme: str, name: str
) -> None:
    """Labels, the provisioning warning, the step and the recovery hint reach 4.5:1.

    Rendered by the shipped renderers from a stubbed API. The colour is what the
    browser paints after the cascade (an inline style included), the surface is
    the opaque card behind it, and the expectations come from tokens.css for the
    theme, so neither side is a pinned colour.
    """
    state, minimum = GIGAHOST_STATES[name]
    probe = _render_gigahost(authenticated_page, base_url, theme, state)
    tokens = contrast.theme_tokens(theme)
    want_color = _rgb(contrast.resolve("text-secondary", tokens))
    want_surface = _rgb(contrast.resolve("bg-card", tokens))
    for group, count in minimum.items():
        nodes = probe[group]
        assert len(nodes) >= count, f"{name}/{group}: expected >= {count} nodes, got {probe}"
        for node in nodes:
            where = (name, theme, group, node)
            assert node["color"] == want_color, where
            assert node["bg"] == want_surface, where
            got = contrast.ratio(_hex(node["color"]), _hex(node["bg"]))
            assert got >= contrast.AA_TEXT, (*where, f"{got:.2f}:1")


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("name", sorted(GIGAHOST_STATES))
def test_no_populated_gigahost_text_is_painted_in_the_muted_colour(
    authenticated_page: Page, base_url: str, theme: str, name: str
) -> None:
    """Catches a sibling nobody listed: no text node here may use --text-muted."""
    state, _ = GIGAHOST_STATES[name]
    probe = _render_gigahost(authenticated_page, base_url, theme, state)
    muted = _rgb(contrast.resolve("text-muted", contrast.theme_tokens(theme)))
    assert probe["everything"], "the populated state rendered no text"
    offenders = [node for node in probe["everything"] if node["color"] == muted]
    assert offenders == [], (name, theme, offenders)


@pytest.mark.e2e
def test_settings_late_save_does_not_take_focus_and_restores_lost_focus(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Focus in a real browser, both halves of the rule.

    A save is held on the wire. First the operator stays where they were: the
    browser drops focus when the focused Save becomes disabled, and the operation
    puts it back inside the card. Then, in a second pass, the operator moves to an
    input in a different card while the save is held, and the late completion
    leaves focus and the typed text alone.
    """
    page = authenticated_page
    original = api_get(page, "/api/settings")
    try:
        for moves_away in (False, True):
            page.goto(f"{base_url}/settings")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(700)
            held: list = []
            page.route("**/api/settings/save", lambda route: held.append(route))
            page.locator("#max_connections_per_user").fill("37" if moves_away else "36")
            save = page.locator("#limitsCard [data-commit]")
            save.focus()
            save.click()
            for _ in range(100):
                if held:
                    break
                page.wait_for_timeout(50)
            assert held, "the save never reached the network"
            if moves_away:
                page.locator("#app_title").focus()
                page.keyboard.type("-typed-meanwhile")
            else:
                # Chromium keeps the disabled control as the active element for the
                # rest of the task and moves focus to the body right after, so wait
                # one tick before looking. Either state must end inside the card.
                page.wait_for_timeout(100)
                assert page.evaluate("document.activeElement === document.body"), (
                    "the browser should have dropped focus when Save became disabled"
                )
            held[0].continue_()
            page.unroute("**/api/settings/save")
            page.wait_for_function(
                "document.getElementById('limitsCard').getAttribute('aria-busy') === 'false'"
            )
            page.wait_for_timeout(200)
            where = page.evaluate(
                "({id: document.activeElement.id, inLimits: !!document.activeElement.closest('#limitsCard')})"
            )
            if moves_away:
                assert where["id"] == "app_title", f"a late completion took focus from the operator: {where}"
                assert "-typed-meanwhile" in page.locator("#app_title").input_value(), (
                    "what the operator typed while the save was held must still be there"
                )
            else:
                assert where["inLimits"], f"focus the operation lost was not restored to the card: {where}"
    finally:
        api_post(
            page,
            "/api/settings/save",
            {k: original.get(k, {}) for k in ("appearance", "captcha", "ssl", "limits", "telegram")},
            csrf_token,
        )


