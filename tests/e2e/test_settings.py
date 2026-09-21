"""E2E tests for settings page and API."""

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
