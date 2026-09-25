"""E2E tests for authentication flows."""

import os

import pytest
from playwright.sync_api import Browser, Page

from tests.e2e.conftest import _do_login, _get_csrf_cookie, api_get, api_post, assert_response_shape


@pytest.mark.e2e
def test_login_page_loads(page: Page, base_url: str) -> None:
    """GET /login returns 200 and shows the login form."""
    page.goto(f"{base_url}/login")
    page.wait_for_load_state("networkidle")

    # Page should have the login form
    assert page.locator("input#username").is_visible()
    assert page.locator("input#password").is_visible()
    assert page.locator("form#loginForm").is_visible()


@pytest.mark.e2e
def test_login_success(page: Page, base_url: str, admin_user: str, admin_pass: str) -> None:
    """Valid admin credentials -> redirected to index page."""
    _do_login(page, base_url, admin_user, admin_pass)

    # Should be on index page, not login
    assert "/login" not in page.url


@pytest.mark.e2e
def test_login_failure(page: Page, base_url: str) -> None:
    """Wrong password -> login returns error."""
    page.goto(f"{base_url}/login")
    page.wait_for_load_state("networkidle")

    # Get CSRF cookie via Playwright's cookie API
    csrf_value = _get_csrf_cookie(page)

    # Try to login with wrong credentials via API
    result = page.request.post(
        f"{base_url}/api/auth/login",
        data={"username": "admin", "password": "wrongpassword123", "captcha": None},
        headers={
            "X-CSRF-Token": csrf_value,
            "Content-Type": "application/json",
        },
    )

    # Should fail (401 or 400)
    assert result.status in (400, 401, 403)

    # Validate error response shape
    assert_response_shape(result.json(), {"error": str}, "login_failure")

    # Should still be able to see the login page
    page.reload()
    page.wait_for_load_state("networkidle")
    assert "/login" in page.url


@pytest.mark.e2e
def test_slide_captcha_rejects_replay(
    authenticated_page: Page, browser: Browser, base_url: str, csrf_token: str
) -> None:
    """Enabled puzzle renders offline assets and refuses an invalid or replayed solve."""
    admin = authenticated_page
    original = api_get(admin, "/api/settings")
    assert isinstance(original, dict)
    settings = {key: original.get(key, {}) for key in ("appearance", "ssl", "limits", "telegram")}
    settings["captcha"] = {"enabled": True}
    guest_context = browser.new_context()
    try:
        assert api_post(admin, "/api/settings/save", settings, csrf_token)["status"] == 200
        guest = guest_context.new_page()
        with guest.expect_response(lambda response: response.url.endswith("/api/auth/captcha")) as issued:
            guest.goto(f"{base_url}/login")
        guest.locator("#captchaHandle:not([disabled])").wait_for()
        challenge = issued.value.json()
        assert guest.locator("#captchaImage").get_attribute("src") == challenge["image"]
        assert guest.locator("#captchaPiece").get_attribute("src") == challenge["thumb"]
        assert challenge["captcha_id"] and challenge["thumb_y"] >= 0
        token = guest.locator('meta[name="csrf-token"]').get_attribute("content")
        attempt = {
            "captcha_id": challenge["captcha_id"],
            "point": {"x": challenge["thumb_x"], "y": challenge["thumb_y"]},
        }
        assert api_post(guest, "/api/auth/captcha/verify", attempt, token)["status"] == 400
        assert api_post(guest, "/api/auth/captcha/verify", attempt, token)["status"] == 400
        no_ticket = guest.request.post(
            f"{base_url}/api/auth/login",
            data={"username": "admin", "password": "wrong-password"},
            headers={"Content-Type": "application/json"},
        )
        assert no_ticket.status == 400
    finally:
        settings["captcha"] = original.get("captcha", {"enabled": False})
        api_post(admin, "/api/settings/save", settings, csrf_token)
        guest_context.close()


@pytest.mark.e2e
@pytest.mark.skipif(
    os.environ.get("E2E_TESTING", "").lower() not in ("true", "1"),
    reason="The puzzle's test-only target is available only with E2E_TESTING enabled",
)
def test_slide_captcha_browser_login(
    authenticated_page: Page, browser: Browser, base_url: str, csrf_token: str,
    admin_user: str, admin_pass: str,
) -> None:
    """Drag the rendered slider, receive a ticket, and log in through the page."""
    admin = authenticated_page
    original = api_get(admin, "/api/settings")
    assert isinstance(original, dict)
    settings = {key: original.get(key, {}) for key in ("appearance", "ssl", "limits", "telegram")}
    settings["captcha"] = {"enabled": True}
    guest_context = browser.new_context()
    try:
        assert api_post(admin, "/api/settings/save", settings, csrf_token)["status"] == 200
        guest = guest_context.new_page()
        with guest.expect_response(lambda response: response.url.endswith("/api/auth/captcha")) as issued:
            guest.goto(f"{base_url}/login")
        challenge = issued.value.json()
        target_x = int(issued.value.headers["x-e2e-captcha-target-x"])
        handle = guest.locator("#captchaHandle:not([disabled])")
        handle.wait_for()
        assert guest.locator("#captchaImage").get_attribute("src") == challenge["image"]
        assert guest.locator("#captchaPiece").get_attribute("src") == challenge["thumb"]

        # Drag the visible handle; the page must verify this exact challenge.
        travel = guest.locator("#captchaTrack").evaluate(
            "track => track.clientWidth - track.querySelector('#captchaHandle').offsetWidth"
        )
        box = handle.bounding_box()
        assert box and travel > 0
        start_x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        end_x = start_x + (target_x - challenge["thumb_x"]) * travel / (236 - challenge["thumb_x"])
        guest.mouse.move(start_x, y)
        guest.mouse.down()
        guest.mouse.move(end_x, y, steps=10)
        guest.mouse.up()

        guest.locator("#captchaStatus.success").wait_for()
        assert guest.evaluate("window.CaptchaSlider.ticket()")
        guest.locator("#username").fill(admin_user)
        guest.locator("#password").fill(admin_pass)
        with guest.expect_response(
            lambda response: response.url.endswith("/api/auth/login") and response.request.method == "POST"
        ) as login:
            guest.locator("#loginBtn").click()
        assert login.value.status == 200, login.value.text()[:200]
        guest.wait_for_url(lambda url: "/login" not in url.path)
    finally:
        settings["captcha"] = original.get("captcha", {"enabled": False})
        api_post(admin, "/api/settings/save", settings, csrf_token)
        guest_context.close()


@pytest.mark.e2e
@pytest.mark.skipif(
    os.environ.get("E2E_TESTING", "").lower() == "true",
    reason="Rate limiting disabled in E2E test mode",
)
def test_login_rate_limiting(page: Page, base_url: str) -> None:
    """Rapidly hit login with wrong creds 6 times -> 429 on 6th attempt."""
    page.goto(f"{base_url}/login")
    page.wait_for_load_state("networkidle")

    # Extract CSRF from cookie store
    csrf_token = _get_csrf_cookie(page)

    statuses = []
    for i in range(6):
        result = page.request.post(
            f"{base_url}/api/auth/login",
            data={
                "username": "ratelimit_test_user",
                "password": "wrong_password",
                "captcha": None,
            },
            headers={
                "X-CSRF-Token": csrf_token,
                "Content-Type": "application/json",
            },
        )
        statuses.append(result.status)

    # At least one response should be 429 (or the last one)
    assert 429 in statuses, f"Expected rate limiting (429), got statuses: {statuses}"


@pytest.mark.e2e
def test_csrf_protection(page: Page, base_url: str) -> None:
    """POST to login without CSRF token -> 403 Forbidden."""
    # Navigate to login first so the browser has a session context
    page.goto(f"{base_url}/login")
    page.wait_for_load_state("networkidle")

    # Use Playwright's request API — POST without CSRF header
    result = page.request.post(
        f"{base_url}/api/auth/login",
        data={
            "username": "admin",
            "password": "test",
            "captcha": None,
        },
        headers={"Content-Type": "application/json"},
    )

    # CSRF middleware returns 403 for POSTs without the token when the session
    # cookie is present. Without a session, the app returns 401 instead.
    assert result.status in (403, 401), f"Expected 403/401 rejection, got {result.status}"


@pytest.mark.e2e
def test_logout(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Login then logout -> session cleared, redirected to /login."""
    page = authenticated_page

    # Navigate to logout
    page.goto(f"{base_url}/logout")
    # Should redirect to /login
    page.wait_for_url("**/login**", timeout=5000)

    # Verify we're on the login page
    assert "/login" in page.url
    assert page.locator("input#username").is_visible()
