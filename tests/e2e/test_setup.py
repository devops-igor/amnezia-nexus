"""E2E tests for the initial setup wizard (/setup)."""

import pytest
from playwright.sync_api import Page
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from tests.e2e.conftest import _get_csrf_cookie

# On the DEV host (single-board ARM, SD card) a fresh panel answers
# POST /api/auth/setup in about 0.7s and the success banner follows the answer by
# about 0.04s (8 fresh panels measured). In the failing run (issue #911) the
# request was sent and no answer arrived within the old 10s wait on the banner.
# The two waits are now separate so a failure says which one stalled. The answer
# gets 60s, a judgement rather than a derived constant: no stall duration was
# measured, only that 10s was not enough once. The banner stays at 10s because it
# only follows an answer that has already arrived.
SETUP_RESPONSE_TIMEOUT_MS = 60000
SETUP_BANNER_TIMEOUT_MS = 10000


@pytest.mark.e2e
def test_setup_page_redirect_and_form(page: Page, base_url: str) -> None:
    """When no users exist, GET / redirects to /setup and shows setup form."""
    page.goto(base_url)
    page.wait_for_load_state("networkidle")
    assert "/setup" in page.url

    assert page.locator("input#username").is_visible()
    assert page.locator("input#password").is_visible()
    assert page.locator("input#confirmPassword").is_visible()
    assert page.locator("button#setupBtn").is_visible()


@pytest.mark.e2e
def test_setup_client_validation_password_mismatch(page: Page, base_url: str) -> None:
    """Password mismatch shows error in UI."""
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")

    page.fill("input#username", "admin")
    page.fill("input#password", "Password123!")
    page.fill("input#confirmPassword", "DifferentPass456!")
    page.click("button#setupBtn")

    error_el = page.locator("div#setupError")
    assert error_el.is_visible()


@pytest.mark.e2e
def test_setup_success(
    page: Page,
    base_url: str,
    admin_user: str,
    admin_pass: str,
    request_navigation_evidence,
) -> None:
    """Successful initial setup creates admin user and redirects.

    ``request_navigation_evidence`` only records allowlisted request and
    navigation facts; it changes no assertion or timing (issue #724).
    """
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")

    page.fill("input#username", admin_user)
    page.fill("input#password", admin_pass)
    page.fill("input#confirmPassword", admin_pass)

    # Click exactly once. Setup creates the first administrator, so submitting
    # again after a slow answer would get 409 and turn a slow success into a
    # false failure. The wait for the answer is therefore longer, never a retry.
    try:
        with page.expect_response(
            lambda response: response.url.endswith("/api/auth/setup"),
            timeout=SETUP_RESPONSE_TIMEOUT_MS,
        ) as response_info:
            page.click("button#setupBtn")
    except PlaywrightTimeoutError:
        pytest.fail(
            f"POST /api/auth/setup got no answer within {SETUP_RESPONSE_TIMEOUT_MS // 1000}s: "
            "the panel or its host stalled; the request was sent once and is not retried"
        )

    status = response_info.value.status
    assert status == 200, f"POST /api/auth/setup answered {status}, expected 200"

    # Success indicator should appear as soon as the answer has been handled
    success_el = page.locator("div#setupSuccess")
    try:
        page.wait_for_selector("div#setupSuccess.visible", timeout=SETUP_BANNER_TIMEOUT_MS)
    except PlaywrightTimeoutError:
        pytest.fail(
            "POST /api/auth/setup answered 200 but div#setupSuccess did not become visible "
            f"within {SETUP_BANNER_TIMEOUT_MS // 1000}s: the page did not handle the answer"
        )
    assert success_el.is_visible()


@pytest.mark.e2e
def test_setup_locked_after_completion(
    page: Page, base_url: str, admin_user: str, admin_pass: str
) -> None:
    """Once setup is done, /setup redirects to /login and API returns 403."""
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")
    assert "/login" in page.url or "/setup" not in page.url

    # Attempt API setup again
    csrf_value = _get_csrf_cookie(page)
    result = page.request.post(
        f"{base_url}/api/auth/setup",
        data={
            "username": admin_user,
            "password": admin_pass,
            "confirm_password": admin_pass,
        },
        headers={
            "X-CSRF-Token": csrf_value,
            "Content-Type": "application/json",
        },
    )
    assert result.status == 403
