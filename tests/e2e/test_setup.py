"""E2E tests for the initial setup wizard (/setup)."""

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import _get_csrf_cookie


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
def test_setup_success(page: Page, base_url: str, admin_user: str, admin_pass: str) -> None:
    """Successful initial setup creates admin user and redirects."""
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")

    page.fill("input#username", admin_user)
    page.fill("input#password", admin_pass)
    page.fill("input#confirmPassword", admin_pass)
    page.click("button#setupBtn")

    # Success indicator should appear
    success_el = page.locator("div#setupSuccess")
    page.wait_for_selector("div#setupSuccess.visible", timeout=10000)
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
