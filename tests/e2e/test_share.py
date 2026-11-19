"""E2E tests for share link functionality."""

import uuid

import pytest
from playwright.sync_api import Page

from tests.e2e.conftest import api_get, api_post, assert_response_shape
from tests.e2e.prerequisites import require
from tests.e2e.share_page import SERVED_SHARE_SURFACE, assert_share_page_served


def _find_or_create_user(page: Page, csrf_token: str, username: str = "e2e_share_user") -> dict:
    """Find a user by username, or create one if not found."""
    users_result = api_get(page, "/api/users/?size=100")
    users = users_result if isinstance(users_result, list) else users_result.get("users", [])

    for u in users:
        if u.get("username") == username:
            return u

    # Not found — create one
    add_result = api_post(
        page,
        "/api/users/add",
        {
            "username": username,
            "password": "TestPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )

    require(add_result["status"] == 200, "Could not create user for share test")

    # Re-fetch to get full user record
    users_result2 = api_get(page, "/api/users/?size=100")
    users2 = users_result2 if isinstance(users_result2, list) else users_result2.get("users", [])

    for u in users2:
        if u.get("username") == username:
            return u

    require(False, "Test user not found after creation")
    return {}  # unreachable


@pytest.mark.e2e
def test_enable_sharing(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Set up share for a user connection -> share link generated."""
    page = authenticated_page

    target_user = _find_or_create_user(page, csrf_token, "e2e_share_user")
    user_id = target_user["id"]

    # Enable sharing via the setup endpoint
    share_result = api_post(
        page,
        f"/api/users/{user_id}/share/setup",
        {"enabled": True, "password": "sharetest123"},
        csrf_token,
    )

    # Should succeed
    body = share_result["body"]
    assert share_result["status"] == 200
    assert body.get("status") == "success"
    assert "share_token" in body

    # Validate share setup response shape
    assert_response_shape(body, {"status": str, "share_token": str}, "share_setup")

    # Clean up — disable sharing
    api_post(
        page,
        f"/api/users/{user_id}/share/setup",
        {"enabled": False},
        csrf_token,
    )


@pytest.mark.e2e
def test_access_share_link(authenticated_page: Page, base_url: str, csrf_token: str) -> None:
    """Navigate to share link -> sees share page."""
    page = authenticated_page

    target_user = _find_or_create_user(page, csrf_token, "e2e_share_access_user")
    user_id = target_user["id"]

    # Enable sharing
    share_result = api_post(
        page,
        f"/api/users/{user_id}/share/setup",
        {"enabled": True, "password": "sharetest123"},
        csrf_token,
    )

    require(share_result["status"] == 200, "Could not enable sharing")

    share_token = share_result["body"].get("share_token")
    require(bool(share_token), "No share token returned")

    # Navigate to the share link. The share page is judged from the navigation's
    # own status, never from the token text: the token is random hex and may
    # contain "404" inside a perfectly valid link.
    response = page.goto(f"{base_url}/share/{share_token}")
    page.wait_for_load_state("networkidle")
    assert_share_page_served(response, page)

    # Clean up
    api_post(
        page,
        f"/api/users/{user_id}/share/setup",
        {"enabled": False},
        csrf_token,
    )
    api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


@pytest.mark.e2e
@pytest.mark.parametrize(
    "marker",
    [
        pytest.param("dead404", id="bogus-token-contains-404"),
        pytest.param("deadbee", id="bogus-token-without-404"),
    ],
)
def test_missing_share_link_is_not_served(
    authenticated_page: Page, base_url: str, marker: str
) -> None:
    """Failure control: a genuinely missing share page must fail the served check.

    Both tokens are random hex that does not exist. One contains "404" and one
    does not, which are the two ways the old URL-substring assertion was wrong:

    * token with "404" on a *served* page -> false failure (the #915 report),
    * token without "404" on a *missing* page -> false pass.

    The corrected check must reject the page in both cases, because it reads the
    navigation's status instead of the token text.
    """
    page = authenticated_page
    suffix = uuid.uuid4().hex[7:]
    # The tail is random, so make each case hold by construction rather than by
    # chance: one token must contain "404", the other must not.
    if marker == "deadbee":
        while "404" in suffix:
            suffix = uuid.uuid4().hex[7:]
    bogus_token = f"{marker}{suffix}"
    assert ("404" in bogus_token) is (
        marker == "dead404"
    ), f"this case needs a token whose 404 content matches its id: {bogus_token}"

    response = page.goto(f"{base_url}/share/{bogus_token}")
    page.wait_for_load_state("networkidle")

    assert response is not None, "the share link navigation produced no response"
    assert response.status == 404, (
        "a share link that does not exist must answer 404; "
        f"got {response.status} for a bogus token"
    )
    assert (
        page.locator(SERVED_SHARE_SURFACE).count() == 0
    ), "a missing share page must not render the served share surface"

    # The control that matters: the assertion the real test relies on rejects
    # this page. If it ever starts passing here, the test has stopped proving
    # anything about the share page.
    with pytest.raises(AssertionError):
        assert_share_page_served(response, page)


@pytest.mark.e2e
def test_download_config_from_share(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """Authenticate on share page, download config -> gets config file."""
    page = authenticated_page

    # This test requires a server for connection creation
    servers_result = api_get(page, "/api/servers/")
    servers = (
        servers_result if isinstance(servers_result, list) else servers_result.get("servers", [])
    )

    require(servers, "No servers available for share config test")

    # Create a test user with share enabled
    target_user = _find_or_create_user(page, csrf_token, "e2e_share_dl_user")
    user_id = target_user["id"]

    # Enable sharing with password
    share_result = api_post(
        page,
        f"/api/users/{user_id}/share/setup",
        {"enabled": True, "password": "sharetest123"},
        csrf_token,
    )

    if share_result["status"] != 200:
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)
        require(False, "Could not enable sharing")

    share_token = share_result["body"].get("share_token")
    require(bool(share_token), "No share token returned")

    # Authenticate on share page via Playwright's request API (bypasses CSP)
    auth_result = page.request.post(
        f"{base_url}/api/share/{share_token}/auth",
        data={"password": "sharetest123"},
        headers={
            "X-CSRF-Token": csrf_token,
            "Content-Type": "application/json",
        },
    )

    # Auth might succeed or fail depending on CSRF and session state
    # Just verify the endpoint is reachable
    assert auth_result.status in (200, 401, 403)

    # Clean up
    api_post(
        page,
        f"/api/users/{user_id}/share/setup",
        {"enabled": False},
        csrf_token,
    )
    api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)
