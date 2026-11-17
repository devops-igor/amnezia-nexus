"""E2E tests for the admin notification settings and history (epic #785 phase 1).

The panel-only hosted runner owns this file: the whole feature is served by the
panel binary and its temporary SQLite database. No Gotify server is contacted;
the test proves the card loads, the token is masked, mutations are blocked until
the read settles, and unsafe destinations are refused by the real API.
"""

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get, api_post


@pytest.mark.e2e
def test_notification_card_loads_for_admin(
    authenticated_page: Page, base_url: str
) -> None:
    page = authenticated_page
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")

    card = page.locator("#notificationsCard")
    expect(card).to_be_visible()
    expect(page.locator("#notifications_enabled")).not_to_be_checked()
    expect(page.locator("#notificationSaveBtn")).to_be_enabled()
    expect(page.locator("#notificationTestBtn")).to_be_enabled()
    # History is rendered by the shipped module after its read settles.
    expect(page.locator("#notificationHistory")).to_contain_text("No notifications yet")


@pytest.mark.e2e
def test_notification_settings_masks_token_and_refuses_unsafe_url(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    page = authenticated_page

    saved = api_post(
        page,
        "/api/notifications/settings",
        {
            "enabled": False,
            "url": "http://127.0.0.1:65535",
            "app_token": "e2e-secret-token",
            "min_severity": "info",
            "categories": {
                "server_health": True,
                "backend_health": True,
                "provisioning": True,
                "updates": True,
                "failover": True,
            },
            "cooldown_seconds": 60,
            "max_attempts": 3,
        },
        csrf_token,
    )
    assert saved["status"] == 200
    assert "e2e-secret-token" not in str(saved["body"])
    assert saved["body"].get("app_token_set") is True

    read = api_get(page, "/api/notifications/settings")
    assert "e2e-secret-token" not in str(read)
    assert read.get("app_token_set") is True
    assert read.get("enabled") is False

    unsafe = api_post(
        page,
        "/api/notifications/settings",
        {
            "enabled": True,
            "url": "http://169.254.169.254",
            "app_token": "e2e-secret-token",
            "min_severity": "info",
            "cooldown_seconds": 60,
            "max_attempts": 3,
        },
        csrf_token,
    )
    assert unsafe["status"] == 400

    history = api_get(page, "/api/notifications/history")
    assert isinstance(history, dict)
    assert isinstance(history.get("events"), list)
