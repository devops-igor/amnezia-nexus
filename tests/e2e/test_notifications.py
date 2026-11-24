"""E2E tests for the admin notification settings and history (epic #785 phase 1).

The panel-only hosted runner owns this file: the whole feature is served by the
panel binary and its temporary SQLite database. No Gotify server is contacted;
the test proves the card loads, the token is masked, mutations are blocked until
the read settles, and unsafe destinations are refused by the real API.
"""

import json

import pytest
from playwright.sync_api import Page, expect

from tests.e2e import contrast
from tests.e2e.conftest import api_get, api_post
from tests.e2e.rendered_pixels import dominant_colour


@pytest.mark.e2e
def test_notification_card_loads_for_admin(authenticated_page: Page, base_url: str) -> None:
    page = authenticated_page
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")

    card = page.locator("#notificationsCard")
    expect(card).to_be_visible()
    expect(page.locator("#notifications_enabled")).not_to_be_checked()
    # The stored record has loaded, so the test action is available. Save is not:
    # a card with nothing staged has nothing to commit.
    expect(page.locator("#notificationTestBtn")).to_be_enabled()
    expect(page.locator("#notificationSaveBtn")).to_be_disabled()
    # The switch is the visible control while delivery is off; the destination
    # fields appear once it is on.
    page.locator("label.switch-container:has(#notifications_enabled)").click()
    expect(page.locator("#notificationsCard [data-dirty]")).to_have_text("Unsaved changes")
    expect(page.locator("#notificationSaveBtn")).to_be_enabled()
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


# ===== Feedback ink =====
# #notificationTestResult is a `.form-hint` whose ink the controller assigns inline,
# so the stylesheet rule cannot govern it. This drives the real controller -- the
# failed read of load() and both outcomes of testConnection() with controlled
# responses -- then measures the colour the browser resolved for the populated
# message against the pixels of the card behind it, in both themes.
FEEDBACK_SELECTOR = "#notificationTestResult"
CONTROL_SELECTOR = "#notificationsCard .form-hint:not(#notificationTestResult)"

FEEDBACK_PROBE = """(sel) => {
  const el = document.querySelector(sel);
  if (!el) return null;
  const box = el.getBoundingClientRect();
  const card = el.closest('.card');
  return {
    text: (el.textContent || '').trim(),
    colour: getComputedStyle(el).color,
    x: box.left + window.scrollX,
    y: box.top + window.scrollY,
    w: box.width,
    h: box.height,
    card: card ? (card.id || 'card') : '',
    theme: document.documentElement.getAttribute('data-theme'),
  };
}"""

# (case, route glob, status, payload, controller call, expected message, expected ink)
FEEDBACK_CASES = [
    (
        "load-failure",
        "**/api/notifications/settings",
        500,
        {"error": "unavailable", "detail": "stub"},
        "() => window.NotificationSettingsUI.load()",
        "Could not load notification settings",
        "text-danger",
    ),
    (
        "test-sent",
        "**/api/notifications/test",
        200,
        {"status": "sent"},
        "() => window.NotificationSettingsUI.testConnection()",
        "accepted by Gotify",
        "text-success",
    ),
    (
        "test-not-delivered",
        "**/api/notifications/test",
        200,
        {"status": "failed", "reason": "upstream refused"},
        "() => window.NotificationSettingsUI.testConnection()",
        "was not delivered",
        "text-danger",
    ),
]
CASE_IDS = [case[0] for case in FEEDBACK_CASES]


def _hex(rgb_text: str) -> str:
    red, green, blue, _ = contrast.parse_color(rgb_text)
    return "#%02x%02x%02x" % (int(red), int(green), int(blue))


def _measure(page: Page, theme: str, selector: str) -> dict:
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
    page.wait_for_timeout(120)
    info = page.evaluate(FEEDBACK_PROBE, selector)
    assert info is not None, f"{selector} is not on the page"
    assert info["w"] > 0 and info["h"] > 0, f"{selector} is not rendered in the {theme} theme"
    shot = page.screenshot(full_page=True)
    backdrop, share = dominant_colour(shot, (info["x"], info["y"], info["w"], info["h"]))
    ink = _hex(info["colour"])
    return {
        **info,
        "ink": ink,
        "backdrop": backdrop,
        "share": share,
        "ratio": contrast.ratio(ink, backdrop),
    }


@pytest.mark.e2e
@pytest.mark.parametrize(
    "case,route_glob,status,payload,call,expected,token", FEEDBACK_CASES, ids=CASE_IDS
)
def test_notification_feedback_ink_clears_aa_in_both_themes(
    authenticated_page: Page,
    base_url: str,
    case: str,
    route_glob: str,
    status: int,
    payload: dict,
    call: str,
    expected: str,
    token: str,
) -> None:
    page = authenticated_page
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    # The stored record has loaded, so the controller will run its test branch.
    expect(page.locator("#notificationTestBtn")).to_be_enabled()

    def fulfil(route) -> None:
        route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

    page.route(route_glob, fulfil)
    try:
        page.evaluate(call)
        # Wait for the branch's own message, not for "Sending test…" on its way past.
        expect(page.locator(FEEDBACK_SELECTOR)).to_contain_text(expected, ignore_case=True)
    finally:
        page.unroute(route_glob)

    # Read both themes before judging either, so a failure names every measurement
    # instead of stopping at the first: the ink has to work in both, and the message
    # has to be the branch's own text in both.
    readings = {theme: _measure(page, theme, FEEDBACK_SELECTOR) for theme in ("light", "dark")}
    controls = {theme: _measure(page, theme, CONTROL_SELECTOR) for theme in ("light", "dark")}

    problems = []
    for theme, got in readings.items():
        if not got["text"]:
            problems.append(f"{case}/{theme}: the feedback line is empty")
            continue
        if expected.lower() not in got["text"].lower():
            problems.append(f"{case}/{theme}: expected {expected!r} in {got['text']!r}")
        # The property the issue promises: the message an operator has to read
        # clears 4.5:1 against the surface it is painted on.
        if got["ratio"] < contrast.AA_TEXT:
            problems.append(
                f"{case}/{theme}: {got['ink']} on {got['backdrop']} = "
                f"{got['ratio']:.2f}:1, below {contrast.AA_TEXT}:1"
            )
        # And the reason it now does: the ink is the theme's role, not a literal
        # that happens to be readable today.
        if got["ink"] != contrast.resolve(token, contrast.theme_tokens(theme)):
            problems.append(f"{case}/{theme}: effective ink {got['ink']} is not --{token}")
        # Positive control: the static hint in the same card is governed by the
        # stylesheet alone, so it keeps passing while the feedback ink is measured.
        control = controls[theme]
        if control["ratio"] < contrast.AA_TEXT:
            problems.append(
                f"{case}/{theme}: control hint {control['ink']} on {control['backdrop']} "
                f"= {control['ratio']:.2f}:1, below {contrast.AA_TEXT}:1"
            )

    assert not problems, f"{case}: the feedback ink is not readable as promised:\n" + "\n".join(
        problems
    )
