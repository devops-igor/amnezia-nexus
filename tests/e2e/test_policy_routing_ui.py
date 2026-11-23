"""Browser smoke test for the admin policy routing section (#679).

The section is rendered by ``web/templates/settings_policy.html`` and driven by
``web/static/js/policy_routing.js``; the API is the #678 backend under
``/api/vpn/policy``. These tests exercise the real page against the real binary
started by ``scripts/run_e2e.sh`` — a panel-only deployment with no dataplane —
so the refusals below are the server's genuine answers, not simulated ones.

The section offers exactly the inputs that reach a packet decision: the master
switch, the IPv4 PROXY exception list, the inventory override and the refresh
interval. It has no source selection, so there is no preset to pick and no list
URL to fetch; the operator's own addresses go in the exception list.

Covered here:
* saving an exception-list entry and finding it after a reload;
* a sync the panel cannot perform, reported with the server's own wording;
* an enablement the server refuses, which must not stay visible as enabled;
* a list entry that is not an IPv4 rule, rejected inline with the typed value
  kept and nothing stored;
* the admin-only boundary: a support operator gets no section and a 403 API;
* CSRF: a mutating policy call without the token is rejected.

The suite is registered as ``hosted-panel`` in ``runner_map.toml``. It must not
acquire a DEV-only dependency: no SSH, no provisioning and no dataplane.
"""

import random
import uuid

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get, api_post

POLICY_ENDPOINT = "/api/vpn/policy"
SYNC_ENDPOINT = "/api/vpn/policy/sync"

CARD = "#policyRoutingCard"
ALERT = "#policyAlert"
SAVE_BTN = "#policySaveBtn"
SYNC_BTN = "#policySyncBtn"
ENABLE_TOGGLE = "#policy_enabled"
# The exception list is the operator's only entry surface for a decision that
# reaches a packet: every line is an IPv4 address or CIDR forced through PROXY
# ahead of the classifier. It replaced the custom-URL field, so it is what the
# list-shaped tests below drive.
EXCEPTIONS = "#policy_proxy_exceptions"


def _open_settings(page: Page, base_url: str) -> None:
    """Open /settings and wait until the controller has finished its first load."""
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_selector(CARD, state="visible")
    # The controller writes the enabled flag once it has read the record; the
    # badge is the visible half of that answer.
    expect(page.locator("#policyStatusBadge")).to_have_attribute("data-enabled", "false")


def _stage_change(page: Page) -> None:
    """Make sure the card has something staged: it commits only what changed.

    A card whose fields match the stored record is clean and its Save is
    disabled, so a test that re-selects what is already stored has to stage one
    real edit first. The entry is unique, so it is always a change.
    """
    if page.locator(SAVE_BTN).is_disabled():
        octets = (random.randint(1, 254) for _ in range(4))
        page.fill(EXCEPTIONS, "10.{}.{}.{}".format(*octets))
    expect(page.locator(SAVE_BTN)).to_be_enabled()


def _save(page: Page):
    """Click Save and return the policy PUT response that the click caused."""
    _stage_change(page)
    with page.expect_response(
        lambda r: r.url.endswith(POLICY_ENDPOINT) and r.request.method == "PUT"
    ) as info:
        page.click(SAVE_BTN)
    return info.value


def _alert_text(page: Page) -> str:
    alert = page.locator(ALERT)
    expect(alert).to_be_visible()
    return alert.inner_text()


def _set_policy_enabled(page: Page, enabled: bool) -> None:
    """Operate the master switch the way an operator does.

    The native checkbox is visually replaced by the .switch-slider markup, so it
    is not clickable itself; the surrounding label is the control.
    """
    toggle = page.locator(ENABLE_TOGGLE)
    if toggle.is_checked() == enabled:
        return
    page.locator(f"{CARD} label.switch-container").click()
    if enabled:
        expect(toggle).to_be_checked()
    else:
        expect(toggle).not_to_be_checked()


@pytest.mark.e2e
def test_policy_exception_entry_saves_and_survives_reload(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """An exception-list entry persists across a full page reload."""
    page = authenticated_page
    _open_settings(page, base_url)

    entry = "198.51.100.0/24"
    page.fill(EXCEPTIONS, entry)
    response = _save(page)
    assert response.status == 200, f"save failed: {response.status} {response.text()[:200]}"
    body = response.json()
    assert body.get("status") == "ok"
    # The exception list is what was saved, and the preset/custom-URL shape is gone
    # from the wire contract rather than merely from the markup.
    assert body.get("proxy_exceptions") == [entry]
    assert "preset" not in body and "custom_urls" not in body

    expect(page.locator(ALERT)).to_have_attribute("data-state", "success")

    page.reload()
    page.wait_for_load_state("networkidle")
    page.wait_for_selector(CARD, state="visible")
    # A refusal would restore the stored value; an acceptance rebases onto it, so
    # this is the entry the server kept, not the text left behind in the box.
    assert page.locator(EXCEPTIONS).input_value() == entry
    expect(page.locator(ENABLE_TOGGLE)).not_to_be_checked()
    expect(page.locator("#policyStatusBadge")).to_have_attribute("data-enabled", "false")

    # Independent read of the same contract through the API.
    stored = api_get(page, POLICY_ENDPOINT)
    assert stored.get("proxy_exceptions") == [entry]
    assert stored.get("enabled") is False
    # The mutating endpoint kept its CSRF requirement.
    unguarded = page.request.put(
        f"{base_url}{POLICY_ENDPOINT}",
        data={"enabled": False, "proxy_exceptions": [entry]},
        headers={"Content-Type": "application/json"},
    )
    assert unguarded.status == 403, "policy PUT without a CSRF token must be rejected"


@pytest.mark.e2e
def test_policy_sync_failure_is_reported_with_the_server_reason(
    authenticated_page: Page, base_url: str
) -> None:
    """A sync the panel cannot perform is reported truthfully, never as success."""
    page = authenticated_page
    _open_settings(page, base_url)
    page.fill(EXCEPTIONS, "198.51.100.0/24")
    assert _save(page).status == 200

    with page.expect_response(lambda r: r.url.endswith(SYNC_ENDPOINT)) as info:
        page.click(SYNC_BTN)
    response = info.value
    assert response.status >= 400, (
        "the panel-only deployment has no dataplane, so the sync must be refused; "
        f"got {response.status}"
    )
    detail = response.json().get("detail", "")
    assert detail, "the refused sync carried no detail to display"

    text = _alert_text(page)
    assert detail in text, f"the backend reason must be shown verbatim; banner={text!r}"
    expect(page.locator(ALERT)).to_have_attribute("data-state", "error")
    # The action returns to a usable state instead of staying stuck or claiming success.
    expect(page.locator(SYNC_BTN)).to_be_enabled()
    expect(page.locator("#policySyncSpinner")).to_have_class("spinner hidden")


@pytest.mark.e2e
def test_policy_rejected_enablement_is_not_shown_as_enabled(
    authenticated_page: Page, base_url: str
) -> None:
    """An enablement the server refuses is not shown as running, and is not lost."""
    page = authenticated_page
    _open_settings(page, base_url)
    page.fill(EXCEPTIONS, "198.51.100.0/24")
    assert _save(page).status == 200

    _set_policy_enabled(page, True)
    response = _save(page)
    assert response.status == 422, (
        "activation without a published snapshot and direct egress must be refused "
        f"with 422; got {response.status} {response.text()[:200]}"
    )
    detail = response.json().get("detail", "")
    assert detail, "the refused activation carried no detail to display"

    text = _alert_text(page)
    assert detail in text, f"the refusal must be shown verbatim; banner={text!r}"
    expect(page.locator(ALERT)).to_have_attribute("data-state", "error")

    # The decisive assertions. A refused enablement is never shown as running: the
    # status badge follows what the server runs, and the stored record is
    # unchanged. The switch itself keeps the operator's edit, and the card stays
    # marked unsaved, because the refused change was neither stored nor discarded.
    expect(page.locator("#policyStatusBadge")).to_have_attribute("data-enabled", "false")
    stored = api_get(page, POLICY_ENDPOINT)
    assert stored.get("enabled") is False
    expect(page.locator(ENABLE_TOGGLE)).to_be_checked()
    expect(page.locator(f"{CARD} [data-dirty]")).to_have_text("Unsaved changes")
    expect(page.locator(SAVE_BTN)).to_be_enabled()


@pytest.mark.e2e
def test_policy_exception_validation_error_is_inline(
    authenticated_page: Page, base_url: str
) -> None:
    """A line that is not an IPv4 rule is refused by the server and shown inline.

    The exception list replaced the custom-URL field, and it is an address set: the
    packet path matches it against the destination, so a domain line would be
    stored and never applied. The boundary therefore refuses it. A host name is
    used rather than a mistyped address because it is the exact input an operator
    migrating from the old domain list would paste.
    """
    page = authenticated_page
    _open_settings(page, base_url)

    rejected = "not-an-address.example"
    page.fill(EXCEPTIONS, rejected)
    response = _save(page)
    assert response.status == 400, (
        "a domain line in an IPv4 exception list must be refused server-side; "
        f"got {response.status} {response.text()[:200]}"
    )
    detail = response.json().get("detail", "")
    assert detail, "the validation failure carried no detail to display"

    text = _alert_text(page)
    assert detail in text, f"the validation detail must be shown verbatim; banner={text!r}"
    expect(page.locator(ALERT)).to_have_attribute("data-state", "error")
    # A refusal never stored the entry and never discards it either: the operator's
    # text stays in the box, the card stays marked unsaved, and the stored record
    # does not contain it.
    assert page.locator(EXCEPTIONS).input_value() == rejected
    expect(page.locator(f"{CARD} [data-dirty]")).to_have_text("Unsaved changes")
    stored = api_get(page, POLICY_ENDPOINT)
    assert rejected not in stored.get("proxy_exceptions", [])
    # The control the old test drove is gone, so it cannot be what was validated.
    assert page.locator("#policy_custom_urls").count() == 0


def _login_as(page: Page, base_url: str, username: str, password: str) -> None:
    """Log in on a fresh context using the same flow as the shared fixture."""
    page.goto(f"{base_url}/login")
    page.wait_for_load_state("networkidle")
    token = ""
    for cookie in page.context.cookies():
        if cookie["name"] == "csrftoken":
            token = cookie["value"]
            break
    assert token, "no CSRF cookie was issued by the login page"
    result = page.request.post(
        f"{base_url}/api/auth/login",
        data={"username": username, "password": password, "captcha": None},
        headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
    )
    assert result.status == 200, f"login as {username} failed: {result.status}"


@pytest.mark.e2e
def test_policy_section_and_api_are_admin_only(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """A support operator is refused /settings and the policy API with a 403."""
    admin_page = authenticated_page
    # Control: the administrator does get the section.
    _open_settings(admin_page, base_url)
    expect(admin_page.locator(CARD)).to_be_visible()

    username = f"e2e_policy_support_{uuid.uuid4().hex[:8]}"
    password = "SupportPass123!"
    created = api_post(
        admin_page,
        "/api/users/add",
        {"username": username, "password": password, "role": "support", "enabled": True},
        csrf_token,
    )
    assert created["status"] == 200, f"could not create the support operator: {created}"
    user_id = created["body"].get("user_id")
    assert user_id, f"user creation returned no id: {created}"

    context = admin_page.context.browser.new_context()
    try:
        support_page = context.new_page()
        _login_as(support_page, base_url, username, password)
        response = support_page.goto(f"{base_url}/settings")
        assert response is not None, "the settings request produced no response"
        assert (
            response.status == 403
        ), f"a support operator must be refused /settings; got {response.status}"
        assert (
            support_page.locator(CARD).count() == 0
        ), "the admin-only policy section must not render for a support operator"
        assert (
            support_page.locator('script[src="/static/js/policy_routing.js"]').count() == 0
        ), "the controller must not be loaded for a support operator"

        # The endpoint boundary is authoritative, not the hidden markup.
        forbidden = context.request.get(f"{base_url}{POLICY_ENDPOINT}")
        assert (
            forbidden.status == 403
        ), f"support must be refused the policy API; got {forbidden.status}"
    finally:
        context.close()
        api_post(admin_page, f"/api/users/{user_id}/delete", {}, csrf_token)
