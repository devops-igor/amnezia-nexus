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
* CSRF: a mutating policy call without the token is rejected;
* the four readouts (#971): their healthy answers, the disclosures that keep
  every excluded network reachable, the removed traffic counters, and the
  in-page action that moves focus instead of only changing the URL;
* the same page at 1440 and 390 px in both themes, which is where a layout that
  "looks fine" in one width hides its overflow.

The suite is registered as ``hosted-panel`` in ``runner_map.toml``. It must not
acquire a DEV-only dependency: no SSH, no provisioning and no dataplane.
"""

import json
import random
import uuid
from typing import Any

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import api_get, api_post

POLICY_ENDPOINT = "/api/vpn/policy"
SYNC_ENDPOINT = "/api/vpn/policy/sync"
STATS_ENDPOINT = "/api/vpn/policy/stats"

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
def test_policy_sync_control_matches_what_the_operation_can_do(
    authenticated_page: Page, base_url: str, csrf_token: str
) -> None:
    """A sync cannot start a stopped runtime, so the form does not offer it.

    The backend refuses a sync while policy routing has no runtime, and this
    deployment runs with the policy off. The control is therefore disabled and
    explains why, the readouts keep reporting the runtime's own state, and the
    request itself is still refused with a reason — the disabled control is not a
    guess about a server that might have accepted it.
    """
    page = authenticated_page
    _open_settings(page, base_url)
    page.fill(EXCEPTIONS, "198.51.100.0/24")
    assert _save(page).status == 200

    expect(page.locator(SYNC_BTN)).to_be_disabled()
    expect(page.locator("#policySyncUnavailableHint")).to_be_visible()
    assert "Enable policy routing first" in page.locator("#policySyncUnavailableHint").inner_text()

    # The readout answers about the runtime snapshot; a refused request is not the
    # runtime's last_error, so the failure belongs to the request, not to this panel.
    expect(page.locator("#policySyncErrorAnswerHeadline")).to_have_text("No sync error reported")
    expect(page.locator("#policySyncNowBtn")).to_be_hidden()

    # Independent read of the same contract: the operation really is refused, and
    # says why, so the disabled control states a fact about the server.
    refused = page.request.post(
        f"{base_url}{SYNC_ENDPOINT}",
        data={},
        headers={"X-CSRF-Token": csrf_token, "Content-Type": "application/json"},
    )
    assert refused.status >= 400, (
        "the panel-only deployment must refuse a policy sync; " f"got {refused.status}"
    )
    assert refused.json().get("detail"), "the refused sync carried no detail"


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


# ── #971: the four policy readouts ───────────────────────────────────
#
# The page answers four questions — is split egress active, is the shipped address
# list current, can a CDN keep a destination on the proxy path, and did the latest
# rule sync fail. Each answer is a state, not a bare value, so these tests assert
# the state attribute and the sentence beside it, and they assert the disclosures
# still carry the detail the answer does not.


def _answers(page: Page) -> dict[str, str]:
    """Return the rendered state of each readout by its answer element id."""
    return page.evaluate(
        """() => {
            const ids = ['policyStatusAnswer', 'policyInventoryAnswer',
                         'policyCdnAnswer', 'policySyncErrorAnswer'];
            const out = {};
            for (const id of ids) {
                const node = document.getElementById(id);
                const headline = document.getElementById(id + 'Headline');
                out[id] = node ? node.getAttribute('data-state') + '|' + headline.textContent.trim() : 'missing';
            }
            return out;
        }"""
    )


@pytest.mark.e2e
def test_policy_readouts_answer_all_four_questions(
    authenticated_page: Page, base_url: str
) -> None:
    """Each readout reaches a real answer, and none of them is still loading.

    The deployment is panel-only, so what matters here is that the answer is
    derived from the server's snapshot rather than left at the loading
    placeholder or invented locally.
    """
    page = authenticated_page
    _open_settings(page, base_url)

    stored = api_get(page, POLICY_ENDPOINT)
    answers = _answers(page)
    for answer_id, rendered in answers.items():
        assert rendered != "missing", f"{answer_id} is not rendered at all"
        state, headline = rendered.split("|", 1)
        assert state != "loading", f"{answer_id} is still showing its loading state: {headline!r}"
        assert headline, f"{answer_id} renders an empty answer"
        assert "Loading" not in headline, f"{answer_id} still shows a loading sentence: {headline!r}"

    # P1 answers from the runtime flag, and this deployment reports the policy as
    # off: a management-only build reports no runtime at all, which has its own
    # answer. Either way it must not claim the saved switch as the runtime.
    status_state, status_headline = answers["policyStatusAnswer"].split("|", 1)
    if "status" in stored:
        assert status_headline == "Off", f"a disabled runtime must read Off, got {status_headline!r}"
    else:
        assert status_headline == "Status unavailable", (
            f"without a runtime snapshot the answer must say so, got {status_headline!r}"
        )
    assert status_state in ("info", "warning")

    # P4 reports the absence of a sync error as its own answer.
    sync_state, sync_headline = answers["policySyncErrorAnswer"].split("|", 1)
    assert sync_headline == "No sync error reported", (
        f"an untouched deployment reports no sync error, got {sync_headline!r}"
    )
    assert sync_state in ("info", "success")

    # An action the state does not offer must be absent from the layout, not only
    # marked hidden in the DOM: the panel's own display rules would otherwise win
    # over the hidden attribute and offer a retry beside a healthy answer.
    expect(page.locator("#policySyncNowBtn")).to_be_hidden()
    expect(page.locator("#policyCdnActionDiagnosis")).to_be_visible()
    if status_headline == "Off":
        expect(page.locator("#policyStatusActionSettings")).to_be_visible()
        expect(page.locator("#policyStatusActionError")).to_be_hidden()


@pytest.mark.e2e
def test_policy_cdn_disclosure_lists_every_excluded_network(
    authenticated_page: Page, base_url: str
) -> None:
    """The disclosure keeps the whole list, and the answer keeps the count.

    The count in the answer is a summary; an operator who needs to know whether one
    network is on the list has to be able to read every entry, in the order the
    server sent them. A surface that dropped an entry would still render a
    plausible count.
    """
    page = authenticated_page
    _open_settings(page, base_url)

    payload = api_get(page, POLICY_ENDPOINT)
    cdn = (payload.get("status") or {}).get("cdn") or {}
    entries = cdn.get("entries")
    assert entries, f"the panel-only deployment must expose the built-in CDN set: {cdn}"

    summary = page.locator("#policyCdnNetworksDetails > summary")
    if not page.locator("#policyCdnNetworksDetails").evaluate("el => el.open"):
        summary.click()
    expect(page.locator("#policyCdnEntries li")).to_have_count(len(entries))

    rendered = page.locator("#policyCdnEntries li").all_inner_texts()
    for index, entry in enumerate(entries):
        if entry.get("provider"):
            assert entry["provider"] in rendered[index], f"entry {index} lost its provider: {rendered[index]!r}"
        if entry.get("asn"):
            assert f"AS{entry['asn']}" in rendered[index], f"entry {index} lost its ASN: {rendered[index]!r}"

    expect(page.locator("#policyCdnAnswerHeadline")).to_have_text(
        f"{len(entries)} networks excluded from direct routing"
    )
    expect(page.locator("#policyCdnDisclosureLabel")).to_have_text("View excluded networks")


@pytest.mark.e2e
def test_policy_traffic_counters_are_not_fetched_or_rendered(
    authenticated_page: Page, base_url: str
) -> None:
    """The retired counters panel is gone from the page and from its reads."""
    page = authenticated_page
    _open_settings(page, base_url)

    for removed in ("#policyProxyBytes", "#policyDirectBytes", "#policyProxyDrops", "#policyDirectDrops"):
        assert page.locator(removed).count() == 0, f"the section still renders {removed}"

    requested: list[str] = []
    page.on("request", lambda request: requested.append(request.url))
    page.reload()
    page.wait_for_load_state("networkidle")
    page.wait_for_selector(CARD, state="visible")
    expect(page.locator("#policyStatusBadge")).to_have_attribute("data-enabled", "false")

    stats_reads = [url for url in requested if url.endswith(STATS_ENDPOINT)]
    assert stats_reads == [], f"the page still reads the retired counters: {stats_reads}"


@pytest.mark.e2e
def test_policy_in_page_action_moves_focus(
    authenticated_page: Page, base_url: str
) -> None:
    """An in-page action moves focus to its target heading, not only the URL.

    A fragment link alone leaves a keyboard operator where they were in browsers
    that do not focus a tabindex="-1" target, so the action would look inert while
    the address bar changed.
    """
    page = authenticated_page
    _open_settings(page, base_url)

    page.locator("#policyCdnActionDiagnosis").scroll_into_view_if_needed()
    page.locator("#policyCdnActionDiagnosis").click()
    focused = page.evaluate("() => document.activeElement ? document.activeElement.id : ''")
    assert focused == "policyClientTitle", f"focus landed on {focused!r}, not the diagnosis heading"
    expect(page.locator("#policyClientTitle")).to_be_in_viewport()


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("width", [1440, 390])
def test_policy_readouts_layout_and_state(
    authenticated_page: Page, base_url: str, width: int, theme: str
) -> None:
    """The readouts render at both widths in both themes without horizontal overflow.

    The answers, their actions and the network list are the parts that grow, so a
    laptop viewport that wraps them still leaves the 390 px one to check.
    """
    page = authenticated_page
    page.set_viewport_size({"width": width, "height": 900})
    _open_settings(page, base_url)
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)

    for panel in ("policyPanelStatus", "policyPanelInventory", "policyPanelCdn", "policyPanelSyncError"):
        expect(page.locator(f"#{panel}")).to_be_visible()

    answers = _answers(page)
    for answer_id, rendered in answers.items():
        state, headline = rendered.split("|", 1)
        assert state != "loading", f"{width}px/{theme}: {answer_id} never left its loading state"
        assert headline and "Loading" not in headline, f"{width}px/{theme}: {answer_id} = {headline!r}"

    overflow = page.evaluate(
        "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
    )
    assert overflow <= 1, f"{width}px/{theme}: the page overflows horizontally by {overflow}px"

    # The network list stays a single readable column, and a disclosure still opens
    # with the keyboard rather than only with the pointer.
    summary = page.locator("#policyCdnNetworksDetails > summary")
    summary.focus()
    page.keyboard.press("Enter")
    assert page.locator("#policyCdnNetworksDetails").evaluate("el => el.open"), (
        f"{width}px/{theme}: Enter did not open the excluded-network disclosure"
    )
    page.keyboard.press("Enter")
    assert not page.locator("#policyCdnNetworksDetails").evaluate("el => el.open"), (
        f"{width}px/{theme}: a second Enter did not close the disclosure again"
    )


# ── R3: action fit, target size and the RTL marker ───────────────────
#
# These are rendered measurements, so they live in the browser suite: a stylesheet
# assertion cannot tell whether a translated label fits the column a phone gives it.

ACTION_IDS = [
    "policyStatusActionError",
    "policyStatusActionSettings",
    "policyInventoryActionStatus",
    "policyInventoryActionOverride",
    "policyCdnActionDiagnosis",
    "policySyncNowBtn",
]


def _failure_payload() -> dict:
    """An active runtime whose last sync failed: every readout shows an action."""
    return {
        "enabled": True,
        "proxy_exceptions": [],
        "inventory_override": [],
        "sync_interval_seconds": 21600,
        "status": {
            "enabled": True,
            "ready": False,
            "cidr_count": 4,
            "sync_state": "error",
            "last_success": "2026-11-15T00:00:00Z",
            "last_error": "sync failed: backend unavailable",
            "cdn": {"source": "geodb.KnownCDNASNs", "entries": []},
            "inventory": {
                "source": "ipdeny",
                "retrieved_at": "2026-11-19",
                "prefix_count": 8664,
                "age_days": 1,
                "max_age_days": 180,
                "stale": False,
                "override_prefix_count": 2,
                "override_sha256": "deadbeefcafe1234",
            },
        },
    }


def _open_settings_with_failure(page: Page, base_url: str, lang: str) -> None:
    """Open the section in `lang` with a sync-failure snapshot served in the browser."""
    payload = json.dumps(_failure_payload())

    def fulfil(route: Any, *args: Any) -> None:
        if route.request.url.endswith(POLICY_ENDPOINT):
            route.fulfill(status=200, content_type="application/json", body=payload)
            return
        route.continue_()

    page.route(f"**{POLICY_ENDPOINT}", fulfil)
    page.goto(f"{base_url}/settings?lang={lang}")
    page.wait_for_selector(CARD, state="visible")
    page.wait_for_function(
        "() => document.getElementById('policySyncNowBtn') && "
        "!document.getElementById('policySyncErrorAnswer').getAttribute('data-state').includes('loading')"
    )
    expect(page.locator("#policySyncErrorAnswerHeadline")).to_have_text(
        {
            "en": "Rule sync failed",
            "ru": "Синхронизация правил не удалась",
            "fr": "Synchronisation des règles en échec",
            "zh": "规则同步失败",
            "fa": "همگام‌سازی قواعد ناموفق بود",
        }[lang]
    )


@pytest.mark.e2e
@pytest.mark.parametrize("lang", ["ru", "fr", "en", "zh", "fa"])
def test_policy_readout_actions_fit_a_phone_width(
    authenticated_page: Page, base_url: str, lang: str
) -> None:
    """Every readout action wraps inside its card inset and inside the viewport.

    The shared button sets `white-space: nowrap`, so a long localized label used to
    run past the answer card and, in Russian and French, past the viewport itself.
    Both bounds are measured here, because a control can fit the viewport and still
    leave its card.
    """
    page = authenticated_page
    page.set_viewport_size({"width": 390, "height": 900})
    _open_settings_with_failure(page, base_url, lang)

    bounds = page.evaluate(
        """(ids) => {
            const card = document.getElementById('policyRoutingCard').getBoundingClientRect();
            const doc = document.documentElement;
            const out = {overflow: doc.scrollWidth - doc.clientWidth, bad: []};
            for (const id of ids) {
                const el = document.getElementById(id);
                if (!el || el.hidden || el.closest('[hidden]')) continue;
                const r = el.getBoundingClientRect();
                const inset = el.closest('.policy-answer').getBoundingClientRect();
                const problems = [];
                if (r.width === 0 || r.height === 0) problems.push('not rendered');
                if (r.left < inset.left - 0.5 || r.right > inset.right + 0.5) {
                    problems.push('outside its answer inset');
                }
                if (r.left < card.left - 0.5 || r.right > card.right + 0.5) {
                    problems.push('outside the card');
                }
                if (r.left < -0.5 || r.right > doc.clientWidth + 0.5) {
                    problems.push('outside the viewport');
                }
                if (el.scrollWidth > el.clientWidth + 1) {
                    problems.push('label clipped inside the control');
                }
                if (problems.length) out.bad.push(id + ': ' + problems.join(', '));
            }
            return out;
        }""",
        ACTION_IDS,
    )
    assert bounds["overflow"] <= 1, (
        f"{lang} at 390 px scrolls {bounds['overflow']} px past the viewport"
    )
    assert not bounds["bad"], f"{lang} at 390 px: " + "; ".join(bounds["bad"])


@pytest.mark.e2e
def test_policy_retry_meets_the_target(authenticated_page: Page, base_url: str) -> None:
    """The retry is the same 44 px target as the links beside it."""
    page = authenticated_page
    page.set_viewport_size({"width": 390, "height": 900})
    _open_settings_with_failure(page, base_url, "en")
    assert page.locator("#policySyncNowBtn").evaluate("el => el.tagName") == "BUTTON", (
        "the retry must keep its button semantics"
    )
    height = page.evaluate(
        "() => document.getElementById('policySyncNowBtn').getBoundingClientRect().height"
    )
    assert height >= 44, f"the retry measures {height} px, below the 44 px target"


@pytest.mark.e2e
def test_policy_retry_does_not_move_under_reduced_motion(
    authenticated_page: Page, base_url: str
) -> None:
    """The sizing treatment carries the no-motion rule to the retry as well."""
    page = authenticated_page
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": 390, "height": 900})
    _open_settings_with_failure(page, base_url, "en")
    measured = page.evaluate(
        """() => {
            const el = document.getElementById('policySyncNowBtn');
            return {
                reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
                durations: getComputedStyle(el).transitionDuration.split(',')
                    .map(v => parseFloat(v) * (v.trim().endsWith('ms') ? 1 : 1000)),
                transform: getComputedStyle(el).transform
            };
        }"""
    )
    assert measured["reduced"], "the reduced-motion preference was not in effect"
    assert all(value == 0 for value in measured["durations"]), (
        f"the retry still transitions under reduced motion: {measured['durations']}"
    )
    assert measured["transform"] in ("none", "matrix(1, 0, 0, 1, 0, 0)"), (
        f"the retry is transformed at rest: {measured['transform']}"
    )


@pytest.mark.e2e
def test_policy_disclosure_marker_points_down_and_up_in_rtl(
    authenticated_page: Page, base_url: str
) -> None:
    """The marker's shape is direction-independent; only its placement is logical."""
    page = authenticated_page
    page.set_viewport_size({"width": 390, "height": 900})

    def marker(lang: str) -> dict:
        _open_settings_with_failure(page, base_url, lang)
        return page.evaluate(
            """() => {
                const details = document.getElementById('policyCdnNetworksDetails');
                const summary = details.querySelector('summary');
                const read = () => getComputedStyle(summary, '::after').transform;
                details.open = false;
                const closed = read();
                details.open = true;
                const open = read();
                details.open = false;
                const marker = getComputedStyle(summary, '::after');
                return {
                    closed, open,
                    direction: getComputedStyle(summary).direction,
                    // Which sides of the marker box carry the chevron's stroke. A
                    // logical pair mirrors here in RTL, which is the whole defect:
                    // the pair that is drawn decides which way the corner points.
                    right: marker.borderRightWidth,
                    left: marker.borderLeftWidth,
                    bottom: marker.borderBottomWidth,
                    markerStart: parseFloat(marker.marginInlineStart) || 0
                };
            }"""
        )

    ltr = marker("en")
    rtl = marker("fa")
    assert ltr["direction"] == "ltr" and rtl["direction"] == "rtl"
    assert ltr["closed"] != ltr["open"], "the marker does not change between states"
    for name, markers in (("LTR", ltr), ("RTL", rtl)):
        assert markers["right"] == "2px" and markers["bottom"] == "2px", (
            f"the {name} marker does not draw the right+bottom pair, so its corner "
            f"does not point down (right={markers['right']}, left={markers['left']}, "
            f"bottom={markers['bottom']})"
        )
        assert markers["left"] == "0px", (
            f"the {name} marker draws its left border, so the chevron is mirrored"
        )
    assert rtl["closed"] == ltr["closed"], (
        "the closed marker is drawn differently in RTL, so it points sideways"
    )
    assert rtl["open"] == ltr["open"], (
        "the open marker is drawn differently in RTL, so it points sideways"
    )
    assert rtl["markerStart"] > 0, (
        "the marker is not pushed to the inline end in RTL"
    )
