"""Browser cases for the Settings confirmations and the badge contrast."""

import json

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast
# The page probe and the hex reader are the settings suite's own, so the two files
# cannot disagree about how the page is opened or how a colour is converted.
from tests.e2e.test_settings import _hex, _open_settings, _rgb


# --- Deploy VPS confirms before the order leaves the page --------------------
# The design review found the first press posting an order: no confirmation, no
# statement of what was being bought. These run the ordering form against a local
# test catalog, so no provider is contacted, and watch the order request itself
# rather than the confirmation's appearance.

DEPLOY_TEST_CATALOG = {
    "plans": [
        {
            "product_id": 101,
            "price_id": 555,
            "name": "Cloud 2",
            "type": "vm",
            "built_to_order": False,
            "in_stock": True,
            "currency": "NOK",
            "hourly_rate_nok": 0.14375,
            "monthly_ceiling_nok": 90,
            "regions": [
                {"id": 1, "name": "Norway", "country": "NO", "available": True, "in_stock": True}
            ],
            "datacenters": [
                {
                    "id": 1,
                    "name": "DC1",
                    "region_id": 1,
                    "location": "Sandefjord",
                    "country": "NO",
                    "in_stock": True,
                }
            ],
            "os_options": [{"os_id": 12, "os_name": "Debian 12"}],
        }
    ]
}

DEPLOY_SELECTIONS = (
    "() => ['deployPlanSelect', 'deployRegionSelect', 'deployOSSelect', 'deployPlacementSelect']"
    ".map(id => document.getElementById(id).value)"
)


def _deploy_form(page: Page, base_url: str, orders: list) -> None:
    """Open Settings with a local test catalog, recording the order request."""
    page.route(
        "**/api/admin/hosting/gigahost/catalog**",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(DEPLOY_TEST_CATALOG)
        ),
    )

    def record_order(route):
        orders.append(route.request.post_data_json)
        route.fulfill(
            status=200, content_type="application/json", body='{"message": "Order placed"}'
        )

    page.route("**/api/admin/hosting/gigahost/order", record_order)
    _open_settings(page, base_url, "dark")
    page.wait_for_function(
        "() => { const s = document.getElementById('deployPlanSelect');"
        " return !!s && s.options.length > 0 && !s.disabled; }"
    )
    page.select_option("#deployRegionSelect", "1")
    page.select_option("#deployOSSelect", "12")
    page.wait_for_function("() => !document.getElementById('btnDeployVPS').disabled")


@pytest.mark.e2e
def test_deploy_vps_confirms_plan_region_image_and_cost(
    authenticated_page: Page, base_url: str
) -> None:
    """The summary names what is being bought, and cancelling sends nothing."""
    page = authenticated_page
    orders: list = []
    try:
        _deploy_form(page, base_url, orders)

        page.locator("#btnDeployVPS").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")
        summary = page.locator("#nexusConfirmBody").inner_text()
        for fact in ("Cloud 2", "Norway (NO)", "Debian 12", "0.14375 NOK/hr", "max 90 NOK/mo"):
            assert fact in summary, (fact, summary)
        assert page.locator("#nexusConfirmTitle").inner_text().strip()
        assert page.locator("#nexusConfirmOkBtn").inner_text().strip()
        assert orders == [], "the order left the page before the operator confirmed"

        chosen = page.evaluate(DEPLOY_SELECTIONS)
        page.locator("#nexusConfirmCancelBtn").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="detached")
        assert orders == [], "cancelling sent an order"
        assert page.evaluate(DEPLOY_SELECTIONS) == chosen, "cancelling changed the form"
        assert page.locator("#btnDeployVPS").is_enabled(), "cancelling left the form unusable"

        # Confirming sends the order, once, with the selection the summary named.
        page.locator("#btnDeployVPS").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")
        assert page.locator("#nexusConfirmBody").inner_text() == summary
        page.locator("#nexusConfirmOkBtn").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="detached")
        for _ in range(100):
            if orders:
                break
            page.wait_for_timeout(50)
        assert len(orders) == 1, orders
        payload = orders[0]
        assert (payload["pid"], payload["price_id"]) == (101, 555), payload
        assert (payload["region_id"], payload["os_id"]) == (1, 12), payload
        assert payload["hourly_price_nok"] == 0.14375, payload

        # Two presses in one tick must not become two orders.
        page.wait_for_function("() => !document.getElementById('btnDeployVPS').disabled")
        orders.clear()
        page.evaluate(
            "() => { const b = document.getElementById('btnDeployVPS'); b.click(); b.click(); }"
        )
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")
        page.locator("#nexusConfirmOkBtn").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="detached")
        for _ in range(100):
            if orders:
                break
            page.wait_for_timeout(50)
        assert len(orders) == 1, f"a second press became a second order: {orders}"
    finally:
        page.unroute("**/api/admin/hosting/gigahost/catalog**")
        page.unroute("**/api/admin/hosting/gigahost/order")


# --- Badge contrast and the destructive confirmation ------------------------
# Both are visual outcomes of the design review, so both are read from what the
# browser paints rather than from the stylesheet text.

BADGE_PROBE = """() => {
  const parse = s => {
    const m = (s.match(/[\\d.]+/g) || []).map(Number);
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
  return [...document.querySelectorAll('.badge')].map(el => {
    const color = parse(getComputedStyle(el).color);
    const bg = surface(el);
    return {
      id: el.id,
      cls: el.className,
      text: el.textContent.trim().slice(0, 32),
      color: 'rgb(' + color.slice(0, 3).map(Math.round).join(', ') + ')',
      bg: 'rgb(' + bg.slice(0, 3).map(Math.round).join(', ') + ')',
    };
  });
}"""


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_settings_badges_meet_aa_in_both_themes(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """Every badge's painted text reaches 4.5:1 on the surface behind it.

    The version badge and the update badges are named explicitly because they are
    the two the review measured; the rest are checked so a sibling cannot keep the
    old colour. Colour and surface are both read from the live cascade.
    """
    page = authenticated_page
    _open_settings(page, base_url, theme)
    page.wait_for_function(
        "() => [...document.querySelectorAll('#upstreamCard .badge')]"
        ".every(b => b.textContent.trim() !== '...')",
        timeout=30000,
    )
    badges = page.evaluate(BADGE_PROBE)
    assert badges, "the settings page rendered no badges"

    version = [b for b in badges if "badge-info" in b["cls"]]
    updates = [b for b in badges if "badge-success" in b["cls"]]
    assert version, "the version badge is missing"
    assert updates, "the update badges are missing"

    for badge in badges:
        ratio = contrast.ratio(_hex(badge["color"]), _hex(badge["bg"]))
        assert ratio >= contrast.AA_TEXT, (theme, badge, f"{ratio:.2f}:1")


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_restore_confirmation_is_destructive_and_escape_cancels(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """The restore confirmation carries the danger treatment, and Escape cancels.

    Choosing a backup file opens the confirmation; nothing is uploaded while it is
    open, Escape closes it and returns focus to the control that opened it, and no
    restore request is sent.
    """
    page = authenticated_page
    posts: list = []
    try:
        page.route("**/api/settings/backup/restore", lambda route: posts.append(route))
        _open_settings(page, base_url, theme)
        page.locator("#restoreBtn").focus()
        page.set_input_files(
            "#backupFile", {"name": "backup.json", "mimeType": "application/json", "buffer": b"{}"}
        )
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")

        ok_class = page.locator("#nexusConfirmOkBtn").get_attribute("class") or ""
        assert "btn-danger" in ok_class.split(), ok_class
        assert "btn-warning" not in ok_class.split(), ok_class
        assert page.locator("#nexusConfirmOkBtn").inner_text().strip()
        want_danger = _rgb(contrast.resolve("danger", contrast.theme_tokens(theme)))
        painted = page.evaluate(
            "() => getComputedStyle(document.getElementById('nexusConfirmOkBtn')).color"
        )
        assert painted == want_danger, (painted, want_danger)
        assert posts == [], "the restore request left the page before it was confirmed"

        page.keyboard.press("Escape")
        page.locator("#nexusConfirmModal.active").wait_for(state="detached")
        assert posts == [], "Escape sent a restore request"
        assert page.evaluate("() => document.activeElement.id") == "restoreBtn", (
            "Escape did not return focus to the restore control"
        )
        assert page.evaluate("() => document.getElementById('backupFile').value") == "", (
            "cancelling left the chosen file selected"
        )
    finally:
        page.unroute("**/api/settings/backup/restore")
