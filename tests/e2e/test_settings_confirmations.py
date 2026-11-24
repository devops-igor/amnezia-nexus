"""Browser cases for the Settings confirmations and the badge contrast."""

import json

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast
from tests.e2e.conftest import api_post
# The page probe and the hex reader are the settings suite's own, so the two files
# cannot disagree about how the page is opened or how a colour is converted.
from tests.e2e.test_settings import NO_TRANSITIONS, _hex, _open_settings


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
    page.select_option("#deployPlacementSelect", "1")
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
        for fact in (
            "Cloud 2",
            "Norway (NO)",
            "DC1 - Sandefjord",
            "Debian 12",
            "0.14375 NOK/hr",
            "max 90 NOK/mo",
        ):
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


# --- The narrow opening position ---------------------------------------------
# At 390px the shell's fixed top bar and the bottom-docked dialog leave a strip in
# which the confirmed controls have to be visible, and the price has to be
# rendered in full inside the dialog.

NARROW_PROBE = """() => {
  const box = el => {
    const r = el.getBoundingClientRect();
    return {x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width),
            h: Math.round(r.height), bottom: Math.round(r.bottom), right: Math.round(r.right)};
  };
  const inter = (a, b) => {
    const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
    const h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
    return w > 0 && h > 0;
  };
  const bar = document.querySelector('.mobile-topbar');
  const backdrop = document.getElementById('nexusConfirmModal');
  const dialog = backdrop.querySelector('.modal');
  const body = document.getElementById('nexusConfirmBody');
  const barBox = bar ? box(bar) : null;
  const dialogBox = box(dialog);
  const fields = ['deployPlanSelect', 'deployRegionSelect', 'deployPlacementSelect', 'deployOSSelect']
    .map(id => document.getElementById(id))
    .filter(Boolean)
    .map(el => ({id: el.id, box: box(el)}));
  // The price is the text after the line break: its own rendered box, so a wrap is
  // distinguishable from a clip.
  const node = body.firstChild;
  const raw = node && node.nodeValue ? node.nodeValue : '';
  const at = raw.indexOf(String.fromCharCode(10));
  let price = null;
  if (at !== -1) {
    const range = document.createRange();
    range.setStart(node, at + 1);
    range.setEnd(node, raw.length);
    const r = range.getBoundingClientRect();
    const lh = parseFloat(getComputedStyle(body).lineHeight) || 0;
    price = {
      text: raw.slice(at + 1),
      x: Math.round(r.x), w: Math.round(r.width), right: Math.round(r.right),
      lines: lh ? Math.max(1, Math.round(r.height / lh)) : 0,
      bodyRight: Math.round(body.getBoundingClientRect().right),
    };
  }
  return {
    confirmKind: backdrop.getAttribute('data-confirm-kind'),
    viewport: {w: window.innerWidth, h: window.innerHeight},
    topbar: barBox,
    dialog: dialogBox,
    fields,
    underBar: barBox ? fields.filter(f => inter(f.box, barBox)).map(f => f.id) : [],
    underDialog: fields.filter(f => inter(f.box, dialogBox)).map(f => f.id),
    price,
    body: {clientWidth: body.clientWidth, scrollWidth: body.scrollWidth,
           clientHeight: body.clientHeight, scrollHeight: body.scrollHeight,
           text: body.textContent},
  };
}"""


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_deploy_confirmation_keeps_the_confirmed_controls_clear_at_narrow_width(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """Opening from the narrow position leaves the plan and its price readable.

    The form is scrolled so the plan field sits at the very top, which is the
    position where the shell's top bar used to clip it. Opening the confirmation
    must leave all four selectors between that bar and the dialog, and the price
    must render in full inside the dialog, wrapping instead of being cut.
    """
    page = authenticated_page
    orders: list = []
    try:
        _deploy_form(page, base_url, orders)
        page.set_viewport_size({"width": 390, "height": 844})
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.locator("#deployPlanSelect").evaluate(
            """el => {
                // Deterministic positioning for the test: the page scrolls smoothly,
                // which would still be animating when the dialog opens.
                const root = document.documentElement;
                const previous = root.style.scrollBehavior;
                root.style.scrollBehavior = 'auto';
                el.scrollIntoView(true);
                root.style.scrollBehavior = previous;
            }"""
        )
        page.wait_for_timeout(150)

        page.locator("#btnDeployVPS").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('nexusConfirmModal')).opacity === '1'"
        )
        probe = page.evaluate(NARROW_PROBE)

        assert probe["confirmKind"] == "order", probe["confirmKind"]
        assert probe["topbar"], "the mobile top bar is missing"
        assert len(probe["fields"]) == 4, probe["fields"]
        assert probe["underBar"] == [], (probe["topbar"], probe["fields"])
        assert probe["underDialog"] == [], (probe["dialog"], probe["fields"])

        price = probe["price"]
        assert price, probe["body"]
        assert "max 90 NOK/mo" in price["text"], price
        assert price["right"] <= price["bodyRight"] + 1, (price, probe["body"])
        assert price["lines"] >= 1, price
        assert probe["body"]["scrollWidth"] <= probe["body"]["clientWidth"] + 1, probe["body"]
        assert orders == [], "opening the confirmation sent an order"
    finally:
        page.unroute("**/api/admin/hosting/gigahost/catalog**")
        page.unroute("**/api/admin/hosting/gigahost/order")


# --- What the operator can compare while the confirmation is open ------------
# The confirmation's job is to be checked against the form, so the backdrop must
# not hide it and the dialog must not sit on the selectors. Both are geometry and
# cascade facts, measured rather than eyeballed.

CONTROL_FILL_PROBE = """(id) => {
  const parse = s => {
    const m = (s.match(/[\\d.]+/g) || []).map(Number);
    return m.length < 3 ? [0, 0, 0, 0] : (m.length < 4 ? [m[0], m[1], m[2], 1] : m);
  };
  const over = (top, under) =>
    [0, 1, 2].map(i => top[i] * top[3] + under[i] * (1 - top[3])).concat([1]);
  const el = document.getElementById(id);
  const layers = [];
  for (let n = el; n; n = n.parentElement) {
    const b = parse(getComputedStyle(n).backgroundColor);
    if (b[3] > 0) layers.push(b);
    if (b[3] === 1) break;
  }
  const fill = layers.reduceRight((acc, layer) => over(layer, acc), [255, 255, 255, 1]);
  const rgb = c => 'rgb(' + c.slice(0, 3).map(Math.round).join(', ') + ')';
  return {color: rgb(parse(getComputedStyle(el).color)), fill: rgb(fill)};
}"""

DIALOG_PROBE = """() => {
  const parse = s => {
    const m = (s.match(/[\\d.]+/g) || []).map(Number);
    return m.length < 3 ? [0, 0, 0, 0] : (m.length < 4 ? [m[0], m[1], m[2], 1] : m);
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
  const rgb = c => 'rgb(' + c.slice(0, 3).map(Math.round).join(', ') + ')';
  const box = el => {
    const r = el.getBoundingClientRect();
    return {x: r.x, y: r.y, w: r.width, h: r.height};
  };
  const area = (a, b) => {
    const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
    const h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
    return w > 0 && h > 0 ? w * h : 0;
  };
  const backdrop = document.getElementById('nexusConfirmModal');
  const dialog = backdrop.querySelector('.modal');
  const veil = parse(getComputedStyle(backdrop).backgroundColor);
  const dialogBox = box(dialog);
  const fields = ['deployPlanSelect', 'deployRegionSelect', 'deployPlacementSelect', 'deployOSSelect']
    .map(id => document.getElementById(id))
    .filter(Boolean)
    .map(el => ({
      id: el.id,
      text: el.options[el.selectedIndex] ? el.options[el.selectedIndex].textContent.trim() : '',
      overlap: Math.round(area(box(el), dialogBox)),
    }));
  // What a value behind the veil looks like on screen, for both channels.
  const osSelect = document.getElementById('deployOSSelect');
  const through = el => {
    const c = parse(getComputedStyle(el).color);
    const bg = surface(el);
    const t = [veil[0] * veil[3] + c[0] * (1 - veil[3]),
               veil[1] * veil[3] + c[1] * (1 - veil[3]),
               veil[2] * veil[3] + c[2] * (1 - veil[3])];
    const b = [veil[0] * veil[3] + bg[0] * (1 - veil[3]),
               veil[1] * veil[3] + bg[1] * (1 - veil[3]),
               veil[2] * veil[3] + bg[2] * (1 - veil[3])];
    return {text: rgb(t), bg: rgb(b)};
  };
  return {
    filter: getComputedStyle(backdrop).backdropFilter
      || getComputedStyle(backdrop).webkitBackdropFilter || 'none',
    veilAlpha: veil[3],
    dialog: {x: Math.round(dialogBox.x), y: Math.round(dialogBox.y),
             w: Math.round(dialogBox.w), h: Math.round(dialogBox.h)},
    viewport: {w: window.innerWidth, h: window.innerHeight},
    fields,
    value: through(osSelect),
    summary: document.getElementById('nexusConfirmBody').textContent,
  };
}"""


@pytest.mark.e2e
@pytest.mark.parametrize("viewport", [(1440, 900), (390, 844)], ids=["wide", "narrow"])
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_deploy_confirmation_leaves_the_form_comparable(
    authenticated_page: Page, base_url: str, viewport: tuple[int, int], theme: str
) -> None:
    """The dialog names the datacenter, dims but does not hide the form, and does
    not sit on the selectors at either width."""
    page = authenticated_page
    orders: list = []
    try:
        _deploy_form(page, base_url, orders)
        page.set_viewport_size({"width": viewport[0], "height": viewport[1]})
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.locator("#btnDeployVPS").scroll_into_view_if_needed()
        page.locator("#btnDeployVPS").click()
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('nexusConfirmModal')).opacity === '1'"
        )
        probe = page.evaluate(DIALOG_PROBE)

        assert "DC1 - Sandefjord" in probe["summary"], probe["summary"]
        assert probe["filter"] in ("none", ""), probe["filter"]
        assert probe["veilAlpha"] <= 0.35, probe["veilAlpha"]
        assert len(probe["fields"]) == 4, probe["fields"]
        covered = [f for f in probe["fields"] if f["overlap"] > 0]
        assert covered == [], (probe["dialog"], probe["viewport"], covered)

        ratio = contrast.ratio(_hex(probe["value"]["text"]), _hex(probe["value"]["bg"]))
        assert ratio >= contrast.AA_TEXT, (theme, probe["value"], f"{ratio:.2f}:1")
        assert orders == [], "opening the confirmation sent an order"
    finally:
        page.unroute("**/api/admin/hosting/gigahost/catalog**")
        page.unroute("**/api/admin/hosting/gigahost/order")


# --- The confirmations that share the modal -----------------------------------
# The VPS ordering confirmation docks itself and dims lightly; the shared modal must
# look and sit exactly as it does for every other confirmation, so both states are
# measured rather than assumed.

SHARED_MODAL_PROBE = """() => {
  const backdrop = document.getElementById('nexusConfirmModal');
  const dialog = backdrop.querySelector('.modal');
  const box = el => {
    const r = el.getBoundingClientRect();
    return {x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height)};
  };
  return {
    classes: backdrop.className,
    confirmKind: backdrop.getAttribute('data-confirm-kind'),
    bg: getComputedStyle(backdrop).backgroundColor,
    filter: getComputedStyle(backdrop).backdropFilter
      || getComputedStyle(backdrop).webkitBackdropFilter || 'none',
    align: getComputedStyle(backdrop).alignItems,
    padding: getComputedStyle(backdrop).padding,
    dialog: box(dialog),
    viewport: {w: window.innerWidth, h: window.innerHeight},
    whiteSpace: getComputedStyle(document.getElementById('nexusConfirmBody')).whiteSpace,
    okColor: getComputedStyle(document.getElementById('nexusConfirmOkBtn')).color,
  };
}"""


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_unrelated_confirmation_keeps_the_shared_modal(
    authenticated_page: Page, base_url: str, csrf_token: str, theme: str
) -> None:
    """Deleting a user opens the shared modal, untouched by the ordering dialog.

    The VPS confirmation marks the dialog only while it is open, and only for
    itself; every other confirmation must keep the shared backdrop, the centred
    position and the danger colour. The delete control only renders for another
    user, so one is created and removed through the API around the check.
    """
    page = authenticated_page
    page.set_viewport_size({"width": 1440, "height": 900})
    created = api_post(
        page,
        "/api/users/add",
        {
            "username": f"delete-me-{theme}",
            "password": "TempPass123!",
            "role": "user",
            "enabled": True,
        },
        csrf_token,
    )
    assert created["status"] == 200, created
    user_id = (created["body"] or {}).get("user_id")
    assert user_id, created
    try:
        page.goto(f"{base_url}/users")
        page.wait_for_load_state("networkidle")
        # The theme is applied after the navigation: a reload resets the attribute.
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_selector('#usersGrid button[aria-label="Delete"]', timeout=15000)
        page.add_style_tag(content=NO_TRANSITIONS)
        page.locator('#usersGrid button[aria-label="Delete"]').first.click()
        page.locator("#nexusConfirmModal.active").wait_for(state="visible")
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('nexusConfirmModal')).opacity === '1'"
        )
        probe = page.evaluate(SHARED_MODAL_PROBE)

        tokens = contrast.theme_tokens(theme)

        def channels(value: str) -> tuple:
            r, g, b, a = contrast.parse_color(value)
            return (round(r), round(g), round(b), round(a, 3))

        assert channels(probe["bg"]) == channels(
            contrast.resolve("bg-modal", tokens)
        ), probe["bg"]
        assert "blur(8px)" in probe["filter"], probe["filter"]
        assert probe["align"] == "center", probe["align"]
        assert probe["padding"] == "0px", probe["padding"]
        assert probe["whiteSpace"] == "normal", probe["whiteSpace"]
        assert channels(probe["okColor"]) == channels(
            contrast.resolve("danger", tokens)
        ), probe["okColor"]
        assert probe["confirmKind"] is None, probe["confirmKind"]
        centred = probe["dialog"]["y"] + probe["dialog"]["h"] / 2
        assert abs(centred - probe["viewport"]["h"] / 2) <= 2, (
            probe["dialog"],
            probe["viewport"],
        )

        page.keyboard.press("Escape")
        page.locator("#nexusConfirmModal.active").wait_for(state="detached")
        assert page.evaluate(
            "() => document.getElementById('nexusConfirmModal').getAttribute('data-confirm-kind')"
        ) is None
    finally:
        api_post(page, f"/api/users/{user_id}/delete", {}, csrf_token)


# --- The update-available state the renderer actually writes ------------------
# The per-component and overall badges use `badge-warning` for "Update available".
# That name has no stylesheet rule, so its contrast comes from the inherited text
# colour; this case renders the real state and measures it.

UPDATE_AVAILABLE = {
    "status": "ok",
    "update_available": True,
    "checked_at": "2026-11-23T18:00:00Z",
    "base_image": "devopsigor/amneziawg:v3.1.20261116-1",
    "components": [
        {
            "name": "amneziawg-go",
            "pinned_version": "v3.1.20261116",
            "latest_version": "v3.1.20261128",
            "release_url": "https://example.invalid/go",
            "update_available": True,
            "error": "",
        },
        {
            "name": "amneziawg-tools",
            "pinned_version": "v3.1.20260812",
            "latest_version": "v3.1.20260812",
            "release_url": "https://example.invalid/tools",
            "update_available": False,
            "error": "",
        },
        {
            "name": "docker-base-image",
            "pinned_version": "v3.1.20261116-1",
            "latest_version": "v3.1.20261116-1",
            "release_url": "https://example.invalid/img",
            "update_available": False,
            "error": "",
        },
    ],
}


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_update_available_badge_meets_aa_in_both_themes(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """The badge the renderer writes for "Update available" clears 4.5:1."""
    page = authenticated_page
    page.route(
        "**/api/system/upstream-status**",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(UPDATE_AVAILABLE)
        ),
    )
    try:
        _open_settings(page, base_url, theme)
        page.wait_for_function(
            "() => document.querySelectorAll('#upstreamCard .badge-warning').length > 0",
            timeout=30000,
        )
        badges = page.evaluate(BADGE_PROBE)
        warnings = [b for b in badges if "badge-warning" in b["cls"]]
        assert len(warnings) >= 2, badges  # the component badge and the overall badge
        assert all(b["text"] == "Update available" for b in warnings), warnings
        for badge in warnings:
            ratio = contrast.ratio(_hex(badge["color"]), _hex(badge["bg"]))
            assert ratio >= contrast.AA_TEXT, (theme, badge, f"{ratio:.2f}:1")
    finally:
        page.unroute("**/api/system/upstream-status**")


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
        cancel_class = page.locator("#nexusConfirmCancelBtn").get_attribute("class") or ""
        assert "btn-secondary" in cancel_class.split(), cancel_class

        # The destructive control must be readable on its own resting fill, and it
        # must still be the red one beside the neutral cancel.
        measured = page.evaluate(CONTROL_FILL_PROBE, "nexusConfirmOkBtn")
        neutral = page.evaluate(CONTROL_FILL_PROBE, "nexusConfirmCancelBtn")
        ratio = contrast.ratio(_hex(measured["color"]), _hex(measured["fill"]))
        assert ratio >= contrast.AA_TEXT, (theme, measured, f"{ratio:.2f}:1")
        assert measured["color"] != neutral["color"], (measured, neutral)
        assert measured["fill"] != neutral["fill"], (measured, neutral)
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
