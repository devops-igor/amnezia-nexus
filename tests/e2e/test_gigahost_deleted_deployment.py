"""E2E: what the panel says about a deployment the provider has deleted.

The panel records the provider's own server inventory, and a deployment whose server that
inventory no longer lists is a fact the operator has to be able to read. This suite drives
the shipped renderers on the real Settings page from a stubbed API and asserts the visible
outcome on both surfaces that show it: the Recent Deployments row and the Saved Setup
Approvals list. The row says Deleted, the order identity and the last recorded address
survive, the retained step is named as history rather than as work in progress, and no
control is offered that would contact a server the panel knows is gone.

Both surfaces are also measured where the browser paints them: the saved rows have to fit
the card at a phone width without a horizontal document scroll, and the deleted badge has
to reach the AA text floor in both themes on both surfaces.

Nothing here contacts a provider, places an order or installs anything. The stub replaces
the panel's API client in the page, so the renderers run exactly as shipped.
"""

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast
from tests.e2e.rendered_pixels import dominant_colour, read_png

# The theme is switched by an attribute and the surface colours transition into place.
# Every measurement here is about the settled appearance, so the transitions are turned
# off before the switch: a capture taken mid-transition reads a blend of two themes, which
# is neither one.
NO_TRANSITIONS = (
    "*, *::before, *::after { transition: none !important; animation: none !important; }"
)


GIGAHOST_DELETED_RENDER = """({orders, intents, observations, deploys}) => {
  stopGigahostOrderStatusRefresh();
  const detail = id => (deploys || {})[id] || {};
  window.API = {
    get: async url => {
      if (url === '/api/admin/hosting/gigahost/orders')
        return {orders, provider_observations: observations};
      if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: intents};
      if (url === '/api/vpn/backends') return {backends: []};
      const m = String(url).match(/\\/orders\\/(.+)\\/status$/);
      if (m) return {status: 'ok', deploy: detail(decodeURIComponent(m[1]))};
      throw new Error('unexpected GET ' + url);
    },
    post: async () => ({}),
    delete: async () => ({}),
  };
  return Promise.all([loadRecentOrders(), loadSetupIntents()]);
}"""

DELETED_ROW_PROBE = """() => {
  const row = document.querySelector('#recentOrdersContainer .gigahost-order-row');
  const cell = row && row.querySelector('.gigahost-order-status');
  const identity = row && row.querySelector('.gigahost-order-identity');
  const panel = row && row.querySelector('.gigahost-order-status-details');
  return {
    stage: cell ? cell.getAttribute('data-stage') : null,
    identity: identity ? identity.textContent.trim() : null,
    labels: row
      ? [...row.querySelectorAll('.badge')].map(b => b.textContent.trim())
      : null,
    retryOffered: row
      ? [...row.querySelectorAll('button')].some(
          b => b.classList.contains('gigahost-order-action')
        )
      : null,
    actions: row
      ? [...row.querySelectorAll('button:not(.gigahost-order-status-toggle)')].map(
          b => b.textContent.trim()
        )
      : null,
    panel: panel ? panel.textContent.trim() : null,
  };
}"""

# The deployment the provider no longer has. The orders endpoint still returns the saved
# ledger row - that behaviour is unchanged - and the deploy read for that order carries the
# recorded observation, which is the only thing the view turns into DELETED.
DELETED_DEPLOYMENT = {
    "orders": [
        {
            "order_id": "ord-deleted",
            "status": "failed",
            "assigned_ip": "198.51.100.9",
        }
    ],
    "intents": [],
    "observations": {"ord-deleted": {"outcome": "confirmed", "status": "failed"}},
    # The failed journal is what offers a Retry control on an ordinary row, so the
    # fixture makes the absence of that control observable rather than trivially true.
    "deploys": {
        "ord-deleted": {
            "status": "failed",
            "step": "installing_protocol",
            "error": "install failed",
            "server_id": 7,
            "provider_absent": True,
        }
    },
}

# The same order as though the provider still had it. It is the control: the row is
# classified normally, keeps its status and offers the action its state allows.
LISTED_DEPLOYMENT = {
    "orders": DELETED_DEPLOYMENT["orders"],
    "intents": [],
    "observations": DELETED_DEPLOYMENT["observations"],
    "deploys": {
        "ord-deleted": {
            "status": "failed",
            "step": "installing_protocol",
            "error": "install failed",
            "server_id": 7,
        }
    },
}


def _open_gigahost(page: Page, base_url: str, state: dict) -> dict:
    """Render one Recent Deployments state on the real page and read the row back."""
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")
    # The deployment list is on the Servers page with the hosting card it fills.
    page.wait_for_function("() => !!document.querySelector('#recentOrdersContainer')")
    # The page starts its own read of this container on load, and the view admits one read
    # at a time: a caller arriving while a chain is running is coalesced into a single
    # follow-up. So the stub is installed and the read requested until the DOM shows the
    # stub's own row, rather than assuming one call is enough.
    page.evaluate(GIGAHOST_DELETED_RENDER, state)
    page.evaluate("() => loadRecentOrders()")
    page.wait_for_function(
        "() => !!document.querySelector('#recentOrdersContainer .gigahost-order-row')",
        timeout=15000,
    )
    return page.evaluate(DELETED_ROW_PROBE)


@pytest.mark.e2e
def test_deleted_deployment_renders_as_deleted(authenticated_page: Page, base_url: str) -> None:
    """The row states the deletion, and the label the operator reads says Deleted."""
    got = _open_gigahost(authenticated_page, base_url, DELETED_DEPLOYMENT)
    assert got["stage"] == "deleted", got
    assert any("Deleted" in label for label in got["labels"]), got
    # The stage's own sentence, not a provider observation: the status cell shows the
    # progression request -> deleted rather than a deploying or failed step.
    assert "Deployed" not in (got["identity"] or ""), got


@pytest.mark.e2e
def test_deleted_deployment_keeps_its_order_identity(
    authenticated_page: Page, base_url: str
) -> None:
    """The order number and the last recorded address stay on the row."""
    got = _open_gigahost(authenticated_page, base_url, DELETED_DEPLOYMENT)
    assert "#ord-deleted" in (got["identity"] or ""), got
    assert "198.51.100.9" in (got["identity"] or ""), got


@pytest.mark.e2e
def test_deleted_deployment_offers_no_contact_action(
    authenticated_page: Page, base_url: str
) -> None:
    """No control is offered, because every one of them would reach the deleted server."""
    got = _open_gigahost(authenticated_page, base_url, DELETED_DEPLOYMENT)
    assert got["actions"] == [], got


@pytest.mark.e2e
def test_a_listed_deployment_keeps_its_ordinary_treatment(
    authenticated_page: Page, base_url: str
) -> None:
    """The control: the same row without the observation is unchanged.

    A deleted-only assertion cannot tell "the absence mark removed the action" from
    "this view never offers one". Here the same order, with the same failed journal and
    no recorded absence, keeps a non-deleted stage and the retry its state allows.
    """
    got = _open_gigahost(authenticated_page, base_url, LISTED_DEPLOYMENT)
    assert got["stage"] == "failed", got
    assert got["retryOffered"] is True, got
    assert got["stage"] != "deleted", got


# ---------------------------------------------------------------------------
# The same recorded absence on the Saved Setup Approvals list.
#
# Nothing here hides a saved job: the row stays, because it is the panel's own record
# and a pending approval can still be revoked. What changes is what it says and what
# it offers. Three rows carry the states the operator has to be able to tell apart - a
# paused job whose server the provider still lists, a paused job whose server it does
# not, and a job the panel is still working on, which keeps the step wording of a
# settled row distinguishable from a running one.
SAVED_JOBS = {
    "orders": [{"order_id": "ord-deleted", "status": "failed", "assigned_ip": "198.51.100.9"}],
    "intents": [
        {
            "order_id": "ord_986_present",
            "protocol": "awg",
            "port": "51820",
            "state": "install_paused",
            "step": "installing_protocol",
        },
        {
            "order_id": "ord_986_vanished",
            "protocol": "awg",
            "port": "51820",
            "state": "install_paused",
            "step": "installing_protocol",
            "provider_absent": True,
        },
        {
            "order_id": "ord_986_moving",
            "protocol": "awg",
            "state": "installing",
            "step": "installing_protocol",
        },
    ],
    "observations": {"ord-deleted": {"outcome": "confirmed", "status": "failed"}},
    "deploys": {
        "ord-deleted": {
            "status": "failed",
            "step": "installing_protocol",
            "error": "install failed",
            "server_id": 7,
            "provider_absent": True,
        }
    },
}

# The rows of the saved list, selected by position rather than by a class the row itself
# carries. A measurement of "does this row fit" must not depend on how the row is built:
# the same selector has to find the row before and after the layout changed, or the
# assertion can only ever prove that a class name exists.
SAVED_ROW_SELECTOR = "#setupIntentsContainer > div > div"

# Both surfaces put the record in the row's first child and the state beside it, so the
# measurement reads those two boxes without naming a class.
ROWS_PROBE = """(rowSelector) => {
  const box = el => {
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return {
      left: r.left, right: r.right, top: r.top, bottom: r.bottom,
      width: r.width, height: r.height,
      x: r.left + window.scrollX, y: r.top + window.scrollY,
    };
  };
  // How many line boxes the badge's own text occupies. A badge squeezed by its row
  // wraps into two or three of them, which is what a width measurement alone cannot
  // express.
  const textLines = el => {
    if (!el) return 0;
    const range = document.createRange();
    range.selectNodeContents(el);
    return new Set([...range.getClientRects()].map(r => Math.round(r.top))).size;
  };
  const rows = [...document.querySelectorAll(rowSelector)].map(row => {
    const badge = row.querySelector('.badge');
    const button = row.querySelector('button');
    return {
      text: row.textContent.replace(/\\s+/g, ' ').trim(),
      row: box(row),
      identity: box(row.children[0]),
      state: box(badge ? badge.parentElement : null),
      badge: box(badge),
      badgeText: badge ? badge.textContent.trim() : null,
      badgeLines: textLines(badge),
      badgeInk: badge ? getComputedStyle(badge).color : null,
      badgeFill: badge ? getComputedStyle(badge).backgroundColor : null,
      button: box(button),
      buttonText: button ? button.textContent.trim() : null,
      buttonClipped: button ? button.scrollWidth > button.clientWidth : null,
    };
  });
  return {
    viewportWidth: window.innerWidth,
    viewportHeight: window.innerHeight,
    scrollWidth: document.documentElement.scrollWidth,
    rows,
  };
}"""

BADGE_PROBE = """el => ({
  ink: getComputedStyle(el).color,
  fill: getComputedStyle(el).backgroundColor,
  text: el.textContent.trim(),
})"""


def _hex(rgb_text: str) -> str:
    red, green, blue, _ = contrast.parse_color(rgb_text)
    return "#%02x%02x%02x" % (int(red), int(green), int(blue))


def _row(got: dict, order_id: str) -> dict:
    """The one measured row whose rendered text names this order id."""
    matches = [row for row in got["rows"] if order_id in (row["text"] or "")]
    assert len(matches) == 1, f"{order_id}: {len(matches)} rows matched {got['rows']}"
    return matches[0]


def _render_saved_jobs(
    page: Page,
    base_url: str,
    viewport: tuple[int, int] = (1440, 900),
    theme: str = "dark",
) -> dict:
    """Render the saved-jobs fixture on the real page and measure its rows."""
    page.set_viewport_size({"width": viewport[0], "height": viewport[1]})
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")
    page.wait_for_function("() => !!document.querySelector('#setupIntentsContainer')")
    page.add_style_tag(content=NO_TRANSITIONS)
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
    # The page starts its own read of these containers on load, and each view admits one
    # read at a time, so the stub is installed and the read requested again until the
    # DOM shows the stub's own rows. The readiness predicate reads the order ids the stub
    # supplied, not a class the renderer writes, so it holds for both layouts.
    page.evaluate(GIGAHOST_DELETED_RENDER, SAVED_JOBS)
    page.evaluate("() => loadSetupIntents()")
    page.wait_for_function(
        """() => {
          const text = document.getElementById('setupIntentsContainer').textContent;
          return ['ord_986_present', 'ord_986_vanished', 'ord_986_moving']
            .every(id => text.includes(id));
        }""",
        timeout=15000,
    )
    # The list is below the fold on a phone, and "in one frame" is a claim about what the
    # operator can see at once: put the list on screen before measuring boxes. The page
    # scrolls smoothly by design, so the scroll is made instant and the readiness
    # predicate waits for the list to actually be in the viewport.
    page.evaluate(
        "() => { document.documentElement.style.scrollBehavior = 'auto';"
        " document.getElementById('setupIntentsContainer')"
        ".scrollIntoView({block: 'center', behavior: 'instant'}); }"
    )
    page.wait_for_function(
        "() => { const r = document.getElementById('setupIntentsContainer')"
        ".getBoundingClientRect(); return r.top >= 0 && r.bottom <= window.innerHeight; }",
        timeout=5000,
    )
    return page.evaluate(ROWS_PROBE, SAVED_ROW_SELECTOR)


@pytest.mark.e2e
def test_saved_jobs_fit_a_phone_viewport(authenticated_page: Page, base_url: str) -> None:
    """At 390 px the document does not scroll sideways and a row keeps its state in view.

    The predecessor laid the row out as one non-wrapping flex line: the identity took the
    width it needed, the state badge and the Resume control were pushed past the card's
    right edge, and the document scrolled by 157 px to reveal them. Neither the state nor
    the action was in the initial frame, and panning right clipped the start of both order
    ids - there was no frame that showed the identity and the action together.
    """
    page = authenticated_page
    got = _render_saved_jobs(page, base_url, viewport=(390, 844))
    assert got["viewportWidth"] == 390, got
    assert got["scrollWidth"] == 390, (
        "the saved-jobs list widens the document past the phone viewport: "
        f"{got['scrollWidth']} px against {got['viewportWidth']} px"
    )

    for order_id in ("ord_986_present", "ord_986_vanished", "ord_986_moving"):
        row = _row(got, order_id)
        assert row["identity"]["left"] >= -0.5, (order_id, row)
        assert row["identity"]["right"] <= 390.5, (
            f"{order_id}: the order identity runs past the viewport", row
        )
        assert row["badge"]["left"] >= -0.5, (
            f"{order_id}: the state badge starts off-screen", row
        )
        assert row["badge"]["right"] <= 390.5, (
            f"{order_id}: the state badge ends off-screen", row
        )
        # One frame: the row carries the identity, the state and any action inside the
        # viewport once the list is on screen.
        assert row["row"]["top"] >= 0 and row["row"]["bottom"] <= 844, (
            f"{order_id}: the row does not fit one phone frame", row
        )
        if row["button"] is not None:
            assert row["button"]["left"] >= -0.5 and row["button"]["right"] <= 390.5, (
                f"{order_id}: the action is not in the same frame as the state", row
            )

    # The state the row must still make readable is the one that ends it, and it offers
    # nothing: the assertion is about the visible badge, not about the action's absence.
    vanished = _row(got, "ord_986_vanished")
    assert vanished["badgeText"] == "Deleted", vanished
    assert vanished["button"] is None, vanished
    present = _row(got, "ord_986_present")
    assert present["buttonText"] == "Resume", present


@pytest.mark.e2e
def test_saved_job_control_row_fits_its_row_at_desktop_width(
    authenticated_page: Page, base_url: str
) -> None:
    """On the half-width card the state and the action reflow instead of overflowing.

    Measured defect: on a 501 px row the action group ran 5 px past the row's edge, the
    amber badge wrapped to three lines and Resume was squeezed to about 38x32 with its
    label crowding the border. The row has to give the group a line of its own rather
    than compress it.
    """
    got = _render_saved_jobs(authenticated_page, base_url, viewport=(1440, 900))
    row = _row(got, "ord_986_present")
    assert row["row"]["width"] < 600, (
        "this case is about the narrow card: the row is no longer half-width", row
    )
    assert row["state"]["right"] <= row["row"]["right"] + 0.5, (
        "the state and action group runs past the row's right edge", row
    )
    assert row["badgeLines"] == 1, (
        f"the state badge wraps to {row['badgeLines']} lines instead of one", row
    )
    assert row["buttonClipped"] is False, (
        "the action's label is clipped by a button narrower than its content", row
    )
    assert row["button"]["height"] <= row["row"]["height"], (
        "the action is taller than the row that holds it", row
    )


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_deleted_badge_ink_meets_aa_on_both_surfaces(
    authenticated_page: Page, base_url: str, theme: str
) -> None:
    """The Deleted label clears 4.5:1 on its own fill, in both themes, on both surfaces.

    The fill is sampled with the label's ink made transparent and the badge captured on
    its own, so the pixels read are the surface under the paint and nothing else: the fill
    is translucent, so the declared value is not what a reader's eye receives, and a
    12 px label covers enough of its badge that a counted colour would blend the two. The
    ink is the colour the browser resolved for the label, so a ratio computed from the
    pair is about this badge in this theme. The saved list's badge is the shared
    .badge-danger, whose ink measured 4.43:1 on that fill in the dark theme; the recent
    deployments badge already used the state's own ink there.
    """
    page = authenticated_page
    _render_saved_jobs(page, base_url, viewport=(1440, 900), theme=theme)
    surfaces = (
        ("saved setup approvals", "#setupIntentsContainer .badge-danger"),
        ("recent deployments", "#recentOrdersContainer .gigahost-order-status-toggle"),
    )
    # The ink is read as shipped, before the capture below makes it transparent: the
    # transparent ink exists only to expose the fill, and reading it back afterwards would
    # measure rgba(0, 0, 0, 0) against the fill.
    resolved = {
        surface: page.locator(selector).first.evaluate(BADGE_PROBE)
        for surface, selector in surfaces
    }
    # Only the ink goes transparent: the fill, the border and the box stay as shipped.
    style = page.add_style_tag(
        content=(
            "#setupIntentsContainer .badge-danger,"
            " #recentOrdersContainer .gigahost-order-status-toggle"
            " { color: transparent !important; }"
        )
    )
    failures = []
    try:
        for surface, selector in surfaces:
            target = page.locator(selector).first
            ink_and_fill = resolved[surface]
            ink = _hex(ink_and_fill["ink"])
            # Centre the badge before clipping it. The shell's navigation is sticky, and a
            # capture taken at whichever edge the element was scrolled to can put the badge
            # underneath it, which samples the bar instead of the badge.
            target.evaluate("el => el.scrollIntoView({block: 'center', behavior: 'instant'})")
            page.wait_for_function(
                """(sel) => {
                  const r = document.querySelector(sel).getBoundingClientRect();
                  return r.top > 80 && r.bottom < window.innerHeight - 80;
                }""",
                arg=selector,
            )
            shot = target.screenshot()
            width, height = read_png(shot)[:2]
            fill, share = dominant_colour(shot, (0, 0, width, height))
            assert fill != ink, (
                f"{surface}/{theme}: the sampled fill equalled the ink ({ink}); the badge "
                "held no surface behind the glyphs"
            )
            # The label says which state this ink belongs to, so a passing ratio cannot
            # come from measuring some other badge on the page.
            assert "Deleted" in ink_and_fill["text"], (surface, theme, ink_and_fill)
            measured = contrast.ratio(ink, fill)
            entry = (
                f"{surface}/{theme}: {ink} on {fill} = {measured:.2f}:1 "
                f"({share:.0%} of {width}x{height}); declared fill {ink_and_fill['fill']}"
            )
            if measured < contrast.AA_TEXT or share < 0.4:
                failures.append(entry)
    finally:
        style.evaluate("el => el.remove()")

    assert not failures, (
        f"the Deleted badge is below {contrast.AA_TEXT}:1 in the {theme} theme: "
        + "; ".join(failures)
    )


@pytest.mark.e2e
def test_saved_terminal_row_labels_its_step_as_recorded(
    authenticated_page: Page, base_url: str
) -> None:
    """A settled saved row names its step as history in the shipped locale; a running one does not.

    A bare [installing_protocol] beside a Deleted badge implies the install is still under
    way. The order disclosure already calls the same fact "Last recorded step", so the row
    reuses that wording instead of carrying a second name for it.
    """
    got = _render_saved_jobs(authenticated_page, base_url, viewport=(1440, 900))
    for order_id in ("ord_986_vanished", "ord_986_present"):
        row = _row(got, order_id)
        assert "Last recorded step: installing_protocol" in row["text"], (order_id, row)
        assert "[installing_protocol]" not in row["text"], (order_id, row)
    moving = _row(got, "ord_986_moving")
    assert "[installing_protocol]" in moving["text"], moving
    assert "Last recorded step" not in moving["text"], moving
