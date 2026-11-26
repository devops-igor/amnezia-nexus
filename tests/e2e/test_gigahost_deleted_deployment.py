"""E2E: what Recent Deployments says about a deployment the provider has deleted.

The panel records the provider's own server inventory, and a deployment whose server that
inventory no longer lists is a fact the operator has to be able to read. This suite drives
the shipped renderers on the real Settings page from a stubbed API and asserts the visible
outcome: the row says Deleted, the order identity and the last recorded address survive,
and the row offers no control that would contact a server the panel knows is gone.

Nothing here contacts a provider, places an order or installs anything. The stub replaces
the panel's API client in the page, so the renderers run exactly as shipped.
"""

import pytest
from playwright.sync_api import Page


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
    page.goto(f"{base_url}/settings")
    page.wait_for_load_state("networkidle")
    page.wait_for_function(
        "document.querySelectorAll('.settings-section-card').length >= 9"
    )
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
