"""E2E: the colour the panel actually paints on the hosting containers.

The static stylesheet rules only reach text that carries a class. The hosting renderers
build their nodes in script and set some colours inline, so a CSS-only check never sees
them and a palette regression there is invisible to every other suite. These measurements
render the shipped renderers on the real page from a stubbed API (no provider, no network)
and read the colour the browser paints against the surface behind it.

The containers live on the Servers page: this suite moved here with them, because the
copy that measured them while opening Settings would have measured nothing.
"""

import re

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast

# The theme is switched by an attribute and the surface colours transition into place, so
# the transitions are turned off before the switch: a capture taken mid-transition reads a
# blend of two themes, which is neither one.
NO_TRANSITIONS = (
    "*, *::before, *::after { transition: none !important; animation: none !important; }"
)


# --- Populated Gigahost states, read from the shipped renderers ---------------
# The static rules only reach text that carries a class. The Gigahost renderers
# build their nodes in script and set the colour inline, so a CSS-only check never
# sees them. This renders the real renderers on the real Settings page from a
# stubbed API (no provider, no network) and reads the colour the browser paints.

GIGAHOST_RENDER = """({orders, intents, observations}) => {
  stopGigahostOrderStatusRefresh();
  window.API = {
    get: async url => {
      if (url === '/api/admin/hosting/gigahost/orders')
        return {orders, provider_observations: observations};
      if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: intents};
      if (url === '/api/vpn/backends') return {backends: []};
      if (/\\/orders\\/.+\\/status$/.test(url)) return {status: 'ok', deploy: {}};
      throw new Error('unexpected GET ' + url);
    },
    post: async () => ({}),
    delete: async () => ({}),
  };
  return Promise.all([loadRecentOrders(), loadSetupIntents()]);
}"""
GIGAHOST_PROBE = """() => {
  const parse = s => {
    const m = s.match(/[\\d.]+/g).map(Number);
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
  const read = el => ({
    text: el.textContent.trim().slice(0, 48),
    color: getComputedStyle(el).color,
    bg: 'rgb(' + surface(el).slice(0, 3).map(Math.round).join(', ') + ')',
  });
  const orders = document.querySelector('#recentOrdersContainer');
  const jobs = document.querySelector('#setupIntentsContainer');
  const panel = orders.querySelector('.gigahost-order-status-details');
  const kids = panel ? [...panel.children] : [];
  const hasText = e => [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
  // A job's step is the one span that states it: a bracket while the panel is still
  // working the job, or the recorded-step label with its value once the row is an
  // outcome. The label comes from the page's own catalogue and the value after it must
  // be non-empty, so a lost step still fails here and no other span can stand in.
  const stepLabel = (typeof window._ === 'function' && window._('gigahost_status_recorded_step')) || '';
  const isStep = s => {
    const text = s.textContent.trim();
    if (text.startsWith('[') && text.endsWith(']') && text.length > 2) return true;
    if (!stepLabel || stepLabel === 'gigahost_status_recorded_step') return false;
    const prefix = stepLabel + ':';
    return text.startsWith(prefix) && text.slice(prefix.length).trim() !== '';
  };
  return {
    labels: panel ? [...panel.querySelectorAll(':scope > div > span:first-child')].map(read) : [],
    bare: kids.filter(c => c.tagName === 'DIV' && c.children.length === 0).map(read),
    steps: [...jobs.querySelectorAll('span')].filter(isStep).map(read),
    recovery: [...jobs.querySelectorAll('.btn-primary + span')].map(read),
    empty: [...document.querySelectorAll('#recentOrdersContainer .text-muted, #setupIntentsContainer .text-muted')].map(read),
    everything: [...document.querySelectorAll('#recentOrdersContainer *, #setupIntentsContainer *')]
      .filter(hasText).map(read),
  };
}"""


PROVISIONING_ORDER = {
    "orders": [{"order_id": "ord-ip", "status": "ready", "assigned_ip": "198.51.100.7"}],
    "intents": [],
    "observations": {"ord-ip": {"outcome": "confirmed", "status": "deploying"}},
}
AWAITING_CREDENTIALS_JOB = {
    "orders": [],
    "intents": [
        {
            "order_id": "job-1",
            "state": "awaiting_credentials",
            "step": "awaiting_credentials",
            "protocol": "awg",
            "port": 51820,
        }
    ],
    "observations": {},
}
# state -> (probe groups that must be present and informative, minimum node count)
GIGAHOST_STATES = {
    "provisioning_order_with_address": (PROVISIONING_ORDER, {"labels": 7, "bare": 2}),
    "saved_job_awaiting_credentials": (AWAITING_CREDENTIALS_JOB, {"steps": 1, "recovery": 1}),
}


def _rgb(hex_or_rgba: str) -> str:
    r, g, b, _ = contrast.parse_color(hex_or_rgba)
    return f"rgb({int(r)}, {int(g)}, {int(b)})"


def _hex(rgb_text: str) -> str:
    r, g, b = (int(float(n)) for n in re.findall(r"[\d.]+", rgb_text)[:3])
    return "#%02x%02x%02x" % (r, g, b)


def _render_gigahost(page: Page, base_url: str, theme: str, state: dict) -> dict:
    """Render the hosting containers on the page that renders them.

    The deployment list and the saved setup approvals moved out of Settings with the
    hosting block, so they render on the Servers page. Opening Settings here would find
    neither container and every measurement below would fail on a missing element rather
    than on a colour.
    """
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")
    page.wait_for_function("() => !!document.querySelector('#recentOrdersContainer')")
    page.add_style_tag(content=NO_TRANSITIONS)
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
    page.evaluate(GIGAHOST_RENDER, state)
    if state["orders"]:
        toggle = page.locator("#recentOrdersContainer .gigahost-order-status-toggle").first
        toggle.wait_for(state="visible")
        toggle.click()
        page.locator("#recentOrdersContainer .gigahost-order-status-details").first.wait_for(
            state="visible"
        )
    if state["intents"]:
        page.locator("#setupIntentsContainer .btn-primary").first.wait_for(state="visible")
    return page.evaluate(GIGAHOST_PROBE)


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("name", sorted(GIGAHOST_STATES))
def test_populated_gigahost_text_is_informative_and_readable(
    authenticated_page: Page, base_url: str, theme: str, name: str
) -> None:
    """Labels, the provisioning warning, the step and the recovery hint reach 4.5:1.

    Rendered by the shipped renderers from a stubbed API. The colour is what the
    browser paints after the cascade (an inline style included), the surface is
    the opaque card behind it, and the expectations come from tokens.css for the
    theme, so neither side is a pinned colour.
    """
    state, minimum = GIGAHOST_STATES[name]
    probe = _render_gigahost(authenticated_page, base_url, theme, state)
    tokens = contrast.theme_tokens(theme)
    want_color = _rgb(contrast.resolve("text-secondary", tokens))
    want_surface = _rgb(contrast.resolve("bg-card", tokens))
    for group, count in minimum.items():
        nodes = probe[group]
        assert len(nodes) >= count, f"{name}/{group}: expected >= {count} nodes, got {probe}"
        for node in nodes:
            where = (name, theme, group, node)
            assert node["color"] == want_color, where
            assert node["bg"] == want_surface, where
            got = contrast.ratio(_hex(node["color"]), _hex(node["bg"]))
            assert got >= contrast.AA_TEXT, (*where, f"{got:.2f}:1")


@pytest.mark.e2e
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("name", sorted(GIGAHOST_STATES))
def test_no_populated_gigahost_text_is_painted_in_the_muted_colour(
    authenticated_page: Page, base_url: str, theme: str, name: str
) -> None:
    """Catches a sibling nobody listed: no text node here may use --text-muted."""
    state, _ = GIGAHOST_STATES[name]
    probe = _render_gigahost(authenticated_page, base_url, theme, state)
    muted = _rgb(contrast.resolve("text-muted", contrast.theme_tokens(theme)))
    assert probe["everything"], "the populated state rendered no text"
    offenders = [node for node in probe["everything"] if node["color"] == muted]
    assert offenders == [], (name, theme, offenders)

