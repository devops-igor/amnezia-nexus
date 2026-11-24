"""The hint line under a control must be readable where the browser paints it.

`tests/test_css_contrast.py` reads the stylesheets; this suite measures the panel.
For every rendered `.form-hint` on a real page — the page itself and the dialogs it
owns — it takes the text colour the browser resolved and the colour of the pixels
behind the text from a screenshot, and asserts the WCAG 1.4.3 ratio for normal text.

The backdrop matters because a hint sits on more than one surface: the page canvas,
a card, the tinted field under a table header, and a dialog's own panel. Those
surfaces are a few levels apart, so a measurement of one is not a measurement of the
others — which is how a hint can look acceptable in the card it was designed in and
fail in every dialog the operator actually types into.
"""

import pytest
from playwright.sync_api import Page

from tests.e2e import contrast
from tests.e2e.rendered_pixels import dominant_colour

NO_TRANSITIONS = (
    "*, *::before, *::after { transition: none !important; animation: none !important; }"
)

# Every rendered hint on the page, with the box it occupied in document
# coordinates, the colour the browser resolved for its text, and the colour of the
# field label that shares its group — the role the hint sits beside and must not
# be mistaken for.
LIST_HINTS = """() => {
  const out = [];
  document.querySelectorAll('.form-hint').forEach((el, i) => {
    const box = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    const rendered = box.width > 0 && box.height > 0
      && style.visibility !== 'hidden' && style.display !== 'none'
      && Number(style.opacity) > 0.05;
    const dialog = el.closest('.modal, .modal-backdrop');
    const group = el.closest('.form-group, .form-row, .settings-field-pair, .settings-fieldset');
    const label = group ? group.querySelector('.form-label, .settings-field-label') : null;
    const labelStyle = label ? getComputedStyle(label) : null;
    out.push({
      index: i,
      id: el.id || '',
      dialog: dialog ? (dialog.id || 'dialog') : '',
      colour: style.color,
      labelColour: labelStyle ? labelStyle.color : '',
      labelText: label ? (label.textContent || '').trim().slice(0, 40) : '',
      x: box.left + window.scrollX,
      y: box.top + window.scrollY,
      w: box.width,
      h: box.height,
      rendered,
      text: (el.textContent || '').trim().slice(0, 60),
    });
  });
  return out;
}"""

# The step the hint must keep from the field label beside it lives beside the
# contrast floors, because both suites apply the same number.
MIN_ROLE_LIGHTNESS_STEP = contrast.MIN_ROLE_LIGHTNESS_STEP

# A surface is a page plus the state that reveals its hints. Each opener returns a
# token naming what it revealed, so a dialog that fails to open fails the case
# instead of measuring the page behind it and passing.
SURFACES = [
    (
        "index-add-server-key",
        "/",
        """() => {
          const open = [...document.querySelectorAll('button')]
            .find(b => (b.getAttribute('onclick') || '').includes('addServerModal'));
          if (!open) return 'no add-server control';
          open.click();
          const keyTab = [...document.querySelectorAll('#addServerModal .tab')]
            .find(b => (b.getAttribute('onclick') || '').includes("'key'"));
          if (!keyTab) return 'no ssh-key tab';
          keyTab.click();
          return 'ssh-key-tab';
        }""",
        "ssh-key-tab",
    ),
    (
        "server-install-awg",
        "/server/1",
        """() => {
          const button = document.getElementById('awg-install-btn');
          if (!button) return 'no awg install control';
          button.click();
          return 'install-dialog';
        }""",
        "install-dialog",
    ),
    (
        "server-install-telemt",
        "/server/1",
        """() => {
          const button = document.getElementById('telemt-install-btn');
          if (!button) return 'no telemt install control';
          button.click();
          return 'install-dialog';
        }""",
        "install-dialog",
    ),
    (
        "server-install-vless",
        "/server/1",
        """() => {
          const button = document.getElementById('vless-install-btn');
          if (!button) return 'no vless install control';
          button.click();
          return 'install-dialog';
        }""",
        "install-dialog",
    ),
    (
        "users-share",
        "/users",
        """() => {
          if (typeof window.openShareModal !== 'function') return 'no share dialog controller';
          window.openShareModal({id: 'probe-user', username: 'probe', enabled: 'true', token: 'probe'});
          return 'share-dialog';
        }""",
        "share-dialog",
    ),
    (
        "settings",
        "/settings",
        None,
        None,
    ),
]

IDS = [surface[0] for surface in SURFACES]
PARAMS = [
    (surface[0], surface[1], surface[2], surface[3], theme)
    for surface in SURFACES
    for theme in ("dark", "light")
]
PARAM_IDS = [f"{surface[0]}-{theme}" for surface in SURFACES for theme in ("dark", "light")]


def _hex(rgb_text: str) -> str:
    red, green, blue, _ = contrast.parse_color(rgb_text)
    return "#%02x%02x%02x" % (int(red), int(green), int(blue))


def _open(page: Page, base_url: str, path: str, opener: str | None, theme: str) -> str:
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}{path}")
    page.wait_for_load_state("networkidle")
    page.add_style_tag(content=NO_TRANSITIONS)
    revealed = "page"
    if opener:
        revealed = page.evaluate(opener)
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
    page.wait_for_timeout(120)
    return revealed


@pytest.mark.e2e
@pytest.mark.parametrize("surface,path,opener,expected,theme", PARAMS, ids=PARAM_IDS)
def test_hint_text_reaches_aa_on_every_measured_surface(
    authenticated_page: Page, base_url: str, surface, path, opener, expected, theme
) -> None:
    """Each rendered hint clears 4.5:1 against the pixels behind it, in both themes."""
    page = authenticated_page
    revealed = _open(page, base_url, path, opener, theme)
    if expected is not None:
        assert revealed == expected, f"{surface}: expected {expected}, got {revealed}"

    hints = [hint for hint in page.evaluate(LIST_HINTS) if hint["rendered"]]
    assert hints, f"{surface}: no rendered .form-hint was measured in the {theme} theme"

    shot = page.screenshot(full_page=True)
    failures = []
    measured = []
    samples = []
    for hint in hints:
        backdrop, share = dominant_colour(shot, (hint["x"], hint["y"], hint["w"], hint["h"]))
        text = _hex(hint["colour"])
        assert backdrop != text, (
            f"{surface}: the sampled backdrop equalled the text colour ({text}); "
            "the box was too small to contain any of the surface behind the glyphs"
        )
        got = contrast.ratio(text, backdrop)
        entry = (
            f"{surface}/{theme}: #{hint['id'] or hint['index']} "
            f"{text} on {backdrop} = {got:.2f}:1 ({share:.0%} of the box) "
            f"{hint['text']!r} in {hint['dialog'] or 'page'}"
        )
        measured.append(entry)
        samples.append((hint, text, backdrop, got))
        if got < contrast.AA_TEXT:
            failures.append(entry)

    assert not failures, (
        f"{len(failures)} of {len(hints)} hints are below {contrast.AA_TEXT}:1 on {surface} "
        f"in the {theme} theme:\n" + "\n".join(failures)
    )

    # The floor alone is satisfied by painting the hint and the field label the same
    # grey. Both roles then read as one, told apart only by size, weight and
    # placement. So a hint that sits beside a label must also be a distinguishable
    # tone, and the quieter of the two: the label names the field, the hint says
    # what to expect from it.
    role_failures = []
    role_checked = 0
    for hint, text, backdrop, got in samples:
        if not hint["labelColour"]:
            continue
        role_checked += 1
        label = _hex(hint["labelColour"])
        where = (
            f"#{hint['id'] or hint['index']} {hint['text']!r} beside label {hint['labelText']!r}"
        )
        if text == label:
            role_failures.append(
                f"{surface}/{theme}: {where} — hint and label are the same colour {text}"
            )
            continue
        step = abs(contrast.lightness(text) - contrast.lightness(label))
        if step < MIN_ROLE_LIGHTNESS_STEP:
            role_failures.append(
                f"{surface}/{theme}: {where} — hint {text} and label {label} differ by "
                f"{step:.1f} L*, under the {MIN_ROLE_LIGHTNESS_STEP} L* step"
            )
        if got >= contrast.ratio(label, backdrop):
            role_failures.append(
                f"{surface}/{theme}: {where} — hint {text} is not quieter than its label "
                f"{label} on {backdrop} ({got:.2f}:1 versus "
                f"{contrast.ratio(label, backdrop):.2f}:1)"
            )

    assert role_checked, (
        f"{surface} in the {theme} theme: no rendered hint sits beside a field label, "
        "so the two-role check measured nothing"
    )
    assert not role_failures, (
        f"{len(role_failures)} of {role_checked} labelled hints do not read as a role "
        f"apart from their label on {surface} in the {theme} theme:\n" + "\n".join(role_failures)
    )
    # A pass is only meaningful if the surface really was the one measured: the
    # dialog-opening cases must have found hints inside a dialog.
    if expected in {"install-dialog", "share-dialog"}:
        assert any(hint["dialog"] for hint in hints), measured
