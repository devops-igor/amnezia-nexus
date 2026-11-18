"""Offline contrast and focus-token guards for the shared stylesheets.

No browser is needed: every number is computed from web/static/css/tokens.css
and from the colour each selector actually declares, so a palette change or a
selector that drifts back to a failing token fails here without anyone
measuring by eye.

* informative text inside the Settings cards reaches 4.5:1 (WCAG 1.4.3) on the
  surfaces it is drawn on, in both themes;
* the focus outline colour is a token that exists and is visible (3:1, WCAG
  1.4.11) against every surface in both themes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.e2e import contrast

CSS_DIR = contrast.CSS_DIR
THEMES = ["dark", "light"]

# Text inside the Settings cards that tells the operator something. Each is read
# from the stylesheet, so the assertion follows what is actually declared.
INFORMATIVE = [
    ".settings-section-card .form-hint",
    ".settings-section-card .info-card-label",
    ".settings-section-card .text-muted",
    ".settings-section-card .data-table th",
    ".settings-section-card .form-input::placeholder",
    ".upstream-component-link",
    ".upstream-component-meta",
    ".upstream-checked-at",
]

# Surfaces that text can sit on inside a Settings card: the card, the table
# header and the focused field (--bg-secondary), and the input fill laid over the card.
TEXT_SURFACES = ["bg-card", "bg-secondary", "bg-input-over-card"]
# Surfaces the focus outline can be drawn against.
OUTLINE_SURFACES = ["bg-primary", "bg-surface", "bg-secondary", "bg-card", "bg-card-hover"]

_RULE_RE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_COLOR_RE = re.compile(r"(?<![-\w])color:\s*([^;]+);")


def _css(name: str) -> str:
    return re.sub(r"/\*.*?\*/", "", (CSS_DIR / f"{name}.css").read_text(encoding="utf-8"), flags=re.S)


def declared_color(css: str, selector: str) -> str:
    """The `color` value of the last rule that lists the selector."""
    found = None
    for head, body in _RULE_RE.findall(css):
        if selector in [" ".join(part.split()) for part in head.split(",")]:
            match = _COLOR_RE.search(body)
            if match:
                found = match.group(1).strip()
    assert found is not None, f"no rule declares a colour for {selector!r}"
    return found


def surface(tokens: dict[str, str], name: str) -> str:
    """An opaque hex for a surface; the translucent input fill is flattened over the card."""
    if name != "bg-input-over-card":
        return contrast.resolve(name, tokens)
    r, g, b, a = contrast.parse_color(contrast.resolve("bg-input", tokens))
    cr, cg, cb, _ = contrast.parse_color(contrast.resolve("bg-card", tokens))
    flat = [round(a * top + (1 - a) * under) for top, under in ((r, cr), (g, cg), (b, cb))]
    return "#%02x%02x%02x" % tuple(flat)


def token_name(value: str) -> str:
    match = re.fullmatch(r"var\(--([\w-]+)\)", value)
    assert match, f"expected a design token, got {value!r}"
    return match.group(1)


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("selector", INFORMATIVE)
def test_informative_text_meets_aa_on_every_surface(theme: str, selector: str) -> None:
    tokens = contrast.theme_tokens(theme)
    name = token_name(declared_color(_css("settings"), selector))
    fg = contrast.resolve(name, tokens)
    for bg_name in TEXT_SURFACES:
        got = contrast.ratio(fg, surface(tokens, bg_name))
        assert got >= contrast.AA_TEXT, (
            f"{selector} uses --{name} ({fg}) on --{bg_name} in the {theme} theme: "
            f"{got:.2f}:1, below {contrast.AA_TEXT}:1"
        )


@pytest.mark.parametrize("theme,expected", [("dark", 2.95), ("light", 2.56)])
def test_muted_token_is_still_the_failing_one_the_fix_moves_away_from(theme: str, expected: float) -> None:
    """Calibrates the arithmetic against the ratios issue 902 measured for --text-muted.

    If this drifts the contrast helper is wrong, and every pass above is suspect.
    """
    tokens = contrast.theme_tokens(theme)
    got = contrast.ratio(contrast.resolve("text-muted", tokens), surface(tokens, "bg-card"))
    assert round(got, 2) == expected


def _focus_declarations() -> list[tuple[str, str]]:
    """(selector list, outline value) for every :focus-visible rule in base.css."""
    out = []
    for head, body in _RULE_RE.findall(_css("base")):
        if ":focus-visible" in head:
            match = re.search(r"outline:\s*([^;]+);", body)
            assert match, f"focus rule without an outline: {head.strip()!r}"
            out.append((" ".join(head.split()), match.group(1).strip()))
    assert out, "base.css declares no :focus-visible rule"
    return out


@pytest.mark.parametrize("theme", THEMES)
def test_focus_outline_colour_is_a_defined_token(theme: str) -> None:
    tokens = contrast.theme_tokens(theme)
    for head, outline in _focus_declarations():
        refs = re.findall(r"var\(--([\w-]+)\)", outline)
        assert refs, f"{head}: outline {outline!r} names no token"
        for ref in refs:
            assert ref in tokens, f"{head}: --{ref} is not defined in tokens.css ({theme} theme)"
            contrast.parse_color(contrast.resolve(ref, tokens))  # must be a real colour


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("bg_name", OUTLINE_SURFACES)
def test_focus_outline_is_visible_against_every_surface(theme: str, bg_name: str) -> None:
    tokens = contrast.theme_tokens(theme)
    for head, outline in _focus_declarations():
        found = re.search(r"var\(--([\w-]+)\)", outline)
        assert found, f"{head}: outline {outline!r} names no token"
        colour_token = found.group(1)
        got = contrast.ratio(contrast.resolve(colour_token, tokens), surface(tokens, bg_name))
        assert got >= contrast.AA_NON_TEXT, (
            f"{head}: --{colour_token} on --{bg_name} in the {theme} theme is {got:.2f}:1, "
            f"below {contrast.AA_NON_TEXT}:1"
        )
