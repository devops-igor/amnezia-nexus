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


def _css(name: str) -> str:
    return re.sub(
        r"/\*.*?\*/", "", (CSS_DIR / f"{name}.css").read_text(encoding="utf-8"), flags=re.S
    )


def declared_color(css: str, selector: str) -> str:
    """The `color` value of the last rule that lists the selector."""
    found = declared(css, selector, "color")
    assert found is not None, f"no rule declares a colour for {selector!r}"
    return found


def declared(css: str, selector: str, property: str) -> str | None:
    """The value of `property` in the last rule that lists the selector.

    Bound to the selector rather than searched for across the sheet: a value that
    appears somewhere else tells nothing about the rule being checked.
    """
    pattern = re.compile(r"(?<![-\w])" + re.escape(property) + r":\s*([^;]+);")
    found = None
    for head, body in _RULE_RE.findall(css):
        if selector in [" ".join(part.split()) for part in head.split(",")]:
            match = pattern.search(body)
            if match:
                found = match.group(1).strip()
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
def test_muted_token_is_still_the_failing_one_the_fix_moves_away_from(
    theme: str, expected: float
) -> None:
    """Calibrates the arithmetic against the ratios issue 902 measured for --text-muted.

    If this drifts the contrast helper is wrong, and every pass above is suspect.
    """
    tokens = contrast.theme_tokens(theme)
    got = contrast.ratio(contrast.resolve("text-muted", tokens), surface(tokens, "bg-card"))
    assert round(got, 2) == expected


# The hint and the field label it sits under are two roles: the label names the
# field, the hint says what to expect from it. A contrast floor alone cannot keep
# them apart -- --text-secondary clears AA on every surface a hint sits on, so
# painting the hint with it passed every ratio check and still collapsed the two
# roles into one grey. The step is measured on the lightness scale, where a shared
# token is a step of zero.
HINT_SELECTORS = [
    ("vpn", ".portal-page .form-hint"),
    ("settings", ".settings-section-card .form-hint"),
]
# Surfaces a hint is drawn on: the card, the card under the pointer, and the tinted
# field or table-header fill. The dialog panel resolves to the card colour in both
# themes, which the browser suite measures on real pixels.
HINT_SURFACES = ["bg-card", "bg-card-hover", "bg-secondary"]


@pytest.mark.parametrize("theme", THEMES)
def test_hint_keeps_a_tone_of_its_own_beside_the_field_label(theme: str) -> None:
    tokens = contrast.theme_tokens(theme)
    label_token = token_name(declared_color(_css("components"), ".form-label"))
    label = contrast.resolve(label_token, tokens)
    label_lightness = contrast.lightness(label)
    card = surface(tokens, "bg-card")
    for sheet, selector in HINT_SELECTORS:
        hint_token = token_name(declared_color(_css(sheet), selector))
        hint = contrast.resolve(hint_token, tokens)
        assert hint != label, (
            f"{selector} paints the hint {hint} with the field label's own colour in "
            f"the {theme} theme, so the two roles read as one"
        )
        step = abs(contrast.lightness(hint) - label_lightness)
        assert step >= contrast.MIN_ROLE_LIGHTNESS_STEP, (
            f"{selector} {hint} sits {step:.1f} L* from the field label {label} in the "
            f"{theme} theme, under the {contrast.MIN_ROLE_LIGHTNESS_STEP} L* step"
        )
        for bg_name in HINT_SURFACES:
            got = contrast.ratio(hint, surface(tokens, bg_name))
            assert got >= contrast.AA_TEXT, (
                f"{selector} uses --{hint_token} ({hint}) on --{bg_name} in the "
                f"{theme} theme: {got:.2f}:1, below {contrast.AA_TEXT}:1"
            )
        assert contrast.ratio(hint, card) < contrast.ratio(label, card), (
            f"{selector} {hint} is not quieter than the field label {label} on the card "
            f"in the {theme} theme; the hint must stay the subordinate role"
        )


# Every other text role this delivery must leave alone: the label itself, muted
# metadata, placeholders, badges, the Settings card variants, body text and the
# disabled treatment. Each is pinned to the value it resolved to before the change,
# so "nothing else moved" is asserted rather than assumed.
UNCHANGED_ROLES = [
    ("components", ".form-label", "color", "var(--text-secondary)"),
    ("vpn", ".text-muted", "color", "var(--text-muted)"),
    ("components", ".form-input::placeholder", "color", "var(--text-muted)"),
    ("components", ".badge-secondary", "color", "var(--text-secondary)"),
    ("base", "body", "color", "var(--text-primary)"),
    ("settings", ".settings-section-card .info-card-label", "color", "var(--text-secondary)"),
    ("settings", ".settings-section-card .text-muted", "color", "var(--text-secondary)"),
    ("settings", ".settings-section-card .data-table th", "color", "var(--text-secondary)"),
    (
        "settings",
        ".settings-section-card .form-input::placeholder",
        "color",
        "var(--text-secondary)",
    ),
    ("components", ".btn:disabled", "opacity", "0.5"),
]


@pytest.mark.parametrize("sheet,selector,property,expected", UNCHANGED_ROLES)
def test_roles_outside_the_hint_keep_their_value(
    sheet: str, selector: str, property: str, expected: str
) -> None:
    got = declared(_css(sheet), selector, property)
    assert got == expected, (
        f"{selector} {property} = {got!r} in {sheet}.css, want {expected!r}: this "
        "delivery changes the hint's tone only"
    )


# The two pages that render outside the portal shell cannot inherit the shared
# `.portal-page .form-hint` rule, so they carry the hint colour inline. They must
# carry the same role value, or the role would be right on the panel and wrong on
# the two pages an operator meets first.
TEMPLATES_DIR = CSS_DIR.parents[1] / "templates"
STANDALONE_HINT_PAGES = ["setup.html", "change_password.html"]


@pytest.mark.parametrize("name", STANDALONE_HINT_PAGES)
def test_standalone_page_hint_carries_the_hint_role_value(name: str) -> None:
    html = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
    inline = re.findall(r'<div class="form-hint" style="([^"]*)"', html)
    assert inline, f"{name}: no inline .form-hint declaration to check"
    for style in inline:
        colours = re.findall(r"(?<![-\w])color:\s*([^;]+);", style)
        assert colours, f"{name}: inline .form-hint without a colour: {style!r}"
        for value in colours:
            assert value.strip() == "var(--text-tertiary)", (
                f"{name}: inline hint colour is {value.strip()!r}; the standalone pages "
                "must use the same hint role value as the shared page rule"
            )


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
