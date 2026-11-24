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


def rule_body(css: str, selector: str) -> str:
    """Every declaration block that lists `selector`, in cascade order.

    A grouped rule repeats the selector, so a presence assertion has to read all of
    them: the last block for `.policy-answer-action` is the one that cancels its
    motion, not the one that sets its wrapping.
    """
    bodies = [
        decls
        for head, decls in _RULE_RE.findall(css)
        if selector in [" ".join(part.split()) for part in head.split(",")]
    ]
    assert bodies, f"no rule declares {selector!r}"
    return "\n".join(bodies)


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


# The Transferred column's not-measured state declares its own colour on the
# sessions row rather than borrowing the shared muted token: that token is
# 2.95:1 in the dark theme and 2.56:1 in the light theme on the card the row is
# drawn on. The shared .form-hint style is issue 977's subject, so this cell owns
# its own rule. Both surfaces the text can sit on are measured: the row as
# rendered, and the row under the pointer.
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("bg_name", ["bg-card", "bg-card-hover"])
def test_transferred_missing_state_meets_aa_on_the_session_row(theme: str, bg_name: str) -> None:
    tokens = contrast.theme_tokens(theme)
    declared = declared_color(_css("vpn"), ".vpn-transferred-missing")
    name = token_name(declared)
    got = contrast.ratio(contrast.resolve(name, tokens), surface(tokens, bg_name))
    assert got >= contrast.AA_TEXT, (
        f".vpn-transferred-missing uses --{name} "
        f"({contrast.resolve(name, tokens)}) on --{bg_name} in the {theme} theme: "
        f"{got:.2f}:1, below {contrast.AA_TEXT}:1"
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


# ===== Notification feedback ink =====
# #notificationTestResult is a `.form-hint` whose ink the controller assigns inline
# (web/static/js/notifications_settings.js). An inline assignment beats the
# stylesheet rule, so the sheet cannot fix it: the ink has to be a theme role the
# controller names, and the roles have to be readable on a card in both themes.
# Before this, the controller named two custom properties that exist nowhere
# (--color-success / --color-danger) and fell back to literals #2f9e44 and #e5484d,
# which measure 3.45:1 and 3.91:1 on the white card.
STATUS_TEXT_TOKENS = ["text-success", "text-danger"]
FEEDBACK_JS = CSS_DIR.parents[1] / "static" / "js" / "notifications_settings.js"
STATUS_SURFACES = ["bg-card", "bg-card-hover", "bg-secondary"]


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("name", STATUS_TEXT_TOKENS)
def test_status_ink_meets_aa_on_the_card(theme: str, name: str) -> None:
    tokens = contrast.theme_tokens(theme)
    assert name in tokens, f"--{name} is not defined for the {theme} theme"
    ink = contrast.resolve(name, tokens)
    for bg_name in STATUS_SURFACES:
        got = contrast.ratio(ink, surface(tokens, bg_name))
        assert got >= contrast.AA_TEXT, (
            f"--{name} ({ink}) on --{bg_name} in the {theme} theme: {got:.2f}:1, "
            f"below {contrast.AA_TEXT}:1"
        )


def test_status_ink_is_declared_in_the_token_file_and_used_only_by_the_feedback() -> None:
    """One declaration site, one consumer — the check the review asked for.

    A role that spreads by accident is how a palette drifts; a role the feedback
    line names but the token file does not define is how this defect happened.
    """
    declared: set[str] = set()
    referenced: set[str] = set()
    for path in sorted((CSS_DIR.parents[1]).rglob("*")):
        if not path.is_file() or path.suffix not in {".css", ".js", ".html"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name in STATUS_TEXT_TOKENS:
            if re.search(rf"--{name}\s*:", text):
                declared.add(path.relative_to(CSS_DIR.parents[1]).as_posix())
            if re.search(rf"var\(\s*--{name}\b", text):
                referenced.add(path.relative_to(CSS_DIR.parents[1]).as_posix())
    assert declared == {"static/css/tokens.css", "static/css/style.css"}, (
        "the status ink must be declared once in tokens.css (and its generated "
        f"bundle), not spread around: {sorted(declared)}"
    )
    # The readouts are the second legitimate consumer: their success and failure
    # answers are status messages an operator must act on, painted on the answer
    # inset rather than on the feedback line. Every consumer is named here, so a
    # third file that reaches for the status ink still fails this guard.
    assert referenced == {
        "static/js/notifications_settings.js",
        "templates/settings_policy.html",
    }, (
        "the status ink is consumed outside its declared surfaces (the notification "
        f"feedback line and the policy readout answers): {sorted(referenced)}"
    )


def test_feedback_ink_assignment_names_a_token_and_carries_no_literal() -> None:
    source = FEEDBACK_JS.read_text(encoding="utf-8")
    assignments = re.findall(r"style\.color\s*=\s*([^;]+);", source)
    assert assignments, "notifications_settings.js no longer assigns the feedback ink"
    for value in assignments:
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", value), (
            f"the feedback ink falls back to a literal colour ({value.strip()!r}); an "
            "undefined token must fail visibly rather than paint an unreadable literal"
        )
        for name in STATUS_TEXT_TOKENS:
            assert (
                f"--{name}" in value
            ), f"the feedback ink assignment {value.strip()!r} does not name --{name}"


@pytest.mark.parametrize("theme", THEMES)
def test_status_ink_keeps_success_and_failure_distinct(theme: str) -> None:
    """A passing test and a failed one must not arrive in the same colour."""
    tokens = contrast.theme_tokens(theme)
    success = contrast.resolve("text-success", tokens)
    danger = contrast.resolve("text-danger", tokens)
    assert success != danger, f"the {theme} theme paints success and failure the same"
    assert contrast.ratio(success, danger) > 1.1, (
        f"the {theme} theme's success {success} and failure {danger} are too close "
        f"({contrast.ratio(success, danger):.2f}:1 apart)"
    )


# ===== Policy readout answers =====
# The four policy readouts paint a state as a tinted answer inset: a headline, a
# sentence, an action and a disclosure. Those roles are declared in the page
# template rather than a stylesheet, so the guards above cannot see them. Every
# colour is still a design token, and the surfaces are resolved the way the browser
# composites them: a translucent tint over the card behind it. The floors are read
# from the contrast helper, never pinned, so a palette change that breaks one of
# these roles fails here.
POLICY_TEMPLATE = CSS_DIR.parents[1] / "templates" / "settings_policy.html"
POLICY_ANSWER_STATES = ["success", "warning", "danger", "info"]
POLICY_BACKDROPS = ["bg-card", "bg-secondary"]


def policy_style() -> str:
    markup = POLICY_TEMPLATE.read_text(encoding="utf-8")
    match = re.search(r"<style>(.*?)</style>", markup, flags=re.S)
    assert match, "settings_policy.html declares no <style> block for the readouts"
    return re.sub(r"/\*.*?\*/", "", match.group(1), flags=re.S)


def flattened(top: str, bottom: str) -> str:
    """A translucent colour over an opaque one, the way the page paints it."""
    r, g, b, a = contrast.parse_color(top)
    br, bg, bb, _ = contrast.parse_color(bottom)
    return "#%02x%02x%02x" % (
        round(a * r + (1 - a) * br),
        round(a * g + (1 - a) * bg),
        round(a * b + (1 - a) * bb),
    )


def policy_color(selector: str, property: str = "color") -> str:
    css = policy_style()
    value = declared(css, selector, property)
    assert value is not None, f"the readout style declares no {property} for {selector!r}"
    return value


def answer_surface(tokens: dict[str, str], state: str, backdrop: str) -> str:
    """The composited surface of one answer state over one backdrop."""
    tint = policy_color(f'#policyRoutingCard .policy-answer[data-state="{state}"]', "background")
    assert tint.startswith("var("), f"the {state} answer paints {tint!r}, not a design token"
    return flattened(contrast.resolve(token_name(tint), tokens), surface(tokens, backdrop))


def test_policy_readout_style_names_tokens_and_no_literal_colour() -> None:
    """Every colour in the readout style is a token, so the palette stays authoritative."""
    css = policy_style()
    literals = re.findall(
        r"(?<![\w-])(#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\))", css
    )
    assert not literals, f"the readout style paints literal colours: {sorted(set(literals))}"
    # Focus is the shared rule's job. A local outline is how the previous revision
    # replaced a compliant focus ring with a translucent border token.
    assert "outline" not in css, (
        "the readout style declares its own outline; the shared :focus-visible rule "
        "is the one measured against the focus floor"
    )


def test_policy_readout_disclosure_shows_an_open_closed_state() -> None:
    """The summary's marker is suppressed by the flex layout, so a replacement is required."""
    css = policy_style()
    assert re.search(
        r"#policyRoutingCard \.policy-disclosure-summary::after\s*\{[^}]*border-right[^}]*\}",
        css,
    ), "the readout disclosure draws no open/closed indicator"
    assert re.search(
        r"#policyRoutingCard \.policy-disclosure\[open\][^{]*\.policy-disclosure-summary::after\s*\{[^}]*transform",
        css,
    ), "the readout disclosure indicator does not change when the disclosure opens"
    # No motion is introduced: the only transition this block may declare is one that
    # removes motion (the shared button's hover lift is cancelled above).
    for match in re.finditer(r"transition\s*:\s*([^;]+);", css):
        assert match.group(1).strip() == "none", (
            f"the readout style sets up a transition ({match.group(1).strip()!r}); movement "
            "must not be introduced for readers who asked for reduced motion"
        )
    assert "animation" not in css and "@keyframes" not in css, (
        "the readout style declares an animation"
    )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("state", POLICY_ANSWER_STATES)
@pytest.mark.parametrize("backdrop", POLICY_BACKDROPS)
def test_policy_answer_text_meets_aa_on_its_inset(theme: str, state: str, backdrop: str) -> None:
    """The headline and the sentence are read on the tint the state paints."""
    tokens = contrast.theme_tokens(theme)
    bg = answer_surface(tokens, state, backdrop)
    # The cascade: a state rule wins where it exists, the base rule otherwise. The
    # oracle resolves the pair rather than requiring a rule per state.
    headline = declared(
        policy_style(),
        f'#policyRoutingCard .policy-answer[data-state="{state}"] .policy-answer-headline',
        "color",
    ) or policy_color("#policyRoutingCard .policy-answer-headline")
    roles = {
        "headline": headline,
        "body": policy_color("#policyRoutingCard .policy-answer-body"),
    }
    for role, value in roles.items():
        name = token_name(value)
        got = contrast.ratio(contrast.resolve(name, tokens), bg)
        assert got >= contrast.AA_TEXT, (
            f"the {state} answer's {role} uses --{name} on its {backdrop} inset in the "
            f"{theme} theme: {got:.2f}:1, below {contrast.AA_TEXT}:1"
        )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("backdrop", POLICY_BACKDROPS)
def test_policy_disclosure_and_fact_ink_meet_aa_on_the_panel(theme: str, backdrop: str) -> None:
    tokens = contrast.theme_tokens(theme)
    bg = surface(tokens, backdrop)
    for selector in ("#policyRoutingCard .policy-disclosure-summary", "#policyRoutingCard .policy-raw"):
        name = token_name(policy_color(selector))
        got = contrast.ratio(contrast.resolve(name, tokens), bg)
        assert got >= contrast.AA_TEXT, (
            f"{selector} uses --{name} on --{backdrop} in the {theme} theme: {got:.2f}:1"
        )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("state", POLICY_ANSWER_STATES)
def test_policy_action_label_meets_aa_on_the_shared_button(theme: str, state: str) -> None:
    """The readout actions are the shared secondary button, so its own pair is measured.

    They sit inside a tinted inset, so the button's declared fill is what the label
    is read against; the tint behind the button is not the label's background.
    """
    tokens = contrast.theme_tokens(theme)
    sheet = _css("components")
    ink = token_name(declared_color(sheet, ".btn-secondary"))
    fill = declared(sheet, ".btn-secondary", "background")
    hover = declared(sheet, ".btn-secondary:hover", "background")
    assert fill and hover, "the shared secondary button lost its fill or hover fill"
    for value in (fill, hover):
        name = token_name(value)
        got = contrast.ratio(contrast.resolve(ink, tokens), contrast.resolve(name, tokens))
        assert got >= contrast.AA_TEXT, (
            f"the readout action label --{ink} on --{name} in the {theme} theme: "
            f"{got:.2f}:1, below {contrast.AA_TEXT}:1"
        )
    # The readout's own hover rule is what wins: the shared `a:hover` ink is the
    # accent (0,1,1) and would silently re-take the label at hover without it.
    hovered = policy_color("#policyRoutingCard .policy-answer-action:hover")
    assert hovered == "var(--text-primary)", (
        "the readout action's hover ink is no longer the readable one: " + hovered
    )
    hover_got = contrast.ratio(
        contrast.resolve(token_name(hovered), tokens),
        contrast.resolve(token_name(hover), tokens),
    )
    assert hover_got >= contrast.AA_TEXT, (
        f"the hovered readout action in the {theme} theme measures {hover_got:.2f}:1 on "
        f"its hover fill, below {contrast.AA_TEXT}:1"
    )
    # And the shared rule it overrides really is the failing ink.
    shared_hover = declared_color(_css("base"), "a:hover")
    shared_got = contrast.ratio(
        contrast.resolve(token_name(shared_hover), tokens),
        contrast.resolve(token_name(hover), tokens),
    )
    assert shared_got < contrast.AA_TEXT, (
        "the shared link hover ink now clears the floor on the button fill; the scoped "
        "override can be retired if so"
    )
    # And the action really is that button, not a look-alike.
    markup = POLICY_TEMPLATE.read_text(encoding="utf-8")
    assert 'class="btn btn-secondary policy-answer-action"' in markup, (
        "the readout actions no longer use the shared secondary button treatment"
    )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("state", POLICY_ANSWER_STATES)
@pytest.mark.parametrize("backdrop", POLICY_BACKDROPS)
def test_policy_focus_ring_clears_the_non_text_floor(theme: str, state: str, backdrop: str) -> None:
    """The shared focus ring is what a keyboard operator sees on a readout control."""
    tokens = contrast.theme_tokens(theme)
    focus_declarations = _focus_declarations()
    assert focus_declarations, "base.css declares no :focus-visible rule"
    bg = answer_surface(tokens, state, backdrop)
    for head, outline in focus_declarations:
        found = re.search(r"var\(--([\w-]+)\)", outline)
        assert found, f"{head}: outline {outline!r} names no token"
        got = contrast.ratio(contrast.resolve(found.group(1), tokens), bg)
        assert got >= contrast.AA_NON_TEXT, (
            f"{head}: --{found.group(1)} on the {state} answer inset over --{backdrop} in the "
            f"{theme} theme is {got:.2f}:1, below {contrast.AA_NON_TEXT}:1"
        )


# ===== Readout action targets =====
# The review measured these in a browser; these are the structural halves that keep a
# later edit from undoing the fix, and the browser case in the policy suite is the
# rendered measurement.
def test_policy_readout_actions_wrap_inside_their_column() -> None:
    """A localized label wraps; it is never clipped and never overflows its card."""
    body = rule_body(policy_style(), "#policyRoutingCard .policy-answer-action")
    assert "white-space: normal" in body, (
        "the readout action inherits the shared button's nowrap, so a long localized "
        "label cannot fit the column a phone gives it"
    )
    assert "overflow-wrap: anywhere" in body, (
        "a long unbreakable translated word would still push the control out"
    )
    assert "max-width: 100%" in body, "the action is not bounded by its container"
    assert "overflow: hidden" not in body, (
        "the action hides its overflow instead of wrapping: the label would be cut"
    )
    # The retry is a real button in the same panel, so it has to carry the same class.
    markup = POLICY_TEMPLATE.read_text(encoding="utf-8")
    assert re.search(
        r'<button[^>]*class="btn btn-secondary policy-answer-action"[^>]*id="policySyncNowBtn"',
        markup,
    ), "the retry button does not carry the readout action treatment"


def test_policy_readout_actions_do_not_move() -> None:
    """Every readout action cancels the shared button's hover lift and transition."""
    css = policy_style()
    for state in ("", ":hover", ":active"):
        selector = f"#policyRoutingCard .policy-answer-action{state}"
        body = rule_body(css, selector)
        assert "transform: none" in body, f"{selector} keeps the shared button's lift"
    base = rule_body(css, "#policyRoutingCard .policy-answer-action")
    assert "transition: none" in base, (
        "the action keeps a transition, so it moves for a reader who asked for "
        "reduced motion"
    )


def test_policy_disclosure_marker_is_direction_independent() -> None:
    """The chevron's own shape is physical; only its placement is logical."""
    css = policy_style()
    body = rule_body(css, "#policyRoutingCard .policy-disclosure-summary::after")
    assert "border-right:" in body and "border-bottom:" in body, (
        "the marker's border pair is not the physical pair that points down in both "
        "directions"
    )
    assert "border-inline-end" not in body and "border-block-end" not in body, (
        "a logical border mirrors in RTL while the rotation does not, so the marker "
        "points sideways there"
    )
    assert "margin-inline-start: auto" in body, (
        "the marker is not placed at the inline end"
    )
    assert not re.search(r'\[dir="rtl"\][^{]*policy-disclosure-summary::after', css), (
        "the marker needs a direction-specific override again: its shape should not "
        "depend on the writing direction"
    )
