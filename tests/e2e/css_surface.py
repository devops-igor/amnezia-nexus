"""Which CSS belongs to the new Settings surface, and how to set it aside.

Deliberately free of Playwright imports so the offline suite can import it.

The computed-style differential compares the modular sheets with the frozen
pre-split reference (fixtures/style.pre-505.css). That reference has to stay
byte-identical: a rule copied into it from the sheet under test reads the same
on both sides, so a wrong value in that rule could never show up as a
difference. The Settings layout classes did not exist when the reference was
cut, so they are named here and set aside on the modular side only. Their
values are checked in tests/e2e/test_settings.py against expectations derived
from the design tokens, not against a copy of themselves.
"""
from __future__ import annotations

import re

# Every class the modular sheets define that the frozen reference does not.
# tests/test_css_reference_frozen.py fails if this set and that difference ever
# disagree, so the exemption cannot grow or shrink without a visible edit.
SETTINGS_SURFACE_CLASSES = frozenset({
    "mb-md", "mb-sm", "mt-sm", "spinner-sm",
    "settings-bar", "settings-bullets",
    "settings-button-row", "settings-button-row-tight",
    "settings-card-header-split", "settings-card-stacked",
    "settings-choice", "settings-choice-hint", "settings-choice-title",
    "settings-cluster", "settings-divider", "settings-field-label",
    "settings-field-pair", "settings-fieldset", "settings-flush",
    "settings-grid", "settings-inline", "settings-list",
    "settings-list-title", "settings-loading", "settings-notice",
    "settings-immediate", "settings-notice-danger", "settings-notice-icon",
    "settings-notice-spaced", "settings-notice-success",
    "settings-notice-warning", "settings-offset", "settings-row",
    "settings-row-card", "settings-source-stats", "settings-stack",
    "settings-stack-sm", "settings-subsection",
    "settings-subsection-header", "settings-subsection-spaced",
    "settings-subsection-title", "settings-toolbar",
    "upstream-checked-at", "upstream-component", "upstream-component-link",
    "upstream-component-meta", "upstream-component-mono",
    "upstream-component-name", "upstream-component-row",
    "upstream-component-sep", "upstream-component-title", "upstream-footer",
})

# Rules that pair a legacy class with a Settings card and exist only to size or
# place controls inside it. Named exactly, so no other legacy rule is set aside by
# accident. The last one takes an empty unsaved badge out of the layout without
# hiding it, which keeps its live region in the accessibility tree.
SETTINGS_SCOPED_OVERRIDES = frozenset({
    ".settings-section-card .btn",
    ".settings-section-card .btn-sm",
    ".settings-card-header .badge",
    ".settings-section-card [data-dirty]:empty",
})

# The three spacing utilities the Settings templates use. They live in vpn.css,
# next to the legacy utilities, so they are removed by exact selector.
SETTINGS_UTILITY_SELECTORS = frozenset({".mt-sm", ".mb-sm", ".mb-md"})

_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_RULE_RE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_CLASS_RE = re.compile(r"\.([A-Za-z_][\w-]*)")


def strip_comments(css: str) -> str:
    return _COMMENT_RE.sub("", css)


def selector_lists(css: str) -> list[str]:
    """Every selector list in css, including the ones inside an @media block."""
    out = []
    for match in _RULE_RE.finditer(strip_comments(css)):
        head = match.group(1).strip()
        if head and not head.startswith("@"):
            out.append(" ".join(head.split()))
    return out


def individual_selectors(css: str) -> list[str]:
    """Every selector of every rule, with comma-separated groups split apart."""
    return [
        selector
        for head in selector_lists(css)
        for selector in (part.strip() for part in head.split(","))
        if selector
    ]


def classes_in(css: str) -> set[str]:
    return set(_CLASS_RE.findall(" ".join(selector_lists(css))))


def surface_violations(settings_css: str) -> list[str]:
    """Selectors in the Settings sheet that are neither new-surface nor a named override.

    A legacy selector hiding in that sheet would be set aside without anyone
    deciding it should be, so the offline guard requires this to be empty.
    """
    bad = []
    for selector in individual_selectors(settings_css):
        if selector in SETTINGS_SCOPED_OVERRIDES:
            continue
        if set(_CLASS_RE.findall(selector)) & SETTINGS_SURFACE_CLASSES:
            continue
        bad.append(selector)
    return bad


def _drop_utility_rules(css: str) -> tuple[str, int]:
    removed = 0

    def repl(match: re.Match) -> str:
        nonlocal removed
        head = " ".join(match.group(1).split())
        if head in SETTINGS_UTILITY_SELECTORS:
            removed += 1
            return ""
        return match.group(0)

    return _RULE_RE.sub(repl, css), removed


def legacy_view(sheets: dict[str, str]) -> dict[str, str]:
    """The modular sheets as the frozen reference can be compared with them.

    Removes exactly the Settings surface: the whole settings sheet and the three
    named utilities in vpn.css. Every other byte is untouched, so the comparison
    still covers every legacy selector, including how legacy rules interact with
    the elements the Settings templates render.
    """
    out = {name: css for name, css in sheets.items() if name != "settings"}
    if "vpn" in out:
        out["vpn"], removed = _drop_utility_rules(out["vpn"])
        if removed != len(SETTINGS_UTILITY_SELECTORS):
            raise AssertionError(
                f"expected to set aside {len(SETTINGS_UTILITY_SELECTORS)} utility rules in vpn.css, found {removed}"
            )
    return out
