"""Which CSS belongs to a surface the frozen reference never had, and how to set it aside.

Deliberately free of Playwright imports so the offline suite can import it.

The computed-style differential compares the modular sheets with the frozen
pre-split reference (fixtures/style.pre-505.css). That reference has to stay
byte-identical: a rule copied into it from the sheet under test reads the same
on both sides, so a wrong value in that rule could never show up as a
difference. Classes that did not exist when the reference was cut are named here
and set aside on the modular side only, so they are never compared with a copy
of themselves. What replaces that comparison differs by surface: the Settings
values are checked in tests/e2e/test_settings.py against expectations derived
from the design tokens, and the VPN health values in the web package's tests
(reduced-motion, RTL logical properties, 44px targets, and a ban on new global
VPN custom properties).
"""
from __future__ import annotations

import re

# Every class the Settings surface adds beyond the frozen reference.
# tests/test_css_reference_frozen.py fails if SURFACE_CLASSES and that difference
# ever disagree, so the exemption cannot grow or shrink without a visible edit.
# Kept separate from VPN_SURFACE_CLASSES because the Settings sheet is only
# allowed to hold Settings-surface selectors (see surface_violations): a legacy
# selector sharing a rule with a VPN class must still be rejected there.
SETTINGS_SURFACE_CLASSES = frozenset({
    "mb-md", "mb-sm", "mt-sm", "spinner-sm",
    # The per-client flows table's cell disclosure: the row keeps four cells and
    # reveals the rest of a fact in place, which the reference never had.
    "cell-detail", "cell-detail-toggle",
    "settings-bar", "settings-bullets",
    "settings-button-row", "settings-button-row-tight",
    "settings-card-header-split", "settings-card-stacked",
    "settings-choice", "settings-choice-hint", "settings-choice-title",
    "settings-cluster", "settings-divider", "settings-field-label",
    "settings-field-pair", "settings-fieldset", "settings-flush",
    # The Gigahost status widget: its row, the two sides of that row, the progression
    # badge and its steps. The rules lay the row out and mark which step is in flight,
    # and the reference predates the widget. Settings-only, so they are named here
    # rather than with the VPN surface.
    "gigahost-order-identity", "gigahost-order-row", "gigahost-order-state",
    "gigahost-order-status", "gigahost-order-status-stage",
    "gigahost-order-status-toggle",
    "settings-grid", "settings-group", "settings-group-title", "settings-inline",
    "settings-list",
    "settings-list-title", "settings-loading", "settings-notice",
    "settings-immediate", "settings-notice-danger", "settings-notice-icon",
    "settings-notice-spaced", "settings-notice-success",
    "settings-notice-warning", "settings-offset", "settings-row",
    "settings-result", "settings-row-card", "settings-source-stats", "settings-stack",
    "settings-stack-sm", "settings-subheading", "settings-subnav",
    "settings-subnav-link", "settings-subnav-list", "settings-subsection",
    "settings-subsection-header", "settings-subsection-spaced",
    "settings-subsection-title", "settings-toolbar",
    "upstream-checked-at", "upstream-component", "upstream-component-link",
    "upstream-component-meta", "upstream-component-mono",
    "upstream-component-name", "upstream-component-row",
    "upstream-component-sep", "upstream-component-title", "upstream-footer",
})

# Every class the VPN health surface adds beyond the frozen reference. The
# reference predates the health panel, the four-signal overview, the Advanced
# Diagnostics disclosure and the configuration strip, so their selectors are not
# in it. Named here so the differential sets them aside by name instead of
# comparing them against a copy of themselves.
VPN_SURFACE_CLASSES = frozenset({
    "vpn-alerts", "vpn-backend-select", "vpn-card-head",
    "vpn-chart", "vpn-chart-axis", "vpn-chart-body", "vpn-chart-caption",
    "vpn-chart-grid", "vpn-chart-tooltip", "vpn-chevron",
    "vpn-config", "vpn-config-body", "vpn-config-field", "vpn-config-grow",
    "vpn-config-label",
    "vpn-diag-entry", "vpn-diag-fold", "vpn-diag-header", "vpn-diag-heading",
    "vpn-diag-section", "vpn-diagnostics",
    "vpn-empty",
    # Focus and scroll targets the page moves to programmatically. The reference
    # has no such rule, so nothing here could be a copy of it.
    "vpn-focus-target", "vpn-region-target",
    "vpn-fold-actions", "vpn-fold-label",
    "vpn-health", "vpn-health-copy", "vpn-health-counts", "vpn-health-head",
    "vpn-health-live", "vpn-health-main", "vpn-health-summary",
    "vpn-health-title",
    "vpn-io-down", "vpn-io-up",
    "vpn-issue", "vpn-issue-action", "vpn-issue-copy", "vpn-issue-entity",
    "vpn-issue-list", "vpn-issue-severity", "vpn-issue-title",
    "vpn-metrics", "vpn-modal-footer", "vpn-modal-hint",
    # Renders the literal words "not measured" where a signal could not be read,
    # so an absent window cannot be mistaken for a zero.
    "vpn-not-measured",
    "vpn-numeric", "vpn-overview", "vpn-page-title",
    "vpn-route-table-region", "vpn-secondary", "vpn-signal-mismatch",
    "vpn-signal-unit", "vpn-subsection", "vpn-table-card", "vpn-table-loading",
    # The Transferred column's own states: the value is one isolated, unbreakable
    # token, and the not-measured label carries its own colour and wrapping.
    "vpn-transferred-head", "vpn-transferred-missing", "vpn-transferred-value",
    # Accessible-name sink for the problem announcement.
    "vpn-visually-hidden",
    "vpn-windows",
})

# Every class the page-content surface adds beyond the frozen reference. The
# shell's content area carries it so the two-step button scale reaches the
# controls a page renders, which the reference predates. `nav-tab` is here for the
# same reason: the server page declares it in a template style block, so the
# frozen reference has never known it, and the page-content scale names it.
# `nav-group` is the sidebar's labelled group: the reference predates it, and the
# rule that lays the group out lives in the shell's own layout sheet, so it is a
# page-shell class rather than one of the VPN page's own.
PORTAL_SURFACE_CLASSES = frozenset({
    "portal-page",
    "nav-tab",
    "nav-group",
})

# Every class newly introduced beyond the frozen reference, whichever sheet holds
# it. tests/test_css_reference_frozen.py asserts this equals the real difference
# between the modular sheets and the reference, so it cannot be padded.
SURFACE_CLASSES = SETTINGS_SURFACE_CLASSES | VPN_SURFACE_CLASSES | PORTAL_SURFACE_CLASSES

# Rules that pair a legacy class with a Settings card and exist only to size or
# place controls inside it. Named exactly, so no other legacy rule is set aside by
# accident. The last one takes an empty unsaved badge out of the layout without
# hiding it, which keeps its live region in the accessibility tree.
SETTINGS_SCOPED_OVERRIDES = frozenset({
    ".settings-section-card .btn",
    ".settings-section-card .btn-sm",
    ".settings-card-header .badge",
    ".settings-section-card [data-dirty]:empty",
    # Informative text inside the cards uses --text-secondary instead of the
    # reference's --text-muted, which fails the 4.5:1 minimum. A deliberate
    # difference from the reference, so it is named here rather than compared.
    ".settings-section-card .form-hint",
    ".settings-section-card .info-card-label",
    ".settings-section-card .text-muted",
    ".settings-section-card .data-table th",
    ".settings-section-card .form-input::placeholder",
})

# The three spacing utilities the Settings templates use. They live in vpn.css,
# next to the legacy utilities. Kept as exact selectors so a regression that
# makes one of them unreachable is reported as a missing utility rather than
# silently absorbed by the broader surface sweep.
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


def _split_selectors(head: str) -> list[str]:
    """The individual selectors of a rule head, with comments removed.

    A comment between rules is part of the head `_RULE_RE` captures, and comment
    prose can contain a comma. Splitting the raw head would then turn a sentence
    into a "selector" and drop the real one, so the comments go first.
    """
    return [part.strip() for part in strip_comments(head).split(",") if part.strip()]


def _drop_surface(css: str, surface: frozenset[str] | set[str]) -> tuple[str, list[str]]:
    """Set aside every selector of css that uses a class from surface.

    A selector list is rewritten rather than deleted when only some of its
    branches are new: `td[data-backend-name]:focus-visible` shares a rule with
    `.vpn-focus-target:focus-visible`, and dropping the whole rule would take a
    legacy selector out of the comparison with it. A rule whose every branch is
    new is removed entirely. Bytes outside a rewritten rule are untouched.
    """
    removed: list[str] = []

    def repl(match: re.Match) -> str:
        head, body = match.group(1), match.group(2)
        if " ".join(strip_comments(head).split()).startswith("@"):
            return match.group(0)
        selectors = _split_selectors(head)
        if not selectors:
            return match.group(0)
        is_surface = [bool(set(_CLASS_RE.findall(s)) & surface) for s in selectors]
        if not any(is_surface):
            return match.group(0)
        removed.extend(s for s, new in zip(selectors, is_surface) if new)
        kept = [s for s, new in zip(selectors, is_surface) if not new]
        if not kept:
            return ""
        return ", ".join(kept) + " {" + body + "}"

    return _RULE_RE.sub(repl, css), removed


def legacy_view(sheets: dict[str, str]) -> dict[str, str]:
    """The modular sheets as the frozen reference can be compared with them.

    Removes the surfaces the reference never had: the whole settings sheet, and
    every selector in the remaining sheets that uses one of SURFACE_CLASSES. A
    sheet with no such selector is returned byte-identical, so the comparison
    still covers every legacy selector, including how legacy rules interact with
    the elements the new templates render.
    """
    out: dict[str, str] = {}
    for name, css in sheets.items():
        if name == "settings":
            continue
        view, removed = _drop_surface(css, SURFACE_CLASSES)
        if name == "vpn":
            missing = sorted(SETTINGS_UTILITY_SELECTORS - set(removed))
            if missing:
                raise AssertionError(
                    "expected to set aside "
                    f"{sorted(SETTINGS_UTILITY_SELECTORS)} in vpn.css, never found {missing}"
                )
        out[name] = view
    return out


# The computed-style differential takes the sheets it compares from the shell
# template's link list, not from a fixed list, so a link the parser cannot read
# removes a sheet from the comparison instead of failing. A stylesheet identified
# by its own bytes carries a quoted argument inside a quoted attribute, which is
# not valid HTML until that action is resolved, so this module resolves it — and
# it lives here, beside the rest of the Playwright-free surface logic, so the
# offline suite can check the resolver without a browser.
ASSET_URL_ACTION = re.compile(r'\{\{\s*asset_url\s+"(/static/css/[\w.-]+)"\s*\}\}')


def resolve_asset_actions(html: str) -> str:
    """Replace each content-derived stylesheet action with its path plus a sentinel.

    The sentinel is deliberately not a version: it only keeps the tag parseable
    and marks that the real identity comes from the stylesheet's bytes.
    """
    return ASSET_URL_ACTION.sub(r"\1?v=@asset-bytes@", html)
