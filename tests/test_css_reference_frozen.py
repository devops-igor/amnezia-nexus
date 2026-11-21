"""Offline guards for the frozen CSS reference and the Settings exemption.

The computed-style differential compares the modular sheets with
tests/e2e/fixtures/style.pre-505.css. That comparison only means something while
the reference is the original, so these tests need no browser and run in the
offline job:

* the reference is byte-identical to its #505 blob;
* it contains none of the new Settings classes (nothing was copied into it);
* the exemption in tests/e2e/css_surface.py is exactly the difference between the
  modular sheets and the reference, no larger and no smaller;
* what the differential still compares keeps every legacy rule, and a legacy
  value changed in a modular sheet is still present in what is compared.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from tests.e2e import css_surface

REPO_ROOT = Path(__file__).resolve().parents[1]
CSS_DIR = REPO_ROOT / "web" / "static" / "css"
FIXTURE = REPO_ROOT / "tests" / "e2e" / "fixtures" / "style.pre-505.css"
SHEETS = ["tokens", "base", "layout", "components", "tables", "server", "vpn", "settings"]

# git blob 8756aa59... as committed by #505, and the sha256 of the same bytes.
FIXTURE_SHA256 = "463cf087dc7bd7745060247b2f59fc9177f2d6cca984d181ae22501ae79035c0"
FIXTURE_BYTES = 63291


def _sheets() -> dict[str, str]:
    return {name: (CSS_DIR / f"{name}.css").read_text(encoding="utf-8") for name in SHEETS}


def _fixture_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_reference_is_the_original_505_bytes() -> None:
    data = FIXTURE.read_bytes()
    assert len(data) == FIXTURE_BYTES
    assert hashlib.sha256(data).hexdigest() == FIXTURE_SHA256


def test_reference_has_no_settings_surface_rule() -> None:
    leaked = css_surface.classes_in(_fixture_text()) & css_surface.SURFACE_CLASSES
    assert not leaked, (
        f"new surface classes were copied into the frozen reference: {sorted(leaked)}"
    )


def test_exemption_is_exactly_the_difference_from_the_reference() -> None:
    modular = css_surface.classes_in("\n".join(_sheets().values()))
    reference = css_surface.classes_in(_fixture_text())
    new = modular - reference
    assert css_surface.SURFACE_CLASSES == new, {
        "exempt but not new": sorted(css_surface.SURFACE_CLASSES - new),
        "new but not exempt": sorted(new - css_surface.SURFACE_CLASSES),
    }


def test_settings_sheet_holds_only_surface_rules_and_named_overrides() -> None:
    assert css_surface.surface_violations(_sheets()["settings"]) == []


def test_what_the_differential_compares_has_no_unexplained_class() -> None:
    compared = css_surface.legacy_view(_sheets())
    assert "settings" not in compared
    extra = css_surface.classes_in("\n".join(compared.values())) - css_surface.classes_in(_fixture_text())
    assert not extra, f"classes compared against a reference that never had them: {sorted(extra)}"


def test_legacy_view_sets_aside_the_surface_without_losing_a_legacy_selector() -> None:
    """Every selector removed is a new-surface one, and the utilities are among them.

    This is the property the exemption depends on: the differential may stop
    comparing a selector only because that selector uses a class the reference
    never had. A legacy selector leaving the compared view would silently delete
    coverage, so it is asserted from the removed set rather than from a count.
    """
    sheets = _sheets()
    view = css_surface.legacy_view(sheets)
    for name in view:
        before = set(css_surface.individual_selectors(sheets[name]))
        after = set(css_surface.individual_selectors(view[name]))
        removed = before - after
        lost = sorted(
            s
            for s in removed
            if not (set(css_surface._CLASS_RE.findall(s)) & css_surface.SURFACE_CLASSES)
        )
        assert not lost, f"{name}: legacy selectors left the compared view: {lost}"
    removed_vpn = set(css_surface.individual_selectors(sheets["vpn"])) - set(
        css_surface.individual_selectors(view["vpn"])
    )
    assert css_surface.SETTINGS_UTILITY_SELECTORS <= removed_vpn
    # Sheets that define no new-surface class are compared byte for byte, so
    # their rules are not merely present but unmodified.
    assert all(view[name] == sheets[name] for name in view if name != "vpn")
    assert "vpn" in view and view["vpn"] != sheets["vpn"]


def test_a_selector_shared_with_a_new_class_keeps_its_legacy_half() -> None:
    """A mixed selector list is rewritten, not deleted, so the legacy half stays compared.

    `td[data-backend-name]:focus-visible` shares a rule with the new
    `.vpn-focus-target:focus-visible`. Dropping the whole rule with the new
    selector would take a legacy selector out of the differential unnoticed.
    """
    view = css_surface.legacy_view(_sheets())
    assert "td[data-backend-name]:focus-visible" in css_surface.individual_selectors(view["vpn"])
    assert ".vpn-focus-target:focus-visible" not in css_surface.individual_selectors(view["vpn"])


def test_a_comment_between_rules_cannot_hide_the_selector_that_follows_it() -> None:
    """Comment prose containing a comma must not be split as a selector list.

    A new-surface comment followed by a legacy rule is the shape that made an
    earlier version drop the rule after the comment.
    """
    css = (
        "/* uses .vpn-health, .vpn-overview and their children */\n"
        ".info-card-grid { gap: 4px; }\n"
    )
    view, removed = css_surface._drop_surface(css, css_surface.SURFACE_CLASSES)
    assert removed == []
    assert ".info-card-grid" in css_surface.individual_selectors(view)


def test_a_legacy_value_changed_in_a_modular_sheet_stays_in_the_compared_view() -> None:
    """The differential still sees a wrong legacy value: it is not exempted."""
    sheets = _sheets()
    mutated = dict(sheets)
    mutated["vpn"], count = re.subn(
        r"(\.info-card-grid \{[^}]*gap: )var\(--space-sm\)", r"\g<1>73px", sheets["vpn"], count=1
    )
    assert count == 1, "the legacy rule used for the mutation is gone"
    assert "gap: 73px" in css_surface.legacy_view(mutated)["vpn"]
    assert "gap: 73px" not in _fixture_text()


def test_a_wrong_settings_value_is_never_compared_with_a_copy_of_itself() -> None:
    """The earlier circularity: a wrong Settings value must not have a twin in the reference."""
    sheets = _sheets()
    mutated = dict(sheets)
    mutated["settings"], count = re.subn(r"gap: var\(--space-lg\)", "gap: 73px", sheets["settings"], count=1)
    assert count == 1
    view = css_surface.legacy_view(mutated)
    assert "settings" not in view  # not part of the legacy comparison at all
    assert "73px" not in _fixture_text()  # and there is no copy in the reference to match it


def test_exemption_rejects_a_legacy_selector_slipped_into_the_settings_sheet() -> None:
    smuggled = _sheets()["settings"] + "\n.card { padding: 0; }\n"
    assert css_surface.surface_violations(smuggled) == [".card"]


@pytest.mark.parametrize("selector", sorted(css_surface.SETTINGS_SCOPED_OVERRIDES))
def test_named_overrides_exist_in_the_settings_sheet(selector: str) -> None:
    selectors = css_surface.individual_selectors(_sheets()["settings"])
    assert selector in selectors, selector
