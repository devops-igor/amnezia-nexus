"""Offline contract between the Naive decoy template default and its E2E oracle.

The shipped Naive install modal renders ``#installNaiveDecoy`` with the Minecraft
theme pre-selected (web/templates/server.html). The Playwright suite asserts that
default and then echoes it in the install payload. Before this check, nothing
offline tied the two together: a template default change was only observable in a
live E2E run. These tests are hermetic (stdlib + pytest, no browser, no network).
"""

from __future__ import annotations

import ast
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO_ROOT / "web/templates/server.html"
E2E_TEST_PATH = REPO_ROOT / "tests/e2e/test_multiprotocol_server.py"

SELECT_ID = "installNaiveDecoy"
MODAL_TEST_NAME = "test_naiveproxy_install_modal_ui_flow"
PAYLOAD_KEY = "decoy_template"

# The established shipped default (366ac26, #692/#693). Explicit contract, not a
# snapshot of whatever the template or a live DOM currently reports.
EXPECTED_DECOY = "minecraft"


class _DecoySelectParser(HTMLParser):
    """Collect ``<option>`` attributes of the decoy ``<select>`` element."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._inside_select = False
        self.options: List[Dict[str, object]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        if tag == "select" and attributes.get("id") == SELECT_ID:
            self._inside_select = True
        elif tag == "option" and self._inside_select:
            self.options.append(
                {
                    "value": attributes.get("value"),
                    "selected": "selected" in attributes,
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "select" and self._inside_select:
            self._inside_select = False


def template_selected_decoy(template_html: str) -> str:
    """Return the single pre-selected decoy theme value rendered by the template."""
    parser = _DecoySelectParser()
    parser.feed(template_html)
    selected = [option["value"] for option in parser.options if option["selected"]]
    assert len(selected) == 1, (
        f"#{SELECT_ID} must pre-select exactly one decoy template, found {selected!r}"
    )
    value = selected[0]
    assert isinstance(value, str) and value, f"#{SELECT_ID} selected option has no value"
    return value


def _modal_locator_ids(function: ast.FunctionDef) -> Dict[str, str]:
    """Map local names assigned from ``modal.locator("<selector>")`` to selectors."""
    mapping: Dict[str, str] = {}
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target, value = node.targets[0], node.value
        if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
            continue
        func = value.func
        if not isinstance(func, ast.Attribute) or func.attr != "locator":
            continue
        if len(value.args) != 1 or not isinstance(value.args[0], ast.Constant):
            continue
        selector = value.args[0].value
        if isinstance(selector, str):
            mapping[target.id] = selector
    return mapping


def e2e_asserted_decoys(test_source: str) -> Tuple[str, str]:
    """Return the decoy default asserted in the modal and in the install payload."""
    module = ast.parse(test_source)
    function = next(
        (
            node
            for node in ast.walk(module)
            if isinstance(node, ast.FunctionDef) and node.name == MODAL_TEST_NAME
        ),
        None,
    )
    assert function is not None, f"{MODAL_TEST_NAME} not found in E2E suite"
    locator_ids = _modal_locator_ids(function)

    modal_values: List[str] = []
    payload_values: List[str] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "to_have_value"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                receiver = func.value
                if (
                    isinstance(receiver, ast.Call)
                    and isinstance(receiver.func, ast.Name)
                    and receiver.func.id == "expect"
                    and len(receiver.args) == 1
                    and isinstance(receiver.args[0], ast.Name)
                    and locator_ids.get(receiver.args[0].id) == f"#{SELECT_ID}"
                ):
                    modal_values.append(node.args[0].value)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left = node.left
            if not (isinstance(left, ast.Call) and isinstance(left.func, ast.Attribute)):
                continue
            if left.func.attr != "get" or len(left.args) != 1:
                continue
            if not (isinstance(left.args[0], ast.Constant) and left.args[0].value == PAYLOAD_KEY):
                continue
            comparator = node.comparators[0]
            if (
                isinstance(node.ops[0], ast.Eq)
                and isinstance(comparator, ast.Constant)
                and isinstance(comparator.value, str)
            ):
                payload_values.append(comparator.value)

    assert len(modal_values) == 1, (
        f"expected one #{SELECT_ID} default assertion in {MODAL_TEST_NAME}, "
        f"found {modal_values!r}"
    )
    assert len(payload_values) == 1, (
        f"expected one {PAYLOAD_KEY!r} payload assertion in {MODAL_TEST_NAME}, "
        f"found {payload_values!r}"
    )
    return modal_values[0], payload_values[0]


def assert_decoy_contract(template_html: str, test_source: str) -> None:
    """Fail when the template default and the E2E expectations disagree."""
    selected = template_selected_decoy(template_html)
    assert selected == EXPECTED_DECOY, (
        f"shipped template selects {selected!r}, but the established decoy default is "
        f"{EXPECTED_DECOY!r}"
    )
    modal_expected, payload_expected = e2e_asserted_decoys(test_source)
    assert modal_expected == selected, (
        f"E2E asserts #{SELECT_ID} default {modal_expected!r} but the shipped template "
        f"selects {selected!r}"
    )
    assert payload_expected == selected, (
        f"E2E asserts payload {PAYLOAD_KEY} {payload_expected!r} but the shipped template "
        f"selects {selected!r}"
    )


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_template_ships_minecraft_decoy_default() -> None:
    """The shipped modal pre-selects the established Minecraft decoy theme."""
    assert template_selected_decoy(_read(TEMPLATE_PATH)) == EXPECTED_DECOY


def test_e2e_expectations_match_shipped_template() -> None:
    """The live UI oracle asserts the template's actual default, not the retired one."""
    template_html = _read(TEMPLATE_PATH)
    test_source = _read(E2E_TEST_PATH)
    assert_decoy_contract(template_html, test_source)
    assert e2e_asserted_decoys(test_source) == (EXPECTED_DECOY, EXPECTED_DECOY)


def test_contract_rejects_retired_default_expectation() -> None:
    """The pre-366ac26 assertion form fails the contract check."""
    template_html = _read(TEMPLATE_PATH)
    stale_expectation = (
        _read(E2E_TEST_PATH)
        .replace('to_have_value("minecraft")', 'to_have_value("default")')
        .replace(f'"{PAYLOAD_KEY}") == "minecraft"', f'"{PAYLOAD_KEY}") == "default"')
    )
    with pytest.raises(AssertionError, match="selects 'minecraft'"):
        assert_decoy_contract(template_html, stale_expectation)


def test_contract_rejects_template_default_drift() -> None:
    """A template default change without a matching oracle update fails the check."""
    drifted_template = _read(TEMPLATE_PATH).replace(
        '<option value="minecraft" selected>', '<option value="default" selected>', 1
    )
    with pytest.raises(AssertionError):
        assert_decoy_contract(drifted_template, _read(E2E_TEST_PATH))


def test_contract_rejects_coordinated_template_and_test_drift() -> None:
    """A matching template+test change to a different theme still violates the contract."""
    drifted_template = _read(TEMPLATE_PATH).replace(
        '<option value="minecraft" selected>', '<option value="jetpack-dash" selected>', 1
    )
    drifted_source = (
        _read(E2E_TEST_PATH)
        .replace('to_have_value("minecraft")', 'to_have_value("jetpack-dash")')
        .replace(f'"{PAYLOAD_KEY}") == "minecraft"', f'"{PAYLOAD_KEY}") == "jetpack-dash"')
    )
    with pytest.raises(AssertionError, match="established decoy default"):
        assert_decoy_contract(drifted_template, drifted_source)


@pytest.mark.parametrize(
    "retired",
    ['<option value="minecraft">'],
    ids=["selected-attribute-removed"],
)
def test_contract_rejects_missing_selection(retired: str) -> None:
    """The oracle cannot silently fall back to whatever the browser picks first."""
    template_html = _read(TEMPLATE_PATH).replace('<option value="minecraft" selected>', retired, 1)
    with pytest.raises(AssertionError, match="exactly one decoy template"):
        template_selected_decoy(template_html)
