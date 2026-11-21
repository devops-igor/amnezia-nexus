"""Tests for the architecture-health workflow's event subscription.

The SG1 gate decides whether a pull request may cross the size ceiling from two
pieces of pull-request metadata: the `sg1-size-exception` label and a statement
under a "SG1 responsibility justification" heading in the description. Neither
act is a push, so neither triggers a `pull_request` workflow whose `types` list
is absent: GitHub then runs only `opened`, `synchronize` and `reopened`.

The consequence is that the gate's verdict belongs to a state of the pull
request that may no longer hold. The dangerous direction is withdrawal: a pull
request that passed under an exception can have the label removed or the
justification deleted and keep its green check, because no run re-assesses it.

These tests read the shipped subscription rather than restating it, so a later
edit that drops one of the six activity types fails here. The parse is
structural - the `on:` mapping is walked by indentation - because the workflow
must keep meaning what it declares, not merely contain the right words.
"""

from typing import Any, Dict, List, Optional

import pytest

from scripts.architecture_health import EXCEPTION_LABEL
from tests.test_architecture_health_pull_request import WORKFLOW_PATH, _gate_step_block

# Every act that can grant or withdraw an exception, plus the three defaults
# GitHub applies when a `types` list is absent. Both halves of the exception can
# be withdrawn independently, so `labeled` and `unlabeled` are not restricted to
# the exception label and `edited` is not restricted to the description.
EXPECTED_PULL_REQUEST_TYPES = [
    "opened",
    "synchronize",
    "reopened",
    "labeled",
    "unlabeled",
    "edited",
]

INLINE_TYPES_LINE = "types: [" + ", ".join(EXPECTED_PULL_REQUEST_TYPES) + "]"


def _uncomment(line: str) -> str:
    """Strip a YAML comment, keeping a `#` that is inside a quoted value.

    In YAML a `#` starts a comment only at the start of a line or after
    whitespace, which is the whole rule this needs.
    """
    quote: Optional[str] = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _lines(text: str) -> List[str]:
    """The workflow as logical lines: comments stripped, blank lines dropped."""
    stripped = [_uncomment(raw).rstrip() for raw in text.splitlines()]
    return [line for line in stripped if line.strip()]


def _block(lines: List[str], start: int, indent: int) -> List[str]:
    """The lines nested under the block header at `start`, one level deeper.

    A block ends at the first line at or above the header's indent, which is
    what makes this a walk of structure rather than a text search.
    """
    block: List[str] = []
    for line in lines[start + 1 :]:
        if _indent(line) <= indent:
            break
        block.append(line)
    return block


def _header(lines: List[str], indent: int, key: str) -> Optional[int]:
    """The index of the `key:` line at exactly `indent`, or None."""
    prefix = " " * indent + key + ":"
    for index, line in enumerate(lines):
        if line == prefix or line.startswith(prefix + " "):
            return index
    return None


def _items(block: List[str], indent: int, key: str) -> Optional[List[str]]:
    """The list declared under `key:` at `indent`, in either YAML spelling.

    Returns None when the key is absent. That distinction is the point: an absent
    `types:` key is not an empty subscription, it is GitHub's three-action default.
    """
    index = _header(block, indent, key)
    if index is None:
        return None
    inline = block[index][len(" " * indent) + len(key) + 1 :].strip()
    if inline:
        assert inline.startswith("[") and inline.endswith("]"), inline
        return [item.strip().strip("'\"") for item in inline[1:-1].split(",") if item.strip()]

    items: List[str] = []
    for line in _block(block, index, indent):
        stripped = line.strip()
        if not stripped.startswith("- "):
            break
        items.append(stripped[2:].strip().strip("'\""))
    return items


def _value(block: List[str], indent: int, key: str) -> Optional[str]:
    """The scalar value of `key:` at `indent`, or None when the key is absent."""
    index = _header(block, indent, key)
    if index is None:
        return None
    return block[index][len(" " * indent) + len(key) + 1 :].strip() or None


def _nested_value(lines: List[str], index: Optional[int], key: str) -> Optional[str]:
    """`key:` one level inside the block at `index`, or None when either is absent."""
    if index is None:
        return None
    return _value(_block(lines, index, 0), 2, key)


def _parsed_workflow(text: str) -> Dict[str, Any]:
    """The parts of the workflow this module judges: triggers, permissions, concurrency."""
    lines = _lines(text)

    on_index = _header(lines, 0, "on")
    if on_index is None:
        raise AssertionError("workflow no longer declares an `on:` trigger block")
    on_block = _block(lines, on_index, 0)
    events = [line.strip()[:-1] for line in on_block if _indent(line) == 2]

    pull_request: Dict[str, Optional[List[str]]] = {}
    pr_index = _header(on_block, 2, "pull_request")
    if pr_index is not None:
        pr_block = _block(on_block, pr_index, 2)
        pull_request = {
            "branches": _items(pr_block, 4, "branches"),
            "types": _items(pr_block, 4, "types"),
        }

    permissions_index = _header(lines, 0, "permissions")
    concurrency_index = _header(lines, 0, "concurrency")
    return {
        "events": events,
        "pull_request": pull_request,
        "permissions": _nested_value(lines, permissions_index, "contents"),
        "concurrency": {
            "group": _nested_value(lines, concurrency_index, "group"),
            "cancel_in_progress": _nested_value(lines, concurrency_index, "cancel-in-progress"),
        },
    }


def _declared_pull_request_types(text: str) -> List[str]:
    """The activity types the workflow subscribes to, refusing an absent key."""
    parsed = _parsed_workflow(text)
    events: List[str] = parsed["events"]
    if "pull_request" not in events:
        raise AssertionError("workflow no longer runs on pull_request")

    declared: Optional[List[str]] = parsed["pull_request"]["types"]
    if declared is None:
        raise AssertionError(
            "the pull_request trigger declares no `types`, so GitHub runs only "
            "opened, synchronize and reopened: a label change or a description "
            "edit would not re-run the SG1 gate"
        )
    return list(declared)


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_pull_request_subscription_covers_grant_and_withdrawal() -> None:
    """The declared set is exactly the six acts that can change the verdict.

    Exact equality rather than a superset check: a seventh type is a subscription
    change nobody asked for, so it must be a deliberate edit that updates this
    list, not something a passing test tolerates.
    """
    assert _declared_pull_request_types(_workflow_text()) == EXPECTED_PULL_REQUEST_TYPES


def test_subscription_keeps_the_main_branch_filter_and_the_other_triggers() -> None:
    """This is a subscription change, not a new workflow.

    The push and workflow_dispatch paths stand down inside the gate's own step,
    so they must survive: they have no base and no exception to judge.
    """
    parsed = _parsed_workflow(_workflow_text())
    assert parsed["pull_request"] == {
        "branches": ["main"],
        "types": EXPECTED_PULL_REQUEST_TYPES,
    }
    assert parsed["events"] == ["pull_request", "push", "workflow_dispatch"]


def test_subscription_never_narrows_the_trigger_to_one_label_name() -> None:
    """Every label change re-runs the gate, not only the exception label.

    Both halves can be withdrawn independently, so a trigger conditioned on the
    exception label would leave the description half, and every other label,
    unjudged. Two narrowings would restore the defect and both are refused here:
    a condition naming the label, and a condition naming individual activity
    types that would re-admit the subscription and then filter it again.
    """
    for line in _workflow_text().splitlines():
        condition = _uncomment(line).strip()
        if not condition.startswith(("if:", "- if:")):
            continue
        assert EXCEPTION_LABEL not in condition, (
            f"the gate must re-run for every label change, not only {EXCEPTION_LABEL!r}: "
            f"{condition}"
        )
        assert "github.event.action" not in condition, (
            "the gate step must not filter activity types the trigger subscribes to: "
            f"{condition}"
        )


def test_gate_step_still_runs_for_every_pull_request_activity() -> None:
    """The step condition stays the event-name test, so the new types reach it.

    Widening the subscription is only useful if the step behind it runs. A
    condition that enumerated activity types would silently drop the three this
    round added, which is the same bypass one layer down.
    """
    block = _gate_step_block()
    conditions = [
        _uncomment(line).strip() for line in block.splitlines() if line.strip().startswith("if:")
    ]
    assert conditions == ["if: github.event_name == 'pull_request'"]


def test_permissions_and_concurrency_are_unchanged() -> None:
    """The repair adds a subscription, not a token and not a second run lane.

    The concurrency group is keyed on the pull request's merge ref, which does
    not change when a label or the description changes, so a metadata-event run
    lands in the group of the run it supersedes and cancels it. Only the latest
    state of the pull request then holds a verdict at that head.
    """
    parsed = _parsed_workflow(_workflow_text())
    assert parsed["permissions"] == "read"
    assert parsed["concurrency"] == {
        "group": "architecture-health-${{ github.workflow }}-${{ github.ref }}",
        "cancel_in_progress": "true",
    }


@pytest.mark.parametrize("removed", EXPECTED_PULL_REQUEST_TYPES)
def test_dropping_any_one_activity_type_is_rejected(removed: str) -> None:
    """Each of the six is load-bearing, so a future edit cannot quietly drop one.

    The mutant is applied to the workflow text in memory, never to the file. The
    parse must read the mutant correctly and the comparison must reject it, so a
    guard that silently returned a default list could not pass this.
    """
    text = _workflow_text()
    remaining = ", ".join(name for name in EXPECTED_PULL_REQUEST_TYPES if name != removed)
    mutant = text.replace(INLINE_TYPES_LINE, f"types: [{remaining}]", 1)
    assert mutant != text, "the declared types line no longer matches the expected set"

    assert _declared_pull_request_types(mutant) == [
        name for name in EXPECTED_PULL_REQUEST_TYPES if name != removed
    ]
    with pytest.raises(AssertionError):
        assert _declared_pull_request_types(mutant) == EXPECTED_PULL_REQUEST_TYPES


def test_absent_types_key_is_rejected_rather_than_read_as_a_default() -> None:
    """Round 3's shape: no `types` at all, which GitHub reads as three actions.

    This is the exact state the round 3 review rejected, so the guard is proved
    against the defect rather than against an invented mutation.
    """
    text = _workflow_text()
    mutant = text.replace("    " + INLINE_TYPES_LINE + "\n", "", 1)
    assert mutant != text

    with pytest.raises(AssertionError, match="declares no `types`"):
        _declared_pull_request_types(mutant)


def test_an_extra_activity_type_is_rejected() -> None:
    """A seventh type is a subscription change, so it must update the list here."""
    text = _workflow_text()
    mutant = text.replace(
        INLINE_TYPES_LINE,
        "types: [" + ", ".join(EXPECTED_PULL_REQUEST_TYPES + ["closed"]) + "]",
        1,
    )
    assert mutant != text

    with pytest.raises(AssertionError):
        assert _declared_pull_request_types(mutant) == EXPECTED_PULL_REQUEST_TYPES


def test_block_sequence_form_declares_the_same_subscription() -> None:
    """The parse reads YAML structure, not one spelling of it.

    A maintainer may reformat the list; the regression must still judge the
    declared set, otherwise the guard would be satisfied by a rewrite.
    """
    block_form = (
        "on:\n"
        "  pull_request:\n"
        "    branches:\n"
        "      - main\n"
        "    types:\n" + "".join(f"      - {name}\n" for name in EXPECTED_PULL_REQUEST_TYPES)
    )
    assert _declared_pull_request_types(block_form) == EXPECTED_PULL_REQUEST_TYPES
