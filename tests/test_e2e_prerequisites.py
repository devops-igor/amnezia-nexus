"""Offline tests for the fail-closed prerequisite helper.

The distinction under test is the whole point of issue #375: a missing
deterministic prerequisite must fail a qualification run and may only skip
outside one.
"""

from __future__ import annotations

import pytest

from tests.e2e import prerequisites


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in prerequisites._QUALIFICATION_ENV:
        monkeypatch.delenv(name, raising=False)


def test_satisfied_prerequisite_never_raises() -> None:
    prerequisites.require(True, "unused")
    prerequisites.require(True, "unused")


@pytest.mark.parametrize("env_name", ["E2E_TESTING", "E2E_REQUIRE_DATAPLANE"])
@pytest.mark.parametrize("value", ["true", "1", "yes", "TRUE", " yes "])
def test_missing_prerequisite_fails_in_qualification_mode(monkeypatch, env_name, value) -> None:
    monkeypatch.setenv(env_name, value)
    with pytest.raises(pytest.fail.Exception, match="no server"):
        prerequisites.require(False, "no server available")


def test_missing_prerequisite_skips_outside_qualification_mode() -> None:
    with pytest.raises(pytest.skip.Exception, match="no server"):
        prerequisites.require(False, "no server available")


@pytest.mark.parametrize("value", ["", "false", "0", "no"])
def test_non_truthy_values_do_not_enable_qualification_mode(monkeypatch, value) -> None:
    monkeypatch.setenv("E2E_TESTING", value)
    assert prerequisites.is_qualification_mode() is False
    with pytest.raises(pytest.skip.Exception):
        prerequisites.require(False, "no server available")
