"""Fail-closed prerequisites for the E2E suite.

Stage 1/2 of the lifecycle establishes the application state every test needs:
a server exists, the admin user can log in, a test user can be created, sharing
can be enabled. When one of those is missing during a qualification run, that is
a regression in the lifecycle, not an optional environment condition — so it
must fail the run rather than convert it into a green workflow with skipped
tests.

Outside qualification mode a skip is still reasonable: a developer may be
pointing the suite at a bare panel with no server, and failing there would make
the suite unusable locally.

Kept free of Playwright imports so the decision can be tested offline.
"""

from __future__ import annotations

import os

import pytest

_QUALIFICATION_ENV = ("E2E_TESTING", "E2E_REQUIRE_DATAPLANE")
_TRUTHY = ("true", "1", "yes")


def is_qualification_mode() -> bool:
    """Return whether the run is a strict qualification/CI lifecycle run."""
    return any(os.environ.get(name, "").strip().lower() in _TRUTHY for name in _QUALIFICATION_ENV)


def require(condition: bool, message: str) -> None:
    """Require a deterministic prerequisite, failing closed in qualification mode.

    Args:
        condition: True when the prerequisite holds.
        message: What is missing, phrased so a failure is actionable.
    """
    if condition:
        return
    if is_qualification_mode():
        pytest.fail(message)
    pytest.skip(message)
