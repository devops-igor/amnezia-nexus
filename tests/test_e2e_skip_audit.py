"""Guard against fail-open prerequisite skips returning to the E2E suite.

Issue #375: a test that skips when its deterministic setup failed turns a
regression into a green workflow. Those paths now go through
``tests.e2e.prerequisites.require``, which fails in qualification mode and only
skips outside it. This test stops the old pattern being reintroduced by copy
and paste, which is how it spread the first time.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
E2E_DIR = REPO_ROOT / "tests" / "e2e"

# Phrases that describe a deterministic prerequisite the lifecycle establishes.
# A pytest.skip carrying one of these is fail-open by definition.
FAIL_OPEN_PHRASES = (
    "No servers available",
    "Could not create",
    "Test user not found",
    "Could not enable sharing",
    "No share token",
)


def test_no_fail_open_prerequisite_skips() -> None:
    offenders = []
    for path in sorted(E2E_DIR.glob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "pytest.skip(" not in line:
                continue
            if any(phrase in line for phrase in FAIL_OPEN_PHRASES):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")

    assert not offenders, (
        "deterministic prerequisites must use prerequisites.require(), not pytest.skip:\n"
        + "\n".join(offenders)
    )
