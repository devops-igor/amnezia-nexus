"""Offline tests for the E2E console privacy filter (#735).

Every fixture is synthetic. The suite drives the real pytest report boundary
(``pytest_runtest_makereport`` -> ``scrub_report``) and also spawns pytest as a
subprocess on a deliberately leaky test file, so a regression in hook wiring,
rendered output or exit status fails here rather than in DEV.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.e2e import log_privacy

REPO_ROOT = Path(__file__).resolve().parents[1]

# Synthetic markers: never real credentials, never a real host.
SESSION = "sess-735-marker-0001"
CSRF = "csrf-735-marker-0002"
BEARER = "bearer-735-marker-0003"
AUTH_HEADER = "authhdr-735-marker-0004"
PRIVATE_HOST = "panel.internal.example.invalid"

TIMEOUT_TRACEBACK = (
    "playwright._impl._errors.TimeoutError: APIRequestContext.post: Timeout 120000ms exceeded.\n"
    "Call log:\n"
    f"  - → POST https://{PRIVATE_HOST}:8443/api/servers/1/install\n"
    "  -     - user-agent: Playwright/1.50.0\n"
    f"  -     - X-CSRF-Token: {CSRF}\n"
    f"  -     - cookie: sessionid={SESSION}; csrftoken={CSRF}\n"
)

MIXED_CASE_TRACEBACK = (
    "Error: request failed\n"
    f"COOKIE: sessionid={SESSION}\n"
    f"Set-Cookie: sessionid={SESSION}; HttpOnly; Path=/\n"
    f"Authorization: Bearer {BEARER}\n"
    f"x-csrf-token: {CSRF}\n"
)

MULTILINE_TRACEBACK = (
    "Error: headers follow\n"
    "Authorization: Bearer\n"
    f"  {BEARER}\n"
    f"  continued-fragment-{BEARER}\n"
    "accept: */*\n"
)


def assert_clean(text: str) -> None:
    """Assert no synthetic credential survived, whatever its case."""
    lowered = text.lower()
    for marker in (SESSION, CSRF, BEARER, AUTH_HEADER):
        assert marker.lower() not in lowered, f"leaked {marker!r}"
    # Header names may stay (they are the actionable detail); their values may
    # not. XML-escaped output renders the placeholder as ``&lt;redacted&gt;``.
    for name in ("sessionid", "csrftoken"):
        assert not re.search(
            name + r"=(?!(&lt;|<)redacted(&gt;|>))", lowered
        ), f"{name}= kept a value"
    assert not re.search(r"bearer\s+(?!(&lt;|<)redacted)", lowered), "bearer kept a value"


# ── Value redaction ──────────────────────────────────────────────────


def test_playwright_call_log_is_redacted() -> None:
    """A real Playwright timeout traceback keeps its shape but loses both values."""
    cleaned = log_privacy.redact(TIMEOUT_TRACEBACK)

    assert_clean(cleaned)
    # Actionable detail survives: error type, endpoint category, the header names.
    assert "Timeout 120000ms exceeded" in cleaned
    assert "/api/servers/1/install" in cleaned
    assert "X-CSRF-Token:" in cleaned
    assert "cookie:" in cleaned
    assert log_privacy.REDACTED in cleaned


@pytest.mark.parametrize(
    "line",
    [
        f"cookie: sessionid={SESSION}",
        f"COOKIE: sessionid={SESSION}",
        f"Cookie:sessionid={SESSION}",
        f"Set-Cookie: sessionid={SESSION}; HttpOnly",
        f"set-cookie: sessionid={SESSION}",
        f"Authorization: Bearer {BEARER}",
        f"AUTHORIZATION: Bearer {BEARER}",
        f"x-csrf-token: {CSRF}",
        f"X-CSRF-Token: {CSRF}",
        f"X-CSRFToken: {CSRF}",
        f"csrf-token: {CSRF}",
        f"X-XSRF-Token: {CSRF}",
        f"proxy-authorization: Basic {AUTH_HEADER}",
    ],
)
def test_header_casing_and_spacing_variants_are_redacted(line: str) -> None:
    """Every casing and separator variant of a sensitive header is covered."""
    cleaned = log_privacy.redact(line)
    assert_clean(cleaned)
    assert log_privacy.REDACTED in cleaned
    # The header name itself is the actionable detail and must survive.
    assert line.split(":", 1)[0] in cleaned


def test_multiline_folded_header_value_is_redacted() -> None:
    """A value folded across continuation lines is removed in full."""
    cleaned = log_privacy.redact(MULTILINE_TRACEBACK)
    assert_clean(cleaned)
    assert "accept: */*" in cleaned


def test_every_sensitive_occurrence_is_redacted() -> None:
    """Repeated headers in one traceback are all removed, not just the first."""
    repeated = "\n".join([MIXED_CASE_TRACEBACK] * 3)
    cleaned = log_privacy.redact(repeated)
    assert_clean(cleaned)
    assert cleaned.count("Error: request failed") == 3


def test_non_sensitive_content_is_preserved() -> None:
    """The filter must not mangle the failure detail it is meant to preserve."""
    text = "assert 500 == 200\n  POST /api/servers/1/install\n  accept: */*\n"
    assert log_privacy.redact(text) == text


def test_empty_input_is_returned_unchanged() -> None:
    """The hot path tolerates empty strings."""
    assert log_privacy.redact("") == ""


def test_registered_secret_is_redacted_without_its_header_name() -> None:
    """A credential registered by a fixture is removed even bare."""
    log_privacy._registered.clear()
    try:
        log_privacy.register_secret(SESSION)
        cleaned = log_privacy.redact(f"debug dump: {SESSION} leaked here")
        assert SESSION not in cleaned
        assert "debug dump:" in cleaned
    finally:
        log_privacy._registered.clear()


@pytest.mark.parametrize("value", ["short", "", "has space in it", None, 12345])
def test_unsafe_registration_is_ignored(value) -> None:
    """Short, empty or whitespace-bearing values would destroy ordinary output."""
    log_privacy._registered.clear()
    try:
        log_privacy.register_secret(value)
        assert log_privacy._registered == []
    finally:
        log_privacy._registered.clear()


def test_registered_secret_list_is_bounded() -> None:
    """Registration cannot grow without bound during a long session."""
    log_privacy._registered.clear()
    try:
        for index in range(log_privacy._MAX_REGISTERED + 5):
            log_privacy.register_secret(f"marker-735-value-{index:04d}")
        assert len(log_privacy._registered) == log_privacy._MAX_REGISTERED
        assert f"marker-735-value-{log_privacy._MAX_REGISTERED + 4:04d}" in (
            log_privacy._registered
        )
    finally:
        log_privacy._registered.clear()


def test_duplicate_registration_is_idempotent() -> None:
    """Re-registering the same credential never grows the list or reorders it."""
    log_privacy._registered.clear()
    try:
        log_privacy.register_secret(SESSION)
        log_privacy.register_secret(CSRF)
        log_privacy.register_secret(SESSION)
        assert log_privacy._registered == [SESSION, CSRF]
    finally:
        log_privacy._registered.clear()


# ── Report boundary (the real seam) ──────────────────────────────────


class _FakeReport:
    """Minimal stand-in carrying the fields pytest renders."""

    def __init__(self, longrepr) -> None:
        self.longrepr = longrepr
        self.sections = []


class _FakeFileLocation:
    def __init__(self, message: str) -> None:
        self.message = message


class _FakeEntry:
    def __init__(self, lines) -> None:
        self.lines = list(lines)


class _FakeTraceback:
    def __init__(self, entries, extraline=None) -> None:
        self.reprentries = entries
        self.extraline = extraline


class _FakeChainRepr:
    def __init__(self, crash, traceback, sections=None) -> None:
        self.reprcrash = crash
        self.reprtraceback = traceback
        self.sections = sections or []
        self.chain = []


def test_scrub_report_redacts_every_rendered_field() -> None:
    """Crash message, entry lines and captured sections are all filtered."""
    log_privacy._registered.clear()
    log_privacy.register_secret(SESSION)
    try:
        report = _FakeReport(
            _FakeChainRepr(
                _FakeFileLocation(f"TimeoutError: timeout\ncookie: sessionid={SESSION}"),
                _FakeTraceback([_FakeEntry([f"E   cookie: sessionid={SESSION}"])]),
                [("Captured stdout call", f"sessionid={SESSION}")],
            )
        )
        report.sections = [("Captured stdout call", f"sessionid={SESSION}")]

        log_privacy.scrub_report(report)

        rendered = repr(report.longrepr.reprcrash.message)
        rendered += "".join(
            str(getattr(entry, "lines", "")) for entry in report.longrepr.reprtraceback.reprentries
        )
        rendered += "".join(body for _, body in report.longrepr.sections)
        rendered += "".join(body for _, body in report.sections)
        assert SESSION not in rendered
        # Failure identity and error type survive.
        assert "TimeoutError: timeout" in report.longrepr.reprcrash.message
        assert "cookie: <redacted>" in report.longrepr.reprcrash.message
    finally:
        log_privacy._registered.clear()


def test_scrub_report_handles_string_longrepr() -> None:
    """A report whose longrepr is already text is filtered in place."""
    report = _FakeReport(f"failure\ncookie: sessionid={SESSION}")
    log_privacy.scrub_report(report)
    assert SESSION not in report.longrepr


def test_scrub_report_redacts_rendered_function_arguments() -> None:
    """``--showlocals`` renders funcarg values; registered credentials are removed."""
    log_privacy._registered.clear()
    log_privacy.register_secret(CSRF)
    try:

        class FuncArgs:
            def __init__(self) -> None:
                self.args = [("token", CSRF), ("name", "chromium")]

        report = _FakeReport(FuncArgs())
        log_privacy.scrub_report(report)

        assert report.longrepr.args == [("token", log_privacy.REDACTED), ("name", "chromium")]
    finally:
        log_privacy._registered.clear()


def test_scrub_report_tolerates_immutable_repr_fields() -> None:
    """A repr object whose string fields reject assignment must not break the run."""

    class Frozen:
        """Slots-only repr carrying a leaky message and lines that cannot be set."""

        __slots__ = ("_message", "_lines")

        def __init__(self) -> None:
            self._message = f"cookie: sessionid={SESSION}"
            self._lines = [f"E   cookie: sessionid={SESSION}"]

        @property
        def message(self) -> str:
            return self._message

        @property
        def lines(self):
            return self._lines

    frozen = Frozen()
    log_privacy._scrub(frozen, 0, set())
    # Nothing was mutated and nothing raised; the boundary still reports failure.
    assert frozen.message == f"cookie: sessionid={SESSION}"


def test_scrub_report_fails_closed_on_filter_error(monkeypatch) -> None:
    """A filter crash withholds detail but keeps the failure and its error type."""

    def boom(_text: str) -> str:
        raise RuntimeError("filter exploded")

    report = _FakeReport(_FakeFileLocation("leaky detail"))
    report.sections = [("Captured stdout call", f"sessionid={SESSION}")]
    monkeypatch.setattr(log_privacy, "redact", boom)

    class FakeExcinfo:
        """Call info stand-in carrying only the exception instance."""

        value: Exception = TimeoutError("original")

    log_privacy.scrub_report(report, FakeExcinfo())

    assert isinstance(report.longrepr, str)
    assert "withheld" in report.longrepr
    assert "TimeoutError" in report.longrepr
    assert SESSION not in report.longrepr
    assert report.sections == []


def test_withhold_survives_a_readonly_report(monkeypatch) -> None:
    """Fail-closed holds even when the report itself rejects both writes."""

    class ReadOnlyReport:
        """Report whose rendered fields cannot be reassigned."""

        __slots__ = ()

        @property
        def longrepr(self):
            return f"cookie: sessionid={SESSION}"

        @property
        def sections(self):
            return [("Captured stdout call", f"sessionid={SESSION}")]

    log_privacy._withhold(ReadOnlyReport(), None)
    # No exception escaped; the caller still reports a failure with a safe message.


def test_withhold_tolerates_unreadable_excinfo() -> None:
    """An excinfo whose value cannot be inspected still yields a safe message."""

    class BrokenExcinfo:
        """Call info stand-in whose value accessor raises."""

        @property
        def value(self):
            raise RuntimeError("no value")

    report = _FakeReport(f"cookie: sessionid={SESSION}")
    log_privacy._withhold(report, BrokenExcinfo())
    assert "withheld" in report.longrepr
    assert "failure" in report.longrepr
    assert SESSION not in report.longrepr


# ── End-to-end: real pytest rendering, real exit status ──────────────

LEAKY_TEST = '''"""Synthetic failing E2E test: every line below must be redacted in the report."""

from tests.e2e import log_privacy


def test_playwright_timeout_failure() -> None:
    log_privacy.register_secret("sess-735-marker-0001")
    print("captured stdout: sessionid=sess-735-marker-0001")
    raise RuntimeError(
        "APIRequestContext.post: Timeout 120000ms exceeded.\\n"
        "Call log:\\n"
        "  - \\u2192 POST https://panel.internal.example.invalid:8443/api/servers/1/install\\n"
        "  -     - X-CSRF-Token: csrf-735-marker-0002\\n"
        "  -     - cookie: sessionid=sess-735-marker-0001; csrftoken=csrf-735-marker-0002\\n"
    )
'''

ROOT_CONFTEST = '''"""Activate the E2E console privacy filter for every run in this repository."""

pytest_plugins = ["tests.e2e.log_privacy"]
'''


def _env() -> dict:
    """Return an environment that can import the repository from any cwd."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run_pytest(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run pytest in a throwaway root that activates the filter under test."""
    (tmp_path / "pytest.ini").write_text("[pytest]\npython_files = test_*.py\n", encoding="utf-8")
    (tmp_path / "test_leaky_e2e.py").write_text(LEAKY_TEST, encoding="utf-8")
    (tmp_path / "conftest.py").write_text(ROOT_CONFTEST, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(tmp_path / "test_leaky_e2e.py"),
            "-p",
            "no:cacheprovider",
            "-c",
            str(tmp_path / "pytest.ini"),
            *args,
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=_env(),
    )


@pytest.mark.parametrize("tb_style", ["long", "short", "line", "auto", "native"])
def test_real_pytest_output_never_leaks(tmp_path: Path, tb_style: str) -> None:
    """Every traceback style renders identity and error type but no credential."""
    result = _run_pytest(tmp_path, f"--tb={tb_style}")

    combined = result.stdout + result.stderr
    assert_clean(combined)
    # Failure identity, error type and status are preserved.
    assert result.returncode == 1, combined
    assert "test_playwright_timeout_failure" in combined
    assert "RuntimeError" in combined
    # --tb=line renders only the exception's first line, which carries no route.
    if tb_style != "line":
        assert "Timeout 120000ms exceeded" in combined
        assert "/api/servers/1/install" in combined
    else:
        assert "Timeout" in combined or "APIRequestContext" in combined


def test_real_pytest_output_without_plugin_would_leak(tmp_path: Path) -> None:
    """Control: the same file leaks when the plugin is not active.

    This documents the exposure the filter closes; it does not exercise it.
    """
    (tmp_path / "pytest.ini").write_text("[pytest]\npython_files = test_*.py\n", encoding="utf-8")
    (tmp_path / "test_leaky_e2e.py").write_text(LEAKY_TEST, encoding="utf-8")
    (tmp_path / "conftest.py").write_text("", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(tmp_path / "test_leaky_e2e.py"),
            "-p",
            "no:cacheprovider",
            "-c",
            str(tmp_path / "pytest.ini"),
            "--tb=long",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT)},
    )
    combined = result.stdout + result.stderr
    assert SESSION in combined, "control run must reproduce the exposure"
    assert re.search(r"sessionid=" + SESSION, combined)


def test_persisted_junit_report_is_filtered(tmp_path: Path) -> None:
    """A machine-readable report written to disk carries no credential either."""
    report_path = tmp_path / "junit.xml"

    result = _run_pytest(tmp_path, f"--junitxml={report_path}", "--tb=long")

    assert result.returncode == 1
    assert report_path.is_file(), result.stdout + result.stderr
    xml = report_path.read_text(encoding="utf-8")
    assert_clean(xml)
    # The report still names the failure and its error type.
    assert "test_playwright_timeout_failure" in xml
    assert "RuntimeError" in xml


def test_log_capture_section_is_filtered(tmp_path: Path) -> None:
    """A credential logged during the test is redacted from the caplog section."""
    leaky_log = '''"""Synthetic failing test that logs a credential."""

import logging


def test_logs_token_then_fails() -> None:
    logging.getLogger("e2e").warning("headers cookie: sessionid=sess-735-marker-0001")
    raise AssertionError("cookie: sessionid=sess-735-marker-0001")
'''
    (tmp_path / "pytest.ini").write_text("[pytest]\npython_files = test_*.py\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text(ROOT_CONFTEST, encoding="utf-8")
    (tmp_path / "test_leaky_e2e.py").write_text(leaky_log, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(tmp_path / "test_leaky_e2e.py"),
            "-p",
            "no:cacheprovider",
            "-c",
            str(tmp_path / "pytest.ini"),
            "--tb=long",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=_env(),
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 1, combined
    assert_clean(combined)
    # The captured-log section is still published, just without the value.
    assert "Captured log call" in combined
    assert "test_logs_token_then_fails" in combined
