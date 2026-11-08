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


def test_registration_is_independent_of_token_source() -> None:
    """P3: a meta-sourced token is registered exactly like a cookie-sourced one."""
    log_privacy._registered.clear()
    try:
        # Both origins converge on the same single registration point.
        log_privacy.register_secret(CSRF)
        assert CSRF in log_privacy._registered
        assert CSRF not in log_privacy.redact(f"traceback shows {CSRF} here")
    finally:
        log_privacy._registered.clear()


def test_csrf_fixture_registers_returned_token_for_every_source() -> None:
    """The fixture registers the value it returns, after the meta/fallback merge."""
    source = (REPO_ROOT / "tests" / "e2e" / "conftest.py").read_text(encoding="utf-8")
    merge_index = source.index("if not token:")
    register_index = source.index("log_privacy.register_secret(token)")
    # Registration must follow the branch point, so it covers both origins.
    assert register_index > merge_index
    assert source.count("log_privacy.register_secret(token)") == 1


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
        self.outcome = "failed"

    @property
    def passed(self) -> bool:
        """Mirror pytest's read-only success predicate."""
        return self.outcome == "passed"


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


def test_scrub_report_replaces_whole_detail_when_repr_is_immutable() -> None:
    """A repr that rejects assignment must not leave the credential rendered.

    The previous version of this test asserted the *leaked* value survived, which
    certified the vulnerability instead of the contract (#735 R2 P2). The
    requirement is that whole rendered detail is replaced and the failure keeps
    its status, type and identity.
    """

    class Frozen:
        """Repr whose message and lines are read-only properties."""

        def __init__(self) -> None:
            self._message = f"cookie: sessionid={SESSION}"
            self._lines = [f"E   cookie: sessionid={SESSION}"]

        @property
        def message(self) -> str:
            return self._message

        @property
        def lines(self):
            return self._lines

    report = _FakeReport(Frozen())
    report.sections = [("Captured stdout call", f"sessionid={SESSION}")]

    log_privacy.scrub_report(report)

    # Detail is replaced wholesale; the credential is unreachable.
    assert isinstance(report.longrepr, str)
    assert SESSION not in report.longrepr
    assert "withheld" in report.longrepr
    assert report.sections == []
    # Status/identity survive: outcome untouched, still a failure report.
    assert not report.passed


def test_replacement_failure_is_not_silently_accepted() -> None:
    """A write that silently does not take escalates instead of passing."""

    class Stubborn:
        """Repr whose message ignores assignment while reporting success."""

        def __init__(self) -> None:
            self._message = f"cookie: sessionid={SESSION}"

        @property
        def message(self) -> str:
            return self._message

        @message.setter
        def message(self, _value) -> None:
            pass

    with pytest.raises(log_privacy._Unscrubbable):
        log_privacy._replace_field(Stubborn(), "message", "redacted")


def test_unreplaceable_report_aborts_rather_than_leaking() -> None:
    """If even whole-detail replacement is refused, the run fails loudly."""

    class Immovable:
        """Report that rejects every write."""

        __slots__ = ()

        @property
        def longrepr(self):
            return f"cookie: sessionid={SESSION}"

        @property
        def sections(self):
            return [("Captured stdout call", f"sessionid={SESSION}")]

    with pytest.raises(log_privacy._Unscrubbable):
        log_privacy.scrub_report(Immovable())


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


def test_withhold_raises_when_report_rejects_replacement() -> None:
    """A report that rejects whole-detail replacement must fail, not pass silently.

    This replaces the earlier assertion that "no exception escaped". Silence here
    meant the credential stayed rendered (#735 R2 P2), so the contract is now an
    explicit raise.
    """

    class ReadOnlyReport:
        """Report whose rendered fields cannot be reassigned."""

        __slots__ = ()

        @property
        def longrepr(self):
            return f"cookie: sessionid={SESSION}"

        @property
        def sections(self):
            return [("Captured stdout call", f"sessionid={SESSION}")]

    with pytest.raises(log_privacy._Unscrubbable):
        log_privacy._withhold(ReadOnlyReport(), None)


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

# R2 regression fixture: an empty-first folded Authorization header, plus an
# immutable repr field. Both must be gone from every real sink.
FOLDED_TEST = '''"""Synthetic failing test exercising the R2 counterexamples."""

MARKER = "fold-735-marker-r2"


def test_empty_first_folded_header_failure() -> None:
    print("captured stdout before failure")
    raise RuntimeError(
        "APIRequestContext.post: Timeout 120000ms exceeded.\\n"
        "Call log:\\n"
        "  - \\u2192 POST https://panel.internal.example.invalid:8443/api/servers/1/install\\n"
        "  -     - Authorization:\\n"
        "  -     -   Bearer " + MARKER + "\\n"
        "  -     - cookie:\\n"
        "  -     -   sessionid=" + MARKER + "\\n"
    )
'''

# A repr whose fields are read-only properties: the plugin must replace the
# whole rendered detail rather than silently keep the secret.
#
# The hook is non-wrapper and runs at this file's conftest priority *before*
# pytest_runtest_makereport completes, so the frozen repr is what the filter
# receives. A wrapper here would run after the filter and prove nothing.
IMMUTABLE_REPR_TEST = '''"""Synthetic failing test whose report must be scrubbed after substitution."""


def test_immutable_repr_failure() -> None:
    raise RuntimeError("boom cookie: sessionid=imm-735-marker-r2")
'''

# The frozen-repr hook must live in a conftest (pytest does not collect hooks from
# test modules). It is a firstresult makereport hook returning a report whose
# rendered fields are read-only, so the filter's post-yield pass receives an
# unscrubbable repr and must replace the whole detail.
IMMUTABLE_REPR_CONFTEST = '''"""Install the filter and substitute an immutable, leaky report repr."""

from _pytest.reports import TestReport

pytest_plugins = ["tests.e2e.log_privacy"]


class _FrozenRepr:
    """Repr exposing read-only rendered fields."""

    def __init__(self, text):
        self._text = text

    @property
    def message(self):
        return self._text

    @property
    def lines(self):
        return [self._text]

    def toterminal(self, tw):
        tw.line(self._text)

    def __str__(self):
        return self._text


def pytest_runtest_makereport(item, call):
    if call.when != "call":
        return None
    report = TestReport.from_item_and_call(item, call)
    if report.failed:
        report.longrepr = _FrozenRepr("cookie: sessionid=imm-735-marker-r2")
    return report
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


# ── R2 counterexample regressions: real console and JUnit sinks ──────

FOLDED_MARKER = "fold-735-marker-r2"
IMMUTABLE_MARKER = "imm-735-marker-r2"


def _run_with(
    tmp_path: Path, source: str, *args: str, conftest: str = ROOT_CONFTEST
) -> subprocess.CompletedProcess:
    """Run pytest on an arbitrary synthetic test file with the filter active."""
    (tmp_path / "pytest.ini").write_text("[pytest]\npython_files = test_*.py\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text(conftest, encoding="utf-8")
    (tmp_path / "test_leaky_e2e.py").write_text(source, encoding="utf-8")
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


@pytest.mark.parametrize("tb_style", ["long", "short", "auto", "native"])
def test_empty_first_folded_auth_header_never_reaches_console(
    tmp_path: Path, tb_style: str
) -> None:
    """P1: an empty-first folded Authorization value is redacted in real output."""
    result = _run_with(tmp_path, FOLDED_TEST, f"--tb={tb_style}")

    combined = result.stdout + result.stderr
    assert FOLDED_MARKER not in combined, "folded continuation leaked to console"
    # Failure status, identity and error type are preserved.
    assert result.returncode == 1, combined
    assert "test_empty_first_folded_header_failure" in combined
    assert "RuntimeError" in combined
    assert "Timeout 120000ms exceeded" in combined


def test_empty_first_folded_auth_header_never_reaches_junit(tmp_path: Path) -> None:
    """P1: the same counterexample cannot reach a persisted JUnit report."""
    report = tmp_path / "junit.xml"
    result = _run_with(tmp_path, FOLDED_TEST, "--tb=long", f"--junitxml={report}")

    assert result.returncode == 1
    assert report.is_file(), result.stdout + result.stderr
    xml = report.read_text(encoding="utf-8")
    assert FOLDED_MARKER not in xml, "folded continuation leaked to JUnit XML"
    assert "test_empty_first_folded_header_failure" in xml
    assert "RuntimeError" in xml


def test_immutable_repr_never_reaches_console_or_junit(tmp_path: Path) -> None:
    """P2: an unscrubbable repr is replaced wholesale; status/type survive.

    The synthetic file returns a report whose rendered fields are read-only
    properties, so the filter must replace the whole detail. Asserting only "no
    marker" would pass vacuously if the frozen repr never reached the filter, so
    this also asserts the withheld placeholder is rendered.
    """
    report = tmp_path / "junit.xml"
    result = _run_with(
        tmp_path,
        IMMUTABLE_REPR_TEST,
        "--tb=long",
        f"--junitxml={report}",
        conftest=IMMUTABLE_REPR_CONFTEST,
    )

    combined = result.stdout + result.stderr
    assert IMMUTABLE_MARKER not in combined, "immutable repr leaked to console"
    if report.is_file():
        assert IMMUTABLE_MARKER not in report.read_text(encoding="utf-8")
    assert result.returncode != 0, combined
    # Non-vacuous: the frozen repr was actually filtered, not merely absent.
    assert "withheld" in combined, f"filter did not engage on the frozen repr:\n{combined}"


def test_folded_redaction_is_not_satisfied_by_absence_of_failure(
    tmp_path: Path,
) -> None:
    """Control: without the plugin the folded counterexample does leak."""
    (tmp_path / "pytest.ini").write_text("[pytest]\npython_files = test_*.py\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text("", encoding="utf-8")
    (tmp_path / "test_leaky_e2e.py").write_text(FOLDED_TEST, encoding="utf-8")
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
    assert FOLDED_MARKER in (
        result.stdout + result.stderr
    ), "control run must reproduce the folded-header exposure"


# ── R2 escalation paths: each fail-closed branch directly exercised ──


def test_verification_rejects_still_sensitive_longrepr() -> None:
    """The verification layer raises on a longrepr that still needs redaction.

    Exercised directly because ``redact`` and the header pass are the same code
    path: any attempt to stub one out also disables detection, which would make a
    scrub-level probe pass vacuously.
    """
    report = _FakeReport(f"cookie: sessionid={SESSION}")
    with pytest.raises(log_privacy._Unscrubbable):
        log_privacy._verify_report(report)


def test_verification_rejects_still_sensitive_repr_tree() -> None:
    """The verification layer raises when a repr tree still carries a secret."""
    report = _FakeReport(_FakeFileLocation(f"cookie: sessionid={SESSION}"))
    with pytest.raises(log_privacy._Unscrubbable):
        log_privacy._verify_report(report)


def test_verification_accepts_clean_longrepr() -> None:
    """A clean longrepr passes verification without raising."""
    log_privacy._verify_report(_FakeReport("assert 1 == 1"))


def test_verification_catches_still_sensitive_repr_tree(monkeypatch) -> None:
    """A repr tree that stays sensitive after scrubbing escalates to withhold."""
    report = _FakeReport(_FakeFileLocation(f"cookie: sessionid={SESSION}"))

    # Make _scrub a no-op so the verification layer must catch the leftover.
    monkeypatch.setattr(log_privacy, "_scrub", lambda *a, **k: None)
    log_privacy.scrub_report(report)
    assert isinstance(report.longrepr, str)
    assert "withheld" in report.longrepr


def test_longrepr_assignment_that_does_not_take_escalates() -> None:
    """A report whose longrepr silently ignores assignment is withheld."""

    class StickyReport:
        """Report that accepts then discards the new longrepr."""

        def __init__(self) -> None:
            self._lr = f"cookie: sessionid={SESSION}"
            self.sections = []

        @property
        def longrepr(self):
            return self._lr

        @longrepr.setter
        def longrepr(self, _value):
            pass

        outcome = "failed"

        @property
        def passed(self):
            return False

    report = StickyReport()
    # Withholding also cannot take; that must raise rather than pass silently.
    with pytest.raises(log_privacy._Unscrubbable):
        log_privacy.scrub_report(report)


def test_redact_lines_pads_non_string_entries() -> None:
    """Non-string line entries are passed through the per-item fallback."""
    result = log_privacy._redact_lines([f"cookie: sessionid={SESSION}", None])
    assert result[0] == "cookie: <redacted>"
    assert result[1] is None


def test_redact_lines_returns_original_when_clean() -> None:
    """An already-clean line list comes back unchanged, preserving boundaries."""
    lines = ["assert 1 == 1", "no secrets here"]
    assert log_privacy._redact_lines(lines) == lines


def test_redact_lines_keeps_boundaries_when_length_is_unchanged() -> None:
    """Boundaries survive when redaction does not change the total length."""
    log_privacy._registered.clear()
    try:
        # Make the sensitive value exactly as long as the placeholder so the
        # re-split path (not the single-element fallback) is taken.
        value = "x" * len(log_privacy.REDACTED)
        log_privacy._registered.append(value)
        lines = [f"echo cookie {value}\n", "tail\n"]
        out = log_privacy._redact_lines(lines)
        assert len(out) == 2, out
        assert out[1] == "tail\n"
        assert value not in "".join(out)
    finally:
        log_privacy._registered.clear()


def test_redact_lines_preserves_content_after_redaction() -> None:
    """Redaction removes the secret and keeps subsequent lines readable."""
    lines = ["cookie: sessionid=" + SESSION + "\n", "tail line\n"]
    out = log_privacy._redact_lines(lines)
    joined = "".join(out)
    assert SESSION not in joined
    # The unindented following line is not a fold continuation and must survive.
    assert "tail line" in joined


def test_redact_lines_falls_back_to_single_element_when_lengths_shift() -> None:
    """A replacement that changes length collapses to one safe element."""
    lines = ["cookie: sessionid=" + SESSION + "\n", "tail"]
    out = log_privacy._redact_lines(lines)
    assert len(out) == 1
    assert SESSION not in out[0]
