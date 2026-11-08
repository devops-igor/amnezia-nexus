"""Redact authentication material from pytest failure output.

Playwright renders the headers of a failed request into the ``Call log`` section
of the exception it raises, so ``cookie``, ``X-CSRF-Token`` and ``Authorization``
values reach the console, the short summary and any machine-readable report of a
failing E2E test. This module is the pytest plugin that rewrites each report
before pytest renders it, so every rendered sink is filtered at one boundary.

Redaction is anchored on header names rather than on known values, so it also
covers values this process never held (a cookie echoed back by a proxy, a CSRF
token rotated mid-run) and the casing variants Playwright may emit. Values
registered with :func:`register_secret` are removed as bare substrings too, which
covers a credential a test prints without its header name.

The plugin imports nothing from Playwright, performs no I/O and never logs the
content it discards: it is safe to activate for every pytest run in the
repository.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

import pytest

REDACTED = "<redacted>"

# Header names whose value carries a session or request-authenticity claim.
_SENSITIVE_NAMES = (
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "x-csrftoken",
)
_SENSITIVE_RE = re.compile(
    r"(?i)\b(?P<name>" + "|".join(_SENSITIVE_NAMES) + r")(?P<sep>\s*:\s*)(?P<value>.*)"
)
# Any ``name: value`` line, sensitive or not, ends a folded header value.
_HEADER_LINE_RE = re.compile(r"^\s*(?:[-*]\s*)*(?:[A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:")
# A new call-log entry (``  - → POST http://…``) ends a folded header value.
_ENTRY_LINE_RE = re.compile(r"^\s*-\s*(?:→|->)")

# A credential shorter than this, or one containing whitespace, cannot be told
# apart from ordinary output; redacting it would destroy the failure detail this
# filter exists to preserve.
_MIN_SECRET_LEN = 8
_MAX_REGISTERED = 16
_MAX_DEPTH = 6

_registered: List[str] = []


def register_secret(value: Any) -> None:
    """Register a live credential for bare-substring redaction.

    Called by the E2E fixtures as they read session cookies and CSRF tokens, so
    a value that escapes into captured stdout or a traceback is still removed
    even without a header name in front of it.
    """
    text = value if isinstance(value, str) else ""
    if len(text) < _MIN_SECRET_LEN or any(char.isspace() for char in text):
        return
    if text in _registered:
        return
    if len(_registered) >= _MAX_REGISTERED:
        _registered.pop(0)
    _registered.append(text)


def redact(text: str) -> str:
    """Return ``text`` with authentication header values and secrets removed."""
    if not text:
        return text
    result = _redact_headers(text)
    for secret in _registered:
        if secret in result:
            result = result.replace(secret, REDACTED)
    return result


def _redact_headers(text: str) -> str:
    """Replace every sensitive header value, including folded continuation lines."""
    out: List[str] = []
    folding = False
    for line in text.splitlines(keepends=True):
        body, ending = _split_ending(line)
        match = _SENSITIVE_RE.search(body)
        if match:
            out.append(body[: match.start("value")] + REDACTED + ending)
            folding = bool(match.group("value").strip())
            continue
        if folding:
            if not body.strip() or _HEADER_LINE_RE.match(body) or _ENTRY_LINE_RE.match(body):
                folding = False
            else:
                stripped = body.lstrip()
                out.append(body[: len(body) - len(stripped)] + REDACTED + ending)
                continue
        out.append(line)
    return "".join(out)


def _split_ending(line: str) -> "tuple[str, str]":
    """Split a line into its body and its trailing newline sequence."""
    body = line.rstrip("\r\n")
    return body, line[len(body) :]


# ── Report rewriting ──────────────────────────────────────────────────


def scrub_report(report: Any, excinfo: Optional[Any] = None) -> None:
    """Redact every rendered field of one pytest report; fail closed on error."""
    try:
        _scrub_sections(report)
        longrepr = getattr(report, "longrepr", None)
        if isinstance(longrepr, str):
            fixed = redact(longrepr)
            if fixed != longrepr:
                report.longrepr = fixed
        else:
            _scrub(longrepr, 0, set())
    except Exception:
        _withhold(report, excinfo)


def _scrub_sections(holder: Any) -> None:
    """Redact a report's captured-output sections, from which capstdout derives."""
    sections = getattr(holder, "sections", None)
    if not isinstance(sections, list):
        return
    for index, entry in enumerate(sections):
        if isinstance(entry, tuple) and len(entry) == 2 and isinstance(entry[1], str):
            sections[index] = (entry[0], redact(entry[1]))


def _scrub(repr_obj: Any, depth: int, seen: set) -> None:
    """Walk the pytest repr tree, rewriting every string field it renders."""
    if repr_obj is None or depth > _MAX_DEPTH or id(repr_obj) in seen:
        return
    if isinstance(repr_obj, str):
        return
    seen.add(id(repr_obj))
    if isinstance(repr_obj, (list, tuple)):
        for item in repr_obj:
            _scrub(item, depth + 1, seen)
        return
    _scrub_sections(repr_obj)
    message = getattr(repr_obj, "message", None)
    if isinstance(message, str):
        fixed_message = redact(message)
        if fixed_message != message:
            try:
                repr_obj.message = fixed_message
            except AttributeError:
                pass
    lines = getattr(repr_obj, "lines", None)
    if isinstance(lines, (list, tuple)):
        fixed_lines = [redact(item) if isinstance(item, str) else item for item in lines]
        if fixed_lines != list(lines):
            try:
                repr_obj.lines = fixed_lines
            except AttributeError:
                pass
    args = getattr(repr_obj, "args", None)
    if isinstance(args, list):
        _scrub_funcargs(args)
    for field in (
        "message",
        "extraline",
        "reprcrash",
        "reprtraceback",
        "reprfileloc",
        "reprlocals",
        "reprfuncargs",
        "chain",
        "reprentries",
        "sections",
    ):
        child = getattr(repr_obj, field, None)
        if child is not None:
            _scrub(child, depth + 1, seen)


def _scrub_funcargs(args: List[Any]) -> None:
    """Redact rendered function-argument values (``name = value`` pairs)."""
    for index, entry in enumerate(args):
        if isinstance(entry, tuple) and len(entry) == 2:
            name, value = entry
            fixed = redact(str(value))
            if fixed != str(value):
                args[index] = (name, fixed)


def _withhold(report: Any, excinfo: Optional[Any]) -> None:
    """Fail closed: withhold all rendered detail but keep identity and error type.

    The test is still reported as failed with its own node id and exception type,
    so the exit status and the identity of the failure survive a broken filter;
    only the detail that could not be scrubbed is dropped.
    """
    name = "failure"
    if excinfo is not None:
        try:
            name = type(excinfo.value).__name__ or name
        except Exception:
            pass
    try:
        report.longrepr = f"{name}: failure detail withheld (privacy filter error)"
    except Exception:
        pass
    try:
        report.sections = []
    except Exception:
        pass


# ── pytest plugin entry point ─────────────────────────────────────────


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    """Redact the report before any pytest reporter renders it."""
    outcome = yield
    report = outcome.get_result()
    if hasattr(report, "longrepr") and hasattr(report, "sections"):
        scrub_report(report, getattr(call, "excinfo", None))
