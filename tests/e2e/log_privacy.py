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
    """Replace every sensitive header value, including folded continuation lines.

    A sensitive header whose own value is empty still opens a fold: the wire
    format lets the credential arrive on the following indented line, so the
    continuation must be consumed rather than treated as ordinary text.
    """
    out: List[str] = []
    folding = False
    for line in text.splitlines(keepends=True):
        body, ending = _split_ending(line)
        match = _SENSITIVE_RE.search(body)
        if match:
            out.append(body[: match.start("value")] + REDACTED + ending)
            # Empty value is not "no fold": a folded credential follows.
            folding = True
            continue
        if folding:
            if (
                not body.strip()
                or _HEADER_LINE_RE.match(body)
                or _ENTRY_LINE_RE.match(body)
                or not body[:1].isspace()
            ):
                # A continuation line is indented by definition; anything that is
                # blank, a new header, a new call-log entry, or unindented ends
                # the fold so ordinary traceback lines are not destroyed.
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


class _Unscrubbable(Exception):
    """A rendered field holds sensitive text that could not be replaced."""


def scrub_report(report: Any, excinfo: Optional[Any] = None) -> None:
    """Redact every rendered field of one pytest report; fail closed on error.

    Any field whose sensitive text cannot be verifiably replaced escalates to
    :func:`_withhold`, so a repr that rejects assignment can never leave
    credentials rendered. Silence is treated as failure, never as success.

    If even whole-detail replacement is refused, the report cannot be made safe
    and this raises :class:`_Unscrubbable` deliberately: aborting the run is the
    only remaining way to avoid rendering the credential. Visible run failure is
    strictly preferable to a clean-looking log with a live secret in it.
    """
    try:
        _scrub_sections(report)
        longrepr = getattr(report, "longrepr", None)
        if isinstance(longrepr, str):
            fixed = redact(longrepr)
            if fixed != longrepr:
                report.longrepr = fixed
                if redact(getattr(report, "longrepr", "") or "") != getattr(
                    report, "longrepr", None
                ):
                    raise _Unscrubbable("longrepr replacement not applied")
        else:
            _scrub(longrepr, 0, set())
        _verify_report(report)
    except Exception:
        _withhold(report, excinfo)


def _verify_report(report: Any) -> None:
    """Confirm no sensitive text survives in anything the report will render."""
    longrepr = getattr(report, "longrepr", None)
    if isinstance(longrepr, str):
        if redact(longrepr) != longrepr:
            raise _Unscrubbable("longrepr still sensitive")
        return
    if longrepr is not None and _contains_sensitive(longrepr, 0, set()):
        raise _Unscrubbable("repr tree still sensitive")


def _contains_sensitive(repr_obj: Any, depth: int, seen: set) -> bool:
    """Return True if any rendered string field still needs redaction."""
    if repr_obj is None or depth > _MAX_DEPTH or id(repr_obj) in seen:
        return False
    if isinstance(repr_obj, str):
        return redact(repr_obj) != repr_obj
    seen.add(id(repr_obj))
    if isinstance(repr_obj, (list, tuple)):
        return any(_contains_sensitive(item, depth + 1, seen) for item in repr_obj)
    for field in (
        "message",
        "extraline",
        "lines",
        "reprcrash",
        "reprtraceback",
        "reprfileloc",
        "reprlocals",
        "reprfuncargs",
        "chain",
        "reprentries",
        "sections",
    ):
        if _contains_sensitive(getattr(repr_obj, field, None), depth + 1, seen):
            return True
    return False


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
            _replace_field(repr_obj, "message", fixed_message)
    lines = getattr(repr_obj, "lines", None)
    if isinstance(lines, (list, tuple)):
        fixed_lines = _redact_lines(lines)
        if fixed_lines != list(lines):
            _replace_field(repr_obj, "lines", fixed_lines)
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


def _redact_lines(lines: Any) -> List[Any]:
    """Redact a rendered line list as one block so fold state crosses lines.

    ``ReprEntry.lines`` is a list of separate strings; redacting each in isolation
    cannot see that a later line continues a folded header and would leak the
    credential (#735 R2 P1). Joining for one pass keeps the fold state intact.
    """
    if not all(isinstance(item, str) for item in lines):
        return [redact(item) if isinstance(item, str) else item for item in lines]
    joined = "".join(lines)
    redacted = redact(joined)
    if redacted == joined:
        return list(lines)
    # Re-split on the same boundaries the caller supplied.
    out: List[str] = []
    cursor = 0
    for item in lines:
        out.append(redacted[cursor : cursor + len(item)])
        cursor += len(item)
    if cursor != len(redacted) or "".join(out) != redacted:
        # Boundaries shifted (a value's length changed mid-line); fall back to
        # the whole redacted text as one element rather than risk a partial cut.
        return [redacted]
    return out


def _replace_field(repr_obj: Any, field: str, value: Any) -> None:
    """Assign a scrubbed value and verify the read-back, or raise to escalate.

    ``AttributeError`` from a read-only property used to be swallowed, which left
    the sensitive original rendered while the run looked clean. Any refusal — or
    a write that silently does not take — is now an error the caller escalates to
    whole-detail replacement.
    """
    setattr(repr_obj, field, value)
    if getattr(repr_obj, field, None) != value:
        raise _Unscrubbable(f"{field} replacement not applied")


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

    Replacement is verified. If the report cannot be rewritten at all, the
    sensitive text is still reachable, so the condition is id-detected for
    :func:`_verify_report` to catch and the failure is reported once rather than
    silently accepted.
    """
    name = "failure"
    if excinfo is not None:
        try:
            name = type(excinfo.value).__name__ or name
        except Exception:
            pass
    withheld = f"{name}: failure detail withheld (privacy filter error)"
    applied = True
    try:
        report.longrepr = withheld
        applied = getattr(report, "longrepr", None) == withheld
    except Exception:
        applied = False
    try:
        report.sections = []
    except Exception:
        applied = False
    if not applied:
        raise _Unscrubbable("report rejects whole-detail replacement")


# ── pytest plugin entry point ─────────────────────────────────────────


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    """Redact the report before any pytest reporter renders it."""
    outcome = yield
    report = outcome.get_result()
    if hasattr(report, "longrepr") and hasattr(report, "sections"):
        scrub_report(report, getattr(call, "excinfo", None))
