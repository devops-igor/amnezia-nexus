"""Privacy-first, allowlisted diagnostics for the E2E setup lifecycle.

The module records only closed-set facts needed to answer one question: which
navigation followed the setup click, and did it ever complete. Every value is
produced by an allowlist, so no request body, header, query string, origin,
cookie or credential is ever read — there is nothing to redact afterwards.
Anything that fails validation is dropped at write time, and the pre-upload
gate deletes whatever fails a second check, so the artifact directory can only
ever hold validated data.

Playwright is not imported here: callers hand in event objects, which keeps the
offline unit tests free of a browser stack.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import sys
import time
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
MAX_EVENTS = 200
MAX_PAYLOAD_BYTES = 65536
MAX_DURATION_MS = 600000
MAX_TEST_ID = 80

_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,31}$")
_ERROR_CODE_RE = re.compile(r"\bnet::[A-Z_]{2,40}\b")
_URL_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*([^?#]*)")

# Substrings that must never reach an artifact: a second line of defence behind
# allowlist-only construction, applied to the serialized payload.
FORBIDDEN_SUBSTRINGS = (
    "password",
    "passwd",
    "cookie",
    "token",
    "authorization",
    "secret",
    "://",
    "?",
    "@",
    "\\",
    "//",
)

# Exact URL paths we are willing to name; anything else collapses to "other".
_ROUTE_CATEGORIES = (
    ("/api/auth/setup", "auth_setup_api"),
    ("/api/auth/login", "auth_login_api"),
    ("/api/auth/logout", "auth_logout_api"),
    ("/api/health", "health_api"),
    ("/setup", "auth_setup_page"),
    ("/login", "auth_login_page"),
    ("/", "panel_index"),
)
_STATIC_TYPES = frozenset({"stylesheet", "script", "image", "font", "media"})
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "other"})
_ROUTES = frozenset(name for _, name in _ROUTE_CATEGORIES) | {"static", "other"}
_PACKAGE_NAMES = ("pytest", "playwright", "pytest-playwright", "pytest-asyncio", "pytest-cov")
_PAYLOAD_KEYS = frozenset({"schema_version", "test", "events", "dropped", "browser"})
_VERSION_FIELDS = ("python", "implementation", "system", "machine")
# Provenance here is *requested*, never verified: the checked-out revision and the
# image label the workflow intended to run. Nothing in an offline artifact can
# prove which image was actually launched or deployed.
_REPORT_KEYS = frozenset(
    {
        "schema_version",
        *_VERSION_FIELDS,
        "packages",
        "provenance",
        "requested_source_sha",
        "requested_image_label",
        "browser",
    }
)
PROVENANCE_REQUESTED_ONLY = "requested-only"
_BROWSER_KEYS = frozenset({"name", "version"})
_KINDS = ("request", "response", "request_failed", "navigation", "load")

# Per-kind field names plus per-field validators: one table drives recording,
# validation and the tests, so what is recorded and what may be published
# cannot drift apart.
_EVENT_FIELDS = {
    "request": ("t_ms", "route", "method", "nav"),
    "response": ("t_ms", "route", "status", "duration_ms"),
    "request_failed": ("t_ms", "route", "method", "error"),
    "navigation": ("t_ms", "route", "mainframe"),
    "load": ("t_ms", "route", "mainframe"),
}


def _bounded_int(value: Any, low: int, high: int) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if low <= number <= high else None


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_status(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return value == 0 or 100 <= value <= 599


def _safe_token(value: Any) -> Optional[str]:
    text = str(value)
    return text if _TOKEN_RE.match(text) else None


_FIELD_VALIDATORS: Dict[str, Callable[[Any], bool]] = {
    "t_ms": lambda value: _bounded_int(value, 0, MAX_DURATION_MS) is not None,
    "route": lambda value: value in _ROUTES,
    "method": lambda value: value in _METHODS,
    "status": _is_status,
    "duration_ms": lambda value: _bounded_int(value, 0, MAX_DURATION_MS) is not None,
    "nav": _is_bool,
    "mainframe": _is_bool,
    "error": lambda value: _safe_token(value) is not None,
}


# ── Allowlisted value helpers ─────────────────────────────────────────


def url_path(url: Any) -> str:
    """Return only the path component of a URL, discarding origin and query."""
    try:
        text = str(url)
    except Exception:  # pragma: no cover - defensive
        return ""
    match = _URL_PATH_RE.match(text)
    if match:
        return match.group(1) or "/"
    return text.split("?", 1)[0].split("#", 1)[0]


def route_category(url: Any, resource_type: Any = "") -> str:
    """Map a URL to one allowlisted route category, never echoing the URL."""
    path = url_path(url)
    if not path:
        return "other"
    if path != "/" and path.endswith("/"):
        path = path[:-1] or "/"
    for known, name in _ROUTE_CATEGORIES:
        if path == known:
            return name
    return "static" if str(resource_type) in _STATIC_TYPES else "other"


def method_name(method: Any) -> str:
    """Return an allowlisted HTTP method or "other"."""
    text = str(method or "").upper()
    return text if text in _METHODS else "other"


def error_code(message: Any) -> str:
    """Extract a Playwright network error code; drop any surrounding text."""
    match = _ERROR_CODE_RE.search(str(message or ""))
    return match.group(0) if match else "other"


def sanitize_test_id(nodeid: Any) -> str:
    """Reduce a pytest node id to a bounded, filesystem-safe token."""
    text = str(nodeid or "unknown").rsplit("/", 1)[-1]
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", text)
    return cleaned[:MAX_TEST_ID] or "unknown"


# ── Recorder ──────────────────────────────────────────────────────────


class RequestNavigationRecorder:
    """Collects bounded, allowlisted request and navigation events."""

    def __init__(self, started: Optional[float] = None, max_events: int = MAX_EVENTS) -> None:
        self._start = time.monotonic() if started is None else started
        self._max_events = max_events
        self._events: List[Dict[str, Any]] = []
        self._inflight: Dict[int, int] = {}
        self._dropped = 0
        self.browser: Dict[str, str] = {}

    @property
    def dropped(self) -> int:
        """Number of events rejected by validation or dropped past the cap."""
        return self._dropped

    def events(self) -> List[Dict[str, Any]]:
        """Return the recorded events (already allowlisted)."""
        return list(self._events)

    def _elapsed(self) -> int:
        return max(0, int((time.monotonic() - self._start) * 1000))

    def _record(self, kind: str, **fields: Any) -> None:
        """Append one bounded event of a known kind, counting what it drops."""
        event = {"kind": kind, **fields}
        if validate_event(event) or len(self._events) >= self._max_events:
            self._dropped += 1
            return
        self._events.append(event)

    def record_browser(self, page: Any) -> None:
        """Record browser name/version if the page exposes them."""
        info: Dict[str, str] = {}
        try:
            browser = page.context.browser
            name = _safe_token(getattr(browser.browser_type, "name", ""))
            version = str(getattr(browser, "version", ""))
            if name:
                info["name"] = name
            if _VERSION_RE.match(version):
                info["version"] = version
        except Exception:
            logger.debug("diagnostics: browser metadata unavailable", exc_info=True)
        self.browser = info

    def on_request(self, request: Any) -> None:
        """Record an outgoing request by category, method and nav flag only."""
        try:
            probe = getattr(request, "is_navigation_request", None)
            self._inflight[id(request)] = self._elapsed()
            self._record(
                "request",
                t_ms=self._elapsed(),
                route=route_category(
                    getattr(request, "url", ""), getattr(request, "resource_type", "")
                ),
                method=method_name(getattr(request, "method", "")),
                nav=bool(probe()) if callable(probe) else False,
            )
        except Exception:
            logger.debug("diagnostics: request event skipped", exc_info=True)

    def on_response(self, response: Any) -> None:
        """Record a response status and elapsed duration for its request."""
        try:
            now = self._elapsed()
            request = getattr(response, "request", None)
            started = self._inflight.pop(id(request), None) if request is not None else None
            self._record(
                "response",
                t_ms=now,
                route=route_category(getattr(response, "url", ""), ""),
                status=getattr(response, "status", 0),
                duration_ms=0 if started is None else min(now - started, MAX_DURATION_MS),
            )
        except Exception:
            logger.debug("diagnostics: response event skipped", exc_info=True)

    def on_requestfailed(self, request: Any) -> None:
        """Record a failed request by category and network error code."""
        try:
            self._inflight.pop(id(request), None)
            self._record(
                "request_failed",
                t_ms=self._elapsed(),
                route=route_category(
                    getattr(request, "url", ""), getattr(request, "resource_type", "")
                ),
                method=method_name(getattr(request, "method", "")),
                error=error_code(getattr(request, "failure", "")),
            )
        except Exception:
            logger.debug("diagnostics: request_failed event skipped", exc_info=True)

    def on_framenavigated(self, frame: Any, mainframe: bool) -> None:
        """Record a navigation target category and whether it is the main frame."""
        try:
            self._record(
                "navigation",
                t_ms=self._elapsed(),
                route=route_category(getattr(frame, "url", ""), "document"),
                mainframe=bool(mainframe),
            )
        except Exception:
            logger.debug("diagnostics: navigation event skipped", exc_info=True)

    def on_load(self, page: Any, mainframe: bool) -> None:
        """Record a completed load, i.e. a navigation that settled."""
        try:
            self._record(
                "load",
                t_ms=self._elapsed(),
                route=route_category(getattr(page, "url", ""), "document"),
                mainframe=bool(mainframe),
            )
        except Exception:
            logger.debug("diagnostics: load event skipped", exc_info=True)


def attach(page: Any, recorder: RequestNavigationRecorder) -> None:
    """Subscribe the recorder to a Playwright page, tolerating API drift."""
    subscriptions = (
        ("request", recorder.on_request),
        ("response", recorder.on_response),
        ("requestfailed", recorder.on_requestfailed),
        (
            "framenavigated",
            lambda frame: recorder.on_framenavigated(frame, _is_mainframe(frame, page)),
        ),
        ("load", lambda _page: recorder.on_load(page, True)),
    )
    for event, handler in subscriptions:
        try:
            page.on(event, handler)
        except Exception:
            logger.debug("diagnostics: cannot subscribe to %s", event, exc_info=True)
    recorder.record_browser(page)


def _is_mainframe(frame: Any, page: Any) -> bool:
    try:
        return frame is page.main_frame
    except Exception:
        return False


# ── Validation: the single source of truth for publishable content ────


def validate_event(event: Any) -> List[str]:
    """Return the reasons an event is not allowlisted; empty means valid."""
    if not isinstance(event, dict):
        return ["event is not an object"]
    expected = _EVENT_FIELDS.get(str(event.get("kind")))
    if expected is None:
        return ["event kind not allowlisted"]
    if frozenset(event) != frozenset({"kind", *expected}):
        return ["event keys do not match its kind"]
    return [
        f"{field} not allowlisted"
        for field in expected
        if not _FIELD_VALIDATORS[field](event.get(field))
    ]


def _scan_for_forbidden(payload: Any) -> List[str]:
    lowered = json.dumps(payload, sort_keys=True).lower()
    if any(marker in lowered for marker in FORBIDDEN_SUBSTRINGS):
        return ["payload contains a forbidden substring"]
    return []


def validate_payload(payload: Any) -> List[str]:
    """Return a list of schema/privacy problems; empty means upload-safe."""
    if not isinstance(payload, dict):
        return ["payload is not an object"]
    if frozenset(payload) != _PAYLOAD_KEYS:
        return ["payload keys are not the allowlisted set"]
    problems: List[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        problems.append("schema_version unsupported")
    if not _TOKEN_RE.match(str(payload.get("test", ""))):
        problems.append("test id is not a safe token")
    if _bounded_int(payload.get("dropped"), 0, 10**6) is None:
        problems.append("dropped is not a bounded integer")
    events = payload.get("events")
    if not isinstance(events, list):
        return problems + ["events is not a list"]
    if len(events) > MAX_EVENTS:
        problems.append("event list exceeds cap")
    for event in events:
        problems.extend(validate_event(event))
    browser = payload.get("browser")
    if not isinstance(browser, dict):
        problems.append("browser is not an object")
    elif any(key not in _BROWSER_KEYS or not _safe_token(v) for key, v in browser.items()):
        problems.append("browser field not allowlisted")
    return problems + _scan_for_forbidden(payload)


def validate_versions(payload: Any) -> List[str]:
    """Return the reasons a runtime version report is unpublishable."""
    if not isinstance(payload, dict):
        return ["version report is not an object"]
    if frozenset(payload) - _REPORT_KEYS:
        return ["version report keys not allowlisted"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return ["version report schema mismatch"]
    for key in _VERSION_FIELDS:
        if not _VERSION_RE.match(str(payload.get(key, ""))):
            return [f"version report {key} invalid"]
    if payload.get("provenance", PROVENANCE_REQUESTED_ONLY) != PROVENANCE_REQUESTED_ONLY:
        return ["provenance must be claimed as requested-only"]
    sha = payload.get("requested_source_sha")
    if sha is not None and not _SHA_RE.match(str(sha)):
        return ["requested_source_sha invalid"]
    image = payload.get("requested_image_label")
    if image is not None and not _IMAGE_RE.match(str(image)):
        return ["requested_image_label invalid"]
    packages = payload.get("packages", {})
    if not isinstance(packages, dict):
        return ["packages is not an object"]
    if any(
        name not in _PACKAGE_NAMES or not _VERSION_RE.match(str(v)) for name, v in packages.items()
    ):
        return ["package entry not allowlisted"]
    browser = payload.get("browser", {})
    if not isinstance(browser, dict):
        return ["browser is not an object"]
    if any(key not in _BROWSER_KEYS or not _safe_token(v) for key, v in browser.items()):
        return ["browser entry not allowlisted"]
    return _scan_for_forbidden(payload)


# ── Payload construction ──────────────────────────────────────────────


def build_payload(test_id: Any, recorder: RequestNavigationRecorder) -> Dict[str, Any]:
    """Build the failure payload from a recorder (allowlisted values only)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "test": sanitize_test_id(test_id),
        "events": recorder.events(),
        "dropped": recorder.dropped,
        "browser": dict(recorder.browser),
    }


def environment_versions() -> Dict[str, Any]:
    """Collect the exact environment facts for this run (no origins/hosts)."""
    packages: Dict[str, str] = {}
    for name in _PACKAGE_NAMES:
        try:
            version = metadata.version(name)
        except Exception:
            continue
        if _VERSION_RE.match(version):
            packages[name] = version
    versions: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "provenance": PROVENANCE_REQUESTED_ONLY,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "packages": packages,
    }
    sha = _env_value("GITHUB_SHA", "E2E_TESTED_SOURCE_SHA", pattern=_SHA_RE)
    if sha:
        versions["requested_source_sha"] = sha
    image = _env_value("E2E_TESTED_IMAGE_LABEL", pattern=_IMAGE_RE)
    if image:
        versions["requested_image_label"] = image
    return versions


def _env_value(*names: str, pattern: Any) -> Optional[str]:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value and pattern.match(value):
            return value
    return None


# ── Artifact writing (fail closed) ────────────────────────────────────


def diagnostics_dir() -> Path:
    """Return the configured artifact directory."""
    configured = os.environ.get("E2E_DIAGNOSTICS_DIR", "").strip()
    return Path(configured) if configured else Path("test-artifacts") / "e2e-diagnostics"


def write_failure_artifact(directory: Path, payload: Dict[str, Any]) -> Optional[Path]:
    """Write one failure payload if, and only if, it validates."""
    name = f"setup-{payload.get('test', 'unknown')}.json"
    return _write_checked(directory / name, payload, validate_payload)


def write_versions_artifact(
    directory: Path, versions: Dict[str, Any], browsers: Dict[str, str]
) -> Optional[Path]:
    """Write the runtime version report if it validates."""
    payload = dict(versions)
    known = {key: value for key, value in browsers.items() if _safe_token(value)}
    if known:
        payload["browser"] = known
    return _write_checked(directory / "runtime-versions.json", payload, validate_versions)


def _write_checked(
    path: Path, payload: Dict[str, Any], validate: Callable[[Any], List[str]]
) -> Optional[Path]:
    """Validate, size-bound and atomically write; return None on refusal."""
    problems = validate(payload)
    if problems:
        logger.warning("E2E diagnostics discarded: %d validation problem(s)", len(problems))
        return None
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if len(text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        logger.warning("E2E diagnostics discarded: artifact exceeds size bound")
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return path
    except Exception:
        logger.warning("E2E diagnostics could not be written")
        return None


# ── Failed-probe evidence: closed-schema facts from the operator log ──

# The panel emits one structured warning when its unprivileged Docker CLI probe
# answers negative (ServerCheckHandler). Those facts are the only thing this
# collector reads: every other byte of the log — and every other field of the
# matching line — is discarded before anything is written or printed.
PROBE_LOG_MARKER = "ServerCheckHandler: docker CLI probe failed"
PROBE_SOURCE = "failed-probe-log"

_PROBE_KEYS = frozenset({"schema_version", "source", "occurrences", "observations"})
_OBSERVATION_KEYS = frozenset(
    {"server_id", "exit_code", "transport_error", "stdout_state", "stdout_len", "stderr_len"}
)
# Closed sets mirrored from internal/handlers/docker_probe.go. A value outside
# these collapses the whole line to a rejection; it is never passed through.
_TRANSPORT_ERRORS = frozenset({"", "not_connected", "timeout", "canceled", "other"})
_STDOUT_STATES = frozenset({"empty", "docker_token", "other_text"})
MAX_PROBE_OCCURRENCES = 100000
MAX_OBSERVATIONS = 16
MAX_LOG_BYTES = 8 * 1024 * 1024

# A logfmt field: key=value, value optionally double-quoted with backslash
# escapes. Anchored so a crafted line cannot smuggle a second assignment in.
_LOGFMT_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|[^\s]*)')


def _unquote_logfmt(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        body = value[1:-1]
        return re.sub(r"\\(.)", r"\1", body)
    return value


def _bounded_int_field(fields: Dict[str, str], key: str) -> Optional[int]:
    raw = fields.get(key)
    if raw is None:
        return None
    if not re.fullmatch(r"-?\d{1,9}", raw):
        return None
    return _bounded_int(raw, -1, 10**6)


def parse_probe_log(text: str) -> Optional[Dict[str, Any]]:
    """Extract closed-schema probe facts from operator log text.

    Returns None when no line carries the marker: absent evidence must not be
    confused with a clean result. Only allowlisted keys are read; the marker
    line's timestamp, level, message and any unknown/crafted field are dropped.
    """
    observations: Dict[tuple, int] = {}
    occurrences = 0
    for line in text.splitlines():
        if PROBE_LOG_MARKER not in line:
            continue
        fields = {k: _unquote_logfmt(v) for k, v in _LOGFMT_RE.findall(line)}
        transport = fields.get("transport_error", "")
        stdout_state = fields.get("stdout_state", "")
        if transport not in _TRANSPORT_ERRORS or stdout_state not in _STDOUT_STATES:
            # Unknown category: the Go side would never emit it, so treat the
            # line as unparseable rather than publishing an unchecked value.
            continue
        server_id = _bounded_int_field(fields, "server_id")
        exit_code = _bounded_int_field(fields, "exit_code")
        stdout_len = _bounded_int_field(fields, "stdout_len")
        stderr_len = _bounded_int_field(fields, "stderr_len")
        if None in (server_id, exit_code, stdout_len, stderr_len):
            continue
        occurrences += 1
        key = (server_id, exit_code, transport, stdout_state, stdout_len, stderr_len)
        observations[key] = observations.get(key, 0) + 1

    if not occurrences:
        return None

    ranked = sorted(observations.items(), key=lambda item: (-item[1], item[0]))
    return {
        "schema_version": SCHEMA_VERSION,
        "source": PROBE_SOURCE,
        "occurrences": occurrences,
        "observations": [
            {
                "server_id": key[0],
                "exit_code": key[1],
                "transport_error": key[2],
                "stdout_state": key[3],
                "stdout_len": key[4],
                "stderr_len": key[5],
            }
            for key, _ in ranked[:MAX_OBSERVATIONS]
        ],
    }


def validate_probe_report(payload: Any) -> List[str]:
    """Return the reasons a probe report is unpublishable; empty means safe."""
    if not isinstance(payload, dict):
        return ["probe report is not an object"]
    if frozenset(payload) != _PROBE_KEYS:
        return ["probe report keys are not the allowlisted set"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return ["probe report schema mismatch"]
    if payload.get("source") != PROBE_SOURCE:
        return ["probe report source not allowlisted"]
    if _bounded_int(payload.get("occurrences"), 1, MAX_PROBE_OCCURRENCES) is None:
        return ["probe report occurrences not a bounded integer"]
    observations = payload.get("observations")
    if not isinstance(observations, list):
        return ["probe report observations is not a list"]
    if not 1 <= len(observations) <= MAX_OBSERVATIONS:
        return ["probe report observations length out of bounds"]
    problems: List[str] = []
    for observation in observations:
        if not isinstance(observation, dict):
            problems.append("probe observation is not an object")
            continue
        if frozenset(observation) != _OBSERVATION_KEYS:
            problems.append("probe observation keys are not the allowlisted set")
            continue
        if _bounded_int(observation.get("server_id"), 0, 10**6) is None:
            problems.append("probe observation server_id not bounded")
        if _bounded_int(observation.get("exit_code"), -1, 10**6) is None:
            problems.append("probe observation exit_code not bounded")
        if observation.get("transport_error") not in _TRANSPORT_ERRORS:
            problems.append("probe observation transport_error not allowlisted")
        if observation.get("stdout_state") not in _STDOUT_STATES:
            problems.append("probe observation stdout_state not allowlisted")
        if _bounded_int(observation.get("stdout_len"), 0, 10**6) is None:
            problems.append("probe observation stdout_len not bounded")
        if _bounded_int(observation.get("stderr_len"), 0, 10**6) is None:
            problems.append("probe observation stderr_len not bounded")
    return problems + _scan_for_forbidden(payload)


def write_probe_artifact(directory: Path, payload: Dict[str, Any]) -> Optional[Path]:
    """Write the probe report if, and only if, it validates."""
    return _write_checked(directory / "docker-probe.json", payload, validate_probe_report)


def collect_probe_log(raw: str, directory: Path) -> int:
    """Parse operator log text and persist the bounded report. 0 = nothing failed.

    Log content is held in memory only. When no marker line is present nothing
    is written and the exit status stays 0, so a clean run publishes no report
    and a collection failure never fails the lifecycle by itself.
    """
    payload = parse_probe_log(raw)
    if payload is None:
        print("E2E diagnostics: probe log collected, 0 failed-probe line(s)")
        return 0
    written = write_probe_artifact(directory, payload)
    print(
        f"E2E diagnostics: probe log collected, {payload['occurrences']} failed-probe line(s), "
        f"observations={len(payload['observations'])}, written={1 if written else 0}"
    )
    return 0


# ── Provider call timing: closed-schema facts from the same operator log ──

# The panel emits one structured slog line per Gigahost provider call when
# GIGAHOST_CALL_TIMING=1 (internal/provider/gigahost/timing.go). That line is the
# only thing read here: the marker plus allowlisted key=value pairs. Every other
# byte of the log, and every field this module does not recognise, is discarded
# before anything is written — the record carries no URL, host, id, header, body
# or error text by construction, and this is the second line of defence.
CALL_TIMING_MARKER = "msg=gigahost_call"
TIMING_SOURCE = "provider-call-timing"

_TIMING_KEYS = frozenset(
    {"schema_version", "source", "occurrences", "calls", "truncated"}
)
_CALL_KEYS = frozenset(
    {
        "method",
        "op",
        "outcome",
        "status",
        "total_ms",
        "last_phase",
        "reused",
        "proto",
        "get_conn_ms",
        "dns_ms",
        "connect_ms",
        "tls_ms",
        "request_written_ms",
        "first_byte_ms",
    }
)
# Closed sets mirrored from internal/provider/gigahost/timing.go. A value outside
# these rejects the whole line rather than passing an unverified string through.
_TIMING_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "other"})
_TIMING_OUTCOMES = frozenset(
    {
        "ok",
        "http_status",
        "caller_deadline",
        "caller_canceled",
        "client_timeout",
        "network_error",
        "other_error",
    }
)
_TIMING_PHASES = frozenset(
    {
        "",
        "get_conn",
        "dns_start",
        "dns_done",
        "connect_start",
        "connect_done",
        "tls_start",
        "tls_done",
        "request_written",
        "first_byte",
    }
)
_TIMING_PROTOS = frozenset({"", "http/1.1", "h2"})
# Operation labels are generated by OperationLabel; the closed shape is
# <known-family>_<verb> or "other". Anything else is not published.
_TIMING_OPS = frozenset(
    {
        f"{family}_{verb}"
        for family in ("deploy_servers", "deploy_status", "servers", "account")
        for verb in ("get", "post", "put", "patch", "delete", "head", "options")
    }
    | {"other"}
)
_NOT_REACHED = -1
MAX_TIMING_OCCURRENCES = 100000
MAX_TIMING_CALLS = 200
# The complete set of keys a timing line may carry: slog's own envelope plus the
# record's fixed fields. A line carrying anything else is rejected whole rather
# than parsed for its allowlisted subset — a log line that was crafted or
# corrupted is not evidence, even when the fields we recognise look valid.
_TIMING_LINE_KEYS = frozenset({"time", "level", "msg"}) | _CALL_KEYS


def _timing_int(fields: Dict[str, str], key: str, low: int, high: int) -> Optional[int]:
    """Read one bounded integer field, or None when it is absent/invalid."""
    raw = fields.get(key)
    if raw is None or not re.fullmatch(r"-?\d{1,9}", raw):
        return None
    return _bounded_int(raw, low, high)


def parse_call_timing_log(text: str) -> Optional[Dict[str, Any]]:
    """Extract closed-schema provider call timings from operator log text.

    Returns None when no line carries the marker: absent evidence must not be
    confused with "the provider was fast". A line whose fields are not exactly the
    allowlisted set, or whose values fall outside the Go-side closed sets, is
    rejected whole — it never contributes a partially-trusted record.
    """
    calls: List[Dict[str, Any]] = []
    occurrences = 0
    truncated = 0
    for line in text.splitlines():
        if CALL_TIMING_MARKER not in line:
            continue
        fields = {k: _unquote_logfmt(v) for k, v in _LOGFMT_RE.findall(line)}
        # Strict whole-line rejection: an unexpected key means the line is not a
        # record this collector produced, so nothing in it is trusted.
        if frozenset(fields) != _TIMING_LINE_KEYS:
            continue
        call: Dict[str, Any] = {}

        method = fields.get("method")
        op = fields.get("op")
        outcome = fields.get("outcome")
        last_phase = fields.get("last_phase", "")
        proto = fields.get("proto", "")
        reused = fields.get("reused")
        if method not in _TIMING_METHODS:
            continue
        if op not in _TIMING_OPS:
            continue
        if outcome not in _TIMING_OUTCOMES:
            continue
        if last_phase not in _TIMING_PHASES:
            continue
        if proto not in _TIMING_PROTOS:
            continue
        if reused not in ("true", "false"):
            continue

        status = _timing_int(fields, "status", 0, 599)
        total_ms = _timing_int(fields, "total_ms", 0, MAX_DURATION_MS)
        phases = {
            key: _timing_int(fields, key, _NOT_REACHED, MAX_DURATION_MS)
            for key in (
                "get_conn_ms",
                "dns_ms",
                "connect_ms",
                "tls_ms",
                "request_written_ms",
                "first_byte_ms",
            )
        }
        if status is None or total_ms is None or any(value is None for value in phases.values()):
            continue

        call.update(
            {
                "method": method,
                "op": op,
                "outcome": outcome,
                "status": status,
                "total_ms": total_ms,
                "last_phase": last_phase,
                "reused": reused == "true",
                "proto": proto,
            }
        )
        call.update(phases)
        occurrences += 1
        if len(calls) < MAX_TIMING_CALLS:
            calls.append(call)
        else:
            truncated += 1

    if not occurrences:
        return None

    return {
        "schema_version": SCHEMA_VERSION,
        "source": TIMING_SOURCE,
        "occurrences": occurrences,
        "calls": calls,
        "truncated": truncated,
    }


def validate_timing_report(payload: Any) -> List[str]:
    """Return the reasons a provider call timing report is unpublishable."""
    if not isinstance(payload, dict):
        return ["timing report is not an object"]
    if frozenset(payload) != _TIMING_KEYS:
        return ["timing report keys are not the allowlisted set"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return ["timing report schema mismatch"]
    if payload.get("source") != TIMING_SOURCE:
        return ["timing report source not allowlisted"]
    if _bounded_int(payload.get("occurrences"), 1, MAX_TIMING_OCCURRENCES) is None:
        return ["timing report occurrences not a bounded integer"]
    if _bounded_int(payload.get("truncated"), 0, MAX_TIMING_OCCURRENCES) is None:
        return ["timing report truncated not a bounded integer"]
    calls = payload.get("calls")
    if not isinstance(calls, list):
        return ["timing report calls is not a list"]
    if not 1 <= len(calls) <= MAX_TIMING_CALLS:
        return ["timing report calls length out of bounds"]

    problems: List[str] = []
    for call in calls:
        if not isinstance(call, dict):
            problems.append("timing call is not an object")
            continue
        if frozenset(call) != _CALL_KEYS:
            problems.append("timing call keys are not the allowlisted set")
            continue
        if call.get("method") not in _TIMING_METHODS:
            problems.append("timing call method not allowlisted")
        if call.get("op") not in _TIMING_OPS:
            problems.append("timing call op not allowlisted")
        if call.get("outcome") not in _TIMING_OUTCOMES:
            problems.append("timing call outcome not allowlisted")
        if call.get("last_phase") not in _TIMING_PHASES:
            problems.append("timing call last_phase not allowlisted")
        if call.get("proto") not in _TIMING_PROTOS:
            problems.append("timing call proto not allowlisted")
        if not isinstance(call.get("reused"), bool):
            problems.append("timing call reused is not a bool")
        if _bounded_int(call.get("status"), 0, 599) is None:
            problems.append("timing call status not bounded")
        if _bounded_int(call.get("total_ms"), 0, MAX_DURATION_MS) is None:
            problems.append("timing call total_ms not bounded")
        for key in (
            "get_conn_ms",
            "dns_ms",
            "connect_ms",
            "tls_ms",
            "request_written_ms",
            "first_byte_ms",
        ):
            if _bounded_int(call.get(key), _NOT_REACHED, MAX_DURATION_MS) is None:
                problems.append(f"timing call {key} not bounded")
    return problems + _scan_for_forbidden(payload)


def write_timing_artifact(directory: Path, payload: Dict[str, Any]) -> Optional[Path]:
    """Write the provider call timing report if, and only if, it validates."""
    return _write_checked(directory / "provider-call-timing.json", payload, validate_timing_report)


def collect_timing_log(raw: str, directory: Path) -> int:
    """Parse operator log text for provider call timings. 0 = nothing failed.

    Same contract as the probe collector: log content stays in memory, absence of
    the marker writes nothing, and a collection problem never fails the lifecycle
    by itself (the gate is the enforcing step).
    """
    payload = parse_call_timing_log(raw)
    if payload is None:
        print("E2E diagnostics: provider call timing collected, 0 record(s)")
        return 0
    written = write_timing_artifact(directory, payload)
    print(
        f"E2E diagnostics: provider call timing collected, {payload['occurrences']} record(s), "
        f"calls={len(payload['calls'])}, truncated={payload['truncated']}, "
        f"written={1 if written else 0}"
    )
    return 0


# ── CLI: gate the artifact directory before upload ────────────────────


def gate(directory: Path) -> int:
    """Validate every artifact and withhold the whole directory on rejection.

    Withholding is all-or-nothing on purpose: a partially pruned directory could
    still publish evidence whose sibling failed validation, and the caller's
    upload step cannot tell the difference. Rejection therefore removes the
    directory outright, so ``upload-artifact`` finds nothing to publish. Only
    counts are printed — never file contents, names or rejected values.
    """
    if not directory.is_dir():
        # Nothing captured: no evidence to withhold, nothing to publish.
        print("E2E diagnostics: files=0 rejected=0 (directory absent)")
        return 0
    files = sorted(directory.glob("*.json"))
    rejected = 0
    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            problems = ["unreadable JSON"]
        else:
            is_payload = isinstance(payload, dict) and ("events" in payload or "test" in payload)
            is_probe = isinstance(payload, dict) and "observations" in payload
            is_timing = isinstance(payload, dict) and "calls" in payload
            if is_payload:
                problems = validate_payload(payload)
            elif is_probe:
                problems = validate_probe_report(payload)
            elif is_timing:
                problems = validate_timing_report(payload)
            else:
                problems = validate_versions(payload)
        if problems:
            rejected += 1
    if rejected:
        withheld = _withhold(directory)
        print(f"E2E diagnostics: files={len(files)} rejected={rejected} withheld={withheld}")
        return 1
    print(f"E2E diagnostics: files={len(files)} rejected=0")
    return 0


def _withhold(directory: Path) -> bool:
    """Remove the evidence directory entirely; True when nothing is left behind."""
    try:
        for path in directory.rglob("*"):
            if path.is_file():
                path.unlink()
        for path in sorted(directory.rglob("*"), reverse=True):
            if path.is_dir():
                path.rmdir()
        directory.rmdir()
        return True
    except OSError:
        logger.warning("E2E diagnostics: could not withhold evidence directory")
        return False


def main(argv: Optional[List[str]] = None) -> int:
    """Validate diagnostics artifacts; non-zero means do not upload."""
    parser = argparse.ArgumentParser(description="Gate E2E diagnostics artifacts before upload")
    parser.add_argument("--validate-dir", required=True, help="directory holding JSON evidence")
    parser.add_argument(
        "--probe-log",
        help="operator log file to reduce to closed-schema failed-probe facts",
    )
    parser.add_argument(
        "--call-timing-log",
        help="operator log file to reduce to closed-schema provider call timings",
    )
    args = parser.parse_args(argv)
    directory = Path(args.validate_dir)
    for flag, collect in (
        ("probe_log", collect_probe_log),
        ("call_timing_log", collect_timing_log),
    ):
        log_arg = getattr(args, flag)
        if not log_arg:
            continue
        # Runs before the gate so the gate validates the artifact this produced.
        # Collection is best-effort: a missing log means nothing to collect.
        log_path = Path(log_arg)
        raw = ""
        try:
            if not log_path.is_file():
                raise OSError("not a regular file")
            if log_path.stat().st_size <= MAX_LOG_BYTES:
                raw = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            print(f"E2E diagnostics: {flag} unreadable, nothing collected")
        collect(raw, directory)
    return gate(directory)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.exit(main())
