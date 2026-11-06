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
            problems = validate_payload(payload) if is_payload else validate_versions(payload)
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
    args = parser.parse_args(argv)
    return gate(Path(args.validate_dir))


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.exit(main())
