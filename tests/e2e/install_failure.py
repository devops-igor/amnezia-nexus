"""Closed-schema AWG install-failure facts from the lifecycle operator log.

The panel already emits one structured error line when a protocol install fails
(``internal/handlers/servers.go``: ``slog.Error("protocol install failed", ...)``)
and that line carries the real ``err=`` value. The client response does not: it
is the constant ``install_failed`` / "Failed to install protocol". The lifecycle
finalizer reads ``docker logs`` into a temporary file and deletes it, so the
cause is destroyed with the container unless it is reduced here first.

This collector reduces that one line to a closed category plus bounded integers.
It never publishes ``err`` text, remote stdout/stderr, paths, addresses, ids or
credentials: a category that does not match an allowlisted producer prefix is
reported as ``other`` rather than guessed, and a line whose shape or field set
is unexpected is rejected whole.

Shared privacy primitives (schema version, logfmt parsing, the forbidden-
substring scan, the checked writer) live in :mod:`tests.e2e.diagnostics` and are
imported from there so there is exactly one implementation; that module imports
this one lazily, which keeps the dependency one-way in practice.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tests.e2e.diagnostics import (
    SCHEMA_VERSION,
    _LOGFMT_RE,
    _bounded_int,
    _scan_for_forbidden,
    _unquote_logfmt,
    _write_checked,
)

# The exact error message the handler logs before it masks the error for the
# client. Matched as a bare substring, like the sibling probe collector, so the
# marker survives a quoting change by the log handler.
INSTALL_FAILURE_MARKER = "protocol install failed"
INSTALL_FAILURE_SOURCE = "protocol-install-failure-log"

_INSTALL_KEYS = frozenset({"schema_version", "source", "occurrences", "failures"})
_FAILURE_KEYS = frozenset({"server_id", "protocol", "port", "step", "exit_code"})
# The complete key set of the producer line: slog's envelope plus the four fields
# the handler passes. A line carrying anything else was not produced by this
# call site (or was corrupted), so none of it is trusted.
_LINE_KEYS = frozenset({"time", "level", "msg", "server_id", "protocol", "port", "err"})

# Failures that fail the install before a container can exist are the ones this
# channel can explain. Order is significant where prefixes overlap.
_STEP_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("failed to acquire remote server lock", "lock_acquire"),
    ("failed to generate AWG params", "awg_params"),
    ("failed to prepare host", "prepare_host"),
    ("UDP port ", "udp_port_in_use"),
    ("failed to upload Dockerfile", "dockerfile_upload"),
    ("failed to pull AWG base image", "image_pull"),
    ("failed to build ", "image_build"),
    ("failed to run container", "container_run"),
)
# SSH client acquisition returns the pool's error verbatim, with no wrapper of
# its own (internal/manager/awg/awg.go getSSHClient).
_SSH_STEP_PREFIXES = (
    "ssh pool is not configured",
    "server cannot be nil",
    "pool failed to dial ",
    "ssh client pool is closed",
)
STEPS = frozenset({step for _, step in _STEP_PREFIXES}) | {"ssh_client", "other"}
# Closed set of protocol names accepted by GetProtocolManager (models.ValidProtocols
# plus models.ProtocolAliases). An install can never reach this log line otherwise.
_PROTOCOLS = {
    "awg": "awg",
    "telemt": "telemt",
    "dns": "dns",
    "vless": "vless",
    "naive": "naive",
    "awg2": "awg",
    "awg_legacy": "awg",
    "vless-reality": "vless",
    "vless_reality": "vless",
    "naiveproxy": "naive",
}
PROTOCOLS = frozenset(_PROTOCOLS.values())
# A remote command's exit status appears as "(code N)" or "(exit code N)".
_EXIT_CODE_RE = re.compile(r"\((?:exit )?code (\d{1,6})\)")
_NOT_STATED = -1
MAX_INSTALL_OCCURRENCES = 100000
MAX_FAILURES = 16


def classify_step(err: str) -> str:
    """Map an ``err=`` value to an allowlisted step, or ``other`` when unknown.

    Only the producer's own wrapper prefixes are matched. Anything else — a
    different error, a reworded message, or hostile text — collapses to
    ``other`` instead of being labelled with a guessed cause.
    """
    for prefix, step in _STEP_PREFIXES:
        if err.startswith(prefix):
            return step
    if err.startswith(_SSH_STEP_PREFIXES):
        return "ssh_client"
    return "other"


def _exit_code(err: str) -> int:
    """Return the bounded exit status the message states, or ``-1``."""
    match = _EXIT_CODE_RE.search(err)
    if not match:
        return _NOT_STATED
    bounded = _bounded_int(match.group(1), 0, 10**6)
    return _NOT_STATED if bounded is None else bounded


def _port(fields: Dict[str, str]) -> Optional[int]:
    raw = fields.get("port", "")
    if raw == "":
        return _NOT_STATED
    if not re.fullmatch(r"\d{1,5}", raw):
        return None
    return _bounded_int(raw, 0, 65535)


def parse_install_failure_log(text: str) -> Optional[Dict[str, Any]]:
    """Extract closed-schema install-failure facts from operator log text.

    Returns ``None`` when no line carries the marker: absent evidence must never
    be read as a successful install. A line whose field set, protocol or port is
    outside the closed sets is rejected whole and contributes nothing.
    """
    failures: Dict[Tuple[int, str, int, str, int], int] = {}
    occurrences = 0
    for line in text.splitlines():
        if INSTALL_FAILURE_MARKER not in line:
            continue
        fields = {k: _unquote_logfmt(v) for k, v in _LOGFMT_RE.findall(line)}
        if frozenset(fields) != _LINE_KEYS:
            continue
        server_id = _bounded_int(fields.get("server_id"), 0, 10**6)
        if server_id is None or not re.fullmatch(r"\d{1,9}", fields.get("server_id", "")):
            continue
        protocol = _PROTOCOLS.get(fields.get("protocol", ""))
        port = _port(fields)
        if protocol is None or port is None:
            continue
        err = fields.get("err", "")
        key = (server_id, protocol, port, classify_step(err), _exit_code(err))
        occurrences += 1
        failures[key] = failures.get(key, 0) + 1

    if not occurrences:
        return None

    ranked = sorted(failures.items(), key=lambda item: (-item[1], item[0]))
    return {
        "schema_version": SCHEMA_VERSION,
        "source": INSTALL_FAILURE_SOURCE,
        "occurrences": occurrences,
        "failures": [
            {
                "server_id": key[0],
                "protocol": key[1],
                "port": key[2],
                "step": key[3],
                "exit_code": key[4],
            }
            for key, _ in ranked[:MAX_FAILURES]
        ],
    }


def validate_install_failure_report(payload: Any) -> List[str]:
    """Return the reasons an install-failure report is unpublishable."""
    if not isinstance(payload, dict):
        return ["install failure report is not an object"]
    if frozenset(payload) != _INSTALL_KEYS:
        return ["install failure report keys are not the allowlisted set"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return ["install failure report schema mismatch"]
    if payload.get("source") != INSTALL_FAILURE_SOURCE:
        return ["install failure report source not allowlisted"]
    if _bounded_int(payload.get("occurrences"), 1, MAX_INSTALL_OCCURRENCES) is None:
        return ["install failure report occurrences not a bounded integer"]
    failures = payload.get("failures")
    if not isinstance(failures, list):
        return ["install failure report failures is not a list"]
    if not 1 <= len(failures) <= MAX_FAILURES:
        return ["install failure report failures length out of bounds"]

    problems: List[str] = []
    for failure in failures:
        if not isinstance(failure, dict):
            problems.append("install failure is not an object")
            continue
        if frozenset(failure) != _FAILURE_KEYS:
            problems.append("install failure keys are not the allowlisted set")
            continue
        if _bounded_int(failure.get("server_id"), 0, 10**6) is None:
            problems.append("install failure server_id not bounded")
        if failure.get("protocol") not in PROTOCOLS:
            problems.append("install failure protocol not allowlisted")
        if _bounded_int(failure.get("port"), _NOT_STATED, 65535) is None:
            problems.append("install failure port not bounded")
        if failure.get("step") not in STEPS:
            problems.append("install failure step not allowlisted")
        if _bounded_int(failure.get("exit_code"), _NOT_STATED, 10**6) is None:
            problems.append("install failure exit_code not bounded")
    return problems + _scan_for_forbidden(payload)


def write_install_failure_artifact(directory: Path, payload: Dict[str, Any]) -> Optional[Path]:
    """Write the install-failure report if, and only if, it validates."""
    return _write_checked(
        directory / "install-failure.json", payload, validate_install_failure_report
    )


def collect_install_failure_log(raw: str, directory: Path) -> int:
    """Parse operator log text for install failures. 0 = nothing failed.

    Same contract as the sibling collectors: log content stays in memory, the
    absence of the marker writes nothing and prints no failure, and a collection
    problem never fails the lifecycle by itself.
    """
    payload = parse_install_failure_log(raw)
    if payload is None:
        print("E2E diagnostics: install failures collected, 0 failed-install line(s)")
        return 0
    written = write_install_failure_artifact(directory, payload)
    print(
        f"E2E diagnostics: install failures collected, {payload['occurrences']} failed-install "
        f"line(s), failures={len(payload['failures'])}, written={1 if written else 0}"
    )
    return 0
