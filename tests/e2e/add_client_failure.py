"""Closed-schema client-creation failure facts from the lifecycle operator log.

Issue #744: the DEV lifecycle repeatedly reported ``add_client_failed`` HTTP 500s
in the user-connection path, but the underlying ``err`` was never retained. Two
facts were missing: the user-path handler discarded the error entirely, and the
lifecycle finalizer deletes the raw operator log after reducing only the install
lines it knows about. The first is fixed at the handler (``internal/handlers/
users.go`` emits ``failed to add client`` exactly like the admin path already
does); this module is the second.

It reduces those lines to a closed category plus bounded integers, and never
publishes ``error`` text, remote stdout/stderr, paths, addresses, ids or
credentials. A step that does not match an allowlisted producer prefix is
reported as ``other`` rather than guessed, and a line whose shape or field set is
unexpected is rejected whole.

``step`` names the stage of ``ProtocolManager.AddClient`` that failed -- the
first question the missing observation has to answer distinguishably, e.g. the
SSH pool versus the durable clients-table write versus the remote config upsert.

Shared privacy primitives and the protocol alias table live in
:mod:`tests.e2e.diagnostics` and :mod:`tests.e2e.install_failure`; they are
imported rather than restated so there is one implementation of each decision.
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
from tests.e2e.install_failure import PROTOCOL_ALIASES

# The exact message both client-creation handlers log before they mask the error
# for the client. Matched as a bare substring, like the sibling collectors, so
# the marker survives a quoting change by the log handler.
ADD_CLIENT_FAILURE_MARKER = "failed to add client"
ADD_CLIENT_FAILURE_SOURCE = "client-creation-failure-log"

_REPORT_KEYS = frozenset({"schema_version", "source", "occurrences", "add_client_failures"})
_FAILURE_KEYS = frozenset({"server_id", "protocol", "step", "occurrences"})
# The complete key set of the producer line: slog's envelope plus the fields the
# handler passes. A line carrying anything else was not produced by these call
# sites (or was corrupted), so none of it is trusted.
_LINE_KEYS = frozenset({"time", "level", "msg", "server_id", "protocol", "error"})

# Steps inside ProtocolManager.AddClient. Order is significant where prefixes
# overlap ("failed to get server config" is a prefix of the container variant).
# Each entry is a wrapper the producer itself emits; nothing here is inferred.
_STEP_PREFIXES: Tuple[Tuple[str, str], ...] = (
    # internal/manager/awg/awg.go AddClient path
    ("failed to acquire remote server lock", "remote_lock"),
    ("failed to generate client keypair", "client_keys"),
    ("failed to get AmneziaWG server public key", "server_key"),
    ("failed to read clientsTable", "clients_table_read"),
    ("failed to allocate non-conflicting IP", "ip_alloc"),
    ("failed to adopt AWG client IP lease", "ip_alloc"),
    ("failed to release conflicting allocated IP lease", "ip_alloc"),
    ("failed to ensure backend NAT rules", "nat_rules"),
    ("failed to save clients table", "clients_table_save"),
    ("failed to upsert peer in config", "config_upsert"),
    ("failed to fetch remote config for CAS check", "config_conflict"),
    ("failed to fetch clientsTable for CAS retry", "config_conflict"),
    ("failed to commit remote config", "config_conflict"),
    ("failed to get server config", "server_config_read"),
    # internal/manager/xray/xray_client.go AddClient path
    ("failed to download xray config", "config_read"),
    ("download xray config", "config_read"),
    ("failed to parse xray config", "config_parse"),
    ("parse xray config", "config_parse"),
    ("add client to xray config", "config_upsert"),
    ("upload updated xray config", "config_upload"),
    ("failed to restart xray container", "container_restart"),
    ("derive reality public key", "reality_key"),
    ("build vless URI", "uri_build"),
    # internal/manager/naive/naive_client.go AddClient path
    ("download Caddyfile", "config_read"),
    ("parse Caddyfile", "config_parse"),
    ("generate credentials", "credentials"),
    ("add client to Caddyfile", "config_upsert"),
    ("validate updated Caddyfile", "config_validate"),
    ("upload updated Caddyfile", "config_upload"),
    ("failed to reload caddy container", "container_restart"),
    ("build naive URI", "uri_build"),
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

MAX_ADD_CLIENT_OCCURRENCES = 100000
MAX_FAILURES = 16
# Server ids are bounded like the sibling collectors; a value outside this is
# corruption, not a measurement.
MAX_SERVER_ID = 10**6


def classify_step(err: str) -> str:
    """Map an ``error=`` value to an allowlisted step, or ``other`` when unknown.

    Only the producer's own wrapper prefixes are matched. Anything else -- a
    different error, a reworded message, or hostile text -- collapses to
    ``other`` instead of being labelled with a guessed cause.
    """
    for prefix, step in _STEP_PREFIXES:
        if err.startswith(prefix):
            return step
    if err.startswith(_SSH_STEP_PREFIXES):
        return "ssh_client"
    return "other"


def parse_add_client_failure_log(text: str) -> Optional[Dict[str, Any]]:
    """Extract closed-schema client-creation failure facts from operator log text.

    Returns ``None`` when no line carries the marker: absent evidence must never
    be read as a successful request. A line whose field set, server id or
    protocol is outside the closed sets is rejected whole and contributes
    nothing.
    """
    failures: Dict[Tuple[int, str, str], int] = {}
    occurrences = 0
    for line in text.splitlines():
        if ADD_CLIENT_FAILURE_MARKER not in line:
            continue
        fields = {k: _unquote_logfmt(v) for k, v in _LOGFMT_RE.findall(line)}
        if frozenset(fields) != _LINE_KEYS:
            continue
        server_id = _bounded_int(fields.get("server_id"), 0, MAX_SERVER_ID)
        if server_id is None or not re.fullmatch(r"\d{1,7}", fields.get("server_id", "")):
            continue
        protocol = PROTOCOL_ALIASES.get(fields.get("protocol", ""))
        if protocol is None:
            continue
        key = (server_id, protocol, classify_step(fields.get("error", "")))
        occurrences += 1
        failures[key] = failures.get(key, 0) + 1

    if not occurrences:
        return None

    ranked = sorted(failures.items(), key=lambda item: (-item[1], item[0]))
    return {
        "schema_version": SCHEMA_VERSION,
        "source": ADD_CLIENT_FAILURE_SOURCE,
        "occurrences": occurrences,
        "add_client_failures": [
            {
                "server_id": key[0],
                "protocol": key[1],
                "step": key[2],
                "occurrences": count,
            }
            for key, count in ranked[:MAX_FAILURES]
        ],
    }


def validate_add_client_failure_report(payload: Any) -> List[str]:
    """Return the reasons a client-creation failure report is unpublishable."""
    if not isinstance(payload, dict):
        return ["client-creation failure report is not an object"]
    if frozenset(payload) != _REPORT_KEYS:
        return ["client-creation failure report keys are not the allowlisted set"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return ["client-creation failure report schema mismatch"]
    if payload.get("source") != ADD_CLIENT_FAILURE_SOURCE:
        return ["client-creation failure report source not allowlisted"]
    if _bounded_int(payload.get("occurrences"), 1, MAX_ADD_CLIENT_OCCURRENCES) is None:
        return ["client-creation failure report occurrences not a bounded integer"]
    failures = payload.get("add_client_failures")
    if not isinstance(failures, list):
        return ["client-creation failure report add_client_failures is not a list"]
    if not 1 <= len(failures) <= MAX_FAILURES:
        return ["client-creation failure report add_client_failures length out of bounds"]

    problems: List[str] = []
    for failure in failures:
        if not isinstance(failure, dict):
            problems.append("client-creation failure is not an object")
            continue
        if frozenset(failure) != _FAILURE_KEYS:
            problems.append("client-creation failure keys are not the allowlisted set")
            continue
        if _bounded_int(failure.get("server_id"), 0, MAX_SERVER_ID) is None:
            problems.append("client-creation failure server_id not bounded")
        if failure.get("protocol") not in PROTOCOL_ALIASES.values():
            problems.append("client-creation failure protocol not allowlisted")
        if failure.get("step") not in STEPS:
            problems.append("client-creation failure step not allowlisted")
        if _bounded_int(failure.get("occurrences"), 1, MAX_ADD_CLIENT_OCCURRENCES) is None:
            problems.append("client-creation failure occurrences not bounded")
    return problems + _scan_for_forbidden(payload)


def write_add_client_failure_artifact(
    directory: Path, payload: Dict[str, Any]
) -> Optional[Path]:
    """Write the client-creation failure report if, and only if, it validates."""
    return _write_checked(
        directory / "add-client-failure.json",
        payload,
        validate_add_client_failure_report,
    )


def collect_add_client_failure_log(raw: str, directory: Path) -> int:
    """Parse operator log text for client-creation failures. 0 = nothing failed.

    Same contract as the sibling collectors: log content stays in memory, the
    absence of the marker writes nothing and prints no failure, and a collection
    problem never fails the lifecycle by itself.
    """
    payload = parse_add_client_failure_log(raw)
    if payload is None:
        print("E2E diagnostics: client-creation failures collected, 0 failed-request line(s)")
        return 0
    written = write_add_client_failure_artifact(directory, payload)
    print(
        "E2E diagnostics: client-creation failures collected, "
        f"{payload['occurrences']} failed-request line(s), "
        f"failures={len(payload['add_client_failures'])}, written={1 if written else 0}"
    )
    return 0
