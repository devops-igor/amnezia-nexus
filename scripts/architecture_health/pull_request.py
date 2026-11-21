"""Pull-request-scoped enforcement of the SG1 size transition rule.

The whole-repository scan reports every file above its pinned ceiling. That
inventory is advisory because the repository already carries violations, so it
cannot be turned into a blocking check. Section 4.3 of the module ownership
conventions phrases the rule as a constraint on pull requests, and that half is
mechanical: a PR must not carry a file across the 1,000-line boundary, and must
not grow a file that already sits at or above it. This module judges exactly
that transition, between the PR's merge base and its head, so a PR is measured
against the tree it branched from rather than against the base branch tip.
"""

import json
import logging
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Mapping, Optional

from scripts.architecture_health.constants import (
    DEFAULT_CEILING_LINES,
    is_excluded,
    is_generated_or_vendor,
)
from scripts.architecture_health.discovery import count_content_lines_and_bytes

logger = logging.getLogger("architecture_health")

CROSSED_TRANSITION = "crossed ceiling"
GREW_TRANSITION = "grew above ceiling"

# The two halves of the exception that section 4.3 permits. The label is the
# maintainer's control, because applying one needs triage or write access and a
# contributor's branch cannot grant itself the permission. The heading is the
# statement section 4.3 asks for, recorded in the pull request itself.
EXCEPTION_LABEL = "sg1-size-exception"
JUSTIFICATION_HEADING = "SG1 responsibility justification"


class PrSizeGateError(RuntimeError):
    """Operational failure reading git data for the pull request size gate."""


def size_transition(
    base_lines: int, head_lines: int, ceiling_lines: int = DEFAULT_CEILING_LINES
) -> Optional[str]:
    """Return the prohibited transition between two line counts, or None.

    The two clauses are the ones section 4.3 names: base below the ceiling and
    head at or above it, and base already at or above the ceiling with a larger
    head. An unchanged count, a shrink, and a file that stays below the ceiling
    are all permitted.
    """
    if base_lines < ceiling_lines <= head_lines:
        return CROSSED_TRANSITION
    if base_lines >= ceiling_lines and head_lines > base_lines:
        return GREW_TRANSITION
    return None


def parse_justification(body: Optional[str]) -> str:
    """Return the statement filed under the justification heading, or an empty string.

    Section 4.3 asks for a stated per-PR responsibility justification, so the
    statement lives in the pull request itself. The heading makes it findable and
    reviewable rather than a sentence buried anywhere in the description; the text
    under the heading up to the next heading is the statement.
    """
    if not body:
        return ""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        if stripped.lstrip("#").strip().casefold() != JUSTIFICATION_HEADING.casefold():
            continue
        statement: List[str] = []
        for following in lines[index + 1 :]:
            if following.strip().startswith("#"):
                break
            statement.append(following)
        return "\n".join(statement).strip()
    return ""


def resolve_exception(
    labels: Optional[List[str]] = None, body: Optional[str] = None
) -> Dict[str, Any]:
    """Decide whether this pull request carries a usable exception.

    Both halves are required. The label is the maintainer's control: applying one
    needs triage or write access, so a contributor cannot grant it to themselves.
    The heading is the statement section 4.3 asks for, which only the pull request
    itself can carry. Either half alone is reported as what it is, never as an
    exception.
    """
    label_names = [str(name) for name in (labels or [])]
    justification = parse_justification(body)
    label_present = EXCEPTION_LABEL in label_names
    return {
        "label": EXCEPTION_LABEL,
        "heading": JUSTIFICATION_HEADING,
        "label_present": label_present,
        "justification_present": bool(justification),
        "justification": justification,
        "requested": label_present,
        "valid": label_present and bool(justification),
    }


def load_pull_request_context(path: Optional[str]) -> Dict[str, Any]:
    """Read label names and the description from a GitHub pull request event payload.

    The payload is the file GitHub writes for the run, so the label is read without
    a token and without an API call, and the workflow keeps its read-only
    permission. There is no command-line flag for this: a flag would let a branch
    point the gate at a payload of its own making, which is the self-granted
    exception this mechanism exists to prevent.

    A missing or non-pull-request payload means no exception is requested, which
    can only leave enforcement in place. A payload that exists but cannot be read
    is an operational failure, raised rather than treated as "no labels".
    """
    if not path:
        return {"available": False, "labels": [], "body": ""}
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PrSizeGateError(
            f"could not read the pull request event payload {path}: {exc}"
        ) from exc
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise PrSizeGateError(
            f"the pull request event payload {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        return {"available": False, "labels": [], "body": ""}
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, Mapping):
        return {"available": False, "labels": [], "body": ""}

    labels = [
        str(label.get("name", ""))
        for label in pull_request.get("labels") or []
        if isinstance(label, Mapping)
    ]
    body = pull_request.get("body")
    return {
        "available": True,
        "labels": [name for name in labels if name],
        "body": body if isinstance(body, str) else "",
    }


def _skip_reason(rel_path: str) -> Optional[str]:
    """Reason the scanner cannot judge this path, using the scanner's own rules."""
    if is_generated_or_vendor(rel_path):
        return "generated or vendor path"
    if is_excluded(rel_path):
        return "excluded from the architecture scan"
    return None


def _git(repo_root: Path, *args: str) -> bytes:
    """Run a read-only git command, failing closed on any error."""
    try:
        res = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            cwd=repo_root,
            capture_output=True,
        )
    except OSError as exc:
        raise PrSizeGateError(f"could not run git {args[0]}: {exc}") from exc
    if res.returncode != 0:
        raise PrSizeGateError(
            f"git {args[0]} failed: {res.stderr.decode('utf-8', 'replace').strip()}"
        )
    return res.stdout


def find_merge_base(repo_root: Path, base_ref: str, head_ref: str) -> str:
    """Resolve the merge base commit of the PR head and its base ref.

    A workflow checkout often has the base branch only as a remote-tracking ref,
    so the ref is resolved as given and then as `origin/<base_ref>`. Nothing is
    guessed beyond the standard remote name: if neither ref exists the gate fails
    closed rather than picking some other commit to compare against.
    """
    candidates = [base_ref] if base_ref.startswith("origin/") else [base_ref, f"origin/{base_ref}"]
    errors: List[str] = []
    for candidate in candidates:
        try:
            out = (
                _git(repo_root, "merge-base", candidate, head_ref)
                .decode("utf-8", "replace")
                .strip()
            )
        except PrSizeGateError as exc:
            errors.append(str(exc))
            continue
        if out:
            return out.splitlines()[0]
        errors.append(f"no merge base between {candidate} and {head_ref}")
    raise PrSizeGateError("; ".join(errors))


def _changed_paths(repo_root: Path, merge_base: str, head_ref: str) -> List[Dict[str, Any]]:
    """List added, modified, type-changed and renamed paths with rename detection."""
    out = _git(
        repo_root,
        "diff",
        "--no-color",
        "--no-ext-diff",
        "-M",
        "--diff-filter=ACMRT",
        "--name-status",
        merge_base,
        head_ref,
    ).decode("utf-8", "replace")
    changes: List[Dict[str, Any]] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip():
            continue
        status = parts[0].strip()[0]
        if status in ("R", "C") and len(parts) >= 3:
            changes.append({"status": status, "path": parts[2], "base_path": parts[1]})
        elif status == "A":
            changes.append({"status": status, "path": parts[1], "base_path": None})
        else:
            changes.append({"status": status, "path": parts[1], "base_path": parts[1]})
    return changes


def _line_count_at(repo_root: Path, ref: str, rel_path: str) -> Optional[int]:
    """Physical line count of a path inside a git revision, None if not text."""
    content = _git(repo_root, "show", f"{ref}:{rel_path}")
    counts = count_content_lines_and_bytes(content)
    return counts[0] if counts else None


def evaluate_pull_request(
    repo_root: Path,
    base_ref: str,
    head_ref: str = "HEAD",
    ceiling_lines: int = DEFAULT_CEILING_LINES,
    exception: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compare every path the PR touches against its merge-base line count.

    `exception` is the resolved result of `resolve_exception`. When it is valid,
    every size transition found is recorded as excused and nothing blocks; when it
    is absent or incomplete, every transition blocks exactly as before.

    Raises:
        PrSizeGateError: If the git data needed for the comparison cannot be read.
    """
    repo_root = Path(repo_root)
    merge_base = find_merge_base(repo_root, base_ref, head_ref)
    changes = _changed_paths(repo_root, merge_base, head_ref)

    checked: List[Dict[str, Any]] = []
    violations: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for change in changes:
        path = change["path"]
        reason = _skip_reason(path)
        if reason:
            skipped.append({"path": path, "reason": reason})
            continue

        base_path = change["base_path"]
        base_lines = 0 if base_path is None else _line_count_at(repo_root, merge_base, base_path)
        head_lines = _line_count_at(repo_root, head_ref, path)
        if base_lines is None or head_lines is None:
            skipped.append({"path": path, "reason": "not measurable as text"})
            continue

        checked.append({"path": path, "base_lines": base_lines, "head_lines": head_lines})
        transition = size_transition(base_lines, head_lines, ceiling_lines)
        if transition:
            violations.append(
                {
                    "path": path,
                    "base_path": base_path,
                    "base_lines": base_lines,
                    "head_lines": head_lines,
                    "transition": transition,
                }
            )

    checked.sort(key=lambda c: c["path"])
    violations.sort(key=lambda v: (v["transition"], v["path"]))
    skipped.sort(key=lambda s: s["path"])

    excused: List[Dict[str, Any]] = []
    if exception and exception.get("valid"):
        excused = violations
        violations = []

    return {
        "base_ref": base_ref,
        "head_ref": head_ref,
        "merge_base": merge_base,
        "ceiling_lines": ceiling_lines,
        "checked_count": len(checked),
        "checked": checked,
        "violations": violations,
        "excused": excused,
        "exception": exception,
        "skipped": skipped,
    }


def report_pull_request_result(result: Dict[str, Any]) -> List[str]:
    """Describe one violation per line, with a GitHub annotation pointing at the file."""
    lines: List[str] = []
    for v in result["violations"]:
        origin = (
            f"from {v['base_path']} at the merge base"
            if v["base_path"] and v["base_path"] != v["path"]
            else "at the merge base"
        )
        lines.append(
            f"::error file={v['path']}::SG1 size rule violated ({v['transition']} at "
            f"{result['ceiling_lines']} lines): {v['path']} is {v['base_lines']} lines "
            f"{origin} and {v['head_lines']} lines at the head of this pull request."
        )
    return lines


def report_excused_result(result: Dict[str, Any]) -> List[str]:
    """Describe every excused transition, so a used exception is never silent.

    One warning annotation per excused path, each naming both counts, plus a
    summary line that states how many transitions the exception covered.
    """
    lines: List[str] = []
    for v in result["excused"]:
        origin = (
            f"from {v['base_path']} at the merge base"
            if v["base_path"] and v["base_path"] != v["path"]
            else "at the merge base"
        )
        lines.append(
            f"::warning file={v['path']}::SG1 size transition excused by the "
            f"{result['exception']['label']} label ({v['transition']} at "
            f"{result['ceiling_lines']} lines): {v['path']} is {v['base_lines']} lines "
            f"{origin} and {v['head_lines']} lines at the head of this pull request."
        )
    if lines:
        lines.append(
            f"SG1 size rule excused {len(result['excused'])} transition(s) under the "
            f"{result['exception']['label']} label and the "
            f"'{result['exception']['heading']}' statement in this pull request."
        )
    return lines
