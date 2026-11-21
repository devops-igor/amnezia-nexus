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

import logging
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional

from scripts.architecture_health.constants import (
    DEFAULT_CEILING_LINES,
    is_excluded,
    is_generated_or_vendor,
)
from scripts.architecture_health.discovery import count_content_lines_and_bytes

logger = logging.getLogger("architecture_health")

CROSSED_TRANSITION = "crossed ceiling"
GREW_TRANSITION = "grew above ceiling"


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
) -> Dict[str, Any]:
    """Compare every path the PR touches against its merge-base line count.

    Raises:
        PrSizeGateError: If the git data needed for the comparison cannot be read.
    """
    repo_root = Path(repo_root)
    merge_base = find_merge_base(repo_root, base_ref, head_ref)
    changes = _changed_paths(repo_root, merge_base, head_ref)

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

    violations.sort(key=lambda v: (v["transition"], v["path"]))
    skipped.sort(key=lambda s: s["path"])
    return {
        "base_ref": base_ref,
        "head_ref": head_ref,
        "merge_base": merge_base,
        "ceiling_lines": ceiling_lines,
        "checked_count": len(changes) - len(skipped),
        "violations": violations,
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
