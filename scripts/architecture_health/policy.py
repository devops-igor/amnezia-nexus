"""Architecture health policies, ceiling evaluations, ratchet controls, and risk metrics."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import scripts.architecture_health as ah
from scripts.architecture_health.constants import (
    CHURN_LONG_DAYS,
    CHURN_SHORT_DAYS,
    DEFAULT_CEILING_LINES,
    DEFAULT_WARNING_LINES,
    LANGUAGE_MAP,
)


def rebase_ceilings(ceilings: Dict[str, int], renames: Dict[str, str]) -> Dict[str, int]:
    """Rebase baseline ceilings across file renames using authoritative move semantics.

    When a file is renamed or moved (old_path -> new_path), the legacy grandfathered
    ceiling is transferred to new_path, and old_path is deleted from the mapping so that
    any newly created file at old_path starts with the default ceiling.
    """
    rebased = dict(ceilings)
    for new_p, old_p in renames.items():
        if old_p == new_p:
            continue
        if old_p in rebased:
            rebased[new_p] = rebased.pop(old_p)
    return rebased


def rebase_files_map(files_map: Dict[str, Any], renames: Dict[str, str]) -> Dict[str, Any]:
    """Rebase baseline files map across file renames using move semantics."""
    rebased = dict(files_map)
    for new_p, old_p in renames.items():
        if old_p == new_p:
            continue
        if old_p in rebased:
            rebased[new_p] = rebased.pop(old_p)
    return rebased


def rebase_churn(churn: Dict[str, int], renames: Dict[str, str]) -> Dict[str, int]:
    """Rebase historical churn frequencies across file renames using move semantics."""
    rebased = dict(churn)
    for new_p, old_p in renames.items():
        if old_p == new_p:
            continue
        if old_p in rebased:
            rebased[new_p] = rebased.pop(old_p)
    return rebased


def calculate_risk_metrics(
    lines: int, churn_30d: int, churn_90d: int, ceiling_lines: int = DEFAULT_CEILING_LINES
) -> Tuple[float, str]:
    """Calculate composite maintainability risk score and risk tier."""
    size_factor = lines / float(ceiling_lines)
    churn_factor = 1.0 + (churn_30d * 0.5) + (churn_90d * 0.2)
    risk_score = round(size_factor * churn_factor, 2)

    if risk_score >= 50.0 or (lines >= ceiling_lines and churn_30d >= 15) or lines >= 4000:
        tier = "CRITICAL"
    elif (
        risk_score >= 15.0
        or lines >= ceiling_lines
        or (lines >= (ceiling_lines // 2) and churn_30d >= 10)
    ):
        tier = "HIGH"
    elif risk_score >= 5.0 or lines >= (ceiling_lines // 2) or churn_30d >= 5:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    return risk_score, tier


def _violation(path: str, comp: str, lines: int, ceil: int) -> Dict[str, Any]:
    return {
        "path": path,
        "component": comp,
        "lines": lines,
        "ceiling": ceil,
        "excess_lines": lines - ceil,
    }


def _ratchet_opp(path: str, comp: str, old: int, curr: int, new: int) -> Dict[str, Any]:
    return {
        "path": path,
        "component": comp,
        "previous_ceiling": old,
        "current_lines": curr,
        "new_ceiling": new,
        "reduction": old - new,
    }


def _ratchet_applied(path: str, old: int, new: int, act: str, red: int = 0) -> Dict[str, Any]:
    d = {"path": path, "old_ceiling": old, "new_ceiling": new, "action": act}
    if red:
        d["reduction"] = red
    return d


def _unauthorized_ratchet(path: str, old: int, curr: int) -> Dict[str, Any]:
    return {"path": path, "old_ceiling": old, "current_lines": curr, "excess": curr - old}


def scan_repository(
    repo_root: Path,
    baseline_ceilings: Optional[Dict[str, int]] = None,
    baseline_files: Optional[Dict[str, Any]] = None,
    baseline_commit: Optional[str] = None,
    reference_epoch: Optional[int] = None,
    ceiling_lines: int = DEFAULT_CEILING_LINES,
    warning_lines: int = DEFAULT_WARNING_LINES,
    days_short: int = CHURN_SHORT_DAYS,
    days_long: int = CHURN_LONG_DAYS,
    renames: Optional[Dict[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Scan tracked repository files, evaluate ceilings/ratchets, and calculate deltas."""
    tracked_files = ah.get_tracked_files(repo_root)

    churn_30: Dict[str, int] = {}
    churn_90: Dict[str, int] = {}
    if baseline_commit and reference_epoch:
        churn_30, churn_90 = ah.compute_git_churn(
            repo_root, baseline_commit, reference_epoch, days_short, days_long
        )

    if renames is None and baseline_commit:
        safe_renames: Dict[str, str] = ah.detect_renames(repo_root, baseline_commit)
    else:
        safe_renames = renames or {}

    ceilings = ah.rebase_ceilings(baseline_ceilings or {}, safe_renames)
    files_map = ah.rebase_files_map(baseline_files or {}, safe_renames)
    churn_30 = ah.rebase_churn(churn_30, safe_renames)
    churn_90 = ah.rebase_churn(churn_90, safe_renames)

    files_data: List[Dict[str, Any]] = []
    ceiling_violations: List[Dict[str, Any]] = []
    ratchet_opportunities: List[Dict[str, Any]] = []
    growing_files: List[Dict[str, Any]] = []

    for rel_path in tracked_files:
        if ah.is_excluded(rel_path):
            continue

        abs_path = repo_root / rel_path
        counts = ah.count_file_lines_and_bytes(abs_path)
        if counts is None:
            continue

        line_count, byte_size = counts
        ext = Path(rel_path).suffix.lower()
        component = ah.classify_component(rel_path)
        language = LANGUAGE_MAP.get(ext, "Other")

        c30 = churn_30.get(rel_path, 0)
        c90 = churn_90.get(rel_path, 0)
        risk_score, risk_tier = calculate_risk_metrics(line_count, c30, c90, ceiling_lines)
        gen = ah.is_generated_or_vendor(rel_path)

        file_ceiling = ceilings.get(rel_path, ceiling_lines)

        # Range partitioning:
        # [0, warning_lines) -> normal
        # [warning_lines, ceiling_lines) -> warning
        # [ceiling_lines, file_ceiling] -> grandfathered/at-ceiling
        # > file_ceiling -> ceiling_violation
        # Generated & vendor files are excluded from violations and warnings
        is_ceiling_violation = (not gen) and (line_count > file_ceiling)
        is_warning = (
            (not gen)
            and (warning_lines <= line_count < ceiling_lines)
            and (line_count <= file_ceiling)
        )
        is_grandfathered = (
            (not gen) and (line_count >= ceiling_lines) and (line_count <= file_ceiling)
        )

        b_entry = files_map.get(rel_path)
        b_lines = b_entry.get("lines") if isinstance(b_entry, dict) else None
        line_delta = (line_count - b_lines) if b_lines is not None else None

        if line_delta is not None and line_delta > 0 and not gen:
            growing_files.append(
                {
                    "path": rel_path,
                    "component": component,
                    "current_lines": line_count,
                    "baseline_lines": b_lines,
                    "line_delta": line_delta,
                }
            )

        files_data.append(
            {
                "path": rel_path,
                "component": component,
                "language": language,
                "lines": line_count,
                "bytes": byte_size,
                "ceiling": file_ceiling,
                "churn_30d": c30,
                "churn_90d": c90,
                "risk_score": 0.0 if gen else risk_score,
                "risk_tier": "GENERATED" if gen else risk_tier,
                "ceiling_violation": is_ceiling_violation,
                "warning_threshold": is_warning,
                "grandfathered": is_grandfathered,
                "is_generated": gen,
                "baseline_lines": b_lines,
                "line_delta": line_delta,
            }
        )

        if is_ceiling_violation:
            ceiling_violations.append(_violation(rel_path, component, line_count, file_ceiling))

        if not gen:
            ratcheted_ceiling = max(ceiling_lines, line_count)
            if ratcheted_ceiling < file_ceiling:
                ratchet_opportunities.append(
                    _ratchet_opp(rel_path, component, file_ceiling, line_count, ratcheted_ceiling)
                )

    files_data.sort(key=lambda x: (x["risk_score"], x["lines"]), reverse=True)
    ceiling_violations.sort(key=lambda x: x["excess_lines"], reverse=True)
    ratchet_opportunities.sort(key=lambda x: x["reduction"], reverse=True)
    growing_files.sort(key=lambda x: x["line_delta"], reverse=True)

    tier_counts = {
        t: sum(1 for f in files_data if f["risk_tier"] == t)
        for t in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    component_stats: Dict[str, Dict[str, Any]] = {}
    for f in files_data:
        comp = f["component"]
        cs = component_stats.setdefault(
            comp,
            {
                "file_count": 0,
                "total_lines": 0,
                "total_bytes": 0,
                "ceiling_violations": 0,
                "warning_count": 0,
                "max_lines": 0,
                "max_file": "",
                "total_churn_30d": 0,
                "total_churn_90d": 0,
            },
        )
        cs["file_count"] += 1
        cs["total_lines"] += f["lines"]
        cs["total_bytes"] += f["bytes"]
        if f["ceiling_violation"]:
            cs["ceiling_violations"] += 1
        if f["warning_threshold"]:
            cs["warning_count"] += 1
        if f["lines"] > cs["max_lines"]:
            cs["max_lines"] = f["lines"]
            cs["max_file"] = f["path"]
        cs["total_churn_30d"] += f["churn_30d"]
        cs["total_churn_90d"] += f["churn_90d"]

    top_go_functions = ah.analyze_go_functions(repo_root, tracked_files)[:25]

    summary = {
        "total_files": len(files_data),
        "total_lines": sum(f["lines"] for f in files_data),
        "total_bytes": sum(f["bytes"] for f in files_data),
        "ceiling_lines": ceiling_lines,
        "warning_lines": warning_lines,
        "ceiling_violations_count": len(ceiling_violations),
        "warning_count": sum(1 for f in files_data if f["warning_threshold"]),
        "grandfathered_count": sum(1 for f in files_data if f.get("grandfathered", False)),
        "ratchet_opportunities_count": len(ratchet_opportunities),
        "tier_counts": tier_counts,
        "component_stats": component_stats,
        "top_growing_files": growing_files[:20],
        "top_go_functions": top_go_functions,
    }
    return files_data, summary, ceiling_violations, ratchet_opportunities


def generate_baseline(
    repo_root: Path,
    commit_ref: str = "HEAD",
    ceiling_lines: int = DEFAULT_CEILING_LINES,
    warning_lines: int = DEFAULT_WARNING_LINES,
    days_short: int = CHURN_SHORT_DAYS,
    days_long: int = CHURN_LONG_DAYS,
    existing_baseline: Optional[Dict[str, Any]] = None,
    allow_ceiling_increase: bool = False,
    renames: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Generate baseline JSON metadata against specified commit reference."""
    sha, iso_ts, epoch = ah.get_commit_metadata(repo_root, commit_ref)
    churn_30, churn_90 = ah.compute_git_churn(
        repo_root, sha, epoch, days_short=days_short, days_long=days_long
    )

    ceilings: Dict[str, int] = {}
    files_map: Dict[str, Dict[str, Any]] = {}

    for rel_path in ah.get_tracked_files(repo_root):
        if ah.is_excluded(rel_path):
            continue

        counts = ah.count_file_lines_and_bytes(repo_root / rel_path)
        if counts is None:
            continue

        line_count, byte_size = counts
        file_ceiling = max(ceiling_lines, line_count)
        ceilings[rel_path] = file_ceiling
        files_map[rel_path] = {
            "lines": line_count,
            "ceiling": file_ceiling,
            "bytes": byte_size,
            "component": ah.classify_component(rel_path),
            "language": LANGUAGE_MAP.get(Path(rel_path).suffix.lower(), "Other"),
            "churn_30d": churn_30.get(rel_path, 0),
            "churn_90d": churn_90.get(rel_path, 0),
        }

    if existing_baseline:
        renames = renames or {}
        existing_ceilings = ah.rebase_ceilings(existing_baseline.get("ceilings", {}), renames)
        increases: List[Tuple[str, int, int]] = []
        for path, new_ceil in ceilings.items():
            if ah.is_generated_or_vendor(path):
                continue
            old_ceil = existing_ceilings.get(path, ceiling_lines)
            if new_ceil > old_ceil:
                increases.append((path, old_ceil, new_ceil))
        if increases and not allow_ceiling_increase:
            inc_summary = ", ".join(f"{p} ({o}->{n})" for p, o, n in increases[:3])
            raise ValueError(
                f"Cannot increase ceilings for {len(increases)} file(s) [{inc_summary}] "
                f"without --allow-ceiling-increase."
            )

    return {
        "metadata": {
            "repository": "amnezia-nexus",
            "baseline_commit": sha,
            "reference_timestamp": iso_ts,
            "reference_timestamp_epoch": epoch,
            "warning_threshold": warning_lines,
            "ceiling_threshold": ceiling_lines,
            "churn_windows_days": [days_short, days_long],
        },
        "ceilings": ceilings,
        "files": files_map,
    }


def update_downward_ratchet(
    current_files_data: List[Dict[str, Any]],
    baseline_data: Dict[str, Any],
    ceiling_lines: int = DEFAULT_CEILING_LINES,
    allow_ceiling_increase: bool = False,
    renames: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Apply downward ratchet updates to baseline ceilings, pruning deleted paths."""
    renames = renames or {}
    ceilings = ah.rebase_ceilings(baseline_data.get("ceilings", {}), renames)
    files_map = ah.rebase_files_map(baseline_data.get("files", {}), renames)
    applied: List[Dict[str, Any]] = []
    unauthorized: List[Dict[str, Any]] = []

    current_paths = {item["path"] for item in current_files_data}

    # Prune paths that no longer exist in the repository
    for path in list(ceilings.keys()):
        if path not in current_paths:
            old_ceil = ceilings.pop(path)
            files_map.pop(path, None)
            applied.append(
                {
                    "path": path,
                    "old_ceiling": old_ceil,
                    "new_ceiling": 0,
                    "action": "pruned_deleted",
                }
            )

    for item in current_files_data:
        path = item["path"]
        if ah.is_generated_or_vendor(path):
            continue

        curr_lines = item["lines"]
        old_ceiling = ceilings.get(path, ceiling_lines)

        if curr_lines > old_ceiling:
            if allow_ceiling_increase:
                ceilings[path] = curr_lines
                files_map.setdefault(path, {}).update({"ceiling": curr_lines, "lines": curr_lines})
                applied.append(_ratchet_applied(path, old_ceiling, curr_lines, "increased"))
            else:
                unauthorized.append(_unauthorized_ratchet(path, old_ceiling, curr_lines))
        elif curr_lines < old_ceiling:
            new_ceiling = max(ceiling_lines, curr_lines)
            if new_ceiling < old_ceiling:
                ceilings[path] = new_ceiling
                files_map.setdefault(path, {}).update({"ceiling": new_ceiling, "lines": curr_lines})
                applied.append(
                    _ratchet_applied(
                        path,
                        old_ceiling,
                        new_ceiling,
                        "ratcheted_down",
                        old_ceiling - new_ceiling,
                    )
                )

    if unauthorized and not allow_ceiling_increase:
        raise ValueError(
            f"Cannot ratchet ceilings upward for {len(unauthorized)} files "
            f"without --allow-ceiling-increase."
        )

    updated_baseline = dict(baseline_data)
    updated_baseline["ceilings"] = ceilings
    updated_baseline["files"] = files_map
    return updated_baseline, applied, unauthorized
