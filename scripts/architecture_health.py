#!/usr/bin/env python3
"""Architecture Health Size and Churn Report with Ratchet.

Scans tracked repository files using git ls-files, collects physical line counts,
evaluates maintainability risk against baseline ceilings and advisory thresholds,
computes deterministic git churn over [T-30d, T] and [T-90d, T] reachable from
baseline commit B, enforces a downward ratchet on file ceilings, and emits
structured JSON and Markdown reports.
"""

import argparse
import datetime
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("architecture_health")

DEFAULT_WARNING_LINES: int = 500
DEFAULT_CEILING_LINES: int = 1000
CHURN_SHORT_DAYS: int = 30
CHURN_LONG_DAYS: int = 90

EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".venv",
    "node_modules",
    "test-artifacts",
    "tasks",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".agents",
}

EXCLUDED_FILES: Set[str] = {
    "WORKLOG.md",
    "architecture_baseline.json",
    "architecture_health_report.json",
}

BINARY_EXTENSIONS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pyc",
    ".o",
    ".a",
    ".so",
    ".tar",
    ".gz",
    ".zip",
    ".bin",
}

LANGUAGE_MAP: Dict[str, str] = {
    ".go": "Go",
    ".html": "HTML",
    ".css": "CSS",
    ".js": "JavaScript",
    ".py": "Python",
    ".sh": "Shell",
    ".json": "JSON",
    ".sql": "SQL",
    ".md": "Markdown",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
}

GENERATED_OR_VENDOR_PATHS: Set[str] = {
    "web/static/js/qrcode.min.js",
    "web/static/css/style.css",
    "tests/e2e/fixtures/style.pre-505.css",
}


def is_generated_or_vendor(rel_path: str) -> bool:
    """Determine whether a path is a generated bundle, minified vendor asset, or fixture."""
    norm = rel_path.replace("\\", "/")
    if norm in GENERATED_OR_VENDOR_PATHS:
        return True
    if norm.endswith(".min.js") or norm.endswith(".min.css"):
        return True
    return "/fixtures/" in norm or norm.startswith("fixtures/")


def find_repo_root(custom_root: Optional[Union[str, Path]] = None) -> Path:
    """Find repository root using git rev-parse or fallback to current directory."""
    if custom_root:
        return Path(custom_root).resolve()
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        return Path(out).resolve() if out else Path.cwd().resolve()
    except Exception:
        return Path.cwd().resolve()


def get_tracked_files(repo_root: Path) -> List[str]:
    """Enumerate repository tracked files strictly using git ls-files."""
    res = subprocess.run(
        ["git", "-c", "core.quotePath=false", "ls-files"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(Path(line.strip()).as_posix() for line in res.stdout.splitlines() if line.strip())


def detect_renames(repo_root: Path, baseline_commit: Optional[str] = None) -> Dict[str, str]:
    """Detect file renames via git diff -M between baseline commit (or HEAD) and working tree."""
    refs_to_try = [baseline_commit, "HEAD"] if baseline_commit else ["HEAD"]
    for ref in refs_to_try:
        if not ref:
            continue
        try:
            res = subprocess.run(
                ["git", "-c", "core.quotePath=false", "diff", "-M", "--name-status", ref],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=True,
            )
            renames: Dict[str, str] = {}
            for line in res.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 3 and parts[0].startswith("R"):
                    old_path = Path(parts[1].strip()).as_posix()
                    new_path = Path(parts[2].strip()).as_posix()
                    renames[new_path] = old_path
            return renames
        except Exception as exc:
            logger.debug("Failed git diff -M for ref %s: %s", ref, exc)
    return {}


def is_excluded(rel_path: str) -> bool:
    """Determine whether a relative file path is excluded from architecture scan."""
    normalized = Path(rel_path).as_posix()
    parts = normalized.split("/")
    if any(p in EXCLUDED_DIRS for p in parts[:-1]):
        return True
    filename = parts[-1]
    if filename in EXCLUDED_FILES:
        return True
    return Path(filename).suffix.lower() in BINARY_EXTENSIONS


def count_file_lines_and_bytes(file_path: Path) -> Optional[Tuple[int, int]]:
    """Count physical newlines and byte size of a file, returning None if binary."""
    try:
        with open(file_path, "rb") as f:
            content = f.read()
    except Exception:
        return None
    if b"\x00" in content:
        return None
    line_count = content.count(b"\n") + (1 if content and not content.endswith(b"\n") else 0)
    return line_count, len(content)


def classify_component(rel_path: str) -> str:
    """Classify a relative path into an architectural component."""
    norm = rel_path.replace("\\", "/")
    if is_generated_or_vendor(norm):
        return "Generated & Vendor"
    fn = os.path.basename(norm)
    if (
        norm.startswith("tests/")
        or fn.startswith("test_")
        or norm.endswith(("_test.go", "_test.py"))
    ):
        return "Test Suites"
    rules: Tuple[Tuple[Union[str, Tuple[str, ...]], str], ...] = (
        ("internal/vpn/forwarder/", "Packet Forwarder"),
        ("internal/vpn/", "Go Core VPN"),
        (("web/templates/", ".html"), "Web Templates"),
        (("web/static/css/", ".css"), "CSS Styles"),
        ("cmd/", "Go Production (CLI & Entrypoints)"),
        ("internal/service/", "Go Production (Services)"),
        ("internal/manager/", "Go Production (WireGuard Manager)"),
        (("internal/handlers/", "internal/router/"), "Go Production (Handlers & Router)"),
        (
            tuple(
                f"internal/{p}/"
                for p in ("database", "config", "models", "security", "middleware", "captcha")
            ),
            "Go Production (Database & Infra)",
        ),
        ("web/static/js/", "Frontend JavaScript"),
        ("web/translations/", "Translations"),
        ("scripts/", "Scripts & Tooling"),
        (("docs/", ".md"), "Documentation"),
    )
    for pattern, comp in rules:
        if isinstance(pattern, tuple):
            if any(norm.startswith(p) if p.endswith("/") else norm.endswith(p) for p in pattern):
                return comp
        elif norm.startswith(pattern):
            return comp
    return "Other"


def get_commit_metadata(repo_root: Path, commit_ref: str = "HEAD") -> Tuple[str, str, int]:
    """Retrieve full commit SHA, UTC ISO timestamp, and epoch seconds for a ref."""
    sha = subprocess.check_output(
        ["git", "rev-parse", commit_ref], cwd=repo_root, text=True
    ).strip()
    epoch_str = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", sha], cwd=repo_root, text=True
    ).strip()
    epoch = int(epoch_str)
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return sha, dt.strftime("%Y-%m-%dT%H:%M:%SZ"), epoch


def compute_git_churn(
    repo_root: Path,
    baseline_commit: str,
    reference_epoch: int,
    days_short: int = CHURN_SHORT_DAYS,
    days_long: int = CHURN_LONG_DAYS,
) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Calculate deterministic churn frequency reachable from baseline commit B."""
    churn_short: Dict[str, int] = {}
    churn_long: Dict[str, int] = {}

    since_short = reference_epoch - (days_short * 86400)
    since_long = reference_epoch - (days_long * 86400)
    until = reference_epoch

    cmd = [
        "git",
        "log",
        f"--since={since_long}",
        f"--until={until}",
        "--name-only",
        "--format=COMMIT:%H:%ct",
        baseline_commit,
    ]

    try:
        res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=True)
    except Exception as exc:
        logger.warning("Failed to execute git log for churn: %s", exc)
        return churn_short, churn_long

    current_commit_epoch: Optional[int] = None
    current_files: Set[str] = set()

    def flush_commit(epoch: Optional[int], touched_files: Set[str]) -> None:
        if epoch is None or not touched_files:
            return
        in_short = since_short <= epoch <= until
        in_long = since_long <= epoch <= until
        for rel_f in touched_files:
            norm_f = Path(rel_f).as_posix()
            if in_short:
                churn_short[norm_f] = churn_short.get(norm_f, 0) + 1
            if in_long:
                churn_long[norm_f] = churn_long.get(norm_f, 0) + 1

    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT:"):
            flush_commit(current_commit_epoch, current_files)
            current_files = set()
            parts = line.split(":")
            if len(parts) >= 3:
                try:
                    current_commit_epoch = int(parts[2])
                except ValueError:
                    current_commit_epoch = None
            else:
                current_commit_epoch = None
        else:
            current_files.add(line)

    flush_commit(current_commit_epoch, current_files)
    return churn_short, churn_long


def calculate_risk_metrics(
    lines: int, churn_30d: int, churn_90d: int, ceiling_lines: int = DEFAULT_CEILING_LINES
) -> Tuple[float, str]:
    """Calculate composite maintainability risk score and tier."""
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
    baseline_commit: Optional[str] = None,
    reference_epoch: Optional[int] = None,
    ceiling_lines: int = DEFAULT_CEILING_LINES,
    warning_lines: int = DEFAULT_WARNING_LINES,
    days_short: int = CHURN_SHORT_DAYS,
    days_long: int = CHURN_LONG_DAYS,
    renames: Optional[Dict[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Scan tracked repository files, compute metrics, and detect ceiling/ratchet delta."""
    tracked_files = get_tracked_files(repo_root)

    churn_30: Dict[str, int] = {}
    churn_90: Dict[str, int] = {}
    if baseline_commit and reference_epoch:
        churn_30, churn_90 = compute_git_churn(
            repo_root, baseline_commit, reference_epoch, days_short, days_long
        )

    if renames is None and baseline_commit:
        renames = detect_renames(repo_root, baseline_commit)
    else:
        renames = renames or {}

    ceilings = dict(baseline_ceilings or {})
    for new_p, old_p in renames.items():
        if new_p not in ceilings and old_p in ceilings:
            ceilings[new_p] = ceilings[old_p]
        if new_p not in churn_30 and old_p in churn_30:
            churn_30[new_p] = churn_30[old_p]
        if new_p not in churn_90 and old_p in churn_90:
            churn_90[new_p] = churn_90[old_p]

    files_data: List[Dict[str, Any]] = []
    ceiling_violations: List[Dict[str, Any]] = []
    ratchet_opportunities: List[Dict[str, Any]] = []

    for rel_path in tracked_files:
        if is_excluded(rel_path):
            continue

        abs_path = repo_root / rel_path
        counts = count_file_lines_and_bytes(abs_path)
        if counts is None:
            continue

        line_count, byte_size = counts
        ext = Path(rel_path).suffix.lower()
        component = classify_component(rel_path)
        language = LANGUAGE_MAP.get(ext, "Other")

        c30 = churn_30.get(rel_path, 0)
        c90 = churn_90.get(rel_path, 0)
        risk_score, risk_tier = calculate_risk_metrics(line_count, c30, c90, ceiling_lines)
        gen = is_generated_or_vendor(rel_path)

        file_ceiling = ceilings.get(rel_path, ceiling_lines)
        is_ceiling_violation = line_count > file_ceiling
        is_warning = (warning_lines <= line_count < ceiling_lines) and (line_count <= file_ceiling)
        is_grandfathered = (line_count > ceiling_lines) and (line_count <= file_ceiling)

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
            }
        )

        if is_ceiling_violation:
            ceiling_violations.append(_violation(rel_path, component, line_count, file_ceiling))

        ratcheted_ceiling = max(ceiling_lines, line_count)
        if ratcheted_ceiling < file_ceiling:
            ratchet_opportunities.append(
                _ratchet_opp(rel_path, component, file_ceiling, line_count, ratcheted_ceiling)
            )

    files_data.sort(key=lambda x: (x["risk_score"], x["lines"]), reverse=True)
    ceiling_violations.sort(key=lambda x: x["excess_lines"], reverse=True)
    ratchet_opportunities.sort(key=lambda x: x["reduction"], reverse=True)

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
    sha, iso_ts, epoch = get_commit_metadata(repo_root, commit_ref)
    churn_30, churn_90 = compute_git_churn(
        repo_root, sha, epoch, days_short=days_short, days_long=days_long
    )

    ceilings: Dict[str, int] = {}
    files_map: Dict[str, Dict[str, Any]] = {}

    for rel_path in get_tracked_files(repo_root):
        if is_excluded(rel_path):
            continue

        counts = count_file_lines_and_bytes(repo_root / rel_path)
        if counts is None:
            continue

        line_count, byte_size = counts
        file_ceiling = max(ceiling_lines, line_count)
        ceilings[rel_path] = file_ceiling
        files_map[rel_path] = {
            "lines": line_count,
            "ceiling": file_ceiling,
            "bytes": byte_size,
            "component": classify_component(rel_path),
            "language": LANGUAGE_MAP.get(Path(rel_path).suffix.lower(), "Other"),
            "churn_30d": churn_30.get(rel_path, 0),
            "churn_90d": churn_90.get(rel_path, 0),
        }

    if existing_baseline:
        existing_ceilings = dict(existing_baseline.get("ceilings", {}))
        if renames:
            for new_p, old_p in renames.items():
                if old_p in existing_ceilings and new_p not in existing_ceilings:
                    existing_ceilings[new_p] = existing_ceilings[old_p]
        increases: List[Tuple[str, int, int]] = []
        for path, new_ceil in ceilings.items():
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
    """Apply downward ratchet updates to baseline ceilings, rejecting unapproved increases."""
    ceilings = dict(baseline_data.get("ceilings", {}))
    files_map = dict(baseline_data.get("files", {}))
    applied: List[Dict[str, Any]] = []
    unauthorized: List[Dict[str, Any]] = []

    if renames:
        for new_p, old_p in renames.items():
            if old_p in ceilings and new_p not in ceilings:
                ceilings[new_p] = ceilings.pop(old_p)
            if old_p in files_map and new_p not in files_map:
                files_map[new_p] = files_map.pop(old_p)

    for item in current_files_data:
        path, curr_lines = item["path"], item["lines"]
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
                        path, old_ceiling, new_ceiling, "ratcheted_down", old_ceiling - new_ceiling
                    )
                )

    if unauthorized and not allow_ceiling_increase:
        raise ValueError(
            f"Cannot ratchet ceilings upward for {len(unauthorized)} files without --allow-ceiling-increase."
        )

    updated_baseline = dict(baseline_data)
    updated_baseline["ceilings"] = ceilings
    updated_baseline["files"] = files_map
    return updated_baseline, applied, unauthorized


def generate_json_report(
    files_data: List[Dict[str, Any]],
    summary: Dict[str, Any],
    ceiling_violations: List[Dict[str, Any]],
    ratchet_opportunities: List[Dict[str, Any]],
    baseline_metadata: Optional[Dict[str, Any]] = None,
    scan_commit: Optional[str] = None,
    top_limit: int = 50,
) -> str:
    """Generate structured JSON architecture health report."""
    meta = baseline_metadata or {}
    developer_hotspots = [f for f in files_data if not f.get("is_generated")][:top_limit]
    generated_files = [f for f in files_data if f.get("is_generated")]
    report = {
        "scan_metadata": {
            "repository": meta.get("repository", "amnezia-nexus"),
            "baseline_commit": meta.get("baseline_commit", "N/A"),
            "reference_timestamp": meta.get("reference_timestamp", "N/A"),
            "scan_commit": scan_commit or "N/A",
            "warning_lines": summary["warning_lines"],
            "ceiling_lines": summary["ceiling_lines"],
            "total_files_analyzed": summary["total_files"],
            "total_lines_analyzed": summary["total_lines"],
            "total_bytes_analyzed": summary["total_bytes"],
            "churn_windows_days": meta.get(
                "churn_windows_days", [CHURN_SHORT_DAYS, CHURN_LONG_DAYS]
            ),
        },
        "summary": {
            "ceiling_violations_count": summary["ceiling_violations_count"],
            "warning_count": summary["warning_count"],
            "grandfathered_count": summary.get("grandfathered_count", 0),
            "ratchet_opportunities_count": summary["ratchet_opportunities_count"],
            "tier_counts": summary["tier_counts"],
            "component_stats": summary["component_stats"],
        },
        "ceiling_violations": ceiling_violations,
        "ratchet_opportunities": ratchet_opportunities,
        "top_hotspots": developer_hotspots,
        "generated_vendor_files": generated_files,
    }
    return json.dumps(report, indent=2)


def generate_markdown_summary(
    files_data: List[Dict[str, Any]],
    summary: Dict[str, Any],
    ceiling_violations: List[Dict[str, Any]],
    ratchet_opportunities: List[Dict[str, Any]],
    baseline_metadata: Optional[Dict[str, Any]] = None,
    top_limit: int = 20,
) -> str:
    """Generate human-readable Markdown summary compatible with GITHUB_STEP_SUMMARY."""
    lines: List[str] = ["## Architecture Health & Churn Report", ""]
    meta = baseline_metadata or {}
    viol_count = summary["ceiling_violations_count"]
    ratchet_count = summary["ratchet_opportunities_count"]

    if viol_count:
        callout = (
            f"> [!WARNING]\n"
            f"> **{viol_count} Ceiling Violation(s) Detected.** Files exceed their pinned architecture ceiling."
        )
    elif ratchet_count:
        callout = (
            f"> [!WARNING]\n"
            f"> **Downward Ratchet Pending.** {ratchet_count} file(s) dropped below baseline ceiling. "
            f"Run `scripts/architecture_health.py --ratchet` to lock in reductions."
        )
    else:
        callout = "> [!NOTE]\n> **Architecture Health Clean.** All tracked files respect baseline ceilings."

    lines.extend(
        [
            callout,
            "",
            f"- **Baseline Commit**: `{meta.get('baseline_commit', 'N/A')[:10]}` (Date: `{meta.get('reference_timestamp', 'N/A')}`)",
            f"- **Default Thresholds**: Strict Ceiling = {summary['ceiling_lines']:,} lines | Warning = {summary['warning_lines']:,} lines",
            f"- **Evaluated Files**: {summary['total_files']:,} tracked files | **Total Lines**: {summary['total_lines']:,}\n",
            "| Metric Category | Count | Status |\n|---|---:|:---:|",
            f"| **Ceiling Violations (> Baseline Ceiling)** | **{viol_count}** | {'❌ VIOLATION' if viol_count else '✅ PASS'} |",
        ]
    )
    if summary.get("grandfathered_count"):
        lines.append(
            f"| **Grandfathered Exceptions (> {summary['ceiling_lines']:,} lines)** | **{summary['grandfathered_count']}** | 📋 Pinned Ceiling |"
        )
    lines.extend(
        [
            f"| **Warning Threshold ({summary['warning_lines']:,}-{summary['ceiling_lines']-1:,} lines)** | **{summary['warning_count']}** | ⚠️ Advisory |",
            f"| **Downward Ratchet Opportunities** | **{ratchet_count}** | {'📉 Ratchet Pending' if ratchet_count else '✅ Synchronized'} |",
        ]
    )
    lines.append(
        f"| **CRITICAL Risk Hotspots** | **{summary['tier_counts']['CRITICAL']}** | 🔥 Urgent |"
    )
    lines.append(f"| **HIGH Risk Hotspots** | **{summary['tier_counts']['HIGH']}** | ⚡ High |\n")

    if ceiling_violations:
        lines.extend(
            [
                "### ❌ Ceiling Violations",
                "",
                "| File Path | Component | Current Lines | Baseline Ceiling | Excess Lines |",
                "|---|---|---:|---:|---:|",
            ]
        )
        lines.extend(
            f"| `{v['path']}` | {v['component']} | {v['lines']:,} | {v['ceiling']:,} | +{v['excess_lines']:,} |"
            for v in ceiling_violations[:15]
        )
        lines.append("")

    if ratchet_opportunities:
        lines.extend(
            [
                "### 📉 Downward Ratchet Opportunities",
                "",
                "> **Notice:** Downward ratchet is pending. These files decreased in size; their ceilings can ratchet downward to lock in gains:\n",
                "| File Path | Component | Previous Ceiling | Current Lines | Proposed Ratchet | Reduction |",
                "|---|---|---:|---:|---:|---:|",
            ]
        )
        lines.extend(
            f"| `{r['path']}` | {r['component']} | {r['previous_ceiling']:,} | {r['current_lines']:,} | {r['new_ceiling']:,} | -{r['reduction']:,} |"
            for r in ratchet_opportunities[:15]
        )
        lines.append("")

    developer_hotspots = [f for f in files_data if not f.get("is_generated")]
    generated_files = [f for f in files_data if f.get("is_generated")]

    lines.extend(
        [
            f"### 🔥 Top {top_limit} Hotspots (Risk & Churn)",
            "",
            "| Rank | File Path | Component | Lines | 30d Churn | 90d Churn | Risk Score | Tier |",
            "|---:|---|---|---:|---:|---:|---:|:---:|",
        ]
    )
    for idx, f in enumerate(developer_hotspots[:top_limit], 1):
        lines.append(
            f"| {idx} | `{f['path']}` | {f['component']} | {f['lines']:,} | {f.get('churn_30d', 0)} | {f.get('churn_90d', 0)} | {f.get('risk_score', 0.0):.2f} | **{f.get('risk_tier', 'LOW')}** |"
        )
    lines.append("")

    if generated_files:
        lines.extend(
            [
                "### 🤖 Generated & Vendor Assets",
                "",
                "These files are generated bundles, fixtures, or vendor assets (excluded from developer hotspots):",
                "",
                "| File Path | Component | Lines | Baseline Ceiling |",
                "|---|---|---:|---:|",
            ]
        )
        lines.extend(
            f"| `{gf['path']}` | {gf['component']} | {gf['lines']:,} | {gf.get('ceiling', 1000):,} |"
            for gf in generated_files
        )
        lines.append("")

    lines.extend(
        [
            "### 📦 Component Distribution",
            "",
            "| Component | Files | Total Lines | Ceiling Violations | 30d Churn | Largest File |",
            "|---|---:|---:|---:|---:|---|",
        ]
    )
    sorted_comps = sorted(
        summary["component_stats"].items(),
        key=lambda kv: (kv[1]["ceiling_violations"], kv[1]["total_lines"]),
        reverse=True,
    )
    for comp_name, cs in sorted_comps:
        max_file_display = f"`{cs['max_file']}` ({cs['max_lines']:,})" if cs["max_file"] else "N/A"
        lines.append(
            f"| **{comp_name}** | {cs['file_count']} | {cs['total_lines']:,} | {cs['ceiling_violations']} | {cs['total_churn_30d']} | {max_file_display} |"
        )
    lines.append("")

    return "\n".join(lines)


def load_baseline(baseline_path: Path) -> Dict[str, Any]:
    """Load baseline JSON file from disk."""
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file does not exist: {baseline_path}")
    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_baseline(baseline_path: Path, baseline_data: Dict[str, Any]) -> None:
    """Save baseline JSON file to disk."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)
        f.write("\n")


def main() -> int:
    """CLI entrypoint for architecture health and churn reporter."""
    logging.basicConfig(
        level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler(sys.stdout)]
    )
    parser = argparse.ArgumentParser(
        description="Architecture Health Size and Churn Report with Ratchet."
    )
    parser.add_argument("--repo-root", default=None, help="Repository root path.")
    parser.add_argument(
        "--baseline-file", default="scripts/architecture_baseline.json", help="Path."
    )
    parser.add_argument("--generate-baseline", action="store_true", help="Generate baseline JSON.")
    parser.add_argument("--check", action="store_true", help="Check baseline ceilings.")
    parser.add_argument("--ratchet", action="store_true", help="Apply downward ratchet.")
    parser.add_argument("--allow-ceiling-increase", action="store_true", help="Allow increase.")
    parser.add_argument("--nonblocking", action="store_true", help="Exit 0 even with violations.")
    parser.add_argument(
        "--report-json", default="architecture_health_report.json", help="JSON report."
    )
    parser.add_argument("--summary-md", default=None, help="Summary path.")
    parser.add_argument("--ceiling", type=int, default=DEFAULT_CEILING_LINES, help="Ceiling lines.")
    parser.add_argument("--warning", type=int, default=DEFAULT_WARNING_LINES, help="Warning lines.")

    args = parser.parse_args()
    repo_root = find_repo_root(args.repo_root)
    baseline_path = Path(args.baseline_file)
    if not baseline_path.is_absolute():
        baseline_path = repo_root / baseline_path

    if args.generate_baseline:
        logger.info("Generating architecture baseline at %s...", baseline_path)
        existing_data = None
        if baseline_path.exists():
            try:
                existing_data = load_baseline(baseline_path)
            except Exception as exc:
                logger.warning("Could not load existing baseline: %s", exc)
        b_commit = (
            existing_data.get("metadata", {}).get("baseline_commit") if existing_data else None
        )
        renames = detect_renames(repo_root, b_commit)
        try:
            baseline_data = generate_baseline(
                repo_root=repo_root,
                commit_ref="HEAD",
                ceiling_lines=args.ceiling,
                warning_lines=args.warning,
                existing_baseline=existing_data,
                allow_ceiling_increase=args.allow_ceiling_increase,
                renames=renames,
            )
        except ValueError as exc:
            logger.error("Baseline generation rejected: %s", exc)
            return 1
        save_baseline(baseline_path, baseline_data)
        meta = baseline_data["metadata"]
        logger.info(
            "Baseline generated! Commit: %s, Files: %d",
            meta["baseline_commit"][:10],
            len(baseline_data["ceilings"]),
        )
        return 0

    if not baseline_path.exists():
        logger.warning(
            "Baseline file not found at %s. Run with --generate-baseline.", baseline_path
        )
        return 0 if args.nonblocking else 1

    baseline_data = load_baseline(baseline_path)
    base_meta = baseline_data.get("metadata", {})
    b_commit = base_meta.get("baseline_commit")
    renames = detect_renames(repo_root, b_commit)

    try:
        scan_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True
        ).strip()
    except Exception:
        scan_commit = "unknown"

    files_data, summary, violations, ratchets = scan_repository(
        repo_root=repo_root,
        baseline_ceilings=baseline_data.get("ceilings", {}),
        baseline_commit=b_commit,
        reference_epoch=base_meta.get("reference_timestamp_epoch"),
        ceiling_lines=args.ceiling,
        warning_lines=args.warning,
        renames=renames,
    )

    if args.ratchet:
        try:
            updated_baseline, applied, _ = update_downward_ratchet(
                current_files_data=files_data,
                baseline_data=baseline_data,
                ceiling_lines=args.ceiling,
                allow_ceiling_increase=args.allow_ceiling_increase,
                renames=renames,
            )
            save_baseline(baseline_path, updated_baseline)
            logger.info("Ratchet applied: %d ceiling updates saved.", len(applied))
        except ValueError as exc:
            logger.error("Ratchet update rejected: %s", exc)
            return 1

    report_path = Path(args.report_json)
    if not report_path.is_absolute():
        report_path = repo_root / report_path
    json_content = generate_json_report(
        files_data, summary, violations, ratchets, base_meta, scan_commit
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(json_content + "\n")

    summary_path_str = args.summary_md or os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path_str:
        summary_path = Path(summary_path_str)
        if not summary_path.is_absolute():
            summary_path = repo_root / summary_path
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(
                generate_markdown_summary(files_data, summary, violations, ratchets, base_meta)
                + "\n"
            )

    logger.info(
        "Files: %d | Lines: %d | Violations: %d | Warnings: %d | Ratchets: %d",
        summary["total_files"],
        summary["total_lines"],
        summary["ceiling_violations_count"],
        summary["warning_count"],
        summary["ratchet_opportunities_count"],
    )

    if ratchets:
        for r in ratchets:
            logger.warning(
                "::warning file=%s::Downward ratchet pending: %s dropped from %d to %d lines "
                "(reduction: %d). Run --ratchet to update baseline.",
                r["path"],
                r["path"],
                r["previous_ceiling"],
                r["current_lines"],
                r["reduction"],
            )

    if violations and not args.nonblocking:
        logger.error(
            "Architecture health check FAILED with %d ceiling violations.", len(violations)
        )
        return 1

    logger.info("Architecture health check PASSED cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
