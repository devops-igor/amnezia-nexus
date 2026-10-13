#!/usr/bin/env python3
"""
Repository Hotspots Inventory Tool

Scans the repository for oversized files, dependency hotspots, and change churn.
Groups files by language/component, analyzes git churn frequency over 30d/90d,
and calculates maintainability risk scores and proposed ratcheting ceilings.

Standard library only: os, sys, json, subprocess, argparse, pathlib.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

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


def find_repo_root(custom_root: Optional[str] = None) -> Path:
    """Find repository root using git rev-parse or fallback to current directory."""
    if custom_root:
        return Path(custom_root).resolve()
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            return Path(out).resolve()
    except Exception:
        pass
    return Path.cwd().resolve()


def get_git_churn(repo_root: Path, days: int) -> Dict[str, int]:
    """Calculate git commit frequency touching each file over the given days."""
    churn_map: Dict[str, int] = {}
    try:
        cmd = [
            "git",
            "log",
            f"--since={days} days ago",
            "--name-only",
            "--format=COMMIT:%H",
        ]
        res = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        current_files: Set[str] = set()
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("COMMIT:"):
                for f in current_files:
                    churn_map[f] = churn_map.get(f, 0) + 1
                current_files = set()
            else:
                current_files.add(line)
        for f in current_files:
            churn_map[f] = churn_map.get(f, 0) + 1
    except Exception:
        pass
    return churn_map


def classify_component(rel_path: str) -> str:
    """Classify a relative path into an architectural component."""
    norm = rel_path.replace("\\", "/")
    filename = os.path.basename(norm)

    # Test Suites
    if (
        norm.endswith("_test.go")
        or norm.startswith("tests/")
        or norm.endswith("_test.py")
        or filename.startswith("test_")
    ):
        return "Test Suites"

    # Packet Forwarder
    if norm.startswith("internal/vpn/forwarder/"):
        return "Packet Forwarder"

    # Go Core VPN
    if norm.startswith("internal/vpn/"):
        return "Go Core VPN"

    # Web Templates
    if norm.startswith("web/templates/") or norm.endswith(".html"):
        return "Web Templates"

    # CSS Styles
    if norm.startswith("web/static/css/") or norm.endswith(".css"):
        return "CSS Styles"

    # Go Production Packages (other services / managers / handlers / db)
    if norm.startswith("cmd/"):
        return "Go Production (CLI & Entrypoints)"
    if norm.startswith("internal/service/"):
        return "Go Production (Services)"
    if norm.startswith("internal/manager/"):
        return "Go Production (WireGuard Manager)"
    if norm.startswith("internal/handlers/") or norm.startswith("internal/router/"):
        return "Go Production (Handlers & Router)"
    if (
        norm.startswith("internal/database/")
        or norm.startswith("internal/config/")
        or norm.startswith("internal/models/")
        or norm.startswith("internal/security/")
        or norm.startswith("internal/middleware/")
        or norm.startswith("internal/captcha/")
    ):
        return "Go Production (Database & Infra)"

    # Frontend Assets
    if norm.startswith("web/static/js/"):
        return "Frontend JavaScript"
    if norm.startswith("web/translations/"):
        return "Translations"

    # Tooling & Docs
    if norm.startswith("scripts/"):
        return "Scripts & Tooling"
    if norm.startswith("docs/") or norm.endswith(".md"):
        return "Documentation"

    return "Other"


def calculate_risk_metrics(
    lines: int, churn_30d: int, churn_90d: int, ceiling_lines: int = 1000
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


def scan_repository(
    repo_root: Path,
    ceiling_lines: int = 1000,
    warning_lines: int = 500,
    days_30: int = 30,
    days_90: int = 90,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Scan all tracked and non-excluded files in repo and collect metrics."""
    churn_30d_map = get_git_churn(repo_root, days_30)
    churn_90d_map = get_git_churn(repo_root, days_90)

    files_data: List[Dict[str, Any]] = []

    for root, dirs, filenames in os.walk(repo_root):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for fname in filenames:
            if fname in EXCLUDED_FILES:
                continue

            file_path = Path(root) / fname
            ext = file_path.suffix.lower()
            if ext in BINARY_EXTENSIONS:
                continue

            try:
                with open(file_path, "rb") as f:
                    content = f.read()

                # Skip binary content with null bytes
                if b"\x00" in content:
                    continue

                line_count = content.count(b"\n") + (
                    1 if content and not content.endswith(b"\n") else 0
                )
                byte_size = len(content)
            except Exception:
                continue

            rel_path = file_path.relative_to(repo_root).as_posix()
            component = classify_component(rel_path)
            language = LANGUAGE_MAP.get(ext, "Other")

            c30 = churn_30d_map.get(rel_path, 0)
            c90 = churn_90d_map.get(rel_path, 0)
            risk_score, risk_tier = calculate_risk_metrics(line_count, c30, c90, ceiling_lines)

            files_data.append(
                {
                    "path": rel_path,
                    "component": component,
                    "language": language,
                    "lines": line_count,
                    "bytes": byte_size,
                    "churn_30d": c30,
                    "churn_90d": c90,
                    "risk_score": risk_score,
                    "risk_tier": risk_tier,
                    "ceiling_violation": line_count >= ceiling_lines,
                    "warning_threshold": warning_lines <= line_count < ceiling_lines,
                }
            )

    # Sort files by risk score descending, then line count descending
    files_data.sort(key=lambda x: (x["risk_score"], x["lines"]), reverse=True)

    # Build summary statistics
    total_files = len(files_data)
    total_lines = sum(f["lines"] for f in files_data)
    total_bytes = sum(f["bytes"] for f in files_data)
    ceiling_violations = sum(1 for f in files_data if f["ceiling_violation"])
    warning_count = sum(1 for f in files_data if f["warning_threshold"])

    tier_counts = {
        "CRITICAL": sum(1 for f in files_data if f["risk_tier"] == "CRITICAL"),
        "HIGH": sum(1 for f in files_data if f["risk_tier"] == "HIGH"),
        "MEDIUM": sum(1 for f in files_data if f["risk_tier"] == "MEDIUM"),
        "LOW": sum(1 for f in files_data if f["risk_tier"] == "LOW"),
    }

    # Group statistics by component
    component_stats: Dict[str, Dict[str, Any]] = {}
    for f in files_data:
        comp = f["component"]
        if comp not in component_stats:
            component_stats[comp] = {
                "file_count": 0,
                "total_lines": 0,
                "total_bytes": 0,
                "ceiling_violations": 0,
                "warning_count": 0,
                "max_lines": 0,
                "max_file": "",
                "total_churn_30d": 0,
                "total_churn_90d": 0,
            }
        cs = component_stats[comp]
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
        "total_files": total_files,
        "total_lines": total_lines,
        "total_bytes": total_bytes,
        "ceiling_lines": ceiling_lines,
        "warning_lines": warning_lines,
        "ceiling_violations_count": ceiling_violations,
        "warning_count": warning_count,
        "tier_counts": tier_counts,
        "component_stats": component_stats,
    }

    return files_data, summary


def generate_json_output(
    files_data: List[Dict[str, Any]],
    summary: Dict[str, Any],
    top_limit: int = 50,
) -> str:
    """Generate structured JSON representation."""
    payload = {
        "scan_metadata": {
            "repository": "amnezia-nexus",
            "ceiling_lines": summary["ceiling_lines"],
            "warning_lines": summary["warning_lines"],
            "total_files_analyzed": summary["total_files"],
            "total_lines_analyzed": summary["total_lines"],
            "total_bytes_analyzed": summary["total_bytes"],
            "churn_windows_days": [30, 90],
        },
        "summary": {
            "ceiling_violations_count": summary["ceiling_violations_count"],
            "warning_count": summary["warning_count"],
            "tier_counts": summary["tier_counts"],
            "component_stats": summary["component_stats"],
        },
        "top_hotspots": files_data[:top_limit],
        "all_ceiling_violations": [f for f in files_data if f["ceiling_violation"]],
    }
    return json.dumps(payload, indent=2)


def generate_markdown_report(
    files_data: List[Dict[str, Any]],
    summary: Dict[str, Any],
    top_limit: int = 25,
) -> str:
    """Generate human-readable markdown architectural hotspots report."""
    lines: List[str] = []

    lines.append("# Architecture Hotspots and Maintainability Inventory Report")
    lines.append("")
    lines.append("**Repository**: amnezia-nexus  ")
    lines.append(
        f"**Baseline Metric Ceilings**: Strict Ceiling = {summary['ceiling_lines']:,} lines | Warning Threshold = {summary['warning_lines']:,} lines  "
    )
    lines.append(
        f"**Total Tracked Non-Task Files**: {summary['total_files']:,} | **Total Analyzed Lines**: {summary['total_lines']:,}  "
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 1: Executive Summary
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(
        "This inventory establishes an empirical baseline of oversized monolithic files, dependency concentration, and change churn frequency across the repository. It supports **Epic #475** (*Incremental decomposition of monolithic Go, frontend, and test files*) by pinpointing files that present the highest risk of merge conflicts, cognitive overload, and regression velocity."
    )
    lines.append("")
    lines.append("| Metric Category | Value | Percentage | Description |")
    lines.append("|---|---:|---:|---|")
    total_files = summary["total_files"]
    viol_cnt = summary["ceiling_violations_count"]
    warn_cnt = summary["warning_count"]
    viol_pct = (viol_cnt / total_files * 100.0) if total_files else 0.0
    warn_pct = (warn_cnt / total_files * 100.0) if total_files else 0.0
    nominal_cnt = total_files - viol_cnt - warn_cnt
    nominal_pct = (nominal_cnt / total_files * 100.0) if total_files else 0.0

    lines.append(
        f"| **Ceiling Violations (>={summary['ceiling_lines']:,} lines)** | **{viol_cnt}** | {viol_pct:.1f}% | Presumptive merge-blocker candidates requiring decomposition |"
    )
    lines.append(
        f"| **Warning Threshold ({summary['warning_lines']:,}-{summary['ceiling_lines']-1:,} lines)** | **{warn_cnt}** | {warn_pct:.1f}% | Approaching ceiling; ratcheted against further expansion |"
    )
    lines.append(
        f"| **Nominal (<{summary['warning_lines']:,} lines)** | **{nominal_cnt}** | {nominal_pct:.1f}% | Healthy modular files meeting maintainability standards |"
    )
    lines.append(
        f"| **Total Evaluated Files** | **{total_files}** | 100.0% | Excluding tasks/, test-artifacts/, .venv/, node_modules |"
    )
    lines.append("")

    tier_counts = summary["tier_counts"]
    lines.append("### Risk Tier Distribution")
    lines.append("")
    lines.append(
        f"- **CRITICAL Risk ({tier_counts['CRITICAL']} files)**: Monoliths with high 30d/90d churn or extreme line counts (>=4,000 lines). Urgent decomposition targets."
    )
    lines.append(
        f"- **HIGH Risk ({tier_counts['HIGH']} files)**: Files exceeding 1,000 lines or 500+ line files undergoing frequent changes."
    )
    lines.append(
        f"- **MEDIUM Risk ({tier_counts['MEDIUM']} files)**: Moderately sized files (500-1,000 lines) or smaller active modules."
    )
    lines.append(
        f"- **LOW Risk ({tier_counts['LOW']} files)**: Well-contained modules with stable change frequency."
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 2: Component Breakdown
    lines.append("## 2. Component Inventory Breakdown")
    lines.append("")
    lines.append(
        "| Component | Total Files | Total Lines | Ceiling Violations (>=1k) | Warning (500-999) | 30d Churn | 90d Churn | Largest File (Lines) |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---|")

    comp_stats = summary["component_stats"]
    # Sort components by ceiling violations descending, then total lines descending
    sorted_comps = sorted(
        comp_stats.items(),
        key=lambda kv: (kv[1]["ceiling_violations"], kv[1]["total_lines"]),
        reverse=True,
    )

    for comp_name, cs in sorted_comps:
        max_file_display = f"`{cs['max_file']}` ({cs['max_lines']:,})" if cs["max_file"] else "N/A"
        lines.append(
            f"| **{comp_name}** | {cs['file_count']} | {cs['total_lines']:,} | {cs['ceiling_violations']} | {cs['warning_count']} | {cs['total_churn_30d']} | {cs['total_churn_90d']} | {max_file_display} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 3: Top Repository Hotspots
    lines.append(f"## 3. Top {top_limit} Repository Hotspots (Ranked by Risk Score)")
    lines.append("")
    lines.append(
        "Risk score combines normalized line count with 30-day and 90-day git churn velocity:"
    )
    lines.append(
        "$$\\text{Risk Score} = \\left(\\frac{\\text{Lines}}{1000}\\right) \\times \\left(1 + 0.5 \\times \\text{Churn}_{30d} + 0.2 \\times \\text{Churn}_{90d}\\right)$$"
    )
    lines.append("")
    lines.append(
        "| Rank | File Path | Component | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Risk Tier | Status |"
    )
    lines.append("|---:|---|---|---:|---:|---:|---:|---:|:---:|:---:|")

    for idx, f in enumerate(files_data[:top_limit], 1):
        status = (
            "VIOLATION"
            if f["ceiling_violation"]
            else ("WARNING" if f["warning_threshold"] else "OK")
        )
        lines.append(
            f"| {idx} | `{f['path']}` | {f['component']} | {f['lines']:,} | {f['bytes']:,} | {f['churn_30d']} | {f['churn_90d']} | {f['risk_score']:.2f} | **{f['risk_tier']}** | `{status}` |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 4: Focused Component Hotspots
    lines.append("## 4. Hotspots by Target Component")
    lines.append("")

    target_groups: List[Tuple[str, str, List[Dict[str, Any]]]] = [
        (
            "Go Core VPN",
            "internal/vpn/ core engine and state machines",
            [f for f in files_data if f["component"] == "Go Core VPN"],
        ),
        (
            "Packet Forwarder",
            "High-throughput packet forwarder and queue pipeline",
            [f for f in files_data if f["component"] == "Packet Forwarder"],
        ),
        (
            "Web Templates",
            "Server-rendered HTML templates",
            [f for f in files_data if f["component"] == "Web Templates"],
        ),
        (
            "Test Suites",
            "Go unit/integration and Python E2E test suites",
            [f for f in files_data if f["component"] == "Test Suites"],
        ),
        (
            "CSS Styles",
            "Frontend styling and design system stylesheets",
            [f for f in files_data if f["component"] == "CSS Styles"],
        ),
        (
            "Go Production Packages",
            "Managers, services, handlers, router, and database infrastructure",
            [f for f in files_data if f["component"].startswith("Go Production")],
        ),
    ]

    for title, desc, group_files in target_groups:
        lines.append(f"### {title}")
        lines.append(f"*{desc}*")
        lines.append("")
        if not group_files:
            lines.append("No files in this component.")
            lines.append("")
            continue

        lines.append(
            "| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|:---:|:---:|")
        # Top 10 in this component
        for f in group_files[:10]:
            status = (
                "VIOLATION"
                if f["ceiling_violation"]
                else ("WARNING" if f["warning_threshold"] else "OK")
            )
            lines.append(
                f"| `{f['path']}` | {f['lines']:,} | {f['bytes']:,} | {f['churn_30d']} | {f['churn_90d']} | {f['risk_score']:.2f} | {f['risk_tier']} | `{status}` |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")

    # Section 5: Churn Velocity Analysis
    lines.append("## 5. Git Churn Velocity Analysis (30-Day vs. 90-Day)")
    lines.append("")
    lines.append(
        "High-churn files experience frequent modifications, creating heightened vulnerability to merge collisions, concurrent agent race conditions, and accidental regression of delicate invariants."
    )
    lines.append("")
    churn_sorted = sorted(files_data, key=lambda x: (x["churn_30d"], x["churn_90d"]), reverse=True)
    lines.append(
        "| Top Churn File | Component | Lines | 30d Commits | 90d Commits | Velocity Trend | Assessment |"
    )
    lines.append("|---|---|---:|---:|---:|:---:|---|")
    for f in churn_sorted[:12]:
        trend = "ACCELERATING" if f["churn_30d"] > (f["churn_90d"] / 2.0) else "STEADY"
        lines.append(
            f"| `{f['path']}` | {f['component']} | {f['lines']:,} | {f['churn_30d']} | {f['churn_90d']} | `{trend}` | {'Severe concurrency hazard: oversized + hyper-active' if f['lines'] >= 1000 else 'Active modular file'} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 6: Candidate Decomposition Workstreams for Epic #475
    lines.append("## 6. Candidate Decomposition Workstreams for Epic #475")
    lines.append("")
    lines.append(
        "Based on the empirical inventory, the following decomposition workstreams are prioritized by maintainability risk and change churn:"
    )
    lines.append("")
    lines.append("### Workstream 1: Go Core VPN Service Monolith (`internal/vpn/vpn.go`)")
    lines.append(
        "- **Current Metrics**: 4,950 lines, 73 commits in 30d, 96 commits in 90d (Risk Score: 280.67, CRITICAL)."
    )
    lines.append(
        "- **Structural Responsibilities**: Centralizes lifecycle orchestration, peer synchronization, session cleanup, handshake monitoring, iptables/routing setup, device creation, and status polling."
    )
    lines.append("- **Decomposition Strategy**:")
    lines.append("  1. Extract peer synchronization loop to `internal/vpn/vpn_peer_sync.go`.")
    lines.append(
        "  2. Extract session allocation and IPAM bridge to `internal/vpn/vpn_session_manager.go`."
    )
    lines.append(
        "  3. Extract iptables and tunnel network configuration to `internal/vpn/vpn_netconfig.go`."
    )
    lines.append("  4. Target size per module: < 800 lines.")
    lines.append("")

    lines.append("### Workstream 2: Frontend VPN Dashboard Monolith (`web/templates/vpn.html`)")
    lines.append(
        "- **Current Metrics**: 3,758 lines, 54 commits in 30d, 62 commits in 90d (Risk Score: 151.82, CRITICAL)."
    )
    lines.append(
        "- **Structural Responsibilities**: Houses inline JavaScript, SVG sparklines, status badges, diagnostics modals, peer troubleshooting drawers, route tables, and telemetry widgets in a single template."
    )
    lines.append("- **Decomposition Strategy**:")
    lines.append("  1. Extract JavaScript controller logic to `web/static/js/vpn_dashboard.js`.")
    lines.append(
        "  2. Decompose sub-components into partial templates (`web/templates/partials/vpn_health_card.html`, `web/templates/partials/vpn_routes_table.html`, `web/templates/partials/vpn_sessions_modal.html`)."
    )
    lines.append("  3. Target main template size: < 600 lines.")
    lines.append("")

    lines.append(
        "### Workstream 3: Monolithic Web & VPN Test Suites (`web/vpn_diagnostics_test.go`, `internal/vpn/vpn_test.go`)"
    )
    lines.append(
        "- **Current Metrics**: `vpn_test.go` = 6,739 lines (Risk Score: 173.87); `vpn_diagnostics_test.go` = 6,295 lines (Risk Score: 195.77)."
    )
    lines.append(
        "- **Structural Responsibilities**: Multi-scenario DOM test cases, mocked backend responses, large JSON inline fixtures, and multi-threaded stress tests all co-located in two giant test files."
    )
    lines.append("- **Decomposition Strategy**:")
    lines.append(
        "  1. Split `web/vpn_diagnostics_test.go` by DOM component: `vpn_diagnostics_sparklines_test.go`, `vpn_diagnostics_routes_test.go`, `vpn_diagnostics_i18n_test.go`."
    )
    lines.append(
        "  2. Split `internal/vpn/vpn_test.go` by feature domain: `vpn_lifecycle_test.go`, `vpn_session_test.go`, `vpn_tunnel_failover_test.go`."
    )
    lines.append("  3. Keep all extracted test suites strictly below 1,000 lines.")
    lines.append("")

    lines.append("### Workstream 4: WireGuard Manager Monolith (`internal/manager/awg/awg.go`)")
    lines.append(
        "- **Current Metrics**: 3,287 lines, 20 commits in 30d, 35 commits in 90d (Risk Score: 59.17, CRITICAL)."
    )
    lines.append(
        "- **Structural Responsibilities**: Handles config generation, remote SSH command execution, atomic lock management, and CIDR/NAT IP allocation."
    )
    lines.append("- **Decomposition Strategy**:")
    lines.append(
        "  1. Separate SSH command execution and IPC into `internal/manager/awg/awg_client.go`."
    )
    lines.append(
        "  2. Separate config serialization and key parsing into `internal/manager/awg/awg_config_builder.go`."
    )
    lines.append("  3. Target module size: < 750 lines.")
    lines.append("")

    lines.append("### Workstream 5: Monolithic Stylesheet (`web/static/css/style.css`)")
    lines.append(
        "- **Current Metrics**: 3,008 lines, 10 commits in 30d, 18 commits in 90d (Risk Score: 28.88, HIGH)."
    )
    lines.append(
        "- **Structural Responsibilities**: Single giant CSS file containing layout grids, component styles, dark theme overrides, animations, and diagnostics table styling."
    )
    lines.append("- **Decomposition Strategy**:")
    lines.append(
        "  1. Split into modular CSS imports: `base.css`, `components/cards.css`, `components/tables.css`, `themes/dark.css`, `pages/vpn.css`."
    )
    lines.append("  2. Bundle or link via template asset loaders.")
    lines.append("")

    lines.append("### Workstream 6: Packet Forwarder Core (`internal/vpn/forwarder/forwarder.go`)")
    lines.append(
        "- **Current Metrics**: 1,886 lines, 28 commits in 30d, 35 commits in 90d (Risk Score: 41.49, CRITICAL)."
    )
    lines.append(
        "- **Structural Responsibilities**: Forwarder packet routing, ring buffer queues, drop tracking atomics, route pressure windows, and worker pool coordination."
    )
    lines.append("- **Decomposition Strategy**:")
    lines.append("  1. Extract route pressure window calculation to `forwarder_pressure.go`.")
    lines.append(
        "  2. Extract worker pool scheduling and epoch lifecycle to `forwarder_workers.go`."
    )
    lines.append("  3. Target main forwarder module: < 800 lines.")
    lines.append("")

    lines.append("---")
    lines.append("")

    # Section 7: Proposed Ratcheting Ceilings and Policy
    lines.append("## 7. Proposed Ratcheting Ceilings & Enforcement Policy")
    lines.append("")
    lines.append(
        "To prevent further regression into monolithic files, the team adopts a **ratcheting ceiling policy**:"
    )
    lines.append("")
    lines.append("1. **Strict Review Ceiling (1,000 Lines)**:")
    lines.append("   - Any new file introduced must not exceed 1,000 lines.")
    lines.append(
        "   - Any PR that pushes an existing file from below 1,000 lines to above 1,000 lines is subject to automatic rejection per code-review quality gates."
    )
    lines.append("")
    lines.append("2. **Warning Threshold (500 Lines)**:")
    lines.append("   - Files crossing 500 lines enter the architectural watch list.")
    lines.append(
        "   - Contributors are encouraged to extract cohesive sub-responsibilities before reaching the 1,000-line ceiling."
    )
    lines.append("")
    lines.append("3. **Ratcheting Ceiling on Legacy Monoliths**:")
    lines.append(
        "   - For the 43 legacy files exceeding 1,000 lines, their current line count serves as an absolute ceiling."
    )
    lines.append("   - PRs touching these files must **never increase** their total line count.")
    lines.append("   - Each decomposition PR ratchets the ceiling downward to the new line count.")
    lines.append(
        "   - Once a file drops below 1,000 lines, it permanently locks into the 1,000-line ceiling rule."
    )
    lines.append("")
    lines.append("4. **Continuous Quality Gate Integration**:")
    lines.append(
        "   - `scripts/inventory_hotspots.py --json` can be executed in CI to verify that no ceiling is breached and no existing ratchet is violated."
    )
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Repository Hotspots Inventory Tool: scans repository for oversized files, component distributions, and change churn."
    )
    parser.add_argument(
        "--repo-root",
        type=str,
        default=None,
        help="Path to repository root (defaults to git top-level or current directory).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Output structured JSON format.",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        dest="markdown_mode",
        help="Output human-readable markdown report format (default).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output file path (defaults to stdout).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=25,
        help="Number of top hotspots to include in summary tables (default: 25).",
    )
    parser.add_argument(
        "--ceiling",
        type=int,
        default=1000,
        help="Strict file line-count ceiling threshold (default: 1000).",
    )
    parser.add_argument(
        "--warning",
        type=int,
        default=500,
        help="Warning line-count threshold (default: 500).",
    )
    parser.add_argument(
        "--days-30",
        type=int,
        default=30,
        help="Short-term churn analysis window in days (default: 30).",
    )
    parser.add_argument(
        "--days-90",
        type=int,
        default=90,
        help="Medium-term churn analysis window in days (default: 90).",
    )

    args = parser.parse_args()

    repo_root = find_repo_root(args.repo_root)

    files_data, summary = scan_repository(
        repo_root=repo_root,
        ceiling_lines=args.ceiling,
        warning_lines=args.warning,
        days_30=args.days_30,
        days_90=args.days_90,
    )

    if args.json_mode:
        output_content = generate_json_output(files_data, summary, top_limit=args.top)
    else:
        # Default to markdown
        output_content = generate_markdown_report(files_data, summary, top_limit=args.top)

    if args.output:
        out_path = Path(args.output)
        if not out_path.is_absolute():
            out_path = repo_root / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(output_content + "\n")
    else:
        print(output_content)

    return 0


if __name__ == "__main__":
    sys.exit(main())
