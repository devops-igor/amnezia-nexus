"""JSON and GitHub Step Summary Markdown report rendering for architecture health."""

import json
from typing import Any, Dict, List, Optional

from scripts.architecture_health.constants import CHURN_LONG_DAYS, CHURN_SHORT_DAYS


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
    top_growing = summary.get("top_growing_files", [])
    newly_added = summary.get("newly_added_files", [])
    top_go_funcs = summary.get("top_go_functions", [])

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
            "newly_added_files_count": summary.get("newly_added_files_count", len(newly_added)),
            "tier_counts": summary["tier_counts"],
            "component_stats": summary["component_stats"],
        },
        "ceiling_violations": ceiling_violations,
        "ratchet_opportunities": ratchet_opportunities,
        "top_hotspots": developer_hotspots,
        "generated_vendor_files": generated_files,
        "newly_added_files": newly_added,
        "top_growing_files": top_growing,
        "top_go_functions": top_go_funcs,
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
    newly_added = summary.get("newly_added_files", [])
    newly_added_count = summary.get("newly_added_files_count", len(newly_added))

    if viol_count:
        callout = (
            f"> [!WARNING]\n"
            f"> **{viol_count} Ceiling Violation(s) Detected.** "
            f"Files exceed their pinned architecture ceiling."
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
            f"| **Grandfathered Exceptions (>= {summary['ceiling_lines']:,} lines)** | "
            f"**{summary['grandfathered_count']}** | 📋 Pinned Ceiling |"
        )
    lines.extend(
        [
            f"| **Warning Threshold ({summary['warning_lines']:,}-{summary['ceiling_lines']-1:,} lines)** | **{summary['warning_count']}** | ⚠️ Advisory |",
            f"| **Downward Ratchet Opportunities** | **{ratchet_count}** | {'📉 Ratchet Pending' if ratchet_count else '✅ Synchronized'} |",
            f"| **Newly Added Files** | **{newly_added_count}** | ℹ️ Tracked |",
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

    top_growing = summary.get("top_growing_files", [])
    if top_growing:
        lines.extend(
            [
                "### 📈 Top Growing Files",
                "",
                "| File Path | Component | Current Lines | Baseline Lines | Delta |",
                "|---|---|---:|---:|---:|",
            ]
        )
        lines.extend(
            f"| `{g['path']}` | {g['component']} | {g['current_lines']:,} | {g['baseline_lines']:,} | +{g['line_delta']:,} |"
            for g in top_growing[:15]
        )
        lines.append("")

    if newly_added:
        lines.extend(
            [
                f"### 🆕 Newly Added Files ({len(newly_added)})",
                "",
                f"Total newly added files since baseline: **{len(newly_added)}**",
                "",
                "| File Path | Component | Lines | Bytes |",
                "|---|---|---:|---:|",
            ]
        )
        lines.extend(
            f"| `{nf['path']}` | {nf['component']} | {nf['lines']:,} | {nf['bytes']:,} |"
            for nf in newly_added[:top_limit]
        )
        lines.append("")

    top_go_funcs = summary.get("top_go_functions", [])
    if top_go_funcs:
        lines.extend(
            [
                "### 🔍 Top Go Functions by Line Count",
                "",
                "| Function | File Path | Lines |",
                "|---|---|---:|",
            ]
        )
        lines.extend(
            f"| `{fn['name']}` | `{fn['file']}:{fn['start_line']}` | {fn['lines']:,} |"
            for fn in top_go_funcs[:15]
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
            f"| {idx} | `{f['path']}` | {f['component']} | {f['lines']:,} | "
            f"{f.get('churn_30d', 0)} | {f.get('churn_90d', 0)} | "
            f"{f.get('risk_score', 0.0):.2f} | **{f.get('risk_tier', 'LOW')}** |"
        )
    lines.append("")

    if generated_files:
        lines.extend(
            [
                "### 🤖 Generated & Vendor Assets",
                "",
                "These files are generated bundles, fixtures, or vendor assets (excluded from developer hotspots and ceilings):",
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
            f"| **{comp_name}** | {cs['file_count']} | {cs['total_lines']:,} | "
            f"{cs['ceiling_violations']} | {cs['total_churn_30d']} | {max_file_display} |"
        )
    lines.append("")

    return "\n".join(lines)
