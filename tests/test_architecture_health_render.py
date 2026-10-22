"""Unit tests for JSON and Markdown report rendering and zero-leak verification."""

import json

from scripts.architecture_health import (
    generate_json_report,
    generate_markdown_summary,
)


def test_generate_json_report_schema_and_zero_leak() -> None:
    """Verify JSON report schema integrity and ensure zero leaks of local system paths."""
    summary = {
        "total_files": 2,
        "total_lines": 1500,
        "total_bytes": 45000,
        "ceiling_lines": 1000,
        "warning_lines": 500,
        "ceiling_violations_count": 1,
        "warning_count": 0,
        "grandfathered_count": 1,
        "ratchet_opportunities_count": 1,
        "tier_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
        "component_stats": {
            "Go Core VPN": {
                "file_count": 1,
                "total_lines": 1200,
                "total_bytes": 36000,
                "ceiling_violations": 1,
                "warning_count": 0,
                "max_lines": 1200,
                "max_file": "internal/vpn/vpn.go",
                "total_churn_30d": 5,
                "total_churn_90d": 10,
            }
        },
        "top_growing_files": [
            {
                "path": "internal/vpn/vpn.go",
                "component": "Go Core VPN",
                "current_lines": 1200,
                "baseline_lines": 1000,
                "line_delta": 200,
            }
        ],
        "top_go_functions": [
            {
                "file": "internal/vpn/vpn.go",
                "name": "NewVPNService",
                "signature": "func NewVPNService()",
                "start_line": 284,
                "end_line": 350,
                "lines": 67,
            }
        ],
    }

    files_data = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "language": "Go",
            "lines": 1200,
            "bytes": 36000,
            "ceiling": 1000,
            "churn_30d": 5,
            "churn_90d": 10,
            "risk_score": 15.6,
            "risk_tier": "HIGH",
            "ceiling_violation": True,
            "warning_threshold": False,
            "grandfathered": False,
            "is_generated": False,
        },
        {
            "path": "web/static/css/style.css",
            "component": "Generated & Vendor",
            "language": "CSS",
            "lines": 3000,
            "bytes": 90000,
            "ceiling": 3000,
            "churn_30d": 0,
            "churn_90d": 0,
            "risk_score": 0.0,
            "risk_tier": "GENERATED",
            "ceiling_violation": False,
            "warning_threshold": False,
            "grandfathered": False,
            "is_generated": True,
        },
    ]

    violations = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "lines": 1200,
            "ceiling": 1000,
            "excess_lines": 200,
        }
    ]

    ratchets = [
        {
            "path": "internal/vpn/old.go",
            "component": "Go Core VPN",
            "previous_ceiling": 1500,
            "current_lines": 1200,
            "new_ceiling": 1200,
            "reduction": 300,
        }
    ]

    meta = {
        "repository": "amnezia-nexus",
        "baseline_commit": "abcdef1234567890abcdef1234567890abcdef12",
        "reference_timestamp": "2026-10-19T12:00:00Z",
        "churn_windows_days": [30, 90],
    }

    report_json = generate_json_report(
        files_data=files_data,
        summary=summary,
        ceiling_violations=violations,
        ratchet_opportunities=ratchets,
        baseline_metadata=meta,
        scan_commit="1234567890abcdef1234567890abcdef12abcdef",
    )

    data = json.loads(report_json)
    assert data["scan_metadata"]["repository"] == "amnezia-nexus"
    assert data["summary"]["ceiling_violations_count"] == 1
    assert len(data["top_hotspots"]) == 1
    assert len(data["generated_vendor_files"]) == 1
    assert len(data["top_growing_files"]) == 1
    assert len(data["top_go_functions"]) == 1

    # Security: Verify zero leaks of absolute home paths, Windows mounts, or RFC 1918 IPs
    assert "/home/" not in report_json
    assert "/Users/" not in report_json
    assert "/mnt/c/" not in report_json
    assert "192.168." not in report_json
    assert "10.0." not in report_json
    assert "172.16." not in report_json


def test_generate_markdown_summary() -> None:
    """Verify Markdown summary table formatting and step-summary callouts."""
    summary = {
        "total_files": 2,
        "total_lines": 1500,
        "total_bytes": 45000,
        "ceiling_lines": 1000,
        "warning_lines": 500,
        "ceiling_violations_count": 1,
        "warning_count": 0,
        "grandfathered_count": 1,
        "ratchet_opportunities_count": 1,
        "tier_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
        "component_stats": {
            "Go Core VPN": {
                "file_count": 1,
                "total_lines": 1200,
                "total_bytes": 36000,
                "ceiling_violations": 1,
                "warning_count": 0,
                "max_lines": 1200,
                "max_file": "internal/vpn/vpn.go",
                "total_churn_30d": 5,
                "total_churn_90d": 10,
            }
        },
        "top_growing_files": [
            {
                "path": "internal/vpn/vpn.go",
                "component": "Go Core VPN",
                "current_lines": 1200,
                "baseline_lines": 1000,
                "line_delta": 200,
            }
        ],
        "top_go_functions": [
            {
                "file": "internal/vpn/vpn.go",
                "name": "NewVPNService",
                "signature": "func NewVPNService()",
                "start_line": 284,
                "end_line": 350,
                "lines": 67,
            }
        ],
    }

    files_data = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "lines": 1200,
            "ceiling": 1000,
            "churn_30d": 5,
            "churn_90d": 10,
            "risk_score": 15.6,
            "risk_tier": "HIGH",
            "is_generated": False,
        },
        {
            "path": "web/static/css/style.css",
            "component": "Generated & Vendor",
            "lines": 3000,
            "ceiling": 3000,
            "is_generated": True,
        },
    ]

    violations = [
        {
            "path": "internal/vpn/vpn.go",
            "component": "Go Core VPN",
            "lines": 1200,
            "ceiling": 1000,
            "excess_lines": 200,
        }
    ]

    ratchets = [
        {
            "path": "internal/vpn/old.go",
            "component": "Go Core VPN",
            "previous_ceiling": 1500,
            "current_lines": 1200,
            "new_ceiling": 1200,
            "reduction": 300,
        }
    ]

    md = generate_markdown_summary(
        files_data=files_data,
        summary=summary,
        ceiling_violations=violations,
        ratchet_opportunities=ratchets,
    )

    assert "## Architecture Health & Churn Report" in md
    assert "> **1 Ceiling Violation(s) Detected.**" in md
    assert "### ❌ Ceiling Violations" in md
    assert "### 📉 Downward Ratchet Opportunities" in md
    assert "### 📈 Top Growing Files" in md
    assert "### 🔍 Top Go Functions by Line Count" in md
    assert "### 🔥 Top 20 Hotspots (Risk & Churn)" in md
    assert "### 🤖 Generated & Vendor Assets" in md
    assert "### 📦 Component Distribution" in md


def test_markdown_callout_states() -> None:
    """Verify the 3 callout states: violations, ratchets only, and clean."""
    empty_summary = {
        "total_files": 1,
        "total_lines": 100,
        "total_bytes": 1000,
        "ceiling_lines": 1000,
        "warning_lines": 500,
        "ceiling_violations_count": 0,
        "warning_count": 0,
        "grandfathered_count": 0,
        "ratchet_opportunities_count": 0,
        "tier_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1},
        "component_stats": {},
    }

    # Clean
    md_clean = generate_markdown_summary([], empty_summary, [], [])
    assert "> **Architecture Health Clean.**" in md_clean

    # Ratchet only
    summary_ratchet = dict(empty_summary, ratchet_opportunities_count=2)
    md_ratchet = generate_markdown_summary(
        [],
        summary_ratchet,
        [],
        [
            {
                "path": "a.go",
                "component": "Go Core VPN",
                "previous_ceiling": 1200,
                "current_lines": 1000,
                "new_ceiling": 1000,
                "reduction": 200,
            }
        ],
    )
    assert "> **Downward Ratchet Pending.**" in md_ratchet
