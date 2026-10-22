"""CLI entrypoint and workflow coordination for architecture health."""

import argparse
import logging
import os
from pathlib import Path
import subprocess
import sys
from typing import List, Optional

import scripts.architecture_health as ah
from scripts.architecture_health.constants import (
    DEFAULT_CEILING_LINES,
    DEFAULT_WARNING_LINES,
)

logger = logging.getLogger("architecture_health")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for architecture health and churn reporter."""
    logging.basicConfig(
        level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler(sys.stdout)]
    )
    parser = argparse.ArgumentParser(
        description="Architecture Health Size and Churn Report with Ratchet."
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root path (defaults to auto-discovered git root).",
    )
    parser.add_argument(
        "--baseline-file",
        default="scripts/architecture_baseline.json",
        help="Path to architecture baseline JSON file.",
    )
    parser.add_argument(
        "--generate-baseline",
        action="store_true",
        help="Generate architecture baseline JSON metadata for the repository.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check tracked files against pinned baseline ceilings.",
    )
    parser.add_argument(
        "--ratchet",
        action="store_true",
        help="Apply downward ratchet to baseline ceilings, locking in size reductions.",
    )
    parser.add_argument(
        "--allow-ceiling-increase",
        action="store_true",
        help="Allow increasing file ceilings when generating baseline or updating ratchet.",
    )
    parser.add_argument(
        "--nonblocking",
        action="store_true",
        help="Report violations advisably with exit code 0 rather than failing the scan.",
    )
    parser.add_argument(
        "--report-json",
        default="architecture_health_report.json",
        help="File path to output the full structured JSON report.",
    )
    parser.add_argument(
        "--summary-md",
        default=None,
        help="File path to output Markdown summary (defaults to GITHUB_STEP_SUMMARY env).",
    )
    parser.add_argument(
        "--ceiling",
        type=int,
        default=DEFAULT_CEILING_LINES,
        help="Strict architectural ceiling in physical lines for tracked files.",
    )
    parser.add_argument(
        "--warning",
        type=int,
        default=DEFAULT_WARNING_LINES,
        help="Advisory warning threshold in physical lines for tracked files.",
    )

    args = parser.parse_args(argv)
    repo_root = ah.find_repo_root(args.repo_root)
    baseline_path = Path(args.baseline_file)
    if not baseline_path.is_absolute():
        baseline_path = repo_root / baseline_path

    if args.generate_baseline:
        logger.info("Generating architecture baseline at %s...", baseline_path)
        existing_data = None
        if baseline_path.exists():
            try:
                existing_data = ah.load_baseline(baseline_path)
            except Exception as exc:
                if not args.allow_ceiling_increase:
                    logger.error(
                        "Failed to parse existing baseline file %s: %s. "
                        "Fails closed without --allow-ceiling-increase.",
                        baseline_path,
                        exc,
                    )
                    return 1
                logger.warning(
                    "Existing baseline is invalid/corrupt, but --allow-ceiling-increase is set. "
                    "Overwriting: %s",
                    exc,
                )
                existing_data = None

        b_commit = (
            existing_data.get("metadata", {}).get("baseline_commit") if existing_data else None
        )
        try:
            renames = ah.detect_renames(repo_root, b_commit)
        except Exception as exc:
            logger.error("Git error during baseline generation: %s", exc)
            return 1

        try:
            baseline_data = ah.generate_baseline(
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
        except Exception as exc:
            logger.error("Operational error during baseline generation: %s", exc)
            return 1

        ah.save_baseline(baseline_path, baseline_data)
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
        return 1

    try:
        baseline_data = ah.load_baseline(baseline_path)
    except Exception as exc:
        logger.error("Failed to load baseline file %s: %s", baseline_path, exc)
        return 1

    base_meta = baseline_data.get("metadata", {})
    b_commit = base_meta.get("baseline_commit")
    try:
        renames = ah.detect_renames(repo_root, b_commit)
    except Exception as exc:
        logger.error("Operational error detecting renames: %s", exc)
        return 1

    try:
        scan_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True, stderr=subprocess.PIPE
        ).strip()
    except Exception:
        scan_commit = "unknown"

    try:
        files_data, summary, violations, ratchets = ah.scan_repository(
            repo_root=repo_root,
            baseline_ceilings=baseline_data.get("ceilings", {}),
            baseline_files=baseline_data.get("files", {}),
            baseline_commit=b_commit,
            reference_epoch=base_meta.get("reference_timestamp_epoch"),
            ceiling_lines=args.ceiling,
            warning_lines=args.warning,
            renames=renames,
        )
    except Exception as exc:
        logger.error("Operational scan failure: %s", exc)
        return 1

    if args.ratchet:
        try:
            updated_baseline, applied, _ = ah.update_downward_ratchet(
                current_files_data=files_data,
                baseline_data=baseline_data,
                ceiling_lines=args.ceiling,
                allow_ceiling_increase=args.allow_ceiling_increase,
                renames=renames,
            )
            ah.save_baseline(baseline_path, updated_baseline)
            logger.info("Ratchet applied: %d ceiling updates saved.", len(applied))
        except ValueError as exc:
            logger.error("Ratchet update rejected: %s", exc)
            return 1
        except Exception as exc:
            logger.error("Operational error during ratchet: %s", exc)
            return 1

    report_path = Path(args.report_json)
    if not report_path.is_absolute():
        report_path = repo_root / report_path
    json_content = ah.generate_json_report(
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
                ah.generate_markdown_summary(files_data, summary, violations, ratchets, base_meta)
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
