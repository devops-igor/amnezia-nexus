"""CLI entrypoint and workflow coordination for architecture health."""

import argparse
import logging
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional

import scripts.architecture_health as ah
from scripts.architecture_health.constants import (
    DEFAULT_CEILING_LINES,
    DEFAULT_WARNING_LINES,
)
from scripts.architecture_health.pull_request import (
    PrSizeGateError,
    evaluate_pull_request,
    load_pull_request_context,
    report_excused_result,
    report_pull_request_result,
    resolve_exception,
)

logger = logging.getLogger("architecture_health")


def _resolve_pr_exception() -> Dict[str, Any]:
    """Resolve this run's exception from the pull request event payload.

    The label and the description both come from the payload GitHub writes for
    the run, so the check needs no token, no API call and no write permission.
    """
    context = load_pull_request_context(os.environ.get("GITHUB_EVENT_PATH"))
    return resolve_exception(labels=context["labels"], body=context["body"])


def _run_pr_size_gate(args: argparse.Namespace, repo_root: Path) -> int:
    """Run the pull-request SG1 size gate and return its exit code.

    There is no base to compare against outside a pull request, so the gate
    stands down and says so rather than pretending it verified anything.
    """
    base_ref = args.base_ref
    if not base_ref:
        event = os.environ.get("GITHUB_EVENT_NAME")
        if event and event != "pull_request":
            logger.info(
                "SG1 pull request gate not applicable: this run is a %s event, "
                "so there is no pull request base to compare against. Not blocking.",
                event,
            )
            return 0
        base_ref = os.environ.get("GITHUB_BASE_REF") or ""
    if not base_ref:
        logger.info(
            "SG1 pull request gate not applicable: no base ref available "
            "(no --base-ref and no GITHUB_BASE_REF). Not blocking.",
        )
        return 0

    head_ref = args.head_ref or ""
    if not head_ref:
        if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
            logger.error(
                "SG1 pull request gate FAILED: no head reference was supplied, and on a "
                "pull request checkout HEAD is the synthetic merge of the base tip and the "
                "pull request head, so it cannot stand in for the pull request. Judging it "
                "would compare the base tip with the merge instead of the branch point with "
                "the head. Failing rather than reporting a verdict from the merge checkout."
            )
            return 1
        head_ref = "HEAD"

    try:
        exception = _resolve_pr_exception()
    except PrSizeGateError as exc:
        logger.error(
            "SG1 pull request gate FAILED to read the pull request event payload: %s. "
            "Failing closed rather than treating an unreadable exception as absent.",
            exc,
        )
        return 1

    try:
        result = evaluate_pull_request(
            repo_root=repo_root,
            base_ref=base_ref,
            head_ref=head_ref,
            ceiling_lines=args.ceiling,
            exception=exception,
        )
    except PrSizeGateError as exc:
        logger.error(
            "SG1 pull request gate FAILED to read git data for base %s: %s. "
            "Failing closed rather than reporting a pass.",
            base_ref,
            exc,
        )
        return 1

    logger.info(
        "SG1 pull request gate: comparing %d changed path(s) between merge base %s of %s "
        "and head %s.",
        result["checked_count"],
        result["merge_base"][:10],
        base_ref,
        result["head_ref"],
    )
    for entry in result["checked"]:
        logger.info(
            "SG1 pull request gate: %s is %d line(s) at the merge base and %d line(s) at the head.",
            entry["path"],
            entry["base_lines"],
            entry["head_lines"],
        )
    for entry in result["skipped"]:
        logger.info("SG1 pull request gate: skipped %s (%s).", entry["path"], entry["reason"])

    # A half-exception is never a pass. The two halves are named separately so
    # the message says exactly which one is missing, and any transition it was
    # meant to cover is still printed: the reader must see both the missing half
    # and the size change, not just the first of the two.
    if exception["requested"] and not exception["valid"]:
        for line in report_pull_request_result(result):
            logger.error(line)
        logger.error(
            "SG1 pull request gate FAILED: the %s label is applied but the pull request "
            "body has no statement under a '%s' heading. Section 4.3 requires a stated "
            "per-PR responsibility justification, so the exception is incomplete and the "
            "size rule still applies.",
            exception["label"],
            exception["heading"],
        )
        return 1

    if result["excused"]:
        for entry in result["excused"]:
            logger.warning(
                "SG1 pull request gate: excused %s by the %s label: %d line(s) at the "
                "merge base and %d line(s) at the head (%s).",
                entry["path"],
                exception["label"],
                entry["base_lines"],
                entry["head_lines"],
                entry["transition"],
            )
        for line in report_excused_result(result):
            logger.warning(line)
        logger.warning(
            "SG1 pull request gate PASSED WITH EXCEPTION: %d size transition(s) excused "
            "by the %s label and the '%s' statement in this pull request. Every excused "
            "path is named above with both counts.",
            len(result["excused"]),
            exception["label"],
            exception["heading"],
        )
        return 0

    if result["violations"]:
        for line in report_pull_request_result(result):
            logger.error(line)
        logger.error(
            "SG1 pull request gate FAILED with %d size violation(s). Section 4.3 forbids "
            "crossing %d lines or growing a file already above it without a stated "
            "per-PR justification.",
            len(result["violations"]),
            result["ceiling_lines"],
        )
        return 1

    if exception["valid"]:
        logger.info(
            "SG1 pull request gate PASSED: the %s exception is present and was not needed, "
            "because this PR introduces no size transition. Nothing was excused.",
            exception["label"],
        )
        return 0

    logger.info("SG1 pull request gate PASSED: no size transition introduced by this PR.")
    return 0


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
        "--check-pr-size",
        action="store_true",
        help="Fail only on SG1 size transitions this pull request introduces against its merge base.",
    )
    parser.add_argument(
        "--base-ref",
        default=None,
        help="Base branch ref for --check-pr-size (defaults to GITHUB_BASE_REF).",
    )
    parser.add_argument(
        "--head-ref",
        default=None,
        help=(
            "Head ref for --check-pr-size. Required in a pull request context, where the "
            "checked-out HEAD is the synthetic Actions merge and cannot stand in for the "
            "pull request head; defaults to HEAD only outside a pull request."
        ),
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
    if args.check_pr_size:
        return _run_pr_size_gate(args, repo_root)
    baseline_path = Path(args.baseline_file)
    if not baseline_path.is_absolute():
        baseline_path = repo_root / baseline_path

    if args.generate_baseline:
        logger.info("Generating architecture baseline at %s...", baseline_path)
        existing_data = None
        if baseline_path.exists():
            try:
                existing_data = ah.load_baseline(baseline_path)
                ah.validate_baseline(existing_data)
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
        ah.validate_baseline(baseline_data)
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
