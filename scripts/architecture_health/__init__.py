"""Architecture Health Size and Churn Report with Ratchet package."""

from pathlib import Path

from scripts.architecture_health.cli import main
from scripts.architecture_health.constants import (
    BINARY_EXTENSIONS,
    CHURN_LONG_DAYS,
    CHURN_SHORT_DAYS,
    DEFAULT_CEILING_LINES,
    DEFAULT_WARNING_LINES,
    EXCLUDED_DIRS,
    EXCLUDED_FILES,
    GENERATED_OR_VENDOR_PATHS,
    LANGUAGE_MAP,
    is_excluded,
    is_generated_or_vendor,
)
from scripts.architecture_health.discovery import (
    analyze_go_functions,
    classify_component,
    compute_git_churn,
    count_file_lines_and_bytes,
    detect_renames,
    find_repo_root,
    get_commit_metadata,
    get_tracked_files,
)
from scripts.architecture_health.policy import (
    calculate_risk_metrics,
    generate_baseline,
    rebase_ceilings,
    rebase_churn,
    rebase_files_map,
    scan_repository,
    update_downward_ratchet,
)
from scripts.architecture_health.render import (
    generate_json_report,
    generate_markdown_summary,
)
from scripts.architecture_health.storage import (
    load_baseline,
    save_baseline,
    validate_baseline,
)

__all__ = [
    "BINARY_EXTENSIONS",
    "CHURN_LONG_DAYS",
    "CHURN_SHORT_DAYS",
    "DEFAULT_CEILING_LINES",
    "DEFAULT_WARNING_LINES",
    "EXCLUDED_DIRS",
    "EXCLUDED_FILES",
    "GENERATED_OR_VENDOR_PATHS",
    "LANGUAGE_MAP",
    "is_excluded",
    "is_generated_or_vendor",
    "analyze_go_functions",
    "classify_component",
    "compute_git_churn",
    "count_file_lines_and_bytes",
    "detect_renames",
    "find_repo_root",
    "get_commit_metadata",
    "get_tracked_files",
    "calculate_risk_metrics",
    "generate_baseline",
    "rebase_ceilings",
    "rebase_churn",
    "rebase_files_map",
    "scan_repository",
    "update_downward_ratchet",
    "generate_json_report",
    "generate_markdown_summary",
    "load_baseline",
    "save_baseline",
    "validate_baseline",
    "main",
    "Path",
]
