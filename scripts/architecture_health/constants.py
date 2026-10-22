"""Constants, mappings, and path classification definitions for architecture health."""

from pathlib import Path
from typing import Dict, Set

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
