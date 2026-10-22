"""Baseline persistence and loading for architecture health."""

import json
from pathlib import Path
from typing import Any, Dict


def validate_baseline(data: Any) -> None:
    """Validate that baseline data is non-empty and structurally complete.

    Requires a non-empty dictionary containing:
      - non-empty 'metadata' dictionary with a non-empty 'baseline_commit' string.
      - non-empty 'ceilings' dictionary.

    Raises:
        ValueError: If the baseline data is empty or structurally incomplete.
    """
    if not isinstance(data, dict) or not data:
        raise ValueError("Baseline data is empty or not a valid JSON object.")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict) or not metadata:
        raise ValueError("Baseline data is missing or has empty 'metadata'.")
    baseline_commit = metadata.get("baseline_commit")
    if not baseline_commit or not isinstance(baseline_commit, str) or not baseline_commit.strip():
        raise ValueError("Baseline metadata is missing a valid 'baseline_commit'.")
    ceilings = data.get("ceilings")
    if not isinstance(ceilings, dict) or not ceilings:
        raise ValueError("Baseline data is missing or has empty 'ceilings'.")


def load_baseline(baseline_path: Path) -> Dict[str, Any]:
    """Load baseline JSON file from disk and validate structural completeness.

    Raises:
        FileNotFoundError: If the baseline file does not exist.
        json.JSONDecodeError: If the baseline file cannot be parsed as valid JSON.
        ValueError: If the baseline data is empty or structurally incomplete.
    """
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file does not exist: {baseline_path}")
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    validate_baseline(data)
    return data


def save_baseline(baseline_path: Path, baseline_data: Dict[str, Any]) -> None:
    """Save baseline JSON file to disk with deterministic 2-space indentation."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)
        f.write("\n")
