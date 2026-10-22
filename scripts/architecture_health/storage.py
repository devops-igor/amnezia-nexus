"""Baseline persistence and loading for architecture health."""

import json
from pathlib import Path
from typing import Any, Dict


def load_baseline(baseline_path: Path) -> Dict[str, Any]:
    """Load baseline JSON file from disk.

    Raises:
        FileNotFoundError: If the baseline file does not exist.
        json.JSONDecodeError: If the baseline file cannot be parsed as valid JSON.
    """
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file does not exist: {baseline_path}")
    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_baseline(baseline_path: Path, baseline_data: Dict[str, Any]) -> None:
    """Save baseline JSON file to disk with deterministic 2-space indentation."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)
        f.write("\n")
