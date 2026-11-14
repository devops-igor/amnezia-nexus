#!/usr/bin/env python3
"""Assign Go packages to a CI shard using measured test weights.

Usage:
    python3 scripts/ci_go_shards.py --shard 1 --shards 3

Prints a space-separated package list suitable for:

    go test -race -tags with_utls $(python3 scripts/ci_go_shards.py ...)

Assignment is deterministic: packages are ordered by measured weight (largest
first, then name) and each is placed on the currently least-loaded shard. A
package with no measurement gets a small default weight, so a newly added
package is always assigned and can never be silently dropped.

The weights come from a real CI run, not from directory names: see
ci_go_shard_weights.json for the run and step they were measured in.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
WEIGHTS_FILE = REPO_ROOT / "scripts" / "ci_go_shard_weights.json"
MODULE_PREFIX = "github.com/devops-igor/amnezia-nexus/"
DEFAULT_WEIGHT = 1.0


def go_packages() -> List[str]:
    """Return every package in the module, without the module prefix."""
    result = subprocess.run(
        ["go", "list", "./..."], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return sorted(
        line.strip().removeprefix(MODULE_PREFIX)
        for line in result.stdout.splitlines()
        if line.strip()
    )


def load_weights() -> Dict[str, float]:
    data = json.loads(WEIGHTS_FILE.read_text(encoding="utf-8"))
    return {name: float(value) for name, value in data["weights"].items()}


def assign(packages: List[str], weights: Dict[str, float], shards: int) -> List[List[str]]:
    """Return one package list per shard (1-based shard index = list index + 1)."""
    if shards < 1:
        raise ValueError("shards must be >= 1")
    ordered = sorted(packages, key=lambda name: (-weights.get(name, DEFAULT_WEIGHT), name))
    buckets: List[List[str]] = [[] for _ in range(shards)]
    loads = [0.0] * shards
    for package in ordered:
        index = min(range(shards), key=lambda i: (loads[i], i))
        buckets[index].append(package)
        loads[index] += weights.get(package, DEFAULT_WEIGHT)
    return [sorted(bucket) for bucket in buckets]


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the Go packages for one CI shard")
    parser.add_argument("--shard", type=int, required=True, help="1-based shard number")
    parser.add_argument("--shards", type=int, default=3, help="total number of shards")
    parser.add_argument("--list", action="store_true", help="print one package per line")
    args = parser.parse_args(argv)

    if not 1 <= args.shard <= args.shards:
        print(f"shard must be between 1 and {args.shards}", file=sys.stderr)
        return 2

    buckets = assign(go_packages(), load_weights(), args.shards)
    selected = [f"./{package}" for package in buckets[args.shard - 1]]
    print("\n".join(selected) if args.list else " ".join(selected))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
