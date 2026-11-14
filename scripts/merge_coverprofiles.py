#!/usr/bin/env python3
"""Merge per-shard Go coverage profiles into one report.

The shards are built from disjoint package sets, so their profiles describe
disjoint files and merging is a concatenation behind a single ``mode:`` header.

Duplicate blocks are still collapsed defensively, keeping the highest count: if
an overlap ever appears (for example a future ``-coverpkg``), the merge must not
double-count a block. All inputs must use the same coverage mode.

Usage:
    python3 scripts/merge_coverprofiles.py out.out shard-1.out shard-2.out ...
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

Block = Tuple[str, int, int, int]  # file, start column, end column, statement count


def parse_profile(path: Path) -> Tuple[str, Dict[Block, int]]:
    mode = ""
    blocks: Dict[Block, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("mode:"):
            if mode and line != f"mode: {mode}":
                raise ValueError(f"{path}: mixed coverage modes ({mode!r} vs {line!r})")
            mode = line.split(":", 1)[1].strip()
            continue
        location, statements, count = line.rsplit(" ", 2)
        file_part, span = location.rsplit(":", 1)
        start, end = span.split(",")
        key: Block = (file_part, int(start.split(".")[0]), int(end.split(".")[0]), int(statements))
        blocks[key] = max(blocks.get(key, 0), int(count))
    if not mode:
        raise ValueError(f"{path}: missing coverage mode header")
    return mode, blocks


def merge(paths: Iterable[Path]) -> str:
    mode = ""
    merged: Dict[Block, int] = {}
    for path in paths:
        file_mode, blocks = parse_profile(path)
        if mode and file_mode != mode:
            raise ValueError(f"mixed coverage modes: {mode!r} and {file_mode!r}")
        mode = file_mode
        for key, count in blocks.items():
            merged[key] = max(merged.get(key, 0), count)

    lines = [f"mode: {mode}"]
    for (file_part, start, end, statements), count in sorted(merged.items()):
        lines.append(f"{file_part}:{start}.0,{end}.0 {statements} {count}")
    return "\n".join(lines) + "\n"


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: merge_coverprofiles.py <output> <profile> [<profile> ...]", file=sys.stderr)
        return 2
    output, inputs = Path(argv[0]), [Path(p) for p in argv[1:]]
    missing = [str(p) for p in inputs if not p.is_file()]
    if missing:
        print(f"missing coverage profiles: {', '.join(missing)}", file=sys.stderr)
        return 1
    output.write_text(merge(inputs), encoding="utf-8")
    print(f"merged {len(inputs)} profile(s) into {output}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main(sys.argv[1:]))
