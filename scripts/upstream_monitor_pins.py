"""Read the pinned upstream component identities from their single definition.

The scheduled upstream monitor compares upstream release tags with the pins the
build ships. Those pins are defined once in ``internal/version/version.go``,
which also derives the base image from the versioned source instead of repeating
it as a literal, so the monitor reads that file rather than keeping its own copy.

Every read here is strict. A pin this reader cannot resolve is an error, never a
default: a default is exactly the stale value the monitor would keep comparing
against, and it would do so silently, so a correct bump would go unnoticed while
an already-adopted tag could still be reported as new.

Usage
-----
    python3 scripts/upstream_monitor_pins.py [--root DIR]

On success it writes one JSON object to stdout and exits 0. When any input is
missing, unreadable or unparseable it writes a diagnostic to stderr, writes no
JSON, and exits non-zero, so a caller cannot fall back to a remembered pin.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION_SOURCE = Path("internal") / "version" / "version.go"
GO_MOD = Path("go.mod")

# Constants the monitor needs, each defined as one string literal.
_STRING_CONSTANTS = (
    "AWGGoModulePath",
    "PinnedAWGGoVersion",
    "PinnedAWGToolsVersion",
    "DefaultDockerRepo",
    "PinnedAWGImageRevision",
)

# The base image is composed from these operands in this order, so this reader
# can compute the shipped image instead of requiring a literal that would drift.
_BASE_IMAGE_CONSTANT = "PinnedAWGBaseImage"
_BASE_IMAGE_OPERANDS = [
    "DefaultDockerRepo",
    '":"',
    "PinnedAWGGoVersion",
    '"-"',
    "PinnedAWGImageRevision",
]

# A trailing Go line comment after the value is not part of it.
_TRAILING_COMMENT = re.compile(r"\s+//.*$")


class PinReadError(RuntimeError):
    """A pinned value could not be read from the shared definition."""


def _constant_expression(source: str, name: str) -> str:
    """Return the right-hand side of the single ``name = ...`` declaration."""
    matches = re.findall(rf"^\s*{re.escape(name)}\s*=\s*(.+?)\s*$", source, re.MULTILINE)
    if not matches:
        raise PinReadError(f"{VERSION_SOURCE.as_posix()}: no constant named {name}")
    if len(matches) > 1:
        raise PinReadError(
            f"{VERSION_SOURCE.as_posix()}: {name} is declared {len(matches)} times; "
            "the monitor needs exactly one definition"
        )
    return _TRAILING_COMMENT.sub("", matches[0])


def _string_constant(source: str, name: str) -> str:
    """Return the value of a constant declared as one non-empty string literal."""
    expression = _constant_expression(source, name)
    match = re.fullmatch(r'"([^"]+)"', expression)
    if not match:
        raise PinReadError(
            f"{VERSION_SOURCE.as_posix()}: {name} must be a single non-empty string "
            f"literal, got {expression!r}"
        )
    return match.group(1)


def _check_base_image_composition(source: str) -> None:
    """Require the base image to be composed the way this reader computes it."""
    expression = _constant_expression(source, _BASE_IMAGE_CONSTANT)
    operands = [operand.strip() for operand in expression.split("+")]
    if operands != _BASE_IMAGE_OPERANDS:
        raise PinReadError(
            f"{VERSION_SOURCE.as_posix()}: {_BASE_IMAGE_CONSTANT} is composed as "
            f"{' + '.join(operands)!r}, not {' + '.join(_BASE_IMAGE_OPERANDS)!r}; "
            "update the reader together with the composition"
        )


def _go_mod_required_version(root: Path, module_path: str) -> str:
    """Return the version go.mod requires for ``module_path``."""
    path = root / GO_MOD
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PinReadError(f"cannot read {GO_MOD.as_posix()}: {exc}") from exc
    match = re.search(rf"^\s*{re.escape(module_path)}\s+(\S+)", text, re.MULTILINE)
    if not match:
        raise PinReadError(f"{GO_MOD.as_posix()} does not require {module_path}")
    return match.group(1)


def read_pins(root: Path | str = Path(".")) -> dict[str, object]:
    """Return the pinned identities the build ships, read from their definition.

    Raises :class:`PinReadError` for any missing or unparseable input; it never
    substitutes a default.
    """
    root = Path(root)
    source_path = root / VERSION_SOURCE
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PinReadError(f"cannot read {VERSION_SOURCE.as_posix()}: {exc}") from exc

    values = {name: _string_constant(source, name) for name in _STRING_CONSTANTS}
    _check_base_image_composition(source)

    module_path = str(values["AWGGoModulePath"])
    go_version = str(values["PinnedAWGGoVersion"])
    image_revision = str(values["PinnedAWGImageRevision"])
    docker_repo = str(values["DefaultDockerRepo"])
    go_mod_version = _go_mod_required_version(root, module_path)

    return {
        "module_path": module_path,
        "go_version": go_version,
        "tools_version": values["PinnedAWGToolsVersion"],
        "docker_repo": docker_repo,
        "image_revision": image_revision,
        "base_image": f"{docker_repo}:{go_version}-{image_revision}",
        "base_tag": f"{go_version}-{image_revision}",
        "go_mod_version": go_mod_version,
        "go_mod_drift": go_mod_version != go_version,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read the pinned upstream component identities from their single definition."
    )
    parser.add_argument("--root", default=".", help="repository root (default: working directory)")
    args = parser.parse_args(argv)

    try:
        pins = read_pins(Path(args.root))
    except PinReadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    json.dump(pins, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
