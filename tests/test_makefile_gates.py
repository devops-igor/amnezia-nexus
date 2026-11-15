"""Guards for the Makefile verification targets.

`make check` is what a contributor runs before review, so its targets have to be
able to fail. Two defects made that untrue:

* `fmt-check` read only gofmt's stdout, so a file with invalid syntax produced no
  output and the target exited 0.
* `govulncheck` was prefixed with `-`, so make ignored its exit status entirely.

These tests run the real recipes. They need `make` and `git`, both present on the
CI runner; the formatting cases build a throwaway repository so nothing here
touches this checkout.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = REPO_ROOT / "Makefile"

pytestmark = pytest.mark.skipif(
    shutil.which("make") is None or shutil.which("git") is None,
    reason="make and git are required to exercise the Makefile recipes",
)

CLEAN = "package x\n\nfunc Good() {}\n"
UNFORMATTED = "package x\nfunc Bad(){\n}\n"
MALFORMED = "package x\n\nfunc {\n"


def _fmt_check(tmp_path: Path, source: str) -> subprocess.CompletedProcess:
    """Run `make fmt-check` in a throwaway git repository containing one file."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "x.go").write_text(source, encoding="utf-8")
    subprocess.run(["git", "add", "x.go"], cwd=tmp_path, check=True)
    return subprocess.run(
        ["make", "-f", str(MAKEFILE), "fmt-check"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_formatted_file_passes(tmp_path: Path) -> None:
    result = _fmt_check(tmp_path, CLEAN)

    assert result.returncode == 0, result.stdout + result.stderr


def test_unformatted_file_fails(tmp_path: Path) -> None:
    result = _fmt_check(tmp_path, UNFORMATTED)

    assert result.returncode != 0, "a file needing gofmt must fail the gate"
    assert "gofmt required" in result.stdout + result.stderr


def test_malformed_source_fails(tmp_path: Path) -> None:
    """The regression: gofmt reports this on stderr and exits non-zero.

    Reading only stdout made an unparseable file look like a clean tree.
    """
    result = _fmt_check(tmp_path, MALFORMED)

    assert result.returncode != 0, "invalid Go syntax must fail the gate"
    combined = result.stdout + result.stderr
    assert "gofmt failed" in combined or "expected" in combined


# ── Static guards on the recipes themselves ─────────────────────────


def _recipe(target: str) -> list[str]:
    lines = MAKEFILE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{target}:"))
    recipe = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return recipe


def test_govulncheck_cannot_ignore_its_exit_status() -> None:
    """A leading `-` makes make ignore the command's failure."""
    recipe = _recipe("govulncheck")

    assert recipe, "govulncheck has no recipe"
    assert not recipe[0].lstrip().startswith("-"), (
        "govulncheck is prefixed with '-', so make ignores vulnerabilities"
    )


def test_check_verifies_formatting_without_rewriting_the_tree() -> None:
    """`check` must not depend on `fmt`, which modifies files."""
    line = next(l for l in MAKEFILE.read_text(encoding="utf-8").splitlines() if l.startswith("check:"))

    dependencies = line.split(":", 1)[1].split()
    assert "fmt-check" in dependencies
    assert "fmt" not in dependencies, "a verification target must not reformat the tree it checks"
