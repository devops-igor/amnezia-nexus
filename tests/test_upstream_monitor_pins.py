"""Offline guards for the scheduled upstream monitor's pin reader (issue #271).

The monitor compares upstream release tags with the pins the build ships. Before
this round it scraped three quoted assignments out of
``internal/service/upstream/service.go`` and substituted hard-coded values when
it found none, so once the pins moved to their single definition the job read
nothing: a correct bump stayed invisible and an already-adopted tag could still
be reported as new.

These tests drive the reader the workflow runs
(``scripts/upstream_monitor_pins.py``) and the pin-loader block the workflow step
executes, both offline and without ``gh`` or network access.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
READER = REPO_ROOT / "scripts" / "upstream_monitor_pins.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "upstream-monitor.yml"

# A tree in the shape the repository ships: the module path, the pinned
# versions, the image repository and revision as literals, and the base image
# derived from them.
_VERSION_GO = '''package version

const (
\tAWGGoModulePath = "github.com/amnezia-vpn/amneziawg-go/v3"

\tPinnedAWGGoVersion = "{go_version}"

\tPinnedAWGToolsVersion = "{tools_version}"

\tDefaultDockerRepo = "devopsigor/amneziawg"

\tPinnedAWGImageRevision = "{revision}"

{PinnedAWGBaseImage}
)
'''

_DERIVED_IMAGE = (
    'PinnedAWGBaseImage = DefaultDockerRepo + ":" + PinnedAWGGoVersion'
    ' + "-" + PinnedAWGImageRevision'
)

_GO_MOD = """module example.com/panel

go 1.26.0

require (
\tgithub.com/amnezia-vpn/amneziawg-go/v3 {version}
)
"""


def _load_reader():
    spec = importlib.util.spec_from_file_location("upstream_monitor_pins", READER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_tree(
    root: Path,
    *,
    go_version: str = "v9.9.20270101",
    tools_version: str = "v9.9.20261215",
    revision: str = "7",
    go_mod_version: str | None = None,
    include_source: bool = True,
) -> Path:
    """Write a fixture tree; the defaults are a consistent module+image bump."""
    (root / "internal" / "version").mkdir(parents=True, exist_ok=True)
    (root / "go.mod").write_text(
        _GO_MOD.format(version=go_mod_version or go_version), encoding="utf-8"
    )
    if include_source:
        (root / "internal" / "version" / "version.go").write_text(
            _VERSION_GO.format(
                go_version=go_version,
                tools_version=tools_version,
                revision=revision,
                PinnedAWGBaseImage=_DERIVED_IMAGE,
            ),
            encoding="utf-8",
        )
    return root


def _run_reader(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(READER), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def _pin_loader_source() -> str:
    """The pin-loading block of the monitor step, dedented, as the job runs it."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("# -- pin loader begin --")
    end = text.index("# -- pin loader end --")
    return "\n".join(
        line[10:] if line.startswith(" " * 10) else line for line in text[start:end].splitlines()
    )


def _run_pin_loader(
    pins_path: Path, monkeypatch: pytest.MonkeyPatch, namespace: dict | None = None
) -> dict:
    monkeypatch.setenv("PINS_FILE", str(pins_path))
    target = namespace if namespace is not None else {"json": json, "os": os, "sys": sys}
    exec(compile(_pin_loader_source(), "<pin-loader>", "exec"), target)  # noqa: S102
    return target


# -- the reader -------------------------------------------------------------------


def test_a_consistent_module_and_image_bump_is_read_as_bumped(tmp_path: Path) -> None:
    """The whole point: a later bump must reach every value the job compares."""
    root = _write_tree(tmp_path)

    result = _run_reader(root)

    assert result.returncode == 0, result.stderr
    pins = json.loads(result.stdout)
    assert pins["go_version"] == "v9.9.20270101"
    assert pins["tools_version"] == "v9.9.20261215"
    assert pins["image_revision"] == "7"
    assert pins["docker_repo"] == "devopsigor/amneziawg"
    assert pins["base_image"] == "devopsigor/amneziawg:v9.9.20270101-7"
    assert pins["base_tag"] == "v9.9.20270101-7"
    assert pins["go_mod_drift"] is False

    # The values come from the fixture tree, not from anything baked into the
    # reader: they differ from the pins this repository currently ships.
    shipped = _load_reader().read_pins(REPO_ROOT)
    assert pins["base_image"] != shipped["base_image"]
    assert pins["go_version"] != shipped["go_version"]


def test_the_shipped_definition_is_read_as_its_computed_image() -> None:
    pins = _load_reader().read_pins(REPO_ROOT)

    assert pins["base_image"] == (
        f"{pins['docker_repo']}:{pins['go_version']}-{pins['image_revision']}"
    )
    assert pins["base_tag"] == f"{pins['go_version']}-{pins['image_revision']}"
    assert pins["go_mod_drift"] is False


def test_go_mod_drift_is_reported_rather_than_used_as_the_pin(tmp_path: Path) -> None:
    root = _write_tree(tmp_path, go_mod_version="v9.9.20270202")

    pins = _load_reader().read_pins(root)

    assert pins["go_version"] == "v9.9.20270101"
    assert pins["go_mod_version"] == "v9.9.20270202"
    assert pins["go_mod_drift"] is True


def test_a_missing_definition_fails_without_emitting_any_pin(tmp_path: Path) -> None:
    """No definition means no comparison baseline, so the run must not continue."""
    root = _write_tree(tmp_path, include_source=False)

    result = _run_reader(root)

    assert result.returncode != 0
    assert result.stdout.strip() == "", "a failed read must not print pins to fall back on"
    assert "internal/version/version.go" in result.stderr


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        # The pinned version is no longer a literal, so nothing can be resolved.
        ('PinnedAWGGoVersion = "v9.9.20270101"', "PinnedAWGGoVersion = otherVersion"),
        # The image is composed differently from the way this reader computes it.
        (_DERIVED_IMAGE, 'PinnedAWGBaseImage = DefaultDockerRepo + ":" + PinnedAWGToolsVersion'),
        # The derived image is missing altogether.
        (_DERIVED_IMAGE, ""),
        # The image repository the monitor compares against is missing.
        ('DefaultDockerRepo = "devopsigor/amneziawg"', ""),
        # The tools pin the monitor compares against is missing.
        ('PinnedAWGToolsVersion = "v9.9.20261215"', ""),
    ],
)
def test_an_unparseable_definition_fails_without_emitting_any_pin(
    tmp_path: Path, original: str, replacement: str
) -> None:
    root = _write_tree(tmp_path)
    source_path = root / "internal" / "version" / "version.go"
    source = source_path.read_text(encoding="utf-8")
    assert original in source
    source_path.write_text(source.replace(original, replacement), encoding="utf-8")

    result = _run_reader(root)

    assert result.returncode != 0
    assert result.stdout.strip() == "", "an unparseable definition must not yield pins"


# -- the workflow -----------------------------------------------------------------


def test_the_monitor_reads_pins_from_the_shared_source() -> None:
    """The job's wiring, not merely the reader's existence."""
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "scripts/upstream_monitor_pins.py" in text
    assert "PINS_FILE" in text
    # Nothing scraped inline out of Go source, and no old file named as the home
    # of the pins: the file values are the only source the job compares against.
    scrapes = (
        r"PinnedAWGGoVersion\s*=",
        r"PinnedAWGToolsVersion\s*=",
        r"PinnedAWGBaseImage\s*=",
    )
    for scrape in scrapes:
        assert scrape not in text, f"the monitor must not scrape {scrape} out of Go source"
    assert "internal/service/upstream/service.go" not in text
    # The instructions an alert carries must name the file that holds the pins.
    assert "internal/version/version.go" in text


def test_the_monitor_step_loads_every_pin_from_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pins = _load_reader().read_pins(REPO_ROOT)
    pins_path = tmp_path / "upstream-pins.json"
    pins_path.write_text(json.dumps(pins), encoding="utf-8")

    namespace = _run_pin_loader(pins_path, monkeypatch)

    assert namespace["pinned_go"] == pins["go_version"]
    assert namespace["pinned_tools"] == pins["tools_version"]
    assert namespace["pinned_repo"] == pins["docker_repo"]
    assert namespace["pinned_base_image"] == pins["base_image"]
    assert namespace["pinned_base_tag"] == pins["base_tag"]


def test_the_monitor_step_fails_instead_of_defaulting_when_the_file_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _run_pin_loader(tmp_path / "absent.json", monkeypatch)

    assert exit_info.value.code != 0


def test_the_monitor_step_fails_instead_of_defaulting_when_a_pin_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pins = _load_reader().read_pins(REPO_ROOT)
    del pins["docker_repo"]
    pins_path = tmp_path / "upstream-pins.json"
    pins_path.write_text(json.dumps(pins), encoding="utf-8")

    namespace: dict = {"json": json, "os": os, "sys": sys}
    with pytest.raises(SystemExit) as exit_info:
        _run_pin_loader(pins_path, monkeypatch, namespace)

    assert exit_info.value.code != 0
    assert "pinned_repo" not in namespace
