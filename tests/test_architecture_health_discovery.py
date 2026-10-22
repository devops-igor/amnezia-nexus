"""Unit tests for repository discovery, git inspection, line counting, and Go AST parsing."""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from scripts.architecture_health import (
    BINARY_EXTENSIONS,
    EXCLUDED_DIRS,
    EXCLUDED_FILES,
    analyze_go_functions,
    classify_component,
    compute_git_churn,
    count_file_lines_and_bytes,
    detect_renames,
    find_repo_root,
    get_commit_metadata,
    get_tracked_files,
    is_excluded,
    is_generated_or_vendor,
)


def test_find_repo_root() -> None:
    """Verify repository root discovery returns a valid existing directory."""
    root = find_repo_root()
    assert root.exists()
    assert (root / "go.mod").exists() or (root / "pyproject.toml").exists()

    custom = find_repo_root("/tmp")
    assert custom == Path("/tmp").resolve()


def test_get_tracked_files_real_repo() -> None:
    """Verify git ls-files discovery returns tracked repository files with forward slashes."""
    repo_root = find_repo_root()
    tracked = get_tracked_files(repo_root)

    assert isinstance(tracked, list)
    assert len(tracked) > 50
    assert "go.mod" in tracked
    assert "scripts/generate_captcha_assets.py" in tracked
    for f in tracked:
        assert "\\" not in f
        assert not f.startswith("/")


def test_get_tracked_files_mocked() -> None:
    """Verify git ls-files output parsing handles whitespace and sorts cleanly."""
    mock_stdout = "  internal/vpn/vpn.go \n\n web/templates/vpn.html\r\ncmd/server/main.go\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_stdout, returncode=0)
        files = get_tracked_files(Path("/fake/repo"))
        assert files == [
            "cmd/server/main.go",
            "internal/vpn/vpn.go",
            "web/templates/vpn.html",
        ]


def test_get_tracked_files_failure() -> None:
    """Verify git ls-files failure raises RuntimeError."""
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, ["git"], "err")):
        with pytest.raises(RuntimeError, match="Failed to enumerate tracked files"):
            get_tracked_files(Path("/fake/repo"))


def test_exclusion_filtering_directories() -> None:
    """Verify paths within excluded directories are properly identified."""
    for excluded_dir in EXCLUDED_DIRS:
        sample_path = f"{excluded_dir}/some_module/file.py"
        assert is_excluded(sample_path) is True, f"Failed to exclude {sample_path}"
        nested_path = f"subdir/{excluded_dir}/deep/file.go"
        assert is_excluded(nested_path) is True, f"Failed to exclude {nested_path}"


def test_exclusion_filtering_files() -> None:
    """Verify exact excluded files are rejected while non-excluded files pass."""
    for excluded_file in EXCLUDED_FILES:
        assert is_excluded(excluded_file) is True
        assert is_excluded(f"nested/{excluded_file}") is True

    assert is_excluded("internal/vpn/vpn.go") is False
    assert is_excluded("web/static/js/vpn/page.js") is False
    assert is_excluded("web/templates/vpn.html") is False
    assert is_excluded("scripts/architecture_health.py") is False


def test_exclusion_filtering_binary_extensions() -> None:
    """Verify binary file extensions are excluded from line count evaluation."""
    for ext in BINARY_EXTENSIONS:
        sample_path = f"web/static/assets/image{ext}"
        assert is_excluded(sample_path) is True, f"Failed to exclude binary extension {ext}"


def test_is_generated_or_vendor() -> None:
    """Verify generated bundle, vendor asset, and test fixture detection."""
    assert is_generated_or_vendor("web/static/js/qrcode.min.js") is True
    assert is_generated_or_vendor("web/static/css/style.css") is True
    assert is_generated_or_vendor("tests/e2e/fixtures/style.pre-505.css") is True
    assert is_generated_or_vendor("web/static/js/vendor.min.js") is True
    assert is_generated_or_vendor("web/static/css/bundle.min.css") is True
    assert is_generated_or_vendor("tests/e2e/fixtures/data.json") is True
    assert is_generated_or_vendor("fixtures/sample.txt") is True

    assert is_generated_or_vendor("internal/vpn/vpn.go") is False
    assert is_generated_or_vendor("web/static/js/app.js") is False
    assert is_generated_or_vendor("web/templates/index.html") is False


def test_count_file_lines_and_bytes(tmp_path: Path) -> None:
    """Verify line counting and binary zero-byte detection."""
    f = tmp_path / "sample.txt"
    f.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")
    counts = count_file_lines_and_bytes(f)
    assert counts is not None
    lines, byte_size = counts
    assert lines == 3
    assert byte_size == len("line 1\nline 2\nline 3\n".encode("utf-8"))

    # File without trailing newline
    f_no_newline = tmp_path / "no_newline.txt"
    f_no_newline.write_text("a\nb", encoding="utf-8")
    assert count_file_lines_and_bytes(f_no_newline) == (2, 3)

    # Empty file
    f_empty = tmp_path / "empty.txt"
    f_empty.write_text("", encoding="utf-8")
    assert count_file_lines_and_bytes(f_empty) == (0, 0)

    # Binary file containing null byte
    f_bin = tmp_path / "binary.bin"
    f_bin.write_bytes(b"\x00\x01\x02\n\x00")
    assert count_file_lines_and_bytes(f_bin) is None


def test_classify_component() -> None:
    """Verify component classification rules across architectural boundaries."""
    assert classify_component("web/static/js/qrcode.min.js") == "Generated & Vendor"
    assert classify_component("tests/unit/vpn_test.go") == "Test Suites"
    assert classify_component("internal/vpn/vpn_test.go") == "Test Suites"
    assert classify_component("internal/vpn/forwarder/packet.go") == "Packet Forwarder"
    assert classify_component("internal/vpn/vpn.go") == "Go Core VPN"
    assert classify_component("web/templates/vpn.html") == "Web Templates"
    assert classify_component("web/static/css/admin.css") == "CSS Styles"
    assert classify_component("cmd/server/main.go") == "Go Production (CLI & Entrypoints)"
    assert classify_component("internal/service/auth.go") == "Go Production (Services)"
    assert classify_component("internal/manager/awg.go") == "Go Production (WireGuard Manager)"
    assert classify_component("internal/handlers/user.go") == "Go Production (Handlers & Router)"
    assert classify_component("internal/router/router.go") == "Go Production (Handlers & Router)"
    assert classify_component("internal/database/sqlite.go") == "Go Production (Database & Infra)"
    assert classify_component("internal/config/config.go") == "Go Production (Database & Infra)"
    assert classify_component("internal/models/peer.go") == "Go Production (Database & Infra)"
    assert classify_component("internal/security/token.go") == "Go Production (Database & Infra)"
    assert classify_component("internal/middleware/auth.go") == "Go Production (Database & Infra)"
    assert classify_component("internal/captcha/solver.go") == "Go Production (Database & Infra)"
    assert classify_component("web/static/js/dashboard.js") == "Frontend JavaScript"
    assert classify_component("web/translations/ru.json") == "Translations"
    assert classify_component("scripts/build.sh") == "Scripts & Tooling"
    assert classify_component("docs/architecture.md") == "Documentation"
    assert classify_component("unknown/path/file.xyz") == "Other"


def test_get_commit_metadata_real_repo() -> None:
    """Verify commit metadata extraction against real repository HEAD."""
    repo_root = find_repo_root()
    sha, iso_ts, epoch = get_commit_metadata(repo_root, "HEAD")
    assert len(sha) == 40
    assert iso_ts.endswith("Z")
    assert epoch > 1_700_000_000


def test_compute_git_churn_deterministic_boundary() -> None:
    """Verify deterministic churn calculation within short and long windows."""
    ref_epoch = 1_700_000_000
    mock_log = (
        f"COMMIT:sha1:{ref_epoch - 100}\n"
        "internal/vpn/vpn.go\n"
        "cmd/server/main.go\n"
        f"COMMIT:sha2:{ref_epoch - (20 * 86400)}\n"
        "internal/vpn/vpn.go\n"
        f"COMMIT:sha3:{ref_epoch - (45 * 86400)}\n"
        "internal/vpn/vpn.go\n"
        "web/static/js/vpn.js\n"
        f"COMMIT:sha4:{ref_epoch - (100 * 86400)}\n"
        "internal/vpn/vpn.go\n"
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_log, returncode=0)
        churn_30, churn_90 = compute_git_churn(
            Path("/fake/repo"), "baseline_sha", ref_epoch, days_short=30, days_long=90
        )
        assert churn_30["internal/vpn/vpn.go"] == 2
        assert churn_30["cmd/server/main.go"] == 1
        assert "web/static/js/vpn.js" not in churn_30

        assert churn_90["internal/vpn/vpn.go"] == 3
        assert churn_90["cmd/server/main.go"] == 1
        assert churn_90["web/static/js/vpn.js"] == 1


def test_compute_git_churn_unavailable_history_raises() -> None:
    """Verify compute_git_churn raises RuntimeError when git history is unavailable."""
    with patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(128, ["git"], stderr="fatal: shallow clone"),
    ):
        with pytest.raises(RuntimeError, match="Git history unavailable for baseline commit"):
            compute_git_churn(Path("/fake/repo"), "missing_sha", 1_700_000_000)


def test_detect_renames_c_and_r_status() -> None:
    """Verify detect_renames extracts both R (rename) and C (copy/rewrite) statuses."""
    mock_diff = (
        "R100\told_path.go\tnew_path.go\n"
        "C100\tinternal/vpn/vpn.go\tinternal/vpn/vpn_legacy.go\n"
        "M100\tinternal/vpn/vpn.go\n"
        "A\tunrelated.go\n"
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_diff, returncode=0)
        renames = detect_renames(Path("/fake/repo"), "commit_sha")
        assert renames == {
            "new_path.go": "old_path.go",
            "internal/vpn/vpn_legacy.go": "internal/vpn/vpn.go",
        }


def test_analyze_go_functions(tmp_path: Path) -> None:
    """Verify Go AST function parser accurately extracts signatures and line sizes."""
    go_content = (
        "package main\n"
        "\n"
        "// Standalone function\n"
        "func Add(a, b int) int {\n"
        "    // single line comment with { and }\n"
        '    msg := "string with { and }"\n'
        "    raw := `multiline raw string\n"
        "    with { and }\n"
        "    `\n"
        "    _ = raw\n"
        "    _ = msg\n"
        "    return a + b\n"
        "}\n"
        "\n"
        "type Server struct{}\n"
        "\n"
        "// Method with receiver\n"
        "func (s *Server) Handle(req string) (string, error) {\n"
        '    return "ok", nil\n'
        "}\n"
    )
    f = tmp_path / "server.go"
    f.write_text(go_content, encoding="utf-8")

    funcs = analyze_go_functions(tmp_path, ["server.go"])
    assert len(funcs) == 2
    assert funcs[0]["name"] == "Add"
    assert funcs[0]["lines"] == 10
    assert funcs[0]["start_line"] == 4
    assert funcs[0]["end_line"] == 13

    assert funcs[1]["name"] == "Handle"
    assert funcs[1]["lines"] == 3
    assert funcs[1]["start_line"] == 18
    assert funcs[1]["end_line"] == 20
