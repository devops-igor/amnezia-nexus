"""Repository discovery, git inspection, line counting, and Go AST function analysis."""

import datetime
import logging
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple, Union

from scripts.architecture_health.constants import (
    CHURN_LONG_DAYS,
    CHURN_SHORT_DAYS,
    is_generated_or_vendor,
)

logger = logging.getLogger("architecture_health")


def find_repo_root(custom_root: Optional[Union[str, Path]] = None) -> Path:
    """Find repository root using git rev-parse or fallback to current directory."""
    if custom_root:
        return Path(custom_root).resolve()
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        return Path(out).resolve() if out else Path.cwd().resolve()
    except Exception:
        return Path.cwd().resolve()


def get_tracked_files(repo_root: Path) -> List[str]:
    """Enumerate repository tracked files strictly using git ls-files."""
    try:
        res = subprocess.run(
            ["git", "-c", "core.quotePath=false", "ls-files"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to enumerate tracked files: {exc.stderr}") from exc
    return sorted(Path(line.strip()).as_posix() for line in res.stdout.splitlines() if line.strip())


def detect_renames(repo_root: Path, baseline_commit: Optional[str] = None) -> Dict[str, str]:
    """Detect file renames via git diff -M -B between baseline commit (or HEAD) and working tree."""
    ref = baseline_commit or "HEAD"
    cmd = ["git", "-c", "core.quotePath=false", "diff", "-M", "-B", "--name-status", ref]
    try:
        res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=True)
    except Exception as exc:
        logger.debug("Failed git diff -M -B for ref %s: %s", ref, exc)
        return {}

    renames: Dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 3 and (parts[0].startswith("R") or parts[0].startswith("C")):
            old_path = Path(parts[1].strip()).as_posix()
            new_path = Path(parts[2].strip()).as_posix()
            renames[new_path] = old_path
    return renames


def count_file_lines_and_bytes(file_path: Path) -> Optional[Tuple[int, int]]:
    """Count physical newlines and byte size of a file, returning None if binary."""
    try:
        with open(file_path, "rb") as f:
            content = f.read()
    except Exception:
        return None
    if b"\x00" in content:
        return None
    line_count = content.count(b"\n") + (1 if content and not content.endswith(b"\n") else 0)
    return line_count, len(content)


def classify_component(rel_path: str) -> str:
    """Classify a relative path into an architectural component."""
    norm = rel_path.replace("\\", "/")
    if is_generated_or_vendor(norm):
        return "Generated & Vendor"
    fn = os.path.basename(norm)
    if (
        norm.startswith("tests/")
        or fn.startswith("test_")
        or norm.endswith(("_test.go", "_test.py"))
    ):
        return "Test Suites"
    if norm.startswith("internal/vpn/forwarder/"):
        return "Packet Forwarder"
    if norm.startswith("internal/vpn/"):
        return "Go Core VPN"
    if norm.startswith("web/templates/") and norm.endswith(".html"):
        return "Web Templates"
    if norm.startswith("web/static/css/") and norm.endswith(".css"):
        return "CSS Styles"
    if norm.startswith("cmd/"):
        return "Go Production (CLI & Entrypoints)"
    if norm.startswith("internal/service/"):
        return "Go Production (Services)"
    if norm.startswith("internal/manager/"):
        return "Go Production (WireGuard Manager)"
    if norm.startswith(("internal/handlers/", "internal/router/")):
        return "Go Production (Handlers & Router)"
    infra_prefixes = (
        "internal/database/",
        "internal/config/",
        "internal/models/",
        "internal/security/",
        "internal/middleware/",
        "internal/captcha/",
    )
    if any(norm.startswith(p) for p in infra_prefixes):
        return "Go Production (Database & Infra)"
    if norm.startswith("web/static/js/"):
        return "Frontend JavaScript"
    if norm.startswith("web/translations/"):
        return "Translations"
    if norm.startswith("scripts/"):
        return "Scripts & Tooling"
    if norm.startswith("docs/") and norm.endswith(".md"):
        return "Documentation"
    return "Other"


def get_commit_metadata(repo_root: Path, commit_ref: str = "HEAD") -> Tuple[str, str, int]:
    """Retrieve full commit SHA, UTC ISO timestamp, and epoch seconds for a ref."""
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", commit_ref], cwd=repo_root, text=True, stderr=subprocess.PIPE
        ).strip()
        epoch_str = subprocess.check_output(
            ["git", "show", "-s", "--format=%ct", sha],
            cwd=repo_root,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Failed to retrieve commit metadata for ref {commit_ref}: {exc.stderr}"
        ) from exc

    epoch = int(epoch_str)
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return sha, dt.strftime("%Y-%m-%dT%H:%M:%SZ"), epoch


def compute_git_churn(
    repo_root: Path,
    baseline_commit: str,
    reference_epoch: int,
    days_short: int = CHURN_SHORT_DAYS,
    days_long: int = CHURN_LONG_DAYS,
) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Calculate deterministic churn frequency reachable from baseline commit B."""
    churn_short: Dict[str, int] = {}
    churn_long: Dict[str, int] = {}

    since_short = reference_epoch - (days_short * 86400)
    since_long = reference_epoch - (days_long * 86400)
    until = reference_epoch

    cmd = [
        "git",
        "log",
        f"--since={since_long}",
        f"--until={until}",
        "--name-only",
        "--format=COMMIT:%H:%ct",
        baseline_commit,
    ]

    try:
        res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Git history unavailable for baseline commit {baseline_commit}: {exc.stderr.strip()}"
        ) from exc

    current_commit_epoch: Optional[int] = None
    current_files: List[str] = []

    def flush_commit(epoch: Optional[int], touched_files: List[str]) -> None:
        if epoch is None or not touched_files:
            return
        in_short = since_short <= epoch <= until
        in_long = since_long <= epoch <= until
        for rel_f in set(touched_files):
            norm_f = Path(rel_f).as_posix()
            if in_short:
                churn_short[norm_f] = churn_short.get(norm_f, 0) + 1
            if in_long:
                churn_long[norm_f] = churn_long.get(norm_f, 0) + 1

    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT:"):
            flush_commit(current_commit_epoch, current_files)
            current_files = []
            parts = line.split(":")
            if len(parts) >= 3:
                try:
                    current_commit_epoch = int(parts[2])
                except ValueError:
                    current_commit_epoch = None
            else:
                current_commit_epoch = None
        else:
            current_files.append(line)

    flush_commit(current_commit_epoch, current_files)
    return churn_short, churn_long


def analyze_go_functions(repo_root: Path, tracked_go_files: List[str]) -> List[Dict[str, Any]]:
    """Scan tracked Go source files and identify function/method declarations and line sizes."""
    func_decl_re = re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([A-Za-z0-9_]+)")
    functions: List[Dict[str, Any]] = []

    for rel_path in tracked_go_files:
        if not rel_path.endswith(".go") or is_generated_or_vendor(rel_path):
            continue
        abs_path = repo_root / rel_path
        try:
            content = abs_path.read_text(encoding="utf-8")
        except Exception:
            continue
        if "func " not in content:
            continue

        lines = content.splitlines()
        in_raw_string = False
        in_block_comment = False
        brace_depth = 0
        current_func: Optional[Dict[str, Any]] = None

        for idx, line in enumerate(lines):
            line_num = idx + 1
            stripped = line.strip()

            if brace_depth == 0 and not in_raw_string and not in_block_comment:
                m = func_decl_re.match(line)
                if m:
                    current_func = {
                        "file": rel_path,
                        "name": m.group(1),
                        "signature": stripped.split("{")[0].strip(),
                        "start_line": line_num,
                    }

            char_idx = 0
            line_len = len(line)
            while char_idx < line_len:
                ch = line[char_idx]
                if in_raw_string:
                    if ch == "`":
                        in_raw_string = False
                    char_idx += 1
                    continue
                if in_block_comment:
                    if ch == "*" and char_idx + 1 < line_len and line[char_idx + 1] == "/":
                        in_block_comment = False
                        char_idx += 2
                    else:
                        char_idx += 1
                    continue

                if ch == '"':
                    char_idx += 1
                    while char_idx < line_len:
                        if line[char_idx] == "\\":
                            char_idx += 2
                        elif line[char_idx] == '"':
                            char_idx += 1
                            break
                        else:
                            char_idx += 1
                    continue
                elif ch == "'":
                    char_idx += 1
                    while char_idx < line_len:
                        if line[char_idx] == "\\":
                            char_idx += 2
                        elif line[char_idx] == "'":
                            char_idx += 1
                            break
                        else:
                            char_idx += 1
                    continue
                elif ch == "`":
                    in_raw_string = True
                    char_idx += 1
                    continue
                elif ch == "/" and char_idx + 1 < line_len and line[char_idx + 1] == "/":
                    break
                elif ch == "/" and char_idx + 1 < line_len and line[char_idx + 1] == "*":
                    in_block_comment = True
                    char_idx += 2
                    continue
                elif ch == "{":
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
                    if brace_depth == 0 and current_func:
                        current_func["end_line"] = line_num
                        current_func["lines"] = line_num - current_func["start_line"] + 1
                        functions.append(current_func)
                        current_func = None
                char_idx += 1

    functions.sort(key=lambda x: x["lines"], reverse=True)
    return functions
