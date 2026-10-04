"""Privacy regressions for failure-time service evidence using synthetic secrets."""

import io
import os
import re
import subprocess
import textwrap
import runpy
from pathlib import Path

import pytest

from scripts import sanitize_e2e_service_logs as logs


@pytest.mark.parametrize(
    "value",
    [
        "198.51.100.17:51820",
        "[2001:db8::17]:51820",
        "2001:db8:abcd:1::17%eth0",
        "vpn.example.test:51820",
        "client@example.test",
        "https://synthetic-user:synthetic-pass@vpn.example.test/private?token=synthetic-token",
        "postgres://synthetic-user:synthetic-pass@db.example.test/panel",
        "/synthetic-workspace/panel/private.conf",
        '"/synthetic workspace/private file.conf"',
        r"C:\synthetic-workspace\private.conf",
        "a" * 43 + "=",
        "a" * 64,
        "-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n-----END PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-unfinished-key",
        'password="synthetic secret with spaces"',
        '"private_key": "synthetic-private-key"',
        "peer_key=synthetic-peer-key",
        "preshared_key=synthetic-preshared-key",
        "Authorization: Bearer synthetic-bearer-token",
        "Cookie: synthetic-session-cookie",
    ],
    ids=[
        "ipv4",
        "ipv6",
        "ipv6-zone",
        "dns",
        "email",
        "url-userinfo",
        "database-url",
        "linux-path",
        "quoted-path",
        "windows-path",
        "base64-key",
        "hex-key",
        "private-key-pem",
        "unfinished-key-pem",
        "password",
        "json-key",
        "peer-key",
        "preshared-key",
        "authorization",
        "cookie",
    ],
)
def test_sensitive_evidence_is_redacted(value: str) -> None:
    """Sensitive diagnostic substrings never survive into the output artifact."""
    output = logs.sanitize_text(f"failed to enable backend 7: {value}\n", {})
    assert value not in output
    assert "failed to enable backend 7:" in output
    assert "<redacted-" in output
    for secret in ("synthetic-key-material", "synthetic-unfinished-key", "synthetic-bearer-token"):
        assert secret not in output


def test_environment_secret_values_are_removed_without_field_names() -> None:
    """Secrets from the CI environment cannot leak through free-form wrapped errors."""
    env = {
        "E2E_ADMIN_PASS": "synthetic-admin-secret",
        "E2E_SERVER_SSH_KEY": "synthetic-secret-key",
        "DEPLOY_TOKEN": "synthetic-deploy-token",
        "E2E_SERVER_HOST": "synthetic-host",
    }
    output = logs.sanitize_text("failed: " + " ".join(env.values()), env)
    assert all(value not in output for value in env.values())


def test_error_context_survives() -> None:
    """Keep service cause and backend identity useful without disclosing its endpoint."""
    output = logs.sanitize_text(
        "[vpn/handlers] failed to enable backend 7: register_probe_peer: "
        "add client: dial tcp 198.51.100.17:22: connection refused\n",
        {},
    )
    assert "backend 7" in output
    assert "register_probe_peer" in output
    assert "connection refused" in output
    assert "198.51.100.17" not in output


def test_log_filter_removes_controls_and_workflow_annotations() -> None:
    """Raw evidence cannot inject terminal controls or GitHub workflow annotations."""
    output = logs.sanitize_text("\x1b[31m::error::synthetic failure\x1b[0m\x00\n", {})
    assert "\x1b" not in output
    assert "\x00" not in output
    assert "::error::" not in output
    assert "synthetic failure" in output


def test_filter_cli_sanitizes_before_emission(monkeypatch: pytest.MonkeyPatch) -> None:
    """The executable filter emits only sanitized stdin, even when it truncates input."""
    monkeypatch.setattr(logs, "MAX_INPUT_CHARS", 100)
    monkeypatch.setattr(logs.sys, "stdin", io.StringIO("password=synthetic-secret\n" + "x" * 200))
    output = io.StringIO()
    monkeypatch.setattr(logs.sys, "stdout", output)
    assert logs.main() == 0
    assert "synthetic-secret" not in output.getvalue()
    assert "[service evidence truncated]" in output.getvalue()


def test_failure_evidence_precedes_cleanup_in_workflow() -> None:
    """All failure streams are filtered and uploaded before the always-run teardown."""
    workflow = Path(".github/workflows/e2e-dev.yml").read_text()
    capture = workflow.index("- name: Capture Sanitized Panel Failure Evidence")
    upload = workflow.index("- name: Upload Sanitized Panel Failure Evidence")
    cleanup = workflow.index("- name: Post-Test Teardown, Docker Prune")
    assert capture < upload < cleanup
    block = workflow[capture:upload]
    assert "if: failure()" in block
    assert "2>&1 | python3 scripts/sanitize_e2e_service_logs.py" in block
    assert "docker logs --timestamps --tail 1000 amnezia-panel" in block
    assert "if: always()" in workflow[cleanup:]


def test_qualification_evidence_is_uploaded_before_final_cleanup() -> None:
    """Later qualification failures keep their existing always-run public evidence upload."""
    workflow = Path(".github/workflows/e2e-dev.yml").read_text()
    upload = workflow.index("- name: Upload Qualification Evidence Artifacts")
    cleanup = workflow.index("- name: Post-Test Teardown, Docker Prune")
    block = workflow[upload:cleanup]
    assert upload < cleanup
    assert "if: always() && steps.qual-mode.outputs.mode != 'standard'" in block
    assert "path: test-artifacts/public/" in block


def test_short_environment_credentials_are_not_exempted() -> None:
    """Credential redaction also applies to short values and SSH account names."""
    output = logs.sanitize_text(
        "password: xy account synthetic-user",
        {"E2E_ADMIN_PASS": "xy", "E2E_SERVER_SSH_USER": "synthetic-user"},
    )
    assert "xy" not in output
    assert "synthetic-user" not in output


@pytest.mark.parametrize("prefix", ["", "safe completed line\n"])
def test_truncated_split_secret_is_discarded(monkeypatch: pytest.MonkeyPatch, prefix: str) -> None:
    """Truncation cannot emit the unmatched prefix of a secret on the final line."""
    secret = "synthetic-secret-without-field-name"
    monkeypatch.setenv("E2E_ADMIN_PASS", secret)
    monkeypatch.setattr(logs, "MAX_INPUT_CHARS", len(prefix) + 15)
    monkeypatch.setattr(logs.sys, "stdin", io.StringIO(prefix + secret))
    output = io.StringIO()
    monkeypatch.setattr(logs.sys, "stdout", output)
    assert logs.main() == 0
    assert secret[:15] not in output.getvalue()
    assert prefix in output.getvalue()
    assert "[service evidence truncated]" in output.getvalue()


class BrokenEvidenceInput:
    """Simulate a failed stdin stream without emitting its sensitive exception text."""

    def read(self, size: int) -> str:
        """Raise a synthetic transport failure containing a value that must stay private."""
        raise OSError("synthetic-raw-stream-secret")


def test_cli_input_failure_emits_only_safe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even a failed filter never echoes its raw input error or writes unsanitized evidence."""
    output = io.StringIO()
    errors = io.StringIO()
    monkeypatch.setattr(logs.sys, "stdin", BrokenEvidenceInput())
    monkeypatch.setattr(logs.sys, "stdout", output)
    monkeypatch.setattr(logs.sys, "stderr", errors)
    with pytest.raises(SystemExit) as failure:
        runpy.run_path("scripts/sanitize_e2e_service_logs.py", run_name="__main__")
    assert failure.value.code == 1
    assert output.getvalue() == ""
    assert "raw evidence suppressed" in errors.getvalue()
    assert "synthetic-raw-stream-secret" not in errors.getvalue()


def clean_slate_deployment_shell() -> str:
    """Extract the actual deployment step and substitute only the GitHub expression."""
    workflow = Path(".github/workflows/e2e-dev.yml").read_text()
    step = workflow.split("      - name: Clean-Slate Deployment\n", 1)[1]
    step = step.split("\n      - name:", 1)[0]
    shell = textwrap.dedent(step.split("        run: |\n", 1)[1])
    return re.sub(r"\$\{\{.*?\}\}", "fixture-pr", shell)


def run_readiness_failure(
    tmp_path: Path, shell: str, broken_filter: bool = False
) -> subprocess.CompletedProcess[str]:
    """Execute the real shell step in a synthetic home with every operational tool stubbed."""
    checkout = tmp_path / "synthetic checkout with spaces"
    home = tmp_path / "synthetic home"
    checkout.mkdir()
    home.mkdir()
    scripts = checkout / "scripts"
    scripts.mkdir()
    sanitizer = scripts / "sanitize_e2e_service_logs.py"
    if broken_filter:
        sanitizer.write_text(
            "import sys\n"
            "sys.stdin.read()\n"
            "sys.stderr.write('Service evidence sanitization failed; raw evidence suppressed.' + chr(10))\n"
            "raise SystemExit(2)\n"
        )
    else:
        sanitizer.write_text(Path("scripts/sanitize_e2e_service_logs.py").read_text())
    trace = tmp_path / "compose-trace"
    env = {
        **os.environ,
        "HOME": str(home),
        "GITHUB_WORKSPACE": str(checkout),
        "BATCH7_STUB_TRACE": str(trace),
        "E2E_ADMIN_PASS": "synthetic-startup-secret",
        "SYNTHETIC_LOG_STDOUT": (
            "startup failed: password=synthetic-startup-secret "
            "peer_key=" + "a" * 43 + "= address=198.51.100.17"
        ),
        "SYNTHETIC_LOG_STDERR": (
            'probe failed: connection refused token=synthetic-startup-token config="'
            + str(checkout / "private.conf")
            + '"'
        ),
    }
    stubs = """
        docker() {
          case "$1" in
            rm) return 0 ;;
            compose)
              [ "$PWD" = "$HOME" ] || return 99
              printf '%s\n' 'compose-home' >> "$BATCH7_STUB_TRACE"
              ;;
            logs)
              printf '%s\n' "$SYNTHETIC_LOG_STDOUT"
              printf '%s\n' "$SYNTHETIC_LOG_STDERR" >&2
              ;;
            *) return 99 ;;
          esac
        }
        sudo() { return 0; }
        curl() { return 1; }
        sleep() { return 0; }
        sed() { return 0; }
    """
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", stubs + shell],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert trace.read_text().splitlines() == ["compose-home", "compose-home"]
    return result


def assert_readiness_failure_safe(result: subprocess.CompletedProcess[str]) -> None:
    """Require safe useful evidence from both producer streams while retaining failure."""
    output = result.stdout + result.stderr
    failure_preserved = result.returncode != 0
    assert failure_preserved, "Readiness timeout must remain unsuccessful"
    causes_present = "startup failed:" in output and "probe failed: connection refused" in output
    assert causes_present, "Sanitized startup cause missing from producer stdout or stderr"
    secrets_absent = all(
        value not in output
        for value in (
            "synthetic-startup-secret",
            "synthetic-startup-token",
            "a" * 43 + "=",
            "198.51.100.17",
            "private.conf",
            "synthetic checkout with spaces",
            "synthetic home",
        )
    )
    assert secrets_absent, "Readiness failure disclosed synthetic producer content"
    redaction_present = "<redacted-" in output
    assert redaction_present, "Readiness failure must retain sanitized diagnostic evidence"


def test_readiness_failure_sanitizes_both_streams_from_home(tmp_path: Path) -> None:
    """The actual failed step resolves its checkout filter despite a home cwd and spaces."""
    assert_readiness_failure_safe(run_readiness_failure(tmp_path, clean_slate_deployment_shell()))


def test_readiness_failure_suppresses_raw_output_when_filter_fails(tmp_path: Path) -> None:
    """An unsuccessful filter cannot cause a raw-log fallback or successful deployment."""
    result = run_readiness_failure(tmp_path, clean_slate_deployment_shell(), broken_filter=True)
    output = result.stdout + result.stderr
    failure_preserved = result.returncode != 0
    assert failure_preserved, "Failed sanitization must keep deployment unsuccessful"
    raw_suppressed = (
        "raw evidence suppressed" in output
        and "startup failed:" not in output
        and "probe failed:" not in output
        and "synthetic-startup-secret" not in output
        and "synthetic-startup-token" not in output
        and "a" * 43 + "=" not in output
    )
    assert raw_suppressed, "Failed sanitization must emit only its safe diagnostic"


def test_readiness_failure_regression_rejects_old_relative_filter(tmp_path: Path) -> None:
    """Restoring the reviewed relative operand loses evidence in the executable cwd test."""
    shell = clean_slate_deployment_shell()
    old_shell = shell.replace(
        'python3 "$GITHUB_WORKSPACE/scripts/sanitize_e2e_service_logs.py"',
        "python3 scripts/sanitize_e2e_service_logs.py",
        1,
    )
    mutation_applied = old_shell != shell
    assert mutation_applied, "The old relative-filter mutation must change the actual step"
    result = run_readiness_failure(tmp_path, old_shell)
    with pytest.raises(AssertionError, match="Sanitized startup cause missing"):
        assert_readiness_failure_safe(result)
