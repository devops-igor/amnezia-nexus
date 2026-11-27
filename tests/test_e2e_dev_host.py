"""Offline tests for the DEV host probes (issue #911).

The failure being fixed: a ``docker run`` that timed out was reported as "cannot
execute on host architecture", and a fixed short timeout turned a stalled host
into a failed gate. These tests drive the real probe code with a stubbed
``subprocess.run`` and prove three things: each outcome is reported as itself,
only a timeout is retried, and nothing that fails can come back as a pass.

No Docker, browser or network is involved.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tests.e2e import dev_host

REPO_ROOT = Path(__file__).resolve().parents[1]
IMAGE = dev_host.PRIMARY_CLIENT_IMAGE
GOOD_STDOUT = "amneziawg-tools v3.1.20260812 - https://amnezia.org\n"


class _Docker:
    """Scripted stand-in for subprocess.run; records every command it is given."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if cmd[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(cmd, *outcome)

    @property
    def runs(self) -> list[list[str]]:
        return [c for c in self.calls if c[:2] == ["docker", "run"]]


def _timeout() -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(cmd="docker run", timeout=dev_host.PROBE_TIMEOUT_SECONDS)


@pytest.fixture
def docker(monkeypatch):
    def install(*outcomes):
        stub = _Docker(*outcomes)
        monkeypatch.setattr(dev_host.subprocess, "run", stub)
        return stub

    return install


# -- classification: each outcome is reported as itself -----------------------------


def test_success_is_ok(docker) -> None:
    stub = docker((0, GOOD_STDOUT, ""))
    result = dev_host.probe_client_image(IMAGE)
    assert result.ok and result.kind == dev_host.OK and result.attempts == 1
    assert len(stub.runs) == 1


def test_exec_format_error_is_reported_as_an_architecture_failure(docker) -> None:
    stub = docker((255, "", "exec /usr/local/bin/awg: exec format error\n"))
    result = dev_host.probe_client_image(IMAGE)
    assert result.kind == dev_host.EXEC_FORMAT_ERROR and not result.ok
    assert "cannot execute on this host architecture" in result.describe()
    assert "exec format error" in result.describe()
    assert len(stub.runs) == 1, "an exec-format error is deterministic and must not be retried"


def test_timeout_is_never_reported_as_an_architecture_mismatch(docker) -> None:
    docker(_timeout(), _timeout())
    result = dev_host.probe_client_image(IMAGE)
    assert result.kind == dev_host.TIMEOUT and not result.ok
    message = result.describe()
    assert "did not finish within" in message and "stalled" in message
    assert "cannot execute on this host architecture" not in message
    assert "exec format" not in message.lower()


def test_nonzero_exit_is_reported_with_its_status_and_is_not_retried(docker) -> None:
    stub = docker((2, "", "awg: unknown option\n"))
    result = dev_host.probe_client_image(IMAGE)
    assert result.kind == dev_host.NONZERO_EXIT and not result.ok
    assert "exited non-zero" in result.describe() and "exit 2" in result.describe()
    assert "architecture" not in result.describe()
    assert len(stub.runs) == 1


def test_success_with_unexpected_output_is_a_failure_not_a_pass(docker) -> None:
    docker((0, "hello\n", ""))
    result = dev_host.probe_client_image(IMAGE)
    assert result.kind == dev_host.UNEXPECTED_OUTPUT and not result.ok


def test_docker_binary_missing_is_reported_as_such(docker) -> None:
    docker(FileNotFoundError("docker"))
    result = dev_host.probe_client_image(IMAGE)
    assert result.kind == dev_host.DOCKER_UNAVAILABLE and not result.ok
    assert "architecture" not in result.describe()


def test_emulation_warning_alone_is_not_an_architecture_failure() -> None:
    """Docker prints a platform-mismatch warning on runs that succeed under emulation."""
    warning = "WARNING: The requested image's platform does not match the detected host platform"
    assert dev_host.classify(0, GOOD_STDOUT, warning) == (dev_host.OK, "")
    kind, _ = dev_host.classify(1, "", warning)
    assert kind == dev_host.NONZERO_EXIT


# -- retry: only a stall, once, and never a path to a pass --------------------------


def test_one_stalled_start_is_retried_and_the_retry_is_recorded(docker) -> None:
    stub = docker(_timeout(), (0, GOOD_STDOUT, ""))
    with pytest.warns(RuntimeWarning, match="timed out after .*retrying once"):
        result = dev_host.probe_client_image(IMAGE)
    assert result.ok and result.attempts == 2
    assert len(stub.runs) == 2


def test_a_timeout_that_repeats_fails_after_a_bounded_number_of_attempts(docker) -> None:
    stub = docker(_timeout(), _timeout(), _timeout())
    with pytest.warns(RuntimeWarning):
        result = dev_host.probe_client_image(IMAGE)
    assert not result.ok and result.kind == dev_host.TIMEOUT
    assert result.attempts == dev_host.PROBE_ATTEMPTS == 2
    assert len(stub.runs) == dev_host.PROBE_ATTEMPTS


def test_a_real_failure_after_a_stall_still_fails(docker) -> None:
    docker(_timeout(), (255, "", "exec format error"))
    with pytest.warns(RuntimeWarning):
        result = dev_host.probe_client_image(IMAGE)
    assert not result.ok and result.kind == dev_host.EXEC_FORMAT_ERROR


def test_each_attempt_uses_a_distinct_name_and_a_timed_out_one_is_removed(docker) -> None:
    stub = docker(_timeout(), (0, GOOD_STDOUT, ""))
    with pytest.warns(RuntimeWarning):
        dev_host.probe_client_image(IMAGE)
    names = [run[run.index("--name") + 1] for run in stub.runs]
    assert len(set(names)) == 2, "a retry must not collide with the first attempt's container"
    removed = [c for c in stub.calls if c[:3] == ["docker", "rm", "-f"]]
    assert [c[3] for c in removed] == [names[0]], "only the timed-out attempt needs removing"


# -- the fail-closed contract at the call site --------------------------------------


def _unmet(reasons: list[str]):
    def handler(message: str) -> None:
        reasons.append(message)
        raise AssertionError(f"[FAIL-CLOSED] {message}")

    return handler


def test_require_client_image_fails_closed_on_a_stall_without_blaming_the_architecture(
    docker, monkeypatch
) -> None:
    monkeypatch.setattr(dev_host, "check_docker_daemon", lambda timeout=10: (True, ""))
    monkeypatch.setattr(dev_host, "resolve_client_image", lambda: IMAGE)
    docker(_timeout(), _timeout())
    reasons: list[str] = []
    with pytest.warns(RuntimeWarning), pytest.raises(AssertionError, match="FAIL-CLOSED"):
        dev_host.require_client_image(_unmet(reasons))
    assert len(reasons) == 1
    assert "did not finish within" in reasons[0]
    assert "cannot execute on this host architecture" not in reasons[0]


def test_require_client_image_still_fails_on_a_genuine_architecture_mismatch(
    docker, monkeypatch
) -> None:
    monkeypatch.setattr(dev_host, "check_docker_daemon", lambda timeout=10: (True, ""))
    monkeypatch.setattr(dev_host, "resolve_client_image", lambda: IMAGE)
    docker((255, "", "exec /usr/local/bin/awg: exec format error"))
    reasons: list[str] = []
    with pytest.raises(AssertionError, match="FAIL-CLOSED"):
        dev_host.require_client_image(_unmet(reasons))
    assert "cannot execute on this host architecture" in reasons[0]


def test_require_client_image_fails_when_the_daemon_is_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(
        dev_host, "check_docker_daemon", lambda timeout=10: (False, "`docker info` did not answer")
    )
    reasons: list[str] = []
    with pytest.raises(AssertionError, match="FAIL-CLOSED"):
        dev_host.require_client_image(_unmet(reasons))
    assert "unavailable" in reasons[0] and "did not answer" in reasons[0]


def test_require_client_image_fails_when_no_image_can_be_obtained(monkeypatch) -> None:
    monkeypatch.setattr(dev_host, "check_docker_daemon", lambda timeout=10: (True, ""))
    monkeypatch.setattr(dev_host, "resolve_client_image", lambda: None)
    reasons: list[str] = []
    with pytest.raises(AssertionError, match="FAIL-CLOSED"):
        dev_host.require_client_image(_unmet(reasons))
    assert "Neither" in reasons[0] and "could be found or pulled" in reasons[0]


def test_a_handler_that_returns_cannot_turn_a_failure_into_a_pass(monkeypatch) -> None:
    """If a caller's handler ever returned instead of raising, the probe still raises."""
    monkeypatch.setattr(dev_host, "check_docker_daemon", lambda timeout=10: (True, ""))
    monkeypatch.setattr(dev_host, "resolve_client_image", lambda: None)
    with pytest.raises(RuntimeError, match="unmet handler returned"):
        dev_host.require_client_image(lambda message: None)


def test_daemon_check_names_a_timeout_instead_of_calling_it_unreachable(monkeypatch) -> None:
    def stalled(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 10)

    monkeypatch.setattr(dev_host.subprocess, "run", stalled)
    reachable, reason = dev_host.check_docker_daemon()
    assert not reachable and "did not answer within" in reason and "unreachable" not in reason


# -- pulls --------------------------------------------------------------------------


def test_a_failed_pull_is_retried_a_bounded_number_of_times(docker, monkeypatch) -> None:
    monkeypatch.setattr(dev_host.time, "sleep", lambda seconds: None)
    stub = docker((1, "", "net/http: TLS handshake timeout"), (0, "", ""))
    assert dev_host._pull(IMAGE) is True
    assert [c[:2] for c in stub.calls] == [["docker", "pull"], ["docker", "pull"]]


def test_a_pull_that_never_succeeds_returns_false_after_the_bound(docker, monkeypatch) -> None:
    monkeypatch.setattr(dev_host.time, "sleep", lambda seconds: None)
    stub = docker(*[(1, "", "denied")] * dev_host.PULL_ATTEMPTS)
    assert dev_host._pull(IMAGE) is False
    assert len(stub.calls) == dev_host.PULL_ATTEMPTS


def test_a_present_image_is_not_pulled(docker) -> None:
    stub = docker((0, "[]", ""))
    assert dev_host.resolve_client_image() == dev_host.PRIMARY_CLIENT_IMAGE
    assert all(call[:2] != ["docker", "pull"] for call in stub.calls)


# -- structural wiring: nothing may drift -------------------------------------------

VERSION_SOURCE = REPO_ROOT / "internal" / "version" / "version.go"
INSTALLER_SOURCE = REPO_ROOT / "internal" / "manager" / "awg" / "awg_install.go"


def _go_string_const(source: str, name: str) -> str:
    """Return the string literal a Go constant is declared with."""
    match = re.search(rf'^\s*{name}\s*=\s*"([^"]+)"', source, re.MULTILINE)
    assert match, (
        f"constant {name} must be declared as a string literal "
        "in internal/version/version.go"
    )
    return match.group(1)


def canonical_base_image() -> str:
    """The image the panel installs, composed from its single definition.

    The tag is derived there (repository + versioned source + image revision)
    rather than written out, so the same derivation has to be applied here; a
    literal to scrape no longer exists, and inventing a second copy of the value
    is the drift this check exists to catch.
    """
    source = VERSION_SOURCE.read_text(encoding="utf-8")
    repository = _go_string_const(source, "DefaultDockerRepo")
    version = _go_string_const(source, "PinnedAWGGoVersion")
    revision = _go_string_const(source, "PinnedAWGImageRevision")
    return f"{repository}:{version}-{revision}"


def assert_client_image_matches_installer(effective_image: str) -> None:
    """Fail when the image the DEV client runs is not the one the panel installs."""
    canonical = canonical_base_image()
    assert effective_image == canonical, (
        f"DEV client image {effective_image!r} must equal the panel's pinned base image "
        f"{canonical!r}; both are pinned so a DEV run exercises the shipped datapath"
    )


def test_the_pinned_client_image_equals_the_one_the_panel_installs() -> None:
    """One definition, two consumers: the Go installer and this module."""
    installer = INSTALLER_SOURCE.read_text(encoding="utf-8")
    assert re.search(r"const awgBaseImage = version\.PinnedAWGBaseImage\b", installer), (
        "the installer must consume version.PinnedAWGBaseImage rather than "
        "declaring its own literal"
    )
    assert_client_image_matches_installer(dev_host.PRIMARY_CLIENT_IMAGE)


def test_the_parity_check_rejects_a_divergent_effective_image() -> None:
    """The assertion above must be able to fail, or it protects nothing."""
    canonical = canonical_base_image()
    repository, _, tag = canonical.rpartition(":")
    divergent = f"{repository}:{tag.rsplit('-', 1)[0]}-99"
    assert divergent != canonical

    with pytest.raises(AssertionError):
        assert_client_image_matches_installer(divergent)


def test_the_traffic_suite_uses_the_shared_probe_and_no_inline_architecture_check() -> None:
    text = (REPO_ROOT / "tests" / "e2e" / "test_traffic.py").read_text(encoding="utf-8")
    assert text.count("dev_host.require_client_image(_handle_skip_or_fail)") == 2
    assert "_verify_client_image_architecture" not in text
    assert "cannot execute on host architecture" not in text


def test_the_setup_test_separates_the_answer_wait_from_the_banner_wait() -> None:
    text = (REPO_ROOT / "tests" / "e2e" / "test_setup.py").read_text(encoding="utf-8")
    assert "expect_response" in text and "SETUP_BANNER_TIMEOUT_MS" in text
    assert (
        text.count('page.click("button#setupBtn")') == 2
    ), "the success test clicks once, inside the response wait, and is never retried"
    assert "timeout=10000" not in text


def test_the_workflow_does_not_pre_pull_the_image_the_installer_pulls() -> None:
    """A pre-pull would turn Stage 2's own `docker pull` into a cache hit."""
    text = (REPO_ROOT / ".github" / "workflows" / "e2e-dev.yml").read_text(encoding="utf-8")
    assert "tests.e2e.dev_host" not in text
    assert "docker pull devopsigor/amneziawg" not in text
