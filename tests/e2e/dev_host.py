"""DEV host probes shared by the lifecycle suite and the workflow (issue #911).

The DEV runner is a single-board ARM machine with SD-card storage. Its I/O
stalls for seconds at a time, so a fixed short timeout on a container start or
on the panel answering the setup request fails for reasons unrelated to the
product. Two things follow, and this module implements both:

* A timeout, a non-zero exit and an exec-format error are different facts and
  are reported as different facts. A client image that genuinely cannot run on
  the host still fails the run; a slow host is no longer reported as an
  architecture mismatch.
* The client image is pulled with a bounded retry before it is run, so a
  registry wait is not measured as a capability failure. It is deliberately not
  pre-pulled by the workflow: Stage 2's installer pulls the same tag, and a
  pre-pull would turn that pull into a cache hit and stop testing it.

Standard library only, so the decisions here are tested offline without
Playwright.
"""

from __future__ import annotations

import dataclasses
import subprocess
import time
import uuid
import warnings
from typing import Callable, Optional

# Pinned multiarch AmneziaWG client image; must equal the base image the panel
# derives in internal/version/version.go (tests/test_e2e_dev_host.py enforces it).
PRIMARY_CLIENT_IMAGE = "devopsigor/amneziawg:v3.1.20261116-1"
FALLBACK_CLIENT_IMAGE = "devopsigor/amneziawg:ci-test"

# Budget for one `docker run --rm ... awg --version` on the DEV host.
# Evidence: 33 passing DEV runs took 2.2s to 13.3s (median 2.8s) for the whole
# preflight, so the old 15s budget sat 1.7s above the slowest pass; the one run
# that failed it was a timeout at 15s. scripts/preflight_naive_caddy.sh records
# container starts of 2s to 29s on this runner. 60s is about twice that
# recorded maximum. It is a judgement, not a derived constant: a saturated SD
# card can stall a start for minutes, which no finite budget covers, so a start
# that still times out is reported as a stall and fails the run.
PROBE_TIMEOUT_SECONDS = 60
# A timeout is retried once. A non-zero exit or an exec-format error is a
# deterministic answer from a container that did start, and is never retried.
PROBE_ATTEMPTS = 2
# Same budget as the previous inline pull (120s). One retry, so a stalled or
# failed pull costs at most 2 x 120s + 5s before the run fails.
PULL_TIMEOUT_SECONDS = 120
PULL_ATTEMPTS = 2
PULL_RETRY_DELAY_SECONDS = 5.0
# Bound for the best-effort removal of a container left by a timed-out start.
_CLEANUP_TIMEOUT_SECONDS = 30

OK = "ok"
TIMEOUT = "timeout"
EXEC_FORMAT_ERROR = "exec_format_error"
NONZERO_EXIT = "nonzero_exit"
UNEXPECTED_OUTPUT = "unexpected_output"
DOCKER_UNAVAILABLE = "docker_unavailable"

# Only text that proves the binary could not be executed. Docker's "requested
# image's platform ... does not match the detected host platform" line is a
# warning that is also printed on runs that succeed under emulation, so it is
# deliberately not a marker.
_FORMAT_MARKERS = ("exec format error", "no matching manifest")


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    """Outcome of running the client image once, with the cause named."""

    kind: str
    image: str
    attempts: int
    elapsed: float
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.kind == OK

    def describe(self) -> str:
        """One honest sentence naming which failure occurred."""
        where = f"{self.image} after {self.attempts} attempt(s), {self.elapsed:.1f}s"
        if self.kind == TIMEOUT:
            return (
                f"docker run of {where} did not finish within {PROBE_TIMEOUT_SECONDS}s per "
                "attempt. This is a stalled host or Docker daemon, not an architecture result"
            )
        if self.kind == EXEC_FORMAT_ERROR:
            return f"client image {where} cannot execute on this host architecture: {self.detail}"
        if self.kind == NONZERO_EXIT:
            return f"docker run of {where} exited non-zero: {self.detail}"
        if self.kind == UNEXPECTED_OUTPUT:
            return f"docker run of {where} succeeded but printed unexpected output: {self.detail}"
        if self.kind == DOCKER_UNAVAILABLE:
            return f"docker could not be started to run {self.image}: {self.detail}"
        return f"client image {self.image} runs on this host ({self.elapsed:.1f}s)"


def _tail(text: str, limit: int = 200) -> str:
    """Last non-empty line of ``text``, bounded, for a one-line report."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return (lines[-1] if lines else "")[:limit]


def classify(returncode: int, stdout: str, stderr: str) -> tuple[str, str]:
    """Map a finished ``docker run`` to (kind, detail). Pure, no I/O."""
    combined = f"{stdout}\n{stderr}"
    if returncode == 0:
        if "amneziawg-tools" in stdout:
            return OK, ""
        return UNEXPECTED_OUTPUT, _tail(combined)
    lowered = combined.lower()
    if any(marker in lowered for marker in _FORMAT_MARKERS):
        return EXEC_FORMAT_ERROR, _tail(stderr or stdout)
    return NONZERO_EXIT, f"exit {returncode}: {_tail(stderr or stdout)}"


def _remove_container(name: str) -> None:
    """Best-effort removal of a container whose client process was killed."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            text=True,
            timeout=_CLEANUP_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _run_once(image: str, timeout: int) -> tuple[str, str]:
    """Run ``awg --version`` in ``image`` once and return (kind, detail)."""
    name = f"e2e-probe-{uuid.uuid4().hex[:10]}"
    cmd = ["docker", "run", "--rm", "--name", name, "--entrypoint", "awg", image, "--version"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _remove_container(name)
        return TIMEOUT, ""
    except OSError as exc:
        return DOCKER_UNAVAILABLE, str(exc)
    return classify(res.returncode, res.stdout, res.stderr)


def probe_client_image(
    image: str, timeout: int = PROBE_TIMEOUT_SECONDS, attempts: int = PROBE_ATTEMPTS
) -> ProbeResult:
    """Run the client image and report which of the possible outcomes occurred.

    Only a timeout is retried. A container that started and answered, however
    badly, is a deterministic result: a non-zero exit, an exec-format error or
    wrong output is returned on the first attempt, so a retry can never turn a
    real failure into a pass. A start that times out on every attempt returns
    ``TIMEOUT``, which callers must treat as a failure.
    """
    begin = time.monotonic()
    kind, detail = TIMEOUT, ""
    for attempt in range(1, max(1, attempts) + 1):
        kind, detail = _run_once(image, timeout)
        if kind != TIMEOUT:
            return ProbeResult(kind, image, attempt, time.monotonic() - begin, detail)
        if attempt < attempts:
            # Never silent: a retried stall shows in the pytest warnings summary.
            warnings.warn(
                f"docker run of {image} timed out after {timeout}s (attempt {attempt} of "
                f"{attempts}); retrying once. The host or Docker daemon stalled.",
                RuntimeWarning,
                stacklevel=2,
            )
    return ProbeResult(kind, image, max(1, attempts), time.monotonic() - begin, detail)


def _image_present(image: str) -> bool:
    try:
        res = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=_CLEANUP_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0


def _pull(image: str) -> bool:
    """Pull ``image``, retrying a stalled or failed pull a bounded number of times."""
    for attempt in range(1, PULL_ATTEMPTS + 1):
        try:
            res = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=PULL_TIMEOUT_SECONDS,
            )
            if res.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass
        if attempt < PULL_ATTEMPTS:
            time.sleep(PULL_RETRY_DELAY_SECONDS)
    return False


def resolve_client_image() -> Optional[str]:
    """Return the first client image present or pullable, or None.

    The DEV teardown prunes every image, so a run starts without the client
    image until Stage 2 installs it. If it is still absent, pull it here with a
    bounded retry so a registry wait stays out of the capability check.
    """
    for image in (PRIMARY_CLIENT_IMAGE, FALLBACK_CLIENT_IMAGE):
        if _image_present(image) or _pull(image):
            return image
    return None


def check_docker_daemon(timeout: int = 10) -> tuple[bool, str]:
    """Return (reachable, reason). A timeout is reported as a timeout.

    ``docker info`` previously had a 10s budget and any exception, including a
    timeout, was reported as "daemon unreachable".
    """
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"`docker info` did not answer within {timeout}s (stalled host or daemon)"
    except OSError as exc:
        return False, f"`docker` could not be started: {exc}"
    if res.returncode != 0:
        return False, f"`docker info` exited {res.returncode}: {_tail(res.stderr)}"
    return True, ""


def require_client_image(unmet: Callable[[str], None]) -> str:
    """Return a client image that is present and runs, or call ``unmet(reason)``.

    ``unmet`` is the caller's fail-closed handler: it fails the run when the
    data plane is required and skips otherwise, and must raise. Every outcome is
    reported as what it was (unreachable daemon, missing image, stalled start,
    non-zero exit, genuine architecture mismatch). A timeout is never reported
    as an architecture mismatch, and none of them can pass.
    """
    reachable, reason = check_docker_daemon()
    if not reachable:
        unmet(f"Docker daemon is unavailable: {reason}; skipping data plane test")
        raise RuntimeError("unmet handler returned for an unavailable Docker daemon")

    image = resolve_client_image()
    if image is None:
        unmet(
            f"Neither {PRIMARY_CLIENT_IMAGE} nor {FALLBACK_CLIENT_IMAGE} could be found or "
            "pulled; skipping"
        )
        raise RuntimeError("unmet handler returned for a missing client image")

    result = probe_client_image(image)
    if not result.ok:
        unmet(result.describe())
        raise RuntimeError("unmet handler returned for a client image that does not run")
    return image
