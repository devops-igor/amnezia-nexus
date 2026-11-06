"""Offline privacy and schema tests for the E2E setup diagnostics recorder.

Every fixture here is synthetic: fake pages, requests and responses built from
marker strings that would be catastrophic to leak. The suite asserts both that
the recorder cannot emit them and that the artifact writer refuses to persist
anything that fails validation.
"""

import json
import time
from pathlib import Path

import pytest

from tests.e2e import diagnostics

SECRET_PASSWORD = "Synthetic-Pa55word-marker"
SECRET_COOKIE = "sessionid-synthetic-cookie-marker"
SECRET_TOKEN = "csrftoken-synthetic-token-marker"
PRIVATE_HOST = "panel.internal.example.invalid"
PRIVATE_QUERY = "user=synthetic-user&token=" + SECRET_TOKEN


class FakeRequest:
    """Minimal stand-in for a Playwright Request carrying hostile fields."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        resource_type: str = "xhr",
        navigation: bool = False,
        failure: str = "",
    ) -> None:
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self._navigation = navigation
        self.failure = failure
        self.post_data = json.dumps({"password": SECRET_PASSWORD})
        self.headers = {"cookie": SECRET_COOKIE, "authorization": SECRET_TOKEN}

    def is_navigation_request(self) -> bool:
        """Report the synthetic navigation flag."""
        return self._navigation


class FakeResponse:
    """Minimal stand-in for a Playwright Response."""

    def __init__(self, request: FakeRequest, status: int = 200) -> None:
        self.request = request
        self.status = status
        self.url = request.url
        self.headers = {"set-cookie": SECRET_COOKIE}
        self._text = json.dumps({"password": SECRET_PASSWORD})

    def text(self) -> str:
        """Return a hostile body that must never be recorded."""
        return self._text


class FakeFrame:
    """Minimal stand-in for a Playwright Frame."""

    def __init__(self, url: str) -> None:
        self.url = url


class FakePage:
    """Minimal stand-in for a Playwright Page."""

    def __init__(self, url: str = "") -> None:
        self.url = url
        self.listeners = []
        self.main_frame = FakeFrame(url)
        self.context = self
        self.browser = self
        self.browser_type = self
        self.name = "chromium"
        self.version = "141.0.7390.37"

    def on(self, event: str, handler) -> None:
        """Register a synthetic listener."""
        self.listeners.append((event, handler))


def build_recorder() -> diagnostics.RequestNavigationRecorder:
    """Return a recorder started now, so elapsed times stay in range."""
    return diagnostics.RequestNavigationRecorder(started=time.monotonic())


def hostile_urls():
    """Return URLs whose origin, path and query must not reach any artifact."""
    return [
        f"https://{PRIVATE_HOST}/api/auth/setup?{PRIVATE_QUERY}",
        f"http://{PRIVATE_HOST}:8443/setup?{PRIVATE_QUERY}",
        f"https://{PRIVATE_HOST}/login?{PRIVATE_QUERY}#fragment",
        f"https://{PRIVATE_HOST}/",
        f"https://{PRIVATE_HOST}/nonexistent-deep/path?{PRIVATE_QUERY}",
    ]


def drive_full_cycle(recorder: diagnostics.RequestNavigationRecorder) -> None:
    """Exercise every listener with hostile inputs, including a failure."""
    for url in hostile_urls():
        request = FakeRequest(url)
        recorder.on_request(request)
        recorder.on_response(FakeResponse(request))
        failing = FakeRequest(url, failure=f"net::ERR_ABORTED {SECRET_TOKEN} {PRIVATE_HOST}")
        recorder.on_request(failing)
        recorder.on_requestfailed(failing)
        recorder.on_framenavigated(FakeFrame(url), True)
        recorder.on_load(FakePage(url), True)


def assert_no_secrets(text: str) -> None:
    """Assert that no synthetic marker or raw origin reached the text."""
    for marker in (SECRET_PASSWORD, SECRET_COOKIE, SECRET_TOKEN, PRIVATE_HOST, "synthetic-user"):
        assert marker.lower() not in text.lower(), f"artifact leaked {marker!r}"
    assert "://" not in text
    assert "?" not in text


def test_url_path_discards_origin_and_query() -> None:
    """The path helper keeps only the path segment of any URL."""
    for url in hostile_urls():
        path = diagnostics.url_path(url)
        assert PRIVATE_HOST not in path
        assert "?" not in path
        assert "synthetic-user" not in path


@pytest.mark.parametrize(
    ("url", "resource_type", "expected"),
    [
        ("https://panel.invalid/api/auth/setup?x=1", "fetch", "auth_setup_api"),
        ("https://panel.invalid/api/auth/setup/", "fetch", "auth_setup_api"),
        ("https://panel.invalid/api/auth/login", "fetch", "auth_login_api"),
        ("https://panel.invalid/api/health", "fetch", "health_api"),
        ("https://panel.invalid/setup", "document", "auth_setup_page"),
        ("https://panel.invalid/login", "document", "auth_login_page"),
        ("https://panel.invalid/", "document", "panel_index"),
        ("https://panel.invalid/static/app.css", "stylesheet", "static"),
        ("https://panel.invalid/users?size=100", "document", "other"),
        ("", "", "other"),
    ],
)
def test_route_category_is_allowlisted(url: str, resource_type: str, expected: str) -> None:
    """Only the closed route vocabulary leaves the classifier."""
    assert diagnostics.route_category(url, resource_type) == expected


@pytest.mark.parametrize(
    ("method", "expected"),
    [("get", "GET"), ("post", "POST"), ("TRACE", "other"), (None, "other"), ("CUSTOM", "other")],
)
def test_method_name_is_allowlisted(method, expected: str) -> None:
    """Unknown verbs collapse to "other" instead of being echoed."""
    assert diagnostics.method_name(method) == expected


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("net::ERR_ABORTED at https://panel.invalid/x", "net::ERR_ABORTED"),
        ("net::ERR_CONNECTION_REFUSED cookie=abc", "net::ERR_CONNECTION_REFUSED"),
        ("Timeout 30000ms exceeded", "other"),
        (None, "other"),
    ],
)
def test_error_code_extraction(message, expected: str) -> None:
    """Only Playwright network error codes survive, never the surrounding text."""
    assert diagnostics.error_code(message) == expected


def test_recorder_events_contain_no_secret_or_origin() -> None:
    """A full hostile cycle produces allowlisted events with nothing sensitive."""
    recorder = build_recorder()
    drive_full_cycle(recorder)

    events = recorder.events()
    assert events
    payload = diagnostics.build_payload(
        "tests/e2e/test_setup.py::test_setup_success[chromium]", recorder
    )
    assert diagnostics.validate_payload(payload) == []
    assert_no_secrets(json.dumps(payload, sort_keys=True))
    for event in events:
        assert diagnostics.validate_event(event) == []
        assert frozenset(event) == frozenset({"kind", *diagnostics._EVENT_FIELDS[event["kind"]]})
        for value in event.values():
            assert PRIVATE_HOST not in str(value)


def test_recorder_reports_all_kinds() -> None:
    """Request, response, failure, navigation and load events are all produced."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    kinds = {event["kind"] for event in recorder.events()}
    assert kinds == set(diagnostics._KINDS)


def test_recorder_caps_events_and_counts_dropped() -> None:
    """The event cap bounds the artifact and counts what was discarded."""
    recorder = diagnostics.RequestNavigationRecorder(started=time.monotonic(), max_events=5)
    for _ in range(20):
        recorder.on_request(FakeRequest("https://panel.invalid/api/auth/setup"))
    assert len(recorder.events()) == 5
    assert recorder.dropped == 15
    assert diagnostics.validate_payload(diagnostics.build_payload("setup", recorder)) == []


def test_durations_and_timestamps_are_bounded() -> None:
    """Elapsed values are non-negative integers within the configured ceiling."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    for event in recorder.events():
        assert isinstance(event["t_ms"], int) and 0 <= event["t_ms"] <= diagnostics.MAX_DURATION_MS
        if event["kind"] == "response":
            assert 0 <= event["duration_ms"] <= diagnostics.MAX_DURATION_MS


def test_payload_rejects_unrecognised_fields() -> None:
    """Any extra field makes the payload unuploadable."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    payload = diagnostics.build_payload("setup", recorder)
    payload["unexpected"] = SECRET_PASSWORD
    assert diagnostics.validate_payload(payload)


def test_payload_rejects_non_allowlisted_route() -> None:
    """A route outside the vocabulary fails validation."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    payload = diagnostics.build_payload("setup", recorder)
    payload["events"][0]["route"] = f"https://{PRIVATE_HOST}/api/auth/setup"
    assert diagnostics.validate_payload(payload)


@pytest.mark.parametrize("bad", ["net::ERR_FAILED", "other", "UNKNOWN_CODE"])
def test_payload_accepts_allowlisted_error_codes(bad: str) -> None:
    """Allowlisted error tokens keep the payload valid."""
    recorder = build_recorder()
    recorder.on_requestfailed(FakeRequest("https://panel.invalid/api/auth/setup", failure=bad))
    payload = diagnostics.build_payload("setup", recorder)
    assert diagnostics.validate_payload(payload) == []


def test_payload_rejects_oversized_and_malformed_values() -> None:
    """Timestamps, statuses and ids outside their bounds are rejected."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    payload = diagnostics.build_payload("setup", recorder)
    payload["events"][0]["t_ms"] = -1
    assert diagnostics.validate_payload(payload)

    payload = diagnostics.build_payload("setup", recorder)
    payload["schema_version"] = 99
    assert diagnostics.validate_payload(payload)

    payload = diagnostics.build_payload("setup", recorder)
    payload["test"] = "../" + SECRET_PASSWORD
    assert diagnostics.validate_payload(payload)


def test_test_id_is_sanitised() -> None:
    """Node ids become bounded filesystem-safe tokens."""
    token = diagnostics.sanitize_test_id("tests/e2e/test_setup.py::test_setup_success[chromium]")
    assert token.startswith("test_setup")
    assert diagnostics._TOKEN_RE.match(token)
    assert len(diagnostics.sanitize_test_id("x" * 500)) == diagnostics.MAX_TEST_ID


def test_artifact_written_for_valid_payload_then_rejected_if_tampered(tmp_path: Path) -> None:
    """Valid evidence is persisted with restrictive permissions; tampered data is not."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    payload = diagnostics.build_payload("setup", recorder)

    path = diagnostics.write_failure_artifact(tmp_path, payload)
    assert path is not None and path.exists()
    assert path.stat().st_mode & 0o077 == 0
    text = path.read_text(encoding="utf-8")
    assert_no_secrets(text)
    assert json.loads(text)["schema_version"] == diagnostics.SCHEMA_VERSION

    tampered = diagnostics.build_payload("setup", recorder)
    tampered["events"][0]["route"] = PRIVATE_HOST
    assert diagnostics.write_failure_artifact(tmp_path, tampered) is None
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_version_report_records_actual_environment(tmp_path: Path) -> None:
    """The version report carries measured values only, no origins."""
    versions = diagnostics.environment_versions()
    assert versions["python"]
    assert versions["packages"].get("pytest")

    path = diagnostics.write_versions_artifact(
        tmp_path, versions, {"name": "chromium", "version": "141.0.7390.37"}
    )
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert_no_secrets(text)
    recorded = json.loads(text)
    assert recorded["python"] == versions["python"]
    assert recorded["browser"]["name"] == "chromium"


def test_version_report_claims_requested_provenance_only(tmp_path: Path) -> None:
    """Provenance is labelled requested-only, never as runtime-verified."""
    versions = diagnostics.environment_versions()
    assert versions["provenance"] == diagnostics.PROVENANCE_REQUESTED_ONLY

    path = diagnostics.write_versions_artifact(tmp_path, versions, {})
    assert path is not None
    recorded = json.loads(path.read_text(encoding="utf-8"))
    assert recorded["provenance"] == "requested-only"
    for unverified in (
        "tested_sha",
        "tested_image",
        "image_id",
        "image_digest",
        "runtime_verified",
    ):
        assert unverified not in recorded


def test_version_report_rejects_verified_provenance_claim() -> None:
    """A report claiming runtime-verified provenance is refused."""
    versions = diagnostics.environment_versions()
    versions["provenance"] = "runtime-verified"
    assert diagnostics.validate_versions(versions) == [
        "provenance must be claimed as requested-only"
    ]


def test_version_report_rejects_unmeasured_fields(tmp_path: Path) -> None:
    """An origin smuggled into a requested field is refused."""
    versions = diagnostics.environment_versions()
    versions["requested_image_label"] = f"https://{PRIVATE_HOST}/img"
    assert diagnostics.write_versions_artifact(tmp_path, versions, {}) is None
    assert not any(tmp_path.iterdir())


def test_version_report_accepts_requested_sha_and_label(tmp_path: Path) -> None:
    """A well-formed requested SHA and image label are recorded as requested."""
    versions = diagnostics.environment_versions()
    versions["requested_source_sha"] = "ff46142e5bef3c6f31a392d550baa09842190e65"
    versions["requested_image_label"] = "ghcr.io/devops-igor/amnezia-nexus:pr-724"
    path = diagnostics.write_versions_artifact(tmp_path, versions, {})
    assert path is not None
    recorded = json.loads(path.read_text(encoding="utf-8"))
    assert recorded["requested_source_sha"].startswith("ff46142")
    assert recorded["requested_image_label"].endswith("pr-724")


def test_gate_withholds_whole_directory_on_one_rejection(tmp_path: Path) -> None:
    """One bad file withholds every sibling, not just itself."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    good = diagnostics.build_payload("setup", recorder)
    (tmp_path / "setup-valid.json").write_text(json.dumps(good), encoding="utf-8")
    (tmp_path / "setup-poisoned.json").write_text(
        json.dumps({"schema_version": 1, "url": f"https://{PRIVATE_HOST}/setup?{PRIVATE_QUERY}"}),
        encoding="utf-8",
    )

    assert diagnostics.main(["--validate-dir", str(tmp_path)]) == 1
    assert not tmp_path.exists()


def test_gate_withholds_on_unreadable_file(tmp_path: Path) -> None:
    """Unparseable evidence is uncertainty, so nothing is published."""
    (tmp_path / "setup-broken.json").write_text("{not json", encoding="utf-8")
    assert diagnostics.main(["--validate-dir", str(tmp_path)]) == 1
    assert not tmp_path.exists()


def test_gate_never_echoes_rejected_content(tmp_path: Path, capsys) -> None:
    """Rejection prints counts only; no marker secret reaches stdout or logs."""
    (tmp_path / "setup-leaky.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "url": f"https://{PRIVATE_HOST}/setup?{PRIVATE_QUERY}",
                "password": SECRET_PASSWORD,
                "cookie": SECRET_COOKIE,
            }
        ),
        encoding="utf-8",
    )

    assert diagnostics.main(["--validate-dir", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    emitted = captured.out + captured.err
    assert "files=1" in emitted and "rejected=1" in emitted
    assert_no_secrets(emitted)
    assert "setup-leaky.json" not in emitted


def test_gate_leaves_clean_directory_intact(tmp_path: Path) -> None:
    """A directory holding only validated evidence survives the gate."""
    recorder = build_recorder()
    drive_full_cycle(recorder)
    payload = diagnostics.build_payload("setup", recorder)
    path = tmp_path / "setup-valid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert diagnostics.main(["--validate-dir", str(tmp_path)]) == 0
    assert path.exists()


def test_gate_tolerates_absent_directory(tmp_path: Path) -> None:
    """No captured evidence is not a privacy failure."""
    assert diagnostics.main(["--validate-dir", str(tmp_path / "missing")]) == 0


def test_attach_tolerates_listener_api_drift() -> None:
    """Attaching to a page without browser metadata still records events."""

    class BarePage:
        """Page whose browser/context introspection raises."""

        def __init__(self) -> None:
            self.url = "https://panel.invalid/setup"
            self.listeners = []
            self.main_frame = FakeFrame(self.url)

        @property
        def context(self):
            raise RuntimeError("no context")

        def on(self, event: str, handler) -> None:
            """Register a synthetic listener."""
            self.listeners.append((event, handler))

    page = BarePage()
    recorder = build_recorder()
    diagnostics.attach(page, recorder)
    assert recorder.browser == {}
    assert {event for event, _ in page.listeners} == {
        "request",
        "response",
        "requestfailed",
        "framenavigated",
        "load",
    }


def test_listener_handlers_record_without_raising() -> None:
    """Handlers driven through a real attach() still emit allowlisted events."""
    page = FakePage("https://panel.invalid/setup")
    recorder = build_recorder()
    diagnostics.attach(page, recorder)
    handlers = dict(page.listeners)

    request = FakeRequest(f"https://{PRIVATE_HOST}/api/auth/setup?{PRIVATE_QUERY}")
    handlers["request"](request)
    handlers["response"](FakeResponse(request))
    failing = FakeRequest(f"https://{PRIVATE_HOST}/api/auth/setup", failure="net::ERR_FAILED")
    handlers["request"](failing)
    handlers["requestfailed"](failing)
    handlers["framenavigated"](page.main_frame)
    handlers["load"](page)

    assert {event["kind"] for event in recorder.events()} == set(diagnostics._KINDS)
    assert diagnostics.validate_payload(diagnostics.build_payload("setup", recorder)) == []
    assert_no_secrets(json.dumps(recorder.events(), sort_keys=True))


def test_recorder_drops_events_it_cannot_bound() -> None:
    """An out-of-range status is counted as dropped instead of recorded."""
    recorder = build_recorder()
    recorder.on_response(FakeResponse(FakeRequest("https://panel.invalid/setup"), status=99))
    assert recorder.events() == []
    assert recorder.dropped == 1

    # A failure message without a network code still records the "other" token.
    recorder.on_requestfailed(FakeRequest("https://panel.invalid/setup", failure=""))
    assert [event["error"] for event in recorder.events()] == ["other"]


def test_recorder_survives_broken_event_objects() -> None:
    """Objects whose attributes raise do not break the recorder."""

    class Exploding:
        """Every attribute access raises."""

        def __getattr__(self, name):
            raise RuntimeError(name)

    recorder = build_recorder()
    recorder.on_request(Exploding())
    recorder.on_response(Exploding())
    recorder.on_requestfailed(Exploding())
    recorder.on_framenavigated(Exploding(), True)
    recorder.on_load(Exploding(), True)
    assert recorder.events() == []


def test_main_frame_detection_falls_back_to_false() -> None:
    """A page without main_frame is treated as a subframe."""

    class NoFrame:
        """Page stand-in whose main_frame raises."""

        @property
        def main_frame(self):
            raise RuntimeError("no main frame")

    assert diagnostics._is_mainframe(FakeFrame("https://panel.invalid/"), NoFrame()) is False
