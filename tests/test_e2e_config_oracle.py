"""Deterministic proof of the server-config read-back oracle in the E2E suite.

The real SSH execution path applies strings.TrimSpace to stdout
(internal/manager/ssh/exec.go), so a configuration read back over the transport
never carries surrounding blank lines. These checks drive the actual E2E test
function against a transport-faithful fixture and prove the oracle tolerates that
trimming without becoming vacuous: a save that does not persist the requested
change still fails the test.
"""

from typing import Any, cast

import pytest

from playwright.sync_api import Page

from tests.e2e import test_servers as servers

PROVISIONED_CONFIG = "[Interface]\nAddress = <server-network>\nPrivateKey = synthetic-fixture\n"


class TransportFaithfulConfigAPI:
    """Model a server whose config is persisted on disk but trimmed on read-back.

    Writes keep the exact bytes submitted; reads apply the same surrounding
    whitespace trim the SSH execution path applies to stdout. A mutation can make
    the marker save a no-op, corrupt the persisted body, or refuse the restoration
    save, so the E2E oracle can be shown to be live rather than normalized into
    meaninglessness.
    """

    def __init__(self, mutation: str = "") -> None:
        self.mutation = mutation
        self.stored = PROVISIONED_CONFIG
        self.saves: list[str] = []
        self.reads: list[str] = []

    def api_get(self, page: Any, url: str) -> Any:
        """Return only the provisioned server inventory the test needs."""
        assert url == "/api/servers", f"Unexpected fixture GET endpoint: {url}"
        return [{"id": 1}]

    def api_post(self, page: Any, url: str, data: dict[str, Any], token: str) -> dict:
        """Persist submitted configuration and serve it back with a transport trim."""
        if url.endswith("/server_config/save"):
            self._save(data["config"])
            return {"status": 200, "body": {"status": "ok"}}
        assert url.endswith("/server_config"), f"Unexpected fixture POST endpoint: {url}"
        self.reads.append(self.stored.strip())
        return {"status": 200, "body": {"status": "ok", "config": self.stored.strip()}}

    def _save(self, submitted: str) -> None:
        """Apply the first save the test performs, then its restoration save."""
        self.saves.append(submitted)
        first_save = len(self.saves) == 1
        if self.mutation == "save_noop" and first_save:
            return
        if self.mutation == "save_corrupt" and first_save:
            self.stored = submitted.replace("Address =", "Adress =")
            return
        if self.mutation == "restore_noop" and not first_save:
            return
        self.stored = submitted

    @property
    def disk_state(self) -> str:
        """Expose the exact on-disk bytes, proving the trim is read-side only."""
        return self.stored


def run_e2e_config_test(
    monkeypatch: pytest.MonkeyPatch, fixture: TransportFaithfulConfigAPI
) -> None:
    """Run the real E2E function against the fixture without a browser."""
    monkeypatch.setattr(servers, "api_get", fixture.api_get)
    monkeypatch.setattr(servers, "api_post", fixture.api_post)
    servers.test_server_config_get_and_save(
        cast(Page, fixture), "https://panel.example.test", "fixture-csrf"
    )


def test_transport_trim_is_read_side_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """The trim seen in a read-back never reached the bytes written to disk."""
    fixture = TransportFaithfulConfigAPI()
    run_e2e_config_test(monkeypatch, fixture)

    written = fixture.saves[0]
    assert written.endswith("\n"), "The save must persist the trailing newline verbatim"
    assert written.endswith(servers.CONFIG_ROUND_TRIP_MARKER + "\n")
    assert (
        len(fixture.reads) == 3
    ), "The E2E test must read before saving, after saving, and after restoring"
    assert all(read == read.strip() for read in fixture.reads), "Reads are transport-trimmed"
    assert fixture.reads[1] == written.strip(), "Only the read-back is trimmed"


def test_e2e_oracle_passes_when_save_persists_despite_trim(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression 1: a genuinely persisted save passes even though the read is trimmed."""
    fixture = TransportFaithfulConfigAPI()
    run_e2e_config_test(monkeypatch, fixture)
    assert len(fixture.saves) == 2, "The test must save and then restore"
    assert fixture.disk_state == PROVISIONED_CONFIG.strip(), "Restoration wrote the read-back text"
    assert servers.CONFIG_ROUND_TRIP_MARKER not in fixture.disk_state


def test_e2e_oracle_fails_when_save_does_not_persist(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression 2 (mutation): a silently no-op save still fails the E2E test."""
    fixture = TransportFaithfulConfigAPI("save_noop")
    with pytest.raises(AssertionError, match="did not persist the requested change"):
        run_e2e_config_test(monkeypatch, fixture)
    assert servers.CONFIG_ROUND_TRIP_MARKER not in fixture.disk_state


def test_e2e_oracle_fails_on_substantive_content_difference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression 4: saving a different body is caught despite whitespace normalization."""
    fixture = TransportFaithfulConfigAPI("save_corrupt")
    with pytest.raises(AssertionError, match="did not persist the requested change"):
        run_e2e_config_test(monkeypatch, fixture)
    assert "Adress =" in fixture.reads[1], "The fixture must have stored a different body"


def test_e2e_oracle_verifies_restoration_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression 3: the restoration branch is asserted, and a failed restore fails."""
    fixture = TransportFaithfulConfigAPI()
    run_e2e_config_test(monkeypatch, fixture)
    assert fixture.disk_state == PROVISIONED_CONFIG.strip()
    assert servers.CONFIG_ROUND_TRIP_MARKER not in fixture.disk_state

    unrestored = TransportFaithfulConfigAPI("restore_noop")
    with pytest.raises(AssertionError, match="Original server config was not restored"):
        run_e2e_config_test(monkeypatch, unrestored)
    assert servers.CONFIG_ROUND_TRIP_MARKER in unrestored.disk_state


def test_normalization_ignores_only_surrounding_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """The comparison tolerates the transport trim and nothing else."""
    base = PROVISIONED_CONFIG
    assert servers.normalize_config_text(base + "\n\n") == servers.normalize_config_text(base)
    assert servers.normalize_config_text(base) != servers.normalize_config_text(
        base.replace("Address =", "Adress =")
    )
    assert servers.normalize_config_text(base) != servers.normalize_config_text(base + "X = 1\n")
    assert servers.normalize_config_text(base) != servers.normalize_config_text(
        base.replace("Address", " Address")
    )
