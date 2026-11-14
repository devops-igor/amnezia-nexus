"""Unit tests for server onboarding credential resolution and validation."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests.e2e import test_onboard


def test_get_server_credentials_existing_key_file(tmp_path: Path) -> None:
    """Read private key from a valid existing file path."""
    key_file = tmp_path / "id_ed25519"
    key_content = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-content\n-----END OPENSSH PRIVATE KEY-----"
    )
    key_file.write_text(key_content, encoding="utf-8")

    env = {
        "E2E_SERVER_HOST": "10.0.0.1",
        "E2E_SERVER_SSH_PORT": "2222",
        "E2E_SERVER_SSH_USER": "testuser",
        "E2E_SERVER_SSH_KEY": str(key_file),
        "E2E_SERVER_SSH_PASS": "",
    }
    with patch.dict(os.environ, env, clear=True):
        creds = test_onboard._get_server_credentials()
        assert creds["host"] == "10.0.0.1"
        assert creds["ssh_port"] == 2222
        assert creds["username"] == "testuser"
        assert creds["password"] == ""
        assert creds["private_key"] == key_content
        assert creds["ssh_key_path"] == str(key_file)


def test_get_server_credentials_inline_key() -> None:
    """Read private key directly when provided inline as a string."""
    inline_key = "-----BEGIN RSA PRIVATE KEY-----\ninlinedata\n-----END RSA PRIVATE KEY-----"
    env = {
        "E2E_SERVER_SSH_KEY": inline_key,
        "E2E_SERVER_SSH_PASS": "",
    }
    with patch.dict(os.environ, env, clear=True):
        creds = test_onboard._get_server_credentials()
        assert creds["private_key"] == inline_key
        assert creds["ssh_key_path"] == inline_key


def test_get_server_credentials_fallback_to_ed25519(tmp_path: Path) -> None:
    """Fall back to ~/.ssh/id_ed25519 when specified key path does not exist."""
    fallback_key = tmp_path / "id_ed25519"
    fallback_content = "fallback-ed25519-content"
    fallback_key.write_text(fallback_content, encoding="utf-8")

    def mock_expanduser(path: str) -> str:
        if "id_ed25519" in path and "nonexistent" not in path:
            return str(fallback_key)
        return path

    env = {
        "E2E_SERVER_SSH_KEY": "/tmp/nonexistent_key_path",
        "E2E_SERVER_SSH_PASS": "",
    }
    with (
        patch.dict(os.environ, env, clear=True),
        patch("os.path.expanduser", side_effect=mock_expanduser),
    ):
        creds = test_onboard._get_server_credentials()
        assert creds["private_key"] == fallback_content


def test_get_server_credentials_fallback_to_rsa(tmp_path: Path) -> None:
    """Fall back to ~/.ssh/id_rsa when specified key and id_ed25519 do not exist."""
    rsa_key = tmp_path / "id_rsa"
    rsa_content = "fallback-rsa-content"
    rsa_key.write_text(rsa_content, encoding="utf-8")

    def mock_expanduser(path: str) -> str:
        if "id_rsa" in path and "nonexistent" not in path:
            return str(rsa_key)
        if "id_ed25519" in path:
            return "/tmp/nonexistent_ed25519"
        return path

    env = {
        "E2E_SERVER_SSH_KEY": "/tmp/nonexistent_key_path",
        "E2E_SERVER_SSH_PASS": "",
    }
    with (
        patch.dict(os.environ, env, clear=True),
        patch("os.path.expanduser", side_effect=mock_expanduser),
    ):
        creds = test_onboard._get_server_credentials()
        assert creds["private_key"] == rsa_content


def test_get_server_credentials_nonexistent_key_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Log a warning when the configured key path is missing."""
    env = {
        "E2E_SERVER_SSH_KEY": "/tmp/nonexistent_key_path",
        "E2E_SERVER_SSH_PASS": "testpass",
    }
    with (
        patch.dict(os.environ, env, clear=True),
        patch("os.path.isfile", return_value=False),
        caplog.at_level("WARNING"),
    ):
        creds = test_onboard._get_server_credentials()
        assert creds["password"] == "testpass"
        assert creds["private_key"] == ""
        assert "Configured SSH key path does not exist" in caplog.text


def test_get_server_credentials_empty_when_no_credentials_and_no_fallbacks() -> None:
    """Return empty private_key and password when no credentials or fallbacks exist."""
    env = {
        "E2E_SERVER_SSH_KEY": "",
        "E2E_SERVER_SSH_PASS": "",
    }
    with (
        patch.dict(os.environ, env, clear=True),
        patch("os.path.isfile", return_value=False),
    ):
        creds = test_onboard._get_server_credentials()
        assert creds["private_key"] == ""
        assert creds["password"] == ""


def test_get_server_credentials_password_bypasses_fallback() -> None:
    """When password is provided and key is empty, do not check fallback keys."""
    env = {
        "E2E_SERVER_SSH_KEY": "",
        "E2E_SERVER_SSH_PASS": "SecretPassword123",
        "E2E_SERVER_SSH_PORT": "invalid_port",
    }
    with patch.dict(os.environ, env, clear=True):
        creds = test_onboard._get_server_credentials()
        assert creds["password"] == "SecretPassword123"
        assert creds["private_key"] == ""
        assert creds["ssh_port"] == 22


def test_onboard_server_add_fails_fast_when_credentials_missing() -> None:
    """Fail immediately in test_onboard_server_add with descriptive message."""
    page_mock = MagicMock()
    env = {
        "E2E_SERVER_SSH_KEY": "/home/user/.ssh/id_ed25519",
        "E2E_SERVER_SSH_PASS": "",
    }
    with (
        patch.dict(os.environ, env, clear=True),
        patch("os.path.isfile", return_value=False),
    ):
        expected_msg = (
            "No valid SSH key or password found for onboarding Server 1. "
            "Configured E2E_SERVER_SSH_KEY='/home/user/.ssh/id_ed25519' was not found."
        )
        with pytest.raises(pytest.fail.Exception, match=expected_msg):
            test_onboard.test_onboard_server_add(page_mock, "http://127.0.0.1:8443", "csrf_token")


def test_onboard_server_add_proceeds_with_valid_key() -> None:
    """Successfully send credentials and confirm fingerprint when valid key is provided."""
    page_mock = MagicMock()
    env = {
        "E2E_SERVER_SSH_KEY": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "E2E_SERVER_SSH_PASS": "",
    }

    add_response = {
        "status": 200,
        "body": {
            "status": "pending_fingerprint_confirmation",
            "fingerprint": "SHA256:abc123testfingerprint",
            "server_info": "Linux ubuntu 5.15.0",
        },
    }
    confirm_response = {
        "status": 200,
        "body": {
            "status": "ok",
            "server_id": 1,
        },
    }

    with (
        patch.dict(os.environ, env, clear=True),
        patch(
            "tests.e2e.test_onboard.api_post",
            side_effect=[add_response, confirm_response],
        ) as mock_api_post,
    ):
        test_onboard.test_onboard_server_add(page_mock, "http://127.0.0.1:8443", "csrf_token")
        assert mock_api_post.call_count == 2
        call1_args = mock_api_post.call_args_list[0]
        assert call1_args[0][1] == "/api/servers/add"
        assert call1_args[0][2]["private_key"] == env["E2E_SERVER_SSH_KEY"]


def test_onboard_server_reachability() -> None:
    """Verify server reachability check logic."""
    page_mock = MagicMock()
    mock_resp = {
        "status": 200,
        "body": {"connection": "ok", "docker_installed": True},
    }
    with patch("tests.e2e.test_onboard.api_post", return_value=mock_resp) as mock_api:
        test_onboard.test_onboard_server_reachability(
            page_mock, "http://127.0.0.1:8443", "csrf_token"
        )
        assert mock_api.called


def test_onboard_install_amneziawg() -> None:
    """Verify AWG protocol installation API call."""
    page_mock = MagicMock()
    mock_resp = {
        "status": 200,
        "body": {"status": "ok", "protocol": "awg"},
    }
    with patch("tests.e2e.test_onboard.api_post", return_value=mock_resp) as mock_api:
        test_onboard.test_onboard_install_amneziawg(
            page_mock, "http://127.0.0.1:8443", "csrf_token"
        )
        assert mock_api.called


def test_onboard_verify_awg_container_healthy() -> None:
    """Verify AWG container health polling logic."""
    page_mock = MagicMock()
    mock_resp = {
        "status": 200,
        "body": {"protocols": {"awg": {"container_running": True}}},
    }
    with patch("tests.e2e.test_onboard.api_post", return_value=mock_resp) as mock_api:
        test_onboard.test_onboard_verify_awg_container_healthy(
            page_mock, "http://127.0.0.1:8443", "csrf_token"
        )
        assert mock_api.called
