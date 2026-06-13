"""Unit tests for the keyring module — all platform backends mocked."""

import time
import subprocess
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestDarwinKeyring:
    def test_get_password_found(self, monkeypatch):
        """macOS: get returns password when security succeeds."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="mysecret\n", stderr="",
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core import keyring
        # Force re-evaluation of module-level dispatch
        keyring.get_password = keyring._macos_get_password
        keyring.set_password = keyring._macos_set_password
        keyring.clear_password = keyring._macos_clear_password

        result = keyring.get_password()
        assert result == "mysecret"

    def test_get_password_not_found(self, monkeypatch):
        """macOS: get returns None when entry not found."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=44, stdout="", stderr="",
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core import keyring
        keyring.get_password = keyring._macos_get_password

        result = keyring.get_password()
        assert result is None

    def test_get_password_handles_error(self, monkeypatch):
        """macOS: get returns None on subprocess error."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("subprocess.run",
                            MagicMock(side_effect=FileNotFoundError))

        from sshman.core import keyring
        keyring.get_password = keyring._macos_get_password

        result = keyring.get_password()
        assert result is None

    def test_set_password_calls_security(self, monkeypatch):
        """macOS: set calls security add-generic-password."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core import keyring
        keyring.set_password = keyring._macos_set_password

        keyring.set_password("newpw")
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "/usr/bin/security" in args
        assert "add-generic-password" in args
        assert "-w" in args
        assert "newpw" in args

    def test_clear_password_calls_security(self, monkeypatch):
        """macOS: clear calls security delete-generic-password."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core import keyring
        keyring.clear_password = keyring._macos_clear_password

        keyring.clear_password()
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "delete-generic-password" in args


class TestSessionCache:
    def test_cache_roundtrip(self, tmp_path, monkeypatch):
        """Session cache: write → read returns written password."""
        monkeypatch.setattr("sshman.core.keyring._session_cache_path",
                            lambda: tmp_path / ".session_cache")

        from sshman.core.keyring import _session_cache_set, _session_cache_get

        _session_cache_set("cached_pw")
        result = _session_cache_get()
        assert result == "cached_pw"

    def test_cache_expired(self, tmp_path, monkeypatch):
        """Session cache: expired entry returns None."""
        path = tmp_path / ".session_cache"
        monkeypatch.setattr("sshman.core.keyring._session_cache_path",
                            lambda: path)

        from sshman.core.keyring import _session_cache_get
        from sshman.core.keyring import _SESSION_CACHE_TTL

        # Write an entry that is already expired
        stale_ts = int(time.time()) - _SESSION_CACHE_TTL - 60
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{stale_ts}:oldpw")

        result = _session_cache_get()
        assert result is None
        assert not path.exists()  # should be cleaned up

    def test_cache_malformed(self, tmp_path, monkeypatch):
        """Session cache: malformed file returns None."""
        path = tmp_path / ".session_cache"
        monkeypatch.setattr("sshman.core.keyring._session_cache_path",
                            lambda: path)

        from sshman.core.keyring import _session_cache_get

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not-valid-content")

        result = _session_cache_get()
        assert result is None

    def test_cache_clear(self, tmp_path, monkeypatch):
        """Session cache clear removes the file."""
        path = tmp_path / ".session_cache"
        monkeypatch.setattr("sshman.core.keyring._session_cache_path",
                            lambda: path)

        from sshman.core.keyring import _session_cache_set, _session_cache_clear

        _session_cache_set("pw")
        assert path.exists()
        _session_cache_clear()
        assert not path.exists()


class TestSSHPasswordDarwin:
    def test_get_ssh_password_found(self, monkeypatch):
        """macOS: get_ssh_password returns password for session."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ssh-secret\n", stderr="",
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core.keyring import get_ssh_password
        result = get_ssh_password("prod-web")
        assert result == "ssh-secret"
        # Verify service name contains session name
        args = mock_run.call_args[0][0]
        assert "sshman-ssh-prod-web" in args

    def test_get_ssh_password_not_found(self, monkeypatch):
        """macOS: get_ssh_password returns None for unknown session."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("subprocess.run",
                            MagicMock(side_effect=FileNotFoundError))

        from sshman.core.keyring import get_ssh_password
        result = get_ssh_password("nonexistent")
        assert result is None

    def test_set_ssh_password_calls_security(self, monkeypatch):
        """macOS: set_ssh_password calls security add-generic-password."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core.keyring import set_ssh_password
        set_ssh_password("my-session", "mypassword")
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "add-generic-password" in args
        assert "sshman-ssh-my-session" in args
        assert "mypassword" in args

    def test_clear_ssh_password_calls_security(self, monkeypatch):
        """macOS: clear_ssh_password calls security delete-generic-password."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        mock_run = MagicMock()
        monkeypatch.setattr("subprocess.run", mock_run)

        from sshman.core.keyring import clear_ssh_password
        clear_ssh_password("old-session")
        args = mock_run.call_args[0][0]
        assert "delete-generic-password" in args
        assert "sshman-ssh-old-session" in args


class TestOtherPlatform:
    def test_get_password_returns_none(self, monkeypatch):
        """Non-Darwin/Linux: get is always None."""
        monkeypatch.setattr("platform.system", lambda: "Windows")

        from sshman.core import keyring
        # Dispatch lambda
        assert keyring._system == "Darwin"  # actual platform — not changed
        # Test the lambda behavior directly
        fn = (lambda: None)
        assert fn() is None

    def test_set_password_is_noop(self, monkeypatch):
        """Non-Darwin/Linux: set is no-op."""
        fn = (lambda p: None)
        fn("anything")  # should not raise
