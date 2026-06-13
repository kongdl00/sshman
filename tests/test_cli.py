from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from sshman.cli import main


# ---------------------------------------------------------------------------
# Helpers — used by most tests to prevent real keychain access
# ---------------------------------------------------------------------------

def _mock_keyring_get_none():
    """patch get_password to always return None (no cached password)."""
    return patch("sshman.commands._helpers.get_password", return_value=None)


def _mock_keyring_set():
    """patch set_password to be a no-op."""
    return patch("sshman.commands._helpers.set_password")


def _apply_keyring_mocks(test_fn):
    """Decorator: mock get_password→None + set_password→noop for a test."""
    return _mock_keyring_get_none()(_mock_keyring_set()(test_fn))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCLIStartup:
    def test_help_shows_commands(self):
        """sshman --help lists all subcommands (including keyring)."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "init" in result.output
        assert "add" in result.output
        assert "list" in result.output
        assert "connect" in result.output
        assert "remove" in result.output
        assert "edit" in result.output
        assert "crypto" in result.output
        assert "keyring" in result.output

    def test_version(self):
        """sshman --version shows version."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_no_command_shows_help(self):
        """sshman with no args shows help."""
        runner = CliRunner()
        result = runner.invoke(main)
        assert result.exit_code in (0, 2)
        assert "Usage:" in result.output or "--help" in result.output


class TestInitCommand:
    @patch("sshman.core.keyring.set_password")
    @patch("sshman.commands.init_cmd.os.fdopen")
    @patch("sshman.commands.init_cmd.os.open")
    @patch("sshman.commands.init_cmd.ConfigManager")
    def test_init_creates_config(self, mock_cm_class, mock_os_open,
                                  mock_fdopen, mock_set_pw, tmp_path):
        """init creates encrypted config and salt file."""
        mock_cm = MagicMock()
        mock_cm.config_file = MagicMock()
        mock_cm.config_file.exists.return_value = False
        mock_cm.config_dir = MagicMock()
        mock_cm.settings = {
            "default_user": "root", "default_port": 22,
            "log_dir": str(tmp_path / ".sshman" / "logs"),
            "connect_timeout": 10, "master_password_salt": "",
        }
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["init", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\ntestpass\ny\n",
        )
        assert result.exit_code == 0
        mock_cm.encrypt_file.assert_called_once_with("testpass")


class TestCryptoCommands:
    @patch("sshman.commands.crypto_cmd.set_password")
    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_encrypt_success(self, mock_cm_class, mock_set_pw, tmp_path):
        """crypto encrypt encrypts the temp file."""
        mock_cm = MagicMock()
        mock_cm.temp_file = MagicMock()
        mock_cm.temp_file.exists.return_value = True
        mock_cm.config_file = MagicMock()
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["crypto", "encrypt", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\ny\n",
        )
        assert result.exit_code == 0
        mock_cm.encrypt_file.assert_called_once_with("testpass")

    @patch("sshman.commands.crypto_cmd.set_password")
    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_encrypt_no_temp_file(self, mock_cm_class, mock_set_pw, tmp_path):
        """crypto encrypt fails when no temp file exists."""
        mock_cm = MagicMock()
        mock_cm.temp_file = MagicMock()
        mock_cm.temp_file.exists.return_value = False
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["crypto", "encrypt", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\ny\n",
        )
        assert result.exit_code != 0

    @patch("sshman.commands.crypto_cmd.set_password")
    @patch("sshman.commands.crypto_cmd.get_password", return_value=None)
    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_decrypt_success(self, mock_cm_class, mock_get_pw, mock_set_pw, tmp_path):
        """crypto decrypt outputs YAML."""
        mock_cm = MagicMock()
        mock_cm.config_file = MagicMock()
        mock_cm.config_file.exists.return_value = True
        mock_cm.decrypt_file.return_value = {
            "sessions": [], "settings": {"default_user": "root"},
        }
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["crypto", "decrypt", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code == 0
        assert "sessions" in result.output


class TestAddCommand:
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.add_cmd.ConfigManager")
    def test_add_session_success(self, mock_cm_class, mock_get, mock_set, tmp_path):
        """add creates a new session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm.sessions = []
        mock_cm.config_file = MagicMock()
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "add", "--name", "test-server", "--host", "10.0.0.1",
            "--user", "root", "--tags", "prod,web",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        assert "test-server" in result.output
        assert len(mock_cm.sessions) == 1
        mock_cm.save.assert_called_once()

    @patch("sshman.core.keyring.set_ssh_password")
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.add_cmd.ConfigManager")
    def test_add_with_keychain_stores_in_keychain(self, mock_cm_class,
                                                   mock_get, mock_set_master,
                                                   mock_set_ssh, tmp_path):
        """add --password X --keychain stores SSH password in keychain, not YAML."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm.sessions = []
        mock_cm.config_file = MagicMock()
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "add", "--name", "test-server", "--host", "10.0.0.1",
            "--user", "root", "--password", "ssh-secret", "--keychain",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        mock_set_ssh.assert_called_once_with("test-server", "ssh-secret")
        # Password should NOT be in the YAML session
        saved_session = mock_cm.sessions[0]
        assert saved_session.password == ""


class TestListCommand:
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.list_cmd.ConfigManager")
    def test_list_empty(self, mock_cm_class, mock_get, mock_set, tmp_path):
        """list with no sessions shows empty message."""
        mock_cm = MagicMock()
        mock_cm.list_sessions.return_value = []
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["list", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code == 0
        assert "No sessions" in result.output


class TestRemoveCommand:
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.remove_cmd.ConfigManager")
    def test_remove_nonexistent(self, mock_cm_class, mock_get, mock_set, tmp_path):
        """remove fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["remove", "nosuch", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code != 0
        assert "not found" in result.output


class TestEditCommand:
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.edit_cmd.ConfigManager")
    def test_edit_updates_port_and_tags(self, mock_cm_class, mock_get,
                                         mock_set, tmp_path):
        """edit updates only specified fields."""
        from sshman.core.session import Session
        mock_cm = MagicMock()
        session = Session(name="test", host="10.0.0.1", user="root",
                          port=22, tags=["old"])
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "edit", "test", "--port", "2222", "--tags", "prod,web",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        assert session.port == 2222
        assert session.tags == ["prod", "web"]
        mock_cm.save.assert_called_once()

    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.edit_cmd.ConfigManager")
    def test_edit_session_not_found(self, mock_cm_class, mock_get,
                                     mock_set, tmp_path):
        """edit fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["edit", "nosuch", "--port", "2222",
                   "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.edit_cmd.ConfigManager")
    def test_edit_auto_log_and_jumphost(self, mock_cm_class, mock_get,
                                         mock_set, tmp_path):
        """edit --auto-log true --jumphost bastion sets both fields."""
        from sshman.core.session import Session
        mock_cm = MagicMock()
        session = Session(name="test", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "edit", "test",
            "--auto-log", "true",
            "--jumphost", "bastion",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        assert session.auto_log is True
        assert session.jumphost == "bastion"
        mock_cm.save.assert_called_once()


class TestConnectCommand:
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands.connect_cmd.SSHConnector")
    @patch("sshman.commands.connect_cmd.ConfigManager")
    def test_connect_session_not_found(self, mock_cm_class, mock_connector,
                                        mock_get, mock_set, tmp_path):
        """connect fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["connect", "nosuch", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code != 0
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# Keyring command tests
# ---------------------------------------------------------------------------


class TestKeyringCommands:
    @patch("sshman.commands.keyring_cmd.get_password", return_value=None)
    def test_keyring_status_not_stored(self, mock_get):
        """keyring status reports no stored password."""
        runner = CliRunner()
        result = runner.invoke(main, ["keyring", "status"])
        assert result.exit_code == 0
        assert "No master password" in result.output

    @patch("sshman.commands.keyring_cmd.get_password", return_value="testpw")
    def test_keyring_status_stored(self, mock_get):
        """keyring status reports password is stored."""
        runner = CliRunner()
        result = runner.invoke(main, ["keyring", "status"])
        assert result.exit_code == 0
        assert "stored" in result.output.lower()

    @patch("sshman.commands.keyring_cmd.clear_password")
    def test_keyring_clear(self, mock_clear):
        """keyring clear calls clear_password."""
        runner = CliRunner()
        result = runner.invoke(main, ["keyring", "clear"])
        assert result.exit_code == 0
        mock_clear.assert_called_once()

    @patch("sshman.commands.keyring_cmd.set_password")
    @patch("sshman.commands.keyring_cmd.ConfigManager")
    def test_keyring_set_success(self, mock_cm_class, mock_set, tmp_path):
        """keyring set stores password after verification."""
        mock_cm = MagicMock()
        mock_cm.config_file = MagicMock()
        mock_cm.config_file.exists.return_value = True
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["keyring", "set", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code == 0
        mock_cm.load.assert_called_once_with("testpass")
        mock_set.assert_called_once_with("testpass")

    @patch("sshman.commands.keyring_cmd.ConfigManager")
    def test_keyring_set_no_config(self, mock_cm_class, tmp_path):
        """keyring set fails when no config exists."""
        mock_cm = MagicMock()
        mock_cm.config_file = MagicMock()
        mock_cm.config_file.exists.return_value = False
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(
            main, ["keyring", "set", "--config-dir", str(tmp_path / ".sshman")],
            input="testpass\n",
        )
        assert result.exit_code != 0
        assert "sshman init" in result.output

    @patch("sshman.commands.keyring_cmd.clear_ssh_password")
    def test_keyring_ssh_clear(self, mock_clear_ssh):
        """keyring ssh-clear clears SSH password for a session."""
        runner = CliRunner()
        result = runner.invoke(main, ["keyring", "ssh-clear", "prod-web"])
        assert result.exit_code == 0
        mock_clear_ssh.assert_called_once_with("prod-web")
