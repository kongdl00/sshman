from unittest.mock import patch, MagicMock, PropertyMock
from click.testing import CliRunner
from sshman.cli import main


class TestCLIStartup:
    def test_help_shows_commands(self):
        """sshman --help lists all subcommands."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "init" in result.output
        assert "add" in result.output
        assert "list" in result.output
        assert "connect" in result.output
        assert "remove" in result.output
        assert "crypto" in result.output

    def test_version(self):
        """sshman --version shows version."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_no_command_shows_help(self):
        """sshman with no args shows help (Click exits 2 for no command)."""
        runner = CliRunner()
        result = runner.invoke(main)
        # Click exits with code 2 when no subcommand provided
        assert result.exit_code in (0, 2)
        assert "Usage:" in result.output or "--help" in result.output


class TestInitCommand:
    @patch("sshman.commands.init_cmd.os.fdopen")
    @patch("sshman.commands.init_cmd.os.open")
    @patch("sshman.commands.init_cmd.ConfigManager")
    def test_init_creates_config(self, mock_cm_class, mock_os_open, mock_fdopen, tmp_path):
        """init creates encrypted config and salt file."""
        mock_cm = MagicMock()
        mock_cm.config_file = MagicMock()
        mock_cm.config_file.exists.return_value = False
        mock_cm.config_dir = MagicMock()
        mock_cm.settings = {
            "default_user": "root",
            "default_port": 22,
            "log_dir": str(tmp_path / ".sshman" / "logs"),
            "connect_timeout": 10,
            "master_password_salt": "",
        }
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["init", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\ntestpass\n")
        assert result.exit_code == 0
        mock_cm.encrypt_file.assert_called_once_with("testpass")


class TestCryptoCommands:
    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_encrypt_success(self, mock_cm_class, tmp_path):
        """crypto encrypt encrypts the temp file."""
        mock_cm = MagicMock()
        mock_cm.temp_file = MagicMock()
        mock_cm.temp_file.exists.return_value = True
        mock_cm.config_file = MagicMock()
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["crypto", "encrypt", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code == 0
        mock_cm.encrypt_file.assert_called_once_with("testpass")

    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_encrypt_no_temp_file(self, mock_cm_class, tmp_path):
        """crypto encrypt fails when no temp file exists."""
        mock_cm = MagicMock()
        mock_cm.temp_file = MagicMock()
        mock_cm.temp_file.exists.return_value = False
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["crypto", "encrypt", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code != 0


class TestAddCommand:
    @patch("sshman.commands.add_cmd.ConfigManager")
    def test_add_session_success(self, mock_cm_class, tmp_path):
        """add creates a new session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm.sessions = []
        mock_cm.config_file = MagicMock()
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "add",
            "--name", "test-server",
            "--host", "10.0.0.1",
            "--user", "root",
            "--tags", "prod,web",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        assert "test-server" in result.output
        assert len(mock_cm.sessions) == 1
        mock_cm.save.assert_called_once()


class TestListCommand:
    @patch("sshman.commands.list_cmd.ConfigManager")
    def test_list_empty(self, mock_cm_class, tmp_path):
        """list with no sessions shows empty message."""
        mock_cm = MagicMock()
        mock_cm.list_sessions.return_value = []
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["list", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code == 0
        assert "No sessions" in result.output


class TestRemoveCommand:
    @patch("sshman.commands.remove_cmd.ConfigManager")
    def test_remove_nonexistent(self, mock_cm_class, tmp_path):
        """remove fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["remove", "nosuch", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code != 0
        assert "not found" in result.output


class TestConnectCommand:
    @patch("sshman.commands.connect_cmd.SSHConnector")
    @patch("sshman.commands.connect_cmd.ConfigManager")
    def test_connect_session_not_found(self, mock_cm_class, mock_connector, tmp_path):
        """connect fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["connect", "nosuch", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code != 0
        assert "not found" in result.output
