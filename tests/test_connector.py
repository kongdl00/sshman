from pathlib import Path
from unittest.mock import patch, MagicMock
import pexpect
from sshman.core.connector import SSHConnector, SSHConnectionError
from sshman.core.session import Session


class TestSSHConnectorBuildCommand:
    def test_build_command_minimal(self):
        """build_command returns proper ssh command list."""
        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        cmd = connector.build_command(session)
        assert cmd[0] == "ssh"
        assert "root@10.0.0.1" in cmd

    def test_build_command_custom_port(self):
        """Custom port is included in ssh args."""
        session = Session(name="test", host="10.0.0.1", user="root", port=2222)
        connector = SSHConnector(session)
        cmd = connector.build_command(session)
        assert "-p" in cmd
        assert "2222" in cmd

    def test_build_command_identity_file(self):
        """Identity file adds -i flag with expanded user path."""
        import os
        session = Session(name="test", host="10.0.0.1", user="root", identity_file="~/.ssh/id_rsa")
        connector = SSHConnector(session)
        cmd = connector.build_command(session)
        idx = cmd.index("-i")
        assert cmd[idx + 1] == os.path.expanduser("~/.ssh/id_rsa")

    def test_build_command_keepalive(self):
        """keepalive adds -o ServerAliveInterval."""
        session = Session(name="test", host="10.0.0.1", user="root", keepalive=60)
        connector = SSHConnector(session)
        cmd = connector.build_command(session)
        assert "-o" in cmd
        assert "ServerAliveInterval=60" in cmd

    def test_build_command_default_port_not_in_args(self):
        """Default port 22 is not added to args."""
        session = Session(name="test", host="10.0.0.1", user="root", port=22)
        connector = SSHConnector(session)
        cmd = connector.build_command(session)
        assert "ssh" == cmd[0]


class TestSSHConnectorConnect:
    @patch("sshman.core.connector.SSHConnector._handle_interactive_login")
    @patch("pexpect.spawn")
    def test_connect_calls_spawn(self, mock_spawn, mock_handle):
        """connect spawns a pexpect child with SSH command."""
        mock_child = MagicMock()
        mock_spawn.return_value = mock_child
        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        connector.connect()
        mock_spawn.assert_called_once()
        args = mock_spawn.call_args[0][0]
        assert "ssh" in args

    @patch("sshman.core.connector.SSHConnector._handle_interactive_login")
    @patch("pexpect.spawn")
    def test_connect_with_password_sends_password(self, mock_spawn, mock_handle):
        """When session has password, connector stores it for _handle_interactive_login."""
        mock_child = MagicMock()
        mock_spawn.return_value = mock_child
        session = Session(name="test", host="10.0.0.1", user="root", password="secret123")
        connector = SSHConnector(session)
        connector.connect()
        assert connector.session.password == "secret123"


class TestHandleInteractiveLogin:
    def test_login_sends_password_and_returns_without_consuming_output(self):
        """After password is sent, function returns without calling
        expect() for shell prompt — preserving MOTD/prompt in buffer."""
        session = Session(name="test", host="10.0.0.1", user="root", password="secret")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        # First expect() matches password prompt, then we return
        mock_child.expect.return_value = SSHConnector.PATTERN_PASSWORD
        connector.child = mock_child

        connector._handle_interactive_login()

        # Should have matched password prompt
        mock_child.expect.assert_called_once()
        # Should have sent the password
        mock_child.sendline.assert_called_once_with("secret")
        # Should have checked that child is alive
        mock_child.isalive.assert_called_once()
        # CRITICAL: should NOT have called expect() a second time
        # (which would consume MOTD/banners/prompt from the buffer)
        assert mock_child.expect.call_count == 1

    def test_login_hostkey_accepted(self):
        """Host key prompt is accepted with 'yes'."""
        session = Session(name="test", host="10.0.0.1", user="root", password="p")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        # First: host key prompt, second: password prompt
        mock_child.expect.side_effect = [
            SSHConnector.PATTERN_HOSTKEY,
            SSHConnector.PATTERN_PASSWORD,
        ]
        connector.child = mock_child

        connector._handle_interactive_login()

        mock_child.sendline.assert_any_call("yes")
        mock_child.sendline.assert_any_call("p")
        assert mock_child.expect.call_count == 2

    def test_login_dead_after_password_raises(self):
        """If child dies after sending password, raise SSHConnectionError."""
        session = Session(name="test", host="10.0.0.1", user="root", password="pw")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.expect.return_value = SSHConnector.PATTERN_PASSWORD
        mock_child.isalive.return_value = False
        connector.child = mock_child

        try:
            connector._handle_interactive_login()
        except SSHConnectionError as e:
            assert "connection lost" in str(e).lower()
        else:
            raise AssertionError("Expected SSHConnectionError")

    @patch("sshman.core.keyring.get_ssh_password")
    def test_login_falls_back_to_keychain(self, mock_get_ssh):
        """When session.password is empty, check keychain for SSH password."""
        session = Session(name="test", host="10.0.0.1", user="root",
                          password="")  # no password in config
        mock_get_ssh.return_value = "keychain-pw"
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.expect.return_value = SSHConnector.PATTERN_PASSWORD
        mock_child.isalive.return_value = True
        connector.child = mock_child

        connector._handle_interactive_login()

        mock_get_ssh.assert_called_once_with("test")
        mock_child.sendline.assert_called_once_with("keychain-pw")

    @patch("sshman.core.keyring.get_ssh_password", return_value=None)
    def test_login_keychain_empty_falls_back_to_config(self, mock_get_ssh):
        """When keychain returns None, use session.password from config."""
        session = Session(name="test", host="10.0.0.1", user="root",
                          password="config-pw")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.expect.return_value = SSHConnector.PATTERN_PASSWORD
        mock_child.isalive.return_value = True
        connector.child = mock_child

        connector._handle_interactive_login()

        # Should NOT send empty string — should fall back to config password
        mock_child.sendline.assert_called_once_with("config-pw")


class TestAutoLogInteract:
    def test_interact_with_auto_log_uses_output_filter(self, tmp_path):
        """When auto_log is set, interact() tees child output to log file."""
        session = Session(name="test", host="10.0.0.1", user="root",
                          auto_log=True)
        connector = SSHConnector(session)
        log_path = tmp_path / "test.log"
        connector._log_path = str(log_path)
        mock_child = MagicMock()

        def fake_interact(**kwargs):
            fn = kwargs.get("output_filter")
            assert fn is not None
            assert fn("line1\n") == "line1\n"
            fn("line2\n")

        mock_child.interact = fake_interact
        connector.child = mock_child

        connector.interact()

        # Verify log file contains the teed output
        log_content = log_path.read_text()
        assert "line1" in log_content
        assert "line2" in log_content

    def test_interact_without_auto_log_no_output_filter(self):
        """When auto_log is not set, interact() passes no output_filter."""
        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        connector._log_path = None
        mock_child = MagicMock()
        connector.child = mock_child

        connector.interact()

        mock_child.interact.assert_called_once_with()
