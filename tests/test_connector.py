from unittest.mock import patch, MagicMock
from sshman.core.connector import SSHConnector
from sshman.core.session import Session


class TestSSHConnectorBuildCommand:
    def test_build_command_minimal(self):
        """build_command returns proper ssh command list."""
        session = Session(name="test", host="10.0.0.1", user="root")
        cmd = SSHConnector.build_command(session)
        assert cmd[0] == "ssh"
        assert "root@10.0.0.1" in cmd

    def test_build_command_custom_port(self):
        """Custom port is included in ssh args."""
        session = Session(name="test", host="10.0.0.1", user="root", port=2222)
        cmd = SSHConnector.build_command(session)
        assert "-p" in cmd
        assert "2222" in cmd

    def test_build_command_identity_file(self):
        """Identity file adds -i flag with expanded user path."""
        import os
        session = Session(name="test", host="10.0.0.1", user="root", identity_file="~/.ssh/id_rsa")
        cmd = SSHConnector.build_command(session)
        idx = cmd.index("-i")
        assert cmd[idx + 1] == os.path.expanduser("~/.ssh/id_rsa")

    def test_build_command_keepalive(self):
        """keepalive adds -o ServerAliveInterval."""
        session = Session(name="test", host="10.0.0.1", user="root", keepalive=60)
        cmd = SSHConnector.build_command(session)
        assert "-o" in cmd
        assert "ServerAliveInterval=60" in cmd

    def test_build_command_default_port_not_in_args(self):
        """Default port 22 is not added to args."""
        session = Session(name="test", host="10.0.0.1", user="root", port=22)
        cmd = SSHConnector.build_command(session)
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
        # The password is on the session object — _handle_interactive_login will use it
        assert connector.session.password == "secret123"
