from unittest.mock import patch, MagicMock
import pexpect
from sshman.core.connector import SSHConnector, SSHConnectionError
from sshman.core.session import Session


class TestSSHConnectorBuildCommand:
    def test_build_command_minimal(self):
        connector = SSHConnector(Session(name="test", host="10.0.0.1", user="root"))
        cmd = connector.build_command(connector.session)
        assert cmd[0] == "ssh"
        assert "root@10.0.0.1" in cmd

    def test_build_command_custom_port(self):
        connector = SSHConnector(Session(name="test", host="10.0.0.1", user="root", port=2222))
        cmd = connector.build_command(connector.session)
        assert "-p" in cmd
        assert "2222" in cmd

    def test_build_command_identity_file(self):
        import os
        s = Session(name="test", host="10.0.0.1", user="root", identity_file="~/.ssh/id_rsa")
        connector = SSHConnector(s)
        cmd = connector.build_command(connector.session)
        idx = cmd.index("-i")
        assert cmd[idx + 1] == os.path.expanduser("~/.ssh/id_rsa")

    def test_build_command_keepalive(self):
        connector = SSHConnector(Session(name="test", host="10.0.0.1", user="root", keepalive=60))
        cmd = connector.build_command(connector.session)
        assert "-o" in cmd
        assert "ServerAliveInterval=60" in cmd

    def test_build_command_default_port_not_in_args(self):
        connector = SSHConnector(Session(name="test", host="10.0.0.1", user="root"))
        cmd = connector.build_command(connector.session)
        assert "ssh" == cmd[0]


class TestSSHConnectorConnect:
    @patch("sshman.core.connector.SSHConnector._handle_interactive_login")
    @patch("pexpect.spawn")
    def test_connect_calls_spawn(self, mock_spawn, mock_handle):
        mock_child = MagicMock()
        mock_spawn.return_value = mock_child
        connector = SSHConnector(Session(name="test", host="10.0.0.1", user="root"))
        connector.connect()
        mock_spawn.assert_called_once()

    @patch("sshman.core.connector.SSHConnector._handle_interactive_login")
    @patch("pexpect.spawn")
    def test_connect_with_password(self, mock_spawn, mock_handle):
        mock_child = MagicMock()
        mock_spawn.return_value = mock_child
        session = Session(name="test", host="10.0.0.1", user="root", password="secret123")
        connector = SSHConnector(session)
        connector.connect()
        assert connector.session.password == "secret123"


class TestHandleInteractiveLogin:
    def test_login_sends_password_and_returns(self):
        session = Session(name="test", host="10.0.0.1", user="root", password="secret")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        mock_child.expect.return_value = SSHConnector.PATTERN_PASSWORD
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_child.sendline.assert_called_once_with("secret")
        assert mock_child.expect.call_count == 1

    def test_login_hostkey_accepted(self):
        session = Session(name="test", host="10.0.0.1", user="root", password="p")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        mock_child.expect.side_effect = [
            SSHConnector.PATTERN_HOSTKEY, SSHConnector.PATTERN_PASSWORD,
        ]
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_child.sendline.assert_any_call("yes")
        mock_child.sendline.assert_any_call("p")

    def test_login_dead_after_password_raises(self):
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
        session = Session(name="test", host="10.0.0.1", user="root", password="")
        mock_get_ssh.return_value = "keychain-pw"
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.expect.return_value = SSHConnector.PATTERN_PASSWORD
        mock_child.isalive.return_value = True
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_get_ssh.assert_called_once_with("test")
        mock_child.sendline.assert_called_once_with("keychain-pw")


class TestAutoLogInteract:
    """auto_log interact(): raw os.read/os.write select loop."""

    @patch("sys.stdin", new=MagicMock())
    @patch("sys.stdout", new=MagicMock())
    @patch("termios.tcgetattr")
    @patch("termios.tcsetattr")
    @patch("tty.setraw")
    @patch("select.select")
    @patch("os.write")
    @patch("os.read")
    @patch("os.close")
    @patch("os.open")
    def test_auto_log_raw_loop(self, mock_open, mock_close, mock_read,
                                mock_write, mock_select, mock_setraw,
                                mock_tcset, mock_tcget, tmp_path):
        import sys
        sys.stdin.fileno.return_value = 0
        sys.stdout.fileno.return_value = 1

        mock_open.return_value = 99  # fake log fd

        session = Session(name="test", host="10.0.0.1", user="root",
                          auto_log=True)
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.child_fd = 5
        mock_child.buffer = ""  # no leftover from login
        connector.child = mock_child
        connector._log_fh = 99

        # select: child_fd ready → read data → EOF
        mock_select.side_effect = [([5], [], []), ([5], [], [])]
        mock_read.side_effect = [
            b"hello server\n",
            b"",              # child EOF → break outer loop
        ]

        connector.interact()

        # Verify data was teed to both stdout (fd 1) and log (fd 99)
        mock_write.assert_any_call(1, b"hello server\n")
        mock_write.assert_any_call(99, b"hello server\n")
        mock_close.assert_called_once_with(99)

    def test_interact_no_auto_log_delegates_to_pexpect(self):
        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        connector.child = mock_child
        connector.interact()
        mock_child.interact.assert_called_once_with()
