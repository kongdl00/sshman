import errno
from unittest.mock import patch, MagicMock

import pexpect
import pytest

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
    def test_login_sends_password_then_timeout(self):
        """PASSWORD → TIMEOUT (connected) — password sent once, then return."""
        session = Session(name="test", host="10.0.0.1", user="root", password="secret")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        mock_child.expect.side_effect = [
            SSHConnector.PATTERN_PASSWORD, SSHConnector.PATTERN_TIMEOUT,
        ]
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_child.sendline.assert_called_once_with("secret")
        assert mock_child.expect.call_count == 2

    def test_login_hostkey_then_password_then_timeout(self):
        session = Session(name="test", host="10.0.0.1", user="root", password="p")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        mock_child.expect.side_effect = [
            SSHConnector.PATTERN_HOSTKEY, SSHConnector.PATTERN_PASSWORD,
            SSHConnector.PATTERN_TIMEOUT,
        ]
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_child.sendline.assert_any_call("yes")
        mock_child.sendline.assert_any_call("p")
        assert mock_child.expect.call_count == 3

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
        mock_child.isalive.return_value = True
        mock_child.expect.side_effect = [
            SSHConnector.PATTERN_PASSWORD, SSHConnector.PATTERN_TIMEOUT,
        ]
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_get_ssh.assert_called_once_with("test")
        mock_child.sendline.assert_called_once_with("keychain-pw")

    def test_jumphost_two_passwords(self):
        """Jumphost pw + target pw → both sent in order."""
        jh = Session(name="jump", host="10.0.0.1", user="ops", password="jpw")
        tg = Session(name="target", host="10.0.1.1", user="root",
                      password="tpw", jumphost="jump")
        connector = SSHConnector(tg, sessions=[jh, tg])
        mock_child = MagicMock()
        mock_child.isalive.return_value = True
        mock_child.expect.side_effect = [
            SSHConnector.PATTERN_HOSTKEY,
            SSHConnector.PATTERN_PASSWORD,   # jumphost
            SSHConnector.PATTERN_PASSWORD,   # target
            SSHConnector.PATTERN_TIMEOUT,
        ]
        connector.child = mock_child
        connector._handle_interactive_login()
        mock_child.sendline.assert_any_call("yes")
        mock_child.sendline.assert_any_call("jpw")
        mock_child.sendline.assert_any_call("tpw")
        assert mock_child.expect.call_count == 4


class TestInteract:
    @patch("sshman.core.connector.sys.stdin")
    @patch("sshman.core.connector.sys.stdout")
    @patch("sshman.core.connector.termios")
    @patch("sshman.core.connector.tty")
    @patch("sshman.core.connector.select.select")
    def test_interact_loop_exits_when_child_dies(
        self, mock_select, mock_tty, mock_termios, mock_stdout, mock_stdin
    ):
        """Custom interact loop stops and reports when the child exits."""
        mock_stdin.fileno.return_value = 0
        mock_stdout.fileno.return_value = 1

        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.child_fd = 5
        mock_child.encoding = "utf-8"
        mock_child.buffer = ""
        connector.child = mock_child

        # Child alive for two iterations, then dead.  The post-mortem
        # report does *not* call isalive() again — it checks self.child.
        mock_child.isalive.side_effect = [True, True, False]
        mock_select.return_value = ([], [], [])  # no fds ready → timeout

        connector.interact()

        assert mock_child.isalive.call_count == 3

    @patch("sshman.core.connector.sys.stdin")
    @patch("sshman.core.connector.sys.stdout")
    @patch("sshman.core.connector.termios")
    @patch("sshman.core.connector.tty")
    @patch("sshman.core.connector.select.select")
    @patch("sshman.core.connector.os.write")
    def test_interact_prints_disconnect_on_eof(
        self, mock_write, mock_select, mock_tty, mock_termios,
        mock_stdout, mock_stdin
    ):
        """When child EOF is detected, disconnect message is sent to stderr."""
        mock_stdin.fileno.return_value = 0
        mock_stdout.fileno.return_value = 1

        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        mock_child = MagicMock()
        mock_child.child_fd = 5
        mock_child.encoding = "utf-8"
        mock_child.buffer = ""
        connector.child = mock_child

        mock_child.isalive.return_value = True

        with patch("sshman.core.connector.os.read", return_value=b""):
            mock_select.return_value = ([5], [], [])  # child fd ready
            connector.interact()

        # The disconnect message is sent to stderr (fd may vary under pytest).
        found = any(
            len(c.args) >= 2
            and isinstance(c.args[1], bytes)
            and b"Connection closed" in c.args[1]
            for c in mock_write.call_args_list
        )
        assert found, f"Expected disconnect message, got {mock_write.call_args_list}"

    def test_interact_raises_when_not_connected(self):
        """interact raises SSHConnectionError when child is None."""
        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        with pytest.raises(SSHConnectionError):
            connector.interact()
