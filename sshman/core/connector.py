import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import pexpect

from sshman.core.session import Session


class SSHConnectionError(Exception):
    """Raised when SSH connection fails."""
    pass


class SSHConnector:
    """Manages SSH connections via pexpect, handling interactive prompts."""

    PATTERNS = [
        r"(?i)password:",
        r"(?i)are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)",
        r"(?i)passcode:",
        r"(?i)verification code:",
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]

    PATTERN_PASSWORD = 0
    PATTERN_HOSTKEY = 1
    PATTERN_MFA = 2
    PATTERN_MFA_2 = 3
    PATTERN_EOF = 4
    PATTERN_TIMEOUT = 5

    def __init__(self, session: Session,
                 sessions: Optional[list[Session]] = None) -> None:
        self.session = session
        self.sessions = sessions or []
        self.child: pexpect.spawn | None = None
        self._log_path: str | None = None

    def _find_session(self, name: str) -> Optional[Session]:
        for s in self.sessions:
            if s.name == name:
                return s
        return None

    def build_command(self, session: Session,
                      no_tunnels: bool = False,
                      tunnel_only: bool = False) -> list[str]:
        """Build the SSH command list from a Session."""
        cmd = ["ssh"]
        if session.port != 22:
            cmd.extend(["-p", str(session.port)])
        if session.identity_file:
            cmd.extend(["-i", os.path.expanduser(session.identity_file)])
        if session.keepalive > 0:
            cmd.extend(["-o", f"ServerAliveInterval={session.keepalive}"])
        cmd.extend(["-o", "StrictHostKeyChecking=ask"])

        if session.jumphost:
            jump = self._find_session(session.jumphost)
            if jump:
                cmd.extend(["-J", f"{jump.user}@{jump.host}:{jump.port}"])
            else:
                cmd.extend(["-J", session.jumphost])

        if not no_tunnels:
            for t in session.tunnels:
                ttype = t.get("type", "local")
                lp = t.get("local_port", "")
                rh = t.get("remote_host", "127.0.0.1")
                rp = t.get("remote_port", "")
                if ttype == "local":
                    cmd.extend(["-L", f"{lp}:{rh}:{rp}"])
                elif ttype == "remote":
                    cmd.extend(["-R", f"{lp}:{rh}:{rp}"])
                elif ttype == "dynamic":
                    cmd.extend(["-D", str(lp)])

        if tunnel_only:
            cmd.append("-N")

        cmd.append(f"{session.user}@{session.host}")
        return cmd

    def connect(self, *, no_tunnels: bool = False,
                tunnel_only: bool = False) -> pexpect.spawn:
        """Spawn SSH connection and handle interactive authentication.

        Logging (when session.auto_log is True) uses interact()'s
        output_filter to tee child output to a log file, completely
        bypassing pexpect's built-in logfile/logfile_read which call
        flush() on every write and cause interact() to freeze on macOS.
        """
        cmd = self.build_command(self.session,
                                 no_tunnels=no_tunnels,
                                 tunnel_only=tunnel_only)

        self.child = pexpect.spawn(
            " ".join(cmd),
            encoding="utf-8",
            timeout=self.session.keepalive if self.session.keepalive > 0 else 30,
            dimensions=(24, 80),
        )

        if self.session.auto_log:
            log_dir = Path.home() / ".sshman" / "logs" / self.session.name
            log_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            self._log_path = str(log_dir / f"{ts}.log")

        try:
            self._handle_interactive_login()
        except pexpect.TIMEOUT:
            self.child.close()
            raise SSHConnectionError(
                f"Connection to {self.session.name} ({self.session.host}) timed out"
            )
        except pexpect.EOF:
            self.child.close()
            raise SSHConnectionError(
                f"Connection to {self.session.name} ({self.session.host}) closed "
                f"unexpectedly.\nSSH output:\n{self.child.before}"
            )

        return self.child

    def _handle_interactive_login(self) -> None:
        """Process interactive prompts until authenticated."""
        assert self.child is not None

        while True:
            idx = self.child.expect(self.PATTERNS)

            if idx == self.PATTERN_HOSTKEY:
                self.child.sendline("yes")
                continue

            elif idx in (self.PATTERN_PASSWORD, self.PATTERN_MFA, self.PATTERN_MFA_2):
                password = self.session.password
                if not password:
                    from sshman.core.keyring import get_ssh_password
                    password = get_ssh_password(self.session.name)
                if not password:
                    import getpass
                    password = getpass.getpass(
                        f"Password for {self.session.user}@{self.session.host}: "
                    )
                self.child.sendline(password)
                time.sleep(0.8)

                if not self.child.isalive():
                    raise SSHConnectionError(
                        f"SSH connection lost after authentication — "
                        f"check credentials for {self.session.user}@{self.session.host}"
                    )
                return

            elif idx == self.PATTERN_EOF:
                raise SSHConnectionError(
                    f"SSH connection to {self.session.host} ended unexpectedly"
                )

            elif idx == self.PATTERN_TIMEOUT:
                raise pexpect.TIMEOUT("timed out waiting for SSH prompt")

    def interact(self) -> None:
        """Hand control to the user for interactive shell session.

        When auto_log is enabled we run our own select()-based I/O loop
        that reads through pexpect (so its internal buffer stays in sync)
        but writes output to the terminal and log directly via os.write,
        bypassing pexpect's logfile/logfile_read flush() path entirely.
        """
        if self.child is None:
            raise SSHConnectionError("not connected — call connect() first")

        if not self._log_path:
            self.child.interact()
            return

        import select
        import sys
        import tty
        import termios

        log_fh = open(self._log_path, "w", encoding="utf-8")
        child_fd = self.child.child_fd
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()

        # Drain any output pexpect already buffered during login handshake
        self._drain_pexpect_buffer(stdout_fd, log_fh)

        old_tc = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)

        try:
            while True:
                r, _, _ = select.select([child_fd, stdin_fd], [], [])
                if child_fd in r:
                    try:
                        data = self.child.read_nonblocking(size=4096, timeout=0)
                    except pexpect.EOF:
                        break
                    except pexpect.TIMEOUT:
                        continue
                    if data:
                        data_bytes = data.encode("utf-8", errors="replace")
                        os.write(stdout_fd, data_bytes)
                        log_fh.write(data)
                        log_fh.flush()
                if stdin_fd in r:
                    data = os.read(stdin_fd, 4096)
                    if not data:
                        continue
                    os.write(child_fd, data)
        finally:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tc)
            log_fh.close()

    def _drain_pexpect_buffer(self, stdout_fd: int, log_fh) -> None:
        """Flush any data pexpect already read into its internal buffer."""
        while True:
            try:
                data = self.child.read_nonblocking(size=4096, timeout=0)
            except pexpect.EOF:
                return
            except pexpect.TIMEOUT:
                return
            if not data:
                return
            data_bytes = data.encode("utf-8", errors="replace")
            os.write(stdout_fd, data_bytes)
            log_fh.write(data)
            log_fh.flush()

    def close(self) -> None:
        """Close the SSH connection cleanly."""
        if self.child and self.child.isalive():
            self.child.sendline("exit")
            try:
                self.child.wait()
            except pexpect.ExceptionPexpect:
                pass
        if self.child:
            self.child.close()
            self.child = None
