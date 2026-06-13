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

    def _find_session(self, name: str) -> Optional[Session]:
        for s in self.sessions:
            if s.name == name:
                return s
        return None

    def build_command(self, session: Session,
                      no_tunnels: bool = False,
                      tunnel_only: bool = False) -> list[str]:
        """Build the SSH command list from a Session.

        Args:
            session: The session to build args for.
            no_tunnels: If True, skip tunnel flags even if configured.
            tunnel_only: If True, add -N (no remote command — tunnels only).
        """
        cmd = ["ssh"]
        if session.port != 22:
            cmd.extend(["-p", str(session.port)])
        if session.identity_file:
            cmd.extend(["-i", os.path.expanduser(session.identity_file)])
        if session.keepalive > 0:
            cmd.extend(["-o", f"ServerAliveInterval={session.keepalive}"])
        cmd.extend(["-o", "StrictHostKeyChecking=ask"])

        # --- Jumphost ---
        if session.jumphost:
            jump = self._find_session(session.jumphost)
            if jump:
                cmd.extend(["-J", f"{jump.user}@{jump.host}:{jump.port}"])
            else:
                # jumphost name might be a raw host:port or user@host
                cmd.extend(["-J", session.jumphost])

        # --- Tunnels ---
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

        Returns the pexpect.spawn child process.  Caller is responsible
        for calling child.interact() or reading output.

        Raises SSHConnectionError on failure.
        """
        cmd = self.build_command(self.session,
                                 no_tunnels=no_tunnels,
                                 tunnel_only=tunnel_only)

        # --- Logger ---
        logfile = None
        if self.session.auto_log:
            log_dir = Path.home() / ".sshman" / "logs" / self.session.name
            log_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            log_path = log_dir / f"{ts}.log"
            logfile = open(str(log_path), "w", encoding="utf-8")

        self.child = pexpect.spawn(
            " ".join(cmd),
            encoding="utf-8",
            timeout=self.session.keepalive if self.session.keepalive > 0 else 30,
            dimensions=(24, 80),
        )
        if logfile:
            self.child.logfile_read = logfile  # child output only — no interact() stall

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
                f"Connection to {self.session.name} ({self.session.host}) closed unexpectedly.\n"
                f"SSH output:\n{self.child.before}"
            )

        return self.child

    def _handle_interactive_login(self) -> None:
        """Process interactive prompts until authenticated.

        After sending the password, we do NOT call expect() to match a shell
        prompt — that would consume MOTD/banners/prompt from pexpect's buffer,
        leaving the user staring at a blank terminal in interact() mode.
        Instead we sleep briefly and check that the child is still alive.
        """
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
        """Hand control to the user for interactive shell session."""
        if self.child is None:
            raise SSHConnectionError("not connected — call connect() first")
        self.child.interact()

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
