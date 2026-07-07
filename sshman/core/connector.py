import errno
import os
import select
import signal
import shutil
import sys
import termios
import time
import tty
from typing import Optional

import pexpect

from sshman.core.session import Session


def _get_terminal_dimensions() -> tuple[int, int]:
    """Return (rows, cols) for the current terminal, falling back to 80x24."""
    try:
        size = shutil.get_terminal_size()
        return (size.lines, size.columns)
    except Exception:
        return (24, 80)


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
        """Build the SSH command list from a Session."""
        cmd = ["ssh"]
        if session.port != 22:
            cmd.extend(["-p", str(session.port)])
        if session.identity_file:
            cmd.extend(["-i", os.path.expanduser(session.identity_file)])
        if session.keepalive > 0:
            cmd.extend(["-o", f"ServerAliveInterval={session.keepalive}"])
        else:
            # Default keepalive so dead connections are detected promptly.
            cmd.extend(["-o", "ServerAliveInterval=15",
                        "-o", "ServerAliveCountMax=3"])
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
        """Spawn SSH connection and handle interactive authentication."""
        cmd = self.build_command(self.session,
                                 no_tunnels=no_tunnels,
                                 tunnel_only=tunnel_only)

        self.child = pexpect.spawn(
            " ".join(cmd),
            encoding="utf-8",
            timeout=self.session.keepalive if self.session.keepalive > 0 else 30,
            dimensions=_get_terminal_dimensions(),
        )

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
        """Process interactive prompts until authenticated.

        With a jumphost, SSH may ask for multiple passwords.  We never
        return immediately after sending a password — instead we continue
        the loop so additional password / MFA prompts are handled.
        The loop exits when the child closes (EOF, auth failure) or no
        prompt appears within the timeout (TIMEOUT = connected).
        """
        assert self.child is not None

        # Pre-collect passwords: jumphost first, then target
        from sshman.core.keyring import get_ssh_password
        passwords: list[str] = []

        if self.session.jumphost:
            jump = self._find_session(self.session.jumphost)
            if jump:
                jp = jump.password or get_ssh_password(jump.name)
                if jp:
                    passwords.append(jp)

        pw = self.session.password or get_ssh_password(self.session.name)
        if pw:
            passwords.append(pw)

        pw_idx = 0
        hostkeys_accepted = 0

        prompts_handled = 0
        while True:
            # Adaptive timeout: default for first prompt, 1 s after that.
            # SSH sends follow-up prompts (jumphost → target, or MFA)
            # near-instantly, so 1 s is plenty.
            t = 1 if prompts_handled > 0 else -1
            idx = self.child.expect(self.PATTERNS, timeout=t)

            if idx == self.PATTERN_HOSTKEY:
                self.child.sendline("yes")
                hostkeys_accepted += 1
                prompts_handled += 1
                continue

            elif idx in (self.PATTERN_PASSWORD, self.PATTERN_MFA, self.PATTERN_MFA_2):
                prompts_handled += 1
                if pw_idx < len(passwords):
                    password = passwords[pw_idx]
                    pw_idx += 1
                else:
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
                # Don't return — continue loop for next prompt

            elif idx == self.PATTERN_EOF:
                raise SSHConnectionError(
                    f"SSH connection to {self.session.host} ended unexpectedly\n"
                    f"SSH output:\n{self.child.before}"
                )

            elif idx == self.PATTERN_TIMEOUT:
                # No prompt within timeout — we're connected
                return

    def setwinsize(self, rows: int, cols: int) -> None:
        """Update the PTY window size (e.g. after terminal resize)."""
        if self.child is not None:
            self.child.setwinsize(rows, cols)

    def interact(self) -> None:
        """Hand control to the user for interactive shell session.

        Uses a custom select()-based loop (instead of pexpect's
        ``interact()``) so we can periodically check whether the child
        is still alive.  When the SSH connection drops the user sees a
        clear message instead of a hung terminal.
        """
        if self.child is None:
            raise SSHConnectionError("not connected — call connect() first")

        # -- SIGWINCH handler ------------------------------------------------
        old_handler = signal.getsignal(signal.SIGWINCH) if hasattr(signal, "SIGWINCH") else None

        def _on_sigwinch(sig, frame):
            try:
                size = shutil.get_terminal_size()
                self.setwinsize(size.lines, size.columns)
            except Exception:
                pass

        if hasattr(signal, "SIGWINCH"):
            signal.signal(signal.SIGWINCH, _on_sigwinch)

        # -- raw terminal mode ----------------------------------------------
        child_fd = self.child.child_fd
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()

        old_tty = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)

        try:
            self._flush_and_interact_loop(child_fd, stdin_fd, stdout_fd)
        finally:
            tty.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tty)
            if hasattr(signal, "SIGWINCH") and old_handler is not None:
                signal.signal(signal.SIGWINCH, old_handler)

    # ------------------------------------------------------------------
    # Internal helpers for interact()
    # ------------------------------------------------------------------

    def _flush_and_interact_loop(
        self, child_fd: int, stdin_fd: int, stdout_fd: int
    ) -> None:
        """Flush buffered child output, then enter the main I/O loop."""
        encoding = self.child.encoding or "utf-8"
        # Drain any buffered data already read by pexpect.
        if hasattr(self.child, "buffer") and self.child.buffer:
            data = self.child.buffer
            self.child.buffer = self.child.string_type()
            os.write(stdout_fd, data.encode(encoding, errors="replace"))

        self._interact_loop(child_fd, stdin_fd, stdout_fd, encoding)

    def _interact_loop(
        self, child_fd: int, stdin_fd: int, stdout_fd: int, encoding: str
    ) -> None:
        """Core select()-based forwarding loop with liveness checks."""
        alive_check_interval = 1.0  # seconds between isalive() checks

        while self.child is not None and self.child.isalive():
            try:
                r, _, _ = select.select(
                    [child_fd, stdin_fd], [], [], alive_check_interval
                )
            except InterruptedError:
                continue
            except (select.error, OSError):
                break

            # -- child → stdout ---------------------------------------------
            if child_fd in r:
                try:
                    data = os.read(child_fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        # Linux-style EOF — child PTY closed.
                        break
                    raise
                if data == b"":
                    # BSD-style EOF.
                    break
                os.write(stdout_fd, data)

            # -- stdin → child ----------------------------------------------
            if stdin_fd in r:
                try:
                    data = os.read(stdin_fd, 4096)
                except OSError:
                    break
                if data == b"":
                    break
                self.child.write(data.decode(encoding, errors="replace"))

        # ---- post mortem --------------------------------------------------
        if self.child is not None:
            self._report_disconnect()

    @staticmethod
    def _report_disconnect() -> None:
        """Print a visible disconnect message to stderr."""
        msg = "\r\n*** Connection closed (remote host disconnected) ***\r\n"
        try:
            os.write(sys.stderr.fileno(), msg.encode())
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        """Close the SSH connection."""
        if self.child is not None:
            self.child.close(force=True)
            self.child = None
