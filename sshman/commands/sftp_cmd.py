"""sshman sftp — remote file transfer and directory listing."""

import os
import subprocess
import tempfile
import sys
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.connector import SSHConnector, SSHConnectionError
from sshman.core.keyring import get_ssh_password
from sshman.commands._helpers import resolve_master_password


def _build_scp_cmd(session, timeout: int, cm) -> tuple[list[str], str | None]:
    """Build the base SCP / SSH command list, with jumphost & tunnels.

    Returns (cmd_list, password_or_None).
    """
    cmd = ["scp", "-o", f"ConnectTimeout={timeout}",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "BatchMode=no"]
    if session.port != 22:
        cmd.extend(["-P", str(session.port)])
    if session.identity_file:
        cmd.extend(["-i", os.path.expanduser(session.identity_file)])

    if session.jumphost:
        jump = cm.find_session(session.jumphost)
        if jump:
            cmd.extend(["-o", f"ProxyJump={jump.user}@{jump.host}:{jump.port}"])
        else:
            cmd.extend(["-o", f"ProxyJump={session.jumphost}"])

    password = session.password or get_ssh_password(session.name)
    return cmd, password


def _run_with_password(cmd: list[str], password: str | None, timeout: int):
    """Execute a command via subprocess, injecting SSH password if needed."""
    env = None
    askpass_script = None
    if password:
        askpass_script = tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False)
        askpass_script.write("#!/bin/sh\necho \"$SSHMAN_SSH_PASSWORD\"\n")
        askpass_script.close()
        os.chmod(askpass_script.name, 0o700)
        env = {**os.environ, "SSH_ASKPASS": askpass_script.name,
               "SSHMAN_SSH_PASSWORD": password, "DISPLAY": "sshman:0"}

    try:
        proc = subprocess.run(cmd, env=env, start_new_session=(password is not None),
                              capture_output=True, text=True, timeout=timeout + 30)
    finally:
        if askpass_script:
            try:
                os.unlink(askpass_script.name)
            except OSError:
                pass

    if proc.returncode != 0 and proc.stderr:
        click.echo(click.style(proc.stderr.rstrip(), fg="yellow"), err=True)
    if proc.stdout:
        click.echo(proc.stdout.rstrip())
    return proc.returncode


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group("sftp")
def sftp_group() -> None:
    """SFTP file transfer & remote file listing.

    \b
    Commands:
        sshman sftp connect <name>      interactive SFTP shell
        sshman sftp put <name> <local> <remote>
        sshman sftp get <name> <remote> <local>
        sshman sftp ls  <name> <path>
    """


# ---------------------------------------------------------------------------
# connect (interactive)
# ---------------------------------------------------------------------------

@sftp_group.command("connect")
@click.argument("name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def connect_cmd(name: str, config_dir: str | None) -> None:
    """Open an interactive SFTP shell to a session."""
    _interactive_sftp(name, config_dir)


# ---------------------------------------------------------------------------
# put
# ---------------------------------------------------------------------------

@sftp_group.command("put")
@click.argument("name")
@click.argument("local")
@click.argument("remote")
@click.option("--timeout", type=int, default=60, help="Transfer timeout (seconds)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def put_cmd(name: str, local: str, remote: str, timeout: int,
            config_dir: str | None) -> None:
    """Upload a local file to the remote session.

    Example: sshman sftp put web-01 ./app.jar /opt/app.jar
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if not os.path.exists(local):
        click.echo(f"Local file not found: {local}", err=True)
        raise click.Abort()

    cmd, password = _build_scp_cmd(session, timeout, cm)
    cmd.append(local)
    cmd.append(f"{session.user}@{session.host}:{remote}")

    click.echo(f"Uploading {local} → {session.user}@{session.host}:{remote} ...")
    rc = _run_with_password(cmd, password, timeout)
    if rc == 0:
        click.echo("✓ Upload complete.")
    sys.exit(rc)


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

@sftp_group.command("get")
@click.argument("name")
@click.argument("remote")
@click.argument("local")
@click.option("--timeout", type=int, default=60, help="Transfer timeout (seconds)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def get_cmd(name: str, remote: str, local: str, timeout: int,
            config_dir: str | None) -> None:
    """Download a remote file to the local machine.

    Example: sshman sftp get web-01 /var/log/nginx/access.log ./access.log
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    cmd, password = _build_scp_cmd(session, timeout, cm)
    cmd.append(f"{session.user}@{session.host}:{remote}")
    cmd.append(local)

    click.echo(f"Downloading {session.user}@{session.host}:{remote} → {local} ...")
    rc = _run_with_password(cmd, password, timeout)
    if rc == 0:
        click.echo("✓ Download complete.")
    sys.exit(rc)


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

@sftp_group.command("ls")
@click.argument("name")
@click.argument("path", default=".", required=False)
@click.option("--timeout", type=int, default=15, help="SSH timeout (seconds)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def ls_cmd(name: str, path: str, timeout: int, config_dir: str | None) -> None:
    """List remote directory contents.

    Example: sshman sftp ls web-01 /var/log
    """
    # Reuse sshman exec pattern — just run 'ls -la' remotely
    from sshman.commands.exec_cmd import exec_cmd as _exec
    ctx = click.get_current_context()
    ctx.invoke(_exec, name=name, command=f"ls -la {path}",
               timeout=timeout, no_tunnels=False, config_dir=config_dir)


# ---------------------------------------------------------------------------
# interactive
# ---------------------------------------------------------------------------

def _interactive_sftp(name: str, config_dir: str | None) -> None:
    """Open an interactive SFTP shell."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    # Build sftp command
    cmd = ["sftp", "-o", "StrictHostKeyChecking=ask"]
    if session.port != 22:
        cmd.extend(["-P", str(session.port)])
    if session.identity_file:
        cmd.extend(["-i", os.path.expanduser(session.identity_file)])
    if session.jumphost:
        jump = cm.find_session(session.jumphost)
        if jump:
            cmd.extend(["-o", f"ProxyJump={jump.user}@{jump.host}:{jump.port}"])
        else:
            cmd.extend(["-o", f"ProxyJump={session.jumphost}"])
    cmd.append(f"{session.user}@{session.host}")

    import pexpect
    child = pexpect.spawn(" ".join(cmd), encoding="utf-8",
                          timeout=30, dimensions=(24, 80))

    # Handle login (same patterns as SSHConnector)
    patterns = [
        r"(?i)password:",
        r"(?i)are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)",
        pexpect.EOF, pexpect.TIMEOUT,
    ]
    pw = session.password or get_ssh_password(session.name)
    prompted = False

    try:
        while True:
            idx = child.expect(patterns, timeout=10 if not prompted else 1)
            if idx == 0:  # password
                if pw:
                    child.sendline(pw)
                else:
                    import getpass
                    pw = getpass.getpass(f"Password: ")
                    child.sendline(pw)
                prompted = True
            elif idx == 1:  # host key
                child.sendline("yes")
            elif idx in (2, 3):  # EOF/TIMEOUT
                break
            else:
                break

        if child.isalive():
            child.interact()
    except KeyboardInterrupt:
        pass
    finally:
        child.close(force=True)
