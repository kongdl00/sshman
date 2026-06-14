"""sshman exec — run a single command on a remote session."""

import os
import subprocess
import tempfile
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.keyring import get_ssh_password
from sshman.commands._helpers import resolve_master_password


@click.command("exec")
@click.argument("name")
@click.argument("command")
@click.option("--no-tunnels", is_flag=True, help="Skip port forwarding")
@click.option("--timeout", type=int, default=30, help="SSH connect timeout (seconds)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def exec_cmd(name: str, command: str, no_tunnels: bool, timeout: int,
             config_dir: str | None) -> None:
    """Run a single command on a remote session and print the output.

    \b
    Examples:
      sshman exec web-01 "uptime"
      sshman exec db-01 "df -h /data"
      sshman exec web-01 "tail -50 /var/log/nginx/access.log"
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    # Build SSH command
    cmd = ["ssh", "-o", f"ConnectTimeout={timeout}",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "BatchMode=no"]
    if session.port != 22:
        cmd.extend(["-p", str(session.port)])
    if session.identity_file:
        cmd.extend(["-i", os.path.expanduser(session.identity_file)])

    if session.jumphost:
        jump = cm.find_session(session.jumphost)
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

    cmd.append(f"{session.user}@{session.host}")
    cmd.append(command)

    # Resolve SSH password
    password = session.password or get_ssh_password(session.name)
    env = None
    askpass_script = None

    if password:
        askpass_script = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False,
        )
        askpass_script.write("#!/bin/sh\necho \"$SSHMAN_SSH_PASSWORD\"\n")
        askpass_script.close()
        os.chmod(askpass_script.name, 0o700)
        env = {
            **os.environ,
            "SSH_ASKPASS": askpass_script.name,
            "SSHMAN_SSH_PASSWORD": password,
            "DISPLAY": "sshman:0",
        }

    try:
        proc = subprocess.run(
            cmd, env=env, start_new_session=(password is not None),
            capture_output=True, text=True, timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        click.echo("Command timed out.", err=True)
        return
    finally:
        if askpass_script:
            try:
                os.unlink(askpass_script.name)
            except OSError:
                pass

    if proc.stdout:
        click.echo(proc.stdout.rstrip())
    if proc.stderr:
        click.echo(click.style(proc.stderr.rstrip(), fg="yellow"), err=True)

    if proc.returncode != 0:
        raise click.Exit(code=proc.returncode)
