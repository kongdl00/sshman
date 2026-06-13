import os
import tempfile
import asyncio
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.keyring import get_ssh_password
from sshman.commands._helpers import resolve_master_password


@click.command("batch")
@click.argument("command")
@click.option("--tag", default=None, help="Filter by tags (comma-separated)")
@click.option("--group", default=None, help="Filter by session group")
@click.option("--names", default=None, help="Filter by session names (comma-separated)")
@click.option("--parallel", type=int, default=5, help="Max concurrent connections")
@click.option("--timeout", type=int, default=10, help="SSH connect timeout in seconds")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def batch_cmd(command: str, tag: str | None, group: str | None,
              names: str | None, parallel: int, timeout: int,
              config_dir: str | None) -> None:
    """Execute a command on multiple servers in parallel.

    SSH passwords are resolved from the session config or system keychain.
    Sessions requiring interactive password entry are skipped.
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = resolve_master_password(cm)

    # Select target sessions
    tag_list = [t.strip() for t in tag.split(",") if t.strip()] if tag else None
    name_list = [n.strip() for n in names.split(",") if n.strip()] if names else None

    candidates = cm.list_sessions(tags=tag_list)
    if group:
        candidates = [s for s in candidates if s.group == group]
    if name_list:
        candidates = [s for s in candidates if s.name in name_list]

    if not candidates:
        click.echo("No matching sessions found.")
        return

    click.echo(f"Running on {len(candidates)} host(s) "
               f"(parallel={parallel}, timeout={timeout}s):\n")

    sem = asyncio.Semaphore(parallel)

    async def run_one(session):
        async with sem:
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
            cmd.append(f"{session.user}@{session.host}")
            cmd.append(command)

            # Resolve SSH password
            password = session.password or get_ssh_password(session.name)
            askpass_script = None

            if not password and not session.identity_file:
                return (session.name, -1, "",
                        "SKIPPED: no password or key configured")

            kwargs = {}
            if password:
                askpass_script = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".sh", delete=False,
                )
                askpass_script.write("#!/bin/sh\necho \"$SSHMAN_SSH_PASSWORD\"\n")
                askpass_script.close()
                os.chmod(askpass_script.name, 0o700)
                kwargs["env"] = {
                    **os.environ,
                    "SSH_ASKPASS": askpass_script.name,
                    "SSHMAN_SSH_PASSWORD": password,
                    "DISPLAY": "sshman:0",
                }
                kwargs["start_new_session"] = True

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    **kwargs,
                )
                stdout, stderr = await proc.communicate()
                rc = proc.returncode or 0
            except Exception as e:
                rc = -1
                stdout = b""
                stderr = str(e).encode()
            finally:
                if askpass_script:
                    try:
                        os.unlink(askpass_script.name)
                    except OSError:
                        pass

            return session.name, rc, stdout.decode(), stderr.decode()

    async def run_all():
        tasks = [run_one(s) for s in candidates]
        return await asyncio.gather(*tasks)

    loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(run_all())
    finally:
        loop.close()

    # Print results
    for name, rc, out, err in results:
        if rc == 0:
            status = click.style("OK", fg="green")
        elif rc == -1 and "SKIPPED" in err:
            status = click.style("SKIP", fg="yellow")
        else:
            status = click.style(f"ERR({rc})", fg="red")
        click.echo(f"── {name} ── {status}")
        if out.strip():
            click.echo(click.style(out.rstrip(), fg="cyan"))
        if err.strip() and "SKIPPED" not in err:
            click.echo(click.style(err.rstrip(), fg="yellow"))
        elif err.strip():
            click.echo(click.style(err.strip(), fg="yellow"))
        click.echo()
