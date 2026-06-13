import asyncio
import click
from pathlib import Path

from sshman.core.config import ConfigManager
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
    """Execute a command on multiple servers in parallel."""
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

    click.echo(f"Running on {len(candidates)} host(s) (parallel={parallel}, timeout={timeout}s):\n")

    sem = asyncio.Semaphore(parallel)

    async def run_one(session):
        async with sem:
            cmd = ["ssh", "-o", f"ConnectTimeout={timeout}",
                   "-o", "StrictHostKeyChecking=accept-new"]
            if session.port != 22:
                cmd.extend(["-p", str(session.port)])
            if session.identity_file:
                import os
                cmd.extend(["-i", os.path.expanduser(session.identity_file)])
            if session.jumphost:
                jump = cm.find_session(session.jumphost)
                if jump:
                    cmd.extend(["-J", f"{jump.user}@{jump.host}:{jump.port}"])
                else:
                    cmd.extend(["-J", session.jumphost])
            cmd.append(f"{session.user}@{session.host}")
            cmd.append(command)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            return session.name, proc.returncode, stdout.decode(), stderr.decode()

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
        status = click.style("OK", fg="green") if rc == 0 else click.style(f"ERR({rc})", fg="red")
        click.echo(f"── {name} ── {status}")
        if out.strip():
            click.echo(click.style(out.rstrip(), fg="cyan"))
        if err.strip():
            click.echo(click.style(err.rstrip(), fg="yellow"))
        click.echo()
