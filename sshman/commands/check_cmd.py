import socket
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.commands._helpers import resolve_master_password


@click.command("check")
@click.option("--tag", default=None, help="Filter by tags")
@click.option("--group", default=None, help="Filter by session group")
@click.option("--names", default=None, help="Filter by session names")
@click.option("--timeout", type=float, default=3.0, help="Connection timeout in seconds")
@click.option("--config", "check_config", is_flag=True, help="Check config file integrity instead")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def check_cmd(tag: str | None, group: str | None, names: str | None,
              timeout: float, check_config: bool, config_dir: str | None) -> None:
    """Health check — test server reachability or validate config integrity."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    if check_config:
        _check_config_integrity(cm)
        return

    master_password = resolve_master_password(cm)

    tag_list = [t.strip() for t in tag.split(",") if t.strip()] if tag else None
    name_list = [n.strip() for n in names.split(",") if n.strip()] if names else None

    sessions = cm.list_sessions(tags=tag_list)
    if group:
        sessions = [s for s in sessions if s.group == group]
    if name_list:
        sessions = [s for s in sessions if s.name in name_list]

    if not sessions:
        click.echo("No matching sessions found.")
        return

    from rich.table import Table
    from rich.console import Console

    console = Console()
    table = Table(title="SSH Health Check")
    table.add_column("Status")
    table.add_column("Name")
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Latency")

    for s in sessions:
        try:
            start = __import__("time").time()
            sock = socket.create_connection((s.host, s.port), timeout=timeout)
            latency = (__import__("time").time() - start) * 1000
            sock.close()
            table.add_row("🟢", s.name, s.host, str(s.port), f"{latency:.0f}ms")
        except (socket.timeout, OSError) as e:
            msg = str(e).split("] ")[-1] if "] " in str(e) else str(e)
            table.add_row("🔴", s.name, s.host, str(s.port), click.style(msg, fg="red"))

    console.print(table)


def _check_config_integrity(cm: ConfigManager) -> None:
    """Validate config file: duplicate names, dangling jumphost refs, etc."""
    click.echo("Checking config integrity...\n")

    issues = []
    names = set()

    for s in cm.sessions:
        # Missing required fields
        if not s.host:
            issues.append(f"[{s.name}] missing host")
        if not s.user:
            issues.append(f"[{s.name}] missing user")
        if not (1 <= s.port <= 65535):
            issues.append(f"[{s.name}] invalid port: {s.port}")

        # Duplicate names
        if s.name in names:
            issues.append(f"[{s.name}] duplicate session name")
        names.add(s.name)

        # Dangling jumphost reference
        if s.jumphost and not cm.find_session(s.jumphost):
            issues.append(f"[{s.name}] jumphost '{s.jumphost}' not found")

    if issues:
        for issue in issues:
            click.echo(f"  ⚠  {issue}")
        click.echo(f"\n{len(issues)} issue(s) found.")
    else:
        click.echo("  ✓ Config looks good — no issues found.")
