import click
from pathlib import Path

from sshman.core.config import ConfigManager


@click.command("list")
@click.option("--tag", default=None, help="Filter by tags (comma-separated)")
@click.option("--group", default=None, help="Filter by session group")
@click.option("--keyword", default=None, help="Search in name, host, notes")
@click.option("--detail", is_flag=True, help="Show full session details")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def list_cmd(tag: str | None, group: str | None, keyword: str | None,
             detail: bool, config_dir: str | None) -> None:
    """List SSH sessions."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    from sshman.commands._helpers import resolve_master_password
    master_password = resolve_master_password(cm)

    tag_list = [t.strip() for t in tag.split(",") if t.strip()] if tag else None
    sessions = cm.list_sessions(tags=tag_list, keyword=keyword)
    if group:
        sessions = [s for s in sessions if s.group == group]

    if not sessions:
        click.echo("No sessions found.")
        return

    if detail:
        _print_detail(sessions)
    else:
        _print_table(sessions)


def _print_table(sessions) -> None:
    """Print sessions as a rich table."""
    from rich.table import Table
    from rich.console import Console

    console = Console()
    table = Table(title="SSH Sessions")
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="green")
    table.add_column("Port")
    table.add_column("User")
    table.add_column("Group")
    table.add_column("Tags")

    for s in sessions:
        table.add_row(
            s.name,
            s.host,
            str(s.port),
            s.user,
            s.group or "-",
            ", ".join(s.tags) if s.tags else "-",
        )

    console.print(table)


def _print_detail(sessions) -> None:
    """Print detailed session info."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    for s in sessions:
        lines = [
            f"[bold cyan]{s.name}[/bold cyan]",
            f"  Host:     {s.host}:{s.port}",
            f"  User:     {s.user}",
            f"  Key:      {s.identity_file or '(none)'}",
            f"  Tags:     {', '.join(s.tags) if s.tags else '-'}",
            f"  Group:    {s.group or '-'}",
            f"  Jumphost: {s.jumphost or '-'}",
            f"  Tunnels:  {len(s.tunnels)} configured",
            f"  Auto-log: {'yes' if s.auto_log else 'no'}",
            f"  Notes:    {s.notes or '-'}",
        ]
        console.print(Panel("\n".join(lines)))
