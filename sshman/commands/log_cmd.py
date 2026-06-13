import os
import click
from pathlib import Path
from datetime import datetime


@click.command("log")
@click.argument("name", required=False)
@click.option("--last", type=int, default=20, help="Show last N log entries")
@click.option("--date", default=None, help="Filter by date (YYYY-MM-DD)")
@click.option("--search", default=None, help="Search keyword in logs")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def log_cmd(name: str | None, last: int, date: str | None,
            search: str | None, config_dir: str | None) -> None:
    """View SSH session operation logs."""
    log_base = Path.home() / ".sshman" / "logs"

    if not log_base.exists():
        click.echo("No logs found.")
        return

    # List sessions with logs
    if not name:
        click.echo("Sessions with logs:\n")
        for d in sorted(log_base.iterdir()):
            if d.is_dir():
                log_files = sorted(d.glob("*.log"), reverse=True)
                if log_files:
                    latest = log_files[0]
                    size = latest.stat().st_size
                    click.echo(f"  {d.name}  ({len(log_files)} logs, latest: {size}B, {latest.name})")
        return

    # Show logs for a specific session
    session_log_dir = log_base / name
    if not session_log_dir.exists():
        click.echo(f"No logs for session '{name}'.")
        return

    log_files = sorted(session_log_dir.glob("*.log"), reverse=True)

    # Filter by date
    if date:
        log_files = [f for f in log_files if f.stem.startswith(date)]

    if not log_files:
        click.echo("No matching log files.")
        return

    click.echo(f"Logs for '{name}':\n")

    lines_shown = 0
    for lf in log_files[:max(1, last // 50 + 1)]:
        try:
            with open(lf, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    line = raw_line.rstrip()
                    if search and search.lower() not in line.lower():
                        continue
                    click.echo(line)
                    lines_shown += 1
                    if lines_shown >= last:
                        break
        except OSError:
            click.echo(f"  [error reading {lf.name}]")
        if lines_shown >= last:
            break

    if lines_shown == 0:
        click.echo("  (no matching lines)")
