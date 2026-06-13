import click
from pathlib import Path

from sshman.core.config import ConfigManager


@click.command("remove")
@click.argument("name")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def remove_cmd(name: str, force: bool, config_dir: str | None) -> None:
    """Remove an SSH session."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    from sshman.commands._helpers import resolve_master_password
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if not force:
        click.confirm(
            f"Remove session '{name}' ({session.user}@{session.host})?",
            abort=True,
        )

    cm.sessions = [s for s in cm.sessions if s.name != name]
    cm.save(master_password)
    click.echo(f"✓ Session '{name}' removed.")
