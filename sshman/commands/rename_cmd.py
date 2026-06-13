import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.commands._helpers import resolve_master_password


@click.command("rename")
@click.argument("old_name")
@click.argument("new_name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def rename_cmd(old_name: str, new_name: str, config_dir: str | None) -> None:
    """Rename an SSH session."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = resolve_master_password(cm)

    session = cm.find_session(old_name)
    if not session:
        click.echo(f"Session '{old_name}' not found.", err=True)
        raise click.Abort()

    if cm.find_session(new_name):
        click.echo(f"Session '{new_name}' already exists.", err=True)
        raise click.Abort()

    session.name = new_name
    cm.save(master_password)
    click.echo(f"✓ Renamed '{old_name}' → '{new_name}'")
