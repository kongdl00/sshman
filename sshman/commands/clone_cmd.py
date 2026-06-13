import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.session import Session
from sshman.commands._helpers import resolve_master_password


@click.command("clone")
@click.argument("name")
@click.option("--as", "new_name", required=True, help="Name for the cloned session")
@click.option("--host", default=None, help="Override host")
@click.option("--port", type=int, default=None, help="Override port")
@click.option("--user", default=None, help="Override username")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def clone_cmd(name: str, new_name: str, host: str | None, port: int | None,
              user: str | None, config_dir: str | None) -> None:
    """Clone an existing session with optional field overrides."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = resolve_master_password(cm)

    src = cm.find_session(name)
    if not src:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if cm.find_session(new_name):
        click.echo(f"Session '{new_name}' already exists.", err=True)
        raise click.Abort()

    cloned = Session.from_dict(src.to_dict())
    cloned.name = new_name
    if host is not None:
        cloned.host = host
    if port is not None:
        cloned.port = port
    if user is not None:
        cloned.user = user
    # Clear password — user should re-enter or use keychain
    cloned.password = ""

    cm.sessions.append(cloned)
    cm.save(master_password)
    click.echo(f"✓ Cloned '{name}' → '{new_name}' ({cloned.user}@{cloned.host}:{cloned.port})")
