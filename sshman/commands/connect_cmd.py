import sys
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.connector import SSHConnector, SSHConnectionError


@click.command("connect")
@click.argument("name")
@click.option("--log/--no-log", default=None, help="Enable/disable session logging")
@click.option("--no-tunnels", is_flag=True, help="Skip port forwarding")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def connect_cmd(name: str, log: bool | None, no_tunnels: bool, config_dir: str | None) -> None:
    """Connect to an SSH session."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    from sshman.commands._helpers import resolve_master_password
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    connector = SSHConnector(session)
    try:
        click.echo(f"Connecting to {session.name} ({session.user}@{session.host}:{session.port})...")
        connector.connect()
        # Hand control to user
        connector.interact()
    except SSHConnectionError as e:
        click.echo(f"Connection failed: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nDisconnecting...")
    finally:
        connector.close()
