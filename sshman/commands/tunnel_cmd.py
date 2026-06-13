import sys
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.connector import SSHConnector, SSHConnectionError
from sshman.commands._helpers import resolve_master_password


@click.command("tunnel")
@click.argument("name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def tunnel_cmd(name: str, config_dir: str | None) -> None:
    """Establish SSH port forwarding tunnels without a remote shell.

    Uses the session's configured tunnels list.  The SSH connection
    stays in the foreground until Ctrl‑C.
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if not session.tunnels:
        click.echo(f"Session '{name}' has no tunnels configured.", err=True)
        raise click.Abort()

    click.echo(f"Opening tunnels for {session.name} ({session.user}@{session.host})...")
    click.echo("Press Ctrl-C to disconnect.\n")

    connector = SSHConnector(session, sessions=cm.sessions)
    try:
        connector.connect(no_tunnels=False, tunnel_only=True)
        # Stay in foreground until Ctrl-C
        connector.interact()
    except SSHConnectionError as e:
        click.echo(f"Tunnel failed: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nTunnels closed.")
    finally:
        connector.close()
