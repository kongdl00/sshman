"""sshman tunnel — manage SSH port forwarding tunnels."""

import sys
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.connector import SSHConnector, SSHConnectionError
from sshman.commands._helpers import resolve_master_password


def _parse_spec(spec: str, ttype: str) -> dict:
    """Parse a colon-separated tunnel spec into the storage format.

    ``local`` / ``remote``:  ``local_port:remote_host:remote_port``
    ``dynamic``:             ``local_port``
    """
    if ttype in ("local", "remote"):
        parts = spec.split(":")
        if len(parts) != 3:
            raise click.BadParameter(
                f"expected 'local_port:remote_host:remote_port', got '{spec}'"
            )
        return {
            "type": ttype,
            "local_port": int(parts[0]),
            "remote_host": parts[1],
            "remote_port": int(parts[2]),
        }
    else:  # dynamic
        return {"type": "dynamic", "local_port": int(spec)}


@click.group("tunnel", invoke_without_command=True)
@click.pass_context
def tunnel_group(ctx: click.Context) -> None:
    """Manage SSH port forwarding tunnels.

    Shortcuts (when no subcommand given):

    \b
        sshman tunnel <name>            same as tunnel connect <name>
        sshman tunnel <name> --list     same as tunnel list <name>
    """
    if ctx.invoked_subcommand is None:
        # Backward-compat: treat bare 'sshman tunnel <name>' as connect
        name = ctx.args[0] if ctx.args else None
        if name and not name.startswith("-"):
            ctx.invoke(connect_cmd, name=name,
                       config_dir=ctx.params.get("config_dir"))
        else:
            click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# tunnel add
# ---------------------------------------------------------------------------

@tunnel_group.command("add")
@click.argument("name")
@click.option("--local", "local_specs", default=None,
              help="Local forward: local_port:host:remote_port (comma-separated)")
@click.option("--remote", "remote_specs", default=None,
              help="Remote forward: local_port:host:remote_port (comma-separated)")
@click.option("--dynamic", "dynamic_specs", default=None,
              help="Dynamic forward (SOCKS): local_port (comma-separated)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def add_cmd(name: str, local_specs: str | None, remote_specs: str | None,
            dynamic_specs: str | None, config_dir: str | None) -> None:
    """Add port-forwarding tunnels to a session.

    \b
    Examples:
      sshman tunnel add db --local 5432:127.0.0.1:5432
      sshman tunnel add web --local 3306:127.0.0.1:3306,6379:127.0.0.1:6379
      sshman tunnel add proxy --dynamic 1080
      sshman tunnel add db --remote 3000:0.0.0.0:8080
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    added = 0
    for spec_str, ttype in [
        (local_specs, "local"), (remote_specs, "remote"), (dynamic_specs, "dynamic"),
    ]:
        if not spec_str:
            continue
        for spec in spec_str.split(","):
            spec = spec.strip()
            if not spec:
                continue
            session.tunnels.append(_parse_spec(spec, ttype))
            added += 1

    cm.save(master_password)
    click.echo(f"✓ Added {added} tunnel(s) to '{name}' "
               f"({len(session.tunnels)} total)")


# ---------------------------------------------------------------------------
# tunnel rm
# ---------------------------------------------------------------------------

@tunnel_group.command("rm")
@click.argument("name")
@click.option("--index", type=int, required=True, help="Tunnel index to remove (see 'tunnel list')")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def rm_cmd(name: str, index: int, config_dir: str | None) -> None:
    """Remove a tunnel by its index."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if index < 0 or index >= len(session.tunnels):
        click.echo(f"Index {index} out of range (0–{len(session.tunnels) - 1}).",
                   err=True)
        raise click.Abort()

    removed = session.tunnels.pop(index)
    cm.save(master_password)
    click.echo(
        f"✓ Removed tunnel #{index} from '{name}': "
        f"{removed['type']} {removed.get('local_port', '?')}"
    )


# ---------------------------------------------------------------------------
# tunnel list
# ---------------------------------------------------------------------------

@tunnel_group.command("list")
@click.argument("name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def list_cmd(name: str, config_dir: str | None) -> None:
    """List tunnels configured for a session."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if not session.tunnels:
        click.echo(f"'{name}' has no tunnels configured.")
        return

    from rich.table import Table
    from rich.console import Console

    console = Console()
    table = Table(title=f"Tunnels — {name}")
    table.add_column("#", style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Local Port")
    table.add_column("Target", style="green")

    for i, t in enumerate(session.tunnels):
        ttype = t.get("type", "?")
        lp = str(t.get("local_port", ""))
        if ttype == "dynamic":
            target = f"SOCKS :{lp}"
        else:
            target = f"{t.get('remote_host', '?')}:{t.get('remote_port', '?')}"
        table.add_row(str(i), ttype, lp, target)

    console.print(table)


# ---------------------------------------------------------------------------
# tunnel connect
# ---------------------------------------------------------------------------

@tunnel_group.command("connect")
@click.argument("name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def connect_cmd(name: str, config_dir: str | None) -> None:
    """Open tunnels without a remote shell (SSH -N)."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if not session.tunnels:
        click.echo(f"'{name}' has no tunnels configured. "
                   f"Use 'sshman tunnel add {name} ...' first.", err=True)
        raise click.Abort()

    click.echo(f"Opening tunnels for {session.name} ({session.user}@{session.host})...")
    click.echo("Press Ctrl-C to disconnect.\n")

    connector = SSHConnector(session, sessions=cm.sessions)
    try:
        connector.connect(no_tunnels=False, tunnel_only=True)
        connector.interact()
    except SSHConnectionError as e:
        click.echo(f"Tunnel failed: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nTunnels closed.")
    finally:
        connector.close()
