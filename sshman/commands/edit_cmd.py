import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.session import Session


@click.command("edit")
@click.argument("name")
@click.option("--host", default=None, help="New host address")
@click.option("--port", type=int, default=None, help="New SSH port")
@click.option("--user", default=None, help="New username")
@click.option("--password", default=None, help="New SSH password")
@click.option("--keychain", is_flag=True, help="Store SSH password in system keychain instead of config")
@click.option("--identity-file", default=None, help="New SSH private key path")
@click.option("--tags", default=None, help="New tags (comma-separated, replaces all)")
@click.option("--group", default=None, help="New session group")
@click.option("--notes", default=None, help="New notes")
@click.option("--keepalive", type=int, default=None, help="New keepalive interval")
@click.option("--auto-log", type=click.Choice(["true", "false"]), default=None, help="Enable/disable terminal logging (true/false)")
@click.option("--jumphost", default=None, help="Jumphost session name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def edit_cmd(
    name: str, host: str | None, port: int | None, user: str | None,
    password: str | None, identity_file: str | None, tags: str | None,
    group: str | None, notes: str | None, keepalive: int | None,
    auto_log: str | None, jumphost: str | None,
    keychain: bool, config_dir: str | None,
) -> None:
    """Edit an existing SSH session. Only specified fields are updated."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    from sshman.commands._helpers import resolve_master_password
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    # Apply changes only for explicitly provided options
    changed = []
    if host is not None:
        session.host = host
        changed.append("host")
    if port is not None:
        session.port = port
        changed.append("port")
    if user is not None:
        session.user = user
        changed.append("user")
    if password is not None:
        if keychain and password:
            from sshman.core.keyring import set_ssh_password
            set_ssh_password(name, password)
            session.password = ""
            click.echo("  SSH password stored in system keychain.")
        else:
            session.password = password
        changed.append("password")
    if identity_file is not None:
        session.identity_file = identity_file
        changed.append("identity-file")
    if tags is not None:
        session.tags = [t.strip() for t in tags.split(",") if t.strip()]
        changed.append("tags")
    if group is not None:
        session.group = group
        changed.append("group")
    if notes is not None:
        session.notes = notes
        changed.append("notes")
    if keepalive is not None:
        session.keepalive = keepalive
        changed.append("keepalive")
    if auto_log is not None:
        session.auto_log = auto_log == "true"
        changed.append("auto-log")
    if jumphost is not None:
        session.jumphost = jumphost
        changed.append("jumphost")

    if not changed:
        click.echo("No changes specified. Use --help to see available options.")
        return

    cm.save(master_password)
    click.echo(f"✓ Session '{name}' updated ({', '.join(changed)})")
