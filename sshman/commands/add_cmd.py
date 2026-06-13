import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.session import Session


@click.command("add")
@click.option("--name", prompt="Session name", help="Unique name for this session")
@click.option("--host", prompt="Host address", help="SSH server hostname or IP")
@click.option("--port", default=22, help="SSH port (default: 22)")
@click.option("--user", prompt="Username", help="SSH login username")
@click.option("--password", default="", help="SSH password (leave blank to use key or prompt)")
@click.option("--keychain", is_flag=True, help="Store SSH password in system keychain instead of config")
@click.option("--identity-file", default="", help="Path to SSH private key")
@click.option("--tags", default="", help="Comma-separated tags (e.g. prod,web)")
@click.option("--notes", default="", help="Optional notes")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def add_cmd(
    name: str, host: str, port: int, user: str, password: str,
    identity_file: str, tags: str, notes: str, keychain: bool,
    config_dir: str | None,
) -> None:
    """Add a new SSH session interactively."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    # Decrypt existing config to load sessions (auto-caches in keychain)
    from sshman.commands._helpers import resolve_master_password
    master_password = resolve_master_password(cm)

    # Check for duplicates
    if cm.find_session(name):
        click.echo(f"Session '{name}' already exists. Use 'sshman edit {name}' to modify.", err=True)
        raise click.Abort()

    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    # Handle keychain storage for SSH password
    stored_password = password
    if keychain and password:
        from sshman.core.keyring import set_ssh_password
        set_ssh_password(name, password)
        stored_password = ""  # don't write to YAML
        click.echo(f"  SSH password stored in system keychain.")

    session = Session(
        name=name,
        host=host,
        port=port,
        user=user,
        password=stored_password,
        identity_file=identity_file,
        tags=tag_list,
        notes=notes,
    )
    cm.sessions.append(session)
    cm.save(master_password)

    click.echo(f"✓ Session '{name}' added ({user}@{host}:{port})")
    if tag_list:
        click.echo(f"  Tags: {', '.join(tag_list)}")
