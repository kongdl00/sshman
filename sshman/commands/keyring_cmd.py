"""sshman keyring — manage the stored master password."""

import click
from pathlib import Path

from sshman.core.keyring import (
    get_password, set_password, clear_password,
    clear_ssh_password,
)
from sshman.core.config import ConfigManager


@click.group("keyring", invoke_without_command=True)
@click.pass_context
def keyring_group(ctx: click.Context) -> None:
    """Manage cached master password in system keychain."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@keyring_group.command("status")
def status_cmd() -> None:
    """Check if master password is stored in system keychain."""
    password = get_password()
    if password is not None:
        click.echo("Master password is stored in system keychain.")
    else:
        click.echo("No master password stored in system keychain.")


@keyring_group.command("clear")
def clear_cmd() -> None:
    """Remove stored master password from system keychain."""
    clear_password()
    click.echo("✓ Removed stored master password from system keychain.")


@keyring_group.command("set")
@click.option(
    "--config-dir", default=None,
    help="Custom config directory",
    type=click.Path(),
)
def set_cmd(config_dir: str | None) -> None:
    """Store master password in system keychain (verified against config)."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    if not cm.config_file.exists():
        click.echo("No encrypted config found — run sshman init first.", err=True)
        raise click.Abort()

    password = click.prompt("Master password", hide_input=True)
    if not password:
        click.echo("Password cannot be empty.", err=True)
        raise click.Abort()

    try:
        cm.load(password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort() from e

    set_password(password)
    click.echo("✓ Password saved to system keychain.")


@keyring_group.command("ssh-clear")
@click.argument("session_name")
def ssh_clear_cmd(session_name: str) -> None:
    """Remove stored SSH password for a session from system keychain."""
    clear_ssh_password(session_name)
    click.echo(
        f"✓ Removed stored SSH password for '{session_name}' "
        f"from system keychain."
    )
