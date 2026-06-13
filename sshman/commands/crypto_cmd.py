import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.keyring import get_password, set_password, clear_password


@click.group("crypto", invoke_without_command=True)
@click.pass_context
def crypto_group(ctx: click.Context) -> None:
    """Manage config encryption/decryption."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@crypto_group.command("encrypt")
@click.option(
    "--config-dir",
    default=None,
    help="Custom config directory",
    type=click.Path(),
)
def encrypt_cmd(config_dir: str | None) -> None:
    """Encrypt the plaintext config file."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    if not cm.temp_file.exists():
        click.echo("No plaintext config found to encrypt.", err=True)
        raise click.Abort()

    password = click.prompt("Master password", hide_input=True)
    try:
        cm.encrypt_file(password)
        click.echo(f"✓ Config encrypted → {cm.config_file}")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()

    if click.confirm("Remember master password in system keychain?", default=True):
        set_password(password)
        click.echo("✓ Password saved to keychain.")


@crypto_group.command("decrypt")
@click.option(
    "--config-dir",
    default=None,
    help="Custom config directory",
    type=click.Path(),
)
@click.option(
    "--output",
    default=None,
    help="Write decrypted YAML to file (default: stdout)",
    type=click.Path(),
)
def decrypt_cmd(config_dir: str | None, output: str | None) -> None:
    """Decrypt the config file and output YAML."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    if not cm.config_file.exists():
        click.echo("No encrypted config found.", err=True)
        raise click.Abort()

    # Try keychain first, then prompt
    password = get_password()
    if password is not None:
        try:
            config = cm.decrypt_file(password)
        except ValueError:
            clear_password()
            click.echo("⚠  Stored password invalid — removed. Please re-enter.", err=True)
            password = None

    if password is None:
        password = click.prompt("Master password", hide_input=True)
        try:
            config = cm.decrypt_file(password)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
            raise click.Abort() from e
        set_password(password)

    import yaml
    yaml_text = yaml.safe_dump(config, default_flow_style=False, allow_unicode=True)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(yaml_text)
        click.echo(f"✓ Decrypted config written to {output}")
    else:
        click.echo(yaml_text)
