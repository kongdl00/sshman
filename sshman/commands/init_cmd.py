import os
import base64
import click
from pathlib import Path

from sshman.core.config import ConfigManager


@click.command("init")
@click.option(
    "--config-dir",
    default=None,
    help="Custom config directory (default: ~/.sshman)",
    type=click.Path(),
)
def init_cmd(config_dir: str | None) -> None:
    """Initialize sshman configuration and set a master password."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    if cm.config_file.exists():
        click.confirm(
            f"Config already exists at {cm.config_file}. Overwrite?",
            abort=True,
        )

    # Generate random salt
    salt_bytes = os.urandom(32)
    salt = base64.b64encode(salt_bytes).decode("ascii")

    # Get master password
    password = click.prompt(
        "Set master password",
        hide_input=True,
        confirmation_prompt=True,
    )
    if not password:
        click.echo("Password cannot be empty.", err=True)
        raise click.Abort()

    # Write salt file
    salt_file = cm.config_dir / ".salt"
    fd = os.open(salt_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(salt)

    # Save default settings with salt
    cm.settings["master_password_salt"] = salt
    initial_config = {
        "sessions": [],
        "settings": cm.settings,
    }
    cm._save_plain(initial_config)
    cm.encrypt_file(password)

    click.echo(f"✓ sshman initialized — config at {cm.config_file}")
    click.echo(f"✓ Salt stored at {salt_file}")
