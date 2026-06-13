"""Shared helper functions for CLI commands.

These bridge the gap between the core layer (no Click dependency) and
the command layer (full Click integration).  They encapsulate the
repeated "get master password → verify → cache" pattern.
"""

import click

from sshman.core.keyring import get_password, set_password, clear_password


def resolve_master_password(
    cm: "ConfigManager",  # type: ignore[name-defined]  # noqa: F821
    prompt_label: str = "Master password",
) -> str:
    """Resolve the master password — keychain first, then interactive prompt.

    On success the password is cached in the system keychain so subsequent
    commands skip the prompt.  On failure (wrong password, keychain denied)
    the bad cache entry is cleared and the user is re-prompted.

    Returns the verified plaintext master password.
    Raises click.Abort on verification failure.
    """
    from sshman.core.config import ConfigManager  # noqa: F811

    # 1. Try cached password from system keychain
    password = get_password()
    if password is not None:
        try:
            cm.load(password)
            return password
        except ValueError:
            clear_password()
            click.echo(
                "⚠  Stored master password is no longer valid — "
                "removed from keychain. Please re-enter.",
                err=True,
            )

    # 2. Prompt user
    password = click.prompt(prompt_label, hide_input=True)
    if not password:
        click.echo("Password cannot be empty.", err=True)
        raise click.Abort()

    # 3. Verify
    try:
        cm.load(password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort() from e

    # 4. Cache for next time
    set_password(password)

    return password


def prompt_and_maybe_cache(prompt_label: str = "Master password") -> str:
    """Prompt for a password and offer to cache it in the system keychain.

    Use this for commands where the password cannot be verified against
    an existing encrypted config (e.g. ``init``, ``crypto encrypt``).
    """
    password = click.prompt(prompt_label, hide_input=True, confirmation_prompt=True)
    if not password:
        click.echo("Password cannot be empty.", err=True)
        raise click.Abort()

    if click.confirm("Remember master password in system keychain?", default=True):
        set_password(password)
        click.echo("✓ Password saved to keychain.")

    return password
