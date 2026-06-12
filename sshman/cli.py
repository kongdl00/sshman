"""sshman — SSH Session Manager CLI.

Manage multiple SSH sessions with encrypted storage and auto-login.
"""
import click

from sshman.commands.init_cmd import init_cmd
from sshman.commands.add_cmd import add_cmd
from sshman.commands.list_cmd import list_cmd
from sshman.commands.remove_cmd import remove_cmd
from sshman.commands.connect_cmd import connect_cmd
from sshman.commands.crypto_cmd import crypto_group


@click.group()
@click.version_option(version="0.1.0", prog_name="sshman")
def main() -> None:
    """sshman — manage SSH sessions with encrypted storage and auto-login.

    Get started: sshman init
    """
    pass


# Register commands
main.add_command(init_cmd)
main.add_command(add_cmd)
main.add_command(list_cmd)
main.add_command(remove_cmd)
main.add_command(connect_cmd)
main.add_command(crypto_group)


if __name__ == "__main__":
    main()
