"""sshman — SSH Session Manager CLI.

Manage multiple SSH sessions with encrypted storage and auto-login.
"""
import click

from sshman.commands.init_cmd import init_cmd
from sshman.commands.add_cmd import add_cmd
from sshman.commands.list_cmd import list_cmd
from sshman.commands.remove_cmd import remove_cmd
from sshman.commands.connect_cmd import connect_cmd
from sshman.commands.edit_cmd import edit_cmd
from sshman.commands.rename_cmd import rename_cmd
from sshman.commands.clone_cmd import clone_cmd
from sshman.commands.tunnel_cmd import tunnel_cmd
from sshman.commands.batch_cmd import batch_cmd
from sshman.commands.check_cmd import check_cmd
from sshman.commands.import_cmd import import_cmd
from sshman.commands.log_cmd import log_cmd
from sshman.commands.crypto_cmd import crypto_group
from sshman.commands.keyring_cmd import keyring_group


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
main.add_command(edit_cmd)
main.add_command(rename_cmd)
main.add_command(clone_cmd)
main.add_command(tunnel_cmd)
main.add_command(batch_cmd)
main.add_command(check_cmd)
main.add_command(import_cmd)
main.add_command(log_cmd)
main.add_command(crypto_group)
main.add_command(keyring_group)


# ---------------------------------------------------------------------------
# Shell completion
# ---------------------------------------------------------------------------

@main.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion_cmd(shell: str) -> None:
    """Generate shell completion script.

    \b
    bash: eval "$(sshman completion bash)"
    zsh:  eval "$(sshman completion zsh)"
    fish: sshman completion fish | source
    """
    import os
    prog_name = "sshman"
    # Use Click's built-in shell completion support
    if shell == "bash":
        click.echo(f'eval "$(_{prog_name.upper()}_COMPLETE=bash_source {prog_name})"')
        click.echo("")
        click.echo("# Add the above line to ~/.bashrc or ~/.bash_profile")
    elif shell == "zsh":
        click.echo(f'eval "$(_{prog_name.upper()}_COMPLETE=zsh_source {prog_name})"')
        click.echo("")
        click.echo("# Add the above line to ~/.zshrc")
    elif shell == "fish":
        click.echo(f"_{prog_name.upper()}_COMPLETE=fish_source {prog_name} | source")
        click.echo("")
        click.echo("# Add the above line to ~/.config/fish/config.fish")


if __name__ == "__main__":
    main()
