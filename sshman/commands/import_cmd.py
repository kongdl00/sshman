import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.session import Session
from sshman.commands._helpers import resolve_master_password


@click.command("import")
@click.option("--source", "source_type", required=True,
              type=click.Choice(["ssh-config", "ansible", "csv"]),
              help="Import source type")
@click.option("--path", default=None, help="Source file path (default: ~/.ssh/config for ssh-config)")
@click.option("--dry-run", is_flag=True, help="Preview without saving")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def import_cmd(source_type: str, path: str | None, dry_run: bool,
               config_dir: str | None) -> None:
    """Import sessions from external configuration sources."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = resolve_master_password(cm)

    # Parse source
    if source_type == "ssh-config":
        from sshman.utils.importers import parse_ssh_config
        imported = parse_ssh_config(path)
    elif source_type == "ansible":
        if not path:
            click.echo("Ansible inventory path is required.", err=True)
            raise click.Abort()
        from sshman.utils.importers import parse_ansible_inventory
        imported = parse_ansible_inventory(path)
    elif source_type == "csv":
        if not path:
            click.echo("CSV file path is required.", err=True)
            raise click.Abort()
        from sshman.utils.importers import parse_csv
        imported = parse_csv(path)
    else:
        click.echo(f"Unknown source: {source_type}", err=True)
        raise click.Abort()

    if not imported:
        click.echo("No sessions found in source.")
        return

    click.echo(f"Found {len(imported)} session(s):\n")

    new_count = 0
    for d in imported:
        name = d["name"]
        exists = cm.find_session(name) is not None
        prefix = "~ (exists)" if exists else "+ (new)"
        click.echo(f"  {prefix}  {name}  →  {d['user']}@{d['host']}:{d['port']}  "
                    f"tags={d.get('tags', [])}")

        if not exists:
            session = Session.from_dict(d)
            new_count += 1
            if not dry_run:
                cm.sessions.append(session)

    if dry_run:
        click.echo(f"\n[DRY RUN] Would import {new_count} new session(s).")
    else:
        cm.save(master_password)
        click.echo(f"\n✓ Imported {new_count} new session(s).")
