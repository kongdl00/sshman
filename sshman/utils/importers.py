"""Parsers for importing sessions from external formats."""

import csv
import os
from pathlib import Path
from typing import Any


def parse_ssh_config(path: str | None = None) -> list[dict[str, Any]]:
    """Parse ~/.ssh/config into session dicts.

    Returns a list of dicts with keys: name, host, port, user, identity_file.
    """
    config_path = Path(path) if path else Path.home() / ".ssh" / "config"
    if not config_path.exists():
        return []

    sessions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    with open(config_path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            keyword, value = parts[0].lower(), " ".join(parts[1:])

            if keyword == "host":
                if current:
                    sessions.append(current)
                current = {"name": value, "host": value, "port": 22,
                           "user": os.environ.get("USER", "root"),
                           "identity_file": "", "tags": []}
            elif current is not None:
                if keyword == "hostname":
                    current["host"] = value
                elif keyword == "port":
                    try:
                        current["port"] = int(value)
                    except ValueError:
                        pass
                elif keyword == "user":
                    current["user"] = value
                elif keyword == "identityfile":
                    current["identity_file"] = value

    if current:
        sessions.append(current)

    return sessions


def parse_ansible_inventory(path: str) -> list[dict[str, Any]]:
    """Parse a simple Ansible INI-style inventory.

    Supports basic format:
        [group]
        hostname ansible_host=1.2.3.4 ansible_port=2222 ansible_user=admin

    Returns a list of dicts with keys: name, host, port, user, group, tags.
    """
    import re
    inv_path = Path(path)
    if not inv_path.exists():
        return []

    sessions: list[dict[str, Any]] = []
    current_group = ""

    with open(inv_path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Group header
            if line.startswith("[") and line.endswith("]"):
                current_group = line[1:-1]
                continue

            # Host entry
            parts = line.split()
            if not parts:
                continue

            name = parts[0]
            host = name
            port = 22
            user = "root"

            for part in parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    if k == "ansible_host":
                        host = v
                    elif k == "ansible_port":
                        try:
                            port = int(v)
                        except ValueError:
                            pass
                    elif k == "ansible_user":
                        user = v

            sessions.append({
                "name": name, "host": host, "port": port, "user": user,
                "identity_file": "", "tags": [current_group] if current_group else [],
                "group": current_group,
            })

    return sessions


def parse_csv(path: str) -> list[dict[str, Any]]:
    """Parse a CSV file with columns: name,host,port,user,tags.

    Returns a list of session dicts.
    """
    csv_path = Path(path)
    if not csv_path.exists():
        return []

    sessions: list[dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = row.get("name", "").strip()
            host = row.get("host", "").strip()
            if not name or not host:
                continue
            port_str = row.get("port", "22").strip()
            try:
                port = int(port_str)
            except ValueError:
                port = 22
            user = row.get("user", "root").strip()
            tags_str = row.get("tags", "").strip()
            tags = [t.strip() for t in tags_str.split(",") if t.strip()]

            sessions.append({
                "name": name, "host": host, "port": port, "user": user,
                "identity_file": "", "tags": tags, "group": "",
            })

    return sessions
