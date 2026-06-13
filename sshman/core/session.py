from dataclasses import dataclass, field
from typing import Any


@dataclass
class Session:
    """Represents a single SSH session configuration."""
    name: str
    host: str
    user: str
    port: int = 22
    password: str = ""
    identity_file: str = ""
    tags: list[str] = field(default_factory=list)
    group: str = ""
    jumphost: str = ""
    tunnels: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    auto_log: bool = False
    keepalive: int = 0

    def to_ssh_args(self) -> list[str]:
        """Build SSH command arguments list (excluding 'ssh' itself)."""
        args: list[str] = []
        args.extend(["-p", str(self.port)])
        if self.identity_file:
            args.extend(["-i", self.identity_file])
        if self.keepalive > 0:
            args.extend(["-o", f"ServerAliveInterval={self.keepalive}"])
        args.append(f"{self.user}@{self.host}")
        return args

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for YAML storage."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password,
            "identity_file": self.identity_file,
            "tags": list(self.tags),
            "group": self.group,
            "jumphost": self.jumphost,
            "tunnels": list(self.tunnels),
            "notes": self.notes,
            "auto_log": self.auto_log,
            "keepalive": self.keepalive,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        """Deserialize from dictionary."""
        return cls(
            name=d.get("name", ""),
            host=d.get("host", ""),
            user=d.get("user", "root"),
            port=d.get("port", 22),
            password=d.get("password", ""),
            identity_file=d.get("identity_file", ""),
            tags=d.get("tags", []),
            group=d.get("group", ""),
            jumphost=d.get("jumphost", ""),
            tunnels=d.get("tunnels", []),
            notes=d.get("notes", ""),
            auto_log=d.get("auto_log", False),
            keepalive=d.get("keepalive", 0),
        )
