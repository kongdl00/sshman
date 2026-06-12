import os
from pathlib import Path
from typing import Optional

import yaml

from sshman.core.crypto import derive_key, encrypt_data, decrypt_data, CryptoError
from sshman.core.session import Session


def _ensure_permissions(path: Path, mode: int) -> None:
    """Set file/directory permissions if they exist."""
    if path.exists():
        os.chmod(path, mode)


class ConfigManager:
    """Manages encrypted SSH session configuration storage."""

    DEFAULT_SETTINGS = {
        "default_user": "root",
        "default_port": 22,
        "log_dir": "~/.sshman/logs",
        "connect_timeout": 10,
        "master_password_salt": "",
    }

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        self.config_dir = config_dir or (Path.home() / ".sshman")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        _ensure_permissions(self.config_dir, 0o700)

        self.config_file = self.config_dir / "config.enc"
        self.temp_file = self.config_dir / ".config.tmp"
        self.log_dir = self.config_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        _ensure_permissions(self.log_dir, 0o700)
        self.settings = dict(self.DEFAULT_SETTINGS)
        self.sessions: list[Session] = []

    # ---- plaintext I/O (temp file only, never persists unencrypted) ----

    def _load_plain(self) -> dict:
        """Read plaintext YAML from temp file, return default if absent."""
        if not self.temp_file.exists():
            return {
                "sessions": [],
                "settings": dict(self.settings),
            }
        with open(self.temp_file, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {
                "sessions": [],
                "settings": dict(self.settings),
            }

    def _save_plain(self, config: dict) -> None:
        """Write plaintext YAML to temp file with restrictive permissions."""
        fd = os.open(self.temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config, fh, default_flow_style=False, allow_unicode=True)

    def _make_config_dict(self) -> dict:
        """Build config dict from current sessions + default settings."""
        return {
            "sessions": [s.to_dict() for s in self.sessions],
            "settings": dict(self.settings),
        }

    # ---- encrypted file I/O ----

    def encrypt_file(self, master_password: str) -> None:
        """Encrypt plain temp file -> config.enc, remove temp file."""
        if not self.temp_file.exists():
            raise ValueError("no plaintext config to encrypt -- run init or add first")
        config = self._load_plain()
        salt = config["settings"].get("master_password_salt", "")
        if not salt:
            raise ValueError("master_password_salt not set -- run sshman init first")
        # Persist salt to .salt file for bootstrapping decryption
        salt_file = self.config_dir / ".salt"
        salt_file.write_text(salt)
        os.chmod(salt_file, 0o600)

        key = derive_key(master_password, salt)
        plaintext = yaml.safe_dump(
            config, default_flow_style=False, allow_unicode=True
        ).encode("utf-8")
        ciphertext = encrypt_data(plaintext, key)
        fd = os.open(self.config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(ciphertext)
        self.temp_file.unlink(missing_ok=True)

    def decrypt_file(self, master_password: str) -> dict:
        """Decrypt config.enc -> in-memory dict (never written to disk)."""
        if not self.config_file.exists():
            raise ValueError("no encrypted config found -- run sshman init first")
        ciphertext = self.config_file.read_bytes()
        salt_file = self.config_dir / ".salt"
        if not salt_file.exists():
            raise ValueError(
                "salt file not found -- run sshman init to set up"
            )
        salt = salt_file.read_text().strip()
        key = derive_key(master_password, salt)
        try:
            plaintext = decrypt_data(ciphertext, key)
        except CryptoError:
            raise ValueError("wrong master password or corrupted config file")
        return yaml.safe_load(plaintext.decode("utf-8"))

    # ---- session management ----

    def load(self, master_password: str) -> None:
        """Decrypt config and populate sessions list."""
        config = self.decrypt_file(master_password)
        self.sessions = [Session.from_dict(s) for s in config.get("sessions", [])]
        settings = config.get("settings", {})
        if settings:
            for key in self.settings:
                if key in settings:
                    self.settings[key] = settings[key]

    def save(self, master_password: str) -> None:
        """Save current sessions to plain temp, then encrypt."""
        salt = self.settings.get("master_password_salt", "")
        if not salt:
            raise ValueError("master_password_salt not set")
        config = self._make_config_dict()
        config["settings"] = dict(self.settings)
        self._save_plain(config)
        self.encrypt_file(master_password)

    def find_session(self, name: str) -> Optional[Session]:
        """Find a session by exact name match."""
        for s in self.sessions:
            if s.name == name:
                return s
        return None

    def list_sessions(
        self,
        tags: Optional[list[str]] = None,
        keyword: Optional[str] = None,
    ) -> list[Session]:
        """List sessions, optionally filtered by tags or keyword."""
        results = list(self.sessions)
        if tags:
            results = [s for s in results if all(tag in s.tags for tag in tags)]
        if keyword:
            kw = keyword.lower()
            results = [
                s
                for s in results
                if kw in s.name.lower()
                or kw in s.host.lower()
                or kw in s.notes.lower()
            ]
        return results
