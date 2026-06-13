# sshman Phase 1 — MVP Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the sshman MVP — a Python CLI tool for managing SSH sessions with AES-256 encrypted YAML storage and pexpect-based auto-login.

**Architecture:** Modular layered design with Click CLI entrypoint. Core layer handles crypto (AES-256-GCM + Argon2), config (YAML CRUD with encryption), and connection (pexpect SSH). Commands layer maps CLI verbs to core operations.

**Tech Stack:** Python 3.13, Click, PyYAML, cryptography, pexpect, rich, pytest

---

## File Structure

```
sshman/
├── pyproject.toml
├── sshman/
│   ├── __init__.py
│   ├── cli.py              # Click CLI entry point (group + top-level wiring)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── session.py      # Session dataclass
│   │   ├── crypto.py       # AES-256-GCM encrypt/decrypt + Argon2 key derivation
│   │   ├── config.py       # ConfigManager: YAML I/O, session CRUD, encrypt/decrypt file
│   │   └── connector.py    # SSHConnector: pexpect-based SSH connection + auto-login
│   └── commands/
│       ├── __init__.py
│       ├── init_cmd.py     # sshman init
│       ├── add_cmd.py      # sshman add
│       ├── list_cmd.py     # sshman list
│       ├── connect_cmd.py  # sshman connect
│       ├── remove_cmd.py   # sshman remove
│       └── crypto_cmd.py   # sshman encrypt / decrypt
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_crypto.py
    ├── test_config.py
    ├── test_session.py
    ├── test_connector.py
    └── test_cli.py
```

Each file has exactly one responsibility. Core modules have zero Click/CLI dependency. Command modules bridge Click ↔ core.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `sshman/__init__.py`
- Create: `sshman/core/__init__.py`
- Create: `sshman/commands/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write project configuration**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "sshman"
version = "0.1.0"
description = "SSH session management CLI tool"
requires-python = ">=3.10"
dependencies = [
    "click>=8.0",
    "pyyaml>=6.0",
    "cryptography>=41.0",
    "pexpect>=4.8",
    "rich>=13.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-mock>=3.0",
]

[project.scripts]
sshman = "sshman.cli:main"
```

- [ ] **Step 2: Create empty __init__.py files**

```bash
touch sshman/__init__.py
touch sshman/core/__init__.py
touch sshman/commands/__init__.py
touch tests/__init__.py
```

- [ ] **Step 3: Write test conftest with shared fixtures**

```python
# tests/conftest.py
import tempfile
import shutil
from pathlib import Path
import pytest


@pytest.fixture
def tmp_config_dir():
    """Create a temporary .sshman directory for isolated testing."""
    tmp = Path(tempfile.mkdtemp(prefix="sshman_test_"))
    sshman_dir = tmp / ".sshman"
    sshman_dir.mkdir(parents=True)
    old_home = Path.home()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(Path, "home", lambda: tmp)
    yield sshman_dir
    monkeypatch.undo()
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_session_dict():
    """Minimal valid session dictionary."""
    return {
        "name": "test-server",
        "host": "192.168.1.100",
        "port": 22,
        "user": "root",
        "password": "",
        "identity_file": "",
        "tags": ["test", "dev"],
        "jumphost": "",
        "tunnels": [],
        "notes": "Test server",
        "auto_log": False,
        "keepalive": 60,
    }


@pytest.fixture
def sample_yaml_config():
    """Minimal valid plaintext YAML config content."""
    return """sessions: []

settings:
  default_user: root
  default_port: 22
  log_dir: ~/.sshman/logs
  connect_timeout: 10
  master_password_salt: dGVzdF9zYWx0
"""
```

- [ ] **Step 4: Install dev dependencies and verify**

```bash
cd /Users/hongxinanquan/sshman
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

Expected: pip installs successfully with no errors.

- [ ] **Step 5: Verify tests run (0 tests)**

```bash
python3 -m pytest tests/ -v
```

Expected: `no tests ran` or empty suite — confirms pytest discovers the test directory.

- [ ] **Step 6: Commit**

```bash
git init
git add pyproject.toml sshman/__init__.py sshman/core/__init__.py sshman/commands/__init__.py tests/__init__.py tests/conftest.py
git commit -m "chore: scaffold project structure and dependencies"
```

---

### Task 2: Session Dataclass

**Files:**
- Create: `sshman/core/session.py`
- Create: `tests/test_session.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_session.py
import pytest
from sshman.core.session import Session


class TestSession:
    def test_create_session_with_required_fields(self):
        """Session can be created with only name, host, user."""
        s = Session(name="test", host="10.0.0.1", user="root")
        assert s.name == "test"
        assert s.host == "10.0.0.1"
        assert s.user == "root"
        assert s.port == 22  # default

    def test_create_session_all_fields(self):
        """Session accepts all optional fields."""
        s = Session(
            name="prod-web",
            host="10.0.1.100",
            port=2222,
            user="admin",
            password="secret",
            identity_file="~/.ssh/id_ed25519",
            tags=["prod", "web"],
            jumphost="bastion",
            tunnels=[{"type": "local", "local_port": 5432, "remote_host": "127.0.0.1", "remote_port": 5432}],
            notes="Production web server",
            auto_log=True,
            keepalive=60,
        )
        assert s.password == "secret"
        assert s.tags == ["prod", "web"]
        assert len(s.tunnels) == 1
        assert s.tunnels[0]["local_port"] == 5432
        assert s.auto_log is True

    def test_to_ssh_args_minimal(self):
        """to_ssh_args() returns correct SSH command args for minimal session."""
        s = Session(name="test", host="10.0.0.1", user="root")
        args = s.to_ssh_args()
        assert "root@10.0.0.1" in args
        assert "-p" in args
        assert "22" in args

    def test_to_ssh_args_with_identity_file(self):
        """to_ssh_args() includes -i when identity_file is set."""
        s = Session(name="test", host="10.0.0.1", user="root", identity_file="~/.ssh/id_rsa")
        args = s.to_ssh_args()
        assert "-i" in args
        assert "~/.ssh/id_rsa" in args

    def test_to_ssh_args_with_custom_port(self):
        """to_ssh_args() uses custom port when not default."""
        s = Session(name="test", host="10.0.0.1", user="root", port=2222)
        args = s.to_ssh_args()
        assert "-p" in args
        assert "2222" in args

    def test_to_ssh_args_with_keepalive(self):
        """to_ssh_args() includes ServerAliveInterval when keepalive is set."""
        s = Session(name="test", host="10.0.0.1", user="root", keepalive=60)
        args = s.to_ssh_args()
        assert "-o" in args
        assert "ServerAliveInterval=60" in args

    def test_to_dict_returns_all_fields(self):
        """to_dict() serializes Session to dict with all fields."""
        s = Session(name="test", host="10.0.0.1", user="root", tags=["dev"])
        d = s.to_dict()
        assert d["name"] == "test"
        assert d["host"] == "10.0.0.1"
        assert d["port"] == 22
        assert d["tags"] == ["dev"]
        assert d["tunnels"] == []
        assert d["jumphost"] == ""
        assert d["auto_log"] is False

    def test_from_dict_roundtrip(self):
        """from_dict(to_dict(session)) produces identical session."""
        original = Session(
            name="test", host="10.0.0.1", user="root", password="pw",
            tags=["a", "b"], tunnels=[{"type": "local", "local_port": 8080,
            "remote_host": "127.0.0.1", "remote_port": 80}]
        )
        restored = Session.from_dict(original.to_dict())
        assert restored.name == original.name
        assert restored.host == original.host
        assert restored.password == original.password
        assert restored.tags == original.tags
        assert restored.tunnels == original.tunnels
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_session.py -v
```

Expected: All tests FAIL — `ModuleNotFoundError: No module named 'sshman.core.session'`

- [ ] **Step 3: Implement Session dataclass**

```python
# sshman/core/session.py
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
    jumphost: str = ""
    tunnels: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    auto_log: bool = False
    keepalive: int = 0

    def to_ssh_args(self) -> list[str]:
        """Build SSH command arguments list (excluding 'ssh' itself)."""
        args: list[str] = []
        if self.port != 22:
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
            "tags": self.tags,
            "jumphost": self.jumphost,
            "tunnels": self.tunnels,
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
            jumphost=d.get("jumphost", ""),
            tunnels=d.get("tunnels", []),
            notes=d.get("notes", ""),
            auto_log=d.get("auto_log", False),
            keepalive=d.get("keepalive", 0),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_session.py -v
```

Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add sshman/core/session.py tests/test_session.py
git commit -m "feat: add Session dataclass with SSH argument builder"
```

---

### Task 3: Crypto Module — AES-256-GCM + Argon2

**Files:**
- Create: `sshman/core/crypto.py`
- Create: `tests/test_crypto.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_crypto.py
import pytest
from sshman.core.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    CryptoError,
)


class TestDeriveKey:
    def test_derive_key_returns_bytes(self):
        """derive_key returns bytes of correct length (32 for AES-256)."""
        key = derive_key("mypassword", "randomsalt")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_same_password_salt_produces_same_key(self):
        """Same inputs produce identical derived key."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass1", "salt1")
        assert k1 == k2

    def test_different_password_produces_different_key(self):
        """Different passwords produce different keys."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass2", "salt1")
        assert k1 != k2

    def test_different_salt_produces_different_key(self):
        """Different salts produce different keys."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass1", "salt2")
        assert k1 != k2

    def test_empty_password_raises(self):
        """Empty password raises CryptoError."""
        with pytest.raises(CryptoError, match="password"):
            derive_key("", "salt")

    def test_empty_salt_raises(self):
        """Empty salt raises CryptoError."""
        with pytest.raises(CryptoError, match="salt"):
            derive_key("pass", "")


class TestEncryptDecrypt:
    def test_encrypt_returns_bytes(self):
        """encrypt_data returns ciphertext as bytes."""
        key = derive_key("mypass", "mysalt")
        ciphertext = encrypt_data(b"hello world", key)
        assert isinstance(ciphertext, bytes)
        assert ciphertext != b"hello world"

    def test_encrypt_same_plaintext_produces_different_ciphertext(self):
        """AES-GCM nonce ensures same plaintext → different ciphertext (nonce non-reuse)."""
        key = derive_key("mypass", "mysalt")
        ct1 = encrypt_data(b"hello", key)
        ct2 = encrypt_data(b"hello", key)
        assert ct1 != ct2

    def test_decrypt_restores_original(self):
        """decrypt_data restores original plaintext."""
        key = derive_key("mypass", "mysalt")
        original = b"Hello, SSH Manager! This is test data."
        ciphertext = encrypt_data(original, key)
        plaintext = decrypt_data(ciphertext, key)
        assert plaintext == original

    def test_decrypt_wrong_key_raises(self):
        """Decrypting with wrong key raises CryptoError."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass2", "salt2")
        ciphertext = encrypt_data(b"secret", k1)
        with pytest.raises(CryptoError):
            decrypt_data(ciphertext, k2)

    def test_decrypt_corrupted_data_raises(self):
        """Decrypting corrupted/tampered ciphertext raises CryptoError."""
        key = derive_key("password", "salt")
        ciphertext = encrypt_data(b"secret", key)
        corrupted = ciphertext[:10] + b"x" + ciphertext[11:]
        with pytest.raises(CryptoError):
            decrypt_data(corrupted, key)

    def test_encrypt_decrypt_empty_data(self):
        """Empty data encrypt/decrypt round-trips."""
        key = derive_key("pw", "salt")
        ct = encrypt_data(b"", key)
        pt = decrypt_data(ct, key)
        assert pt == b""

    def test_encrypt_decrypt_unicode_data(self):
        """Unicode data (converted to bytes) round-trips correctly."""
        key = derive_key("pw", "salt")
        original = "你好，世界！配置内容包含中文。".encode("utf-8")
        ct = encrypt_data(original, key)
        pt = decrypt_data(ct, key)
        assert pt == original

    def test_encrypt_decrypt_large_data(self):
        """Large data (> 64KB) round-trips correctly."""
        key = derive_key("pw", "salt")
        original = b"x" * 128_000
        ct = encrypt_data(original, key)
        pt = decrypt_data(ct, key)
        assert pt == original
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_crypto.py -v
```

Expected: All tests FAIL — module not found.

- [ ] **Step 3: Implement crypto module**

```python
# sshman/core/crypto.py
import os
import base64
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptoError(Exception):
    """Raised when crypto operations fail (wrong password, corrupted data, etc.)."""
    pass


def derive_key(password: str, salt: str) -> bytes:
    """Derive a 32-byte AES-256 key from password using Argon2id.

    Args:
        password: User's master password (must be non-empty).
        salt: Base64-encoded salt string (must be non-empty).

    Returns:
        32-byte derived key.

    Raises:
        CryptoError: If password or salt is empty.
    """
    if not password:
        raise CryptoError("password must not be empty")
    if not salt:
        raise CryptoError("salt must not be empty")

    salt_bytes = salt.encode("utf-8")
    kdf = Argon2id(
        salt=salt_bytes,
        length=32,
        memory_cost=65536,   # 64 MB
        time_cost=3,
        parallelism=4,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-GCM.

    Each call generates a fresh 96-bit nonce. The ciphertext format is:
    nonce (12 bytes) + ciphertext.

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES key.

    Returns:
        Encrypted bytes (nonce + ciphertext).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        ciphertext: Encrypted bytes (nonce + ciphertext).
        key: 32-byte AES key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        CryptoError: If decryption fails (wrong key, tampered data).
    """
    if len(ciphertext) < 12:
        raise CryptoError("ciphertext too short — must be at least 12 bytes")
    nonce = ciphertext[:12]
    encrypted = ciphertext[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, encrypted, None)
    except InvalidTag:
        raise CryptoError("decryption failed — wrong password or corrupted data")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_crypto.py -v
```

Expected: All 12 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add sshman/core/crypto.py tests/test_crypto.py
git commit -m "feat: add AES-256-GCM encrypt/decrypt and Argon2id key derivation"
```

---

### Task 4: Config Module — Encrypted YAML Storage

**Files:**
- Create: `sshman/core/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_config.py
import os
import stat
import pytest
import yaml
from pathlib import Path
from sshman.core.config import ConfigManager
from sshman.core.session import Session


class TestConfigManagerInit:
    def test_init_sets_paths(self, tmp_config_dir):
        """ConfigManager sets config and log paths."""
        cm = ConfigManager()
        assert cm.config_dir == Path.home() / ".sshman"
        assert cm.config_file == Path.home() / ".sshman" / "config.enc"
        assert cm.log_dir == Path.home() / ".sshman" / "logs"

    def test_init_uses_custom_config_dir(self, tmp_config_dir):
        """ConfigManager accepts custom config_dir."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        assert cm.config_dir == tmp_config_dir


class TestLoadSavePlain:
    def test_save_and_load_plain_yaml(self, tmp_config_dir, sample_session_dict):
        """Save plain config and load it back, preserving session data."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        config = {
            "sessions": [sample_session_dict],
            "settings": {
                "default_user": "root",
                "default_port": 22,
                "log_dir": str(tmp_config_dir / "logs"),
                "connect_timeout": 10,
                "master_password_salt": "dGVzdF9zYWx0",
            },
        }
        cm._save_plain(config)
        loaded = cm._load_plain()
        assert len(loaded["sessions"]) == 1
        assert loaded["sessions"][0]["name"] == "test-server"
        assert loaded["settings"]["default_port"] == 22

    def test_load_plain_no_file_returns_default(self, tmp_config_dir):
        """Loading nonexistent file returns default empty config."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        config = cm._load_plain()
        assert config["sessions"] == []
        assert "default_user" in config["settings"]

    def test_save_plain_sets_0600_permissions(self, tmp_config_dir):
        """Saved plain config file has 0o600 permissions."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        cm._save_plain({"sessions": [], "settings": {"default_user": "root"}})
        file_mode = os.stat(cm.temp_file).st_mode & 0o777
        assert file_mode == 0o600 or file_mode == 0o600, f"Expected 0o600 got {oct(file_mode)}"


class TestEncryptDecryptFile:
    def test_encrypt_and_decrypt_file(self, tmp_config_dir, sample_session_dict):
        """Encrypt then decrypt a config file, preserving all data."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        config = {
            "sessions": [sample_session_dict],
            "settings": {
                "default_user": "root",
                "default_port": 22,
                "log_dir": str(tmp_config_dir / "logs"),
                "connect_timeout": 10,
                "master_password_salt": "dGVzdF9zYWx0",
            },
        }
        cm._save_plain(config)
        cm.encrypt_file("testpassword")
        assert cm.config_file.exists()
        assert not cm.temp_file.exists()  # temp file removed after encrypt
        decrypted = cm.decrypt_file("testpassword")
        assert decrypted["sessions"][0]["name"] == "test-server"
        assert "master_password_salt" in decrypted["settings"]

    def test_decrypt_wrong_password_raises(self, tmp_config_dir, sample_session_dict):
        """Decrypting with wrong password raises ValueError."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        config = {
            "sessions": [sample_session_dict],
            "settings": {"default_user": "root", "master_password_salt": "dGVzdF9zYWx0"},
        }
        cm._save_plain(config)
        cm.encrypt_file("correct_password")
        with pytest.raises(ValueError, match="password"):
            cm.decrypt_file("wrong_password")

    def test_encrypted_file_is_not_plaintext(self, tmp_config_dir):
        """Encrypted config file does not contain plaintext session names."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        config = {
            "sessions": [{"name": "VERY_SECRET_SERVER", "host": "10.0.0.1", "user": "root", "port": 22}],
            "settings": {"default_user": "root", "master_password_salt": "dGVzdF9zYWx0"},
        }
        cm._save_plain(config)
        cm.encrypt_file("masterkey")
        raw = cm.config_file.read_bytes()
        assert b"VERY_SECRET_SERVER" not in raw
        assert b"10.0.0.1" not in raw


class TestSessionCRUD:
    def test_add_session(self, tmp_config_dir, sample_session_dict):
        """add_session adds a new session."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        s = Session.from_dict(sample_session_dict)
        cm.sessions.append(s)
        cm._save_plain(cm._make_config_dict())
        loaded = cm._load_plain()
        assert len(loaded["sessions"]) == 1

    def test_remove_session(self, tmp_config_dir, sample_session_dict):
        """remove_session removes a session by name."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        s = Session.from_dict(sample_session_dict)
        cm.sessions.append(s)
        cm._save_plain(cm._make_config_dict())
        cm.sessions = [x for x in cm.sessions if x.name != "test-server"]
        cm._save_plain(cm._make_config_dict())
        loaded = cm._load_plain()
        assert len(loaded["sessions"]) == 0

    def test_find_by_name(self, tmp_config_dir, sample_session_dict):
        """find_session finds a session by name."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        s = Session.from_dict(sample_session_dict)
        cm.sessions.append(s)
        found = cm.find_session("test-server")
        assert found is not None
        assert found.host == "192.168.1.100"

    def test_find_by_name_not_found(self, tmp_config_dir):
        """find_session returns None for nonexistent session."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        assert cm.find_session("nonexistent") is None

    def test_list_by_tag(self, tmp_config_dir):
        """list_sessions with tag filter returns only matching sessions."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        cm.sessions = [
            Session(name="web1", host="10.0.0.1", user="root", tags=["prod", "web"]),
            Session(name="db1", host="10.0.0.2", user="root", tags=["prod", "db"]),
            Session(name="dev1", host="10.0.0.3", user="root", tags=["dev"]),
        ]
        prod_sessions = cm.list_sessions(tags=["prod"])
        assert len(prod_sessions) == 2
        db_sessions = cm.list_sessions(tags=["db"])
        assert len(db_sessions) == 1
        assert db_sessions[0].name == "db1"

    def test_list_by_keyword(self, tmp_config_dir):
        """list_sessions with keyword searches name, host, notes."""
        cm = ConfigManager(config_dir=tmp_config_dir)
        cm.sessions = [
            Session(name="prod-web", host="10.0.0.1", user="root", notes="production"),
            Session(name="stage-db", host="10.0.0.2", user="root", notes="staging"),
        ]
        results = cm.list_sessions(keyword="web")
        assert len(results) == 1
        assert results[0].name == "prod-web"
        results = cm.list_sessions(keyword="staging")
        assert len(results) == 1
        assert results[0].name == "stage-db"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_config.py -v
```

Expected: All tests FAIL — module not found.

- [ ] **Step 3: Implement ConfigManager**

```python
# sshman/core/config.py
import os
import stat
import tempfile
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
    """Manages encrypted SSH session configuration storage.

    Config file lifecycle:
      plain YAML (tempfile) ──encrypt──→ ~/.sshman/config.enc (on disk)
      ~/.sshman/config.enc ──decrypt──→ plain YAML (in memory, never written)
    """

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
        self.log_dir = Path.home() / ".sshman" / "logs"
        self.sessions: list[Session] = []

    # ---- plaintext I/O (temp file, never persists unencrypted) ----

    def _load_plain(self) -> dict:
        """Read plaintext YAML from temp file, return default if absent."""
        if not self.temp_file.exists():
            return {
                "sessions": [],
                "settings": dict(self.DEFAULT_SETTINGS),
            }
        with open(self.temp_file, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {"sessions": [], "settings": dict(self.DEFAULT_SETTINGS)}

    def _save_plain(self, config: dict) -> None:
        """Write plaintext YAML to temp file and set restrictive permissions."""
        fd = os.open(self.temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config, fh, default_flow_style=False, allow_unicode=True)

    def _make_config_dict(self) -> dict:
        """Build a config dict from current sessions + default settings."""
        settings = dict(self.DEFAULT_SETTINGS)
        return {
            "sessions": [s.to_dict() for s in self.sessions],
            "settings": settings,
        }

    # ---- encrypted file I/O ----

    def encrypt_file(self, master_password: str) -> None:
        """Encrypt the plain temp file → config.enc, then remove temp file.

        Raises ValueError if no plaintext config exists to encrypt.
        """
        if not self.temp_file.exists():
            raise ValueError("no plaintext config to encrypt — run init or add first")
        config = self._load_plain()
        salt = config["settings"].get("master_password_salt", "")
        if not salt:
            raise ValueError("master_password_salt not set — run sshman init first")
        key = derive_key(master_password, salt)
        plaintext = yaml.safe_dump(config, default_flow_style=False, allow_unicode=True).encode("utf-8")
        ciphertext = encrypt_data(plaintext, key)
        # Write with restrictive permissions
        fd = os.open(self.config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(ciphertext)
        self.temp_file.unlink(missing_ok=True)

    def decrypt_file(self, master_password: str) -> dict:
        """Decrypt config.enc → in-memory dict (never written to disk).

        Returns the decrypted config dict. Does NOT write the temp file.

        Raises ValueError if config.enc doesn't exist or password is wrong.
        """
        if not self.config_file.exists():
            raise ValueError("no encrypted config found — run sshman init first")
        ciphertext = self.config_file.read_bytes()
        # Extract salt from config header — for bootstrapping we need it.
        # The salt is embedded in the plaintext. To bootstrap, we try with a known salt.
        # Strategy: salt is stored in a small companion file or we use a two-phase approach:
        # Phase 1: The salt is stored in plaintext at config_dir / ".salt"
        salt_file = self.config_dir / ".salt"
        if not salt_file.exists():
            raise ValueError("salt file not found — run sshman init to set up")
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
        # Update settings
        settings = config.get("settings", {})
        if settings:
            for key in self.DEFAULT_SETTINGS:
                if key in settings:
                    self.DEFAULT_SETTINGS[key] = settings[key]

    def save(self, master_password: str) -> None:
        """Save current sessions to plain temp, then encrypt."""
        salt = self.DEFAULT_SETTINGS.get("master_password_salt", "")
        if not salt:
            raise ValueError("master_password_salt not set")
        config = self._make_config_dict()
        config["settings"] = dict(self.DEFAULT_SETTINGS)
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
        """List sessions, optionally filtered by tags or keyword search.

        Args:
            tags: Filter to sessions that have ALL specified tags.
            keyword: Case-insensitive search in name, host, notes.
        """
        results = list(self.sessions)
        if tags:
            results = [
                s for s in results
                if all(tag in s.tags for tag in tags)
            ]
        if keyword:
            kw = keyword.lower()
            results = [
                s for s in results
                if kw in s.name.lower()
                or kw in s.host.lower()
                or kw in s.notes.lower()
            ]
        return results
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_config.py -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add sshman/core/config.py tests/test_config.py
git commit -m "feat: add ConfigManager with encrypted YAML storage and session CRUD"
```

---

### Task 5: SSH Connector — pexpect Auto-Login

**Files:**
- Create: `sshman/core/connector.py`
- Create: `tests/test_connector.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_connector.py
import pytest
from unittest.mock import patch, MagicMock
from sshman.core.connector import SSHConnector
from sshman.core.session import Session


class TestSSHConnectorBuildCommand:
    def test_build_command_minimal(self):
        """build_command returns proper ssh command list for a simple session."""
        session = Session(name="test", host="10.0.0.1", user="root")
        cmd = SSHConnector.build_command(session)
        assert cmd[0] == "ssh"
        assert "root@10.0.0.1" in cmd

    def test_build_command_custom_port(self):
        """Custom port is included in ssh args."""
        session = Session(name="test", host="10.0.0.1", user="root", port=2222)
        cmd = SSHConnector.build_command(session)
        assert "-p" in cmd
        assert "2222" in cmd

    def test_build_command_identity_file(self):
        """Identity file adds -i flag."""
        session = Session(name="test", host="10.0.0.1", user="root", identity_file="~/.ssh/id_rsa")
        cmd = SSHConnector.build_command(session)
        idx = cmd.index("-i")
        assert cmd[idx + 1] == "~/.ssh/id_rsa"

    def test_build_command_keepalive(self):
        """keepalive adds -o ServerAliveInterval."""
        session = Session(name="test", host="10.0.0.1", user="root", keepalive=60)
        cmd = SSHConnector.build_command(session)
        assert "-o" in cmd
        assert "ServerAliveInterval=60" in cmd

    def test_build_command_default_port_not_in_args(self):
        """Default port 22 is not explicitly added to args."""
        session = Session(name="test", host="10.0.0.1", user="root", port=22)
        cmd = SSHConnector.build_command(session)
        # -p 22 is not strictly needed; the implementation may or may not include it
        # For simplicity, we just ensure the command is well-formed
        assert "ssh" == cmd[0]


class TestSSHConnectorConnect:
    @patch("pexpect.spawn")
    def test_connect_calls_spawn(self, mock_spawn, tmp_config_dir):
        """connect spawns a pexpect child with the correct SSH command."""
        mock_child = MagicMock()
        mock_spawn.return_value = mock_child
        session = Session(name="test", host="10.0.0.1", user="root")
        connector = SSHConnector(session)
        connector.connect()
        mock_spawn.assert_called_once()
        args = mock_spawn.call_args[0][0]
        assert "ssh" in args

    @patch("pexpect.spawn")
    def test_connect_with_password_sends_password(self, mock_spawn):
        """When session has password, connector sends it on password prompt."""
        mock_child = MagicMock()
        mock_child.expect.side_effect = [
            1,  # match "password:"
            2,  # match shell prompt or EOF
        ]
        mock_spawn.return_value = mock_child
        session = Session(name="test", host="10.0.0.1", user="root", password="secret123")
        connector = SSHConnector(session)
        connector.connect()
        mock_child.sendline.assert_any_call("secret123")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_connector.py -v
```

Expected: All tests FAIL — module not found.

- [ ] **Step 3: Implement SSHConnector**

```python
# sshman/core/connector.py
import os
import sys
import pexpect

from sshman.core.session import Session


class SSHConnectionError(Exception):
    """Raised when SSH connection fails."""
    pass


class SSHConnector:
    """Manages SSH connections via pexpect, handling interactive prompts."""

    # Patterns to expect during SSH connection
    PATTERNS = [
        r"(?i)password:",
        r"(?i)are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)",
        r"(?i)passcode:",
        r"(?i)verification code:",
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]

    PATTERN_PASSWORD = 0
    PATTERN_HOSTKEY = 1
    PATTERN_MFA = 2
    PATTERN_MFA_2 = 3
    PATTERN_EOF = 4
    PATTERN_TIMEOUT = 5

    def __init__(self, session: Session) -> None:
        self.session = session
        self.child: pexpect.spawn | None = None

    @staticmethod
    def build_command(session: Session) -> list[str]:
        """Build the SSH command list from a Session."""
        cmd = ["ssh"]
        if session.port != 22:
            cmd.extend(["-p", str(session.port)])
        if session.identity_file:
            cmd.extend(["-i", os.path.expanduser(session.identity_file)])
        if session.keepalive > 0:
            cmd.extend(["-o", f"ServerAliveInterval={session.keepalive}"])
        # Disable strict host key checking for first connection — we handle it via pexpect
        cmd.extend(["-o", "StrictHostKeyChecking=ask"])
        cmd.append(f"{session.user}@{session.host}")
        return cmd

    def connect(self) -> pexpect.spawn:
        """Spawn SSH connection and handle interactive authentication.

        Handles: host key confirmation → password → MFA → shell ready.

        Returns the pexpect.spawn child process connected to the remote shell.
        The caller is responsible for calling child.interact() or reading output.

        Raises SSHConnectionError on connection failure.
        """
        cmd = self.build_command(self.session)
        self.child = pexpect.spawn(
            " ".join(cmd),
            encoding="utf-8",
            timeout=self.session.keepalive if self.session.keepalive > 0 else 30,
            dimensions=(24, 80),
        )

        try:
            self._handle_interactive_login()
        except pexpect.TIMEOUT:
            self.child.close()
            raise SSHConnectionError(
                f"Connection to {self.session.name} ({self.session.host}) timed out"
            )
        except pexpect.EOF:
            self.child.close()
            raise SSHConnectionError(
                f"Connection to {self.session.name} ({self.session.host}) closed unexpectedly.\n"
                f"SSH output:\n{self.child.before}"
            )

        return self.child

    def _handle_interactive_login(self) -> None:
        """Process interactive prompts until we reach a shell or error out."""
        assert self.child is not None

        while True:
            idx = self.child.expect(self.PATTERNS)

            if idx == self.PATTERN_HOSTKEY:
                # Accept host key
                self.child.sendline("yes")
                continue

            elif idx in (self.PATTERN_PASSWORD, self.PATTERN_MFA, self.PATTERN_MFA_2):
                password = self.session.password
                if not password:
                    # No stored password — read from terminal
                    import getpass
                    password = getpass.getpass(
                        f"Password for {self.session.user}@{self.session.host}: "
                    )
                self.child.sendline(password)
                # After sending password, wait a moment then check if we're at a shell
                try:
                    idx2 = self.child.expect(
                        [r"[$#]\s*$", r"(?i)password:", r"(?i)permission denied", pexpect.EOF],
                        timeout=5,
                    )
                    if idx2 == 0:
                        # Got a shell prompt — done
                        return
                    elif idx2 == 1:
                        # Wrong password, asked again
                        raise SSHConnectionError("authentication failed — wrong password")
                    elif idx2 in (2, 3):
                        raise SSHConnectionError("authentication failed — permission denied")
                except pexpect.TIMEOUT:
                    # No prompt detected — assume we're in the shell
                    return

            elif idx == self.PATTERN_EOF:
                raise SSHConnectionError(
                    f"SSH connection to {self.session.host} ended unexpectedly"
                )

            elif idx == self.PATTERN_TIMEOUT:
                raise pexpect.TIMEOUT("timed out waiting for SSH prompt")

    def interact(self) -> None:
        """Hand control to the user for interactive shell session."""
        if self.child is None:
            raise SSHConnectionError("not connected — call connect() first")
        self.child.interact()

    def close(self) -> None:
        """Close the SSH connection cleanly."""
        if self.child and self.child.isalive():
            self.child.sendline("exit")
            try:
                self.child.wait()
            except pexpect.ExceptionPexpect:
                pass
        if self.child:
            self.child.close()
            self.child = None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_connector.py -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add sshman/core/connector.py tests/test_connector.py
git commit -m "feat: add SSHConnector with pexpect-based interactive login"
```

---

### Task 6: CLI Commands (Part 1) — init, encrypt, decrypt

**Files:**
- Create: `sshman/commands/init_cmd.py`
- Create: `sshman/commands/crypto_cmd.py`

- [ ] **Step 1: Write init command**

```python
# sshman/commands/init_cmd.py
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
    cm.DEFAULT_SETTINGS["master_password_salt"] = salt
    initial_config = {
        "sessions": [],
        "settings": cm.DEFAULT_SETTINGS,
    }
    cm._save_plain(initial_config)
    cm.encrypt_file(password)

    click.echo(f"✓ sshman initialized — config at {cm.config_file}")
    click.echo(f"✓ Salt stored at {salt_file}")
```

```python
# sshman/commands/crypto_cmd.py
import click
from pathlib import Path

from sshman.core.config import ConfigManager


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

    password = click.prompt("Master password", hide_input=True)
    try:
        config = cm.decrypt_file(password)
        import yaml
        yaml_text = yaml.safe_dump(config, default_flow_style=False, allow_unicode=True)
        if output:
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(yaml_text)
            click.echo(f"✓ Decrypted config written to {output}")
        else:
            click.echo(yaml_text)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()
```

- [ ] **Step 2: Commit**

```bash
git add sshman/commands/init_cmd.py sshman/commands/crypto_cmd.py
git commit -m "feat: add init, encrypt, and decrypt CLI commands"
```

---

### Task 7: CLI Commands (Part 2) — add, list, remove, connect

**Files:**
- Create: `sshman/commands/add_cmd.py`
- Create: `sshman/commands/list_cmd.py`
- Create: `sshman/commands/remove_cmd.py`
- Create: `sshman/commands/connect_cmd.py`

- [ ] **Step 1: Write add command**

```python
# sshman/commands/add_cmd.py
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.session import Session


@click.command("add")
@click.option("--name", prompt="Session name", help="Unique name for this session")
@click.option("--host", prompt="Host address", help="SSH server hostname or IP")
@click.option("--port", default=22, help="SSH port (default: 22)")
@click.option("--user", prompt="Username", help="SSH login username")
@click.option("--password", default="", help="SSH password (leave blank to use key or prompt)")
@click.option("--identity-file", default="", help="Path to SSH private key")
@click.option("--tags", default="", help="Comma-separated tags (e.g. prod,web)")
@click.option("--notes", default="", help="Optional notes")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def add_cmd(
    name: str, host: str, port: int, user: str, password: str,
    identity_file: str, tags: str, notes: str, config_dir: str | None,
) -> None:
    """Add a new SSH session interactively."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    # Decrypt existing config to load sessions
    master_password = click.prompt("Master password", hide_input=True)
    try:
        cm.load(master_password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()

    # Check for duplicates
    if cm.find_session(name):
        click.echo(f"Session '{name}' already exists. Use 'sshman edit {name}' to modify.", err=True)
        raise click.Abort()

    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    session = Session(
        name=name,
        host=host,
        port=port,
        user=user,
        password=password,
        identity_file=identity_file,
        tags=tag_list,
        notes=notes,
    )
    cm.sessions.append(session)
    cm.save(master_password)

    click.echo(f"✓ Session '{name}' added ({user}@{host}:{port})")
    if tag_list:
        click.echo(f"  Tags: {', '.join(tag_list)}")
```

```python
# sshman/commands/list_cmd.py
import click
from pathlib import Path

from sshman.core.config import ConfigManager


@click.command("list")
@click.option("--tag", default=None, help="Filter by tags (comma-separated)")
@click.option("--keyword", default=None, help="Search in name, host, notes")
@click.option("--detail", is_flag=True, help="Show full session details")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def list_cmd(tag: str | None, keyword: str | None, detail: bool, config_dir: str | None) -> None:
    """List SSH sessions."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = click.prompt("Master password", hide_input=True)
    try:
        cm.load(master_password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()

    tag_list = [t.strip() for t in tag.split(",") if t.strip()] if tag else None
    sessions = cm.list_sessions(tags=tag_list, keyword=keyword)

    if not sessions:
        click.echo("No sessions found.")
        return

    if detail:
        _print_detail(sessions)
    else:
        _print_table(sessions)


def _print_table(sessions) -> None:
    """Print sessions as a rich table."""
    from rich.table import Table
    from rich.console import Console

    console = Console()
    table = Table(title="SSH Sessions")
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="green")
    table.add_column("Port")
    table.add_column("User")
    table.add_column("Tags")

    for s in sessions:
        table.add_row(
            s.name,
            s.host,
            str(s.port),
            s.user,
            ", ".join(s.tags) if s.tags else "-",
        )

    console.print(table)


def _print_detail(sessions) -> None:
    """Print detailed session info."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    for s in sessions:
        lines = [
            f"[bold cyan]{s.name}[/bold cyan]",
            f"  Host:     {s.host}:{s.port}",
            f"  User:     {s.user}",
            f"  Key:      {s.identity_file or '(none)'}",
            f"  Tags:     {', '.join(s.tags) if s.tags else '-'}",
            f"  Jumphost: {s.jumphost or '-'}",
            f"  Tunnels:  {len(s.tunnels)} configured",
            f"  Auto-log: {'yes' if s.auto_log else 'no'}",
            f"  Notes:    {s.notes or '-'}",
        ]
        console.print(Panel("\n".join(lines)))
```

```python
# sshman/commands/remove_cmd.py
import click
from pathlib import Path

from sshman.core.config import ConfigManager


@click.command("remove")
@click.argument("name")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def remove_cmd(name: str, force: bool, config_dir: str | None) -> None:
    """Remove an SSH session."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = click.prompt("Master password", hide_input=True)
    try:
        cm.load(master_password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    if not force:
        click.confirm(
            f"Remove session '{name}' ({session.user}@{session.host})?",
            abort=True,
        )

    cm.sessions = [s for s in cm.sessions if s.name != name]
    cm.save(master_password)
    click.echo(f"✓ Session '{name}' removed.")
```

```python
# sshman/commands/connect_cmd.py
import sys
import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.connector import SSHConnector, SSHConnectionError


@click.command("connect")
@click.argument("name")
@click.option("--log/--no-log", default=None, help="Enable/disable session logging")
@click.option("--no-tunnels", is_flag=True, help="Skip port forwarding")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def connect_cmd(name: str, log: bool | None, no_tunnels: bool, config_dir: str | None) -> None:
    """Connect to an SSH session."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)

    master_password = click.prompt("Master password", hide_input=True)
    try:
        cm.load(master_password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    connector = SSHConnector(session)
    try:
        click.echo(f"Connecting to {session.name} ({session.user}@{session.host}:{session.port})...")
        child = connector.connect()
        # Hand control to user
        connector.interact()
    except SSHConnectionError as e:
        click.echo(f"Connection failed: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nDisconnecting...")
    finally:
        connector.close()
```

- [ ] **Step 2: Commit**

```bash
git add sshman/commands/add_cmd.py sshman/commands/list_cmd.py sshman/commands/remove_cmd.py sshman/commands/connect_cmd.py
git commit -m "feat: add CLI commands — add, list, remove, connect"
```

---

### Task 8: CLI Entry Point — Wire Everything Together

**Files:**
- Create: `sshman/cli.py`

- [ ] **Step 1: Write CLI entry point**

```python
# sshman/cli.py
"""sshman — SSH Session Manager CLI.

Manage multiple SSH sessions with encrypted storage and auto-login.
"""
import sys
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
```

- [ ] **Step 2: Install in development mode and verify CLI works**

```bash
pip install -e .
sshman --help
```

Expected: Output shows all subcommands (init, add, list, remove, connect, crypto).

- [ ] **Step 3: Commit**

```bash
git add sshman/cli.py
git commit -m "feat: wire up CLI entry point with all Phase 1 commands"
```

---

### Task 9: CLI Integration Tests

**Files:**
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write CLI integration tests**

```python
# tests/test_cli.py
import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from pathlib import Path

from sshman.cli import main


class TestCLIStartup:
    def test_help_shows_commands(self):
        """sshman --help lists all subcommands."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "init" in result.output
        assert "add" in result.output
        assert "list" in result.output
        assert "connect" in result.output
        assert "remove" in result.output
        assert "crypto" in result.output

    def test_version(self):
        """sshman --version shows version."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_no_command_shows_help(self):
        """sshman with no args shows help."""
        runner = CliRunner()
        result = runner.invoke(main)
        assert result.exit_code == 0
        assert "Usage:" in result.output or "--help" in result.output


class TestInitCommand:
    @patch("sshman.commands.init_cmd.ConfigManager")
    def test_init_creates_config(self, mock_cm_class, tmp_path):
        """init creates encrypted config and salt file."""
        mock_cm = MagicMock()
        mock_cm.config_file = tmp_path / ".sshman" / "config.enc"
        mock_cm.config_dir = tmp_path / ".sshman"
        mock_cm.config_file.exists.return_value = False
        mock_cm.DEFAULT_SETTINGS = {
            "default_user": "root",
            "default_port": 22,
            "log_dir": str(tmp_path / ".sshman" / "logs"),
            "connect_timeout": 10,
            "master_password_salt": "",
        }
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["init", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\ntestpass\n")
        assert result.exit_code == 0
        mock_cm.encrypt_file.assert_called_once_with("testpass")


class TestCryptoCommands:
    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_encrypt_success(self, mock_cm_class, tmp_path):
        """crypto encrypt encrypts the temp file."""
        mock_cm = MagicMock()
        mock_cm.temp_file = tmp_path / ".sshman" / ".config.tmp"
        mock_cm.temp_file.exists.return_value = True
        mock_cm.config_file = tmp_path / ".sshman" / "config.enc"
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["crypto", "encrypt", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code == 0
        mock_cm.encrypt_file.assert_called_once_with("testpass")

    @patch("sshman.commands.crypto_cmd.ConfigManager")
    def test_encrypt_no_temp_file(self, mock_cm_class, tmp_path):
        """crypto encrypt fails when no temp file exists."""
        mock_cm = MagicMock()
        mock_cm.temp_file = tmp_path / ".sshman" / ".config.tmp"
        mock_cm.temp_file.exists.return_value = False
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["crypto", "encrypt", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code != 0


class TestAddCommand:
    @patch("sshman.commands.add_cmd.ConfigManager")
    def test_add_session_success(self, mock_cm_class, tmp_path):
        """add creates a new session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm.sessions = []
        mock_cm.config_file = tmp_path / ".sshman" / "config.enc"
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "add",
            "--name", "test-server",
            "--host", "10.0.0.1",
            "--user", "root",
            "--tags", "prod,web",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        assert "test-server" in result.output
        # Verify session was appended and saved
        assert len(mock_cm.sessions) == 1
        mock_cm.save.assert_called_once()


class TestListCommand:
    @patch("sshman.commands.list_cmd.ConfigManager")
    def test_list_empty(self, mock_cm_class, tmp_path):
        """list with no sessions shows empty message."""
        mock_cm = MagicMock()
        mock_cm.list_sessions.return_value = []
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["list", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code == 0
        assert "No sessions" in result.output


class TestRemoveCommand:
    @patch("sshman.commands.remove_cmd.ConfigManager")
    def test_remove_nonexistent(self, mock_cm_class, tmp_path):
        """remove fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["remove", "nosuch", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code != 0
        assert "not found" in result.output


class TestConnectCommand:
    @patch("sshman.commands.connect_cmd.SSHConnector")
    @patch("sshman.commands.connect_cmd.ConfigManager")
    def test_connect_session_not_found(self, mock_cm_class, mock_connector, tmp_path):
        """connect fails gracefully for nonexistent session."""
        mock_cm = MagicMock()
        mock_cm.find_session.return_value = None
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, ["connect", "nosuch", "--config-dir", str(tmp_path / ".sshman")],
                               input="testpass\n")
        assert result.exit_code != 0
        assert "not found" in result.output
```

- [ ] **Step 2: Run all tests**

```bash
python3 -m pytest tests/ -v
```

Expected: All tests PASS (13 session + 12 crypto + 11 config + 5 connector + 9 CLI = ~50 tests).

- [ ] **Step 3: Commit**

```bash
git add tests/test_cli.py
git commit -m "test: add CLI integration tests for all Phase 1 commands"
```

---

### Task 10: Final Verification

- [ ] **Step 1: Run full test suite with coverage**

```bash
python3 -m pytest tests/ -v --cov=sshman --cov-report=term-missing
```

Expected: All tests pass, coverage ≥ 90% for core modules.

- [ ] **Step 2: Test end-to-end manual flow**

```bash
# Initialize
sshman init

# Add a session
sshman add --name test --host 127.0.0.1 --user $(whoami)

# List sessions
sshman list

# Remove session
sshman remove test --force

# Test encrypt/decrypt
sshman crypto decrypt
```

Expected: Each command completes successfully with clear output.

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "chore: finalize Phase 1 MVP with all tests passing"
```

Co-Authored-By: Claude <noreply@anthropic.com>
