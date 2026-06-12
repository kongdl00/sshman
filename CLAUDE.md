# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

```bash
# Activate virtual environment (required for all commands)
source venv/bin/activate

# Install editable with dev dependencies
pip install -e ".[dev]"

# Run all tests
python3 -m pytest tests/ -v

# Run a single test file
python3 -m pytest tests/test_config.py -v

# Run a single test case
python3 -m pytest tests/test_crypto.py::TestDeriveKey::test_derive_key_returns_bytes -v

# Run with coverage
pip install pytest-cov
python3 -m pytest tests/ -v --cov=sshman --cov-report=term-missing

# Verify CLI works
sshman --help
```

## Architecture

The project follows a **layered architecture** with strict separation: core modules have no CLI dependency, command modules bridge Click ↔ core, CLI entry point is wiring-only.

### Core Layer (`sshman/core/`)

- **`session.py`** — `Session` dataclass (12 fields). `to_dict()` returns shallow copies of `tags` and `tunnels` to prevent external mutation. `to_ssh_args()` always includes `-p` (even for default port 22).
- **`crypto.py`** — AES-256-GCM + Argon2id key derivation. Ciphertext format: `nonce(12 bytes) + ciphertext`. All failures raise `CryptoError`. Adapted for cryptography 48.x API (`time_cost`→`iterations`, `parallelism`→`lanes`, salt auto-padded to 8-byte minimum).
- **`config.py`** — `ConfigManager` orchestrates encrypted YAML storage. **Salt bootstrapping:** the salt needed for key derivation is stored in a companion `.salt` plaintext file alongside `config.enc`, because the salt must be known before decryption. Every `ConfigManager` instance maintains its own `self.settings` dict (copied from `DEFAULT_SETTINGS`) to avoid mutable class-variable bugs. Plaintext config is written to a temp file (`.config.tmp`, `chmod 600`) and deleted immediately after encryption.
- **`connector.py`** — `SSHConnector` uses pexpect to spawn `ssh` and handle interactive prompts (host key confirmation → password → MFA → shell). `build_command()` is a static method. `_handle_interactive_login()` is the internal prompt-processing loop.

### Command Layer (`sshman/commands/`)

Each command file defines a Click command function. Commands follow this pattern: instantiate `ConfigManager` → `cm.load(master_password)` → operate on `cm.sessions` → `cm.save(master_password)`. The `crypto` command is a Click group with `encrypt`/`decrypt` subcommands.

### Config Lifecycle

```
Encrypted on disk:  ~/.sshman/config.enc  (AES-256-GCM ciphertext)
Plaintext companion: ~/.sshman/.salt       (salt for key derivation)
Decrypted in memory: dict (never persisted unencrypted)
```

### Key dependencies

| Dependency | Usage |
|-----------|-------|
| `click` | CLI framework (group, commands, prompts, CliRunner for tests) |
| `cryptography` | AES-256-GCM via `AESGCM`, Argon2id via `Argon2id` |
| `pexpect` | SSH process spawn and interactive prompt handling |
| `pyyaml` | YAML serialization (`safe_load`/`safe_dump` only) |
| `rich` | Terminal tables and panels (used in `list --detail`) |
