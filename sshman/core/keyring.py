"""Platform-agnostic keyring abstraction for storing the master password.

On macOS, uses the Keychain via the /usr/bin/security CLI.
On Linux, tries secret-tool (libsecret), falling back to a time-limited
session cache file (~/.sshman/.session_cache, chmod 600, 30-min TTL).
On other platforms, silently no-ops (password is never cached).
"""

import os
import time
import platform
import subprocess
from pathlib import Path

SERVICE_NAME = "sshman-master"
ACCOUNT_NAME = "sshman"
_SESSION_CACHE_TTL = 1800  # 30 minutes


# ---------------------------------------------------------------------------
# macOS Keychain (security CLI)
# ---------------------------------------------------------------------------

def _macos_get_password() -> str | None:
    try:
        result = subprocess.run(
            [
                "/usr/bin/security", "find-generic-password",
                "-a", ACCOUNT_NAME,
                "-s", SERVICE_NAME,
                "-w",
            ],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def _macos_set_password(password: str) -> None:
    try:
        subprocess.run(
            [
                "/usr/bin/security", "add-generic-password",
                "-a", ACCOUNT_NAME,
                "-s", SERVICE_NAME,
                "-w", password,
                "-U",  # update if exists
            ],
            capture_output=True, timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        pass  # silently fail — user can still type password manually


def _macos_clear_password() -> None:
    try:
        subprocess.run(
            [
                "/usr/bin/security", "delete-generic-password",
                "-a", ACCOUNT_NAME,
                "-s", SERVICE_NAME,
            ],
            capture_output=True, timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        pass


# ---------------------------------------------------------------------------
# Linux: secret-tool + session cache fallback
# ---------------------------------------------------------------------------

def _session_cache_path() -> Path:
    return Path.home() / ".sshman" / ".session_cache"


def _session_cache_get() -> str | None:
    path = _session_cache_path()
    if not path.exists():
        return None
    try:
        content = path.read_text(errors="replace").strip()
        colon = content.index(":")
        timestamp = int(content[:colon])
        password = content[colon + 1:]
        if time.time() - timestamp < _SESSION_CACHE_TTL:
            return password
    except (ValueError, OSError):
        pass
    # Expired or malformed — remove
    path.unlink(missing_ok=True)
    return None


def _session_cache_set(password: str) -> None:
    path = _session_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{int(time.time())}:{password}")


def _session_cache_clear() -> None:
    _session_cache_path().unlink(missing_ok=True)


def _linux_get_password() -> str | None:
    # Try secret-tool first
    try:
        result = subprocess.run(
            ["secret-tool", "lookup", "application", SERVICE_NAME,
             "account", ACCOUNT_NAME],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    # Fall back to session cache
    return _session_cache_get()


def _linux_set_password(password: str) -> None:
    # Try secret-tool first
    try:
        subprocess.run(
            ["secret-tool", "store", "--label", "sshman master password",
             "application", SERVICE_NAME, "account", ACCOUNT_NAME],
            input=password, capture_output=True, text=True, timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    # Always also write session cache as fallback
    _session_cache_set(password)


def _linux_clear_password() -> None:
    try:
        subprocess.run(
            ["secret-tool", "clear", "application", SERVICE_NAME,
             "account", ACCOUNT_NAME],
            capture_output=True, timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    _session_cache_clear()


# ---------------------------------------------------------------------------
# Public API — platform-dispatched at module load
# ---------------------------------------------------------------------------

_system = platform.system()

if _system == "Darwin":
    get_password = _macos_get_password
    set_password = _macos_set_password
    clear_password = _macos_clear_password
elif _system == "Linux":
    get_password = _linux_get_password
    set_password = _linux_set_password
    clear_password = _linux_clear_password
else:
    get_password = lambda: None       # type: ignore[assignment]
    set_password = lambda p: None     # type: ignore[assignment]
    clear_password = lambda: None     # type: ignore[assignment]
