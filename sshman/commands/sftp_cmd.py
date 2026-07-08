"""sshman sftp — remote file transfer and directory listing."""

import glob as glob_module
import os
import subprocess
import sys
import tempfile
import time

import click
from pathlib import Path

from sshman.core.config import ConfigManager
from sshman.core.connector import SSHConnector, SSHConnectionError
from sshman.core.keyring import get_ssh_password
from sshman.commands._helpers import resolve_master_password


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _format_size(size: float) -> str:
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as a human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def _collect_file_stats(sources: list[str]) -> tuple[int, int]:
    """Return ``(file_count, total_bytes)`` for regular files in *sources*.

    Directories are counted but their byte size is excluded (summing a
    recursive tree would be too expensive for a pre-transfer summary).
    """
    file_count = 0
    total_bytes = 0
    for path in sources:
        if os.path.isfile(path):
            file_count += 1
            total_bytes += os.path.getsize(path)
        elif os.path.isdir(path):
            file_count += 1  # count the directory itself
    return file_count, total_bytes


def _has_glob_chars(path: str) -> bool:
    """Return True if *path* contains shell-style wildcard characters."""
    return bool(set(path) & {"*", "?", "[", "]"})


def _expand_local_sources(local: str) -> list[str]:
    """Expand *local* into a sorted list of concrete paths.

    - Glob wildcards (``*``, ``?``, ``[...]``) are expanded via :func:`glob.glob`.
    - A plain path is returned as a one-element list (checked for existence).
    - ``~`` is expanded via :func:`os.path.expanduser`.

    Raises :class:`click.Abort` when a glob produces no matches or the
    literal path does not exist.
    """
    expanded_local = os.path.expanduser(local)

    if _has_glob_chars(expanded_local):
        matches = sorted(glob_module.glob(expanded_local))
        if not matches:
            click.echo(f"No files match pattern: {local}", err=True)
            raise click.Abort()
        return matches

    if not os.path.exists(expanded_local):
        click.echo(f"Local path not found: {local}", err=True)
        raise click.Abort()

    return [expanded_local]


def _sources_need_recursive(sources: list[str]) -> bool:
    """Return True if any source is a directory (SCP needs ``-r``)."""
    return any(os.path.isdir(s) for s in sources)


def _build_scp_cmd(session, timeout: int, cm, *,
                   recursive: bool = False,
                   compress: bool = False) -> tuple[list[str], str | None]:
    """Build the base SCP / SSH command list, with jumphost & tunnels.

    Returns (cmd_list, password_or_None).
    """
    cmd = ["scp", "-o", f"ConnectTimeout={timeout}",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "BatchMode=no"]
    if compress:
        cmd.insert(1, "-C")
    if recursive:
        cmd.insert(1, "-r")
    if session.port != 22:
        cmd.extend(["-P", str(session.port)])
    if session.identity_file:
        cmd.extend(["-i", os.path.expanduser(session.identity_file)])

    if session.jumphost:
        jump = cm.find_session(session.jumphost)
        if jump:
            cmd.extend(["-o", f"ProxyJump={jump.user}@{jump.host}:{jump.port}"])
        else:
            cmd.extend(["-o", f"ProxyJump={session.jumphost}"])

    password = session.password or get_ssh_password(session.name)
    return cmd, password


def _run_with_password(cmd: list[str], password: str | None, timeout: int) -> int:
    """Execute ``scp`` / ``sftp``, streaming output to the terminal.

    Returns the exit code.  The *timeout* is already baked into the
    command line as ``ConnectTimeout`` — we deliberately do **not**
    set a wall-clock timeout on the subprocess so large file transfers
    are not killed prematurely.
    """
    env = None
    askpass_script = None
    if password:
        askpass_script = tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False)
        askpass_script.write("#!/bin/sh\necho \"$SSHMAN_SSH_PASSWORD\"\n")
        askpass_script.close()
        os.chmod(askpass_script.name, 0o700)
        env = {**os.environ, "SSH_ASKPASS": askpass_script.name,
               "SSHMAN_SSH_PASSWORD": password, "DISPLAY": "sshman:0"}

    try:
        # Stream stdout/stderr so the user sees scp's progress bar.
        proc = subprocess.run(cmd, env=env,
                              start_new_session=(password is not None))
    finally:
        if askpass_script:
            try:
                os.unlink(askpass_script.name)
            except OSError:
                pass

    return proc.returncode


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group("sftp")
def sftp_group() -> None:
    """SFTP file transfer & remote file listing.

    \b
    Commands:
        sshman sftp connect <name>      interactive SFTP shell
        sshman sftp put <name> <local> <remote>
        sshman sftp get <name> <remote> <local>
        sshman sftp ls  <name> <path>
    """


# ---------------------------------------------------------------------------
# connect (interactive)
# ---------------------------------------------------------------------------

@sftp_group.command("connect")
@click.argument("name")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def connect_cmd(name: str, config_dir: str | None) -> None:
    """Open an interactive SFTP shell to a session."""
    _interactive_sftp(name, config_dir)


# ---------------------------------------------------------------------------
# put
# ---------------------------------------------------------------------------

@sftp_group.command("put")
@click.argument("name")
@click.argument("local", nargs=-1)
@click.option("--timeout", type=int, default=60, help="Connect timeout (seconds)")
@click.option("--compress", "-C", is_flag=True, help="Enable SSH compression (2-5× faster for text files)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def put_cmd(name: str, local: tuple[str, ...], timeout: int,
            compress: bool, config_dir: str | None) -> None:
    """Upload files or directories to the remote session.

    \b
    LOCAL accepts one or more paths.  The **last** argument is always
    treated as the remote destination.  Shell globs may be quoted (so
    sshman expands them) or left unquoted (the shell expands them).

    \b
        sshman sftp put web-01 ./app.jar             /opt/app.jar
        sshman sftp put web-01 ./dist/               /opt/          # dir → -r
        sshman sftp put web-01 ./*.log                /var/log/      # glob
        sshman sftp put web-01 '*/target/sdp-*.jar'  /tmp/sdp-admin/ # quoted glob
    """
    if len(local) < 2:
        click.echo("Error: LOCAL and REMOTE arguments are required.\n"
                   "Usage: sshman sftp put <name> <local> <remote>", err=True)
        raise click.Abort()

    *local_parts, remote = local  # last arg is always the remote destination

    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    # Expand each local part (the user may have passed multiple
    # already-expanded paths, or a single unexpanded glob pattern).
    sources: list[str] = []
    for lp in local_parts:
        sources.extend(_expand_local_sources(lp))

    if not sources:
        click.echo("Error: no local files found to upload.", err=True)
        raise click.Abort()

    recursive = _sources_need_recursive(sources)

    cmd, password = _build_scp_cmd(session, timeout, cm,
                                   recursive=recursive, compress=compress)

    # scp requires the remote destination to be directory-like when
    # uploading multiple local sources.
    cmd.extend(sources)
    remote_dest = f"{session.user}@{session.host}:{remote}"
    if len(sources) > 1 and not remote.endswith("/"):
        remote_dest += "/"
    cmd.append(remote_dest)

    # ----- pre-transfer summary -----
    file_count, total_bytes = _collect_file_stats(sources)
    parts: list[str] = [f"{file_count} file{'s' if file_count != 1 else ''}"]
    if total_bytes > 0:
        parts.append(_format_size(total_bytes))
    summary = ", ".join(parts)

    label = ", ".join(local_parts) if len(local_parts) <= 3 else f"{len(local_parts)} paths"
    click.echo(f"Uploading {label} → {session.user}@{session.host}:{remote}")
    click.echo(f"  [{summary}]")

    started = time.time()
    rc = _run_with_password(cmd, password, timeout)
    elapsed = time.time() - started

    if rc == 0:
        speed = ""
        if elapsed > 0 and total_bytes > 0:
            speed = f" @ {_format_size(total_bytes / elapsed)}/s"
        click.echo(f"✓ Upload complete ({_format_elapsed(elapsed)}{speed}).")
    sys.exit(rc)


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

@sftp_group.command("get")
@click.argument("name")
@click.argument("remote")
@click.argument("local")
@click.option("--timeout", type=int, default=60, help="Connect timeout (seconds)")
@click.option("--compress", "-C", is_flag=True, help="Enable SSH compression")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def get_cmd(name: str, remote: str, local: str, timeout: int,
            compress: bool, config_dir: str | None) -> None:
    """Download a remote file to the local machine.

    Example: sshman sftp get web-01 /var/log/nginx/access.log ./access.log
    """
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    cmd, password = _build_scp_cmd(session, timeout, cm, compress=compress)
    cmd.append(f"{session.user}@{session.host}:{remote}")
    cmd.append(local)

    click.echo(f"Downloading {session.user}@{session.host}:{remote} → {local} ...")
    started = time.time()
    rc = _run_with_password(cmd, password, timeout)
    elapsed = time.time() - started
    if rc == 0:
        click.echo(f"✓ Download complete ({_format_elapsed(elapsed)}).")
    sys.exit(rc)


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

@sftp_group.command("ls")
@click.argument("name")
@click.argument("path", default=".", required=False)
@click.option("--timeout", type=int, default=15, help="SSH timeout (seconds)")
@click.option("--config-dir", default=None, help="Custom config directory", type=click.Path())
def ls_cmd(name: str, path: str, timeout: int, config_dir: str | None) -> None:
    """List remote directory contents.

    Example: sshman sftp ls web-01 /var/log
    """
    # Reuse sshman exec pattern — just run 'ls -la' remotely
    from sshman.commands.exec_cmd import exec_cmd as _exec
    ctx = click.get_current_context()
    ctx.invoke(_exec, name=name, command=f"ls -la {path}",
               timeout=timeout, no_tunnels=False, config_dir=config_dir)


# ---------------------------------------------------------------------------
# interactive
# ---------------------------------------------------------------------------

def _interactive_sftp(name: str, config_dir: str | None) -> None:
    """Open an interactive SFTP shell."""
    config_dir_path = Path(config_dir) if config_dir else None
    cm = ConfigManager(config_dir=config_dir_path)
    master_password = resolve_master_password(cm)

    session = cm.find_session(name)
    if not session:
        click.echo(f"Session '{name}' not found.", err=True)
        raise click.Abort()

    # Build sftp command
    cmd = ["sftp", "-o", "StrictHostKeyChecking=ask"]
    if session.port != 22:
        cmd.extend(["-P", str(session.port)])
    if session.identity_file:
        cmd.extend(["-i", os.path.expanduser(session.identity_file)])
    if session.jumphost:
        jump = cm.find_session(session.jumphost)
        if jump:
            cmd.extend(["-o", f"ProxyJump={jump.user}@{jump.host}:{jump.port}"])
        else:
            cmd.extend(["-o", f"ProxyJump={session.jumphost}"])
    cmd.append(f"{session.user}@{session.host}")

    import pexpect
    import signal
    import shutil

    def _sftp_dimensions():
        try:
            size = shutil.get_terminal_size()
            return (size.lines, size.columns)
        except Exception:
            return (24, 80)

    child = pexpect.spawn(" ".join(cmd), encoding="utf-8",
                          timeout=30, dimensions=_sftp_dimensions())

    # Handle login (same patterns as SSHConnector)
    patterns = [
        r"(?i)password:",
        r"(?i)are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)",
        pexpect.EOF, pexpect.TIMEOUT,
    ]
    pw = session.password or get_ssh_password(session.name)
    prompted = False

    try:
        while True:
            idx = child.expect(patterns, timeout=10 if not prompted else 1)
            if idx == 0:  # password
                if pw:
                    child.sendline(pw)
                else:
                    import getpass
                    pw = getpass.getpass(f"Password: ")
                    child.sendline(pw)
                prompted = True
            elif idx == 1:  # host key
                child.sendline("yes")
            elif idx in (2, 3):  # EOF/TIMEOUT
                break
            else:
                break

        if child.isalive():
            old_handler = signal.getsignal(signal.SIGWINCH) if hasattr(signal, "SIGWINCH") else None

            def _on_sigwinch(sig, frame):
                try:
                    size = shutil.get_terminal_size()
                    child.setwinsize(size.lines, size.columns)
                except Exception:
                    pass

            if hasattr(signal, "SIGWINCH"):
                signal.signal(signal.SIGWINCH, _on_sigwinch)

            try:
                child.interact()
            finally:
                if hasattr(signal, "SIGWINCH") and old_handler is not None:
                    signal.signal(signal.SIGWINCH, old_handler)
    except KeyboardInterrupt:
        pass
    finally:
        child.close(force=True)
