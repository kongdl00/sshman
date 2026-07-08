"""Tests for sftp_cmd helpers and CLI behaviour."""

import click
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from sshman.commands.sftp_cmd import (
    _build_scp_cmd,
    _collect_file_stats,
    _expand_local_sources,
    _format_elapsed,
    _format_size,
    _has_glob_chars,
    _sources_need_recursive,
)


# ---------------------------------------------------------------------------
# _format_size
# ---------------------------------------------------------------------------


class TestFormatSize:
    def test_bytes(self):
        assert _format_size(500) == "500.0 B"

    def test_kilobytes(self):
        assert _format_size(2048) == "2.0 KB"

    def test_megabytes(self):
        assert _format_size(300 * 1024 * 1024) == "300.0 MB"

    def test_gigabytes(self):
        assert _format_size(2.5 * 1024 * 1024 * 1024) == "2.5 GB"


# ---------------------------------------------------------------------------
# _format_elapsed
# ---------------------------------------------------------------------------


class TestFormatElapsed:
    def test_seconds(self):
        assert "s" in _format_elapsed(3.2)

    def test_minutes(self):
        result = _format_elapsed(125)
        assert "m" in result
        assert "s" in result


# ---------------------------------------------------------------------------
# _collect_file_stats
# ---------------------------------------------------------------------------


class TestCollectFileStats:
    def test_empty_list(self):
        count, total = _collect_file_stats([])
        assert count == 0
        assert total == 0

    def test_single_file(self, tmp_path):
        f = tmp_path / "app.jar"
        f.write_text("hello world")
        count, total = _collect_file_stats([str(f)])
        assert count == 1
        assert total == len("hello world")

    def test_multiple_files(self, tmp_path):
        (tmp_path / "a.txt").write_text("aaa")
        (tmp_path / "b.txt").write_text("bbbb")
        count, total = _collect_file_stats(
            [str(tmp_path / "a.txt"), str(tmp_path / "b.txt")]
        )
        assert count == 2
        assert total == 7

    def test_directory_counted_but_not_sized(self, tmp_path):
        d = tmp_path / "mydir"
        d.mkdir()
        count, total = _collect_file_stats([str(d)])
        assert count == 1
        assert total == 0  # dirs are not recursed

    def test_mixed_files_and_dirs(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("abcd")
        d = tmp_path / "d"
        d.mkdir()
        count, total = _collect_file_stats([str(f), str(d)])
        assert count == 2
        assert total == 4


# ---------------------------------------------------------------------------
# _has_glob_chars
# ---------------------------------------------------------------------------

class TestHasGlobChars:
    def test_star_is_glob(self):
        assert _has_glob_chars("*.txt") is True

    def test_question_mark_is_glob(self):
        assert _has_glob_chars("file?.txt") is True

    def test_bracket_is_glob(self):
        assert _has_glob_chars("file[0-9].txt") is True

    def test_plain_path_is_not_glob(self):
        assert _has_glob_chars("/var/log/app.log") is False

    def test_tilde_is_not_glob(self):
        """~ is handled by expanduser, not glob."""
        assert _has_glob_chars("~/myfile.txt") is False


# ---------------------------------------------------------------------------
# _expand_local_sources
# ---------------------------------------------------------------------------

class TestExpandLocalSources:
    def test_single_file_returns_list(self, tmp_path):
        f = tmp_path / "app.jar"
        f.write_text("")
        result = _expand_local_sources(str(f))
        assert result == [str(f)]

    def test_missing_file_aborts(self, tmp_path):
        with pytest.raises(click.exceptions.Abort):
            _expand_local_sources(str(tmp_path / "nope.txt"))

    def test_glob_expands_wildcard_star(self, tmp_path):
        (tmp_path / "a.log").write_text("")
        (tmp_path / "b.log").write_text("")
        (tmp_path / "c.txt").write_text("")
        result = _expand_local_sources(str(tmp_path / "*.log"))
        assert len(result) == 2
        assert all(p.endswith(".log") for p in result)

    def test_glob_no_match_aborts(self, tmp_path):
        with pytest.raises(click.exceptions.Abort):
            _expand_local_sources(str(tmp_path / "*.nothing"))

    def test_glob_expands_question_mark(self, tmp_path):
        (tmp_path / "f1.txt").write_text("")
        (tmp_path / "f2.txt").write_text("")
        (tmp_path / "f10.txt").write_text("")
        result = _expand_local_sources(str(tmp_path / "f?.txt"))
        assert len(result) == 2  # f1, f2 — not f10

    def test_glob_results_are_sorted(self, tmp_path):
        (tmp_path / "z.txt").write_text("")
        (tmp_path / "a.txt").write_text("")
        (tmp_path / "m.txt").write_text("")
        result = _expand_local_sources(str(tmp_path / "*.txt"))
        assert result == sorted(result)

    def test_expanduser_tilde(self, monkeypatch, tmp_path):
        """~ should be expanded before existence check."""
        import os
        home_dir = str(tmp_path)
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(tmp_path / "app.jar"))
        (tmp_path / "app.jar").write_text("")
        result = _expand_local_sources("~/app.jar")
        assert str(tmp_path / "app.jar") in result[0]

    def test_directory_is_valid_source(self, tmp_path):
        d = tmp_path / "mydir"
        d.mkdir()
        result = _expand_local_sources(str(d))
        assert result == [str(d)]

    def test_glob_with_directory_matches(self, tmp_path):
        (tmp_path / "dir_a").mkdir()
        (tmp_path / "dir_b").mkdir()
        (tmp_path / "file_c").write_text("")
        result = _expand_local_sources(str(tmp_path / "dir_*"))
        assert len(result) == 2
        assert all("dir_" in p for p in result)


# ---------------------------------------------------------------------------
# _sources_need_recursive
# ---------------------------------------------------------------------------

class TestSourcesNeedRecursive:
    def test_file_only_returns_false(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("")
        assert _sources_need_recursive([str(f)]) is False

    def test_directory_returns_true(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        assert _sources_need_recursive([str(d)]) is True

    def test_any_directory_in_list_returns_true(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        f = tmp_path / "f.txt"
        f.write_text("")
        assert _sources_need_recursive([str(f), str(d)]) is True


# ---------------------------------------------------------------------------
# _build_scp_cmd
# ---------------------------------------------------------------------------

class TestBuildScpCmd:
    def test_minimal(self):
        from sshman.core.session import Session

        cm = MagicMock()
        cm.find_session.return_value = None

        session = Session(name="test", host="10.0.0.1", user="root")
        cmd, _ = _build_scp_cmd(session, 30, cm)
        assert cmd[0] == "scp"
        assert "-o" in cmd
        assert "root@10.0.0.1" not in cmd  # destination is appended later

    def test_recursive_flag_added(self):
        from sshman.core.session import Session

        cm = MagicMock()
        cm.find_session.return_value = None

        session = Session(name="test", host="10.0.0.1", user="root")
        cmd, _ = _build_scp_cmd(session, 30, cm, recursive=True)
        assert "-r" in cmd
        assert cmd[1] == "-r"  # immediately after 'scp'

    def test_recursive_flag_absent_by_default(self):
        from sshman.core.session import Session

        cm = MagicMock()
        cm.find_session.return_value = None

        session = Session(name="test", host="10.0.0.1", user="root")
        cmd, _ = _build_scp_cmd(session, 30, cm)
        assert "-r" not in cmd

    def test_custom_port(self):
        from sshman.core.session import Session

        cm = MagicMock()
        cm.find_session.return_value = None

        session = Session(name="test", host="10.0.0.1", user="root", port=2222)
        cmd, _ = _build_scp_cmd(session, 30, cm)
        assert "-P" in cmd
        port_idx = cmd.index("-P")
        assert cmd[port_idx + 1] == "2222"


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------

class TestSftpPutCli:
    """End-to-end tests for `sshman sftp put` via CliRunner."""

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    @patch("sshman.commands.sftp_cmd._run_with_password")
    def test_put_single_file(
        self, mock_run, mock_cm_class, mock_set, mock_get, tmp_path
    ):
        """A plain file upload works as before."""
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_run.return_value = 0

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        f = tmp_path / "app.jar"
        f.write_text("hello")

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web", str(f), "/opt/app.jar",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-r" not in cmd
        assert str(f) in cmd
        assert "root@10.0.0.1:/opt/app.jar" in cmd

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    @patch("sshman.commands.sftp_cmd._run_with_password")
    def test_put_directory_adds_recursive(
        self, mock_run, mock_cm_class, mock_set, mock_get, tmp_path
    ):
        """Uploading a directory adds -r to the scp command."""
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_run.return_value = 0

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        d = tmp_path / "dist"
        d.mkdir()

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web", str(d), "/opt/",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    @patch("sshman.commands.sftp_cmd._run_with_password")
    def test_put_glob_expands_wildcard(
        self, mock_run, mock_cm_class, mock_set, mock_get, tmp_path
    ):
        """Glob patterns are expanded and passed as multiple sources."""
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_run.return_value = 0

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        (tmp_path / "err.log").write_text("e")
        (tmp_path / "out.log").write_text("o")

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web", str(tmp_path / "*.log"), "/var/log/",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        cmd = mock_run.call_args[0][0]
        sources_in_cmd = [a for a in cmd if a.endswith(".log")]
        assert len(sources_in_cmd) == 2

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    @patch("sshman.commands.sftp_cmd._run_with_password")
    def test_put_multiple_sources_appends_slash_to_dest(
        self, mock_run, mock_cm_class, mock_set, mock_get, tmp_path
    ):
        """When multiple files are uploaded, remote destination gets a trailing /."""
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_run.return_value = 0

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        (tmp_path / "a.log").write_text("a")
        (tmp_path / "b.log").write_text("b")

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web", str(tmp_path / "*.log"), "/var/log",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        cmd = mock_run.call_args[0][0]
        # The remote destination should now end with /
        dest = cmd[-1]
        assert dest.endswith("/")

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    def test_put_glob_no_match(self, mock_cm_class, mock_set, mock_get, tmp_path):
        """A glob that matches nothing should abort with a clear message."""
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web", str(tmp_path / "*.nothing"), "/opt/",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code != 0
        assert "No files match pattern" in result.output

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    def test_put_missing_file(self, mock_cm_class, mock_set, mock_get, tmp_path):
        """A plain path that doesn't exist should abort."""
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web", str(tmp_path / "nope.txt"), "/opt/",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code != 0
        assert "not found" in result.output

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    def test_put_missing_args(self, mock_cm_class, mock_set, mock_get, tmp_path):
        """Calling put with no local/remote args should abort."""
        from click.testing import CliRunner
        from sshman.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code != 0
        assert "Error" in result.output

    @patch("sshman.commands._helpers.get_password", return_value=None)
    @patch("sshman.commands._helpers.set_password")
    @patch("sshman.commands.sftp_cmd.ConfigManager")
    @patch("sshman.commands.sftp_cmd._run_with_password")
    def test_put_shell_expanded_multiple_files(
        self, mock_run, mock_cm_class, mock_set, mock_get, tmp_path
    ):
        """Shell-expanded paths (multiple separate args) + remote dest.

        Simulates: sshman sftp put host a.jar b.jar c.jar /tmp/out/
        """
        from sshman.core.session import Session
        from click.testing import CliRunner
        from sshman.cli import main

        mock_run.return_value = 0

        mock_cm = MagicMock()
        session = Session(name="web", host="10.0.0.1", user="root")
        mock_cm.find_session.return_value = session
        mock_cm_class.return_value = mock_cm

        (tmp_path / "a.jar").write_text("a")
        (tmp_path / "b.jar").write_text("b")
        (tmp_path / "c.jar").write_text("c")

        runner = CliRunner()
        result = runner.invoke(main, [
            "sftp", "put", "web",
            str(tmp_path / "a.jar"),
            str(tmp_path / "b.jar"),
            str(tmp_path / "c.jar"),
            "/tmp/out/",
            "--config-dir", str(tmp_path / ".sshman"),
        ], input="masterpass\n")
        assert result.exit_code == 0
        cmd = mock_run.call_args[0][0]
        sources_in_cmd = [a for a in cmd if a.endswith(".jar")]
        assert len(sources_in_cmd) == 3
        # Destination should end with /
        assert cmd[-1].endswith("/")
