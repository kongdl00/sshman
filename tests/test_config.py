import os
import pytest
from pathlib import Path
from sshman.core.config import ConfigManager
from sshman.core.session import Session


class TestConfigManagerInit:
    def test_init_sets_paths(self, tmp_config_dir):
        cm = ConfigManager()
        assert cm.config_dir == Path.home() / ".sshman"
        assert cm.config_file == Path.home() / ".sshman" / "config.enc"
        assert cm.log_dir == Path.home() / ".sshman" / "logs"

    def test_init_uses_custom_config_dir(self, tmp_config_dir):
        cm = ConfigManager(config_dir=tmp_config_dir)
        assert cm.config_dir == tmp_config_dir


class TestLoadSavePlain:
    def test_save_and_load_plain_yaml(self, tmp_config_dir, sample_session_dict):
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
        cm = ConfigManager(config_dir=tmp_config_dir)
        config = cm._load_plain()
        assert config["sessions"] == []
        assert "default_user" in config["settings"]

    def test_save_plain_sets_0600_permissions(self, tmp_config_dir):
        cm = ConfigManager(config_dir=tmp_config_dir)
        cm._save_plain({"sessions": [], "settings": {"default_user": "root"}})
        file_mode = os.stat(cm.temp_file).st_mode & 0o777
        assert file_mode == 0o600, f"Expected 0o600 got {oct(file_mode)}"


class TestEncryptDecryptFile:
    def test_encrypt_and_decrypt_file(self, tmp_config_dir, sample_session_dict):
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
        assert not cm.temp_file.exists()
        decrypted = cm.decrypt_file("testpassword")
        assert decrypted["sessions"][0]["name"] == "test-server"
        assert "master_password_salt" in decrypted["settings"]

    def test_decrypt_wrong_password_raises(self, tmp_config_dir, sample_session_dict):
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
        cm = ConfigManager(config_dir=tmp_config_dir)
        s = Session.from_dict(sample_session_dict)
        cm.sessions.append(s)
        cm._save_plain(cm._make_config_dict())
        loaded = cm._load_plain()
        assert len(loaded["sessions"]) == 1

    def test_remove_session(self, tmp_config_dir, sample_session_dict):
        cm = ConfigManager(config_dir=tmp_config_dir)
        s = Session.from_dict(sample_session_dict)
        cm.sessions.append(s)
        cm._save_plain(cm._make_config_dict())
        cm.sessions = [x for x in cm.sessions if x.name != "test-server"]
        cm._save_plain(cm._make_config_dict())
        loaded = cm._load_plain()
        assert len(loaded["sessions"]) == 0

    def test_find_by_name(self, tmp_config_dir, sample_session_dict):
        cm = ConfigManager(config_dir=tmp_config_dir)
        s = Session.from_dict(sample_session_dict)
        cm.sessions.append(s)
        found = cm.find_session("test-server")
        assert found is not None
        assert found.host == "192.168.1.100"

    def test_find_by_name_not_found(self, tmp_config_dir):
        cm = ConfigManager(config_dir=tmp_config_dir)
        assert cm.find_session("nonexistent") is None

    def test_list_by_tag(self, tmp_config_dir):
        cm = ConfigManager(config_dir=tmp_config_dir)
        cm.sessions = [
            Session(name="web1", host="10.0.0.1", user="root", tags=["prod", "web"]),
            Session(name="db1", host="10.0.0.2", user="root", tags=["prod", "db"]),
            Session(name="dev1", host="10.0.0.3", user="root", tags=["dev"]),
        ]
        prod = cm.list_sessions(tags=["prod"])
        assert len(prod) == 2
        db = cm.list_sessions(tags=["db"])
        assert len(db) == 1
        assert db[0].name == "db1"

    def test_list_by_keyword(self, tmp_config_dir):
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
