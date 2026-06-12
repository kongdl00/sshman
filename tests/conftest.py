import tempfile
import shutil
from pathlib import Path
import pytest


@pytest.fixture
def tmp_config_dir(monkeypatch):
    """Create a temporary .sshman directory for isolated testing."""
    tmp = Path(tempfile.mkdtemp(prefix="sshman_test_"))
    sshman_dir = tmp / ".sshman"
    sshman_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp)
    try:
        yield sshman_dir
    finally:
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


@pytest.fixture
def parsed_sample_config(sample_yaml_config):
    """YAML-parsed version of sample_yaml_config."""
    import yaml

    return yaml.safe_load(sample_yaml_config)
