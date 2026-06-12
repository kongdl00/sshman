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
