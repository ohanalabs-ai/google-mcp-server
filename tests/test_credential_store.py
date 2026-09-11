"""Tests for the broker's pluggable credential store backends."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from google_mcp_server.broker import (
    BrokerConfigurationError,
    BrokerSettings,
    EncryptedFileStore,
    InMemoryCredentialStore,
    RedisCredentialStore,
    StoredConnectionRecord,
    build_credential_store,
)


def _sample_record(connection_id: str = "conn-1") -> StoredConnectionRecord:
    return StoredConnectionRecord(
        connection_id=connection_id,
        subject="user-123",
        email="user@example.com",
    )


class TestEncryptedFileStore:
    def test_save_then_load_round_trips(self, tmp_path: Path):
        store = EncryptedFileStore(tmp_path, "test-secret")
        record = _sample_record()

        store.save(record)
        loaded = store.load(record.connection_id)

        assert loaded is not None
        assert loaded.connection_id == record.connection_id
        assert loaded.subject == "user-123"

    def test_load_missing_connection_returns_none(self, tmp_path: Path):
        store = EncryptedFileStore(tmp_path, "test-secret")
        assert store.load("does-not-exist") is None

    def test_ciphertext_on_disk_is_not_plaintext(self, tmp_path: Path):
        store = EncryptedFileStore(tmp_path, "test-secret")
        store.save(_sample_record())

        raw = (tmp_path / "conn-1.json").read_text()
        assert "user@example.com" not in raw
        assert "user-123" not in raw


class TestInMemoryCredentialStore:
    def test_save_then_load_round_trips(self):
        store = InMemoryCredentialStore("test-secret")
        record = _sample_record()

        store.save(record)
        loaded = store.load(record.connection_id)

        assert loaded is not None
        assert loaded.email == "user@example.com"

    def test_load_missing_connection_returns_none(self):
        store = InMemoryCredentialStore("test-secret")
        assert store.load("does-not-exist") is None

    def test_two_instances_do_not_share_state(self):
        store_a = InMemoryCredentialStore("test-secret")
        store_b = InMemoryCredentialStore("test-secret")

        store_a.save(_sample_record())

        assert store_b.load("conn-1") is None


class TestRedisCredentialStore:
    def test_save_writes_ciphertext_not_plaintext(self):
        with patch("redis.Redis") as mock_redis_cls:
            mock_client = MagicMock()
            mock_redis_cls.from_url.return_value = mock_client

            store = RedisCredentialStore("test-secret", "redis://localhost:6379/0")
            store.save(_sample_record())

            args, _ = mock_client.set.call_args
            key, blob = args
            assert key == "google-mcp-broker:conn-1"
            assert "user@example.com" not in blob
            assert "user-123" not in blob

    def test_save_then_load_round_trips_through_a_fake_backing_store(self):
        backing: dict[str, str] = {}
        with patch("redis.Redis") as mock_redis_cls:
            mock_client = MagicMock()
            mock_client.set.side_effect = lambda k, v: backing.__setitem__(k, v)
            mock_client.get.side_effect = lambda k: backing.get(k)
            mock_redis_cls.from_url.return_value = mock_client

            store = RedisCredentialStore("test-secret", "redis://localhost:6379/0")
            record = _sample_record()

            store.save(record)
            loaded = store.load(record.connection_id)

        assert loaded is not None
        assert loaded.subject == "user-123"

    def test_load_missing_key_returns_none(self):
        with patch("redis.Redis") as mock_redis_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = None
            mock_redis_cls.from_url.return_value = mock_client

            store = RedisCredentialStore("test-secret", "redis://localhost:6379/0")
            assert store.load("does-not-exist") is None


class TestBuildCredentialStore:
    def test_defaults_to_file_backend(self, tmp_path: Path):
        settings = BrokerSettings(
            bootstrap_secret="b",
            storage_key="s",
            jwt_signing_key="j",
            data_dir=tmp_path,
        )
        assert settings.store_backend == "file"
        store = build_credential_store(settings)
        assert isinstance(store, EncryptedFileStore)

    def test_memory_backend_selected(self, tmp_path: Path):
        settings = BrokerSettings(
            bootstrap_secret="b",
            storage_key="s",
            jwt_signing_key="j",
            data_dir=tmp_path,
            store_backend="memory",
        )
        assert isinstance(build_credential_store(settings), InMemoryCredentialStore)

    def test_redis_backend_selected(self, tmp_path: Path):
        settings = BrokerSettings(
            bootstrap_secret="b",
            storage_key="s",
            jwt_signing_key="j",
            data_dir=tmp_path,
            store_backend="redis",
            redis_url="redis://localhost:6379/0",
        )
        with patch("redis.Redis") as mock_redis_cls:
            mock_redis_cls.from_url.return_value = MagicMock()
            assert isinstance(build_credential_store(settings), RedisCredentialStore)


class TestBrokerSettingsStoreBackendValidation:
    def test_from_env_rejects_unknown_backend(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET", "b")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_STORAGE_KEY", "s")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_JWT_SIGNING_KEY", "j")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_STORE_BACKEND", "sqlite")

        with pytest.raises(BrokerConfigurationError):
            BrokerSettings.from_env(require=True)

    def test_from_env_accepts_redis_backend_and_url(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET", "b")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_STORAGE_KEY", "s")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_JWT_SIGNING_KEY", "j")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_STORE_BACKEND", "redis")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_REDIS_URL", "redis://cache:6379/1")

        settings = BrokerSettings.from_env(require=True)

        assert settings is not None
        assert settings.store_backend == "redis"
        assert settings.redis_url == "redis://cache:6379/1"
