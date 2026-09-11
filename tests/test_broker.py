"""Tests for the local OAuth broker experiment."""

from __future__ import annotations

import io
import json
import time
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import jwt
from google.auth.exceptions import RefreshError
from starlette.datastructures import UploadFile
from starlette.testclient import TestClient

from google_mcp_server import broker
from google_mcp_server.broker import (
    AuthorizedUserUpload,
    BrokerConnectionRuntime,
    BrokerController,
    BrokerPermissionError,
    BrokerSettings,
    BrokerTokenVerifier,
    EncryptedFileStore,
    GoogleGrantVerifier,
    ScopeSelection,
    StoredConnectionRecord,
    UploadValidationError,
    authorize_tool_call,
    compute_permissions,
    compute_requested_scopes,
    compute_scope_status,
)


def upload_file(name: str, payload: dict) -> UploadFile:
    return UploadFile(filename=name, file=io.BytesIO(json.dumps(payload).encode("utf-8")))


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, object]):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class TestBrokerValidation:
    @pytest.mark.asyncio
    async def test_rejects_service_account_oauth_client_upload(self):
        with pytest.raises(UploadValidationError, match="Service-account"):
            await broker.validate_oauth_client_upload(
                upload_file(
                    "client.json",
                    {"type": "service_account", "private_key": "secret"},
                )
            )

    @pytest.mark.asyncio
    async def test_rejects_client_json_in_authorized_user_upload(self):
        with pytest.raises(UploadValidationError, match="OAuth client JSON"):
            await broker.validate_authorized_user_upload(
                upload_file(
                    "token.json",
                    {
                        "installed": {
                            "client_id": "id",
                            "client_secret": "secret",
                            "redirect_uris": ["http://127.0.0.1:8080/oauth/callback"],
                        }
                    },
                )
            )

    def test_requested_vs_granted_scopes_uses_verified_google_response(self):
        verifier = GoogleGrantVerifier(
            transport=Mock(
                get=Mock(
                    side_effect=[
                        FakeResponse(200, {"scope": "https://www.googleapis.com/auth/drive.file"}),
                        FakeResponse(200, {"sub": "subject-1", "email": "user@example.com", "name": "User"}),
                    ]
                )
            )
        )
        mock_creds = Mock()
        mock_creds.expired = False
        mock_creds.refresh_token = "refresh-token"
        mock_creds.token = "access-token"
        mock_creds.to_json.return_value = json.dumps(
            {
                "type": "authorized_user",
                "client_id": "cid",
                "client_secret": "csecret",
                "refresh_token": "refresh-token",
                "token": "access-token",
            }
        )

        with patch("google_mcp_server.broker.Credentials.from_authorized_user_info", return_value=mock_creds):
            verified = verifier.verify_authorized_user(
                AuthorizedUserUpload(
                    client_id="cid",
                    client_secret="csecret",
                    refresh_token="refresh-token",
                    token="access-token",
                ),
                requested_scopes=["https://www.googleapis.com/auth/drive.readonly"],
            )

        record = StoredConnectionRecord(
            connection_id="conn-1",
            requested_scopes=["https://www.googleapis.com/auth/drive.readonly"],
            verified_granted_scopes=verified.granted_scopes,
        )
        status = compute_scope_status(record)
        assert verified.granted_scopes == ["https://www.googleapis.com/auth/drive.file"]
        assert status["missing"] == ["https://www.googleapis.com/auth/drive.readonly"]

    def test_revoked_refresh_token_fails_closed(self):
        verifier = GoogleGrantVerifier(transport=Mock())
        mock_creds = Mock()
        mock_creds.expired = True
        mock_creds.refresh_token = "refresh-token"
        mock_creds.refresh.side_effect = RefreshError("revoked")

        with patch("google_mcp_server.broker.Credentials.from_authorized_user_info", return_value=mock_creds):
            with pytest.raises(BrokerPermissionError, match="refresh failed"):
                verifier.verify_authorized_user(
                    AuthorizedUserUpload(
                        client_id="cid",
                        client_secret="csecret",
                        refresh_token="refresh-token",
                    ),
                    requested_scopes=["openid"],
                )

    def test_expired_token_refreshes_before_verification(self):
        transport = Mock(
            get=Mock(
                side_effect=[
                    FakeResponse(200, {"scope": "openid"}),
                    FakeResponse(200, {"sub": "subject-1"}),
                ]
            )
        )
        verifier = GoogleGrantVerifier(transport=transport)
        mock_creds = Mock()
        mock_creds.expired = True
        mock_creds.refresh_token = "refresh-token"
        mock_creds.token = "access-token"
        mock_creds.to_json.return_value = json.dumps(
            {
                "type": "authorized_user",
                "client_id": "cid",
                "client_secret": "csecret",
                "refresh_token": "refresh-token",
                "token": "access-token",
            }
        )

        with patch("google_mcp_server.broker.Credentials.from_authorized_user_info", return_value=mock_creds):
            verifier.verify_authorized_user(
                AuthorizedUserUpload(
                    client_id="cid",
                    client_secret="csecret",
                    refresh_token="refresh-token",
                ),
                requested_scopes=["openid"],
            )

        mock_creds.refresh.assert_called_once()


class TestBrokerJwtAndAuthorization:
    def test_broker_jwt_verifier_rejects_subject_mismatch(self, tmp_path: Path):
        settings = BrokerSettings(
            bootstrap_secret="bootstrap",
            storage_key="storage-key",
            jwt_signing_key="jwt-signing-key-with-at-least-thirty-two-bytes",
            data_dir=tmp_path,
        )
        store = EncryptedFileStore(tmp_path, settings.storage_key)
        store.save(
            StoredConnectionRecord(
                connection_id="conn-1",
                subject="google-subject",
                requested_scopes=["openid"],
                permissions=["gmail.read"],
                verified_granted_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                authorized_user={
                    "type": "authorized_user",
                    "client_id": "cid",
                    "client_secret": "secret",
                    "refresh_token": "refresh",
                    "token": "access",
                },
            )
        )
        now = int(time.time())
        bad_token = jwt.encode(
            {
                "iss": settings.issuer,
                "sub": "different-subject",
                "aud": settings.mcp_audience,
                "iat": now,
                "exp": now + 300,
                "connection_id": "conn-1",
                "permissions": ["gmail.read"],
            },
            settings.jwt_signing_key,
            algorithm="HS256",
        )
        verifier = BrokerTokenVerifier(lambda require: settings, lambda _: store)

        assert asyncio.run(verifier.verify_token(bad_token)) is None

    def test_authorize_tool_call_denies_missing_permissions(self, tmp_path: Path):
        runtime = BrokerConnectionRuntime(
            BrokerSettings(
                bootstrap_secret="bootstrap",
                storage_key="storage-key",
                jwt_signing_key="jwt-signing-key-with-at-least-thirty-two-bytes",
                data_dir=tmp_path,
            ),
            EncryptedFileStore(tmp_path, "storage-key"),
            StoredConnectionRecord(
                connection_id="conn-1",
                permissions=["gmail.read"],
                verified_granted_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            ),
        )
        with pytest.raises(BrokerPermissionError):
            authorize_tool_call("gmail_send_message", {}, runtime)
        with pytest.raises(BrokerPermissionError, match="unknown MCP operation"):
            authorize_tool_call("nonexistent_tool", {}, runtime)


class TestBrokerHttpUi:
    def test_oauth_callback_rejects_state_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET", "bootstrap")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_STORAGE_KEY", "storage-key")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_JWT_SIGNING_KEY", "jwt-key")
        monkeypatch.setenv("GOOGLE_MCP_BROKER_DATA_DIR", str(tmp_path))

        from google_mcp_server.server import create_http_app

        app = create_http_app()
        client = TestClient(app)
        dashboard = client.get("/")
        csrf = dashboard.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
        login = client.post("/login", data={"csrf_token": csrf, "bootstrap_secret": "bootstrap"}, follow_redirects=False)
        assert login.status_code == 303

        response = client.get("/oauth/callback?state=wrong&code=test")
        assert response.status_code == 400
        assert response.json()["error"] == "OAuth state validation failed"


class TestBrokerScopeSelection:
    def test_selection_preserves_replace_mode_without_default_grants(self):
        selection = ScopeSelection(drive="read_only")
        scopes = compute_requested_scopes(selection)
        assert "https://www.googleapis.com/auth/drive.readonly" in scopes
        assert "https://www.googleapis.com/auth/gmail.readonly" not in scopes

    def test_selection_additive_mode_includes_legacy_defaults(self):
        selection = ScopeSelection(mode="additive_legacy", gmail="write")
        scopes = compute_requested_scopes(selection)
        for expected in (
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/gmail.modify",
        ):
            assert expected in scopes
        assert "gmail.write" in compute_permissions(selection)
