"""Local-first Google OAuth broker helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode
from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from mcp.server.auth.provider import AccessToken
from pydantic import BaseModel, Field, field_validator
from starlette.datastructures import UploadFile
from starlette.requests import Request as StarletteRequest

from .auth import DEFAULT_SCOPES

TRUSTED_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
TRUSTED_TOKEN_URI = "https://oauth2.googleapis.com/token"
TRUSTED_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
TRUSTED_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
MAX_OAUTH_CLIENT_UPLOAD_BYTES = 64 * 1024
MAX_AUTHORIZED_USER_UPLOAD_BYTES = 64 * 1024
SESSION_COOKIE_NAME = "google_mcp_broker_session"
BASE_IDENTITY_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
ADVANCED_SCOPE_ALLOWLIST = [
    "https://www.googleapis.com/auth/contacts",
    "https://www.googleapis.com/auth/documents.readonly",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/spreadsheets",
]
SERVICE_LEVEL_OPTIONS: dict[str, tuple[str, ...]] = {
    "drive": ("disabled", "selected_file", "read_only", "write"),
    "gmail": ("disabled", "read_only", "write"),
    "calendar": ("disabled", "read_only", "write"),
    "contacts": ("disabled", "read_only", "write"),
}
SERVICE_SCOPE_PRESETS: dict[str, dict[str, list[str]]] = {
    "drive": {
        "disabled": [],
        "selected_file": [
            "https://www.googleapis.com/auth/drive.appdata",
            "https://www.googleapis.com/auth/drive.file",
        ],
        "read_only": ["https://www.googleapis.com/auth/drive.readonly"],
        "write": ["https://www.googleapis.com/auth/drive"],
    },
    "gmail": {
        "disabled": [],
        "read_only": [
            "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
            "https://www.googleapis.com/auth/gmail.labels",
            "https://www.googleapis.com/auth/gmail.readonly",
        ],
        "write": [
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.labels",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
        ],
    },
    "calendar": {
        "disabled": [],
        "read_only": ["https://www.googleapis.com/auth/calendar.readonly"],
        "write": ["https://www.googleapis.com/auth/calendar"],
    },
    "contacts": {
        "disabled": [],
        "read_only": ["https://www.googleapis.com/auth/contacts.readonly"],
        "write": ["https://www.googleapis.com/auth/contacts"],
    },
}

READABLE_LEVEL_LABELS = {
    "disabled": "Disabled",
    "selected_file": "Selected-file",
    "read_only": "Read-only",
    "write": "Write",
}


class BrokerError(RuntimeError):
    """Base broker error."""


class BrokerConfigurationError(BrokerError):
    """Raised when broker mode is misconfigured."""


class BrokerPermissionError(BrokerError):
    """Raised when broker JWT or Google grants do not allow an operation."""


class UploadValidationError(BrokerError):
    """Raised when uploaded broker configuration is invalid."""


class ScopeSelection(BaseModel):
    """Requested service-level authorization for the broker."""

    mode: Literal["replace", "additive_legacy"] = "replace"
    drive: Literal["disabled", "selected_file", "read_only", "write"] = "disabled"
    gmail: Literal["disabled", "read_only", "write"] = "disabled"
    calendar: Literal["disabled", "read_only", "write"] = "disabled"
    contacts: Literal["disabled", "read_only", "write"] = "disabled"
    advanced_scopes: list[str] = Field(default_factory=list)

    @field_validator("advanced_scopes")
    @classmethod
    def validate_advanced_scopes(cls, value: list[str]) -> list[str]:
        invalid = sorted(set(value) - set(ADVANCED_SCOPE_ALLOWLIST))
        if invalid:
            raise ValueError(f"Unsupported advanced scope selection: {', '.join(invalid)}")
        return sorted(set(value))


class OAuthClientConfig(BaseModel):
    """Validated Google OAuth client configuration."""

    client_type: Literal["installed", "web"]
    client_id: str
    client_secret: str
    redirect_uris: list[str]

    def to_google_client_config(self) -> dict[str, Any]:
        return {
            self.client_type: {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uris": self.redirect_uris,
                "auth_uri": TRUSTED_AUTH_URI,
                "token_uri": TRUSTED_TOKEN_URI,
            }
        }


class AuthorizedUserUpload(BaseModel):
    """Validated authorized-user token upload."""

    client_id: str
    client_secret: str
    refresh_token: str
    token: str | None = None
    expiry: str | None = None

    def to_google_authorized_user_info(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "type": "authorized_user",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
            "token_uri": TRUSTED_TOKEN_URI,
        }
        if self.token:
            data["token"] = self.token
        if self.expiry:
            data["expiry"] = self.expiry
        return data

    @classmethod
    def from_stored_info(cls, info: dict[str, Any]) -> "AuthorizedUserUpload":
        return cls(
            client_id=info["client_id"],
            client_secret=info["client_secret"],
            refresh_token=info["refresh_token"],
            token=info.get("token"),
            expiry=info.get("expiry"),
        )


class StoredConnectionRecord(BaseModel):
    """Encrypted per-connection broker state."""

    connection_id: str
    selection: ScopeSelection = Field(default_factory=ScopeSelection)
    requested_scopes: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    verified_granted_scopes: list[str] = Field(default_factory=list)
    client_config: OAuthClientConfig | None = None
    authorized_user: dict[str, Any] | None = None
    subject: str | None = None
    email: str | None = None
    display_name: str | None = None
    last_verified_at: str | None = None


class VerifiedGoogleGrant(BaseModel):
    """Verified Google grant state after token import or OAuth callback."""

    authorized_user: dict[str, Any]
    granted_scopes: list[str]
    subject: str
    email: str | None = None
    display_name: str | None = None
    last_verified_at: str


class BrokerSettings(BaseModel):
    """Environment-driven broker runtime settings."""

    bootstrap_secret: str
    storage_key: str
    jwt_signing_key: str
    public_base_url: str = "http://127.0.0.1:8080"
    http_host: str = "127.0.0.1"
    http_port: int = 8080
    jwt_ttl_seconds: int = 300
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".local" / "state" / "google-mcp-server" / "broker")

    @property
    def callback_url(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/oauth/callback"

    @property
    def mcp_audience(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/mcp"

    @property
    def issuer(self) -> str:
        return self.public_base_url.rstrip("/")

    @classmethod
    def from_env(cls, *, require: bool) -> "BrokerSettings | None":
        bootstrap_secret = os.getenv("GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET", "")
        storage_key = os.getenv("GOOGLE_MCP_BROKER_STORAGE_KEY", "")
        jwt_signing_key = os.getenv("GOOGLE_MCP_BROKER_JWT_SIGNING_KEY", "")
        placeholder_prefix = "__MISSING_"
        if bootstrap_secret.startswith(placeholder_prefix):
            bootstrap_secret = ""
        if storage_key.startswith(placeholder_prefix):
            storage_key = ""
        if jwt_signing_key.startswith(placeholder_prefix):
            jwt_signing_key = ""
        if not bootstrap_secret and not storage_key and not jwt_signing_key and not require:
            return None
        if not bootstrap_secret or not storage_key or not jwt_signing_key:
            raise BrokerConfigurationError(
                "Broker mode requires GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET, "
                "GOOGLE_MCP_BROKER_STORAGE_KEY, and GOOGLE_MCP_BROKER_JWT_SIGNING_KEY"
            )
        public_base_url = os.getenv("GOOGLE_MCP_PUBLIC_BASE_URL", "http://127.0.0.1:8080")
        return cls(
            bootstrap_secret=bootstrap_secret,
            storage_key=storage_key,
            jwt_signing_key=jwt_signing_key,
            public_base_url=public_base_url,
            http_host=os.getenv("GOOGLE_MCP_HTTP_HOST", "127.0.0.1"),
            http_port=int(os.getenv("GOOGLE_MCP_HTTP_PORT", "8080")),
            jwt_ttl_seconds=int(os.getenv("GOOGLE_MCP_BROKER_JWT_TTL_SECONDS", "300")),
            data_dir=Path(os.getenv("GOOGLE_MCP_BROKER_DATA_DIR", str(Path.home() / ".local" / "state" / "google-mcp-server" / "broker"))),
        )


@dataclass
class AdminSession:
    session_id: str
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    authenticated: bool = False
    connection_id: str = field(default_factory=lambda: uuid4().hex)
    flash_message: str | None = None
    oauth_state: str | None = None
    oauth_code_verifier: str | None = None
    oauth_requested_scopes: list[str] = field(default_factory=list)


class EncryptedFileStore:
    """Persist encrypted broker records on disk."""

    def __init__(self, data_dir: Path, secret: str):
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._data_dir.chmod(0o700)
        self._key = self._derive_key(secret)

    @staticmethod
    def _derive_key(secret: str) -> bytes:
        try:
            raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
            if len(raw) >= 32:
                return raw[:32]
        except Exception:
            pass
        return hashlib.sha256(secret.encode("utf-8")).digest()

    def _path_for(self, connection_id: str) -> Path:
        return self._data_dir / f"{connection_id}.json"

    def save(self, record: StoredConnectionRecord) -> None:
        payload = record.model_dump_json().encode("utf-8")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, payload, None)
        wrapper = {
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        }
        path = self._path_for(record.connection_id)
        path.write_text(json.dumps(wrapper), encoding="utf-8")
        path.chmod(0o600)

    def load(self, connection_id: str) -> StoredConnectionRecord | None:
        path = self._path_for(connection_id)
        if not path.exists():
            return None
        wrapper = json.loads(path.read_text(encoding="utf-8"))
        nonce = base64.urlsafe_b64decode(wrapper["nonce"])
        ciphertext = base64.urlsafe_b64decode(wrapper["ciphertext"])
        plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, None)
        return StoredConnectionRecord.model_validate_json(plaintext)


class GoogleGrantVerifier:
    """Verify actual Google grants with trusted Google endpoints."""

    def __init__(self, transport: httpx.Client | None = None):
        self._transport = transport or httpx.Client(timeout=10.0)

    def verify_authorized_user(
        self,
        upload: AuthorizedUserUpload,
        *,
        requested_scopes: list[str],
    ) -> VerifiedGoogleGrant:
        creds = Credentials.from_authorized_user_info(
            upload.to_google_authorized_user_info(),
            requested_scopes or BASE_IDENTITY_SCOPES,
        )
        try:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
        except RefreshError as exc:
            raise BrokerPermissionError("Google refresh failed; re-authorize with Google consent") from exc
        if not creds.token:
            raise BrokerPermissionError("No valid Google access token is available")

        tokeninfo = self._transport.get(TRUSTED_TOKENINFO_URL, params={"access_token": creds.token})
        if tokeninfo.status_code != 200:
            raise BrokerPermissionError("Google rejected the uploaded token; re-authorize with Google consent")
        tokeninfo_data = tokeninfo.json()
        granted_scopes = sorted(set((tokeninfo_data.get("scope") or "").split()))
        if not granted_scopes:
            raise BrokerPermissionError("Could not verify any granted Google scopes")

        userinfo = self._transport.get(
            TRUSTED_USERINFO_URL,
            headers={"Authorization": f"******"},
        )
        if userinfo.status_code != 200:
            raise BrokerPermissionError("Could not verify the Google account for this token")
        userinfo_data = userinfo.json()
        subject = userinfo_data.get("sub")
        if not subject:
            raise BrokerPermissionError("Could not verify the Google account subject for this token")

        verified_at = datetime.now(timezone.utc).isoformat()
        return VerifiedGoogleGrant(
            authorized_user=json.loads(creds.to_json()),
            granted_scopes=granted_scopes,
            subject=subject,
            email=userinfo_data.get("email"),
            display_name=userinfo_data.get("name"),
            last_verified_at=verified_at,
        )


class BrokerTokenVerifier:
    """Validates broker-issued JWTs for MCP HTTP requests."""

    def __init__(self, settings_provider, store_provider):
        self._settings_provider = settings_provider
        self._store_provider = store_provider

    async def verify_token(self, token: str) -> AccessToken | None:
        settings = self._settings_provider(require=False)
        if settings is None:
            return None
        try:
            claims = jwt.decode(
                token,
                settings.jwt_signing_key,
                algorithms=["HS256"],
                audience=settings.mcp_audience,
                issuer=settings.issuer,
                options={"require": ["aud", "connection_id", "exp", "iat", "iss", "permissions", "sub"]},
            )
        except jwt.PyJWTError:
            return None
        connection_id = claims.get("connection_id")
        subject = claims.get("sub")
        if not isinstance(connection_id, str) or not isinstance(subject, str):
            return None
        record = self._store_provider(settings).load(connection_id)
        if record is None or record.subject != subject:
            return None
        permissions = claims.get("permissions")
        if not isinstance(permissions, list) or not all(isinstance(item, str) for item in permissions):
            return None
        expires_at = claims.get("exp")
        return AccessToken(
            token=token,
            client_id="google-mcp-server-broker",
            scopes=permissions,
            expires_at=expires_at if isinstance(expires_at, int) else None,
            resource=settings.mcp_audience,
            subject=subject,
            claims=claims,
        )


class BrokerConnectionRuntime:
    """Per-request Google runtime resolved from a broker JWT."""

    def __init__(self, settings: BrokerSettings, store: EncryptedFileStore, record: StoredConnectionRecord):
        self._settings = settings
        self._store = store
        self.record = record
        self._creds: Credentials | None = None
        self._drive_client = None
        self._docs_client = None
        self._gmail_client = None
        self._calendar_client = None
        self._contacts_client = None
        self._integration_client = None
        self._smart_tools = None
        self._safe_tools = None

    @property
    def permissions(self) -> set[str]:
        return set(self.record.permissions)

    @property
    def granted_scopes(self) -> set[str]:
        return set(self.record.verified_granted_scopes)

    def ensure_permission(self, required: str) -> None:
        allowed = self.permissions
        if required.startswith("drive."):
            if required == "drive.read" and allowed.intersection({"drive.read", "drive.write", "drive.selected_file"}):
                return
            if required == "drive.write" and allowed.intersection({"drive.write", "drive.selected_file"}):
                return
        if required.startswith("gmail."):
            if required == "gmail.read" and allowed.intersection({"gmail.read", "gmail.write"}):
                return
            if required == "gmail.write" and "gmail.write" in allowed:
                return
        if required.startswith("calendar."):
            if required == "calendar.read" and allowed.intersection({"calendar.read", "calendar.write"}):
                return
            if required == "calendar.write" and "calendar.write" in allowed:
                return
        if required.startswith("contacts."):
            if required == "contacts.read" and allowed.intersection({"contacts.read", "contacts.write"}):
                return
            if required == "contacts.write" and "contacts.write" in allowed:
                return
        if required == "broker.authenticated":
            return
        raise BrokerPermissionError(f"Broker policy denied permission: {required}")

    def ensure_google_scope(self, accepted_scopes: set[str]) -> None:
        if self.granted_scopes.intersection(accepted_scopes):
            return
        raise BrokerPermissionError("Google has not granted the scope required for this MCP operation")

    def _refresh_record_if_needed(self) -> None:
        if self.record.authorized_user is None:
            raise BrokerPermissionError("No verified Google credentials are stored for this connection")
        creds = Credentials.from_authorized_user_info(self.record.authorized_user, self.record.requested_scopes or BASE_IDENTITY_SCOPES)
        try:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
                verifier = GoogleGrantVerifier()
                verified = verifier.verify_authorized_user(
                    AuthorizedUserUpload.from_stored_info(json.loads(creds.to_json())),
                    requested_scopes=self.record.requested_scopes,
                )
                self.record.authorized_user = verified.authorized_user
                self.record.verified_granted_scopes = verified.granted_scopes
                self.record.subject = verified.subject
                self.record.email = verified.email
                self.record.display_name = verified.display_name
                self.record.last_verified_at = verified.last_verified_at
                self._store.save(self.record)
                creds = Credentials.from_authorized_user_info(self.record.authorized_user, self.record.requested_scopes or BASE_IDENTITY_SCOPES)
        except RefreshError as exc:
            raise BrokerPermissionError("Stored Google credentials have expired or been revoked") from exc
        self._creds = creds

    def get_credentials(self) -> Credentials:
        if self._creds is None:
            self._refresh_record_if_needed()
        assert self._creds is not None
        return self._creds

    def get_drive_client(self):
        if self._drive_client is None:
            from .drive_client import GoogleDriveClient

            self._drive_client = GoogleDriveClient(self.get_credentials())
        return self._drive_client

    def get_docs_client(self):
        if self._docs_client is None:
            from .docs_client import GoogleDocsClient

            self._docs_client = GoogleDocsClient(self.get_credentials())
        return self._docs_client

    def get_gmail_client(self):
        if self._gmail_client is None:
            from .gmail_client import GmailClient

            self._gmail_client = GmailClient(self.get_credentials())
        return self._gmail_client

    def get_calendar_client(self):
        if self._calendar_client is None:
            from .calendar_client import GoogleCalendarClient

            self._calendar_client = GoogleCalendarClient(self.get_credentials())
        return self._calendar_client

    def get_contacts_client(self):
        if self._contacts_client is None:
            from .contacts_client import GoogleContactsClient

            self._contacts_client = GoogleContactsClient(self.get_credentials())
        return self._contacts_client

    def get_integration_client(self):
        if self._integration_client is None:
            from .integration_client import GoogleIntegrationClient

            self._integration_client = GoogleIntegrationClient(
                self.get_drive_client(),
                self.get_gmail_client(),
                self.get_calendar_client(),
            )
        return self._integration_client

    def get_smart_tools(self):
        if self._smart_tools is None:
            from .smart_tools import SmartGoogleTools

            self._smart_tools = SmartGoogleTools(
                self.get_contacts_client(),
                self.get_gmail_client(),
                self.get_drive_client(),
                self.get_calendar_client(),
            )
        return self._smart_tools

    def get_safe_tools(self):
        if self._safe_tools is None:
            from .safe_tools import SafeGoogleTools

            self._safe_tools = SafeGoogleTools(
                self.get_contacts_client(),
                self.get_gmail_client(),
                self.get_drive_client(),
                self.get_calendar_client(),
            )
        return self._safe_tools


def normalize_selection(raw: dict[str, str | list[str] | None]) -> ScopeSelection:
    advanced = raw.get("advanced_scopes") or []
    if isinstance(advanced, str):
        advanced = [advanced]
    return ScopeSelection(
        mode=(raw.get("mode") or "replace"),
        drive=(raw.get("drive") or "disabled"),
        gmail=(raw.get("gmail") or "disabled"),
        calendar=(raw.get("calendar") or "disabled"),
        contacts=(raw.get("contacts") or "disabled"),
        advanced_scopes=list(advanced),
    )


def compute_requested_scopes(selection: ScopeSelection) -> list[str]:
    scopes = set(BASE_IDENTITY_SCOPES)
    if selection.mode == "additive_legacy":
        scopes.update(DEFAULT_SCOPES)
    for service_name in SERVICE_LEVEL_OPTIONS:
        scopes.update(SERVICE_SCOPE_PRESETS[service_name][getattr(selection, service_name)])
    scopes.update(selection.advanced_scopes)
    return sorted(scopes)


def compute_permissions(selection: ScopeSelection) -> list[str]:
    permissions: set[str] = set()
    if selection.drive == "selected_file":
        permissions.add("drive.selected_file")
    elif selection.drive == "read_only":
        permissions.add("drive.read")
    elif selection.drive == "write":
        permissions.add("drive.write")

    if selection.gmail == "read_only":
        permissions.add("gmail.read")
    elif selection.gmail == "write":
        permissions.add("gmail.write")

    if selection.calendar == "read_only":
        permissions.add("calendar.read")
    elif selection.calendar == "write":
        permissions.add("calendar.write")

    if selection.contacts == "read_only":
        permissions.add("contacts.read")
    elif selection.contacts == "write":
        permissions.add("contacts.write")

    return sorted(permissions)


def compute_scope_status(record: StoredConnectionRecord) -> dict[str, list[str]]:
    requested = set(record.requested_scopes)
    granted = set(record.verified_granted_scopes)
    return {
        "requested": sorted(requested),
        "granted": sorted(granted),
        "missing": sorted(requested - granted),
    }


async def read_upload_json(upload: UploadFile, *, max_bytes: int) -> dict[str, Any]:
    if not upload.filename:
        raise UploadValidationError("A JSON file upload is required")
    payload = await upload.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise UploadValidationError("Uploaded JSON file is too large")
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise UploadValidationError("Uploaded file is not valid JSON") from exc


async def validate_oauth_client_upload(upload: UploadFile) -> OAuthClientConfig:
    data = await read_upload_json(upload, max_bytes=MAX_OAUTH_CLIENT_UPLOAD_BYTES)
    if data.get("type") == "service_account" or "private_key" in data:
        raise UploadValidationError("Service-account private keys are not supported by this prototype")
    if "installed" in data and "web" in data:
        raise UploadValidationError("Upload either an installed-app JSON or a web-app JSON, not both")
    client_type = "installed" if "installed" in data else "web" if "web" in data else None
    if client_type is None:
        raise UploadValidationError("Google OAuth client JSON must contain an 'installed' or 'web' object")
    client_data = data[client_type]
    if not isinstance(client_data, dict):
        raise UploadValidationError("Google OAuth client JSON has an invalid structure")
    client_id = client_data.get("client_id")
    client_secret = client_data.get("client_secret")
    redirect_uris = client_data.get("redirect_uris") or []
    if not client_id or not client_secret:
        raise UploadValidationError("Google OAuth client JSON must contain client_id and client_secret")
    if not isinstance(redirect_uris, list) or not all(isinstance(item, str) for item in redirect_uris):
        raise UploadValidationError("Google OAuth client JSON must contain redirect_uris")
    return OAuthClientConfig(
        client_type=client_type,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=redirect_uris,
    )


async def validate_authorized_user_upload(upload: UploadFile) -> AuthorizedUserUpload:
    data = await read_upload_json(upload, max_bytes=MAX_AUTHORIZED_USER_UPLOAD_BYTES)
    if data.get("type") == "service_account" or "private_key" in data:
        raise UploadValidationError("Service-account private keys are not supported by this prototype")
    if "installed" in data or "web" in data:
        raise UploadValidationError("OAuth client JSON must be uploaded in the OAuth client section, not as a token")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    refresh_token = data.get("refresh_token")
    if not client_id or not client_secret or not refresh_token:
        raise UploadValidationError(
            "Authorized-user token JSON must contain client_id, client_secret, and refresh_token"
        )
    return AuthorizedUserUpload(
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
        token=data.get("token") or data.get("access_token"),
        expiry=data.get("expiry"),
    )


def build_google_flow(
    client_config: OAuthClientConfig,
    *,
    requested_scopes: list[str],
    redirect_uri: str,
    state: str | None = None,
    code_verifier: str | None = None,
) -> Flow:
    flow = Flow.from_client_config(
        client_config.to_google_client_config(),
        requested_scopes,
        redirect_uri=redirect_uri,
        state=state,
        code_verifier=code_verifier,
        autogenerate_code_verifier=code_verifier is None,
    )
    flow.redirect_uri = redirect_uri
    return flow


class BrokerController:
    """HTTP controller for the local broker UI."""

    def __init__(self, settings: BrokerSettings, grant_verifier: GoogleGrantVerifier | None = None):
        self.settings = settings
        self.store = EncryptedFileStore(settings.data_dir, settings.storage_key)
        self.grant_verifier = grant_verifier or GoogleGrantVerifier()
        self.sessions: dict[str, AdminSession] = {}

    def _record_for_connection(self, connection_id: str) -> StoredConnectionRecord:
        record = self.store.load(connection_id)
        if record is not None:
            return record
        record = StoredConnectionRecord(connection_id=connection_id)
        record.requested_scopes = compute_requested_scopes(record.selection)
        record.permissions = compute_permissions(record.selection)
        self.store.save(record)
        return record

    def get_runtime_for_claims(self, claims: dict[str, Any]) -> BrokerConnectionRuntime:
        connection_id = claims.get("connection_id")
        subject = claims.get("sub")
        if not isinstance(connection_id, str) or not isinstance(subject, str):
            raise BrokerPermissionError("Broker JWT is missing its connection binding")
        record = self.store.load(connection_id)
        if record is None or record.subject != subject:
            raise BrokerPermissionError("Broker JWT does not match the stored Google credentials")
        return BrokerConnectionRuntime(self.settings, self.store, record)

    def mint_broker_token(self, record: StoredConnectionRecord) -> dict[str, Any]:
        status = compute_scope_status(record)
        if not record.authorized_user or not record.subject:
            raise BrokerPermissionError("Google credentials must be uploaded or authorized before minting a broker token")
        if status["missing"]:
            raise BrokerPermissionError("Requested Google scopes are missing consent; complete Google authorization first")
        now = int(time.time())
        payload = {
            "iss": self.settings.issuer,
            "sub": record.subject,
            "aud": self.settings.mcp_audience,
            "iat": now,
            "exp": now + self.settings.jwt_ttl_seconds,
            "connection_id": record.connection_id,
            "permissions": record.permissions,
            "email": record.email,
        }
        token = jwt.encode(payload, self.settings.jwt_signing_key, algorithm="HS256")
        return {
            "token": token,
            "expires_at": payload["exp"],
            "audience": payload["aud"],
            "connection_id": record.connection_id,
            "permissions": record.permissions,
        }

    def _get_session(self, request: StarletteRequest) -> tuple[AdminSession, bool]:
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        created = False
        if session_id and session_id in self.sessions:
            return self.sessions[session_id], created
        session = AdminSession(session_id=secrets.token_urlsafe(24))
        self.sessions[session.session_id] = session
        created = True
        return session, created

    def _attach_session_cookie(self, response, session: AdminSession, *, created: bool) -> None:
        if created or SESSION_COOKIE_NAME not in response.headers.get("set-cookie", ""):
            response.set_cookie(
                SESSION_COOKIE_NAME,
                session.session_id,
                httponly=True,
                samesite="lax",
                secure=self.settings.public_base_url.startswith("https://"),
                path="/",
            )
        response.headers["Cache-Control"] = "no-store"

    async def _require_form_session(self, request: StarletteRequest) -> tuple[AdminSession, dict[str, Any], bool]:
        session, created = self._get_session(request)
        form = await request.form()
        csrf_token = form.get("csrf_token")
        if not isinstance(csrf_token, str) or not hmac.compare_digest(csrf_token, session.csrf_token):
            raise BrokerPermissionError("CSRF validation failed")
        if not session.authenticated:
            raise BrokerPermissionError("Broker administration login is required")
        return session, dict(form), created

    async def dashboard(self, request: StarletteRequest):
        session, created = self._get_session(request)
        record = self._record_for_connection(session.connection_id)
        scope_status = compute_scope_status(record)
        if session.flash_message:
            flash = session.flash_message
            session.flash_message = None
        else:
            flash = ""
        html = render_dashboard(
            session=session,
            record=record,
            settings=self.settings,
            scope_status=scope_status,
            flash_message=flash,
        )
        from starlette.responses import HTMLResponse

        response = HTMLResponse(html)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def login(self, request: StarletteRequest):
        session, created = self._get_session(request)
        form = await request.form()
        csrf_token = form.get("csrf_token")
        secret = form.get("bootstrap_secret")
        if not isinstance(csrf_token, str) or not hmac.compare_digest(csrf_token, session.csrf_token):
            raise BrokerPermissionError("CSRF validation failed")
        if not isinstance(secret, str) or not hmac.compare_digest(secret, self.settings.bootstrap_secret):
            raise BrokerPermissionError("Bootstrap secret is invalid")
        session.authenticated = True
        from starlette.responses import RedirectResponse

        response = RedirectResponse(url="/", status_code=303)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def save_selection(self, request: StarletteRequest):
        session, form, created = await self._require_form_session(request)
        record = self._record_for_connection(session.connection_id)
        record.selection = normalize_selection(form)
        record.requested_scopes = compute_requested_scopes(record.selection)
        record.permissions = compute_permissions(record.selection)
        self.store.save(record)
        session.flash_message = "Updated requested Google scopes and broker permissions."
        from starlette.responses import RedirectResponse

        response = RedirectResponse(url="/", status_code=303)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def upload_client_config(self, request: StarletteRequest):
        session, _, created = await self._require_form_session(request)
        form = await request.form()
        upload = form.get("oauth_client_file")
        if not isinstance(upload, UploadFile):
            raise UploadValidationError("Upload an OAuth client JSON file")
        client_config = await validate_oauth_client_upload(upload)
        record = self._record_for_connection(session.connection_id)
        record.client_config = client_config
        self.store.save(record)
        session.flash_message = f"Stored encrypted {client_config.client_type} OAuth client configuration."
        from starlette.responses import RedirectResponse

        response = RedirectResponse(url="/", status_code=303)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def upload_authorized_user(self, request: StarletteRequest):
        session, _, created = await self._require_form_session(request)
        form = await request.form()
        upload = form.get("authorized_user_file")
        if not isinstance(upload, UploadFile):
            raise UploadValidationError("Upload an authorized-user token JSON file")
        token_upload = await validate_authorized_user_upload(upload)
        record = self._record_for_connection(session.connection_id)
        verified = self.grant_verifier.verify_authorized_user(
            token_upload,
            requested_scopes=record.requested_scopes,
        )
        record.authorized_user = verified.authorized_user
        record.verified_granted_scopes = verified.granted_scopes
        record.subject = verified.subject
        record.email = verified.email
        record.display_name = verified.display_name
        record.last_verified_at = verified.last_verified_at
        self.store.save(record)
        session.flash_message = "Imported and verified Google authorized-user credentials."
        from starlette.responses import RedirectResponse

        response = RedirectResponse(url="/", status_code=303)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def start_google_oauth(self, request: StarletteRequest):
        session, _, created = await self._require_form_session(request)
        record = self._record_for_connection(session.connection_id)
        if record.client_config is None:
            raise UploadValidationError("Upload a Google OAuth client JSON file before starting browser consent")
        if self.settings.callback_url not in record.client_config.redirect_uris:
            raise UploadValidationError(
                "The uploaded OAuth client JSON must include the broker callback URL in redirect_uris"
            )
        flow = build_google_flow(
            record.client_config,
            requested_scopes=record.requested_scopes,
            redirect_uri=self.settings.callback_url,
        )
        include_granted_scopes = "true" if record.selection.mode == "additive_legacy" else "false"
        auth_url, state = flow.authorization_url(
            prompt="consent",
            include_granted_scopes=include_granted_scopes,
        )
        session.oauth_state = state
        session.oauth_code_verifier = flow.code_verifier
        session.oauth_requested_scopes = list(record.requested_scopes)
        from starlette.responses import RedirectResponse

        response = RedirectResponse(url=auth_url, status_code=303)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def oauth_callback(self, request: StarletteRequest):
        session, created = self._get_session(request)
        if not session.authenticated:
            raise BrokerPermissionError("Broker administration login is required")
        state = request.query_params.get("state")
        if not state or not session.oauth_state or not hmac.compare_digest(state, session.oauth_state):
            raise BrokerPermissionError("OAuth state validation failed")
        if request.query_params.get("error"):
            raise BrokerPermissionError(f"Google authorization failed: {request.query_params['error']}")
        record = self._record_for_connection(session.connection_id)
        if record.client_config is None:
            raise UploadValidationError("OAuth client configuration is missing for this broker session")
        flow = build_google_flow(
            record.client_config,
            requested_scopes=session.oauth_requested_scopes or record.requested_scopes,
            redirect_uri=self.settings.callback_url,
            state=session.oauth_state,
            code_verifier=session.oauth_code_verifier,
        )
        flow.fetch_token(authorization_response=str(request.url))
        credentials = flow.credentials
        verified = self.grant_verifier.verify_authorized_user(
            AuthorizedUserUpload.from_stored_info(json.loads(credentials.to_json())),
            requested_scopes=record.requested_scopes,
        )
        record.authorized_user = verified.authorized_user
        record.verified_granted_scopes = verified.granted_scopes
        record.subject = verified.subject
        record.email = verified.email
        record.display_name = verified.display_name
        record.last_verified_at = verified.last_verified_at
        self.store.save(record)
        session.oauth_state = None
        session.oauth_code_verifier = None
        session.oauth_requested_scopes = []
        session.flash_message = "Completed Google OAuth consent and verified granted scopes."
        from starlette.responses import RedirectResponse

        response = RedirectResponse(url="/", status_code=303)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def broker_token(self, request: StarletteRequest):
        session, _, created = await self._require_form_session(request)
        record = self._record_for_connection(session.connection_id)
        payload = self.mint_broker_token(record)
        from starlette.responses import JSONResponse

        response = JSONResponse(payload)
        self._attach_session_cookie(response, session, created=created)
        return response

    async def health(self, request: StarletteRequest):
        from starlette.responses import JSONResponse

        return JSONResponse({"ok": True, "service": "google-mcp-server", "runtime": "broker"})


def render_dashboard(
    *,
    session: AdminSession,
    record: StoredConnectionRecord,
    settings: BrokerSettings,
    scope_status: dict[str, list[str]],
    flash_message: str,
) -> str:
    connection_id = html.escape(record.connection_id)
    callback_url = html.escape(settings.callback_url)
    audience = html.escape(settings.mcp_audience)
    client_status = html.escape(
        f"Stored encrypted {record.client_config.client_type} client JSON"
        if record.client_config
        else "No OAuth client JSON uploaded"
    )
    token_status = html.escape(record.email or record.subject or "No authorized-user token verified")

    def selected_option(name: str, current: str, value: str) -> str:
        return f'<option value="{value}"{" selected" if current == value else ""}>{READABLE_LEVEL_LABELS[value]}</option>'

    advanced_checkboxes = "\n".join(
        f'<label><input type="checkbox" name="advanced_scopes" value="{html.escape(scope)}"{" checked" if scope in record.selection.advanced_scopes else ""}> {html.escape(scope)}</label><br>'
        for scope in ADVANCED_SCOPE_ALLOWLIST
    )
    requested = "<br>".join(html.escape(item) for item in scope_status["requested"]) or "<em>None</em>"
    granted = "<br>".join(html.escape(item) for item in scope_status["granted"]) or "<em>Not yet verified</em>"
    missing = "<br>".join(html.escape(item) for item in scope_status["missing"]) or "<em>None</em>"
    flash_html = f"<p><strong>{html.escape(flash_message)}</strong></p>" if flash_message else ""
    login_form = f"""
    <form method=\"post\" action=\"/login\">
      <input type=\"hidden\" name=\"csrf_token\" value=\"{session.csrf_token}\">
      <label>Bootstrap secret <input type=\"password\" name=\"bootstrap_secret\" required></label>
      <button type=\"submit\">Login</button>
    </form>
    """
    body = login_form
    if session.authenticated:
        body = f"""
        <p><strong>Connection:</strong> {connection_id}</p>
        <p><strong>OAuth client JSON:</strong> {client_status}</p>
        <p><strong>Authorized user:</strong> {token_status}</p>
        <p><strong>Broker callback URL:</strong> {callback_url}</p>
        <p><strong>Production limits:</strong> local single-process prototype; admin login is bootstrap-secret based; one browser admin session owns one connection ID at a time.</p>
        <h2>1. Select scopes</h2>
        <form method=\"post\" action=\"/selection\">
          <input type=\"hidden\" name=\"csrf_token\" value=\"{session.csrf_token}\">
          <label>Scope mode
            <select name=\"mode\">
              <option value=\"replace\"{' selected' if record.selection.mode == 'replace' else ''}>Replace (no default broad grants)</option>
              <option value=\"additive_legacy\"{' selected' if record.selection.mode == 'additive_legacy' else ''}>Additive legacy defaults</option>
            </select>
          </label><br>
          <label>Drive <select name=\"drive\">{selected_option('drive', record.selection.drive, 'disabled')}{selected_option('drive', record.selection.drive, 'selected_file')}{selected_option('drive', record.selection.drive, 'read_only')}{selected_option('drive', record.selection.drive, 'write')}</select></label><br>
          <label>Gmail <select name=\"gmail\">{selected_option('gmail', record.selection.gmail, 'disabled')}{selected_option('gmail', record.selection.gmail, 'read_only')}{selected_option('gmail', record.selection.gmail, 'write')}</select></label><br>
          <label>Calendar <select name=\"calendar\">{selected_option('calendar', record.selection.calendar, 'disabled')}{selected_option('calendar', record.selection.calendar, 'read_only')}{selected_option('calendar', record.selection.calendar, 'write')}</select></label><br>
          <label>Contacts <select name=\"contacts\">{selected_option('contacts', record.selection.contacts, 'disabled')}{selected_option('contacts', record.selection.contacts, 'read_only')}{selected_option('contacts', record.selection.contacts, 'write')}</select></label><br>
          <fieldset><legend>Advanced allowlisted scopes</legend>{advanced_checkboxes}</fieldset>
          <button type=\"submit\">Save scope selection</button>
        </form>
        <h2>2. Upload Google credentials</h2>
        <p>Upload OAuth client JSON separately from authorized-user token JSON. Service-account private keys are rejected for this prototype.</p>
        <form method=\"post\" action=\"/upload/oauth-client\" enctype=\"multipart/form-data\">
          <input type=\"hidden\" name=\"csrf_token\" value=\"{session.csrf_token}\">
          <label>OAuth client JSON (installed or web) <input type=\"file\" name=\"oauth_client_file\" accept=\"application/json\" required></label>
          <button type=\"submit\">Upload client JSON</button>
        </form>
        <form method=\"post\" action=\"/upload/authorized-user\" enctype=\"multipart/form-data\">
          <input type=\"hidden\" name=\"csrf_token\" value=\"{session.csrf_token}\">
          <label>Authorized-user token JSON <input type=\"file\" name=\"authorized_user_file\" accept=\"application/json\" required></label>
          <button type=\"submit\">Upload token JSON</button>
        </form>
        <h2>3. Google consent and broker token</h2>
        <form method=\"post\" action=\"/oauth/start\">
          <input type=\"hidden\" name=\"csrf_token\" value=\"{session.csrf_token}\">
          <button type=\"submit\">Open Google consent flow</button>
        </form>
        <form method=\"post\" action=\"/broker-token\">
          <input type=\"hidden\" name=\"csrf_token\" value=\"{session.csrf_token}\">
          <button type=\"submit\">Mint short-lived broker JWT (JSON response)</button>
        </form>
        <h2>Scope status</h2>
        <p><strong>Requested scopes</strong><br>{requested}</p>
        <p><strong>Verified granted scopes</strong><br>{granted}</p>
        <p><strong>Missing scopes that still require real Google consent</strong><br>{missing}</p>
        <p><strong>JWT audience</strong>: {audience}</p>
        <p><strong>Desktop vs Web OAuth setup</strong>: web clients must include the exact callback URL above; installed clients also need that callback listed here for this containerized loopback prototype.</p>
        """
    return f"""
    <!doctype html>
    <html>
      <head>
        <meta charset=\"utf-8\">
        <title>google-mcp-server OAuth broker</title>
      </head>
      <body>
        <h1>google-mcp-server local OAuth broker</h1>
        {flash_html}
        {body}
      </body>
    </html>
    """


def authorize_tool_call(tool_name: str, arguments: dict[str, Any], runtime: BrokerConnectionRuntime) -> None:
    def drive_read() -> None:
        runtime.ensure_permission("drive.read")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/drive.readonly",
        })

    def drive_write() -> None:
        runtime.ensure_permission("drive.write")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/drive.file",
        })

    def docs_read() -> None:
        runtime.ensure_permission("drive.read")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/documents.readonly",
            "https://www.googleapis.com/auth/drive",
        })

    def gmail_read() -> None:
        runtime.ensure_permission("gmail.read")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.readonly",
        })

    def gmail_write() -> None:
        runtime.ensure_permission("gmail.write")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.send",
        })

    def calendar_read() -> None:
        runtime.ensure_permission("calendar.read")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/calendar.readonly",
        })

    def calendar_write() -> None:
        runtime.ensure_permission("calendar.write")
        runtime.ensure_google_scope({"https://www.googleapis.com/auth/calendar"})

    def contacts_read() -> None:
        runtime.ensure_permission("contacts.read")
        runtime.ensure_google_scope({
            "https://www.googleapis.com/auth/contacts",
            "https://www.googleapis.com/auth/contacts.readonly",
        })

    drive_read_tools = {
        "drive_get_file",
        "drive_get_file_permissions",
        "drive_list_files",
        "drive_list_shared_drives",
    }
    docs_read_tools = {"drive_get_google_doc_tabs"}
    drive_write_tools = {
        "drive_copy_file",
        "drive_create_file",
        "drive_create_folder",
        "drive_create_google_doc",
        "drive_create_google_sheet",
        "drive_create_google_slide",
        "drive_move_file",
        "drive_rename_file",
        "drive_share_file",
        "drive_update_file_content",
        "drive_upload_file",
    }
    gmail_read_tools = {"gmail_get_message", "gmail_list_messages"}
    gmail_write_tools = {
        "gmail_add_label",
        "gmail_archive_message",
        "gmail_bulk_modify",
        "gmail_create_draft",
        "gmail_delete_message",
        "gmail_forward_message",
        "gmail_list_drafts",
        "gmail_remove_label",
        "gmail_reply_to_message",
        "gmail_send_html_message",
        "gmail_send_message",
    }
    calendar_read_tools = {
        "calendar_get_free_busy_info",
        "calendar_list_calendars",
        "calendar_list_events",
        "calendar_search_events",
    }
    calendar_write_tools = {
        "calendar_create_calendar",
        "calendar_create_event",
        "calendar_delete_calendar",
        "calendar_duplicate_event",
        "calendar_respond_to_event",
        "calendar_set_event_reminders",
    }
    contacts_tools = {
        "contacts_debug",
        "contacts_get",
        "contacts_list",
        "contacts_resolve_email",
        "contacts_search",
        "contacts_search_all",
        "contacts_search_directory",
    }

    if tool_name == "google_auth_revoke":
        raise BrokerPermissionError("Revoking Google credentials is an admin UI action only in broker mode")
    if tool_name in {"google_auth_status", "cancel_operation"}:
        runtime.ensure_permission("broker.authenticated")
        return
    if tool_name in drive_read_tools:
        drive_read()
        return
    if tool_name in docs_read_tools:
        docs_read()
        return
    if tool_name in drive_write_tools:
        drive_write()
        return
    if tool_name in gmail_read_tools:
        gmail_read()
        return
    if tool_name in gmail_write_tools:
        if tool_name in {"gmail_forward_message", "gmail_reply_to_message", "gmail_list_drafts"}:
            gmail_read()
        gmail_write()
        return
    if tool_name in calendar_read_tools:
        calendar_read()
        return
    if tool_name in calendar_write_tools:
        calendar_write()
        return
    if tool_name in contacts_tools:
        contacts_read()
        return
    if tool_name in {"prepare_send_email", "confirm_send_email", "smart_send_email_unsafe"}:
        contacts_read()
        gmail_write()
        return
    if tool_name in {"prepare_share_file", "confirm_share_file", "smart_share_file_unsafe"}:
        contacts_read()
        drive_write()
        return
    if tool_name in {"prepare_create_event", "confirm_create_event", "smart_create_event_unsafe"}:
        contacts_read()
        calendar_write()
        return
    if tool_name == "smart_forward_email_unsafe":
        contacts_read()
        gmail_read()
        gmail_write()
        return
    if tool_name in {"prepare_bulk_modify", "confirm_bulk_modify"}:
        gmail_write()
        return
    if tool_name == "create_meeting_from_email":
        gmail_read()
        calendar_write()
        return
    if tool_name == "save_email_to_drive":
        gmail_read()
        drive_write()
        return
    if tool_name == "share_drive_file_via_email":
        drive_write()
        gmail_write()
        return
    if tool_name == "unified_search":
        if arguments.get("search_drive", True):
            drive_read()
        if arguments.get("search_gmail", True):
            gmail_read()
        if arguments.get("search_calendar", True):
            calendar_read()
        return
    raise BrokerPermissionError(f"Broker mode denies unknown MCP operation: {tool_name}")
