"""Google MCP Server - Main server implementation."""

from __future__ import annotations

import argparse
import inspect
import logging
import os
from typing import Any, Callable

from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings

from .auth import GoogleAuthManager
from .broker import (
    BrokerConfigurationError,
    BrokerConnectionRuntime,
    BrokerController,
    BrokerPermissionError,
    BrokerSettings,
    BrokerTokenVerifier,
    authorize_tool_call,
)
from .calendar_client import GoogleCalendarClient
from .contacts_client import GoogleContactsClient
from .docs_client import GoogleDocsClient
from .drive_client import GoogleDriveClient
from .gmail_client import GmailClient
from .integration_client import GoogleIntegrationClient
from .safe_tools import SafeGoogleTools
from .smart_tools import SmartGoogleTools

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_legacy_runtime: LegacyRuntime | None = None
_broker_controller: BrokerController | None = None


class LegacyRuntime:
    """Legacy stdio runtime using environment-provided OAuth credentials."""

    def __init__(self) -> None:
        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ValueError(
                "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in environment variables. "
                "See README.md for setup instructions."
            )
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8080")
        additional_scopes_str = os.getenv("GOOGLE_ADDITIONAL_SCOPES", "")
        additional_scopes = additional_scopes_str.split() if additional_scopes_str else None
        open_browser = os.getenv("GOOGLE_MCP_OAUTH_OPEN_BROWSER", "false").strip().lower() == "true"
        callback_bind_addr = os.getenv("GOOGLE_MCP_OAUTH_BIND_ADDR", "0.0.0.0")
        self.auth_manager = GoogleAuthManager(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            additional_scopes=additional_scopes,
            open_browser=open_browser,
            callback_bind_addr=callback_bind_addr,
        )
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.additional_scopes = additional_scopes or []
        self._creds = None
        self._drive_client = None
        self._docs_client = None
        self._gmail_client = None
        self._calendar_client = None
        self._integration_client = None
        self._contacts_client = None
        self._smart_tools = None
        self._safe_tools = None

    def authorize_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> None:
        return None

    def get_credentials(self):
        if self._creds is None:
            creds = self.auth_manager.get_credentials()
            if not creds:
                raise RuntimeError("Failed to authenticate with Google. Please check your configuration.")
            self._creds = creds
        return self._creds

    def get_drive_client(self) -> GoogleDriveClient:
        if self._drive_client is None:
            self._drive_client = GoogleDriveClient(self.get_credentials())
        return self._drive_client

    def get_docs_client(self) -> GoogleDocsClient:
        if self._docs_client is None:
            self._docs_client = GoogleDocsClient(self.get_credentials())
        return self._docs_client

    def get_gmail_client(self) -> GmailClient:
        if self._gmail_client is None:
            self._gmail_client = GmailClient(self.get_credentials())
        return self._gmail_client

    def get_calendar_client(self) -> GoogleCalendarClient:
        if self._calendar_client is None:
            self._calendar_client = GoogleCalendarClient(self.get_credentials())
        return self._calendar_client

    def get_integration_client(self) -> GoogleIntegrationClient:
        if self._integration_client is None:
            self._integration_client = GoogleIntegrationClient(
                self.get_drive_client(),
                self.get_gmail_client(),
                self.get_calendar_client(),
            )
        return self._integration_client

    def get_contacts_client(self) -> GoogleContactsClient:
        if self._contacts_client is None:
            self._contacts_client = GoogleContactsClient(self.get_credentials())
        return self._contacts_client

    def get_smart_tools(self) -> SmartGoogleTools:
        if self._smart_tools is None:
            self._smart_tools = SmartGoogleTools(
                self.get_contacts_client(),
                self.get_gmail_client(),
                self.get_drive_client(),
                self.get_calendar_client(),
            )
        return self._smart_tools

    def get_safe_tools(self) -> SafeGoogleTools:
        if self._safe_tools is None:
            self._safe_tools = SafeGoogleTools(
                self.get_contacts_client(),
                self.get_gmail_client(),
                self.get_drive_client(),
                self.get_calendar_client(),
            )
        return self._safe_tools

    def revoke_credentials(self) -> bool:
        success = self.auth_manager.revoke_credentials()
        if success:
            self._creds = None
            self._drive_client = None
            self._docs_client = None
            self._gmail_client = None
            self._calendar_client = None
            self._integration_client = None
            self._contacts_client = None
            self._smart_tools = None
            self._safe_tools = None
        return success


def _load_broker_settings(*, require: bool) -> BrokerSettings | None:
    return BrokerSettings.from_env(require=require)


def _get_broker_controller(*, require: bool) -> BrokerController | None:
    global _broker_controller
    settings = _load_broker_settings(require=require)
    if settings is None:
        return None
    if _broker_controller is None or _broker_controller.settings != settings:
        _broker_controller = BrokerController(settings)
    return _broker_controller


def _get_legacy_runtime() -> LegacyRuntime:
    global _legacy_runtime
    if _legacy_runtime is None:
        _legacy_runtime = LegacyRuntime()
    return _legacy_runtime


def _get_runtime() -> LegacyRuntime | BrokerConnectionRuntime:
    access_token = get_access_token()
    if access_token and access_token.claims:
        controller = _get_broker_controller(require=False)
        if controller is None:
            raise BrokerConfigurationError("Broker JWTs are not configured for this server instance")
        return controller.get_runtime_for_claims(access_token.claims)
    return _get_legacy_runtime()


def get_credentials():
    return _get_runtime().get_credentials()


def get_drive_client() -> GoogleDriveClient:
    return _get_runtime().get_drive_client()


def get_docs_client() -> GoogleDocsClient:
    return _get_runtime().get_docs_client()


def get_gmail_client() -> GmailClient:
    return _get_runtime().get_gmail_client()


def get_calendar_client() -> GoogleCalendarClient:
    return _get_runtime().get_calendar_client()


def get_integration_client() -> GoogleIntegrationClient:
    return _get_runtime().get_integration_client()


def get_contacts_client() -> GoogleContactsClient:
    return _get_runtime().get_contacts_client()


def get_smart_tools() -> SmartGoogleTools:
    return _get_runtime().get_smart_tools()


def get_safe_tools() -> SafeGoogleTools:
    return _get_runtime().get_safe_tools()


def _default_auth_settings() -> AuthSettings:
    public_base_url = os.getenv("GOOGLE_MCP_PUBLIC_BASE_URL", "http://127.0.0.1:8080").rstrip('/')
    return AuthSettings(
        issuer_url=public_base_url,
        resource_server_url=f"{public_base_url}/mcp",
        validate_token_resource=False,
    )


mcp = MCPServer(
    "google-mcp-server",
    auth=_default_auth_settings(),
    token_verifier=BrokerTokenVerifier(_load_broker_settings, lambda settings: _get_broker_controller(require=True).store),
)


def broker_tool(*tool_args, **tool_kwargs):
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(fn)

        if inspect.iscoroutinefunction(fn):
            async def wrapped(*args, **kwargs):
                runtime = _get_runtime()
                if isinstance(runtime, BrokerConnectionRuntime):
                    bound = signature.bind_partial(*args, **kwargs)
                    authorize_tool_call(fn.__name__, dict(bound.arguments), runtime)
                return await fn(*args, **kwargs)
        else:
            def wrapped(*args, **kwargs):
                runtime = _get_runtime()
                if isinstance(runtime, BrokerConnectionRuntime):
                    bound = signature.bind_partial(*args, **kwargs)
                    authorize_tool_call(fn.__name__, dict(bound.arguments), runtime)
                return fn(*args, **kwargs)

        wrapped.__name__ = fn.__name__
        wrapped.__doc__ = fn.__doc__
        wrapped.__annotations__ = getattr(fn, '__annotations__', {})
        wrapped.__module__ = fn.__module__
        wrapped.__qualname__ = fn.__qualname__
        wrapped.__wrapped__ = fn
        return mcp.tool(*tool_args, **tool_kwargs)(wrapped)

    return decorator

# Authentication tools
@broker_tool()
def google_auth_status() -> str:
    """Check Google authentication status and user info"""
    try:
        runtime = _get_runtime()
        if isinstance(runtime, BrokerConnectionRuntime):
            if runtime.record.subject:
                return (
                    "✅ Broker credentials loaded for: "
                    f"{runtime.record.display_name or runtime.record.email or runtime.record.subject}"
                )
            return "❌ Broker connection has no verified Google credentials"
        user_info = runtime.auth_manager.get_user_info()
        if user_info:
            return f"✅ Authenticated as: {user_info.get('name', 'Unknown')} ({user_info.get('email', 'Unknown')})"
        else:
            return "❌ Not authenticated"
    except Exception as e:
        return f"Authentication check failed: {str(e)}"

@broker_tool()
def google_auth_revoke() -> str:
    """Revoke Google authentication and clear stored credentials"""
    try:
        runtime = _get_runtime()
        if isinstance(runtime, BrokerConnectionRuntime):
            return "❌ Use the broker administration UI to rotate or delete broker-managed credentials"
        success = runtime.revoke_credentials()
        if success:
            return "✅ Authentication revoked successfully"
        else:
            return "❌ Failed to revoke authentication"
    except Exception as e:
        return f"Error revoking authentication: {str(e)}"

# Google Drive tools
@broker_tool()
def drive_list_files(query: str = "", folder_id: str = "", max_results: int = 10, drive_id: str = "", include_team_drives: bool = True) -> str:
    """List files in Google Drive"""
    try:
        client = get_drive_client()
        result = client.list_files(
            query=query if query else None,
            folder_id=folder_id if folder_id else None,
            max_results=max_results,
            drive_id=drive_id if drive_id else None,
            include_team_drives=include_team_drives
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_get_file(file_id: str, include_content: bool = False) -> str:
    """Get file metadata and content from Google Drive"""
    try:
        client = get_drive_client()
        result = client.get_file(file_id=file_id, include_content=include_content)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_get_google_doc_tabs(document_id: str) -> str:
    """Get the full text content of every tab in a Google Doc.

    Use this instead of drive_get_file for Google Docs that use Google's
    "tabs" feature. Drive's files.export (what drive_get_file uses for
    content) has no documented support for tabs and is not guaranteed to
    return more than the default/first tab - the Docs API's
    documents.get(includeTabsContent=True) is the only documented way to
    read every tab's content and title.
    """
    try:
        client = get_docs_client()
        result = client.get_document_tabs(document_id=document_id)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_upload_file(name: str, content: str, parent_folder_id: str = "", mime_type: str = "text/plain", drive_id: str = "") -> str:
    """Upload a file to Google Drive"""
    try:
        client = get_drive_client()
        result = client.upload_file(
            name=name,
            content=content,
            parent_folder_id=parent_folder_id if parent_folder_id else None,
            mime_type=mime_type,
            drive_id=drive_id if drive_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_create_file(name: str, content: str = "", parent_folder_id: str = "", mime_type: str = "text/plain", drive_id: str = "") -> str:
    """Create a file in Google Drive"""
    try:
        client = get_drive_client()
        result = client.create_file(
            name=name,
            content=content,
            parent_folder_id=parent_folder_id if parent_folder_id else None,
            mime_type=mime_type,
            drive_id=drive_id if drive_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_create_folder(name: str, parent_folder_id: str = "", drive_id: str = "") -> str:
    """Create a folder in Google Drive"""
    try:
        client = get_drive_client()
        result = client.create_folder(
            name=name,
            parent_folder_id=parent_folder_id if parent_folder_id else None,
            drive_id=drive_id if drive_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_copy_file(file_id: str, name: str = "", parent_folder_id: str = "") -> str:
    """Copy a file in Google Drive"""
    try:
        client = get_drive_client()
        result = client.copy_file(
            file_id=file_id,
            name=name if name else None,
            parent_folder_id=parent_folder_id if parent_folder_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_move_file(file_id: str, new_parent_folder_id: str, remove_from_current_parents: bool = True) -> str:
    """Move a file to a different folder in Google Drive"""
    try:
        client = get_drive_client()
        result = client.move_file(
            file_id=file_id,
            new_parent_folder_id=new_parent_folder_id,
            remove_from_current_parents=remove_from_current_parents
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_rename_file(file_id: str, new_name: str) -> str:
    """Rename a file in Google Drive"""
    try:
        client = get_drive_client()
        result = client.rename_file(file_id=file_id, new_name=new_name)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_update_file_content(file_id: str, content: str, mime_type: str = "") -> str:
    """Update the content of an existing file in Google Drive"""
    try:
        client = get_drive_client()
        result = client.update_file_content(
            file_id=file_id,
            content=content,
            mime_type=mime_type if mime_type else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_get_file_permissions(file_id: str) -> str:
    """Get file sharing permissions"""
    try:
        client = get_drive_client()
        result = client.get_file_permissions(file_id=file_id)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_share_file(file_id: str, email_address: str, role: str = "reader", send_notification: bool = True, message: str = "") -> str:
    """Share a file with a user"""
    try:
        client = get_drive_client()
        result = client.share_file(
            file_id=file_id,
            email_address=email_address,
            role=role,
            send_notification=send_notification,
            message=message if message else ""
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_list_shared_drives(max_results: int = 10) -> str:
    """List available shared drives"""
    try:
        client = get_drive_client()
        result = client.list_shared_drives(max_results=max_results)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_create_google_doc(name: str, content: str = "", parent_folder_id: str = "", drive_id: str = "") -> str:
    """Create a Google Doc"""
    try:
        client = get_drive_client()
        result = client.create_google_doc(
            name=name,
            content=content,
            parent_folder_id=parent_folder_id if parent_folder_id else None,
            drive_id=drive_id if drive_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_create_google_sheet(name: str, content: str = "", parent_folder_id: str = "", drive_id: str = "") -> str:
    """Create a Google Sheet"""
    try:
        client = get_drive_client()
        result = client.create_google_sheet(
            name=name,
            content=content,
            parent_folder_id=parent_folder_id if parent_folder_id else None,
            drive_id=drive_id if drive_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def drive_create_google_slide(name: str, content: str = "", parent_folder_id: str = "", drive_id: str = "") -> str:
    """Create a Google Slides presentation"""
    try:
        client = get_drive_client()
        result = client.create_google_slide(
            name=name,
            content=content,
            parent_folder_id=parent_folder_id if parent_folder_id else None,
            drive_id=drive_id if drive_id else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Gmail tools
@broker_tool()
def gmail_list_messages(query: str = "", max_results: int = 10, include_spam_trash: bool = False) -> str:
    """List Gmail messages"""
    try:
        client = get_gmail_client()
        result = client.list_messages(
            query=query if query else None,
            max_results=max_results,
            include_spam_trash=include_spam_trash
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_get_message(message_id: str, format: str = "full") -> str:
    """Get a specific Gmail message"""
    try:
        client = get_gmail_client()
        result = client.get_message(message_id=message_id, format=format)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_send_message(to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> str:
    """Send a Gmail message"""
    try:
        client = get_gmail_client()
        result = client.send_message(
            to=to,
            subject=subject,
            body=body,
            cc=cc if cc else None,
            bcc=bcc if bcc else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_reply_to_message(message_id: str, body: str, include_original: bool = True) -> str:
    """Reply to a Gmail message"""
    try:
        client = get_gmail_client()
        result = client.reply_to_message(
            message_id=message_id,
            body=body,
            include_original=include_original
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_forward_message(message_id: str, to: str, body: str = "") -> str:
    """Forward a Gmail message"""
    try:
        client = get_gmail_client()
        result = client.forward_message(
            message_id=message_id,
            to=to,
            body=body
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_send_html_message(to: str, subject: str, html_body: str, text_body: str = "", cc: str = "", bcc: str = "") -> str:
    """Send an HTML Gmail message"""
    try:
        client = get_gmail_client()
        result = client.send_html_message(
            to=to,
            subject=subject,
            html_body=html_body,
            text_body=text_body if text_body else "",
            cc=cc if cc else None,
            bcc=bcc if bcc else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_archive_message(message_id: str) -> str:
    """Archive a Gmail message"""
    try:
        client = get_gmail_client()
        result = client.archive_message(message_id=message_id)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_delete_message(message_id: str) -> str:
    """Delete a Gmail message (move to trash)"""
    try:
        client = get_gmail_client()
        result = client.delete_message(message_id=message_id)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_add_label(message_id: str, label_ids: str) -> str:
    """Add labels to a Gmail message (comma-separated label IDs)"""
    try:
        client = get_gmail_client()
        label_list = [label.strip() for label in label_ids.split(',') if label.strip()]
        result = client.add_label(message_id=message_id, label_ids=label_list)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_remove_label(message_id: str, label_ids: str) -> str:
    """Remove labels from a Gmail message (comma-separated label IDs)"""
    try:
        client = get_gmail_client()
        label_list = [label.strip() for label in label_ids.split(',') if label.strip()]
        result = client.remove_label(message_id=message_id, label_ids=label_list)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_create_draft(to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> str:
    """Create a Gmail draft"""
    try:
        client = get_gmail_client()
        result = client.create_draft(
            to=to,
            subject=subject,
            body=body,
            cc=cc if cc else None,
            bcc=bcc if bcc else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def gmail_list_drafts(max_results: int = 10) -> str:
    """List Gmail drafts"""
    try:
        client = get_gmail_client()
        result = client.list_drafts(max_results=max_results)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Gmail bulk operations (efficient for large datasets)
@broker_tool()
def gmail_bulk_modify(query: str, add_labels: str = "", remove_labels: str = "", max_messages: int = 1000) -> str:
    """⚠️ UNSAFE: Universal bulk modify messages (executes immediately without confirmation)
    
    ⚠️ DANGER: This modifies emails immediately without showing what will be affected!
    For safety, use prepare_bulk_modify() instead to see a preview first.
    
    Examples:
    - Mark all unread as read: gmail_bulk_modify("is:unread", remove_labels="UNREAD")
    - Archive notifications: gmail_bulk_modify("from:notifications", remove_labels="INBOX") 
    - Label CEO emails as important: gmail_bulk_modify("from:ceo@company.com", add_labels="IMPORTANT")
    - Mark inbox as unread: gmail_bulk_modify("in:inbox -is:unread", add_labels="UNREAD")
    - Complex operation: gmail_bulk_modify("older_than:30d", add_labels="OLD", remove_labels="INBOX,UNREAD")
    
    ✅ SAFER ALTERNATIVE: Use prepare_bulk_modify() to see preview and confirm before executing.
    """
    try:
        client = get_gmail_client()
        
        # Parse comma-separated labels
        add_list = [label.strip() for label in add_labels.split(',') if label.strip()] if add_labels else None
        remove_list = [label.strip() for label in remove_labels.split(',') if label.strip()] if remove_labels else None
        
        result = client.bulk_modify(
            query=query,
            add_labels=add_list,
            remove_labels=remove_list,
            max_messages=max_messages
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Google Calendar tools
@broker_tool()
def calendar_list_calendars() -> str:
    """List available Google Calendars"""
    try:
        client = get_calendar_client()
        result = client.list_calendars()
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_list_events(calendar_id: str = "primary", time_min: str = "", time_max: str = "", max_results: int = 10) -> str:
    """List Google Calendar events"""
    try:
        client = get_calendar_client()
        result = client.list_events(
            calendar_id=calendar_id,
            time_min=time_min if time_min else None,
            time_max=time_max if time_max else None,
            max_results=max_results
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_create_event(
    summary: str, 
    start_time: str, 
    end_time: str, 
    calendar_id: str = "primary",
    description: str = "",
    location: str = "",
    attendees: str = ""
) -> str:
    """Create a Google Calendar event"""
    try:
        client = get_calendar_client()
        result = client.create_event(
            calendar_id=calendar_id,
            summary=summary,
            description=description if description else None,
            start_time=start_time,
            end_time=end_time,
            location=location if location else None,
            attendees=attendees if attendees else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_search_events(query: str, calendar_id: str = "primary", time_min: str = "", time_max: str = "", max_results: int = 10) -> str:
    """Search events by text content"""
    try:
        client = get_calendar_client()
        result = client.search_events(
            query=query,
            calendar_id=calendar_id,
            time_min=time_min if time_min else None,
            time_max=time_max if time_max else None,
            max_results=max_results
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_duplicate_event(calendar_id: str, event_id: str, new_start_time: str, new_end_time: str, new_summary: str = "") -> str:
    """Duplicate an event to a new date/time"""
    try:
        client = get_calendar_client()
        result = client.duplicate_event(
            calendar_id=calendar_id,
            event_id=event_id,
            new_start_time=new_start_time,
            new_end_time=new_end_time,
            new_summary=new_summary if new_summary else None
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_respond_to_event(calendar_id: str, event_id: str, response: str) -> str:
    """Respond to an event invitation (accepted, declined, tentative)"""
    try:
        client = get_calendar_client()
        result = client.respond_to_event(
            calendar_id=calendar_id,
            event_id=event_id,
            response=response
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_get_free_busy_info(calendar_ids: str, time_min: str, time_max: str) -> str:
    """Check free/busy information for calendars (comma-separated calendar IDs)"""
    try:
        client = get_calendar_client()
        calendar_list = [cal_id.strip() for cal_id in calendar_ids.split(',') if cal_id.strip()]
        result = client.get_free_busy_info(
            calendar_ids=calendar_list,
            time_min=time_min,
            time_max=time_max
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_create_calendar(summary: str, description: str = "", time_zone: str = "UTC") -> str:
    """Create a new calendar"""
    try:
        client = get_calendar_client()
        result = client.create_calendar(
            summary=summary,
            description=description,
            time_zone=time_zone
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_delete_calendar(calendar_id: str) -> str:
    """Delete a calendar"""
    try:
        client = get_calendar_client()
        result = client.delete_calendar(calendar_id=calendar_id)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def calendar_set_event_reminders(calendar_id: str, event_id: str, reminders: str) -> str:
    """Set reminders for an event (JSON format: [{"method": "email", "minutes": 30}])"""
    try:
        import json
        client = get_calendar_client()
        reminder_list = json.loads(reminders)
        result = client.set_event_reminders(
            calendar_id=calendar_id,
            event_id=event_id,
            reminders=reminder_list
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Integration tools
@broker_tool()
def create_meeting_from_email(message_id: str, proposed_time: str = "", duration_minutes: int = 60, calendar_id: str = "primary") -> str:
    """Parse an email and create a calendar event from it"""
    try:
        client = get_integration_client()
        result = client.create_meeting_from_email(
            message_id=message_id,
            proposed_time=proposed_time if proposed_time else "",
            duration_minutes=duration_minutes,
            calendar_id=calendar_id
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def save_email_to_drive(message_id: str, folder_id: str = "", file_format: str = "txt") -> str:
    """Save an email as a file in Google Drive"""
    try:
        client = get_integration_client()
        result = client.save_email_to_drive(
            message_id=message_id,
            folder_id=folder_id if folder_id else None,
            file_format=file_format
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def share_drive_file_via_email(file_id: str, recipient_email: str, message: str = "", subject: str = "", permission_role: str = "reader") -> str:
    """Share a Drive file and send email notification"""
    try:
        client = get_integration_client()
        result = client.share_drive_file_via_email(
            file_id=file_id,
            recipient_email=recipient_email,
            message=message,
            subject=subject if subject else "",
            permission_role=permission_role
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def unified_search(query: str, search_drive: bool = True, search_gmail: bool = True, search_calendar: bool = True, max_results: int = 5) -> str:
    """Search across Gmail, Drive, and Calendar with a single query"""
    try:
        client = get_integration_client()
        result = client.unified_search(
            query=query,
            search_drive=search_drive,
            search_gmail=search_gmail,
            search_calendar=search_calendar,
            max_results=max_results
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Contact management tools
@broker_tool()
def contacts_debug() -> str:
    """Debug contacts API connection and permissions"""
    try:
        client = get_contacts_client()
        
        # Test basic API access
        try:
            result = client.service.people().connections().list(
                resourceName='people/me',
                pageSize=1,
                personFields='names'
            ).execute()
            
            connections = result.get('connections', [])
            total_size = result.get('totalSize', 0)
            
            debug_info = {
                'api_access': 'SUCCESS',
                'total_contacts': total_size,
                'sample_returned': len(connections),
                'next_page_token': result.get('nextPageToken', 'None'),
                'sync_token': result.get('syncToken', 'None')
            }
            
            if connections:
                sample_contact = connections[0]
                debug_info['sample_contact_fields'] = list(sample_contact.keys())
                if 'names' in sample_contact:
                    debug_info['sample_contact_name'] = sample_contact['names'][0].get('displayName', 'No display name')
            
            return str({
                'success': True,
                'debug_info': debug_info,
                'suggestion': 'API access working. If total_contacts is 0, you may need to add contacts to your Google account first.'
            })
            
        except Exception as api_error:
            return str({
                'success': False,
                'api_error': str(api_error),
                'suggestion': 'API access failed. You may need to re-authenticate with the contacts scope.'
            })
            
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def contacts_search(query: str, max_results: int = 10) -> str:
    """Search contacts by name or email using improved searchContacts API"""
    try:
        client = get_contacts_client()
        result = client.search_contacts(query=query, max_results=max_results)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def contacts_search_directory(query: str, max_results: int = 10) -> str:
    """Search organization directory (Google Workspace accounts only)"""
    try:
        client = get_contacts_client()
        result = client.search_directory(query=query, max_results=max_results)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def contacts_search_all(query: str, max_results: int = 10) -> str:
    """Search both personal contacts and directory (comprehensive search)"""
    try:
        client = get_contacts_client()
        result = client.search_all_sources(query=query, max_results=max_results)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def contacts_list(max_results: int = 50) -> str:
    """List all contacts"""
    try:
        client = get_contacts_client()
        result = client.list_contacts(max_results=max_results)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def contacts_get(resource_name: str) -> str:
    """Get detailed contact information"""
    try:
        client = get_contacts_client()
        result = client.get_contact(resource_name=resource_name)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def contacts_resolve_email(name_or_email: str) -> str:
    """Resolve a contact name to email address"""
    try:
        client = get_contacts_client()
        result = client.resolve_contact_email(name_or_email=name_or_email)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# UNSAFE Smart tools (immediate execution - use with caution)
@broker_tool()
def smart_send_email_unsafe(to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> str:
    """⚠️ UNSAFE: Send email immediately without confirmation (use names or emails)"""
    try:
        tools = get_smart_tools()
        result = tools.smart_send_email(
            to=to,
            subject=subject,
            body=body,
            cc=cc if cc else "",
            bcc=bcc if bcc else ""
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# SAFE Smart tools with confirmation required
@broker_tool()
def prepare_send_email(to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> str:
    """✅ SAFE: Prepare email for sending - shows preview and requires confirmation"""
    try:
        tools = get_safe_tools()
        result = tools.prepare_email(
            to=to,
            subject=subject,
            body=body,
            cc=cc if cc else "",
            bcc=bcc if bcc else ""
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def smart_share_file_unsafe(file_id: str, recipient: str, role: str = "reader", send_notification: bool = True, message: str = "") -> str:
    """⚠️ UNSAFE: Share file immediately without confirmation (use names or emails)"""
    try:
        tools = get_smart_tools()
        result = tools.smart_share_file(
            file_id=file_id,
            recipient=recipient,
            role=role,
            send_notification=send_notification,
            message=message
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def prepare_share_file(file_id: str, recipient: str, role: str = "reader", send_notification: bool = True, message: str = "") -> str:
    """✅ SAFE: Prepare file sharing - shows preview and requires confirmation"""
    try:
        tools = get_safe_tools()
        result = tools.prepare_file_share(
            file_id=file_id,
            recipient=recipient,
            role=role,
            send_notification=send_notification,
            message=message
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def smart_create_event_unsafe(summary: str, start_time: str, end_time: str, attendees: str = "", calendar_id: str = "primary", description: str = "", location: str = "") -> str:
    """⚠️ UNSAFE: Create calendar event immediately without confirmation (use names or emails)"""
    try:
        tools = get_smart_tools()
        result = tools.smart_create_event(
            summary=summary,
            start_time=start_time,
            end_time=end_time,
            attendees=attendees,
            calendar_id=calendar_id,
            description=description,
            location=location
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def prepare_create_event(summary: str, start_time: str, end_time: str, attendees: str = "", calendar_id: str = "primary", description: str = "", location: str = "") -> str:
    """✅ SAFE: Prepare calendar event - shows preview and requires confirmation"""
    try:
        tools = get_safe_tools()
        result = tools.prepare_calendar_event(
            summary=summary,
            start_time=start_time,
            end_time=end_time,
            attendees=attendees,
            calendar_id=calendar_id,
            description=description,
            location=location
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def smart_forward_email_unsafe(message_id: str, to: str, body: str = "") -> str:
    """⚠️ UNSAFE: Forward email immediately without confirmation (use names or emails)"""
    try:
        tools = get_smart_tools()
        result = tools.smart_forward_email(
            message_id=message_id,
            to=to,
            body=body
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Confirmation tools
@broker_tool()
def confirm_send_email(to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> str:
    """✅ Confirm and send the prepared email"""
    try:
        confirmation_data = {
            'to': to,
            'subject': subject,
            'body': body,
            'cc': cc if cc else None,
            'bcc': bcc if bcc else None
        }
        tools = get_safe_tools()
        result = tools.confirm_send_email(confirmation_data)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def confirm_share_file(file_id: str, recipient_email: str, role: str = "reader", send_notification: bool = True, message: str = "") -> str:
    """✅ Confirm and share the prepared file"""
    try:
        confirmation_data = {
            'file_id': file_id,
            'recipient_email': recipient_email,
            'role': role,
            'send_notification': send_notification,
            'message': message
        }
        tools = get_safe_tools()
        result = tools.confirm_share_file(confirmation_data)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def confirm_create_event(summary: str, start_time: str, end_time: str, attendees: str = "", calendar_id: str = "primary", description: str = "", location: str = "") -> str:
    """✅ Confirm and create the prepared calendar event"""
    try:
        confirmation_data = {
            'summary': summary,
            'start_time': start_time,
            'end_time': end_time,
            'attendees': attendees if attendees else None,
            'calendar_id': calendar_id,
            'description': description,
            'location': location
        }
        tools = get_safe_tools()
        result = tools.confirm_create_event(confirmation_data)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def prepare_bulk_modify(query: str, add_labels: str = "", remove_labels: str = "", max_messages: int = 1000) -> str:
    """✅ SAFE: Prepare bulk email operations - shows preview and requires confirmation
    
    Shows exactly which emails will be affected before making any changes.
    Much safer than direct bulk operations for large datasets.
    
    Examples:
    - Mark all unread as read: prepare_bulk_modify("is:unread", remove_labels="UNREAD")
    - Archive notifications: prepare_bulk_modify("from:notifications", remove_labels="INBOX")
    - Label CEO emails: prepare_bulk_modify("from:ceo@company.com", add_labels="IMPORTANT")
    """
    try:
        tools = get_safe_tools()
        result = tools.prepare_bulk_modify(
            query=query,
            add_labels=add_labels,
            remove_labels=remove_labels,
            max_messages=max_messages
        )
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def confirm_bulk_modify(query: str, add_labels: str = "", remove_labels: str = "", max_messages: int = 1000) -> str:
    """✅ Confirm and execute the prepared bulk email operation"""
    try:
        confirmation_data = {
            'query': query,
            'add_labels': add_labels,
            'remove_labels': remove_labels,
            'max_messages': max_messages
        }
        tools = get_safe_tools()
        result = tools.confirm_bulk_modify(confirmation_data)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@broker_tool()
def cancel_operation() -> str:
    """❌ Cancel any pending operation (email, file share, calendar event, bulk operation)"""
    return "✅ Operation cancelled. No action was taken."

# Export for mcp run
app = mcp

def create_http_app():
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

    controller = _get_broker_controller(require=True)
    assert controller is not None

    async def homepage(request):
        return await controller.dashboard(request)

    async def login(request):
        return await controller.login(request)

    async def save_selection(request):
        return await controller.save_selection(request)

    async def upload_client(request):
        return await controller.upload_client_config(request)

    async def upload_authorized_user(request):
        return await controller.upload_authorized_user(request)

    async def oauth_start(request):
        return await controller.start_google_oauth(request)

    async def oauth_callback(request):
        return await controller.oauth_callback(request)

    async def broker_token(request):
        return await controller.broker_token(request)

    async def health(request):
        return await controller.health(request)

    async def handle_broker_error(request, exc):
        return JSONResponse({"error": str(exc)}, status_code=400, headers={"Cache-Control": "no-store"})

    return Starlette(
        routes=[
            Route('/', homepage, methods=['GET']),
            Route('/login', login, methods=['POST']),
            Route('/selection', save_selection, methods=['POST']),
            Route('/upload/oauth-client', upload_client, methods=['POST']),
            Route('/upload/authorized-user', upload_authorized_user, methods=['POST']),
            Route('/oauth/start', oauth_start, methods=['POST']),
            Route('/oauth/callback', oauth_callback, methods=['GET']),
            Route('/broker-token', broker_token, methods=['POST']),
            Route('/healthz', health, methods=['GET']),
            Mount('/', app=mcp.streamable_http_app(streamable_http_path='/mcp', host='127.0.0.1')),
        ],
        exception_handlers={
            BrokerConfigurationError: handle_broker_error,
            BrokerPermissionError: handle_broker_error,
            RuntimeError: handle_broker_error,
            ValueError: handle_broker_error,
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Google MCP Server')
    parser.add_argument('--runtime', choices=['stdio', 'broker'], default=os.getenv('GOOGLE_MCP_RUNTIME', 'stdio'))
    parser.add_argument('--host', default=os.getenv('GOOGLE_MCP_HTTP_HOST', '127.0.0.1'))
    parser.add_argument('--port', type=int, default=int(os.getenv('GOOGLE_MCP_HTTP_PORT', '8080')))
    args = parser.parse_args(argv)

    if args.runtime == 'broker':
        os.environ['GOOGLE_MCP_HTTP_HOST'] = args.host
        os.environ['GOOGLE_MCP_HTTP_PORT'] = str(args.port)
        app = create_http_app()
        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    mcp.run(transport='stdio')
    return 0


app = mcp
