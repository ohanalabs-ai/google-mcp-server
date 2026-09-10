# Google MCP Server

> Connect Claude to your Google Workspace with intelligent contact resolution and secure OAuth2 authentication

Transform Claude into your Google productivity assistant. Send emails to "John Smith" instead of john.smith@company.com, share files by name, and create calendar events with automatic attendee resolution.

## ✨ Key Features

- **🧠 Smart Contact Resolution**: `send email to Spencer Varney about the meeting` → automatically finds spencer.varney@company.com
- **🔒 Secure by Default**: Uses [restricted scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth) compatible with [Google Advanced Protection](https://landing.google.com/advancedprotection/)
- **📱 50+ Tools**: Complete Gmail, Drive, Calendar integration with shared drive support
- **⚡ Safety First**: All send/share operations require explicit confirmation

## 🚀 Quick Start

### 1. Install
```bash
git clone https://github.com/robcerda/google-mcp-server
cd google-mcp-server
uv sync
```

### 2. Configure Google
1. [Create a Google Cloud project](https://console.cloud.google.com) and enable APIs (Drive, Gmail, Calendar, People)
2. Create OAuth2 credentials (Desktop application type)  
3. Copy your credentials to `.env`:
```bash
cp .env.example .env
# Edit .env with your GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET
```

### 3. Add to Claude Desktop
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "google-services": {
      "command": "/path/to/google-mcp-server/.venv/bin/mcp",
      "args": ["run", "/path/to/google-mcp-server/server.py"]
    }
  }
}
```

## 💡 Examples

**Smart Email** (resolves contacts automatically):
```
Send an email to Spencer Varney about tomorrow's meeting
```

**Safe File Sharing** (shows preview, requires confirmation):
```
Share the Q4 report with the marketing team as editors
```

**Calendar with Attendees** (resolves multiple contacts):
```
Create a meeting tomorrow 2-3pm with Spencer, John, and Sarah
```

## 🔐 Security & Scopes

This server uses **intentionally restrictive OAuth scopes** for maximum security by default and follows the principle of least privilege. Treat any Advanced Protection compatibility as something to verify in your own environment rather than a guaranteed property of this prototype.

### Default Scopes (Security-First)
- `drive.file` - Only files created by this app (not full Drive access)
- `gmail.send` + `gmail.readonly` + `gmail.labels` - Send, read, and manage labels
- `contacts.readonly` - Read contacts for smart name resolution  
- `calendar` - Full calendar access (Google doesn't offer restricted calendar scopes)

### Expanding Permissions
If you need broader access, add scopes to your `.env` file:

```env
# Example: Full Drive access + Gmail modify
GOOGLE_ADDITIONAL_SCOPES=https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.modify

# Common broader scopes:
# https://www.googleapis.com/auth/drive - Full Google Drive access
# https://www.googleapis.com/auth/gmail.modify - Full Gmail modification
# https://www.googleapis.com/auth/spreadsheets - Google Sheets access
# https://www.googleapis.com/auth/contacts - Full contacts read/write
```

**Security Note**: The default restricted scopes protect your account even if credentials are compromised. Only expand permissions if you specifically need the additional functionality.

**File**: Scopes are defined in `src/google_mcp_server/auth.py` (`DEFAULT_SCOPES`)

### Local OAuth broker experiment

This branch also adds an **opt-in local HTTP broker runtime** for browser-based credential upload and broker-issued JWT authorization:

- Separate upload paths for **OAuth client JSON** (`installed` or `web`) and **authorized-user token JSON**
- Explicit per-service scope selection with **disabled**, **selected-file**, **read-only**, and **write** modes where supported
- Verified **requested / granted / missing** scopes using trusted Google endpoints
- Short-lived broker JWTs scoped to the local MCP broker audience only
- Legacy stdio behavior remains the default; the browser broker is opt-in

#### Run the broker locally with Docker Compose

```bash
cp .env.example .env
# Fill GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET, GOOGLE_MCP_BROKER_STORAGE_KEY,
# GOOGLE_MCP_BROKER_JWT_SIGNING_KEY, and GOOGLE_MCP_PUBLIC_BASE_URL
docker compose up --build
```

- Broker UI: `http://127.0.0.1:8080/`
- MCP HTTP endpoint: `http://127.0.0.1:8080/mcp`
- Health check: `http://127.0.0.1:8080/healthz`

#### OAuth client setup notes

- **Web client JSON** must include the exact callback URL: `http://127.0.0.1:8080/oauth/callback` (or your configured `GOOGLE_MCP_PUBLIC_BASE_URL` equivalent).
- **Installed client JSON** is kept separate from authorized-user token uploads. For this containerized prototype, the callback URL above must still appear in the uploaded client configuration if you want to complete browser consent through the broker.
- Uploaded token JSON scope strings are **not** trusted as proof of authorization; the broker verifies actual granted scopes with Google.
- Service-account private keys are rejected in this prototype.

## 📚 Documentation

- **[Complete Setup Guide](docs/setup.md)** - Detailed Google Cloud Console configuration
- **[All Tools Reference](docs/tools.md)** - Complete list of 50+ available tools
- **[Usage Examples](docs/examples.md)** - Common workflows and advanced usage
- **[OAuth Broker Experiment](docs/oauth-broker.md)** - Local HTTP broker setup, JWT flow, and prototype limitations
- **[Troubleshooting](docs/troubleshooting.md)** - Solutions for common issues

## 🛡️ Safety Features

All potentially dangerous operations use a **two-step confirmation process**:

1. **Prepare**: `prepare_send_email()` → Shows preview, resolves contacts
2. **Confirm**: `confirm_send_email()` → Actually sends after your approval

No emails, file shares, or calendar invites are sent without explicit confirmation.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Questions?** Check the [documentation](docs/) or [open an issue](https://github.com/robcerda/google-mcp-server/issues).