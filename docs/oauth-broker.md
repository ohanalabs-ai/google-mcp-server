# OAuth Broker Experiment

This branch adds an opt-in, local-first HTTP runtime for `google-mcp-server`.

## What it does

- Keeps the existing stdio runtime as the default behavior.
- Adds a browser UI for:
  - uploading **OAuth client JSON** (`installed` or `web`)
  - uploading **authorized-user token JSON**
  - selecting per-service Google scopes
  - launching Google consent for missing scopes
  - minting a short-lived broker JWT for MCP HTTP calls
- Stores uploaded Google credentials encrypted on the server side with operator-supplied keys.
- Exposes the MCP endpoint at `/mcp` and a health endpoint at `/healthz`.

## Local setup

1. Copy `.env.example` to `.env`.
2. Generate three local secrets, for example:

```bash
python - <<'PY'
import secrets
for _ in range(3):
    print(secrets.token_urlsafe(48))
PY
```

3. Set:

```env
GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET=...
GOOGLE_MCP_BROKER_STORAGE_KEY=...
GOOGLE_MCP_BROKER_JWT_SIGNING_KEY=...
GOOGLE_MCP_PUBLIC_BASE_URL=http://127.0.0.1:8080
```

4. Start the service:

```bash
docker compose up --build
```

## Manual end-to-end flow

1. Open `http://127.0.0.1:8080/`.
2. Log in with `GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET`.
3. Choose the service scope levels you want.
4. Upload either:
   - an OAuth client JSON file, then use **Open Google consent flow**, or
   - an existing authorized-user token JSON file.
5. Review the **requested / granted / missing** scopes shown by the broker.
6. If scopes are missing, complete Google consent.
7. Mint a broker JWT from the UI's JSON response.
8. Use that JWT as `Authorization: ****** when connecting to `http://127.0.0.1:8080/mcp`.

## Scope behavior

- `replace` mode requests only the identity scopes plus the explicit UI selection.
- `additive_legacy` mode preserves the existing `DEFAULT_SCOPES` / `GOOGLE_ADDITIONAL_SCOPES` style behavior for compatibility.
- Broad Google scopes do not create new MCP tools; they only widen what the existing tools can access.
- Uploaded token JSON scope strings are treated as hints only. The broker verifies granted scopes against Google before minting JWTs.

## Prototype limitations

- Local single-process prototype: admin UI sessions are server-memory backed.
- Broker administration is protected by a bootstrap secret rather than a full identity system.
- No service-account support in this experiment.
- Advanced Protection compatibility is not guaranteed; validate it with your own Google tenant.
- Multi-user tenancy is intentionally limited. Use separate connection IDs / sessions and separate operator secrets per deployment if stronger isolation is required.
- Publishing images from the reusable workflow may require repository or organization approval for package write access; Docker Hub credentials are intentionally not wired through this prototype workflow.
