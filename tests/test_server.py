"""Tests for server startup and runtime selection."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestServerStartup:
    def test_import_does_not_require_google_client_env(self):
        env = os.environ.copy()
        env.pop("GOOGLE_CLIENT_ID", None)
        env.pop("GOOGLE_CLIENT_SECRET", None)
        result = subprocess.run(
            [sys.executable, "-c", "import google_mcp_server.server"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    def test_main_stdio_calls_mcp_run(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_CLIENT_ID", "client")
        monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
        import google_mcp_server.server as server

        with patch.object(server.mcp, "run") as mock_run:
            assert server.main(["--runtime", "stdio"]) == 0
        mock_run.assert_called_once_with(transport="stdio")

    def test_main_broker_requires_broker_secrets(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET", raising=False)
        monkeypatch.delenv("GOOGLE_MCP_BROKER_STORAGE_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_MCP_BROKER_JWT_SIGNING_KEY", raising=False)
        import google_mcp_server.server as server

        with pytest.raises(Exception, match="Broker mode requires"):
            server.create_http_app()
