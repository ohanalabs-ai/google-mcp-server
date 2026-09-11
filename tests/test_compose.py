"""Compose validation tests for the broker deployment."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yaml"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_docker_compose_config_validates(tmp_path: Path):
    env = os.environ.copy()
    env.setdefault("GOOGLE_MCP_BROKER_BOOTSTRAP_SECRET", "bootstrap")
    env.setdefault("GOOGLE_MCP_BROKER_STORAGE_KEY", "storage-key")
    env.setdefault("GOOGLE_MCP_BROKER_JWT_SIGNING_KEY", "jwt-key")
    env.setdefault("GOOGLE_MCP_PUBLIC_BASE_URL", "http://127.0.0.1:8080")
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "google-mcp-server:" in result.stdout
    assert "127.0.0.1:" in result.stdout
