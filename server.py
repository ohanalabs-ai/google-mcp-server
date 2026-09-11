#!/usr/bin/env python3
"""Entry point for Google MCP Server."""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from google_mcp_server.server import app, main

if __name__ == "__main__":
    raise SystemExit(main())