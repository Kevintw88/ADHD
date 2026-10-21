#!/usr/bin/env python3
"""Read-only MCP server (stdio) over an ADHD analysis output directory.

    python3 tools/mcp_server.py /srv/adhd/reports/SubA-20261020

See docs/mcp.md for the tools and how to connect a local model.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.mcp_server import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
