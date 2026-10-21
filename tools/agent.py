#!/usr/bin/env python3
"""ADHD investigation agent: a local model (OpenAI-compatible endpoint, e.g. vLLM) + the read-only MCP server.

    python3 tools/agent.py --report-dir /srv/adhd/reports/SubA-20261020 \
        --base-url http://gpu01:8000/v1 --model <served-model-name> --task report
    python3 tools/agent.py --report-dir ... --model ... --task "誰能取得 Entra Connect 伺服器？"
    python3 tools/agent.py --report-dir ... --verify-only answer.md

See docs/agent.md.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.agent import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
