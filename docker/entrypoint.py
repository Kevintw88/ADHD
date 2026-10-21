#!/usr/bin/env python3
"""Container entry point: `adhd <command> [args]` -> the matching tools/ script.

Globs in arguments (e.g. /data/intake/ADHD-Collect-SubA*20261015*.zip) are expanded here, because the
container has no shell and the host shell cannot see container paths.
"""
import glob
import os
import runpy
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMANDS = {
    "verify-bundle": "tools/verify_bundle.py", "sanity": "tools/bundle_sanity.py", "analyze": "tools/analyze.py",
    "paths": "tools/paths.py", "mcp": "tools/mcp_server.py", "agent": "tools/agent.py", "eval": "tools/eval_agent.py",
    "compare-users": "tools/compare_users.py", "detect": "tools/detect.py", "diag-enabled": "tools/diag_enabled.py",
}
HELP = """ADHD lab container

  adhd verify-bundle <bundles...>          bundle integrity / leakage checks
  adhd sanity <bundles...>                 semantic checks of a round
  adhd analyze <bundles...> --out <dir>    rules + attack paths -> findings.md / .json / graph.sqlite
  adhd paths <bundles...> [--from X|--to X]
  adhd mcp <report-dir>                    read-only MCP server on stdio (docker run -i)
  adhd agent --report-dir <dir> --model <name> [--base-url URL] [--task report|"question"]
  adhd eval --report-dir <dir> --model A --model B [--runs N]
  adhd detect selftest | lint | run <bundles...> --out <dir> | tune <bundles...> --out <dir>
  adhd compare-users --old ... --new ... | adhd diag-enabled <bundles...>
  adhd selftest                            run the test suite inside the image
"""


def expand(args):
    out = []
    for a in args:
        hits = sorted(glob.glob(a)) if any(c in a for c in "*?[") else []
        out.extend(hits or [a])
    return out


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(HELP)
        return 0
    cmd, args = sys.argv[1], expand(sys.argv[2:])
    if cmd == "selftest":
        import unittest
        sys.path.insert(0, os.path.join(ROOT, "tests", "python"))
        suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests", "python"))
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    script = COMMANDS.get(cmd)
    if script is None:
        print(f"unknown command: {cmd}\n\n{HELP}", file=sys.stderr)
        return 2
    path = os.path.join(ROOT, script)
    sys.argv = [path] + args
    try:
        runpy.run_path(path, run_name="__main__")
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
