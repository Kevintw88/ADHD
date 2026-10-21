"""MCP server tests: protocol handling, every tool, read-only guarantees, and (when the official
`mcp` SDK is installed) a real client session over stdio."""
from __future__ import annotations

import io
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures as fx  # noqa: E402
from adhd.analyze import main as analyze_main  # noqa: E402
from adhd.mcp_server import PROTOCOL_VERSIONS, TOOLS, Server, Store  # noqa: E402


class McpCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        paths = fx.make_round(root / "b", True)
        cls.out = root / "report"
        with open(Path(cls._tmp.name) / "log.txt", "w") as sink:
            stdout, sys.stdout = sys.stdout, sink
            try:
                assert analyze_main([str(p) for p in paths] + ["--out", str(cls.out)]) == 0
            finally:
                sys.stdout = stdout
        cls.server = Server(Store(cls.out), log=lambda m: None)
        cls.rpc(cls, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    _ids = iter(range(1, 10_000))

    def rpc(self, method, params=None):
        return self.server.handle({"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}})

    def call(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})["result"]
        if not r["isError"]:   # the text block carries the same JSON as structuredContent
            self.assertEqual(json.loads(r["content"][0]["text"]), r["structuredContent"])
        return r

    def ok(self, name, **args):
        r = self.call(name, **args)
        self.assertFalse(r["isError"], r["content"][0]["text"])
        return r["structuredContent"]


class Protocol(McpCase):
    def test_initialize_negotiates_version(self):
        for v in PROTOCOL_VERSIONS:
            r = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": v}})
            self.assertEqual(r["result"]["protocolVersion"], v)
        r = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})
        self.assertEqual(r["result"]["protocolVersion"], PROTOCOL_VERSIONS[0])
        self.assertIn("tools", r["result"]["capabilities"])
        self.assertIn("skipped", r["result"]["instructions"])

    def test_tools_list_is_read_only(self):
        tools = self.rpc("tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], [t["name"] for t in TOOLS])
        for t in tools:
            self.assertTrue(t["annotations"]["readOnlyHint"])
            self.assertFalse(t["annotations"]["destructiveHint"])
            self.assertEqual(t["inputSchema"]["type"], "object")

    def test_errors(self):
        self.assertEqual(self.rpc("no/such")["error"]["code"], -32601)
        self.assertEqual(self.rpc("tools/call", {"name": "drop_tables"})["error"]["code"], -32602)
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(self.server.handle({"id": 3})["error"]["code"], -32600)
        self.assertEqual(self.rpc("ping")["result"], {})
        bad = self.call("get_finding", finding_id="F999")
        self.assertTrue(bad["isError"])
        amb = self.call("get_node", node="u")
        self.assertTrue(amb["isError"])
        self.assertIn("請改用其中一個 id", amb["content"][0]["text"])

    def test_stdio_roundtrip(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_overview", "arguments": {}}},
        ]
        stdin = io.BytesIO(("\n".join(json.dumps(x) for x in lines) + "\nnot json\n").encode())
        stdout = io.BytesIO()
        Server(Store(self.out), log=lambda m: None).serve(stdin, stdout)
        replies = [json.loads(x) for x in stdout.getvalue().decode().splitlines()]
        self.assertEqual([r.get("id") for r in replies], [1, 2, None])
        self.assertNotIn("structuredContent", replies[1]["result"])     # 2025-03-26: text content only
        self.assertEqual(replies[2]["error"]["code"], -32700)


class Tools(McpCase):
    def test_overview(self):
        o = self.ok("get_overview")
        self.assertEqual(o["scope"]["adDomain"], "corp.local")
        self.assertGreater(o["summary"]["findingsBySeverity"]["critical"], 0)
        self.assertTrue(o["attackPaths"]["topEntries"])

    def test_findings(self):
        lst = self.ok("list_findings", min_severity="critical", limit=100)
        self.assertTrue(all(f["severity"] == "critical" for f in lst["findings"]))
        hy = self.ok("list_findings", rule_id="HY-004")
        self.assertEqual({f["ruleId"] for f in hy["findings"]}, {"HY-004"})
        f = self.ok("get_finding", finding_id=hy["findings"][0]["findingId"])
        self.assertIn("remediation", f)
        self.assertTrue(f["affected"])
        by_obj = self.ok("list_findings", contains="u-svc", limit=100)
        self.assertGreaterEqual(by_obj["total"], 3)

    def test_rules_and_hotspots(self):
        self.assertEqual(self.ok("list_rules", status="error")["total"], 0)
        self.assertTrue(self.ok("get_hotspots")["hotspots"])

    def test_nodes_and_edges(self):
        s = self.ok("search_nodes", query="helpdesk", kind="group")
        self.assertEqual(s["nodes"][0]["id"], fx.sid(1201))
        n = self.ok("get_node", node=fx.sid(1102))
        self.assertEqual(n["node"]["label"], "u-svc")
        self.assertTrue(n["findings"])
        aadc = self.ok("get_node", node="CA-AADC")
        self.assertTrue(aadc["node"]["tier0"])                            # Tier0-equivalent host
        e = self.ok("get_edges", node="Helpdesk", direction="out", kinds=["GenericAll"])
        self.assertIn(fx.sid(512), [x["other"]["id"] for x in e["edges"]])

    def test_paths(self):
        p = self.ok("list_attack_paths", broad_only=True, include_steps=True)
        self.assertTrue(p["paths"] and all(x["broad"] for x in p["paths"]))
        self.assertTrue(p["paths"][0]["steps"])
        r = self.ok("path_to_tier0", node="u-svc")
        self.assertTrue(r["hasPath"])
        self.assertEqual(r["steps"][0]["kind"], "AdminTo")
        t0 = self.ok("path_to_tier0", node="u-da1")
        self.assertTrue(t0["isTier0"])
        w = self.ok("who_can_reach", node="CA-AADC")
        self.assertIn(fx.sid(1201), [x["id"] for x in w["sources"]])
        self.assertTrue(all(not x["tier0"] for x in w["sources"]))

    def test_database_is_opened_read_only(self):
        st = Store(self.out)
        with self.assertRaises(sqlite3.OperationalError):
            st.con.execute("DELETE FROM findings")


class OfficialClient(unittest.TestCase):
    """Interop with the official MCP Python SDK (skipped unless `pip install mcp` was done)."""

    def test_sdk_session(self):
        try:
            import anyio  # noqa: F401
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError:
            self.skipTest("mcp SDK not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = fx.make_round(root / "b", True)
            out = root / "report"
            subprocess.run([sys.executable, str(REPO / "tools" / "analyze.py"), *map(str, paths), "--out", str(out)],
                           check=True, capture_output=True)
            params = StdioServerParameters(command=shutil.which("python3") or sys.executable,
                                           args=[str(REPO / "tools" / "mcp_server.py"), str(out)])

            async def session():
                async with stdio_client(params) as (r, w):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        names = [t.name for t in (await s.list_tools()).tools]
                        res = await s.call_tool("path_to_tier0", {"node": "u-svc"})
                        return names, res

            names, res = anyio.run(session)
            self.assertEqual(len(names), len(TOOLS))
            data = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
            self.assertTrue(data["hasPath"])


if __name__ == "__main__":
    unittest.main()
