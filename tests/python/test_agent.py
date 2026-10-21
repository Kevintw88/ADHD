"""Agent tests: a scripted OpenAI-compatible model (local HTTP server) drives the real MCP server,
and the deterministic report checker (adhd.verify) catches invented findings / names."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures as fx  # noqa: E402
from adhd.agent import ChatClient, LlmError, mcp_to_openai, run  # noqa: E402
from adhd.analyze import main as analyze_main  # noqa: E402
from adhd.verify import check, load_truth  # noqa: E402


class ScriptedModel:
    """Replies in order; each reply is a callable(messages) -> assistant message."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, body):
        self.requests.append(body)
        reply = self.replies.pop(0)
        return reply(body["messages"])


def tool_call(name, **args):
    def reply(messages):
        return {"role": "assistant", "content": None, "tool_calls": [
            {"id": f"c{len(messages)}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}
    return reply


def text(builder):
    return lambda messages: {"role": "assistant", "content": builder(messages)}


def serve(model):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            out = json.dumps({"choices": [{"message": model(body)}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class AgentCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        paths = fx.make_round(root / "b", True)
        cls.report = root / "report"
        with open(root / "log.txt", "w") as sink:
            stdout, sys.stdout = sys.stdout, sink
            try:
                assert analyze_main([str(p) for p in paths] + ["--out", str(cls.report)]) == 0
            finally:
                sys.stdout = stdout
        cls.truth = load_truth(cls.report)
        cls.doc = cls.truth["doc"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def good_report(self):
        lines = ["# 評估摘要", ""]
        for f in self.doc["findings"]:
            if f["severity"] in ("critical", "high"):
                lines += [f"- {f['title']}：{f['summary'][:60]} [{f['findingId']} / {f['ruleId']}]", ""]
        lines += ["## 未評估的範圍", "", "本次沒有因資料不足而未評估的規則。"]
        return "\n".join(lines)


class Verify(AgentCase):
    def test_good_report_passes(self):
        res = check(self.good_report(), self.truth)
        self.assertTrue(res["passed"], res["issues"])
        self.assertEqual(res["highCoverage"], 1.0)

    def test_invented_content_is_caught(self):
        crit = next(f for f in self.doc["findings"] if f["severity"] == "critical")
        other_rule = "AD-001" if crit["ruleId"] != "AD-001" else "AD-002"
        bad = (self.good_report()
               + f"\n\n另外 [F999 / AD-001] 顯示 u-0123456789ab 是網域管理員。"
               + f"\n\n{crit['findingId']} / {other_rule} 也很嚴重。")
        types = {i["type"] for i in check(bad, self.truth)["issues"]}
        self.assertTrue({"unknown_finding", "unknown_name", "wrong_rule"} <= types, types)

    def test_missing_critical_and_skipped_as_passed(self):
        truth = dict(self.truth, skipped={"ADCS-007"})
        res = check("# 摘要\n\nADCS-007 通過，沒有問題。", truth)
        types = {i["type"] for i in res["issues"]}
        self.assertIn("missing_critical", types)
        self.assertIn("skipped_as_passed", types)
        self.assertFalse(res["passed"])


class Loop(AgentCase):
    def test_tool_loop_with_revision(self):
        good = self.good_report()
        model = ScriptedModel([
            tool_call("get_overview"),
            tool_call("list_findings", min_severity="critical"),
            tool_call("path_to_tier0", node="u-svc"),
            text(lambda m: "# 評估摘要\n\n[F999 / AD-001] u-0123456789ab 可以控制網域。"),   # invented: must be sent back
            text(lambda m: good),
        ])
        httpd = serve(model)
        try:
            chat = ChatClient(f"http://127.0.0.1:{httpd.server_port}/v1", "test-model")
            out = Path(self._tmp.name) / "agent"
            out.mkdir()
            res = run("report", self.report, chat, transcript=out / "t.jsonl", revisions=1)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertTrue(res["verification"]["passed"], res["verification"]["issues"])
        self.assertEqual(res["toolCalls"], 3)
        self.assertEqual(res["answer"], good)
        # the model saw the tools, the tool results and the checker's feedback
        first = model.requests[0]
        self.assertEqual({t["function"]["name"] for t in first["tools"]} >= {"get_overview", "who_can_reach"}, True)
        tool_msgs = [m for m in model.requests[3]["messages"] if m["role"] == "tool"]
        self.assertEqual(len(tool_msgs), 3)
        self.assertIn("corp.local", tool_msgs[0]["content"])
        self.assertIn("AdminTo", tool_msgs[2]["content"])
        self.assertIn("unknown_finding", model.requests[4]["messages"][-1]["content"])
        events = [json.loads(x)["type"] for x in (out / "t.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events.count("tool"), 3)
        self.assertEqual(events.count("verify"), 2)

    def test_repeated_calls_and_bad_arguments(self):
        model = ScriptedModel([
            tool_call("get_finding", finding_id="F001"), tool_call("get_finding", finding_id="F001"),
            tool_call("get_finding", finding_id="F001"),
            lambda m: {"role": "assistant", "content": None, "tool_calls": [
                {"id": "x", "type": "function", "function": {"name": "get_node", "arguments": "{not json"}}]},
            text(lambda m: "完成"),
        ])
        httpd = serve(model)
        try:
            res = run("請說明 F001", self.report, ChatClient(f"http://127.0.0.1:{httpd.server_port}/v1", "m"))
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(res["answer"], "完成")
        self.assertIsNone(res["verification"])            # free-form question: no report check
        last = [m["content"] for m in model.requests[-1]["messages"] if m["role"] == "tool"]
        self.assertIn("已經做過", last[2])
        self.assertIn("不是合法的 JSON", last[3])

    def test_unreachable_model(self):
        with self.assertRaises(LlmError):
            run("report", self.report, ChatClient("http://127.0.0.1:9/v1", "m", timeout=2))

    def test_think_tags_are_removed(self):
        model = ScriptedModel([text(lambda m: "<think>先想一下</think>\n答案")])
        httpd = serve(model)
        try:
            res = run("問題", self.report, ChatClient(f"http://127.0.0.1:{httpd.server_port}/v1", "m"))
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(res["answer"], "答案")

    def test_tool_schema_conversion(self):
        tools = mcp_to_openai([{"name": "x", "description": "d", "inputSchema": {"type": "object", "properties": {}}}])
        self.assertEqual(tools[0]["function"]["parameters"]["type"], "object")


if __name__ == "__main__":
    unittest.main()
