"""測試用 Anthropic Messages 相容樁（取代 LiteLLM + 地端模型）。

行為（依對話中已有的 tool_result 數量決定）：
1. 第一輪：呼叫 mcp__bloodhound__path_summary
2. 第二輪：嘗試呼叫 Bash（應被 Hook / 權限擋下）
3. 第三輪：回覆最終文字，內含第一次工具結果的前 80 字
支援串流（SSE）與非串流。只供整合測試使用。
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG: list[dict] = []


def _tool_results(messages: list[dict]) -> list[str]:
    out = []
    for m in messages:
        if m.get("role") != "user" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if b.get("type") == "tool_result":
                c = b.get("content")
                out.append(json.dumps(c, ensure_ascii=False) if not isinstance(c, str) else c)
    return out


def _plan(body: dict) -> list[dict]:
    tools = {t.get("name") for t in body.get("tools", [])}
    results = _tool_results(body.get("messages", []))
    if len(results) == 0 and "mcp__bloodhound__path_summary" in tools:
        return [{"type": "tool_use", "id": "toolu_stub_1", "name": "mcp__bloodhound__path_summary",
                 "input": {"entity": "hq"}}]
    if len(results) == 1:
        return [{"type": "tool_use", "id": "toolu_stub_2", "name": "Bash", "input": {"command": "whoami"}}]
    first = results[0][:80] if results else "（無）"
    return [{"type": "text", "text": f"STUB-FINAL 工具結果摘錄：{first}"}]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 靜音
        pass

    def _json(self, code: int, obj: dict) -> None:
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._json(200, {"data": [], "has_more": False})

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if "count_tokens" in self.path:
            return self._json(200, {"input_tokens": 10})
        if not self.path.startswith("/v1/messages"):
            return self._json(404, {"error": "not found"})
        LOG.append({"model": body.get("model"), "tools": [t.get("name") for t in body.get("tools", [])]})
        blocks = _plan(body)
        stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
        msg = {"id": "msg_stub", "type": "message", "role": "assistant", "model": body.get("model", "stub"),
               "content": blocks, "stop_reason": stop, "stop_sequence": None,
               "usage": {"input_tokens": 10, "output_tokens": 10}}
        if not body.get("stream"):
            return self._json(200, msg)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()

        def ev(name: str, data: dict) -> None:
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode())

        ev("message_start", {"type": "message_start", "message": {**msg, "content": [], "stop_reason": None}})
        for i, b in enumerate(blocks):
            if b["type"] == "text":
                ev("content_block_start", {"type": "content_block_start", "index": i,
                                           "content_block": {"type": "text", "text": ""}})
                ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                           "delta": {"type": "text_delta", "text": b["text"]}})
            else:
                ev("content_block_start", {"type": "content_block_start", "index": i,
                                           "content_block": {**b, "input": {}}})
                ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                           "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}})
            ev("content_block_stop", {"type": "content_block_stop", "index": i})
        ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                             "usage": {"output_tokens": 10}})
        ev("message_stop", {"type": "message_stop"})
        self.wfile.flush()


def serve(port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    srv = serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8787)
    print(f"stub on {srv.server_address}")
    srv.serve_forever()
