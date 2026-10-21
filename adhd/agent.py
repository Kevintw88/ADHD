"""Investigation agent: a local model (OpenAI-compatible API, e.g. vLLM) + the read-only ADHD MCP server.

Follows the simple patterns from Anthropic's "Building effective agents": one augmented LLM in a tool loop
(the MCP tools are its only window on the data), followed by an evaluator-optimizer step — the report is
checked deterministically against the analysis (adhd.verify) and sent back once with the issues if it
fails.  Every request, tool call and result is written to a JSONL transcript for audit.

Standard library only.  Nothing leaves the lab: the model endpoint is whatever --base-url points at.

    python3 tools/agent.py --report-dir /srv/adhd/reports/SubA-20261020 \\
        --base-url http://gpu01:8000/v1 --model <served-model-name> --task report
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .verify import check, feedback, load_truth

REPO = Path(__file__).resolve().parent.parent

SYSTEM_PROMPT = """你是資安評估分析師，負責解讀一份 AD + Entra ID 混合環境的評估結果，對象是資安主管與系統管理員。

你只能透過工具取得資料；工具背後是確定性規則的分析結果，每筆發現都附證據。規則：
1. 只陳述工具回傳的事實。不要推測資料中沒有的帳號、主機、設定或數字；不確定就說「資料中沒有」。
2. 每個風險陳述都要引用來源，格式為 [F001 / AD-021]（findingId / ruleId），兩者必須與工具回傳的一致。
3. 帳號名稱是假名（u-xxxxxxxxxxxx），照原樣使用，不要猜測真實身分。
4. 狀態為 skipped 的規則代表資料不足、未評估，必須寫成「未評估」，絕不能寫成通過或沒有問題。
5. 攻擊路徑是每個起點最短的一條，可能還有其他路徑；建議處理後重新分析確認。
6. 使用繁體中文。工具名稱、規則代號、假名、SID 維持原樣。

先呼叫 get_overview 了解全貌，再依需要查詢；查到足夠資料後再寫答案，不要無止境地查詢。"""

TASKS = {
    "report": """請產出本次評估的報告（Markdown），結構如下：

# 評估摘要
範圍、資料時間、各嚴重度發現數、最需要注意的 3 件事（各一句，附引用）。

## 優先處理
依風險排序 5–10 項：問題、影響（若有攻擊路徑，說明從哪個起點幾步到 Tier0）、建議做法、引用。所有嚴重（critical）發現都必須出現在報告中。

## 攻擊路徑
廣泛群組的路徑、影響帳號最多的路徑、優先切斷的步驟（附引用）。

## 其他發現
依類別（AD、ADCS、Entra、Hybrid）簡述其餘高與中嚴重度的發現，附引用。

## 未評估的範圍
列出因資料不足而略過的規則與缺少的資料，以及補收集的建議。""",
}


# ===========================================================================================
class McpError(Exception):
    pass


class McpClient:
    """Minimal MCP client over stdio (newline-delimited JSON-RPC)."""

    def __init__(self, command: list[str], log: Callable[[dict], None] | None = None) -> None:
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._id = 0
        self.log = log or (lambda e: None)
        init = self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                           "clientInfo": {"name": "adhd-agent", "version": __version__}})
        self.server_info = init.get("serverInfo") or {}
        self.instructions = init.get("instructions") or ""
        self.notify("notifications/initialized")
        self.tools = self.request("tools/list").get("tools", [])

    def _send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        mid = self._id
        self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                err = self.proc.stderr.read().decode("utf-8", "replace") if self.proc.stderr else ""
                raise McpError(f"MCP 伺服器已結束：{err.strip()[-500:]}")
            msg = json.loads(line)
            if msg.get("id") != mid:
                continue
            if "error" in msg:
                raise McpError(f"{method}: {msg['error'].get('message')}")
            return msg.get("result") or {}

    def call(self, name: str, arguments: dict) -> tuple[str, bool]:
        res = self.request("tools/call", {"name": name, "arguments": arguments})
        text = "\n".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        return text, bool(res.get("isError"))

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        for pipe in (self.proc.stdout, self.proc.stderr):
            if pipe:
                pipe.close()


# ===========================================================================================
class LlmError(Exception):
    pass


class ChatClient:
    """OpenAI-compatible /chat/completions client (vLLM, SGLang, Ollama, LM Studio ...)."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None, timeout: float = 600,
                 temperature: float = 0.2, max_tokens: int | None = None) -> None:
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model, self.api_key, self.timeout = model, api_key, timeout
        self.temperature, self.max_tokens = temperature, max_tokens

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        req = urllib.request.Request(self.url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:800]
            hint = ""
            if "tool" in detail.lower():
                hint = ("（模型服務可能沒有開啟工具呼叫：vLLM 需要 --enable-auto-tool-choice 與符合模型的 --tool-call-parser）")
            raise LlmError(f"HTTP {e.code}: {detail}{hint}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LlmError(f"無法連線到 {self.url}：{e}") from None
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise LlmError(f"非預期的回應：{json.dumps(data, ensure_ascii=False)[:500]}") from None


_THINK = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
_TEXT_TOOL_CALL = re.compile(r"<tool_call>|\"name\"\s*:\s*\"(get_overview|list_findings|get_finding)\"")


def _clean(text: str | None) -> str:
    return _THINK.sub("", text or "").strip()


def mcp_to_openai(tools: list[dict]) -> list[dict]:
    return [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                              "parameters": t.get("inputSchema") or {"type": "object", "properties": {}}}}
            for t in tools]


# ===========================================================================================
class Transcript:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.fh = path.open("w", encoding="utf-8") if path else None

    def __call__(self, event: dict) -> None:
        if self.fh:
            self.fh.write(json.dumps(dict(event, ts=time.strftime("%Y-%m-%dT%H:%M:%S")), ensure_ascii=False, default=str) + "\n")
            self.fh.flush()

    def close(self) -> None:
        if self.fh:
            self.fh.close()


def run(task: str, report_dir: Path, chat: ChatClient, *, max_steps: int = 30, max_tool_chars: int = 12000,
        revisions: int = 1, transcript: Path | None = None, mcp_command: list[str] | None = None,
        progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Run one task; returns {"answer", "verification", "steps", "toolCalls"}."""
    say = progress or (lambda m: None)
    log = Transcript(transcript)
    cmd = mcp_command or [sys.executable, str(REPO / "tools" / "mcp_server.py"), str(report_dir)]
    mcp = McpClient(cmd, log)
    truth = load_truth(report_dir) if task in TASKS else None
    try:
        tools = mcp_to_openai(mcp.tools)
        system = SYSTEM_PROMPT + ("\n\n資料來源說明：" + mcp.instructions if mcp.instructions else "")
        messages: list[dict] = [{"role": "system", "content": system},
                                {"role": "user", "content": TASKS.get(task, task)}]
        log({"type": "start", "task": task, "model": chat.model, "server": mcp.server_info, "tools": [t["name"] for t in mcp.tools]})
        steps = calls = 0
        seen: dict[str, int] = {}
        verification = None
        answer = ""
        while steps < max_steps:
            steps += 1
            msg = chat.complete(messages, tools)
            log({"type": "llm", "step": steps, "message": msg})
            tool_calls = msg.get("tool_calls") or []
            content = _clean(msg.get("content"))
            if not tool_calls:
                if _TEXT_TOOL_CALL.search(content) and not content.startswith("#"):
                    raise LlmError("模型以文字輸出工具呼叫而不是 tool_calls：模型服務的 tool-call parser 設定可能不符")
                answer = content
                messages.append({"role": "assistant", "content": content})
                if truth is None:
                    break
                verification = check(answer, truth)
                log({"type": "verify", "result": verification})
                say(f"檢查：{'通過' if verification['passed'] else '未通過'}（錯誤 {verification['errors']}、警告 {verification['warnings']}）")
                if verification["passed"] or revisions <= 0:
                    break
                revisions -= 1
                messages.append({"role": "user", "content": feedback(verification)})
                say("依檢查結果請模型修正一次")
                continue
            messages.append({"role": "assistant", "content": msg.get("content") or None, "tool_calls": tool_calls})
            for tc in tool_calls:
                calls += 1
                fn = (tc.get("function") or {})
                name = fn.get("name", "")
                tc_id = tc.get("id") or f"call_{uuid.uuid4().hex[:8]}"
                shown = fn.get("arguments") or "{}"
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                    if not isinstance(args, dict):
                        raise ValueError("arguments 不是物件")
                except ValueError as e:
                    text, is_err = f"參數不是合法的 JSON：{e}", True
                else:
                    key = name + json.dumps(args, sort_keys=True, ensure_ascii=False)
                    seen[key] = seen.get(key, 0) + 1
                    if seen[key] > 2:
                        text, is_err = "這個查詢已經做過，結果相同；請使用先前的結果，或改查其他資料。", True
                    else:
                        try:
                            text, is_err = mcp.call(name, args)
                        except McpError as e:
                            text, is_err = str(e), True
                say(f"  工具 {name}({shown}){' → 錯誤' if is_err else ''}")
                log({"type": "tool", "name": name, "arguments": fn.get("arguments"), "isError": is_err, "chars": len(text),
                     "result": text})
                if len(text) > max_tool_chars:
                    text = text[:max_tool_chars] + f"\n…（結果過長已截斷，共 {len(text)} 字元；請用 limit / offset 或更精確的條件查詢）"
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": text})
        else:
            say(f"達到最多 {max_steps} 步，停止")
        if not answer:
            answer = "（模型在步數上限內沒有產出最終答案）"
        log({"type": "end", "steps": steps, "toolCalls": calls})
        return {"answer": answer, "verification": verification, "steps": steps, "toolCalls": calls}
    finally:
        mcp.close()
        log.close()


def main(argv=None) -> int:
    import argparse
    import os
    ap = argparse.ArgumentParser(description="ADHD investigation agent: local model + read-only MCP server")
    ap.add_argument("--report-dir", type=Path, required=True, help="output directory of tools/analyze.py")
    ap.add_argument("--base-url", default=os.environ.get("ADHD_LLM_BASE_URL", "http://localhost:8000/v1"),
                    help="OpenAI-compatible endpoint (vLLM: http://<host>:8000/v1)")
    ap.add_argument("--model", default=os.environ.get("ADHD_LLM_MODEL"), help="served model name")
    ap.add_argument("--api-key", default=os.environ.get("ADHD_LLM_API_KEY"))
    ap.add_argument("--task", default="report", help="'report' or a question in natural language")
    ap.add_argument("--out", type=Path, help="where to write answer.md, verification.json and transcript.jsonl "
                                             "(default: <report-dir>/agent-<time>)")
    ap.add_argument("--max-steps", type=int, default=30)
    ap.add_argument("--revisions", type=int, default=1, help="revision rounds when the report fails verification")
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--max-tokens", type=int)
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--verify-only", type=Path, metavar="ANSWER_MD", help="only check an existing report against --report-dir")
    args = ap.parse_args(argv)

    if args.verify_only:
        res = check(args.verify_only.read_text(encoding="utf-8"), load_truth(args.report_dir))
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["passed"] else 1
    if not args.model:
        ap.error("--model is required (or set ADHD_LLM_MODEL)")
    out = args.out or args.report_dir / time.strftime("agent-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    chat = ChatClient(args.base_url, args.model, args.api_key, args.timeout, args.temperature, args.max_tokens)
    try:
        res = run(args.task, args.report_dir, chat, max_steps=args.max_steps, revisions=args.revisions,
                  transcript=out / "transcript.jsonl", progress=lambda m: print(m, file=sys.stderr, flush=True))
    except (LlmError, McpError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    (out / "answer.md").write_text(res["answer"] + "\n", encoding="utf-8")
    if res["verification"] is not None:
        (out / "verification.json").write_text(json.dumps(res["verification"], ensure_ascii=False, indent=2), encoding="utf-8")
    v = res["verification"]
    print(f"完成：{res['steps']} 步、{res['toolCalls']} 次工具呼叫"
          + (f"；檢查{'通過' if v['passed'] else '未通過'}（嚴重發現覆蓋 {v['criticalCoverage']}、"
             f"高嚴重度覆蓋 {int(v['highCoverage'] * 100)}%、錯誤 {v['errors']}、警告 {v['warnings']}）" if v else ""))
    print(f"輸出：{out}/answer.md" + ("、verification.json" if v else "") + "、transcript.jsonl")
    return 0 if (v is None or v["passed"]) else 1


if __name__ == "__main__":
    sys.exit(main())
