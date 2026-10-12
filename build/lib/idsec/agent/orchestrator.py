"""Orchestrator：依能力矩陣決定可用的子代理，組出 ClaudeAgentOptions 並執行問答。

模型路由（經 LiteLLM，Anthropic Messages 相容）：
- 主代理：settings.models.reason
- 子代理 model="haiku" → ANTHROPIC_DEFAULT_HAIKU_MODEL = settings.models.fast
- 子代理 model="sonnet" → ANTHROPIC_DEFAULT_SONNET_MODEL = settings.models.reason
"""

from __future__ import annotations

import os
import sys
from typing import Any

from claude_agent_sdk import (
    AgentDefinition, AssistantMessage, ClaudeAgentOptions, HookMatcher, ResultMessage, TextBlock, query,
)

from .. import services
from ..audit import AuditLog
from ..config import PROJECT_ROOT, Settings
from ..mcp_servers import SERVERS
from .hooks import ORCHESTRATION_TOOLS, allowed_tool_names, make_pre_tool_use, post_tool_use
from .prompts import ORCHESTRATOR, SUBAGENTS

# 內建工具一律關閉（檔案、Shell、網路）；只留委派與 Skill
DISALLOWED_BUILTINS = ["Bash", "BashOutput", "KillShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
                       "Glob", "Grep", "WebFetch", "WebSearch", "TodoWrite",
                       "mcp__claude-in-chrome"]  # 主機若裝了瀏覽器擴充，一併封鎖


def enabled_subagents(entity: str) -> dict[str, dict]:
    """能力矩陣決定可用子代理與其 MCP Server（無 Entra 租戶時不掛 entra-graph）。"""
    enabled = set(services.capability(entity).enabled_modules)
    has_entra = "assess_entra" in enabled
    out = {}
    for k, v in SUBAGENTS.items():
        if v["requires"] in enabled:
            out[k] = {**v, "servers": [s for s in v["servers"] if has_entra or s != "entra-graph"]}
    return out


def _mcp_config(servers: list[str]) -> dict[str, dict]:
    env = {"IDSEC_CONFIG": os.environ.get("IDSEC_CONFIG", str(PROJECT_ROOT / "config" / "settings.yaml")),
           "PYTHONPATH": str(PROJECT_ROOT / "src")}
    return {s: {"type": "stdio", "command": sys.executable, "args": ["-m", SERVERS[s]], "env": env} for s in servers}


def _model_env(settings: Settings) -> dict[str, str]:
    env = {
        "ANTHROPIC_BASE_URL": settings.models.base_url,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": settings.models.fast,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": settings.models.reason,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": settings.models.reason,
        # 封閉環境：關閉非必要對外連線與遙測
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    }
    if token := os.environ.get("LITELLM_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        env["ANTHROPIC_AUTH_TOKEN"] = token
    return env


def build_options(settings: Settings, entity: str, agent: str | None = None) -> ClaudeAgentOptions:
    subs = enabled_subagents(entity)
    if agent:
        if agent not in subs:
            raise ValueError(f"子代理 {agent!r} 未啟用；{entity} 可用：{', '.join(subs) or '無'}")
        spec = subs[agent]
        servers = spec["servers"]
        system_prompt = spec["prompt"]
        agents = None
        model = settings.models.fast if spec["model"] == "haiku" else settings.models.reason
    else:
        servers = sorted({"ad-discovery", *[s for v in subs.values() for s in v["servers"]]})
        system_prompt = ORCHESTRATOR
        agents = {k: AgentDefinition(description=v["description"], prompt=v["prompt"],
                                     tools=allowed_tool_names(v["servers"]), model=v["model"])
                  for k, v in subs.items()}
        model = settings.models.reason

    allowed = allowed_tool_names(servers)
    return ClaudeAgentOptions(
        system_prompt=system_prompt + f"\n目前分析的法人代號：{entity}（工具參數 entity 請填這個值）。",
        mcp_servers=_mcp_config(servers),
        strict_mcp_config=True,  # 只用本平台的 MCP，忽略主機上其他 MCP 設定
        tools=["Agent", "Skill"] if agents else ["Skill"],  # 內建工具只留委派與 Skill
        allowed_tools=allowed + (ORCHESTRATION_TOOLS if agents else ["Skill"]),
        disallowed_tools=DISALLOWED_BUILTINS,
        permission_mode="dontAsk",
        agents=agents,
        model=model,
        cwd=str(PROJECT_ROOT),
        setting_sources=["project"],  # 載入 .claude/skills
        env=_model_env(settings),
        max_turns=30,
        hooks={
            "PreToolUse": [HookMatcher(matcher=None, hooks=[make_pre_tool_use(allowed)])],
            "PostToolUse": [HookMatcher(matcher=None, hooks=[post_tool_use])],
        },
    )


async def ask(settings: Settings, entity: str, question: str, agent: str | None = None,
              on_text: Any = None) -> str:
    audit = AuditLog(settings.resolve(settings.audit_log))
    audit.append("agent", "ask.start", {"entity": entity, "agent": agent or "orchestrator", "question": question[:500]})
    options = build_options(settings, entity, agent)
    texts: list[str] = []
    final = ""
    async for msg in query(prompt=question, options=options):
        if isinstance(msg, AssistantMessage):
            for block in msg.content:
                if isinstance(block, TextBlock):
                    texts.append(block.text)
                    if on_text:
                        on_text(block.text)
        elif isinstance(msg, ResultMessage):
            final = msg.result or ""
            audit.append("agent", "ask.end", {"entity": entity, "is_error": msg.is_error,
                                              "turns": msg.num_turns, "model": options.model})
    return final or "\n".join(texts)
