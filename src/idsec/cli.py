"""命令列入口：idsec <子命令>。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .audit import AuditLog
from .config import PROJECT_ROOT, load_settings


def _entities(settings, arg: str | None) -> list[str]:
    return [e.id for e in settings.entities] if arg in (None, "all") else [arg]


def cmd_mock_gen(args) -> int:
    from .mockgen import generate

    files = generate(args.out or PROJECT_ROOT / "mock_data")
    print(f"已產生 {len(files)} 個模擬檔案")
    return 0


def cmd_discover(args) -> int:
    from .pipeline import discover

    s = load_settings(args.config)
    for e in _entities(s, args.entity):
        fp, cap = discover(s, e)
        print(f"[{e}] Profile {cap.profile} {cap.profile_name}　啟用 {len(cap.enabled_modules)} 個模組　缺口 {len(cap.gaps)} 項")
        for g in cap.gaps:
            print(f"    - {g.id} {g.title}")
    return 0


def cmd_run(args) -> int:
    from .pipeline import run_entity

    s = load_settings(args.config)
    for e in _entities(s, args.entity):
        r = run_entity(s, e)
        p = r.paths
        line = f"[{e}] Profile {r.capability.profile}　發現 {len(r.findings)} 項"
        if p:
            line += f"　可到達 Tier 0：{p.sources_with_path}/{p.sources_total}"
        print(line + f"　報告：{r.out_dir / 'report.md'}")
    return 0


def cmd_ask(args) -> int:
    from .agent.orchestrator import ask

    s = load_settings(args.config)
    answer = asyncio.run(ask(s, args.entity, args.question, agent=args.agent))
    print(answer)
    return 0


def cmd_agents(args) -> int:
    from .agent.orchestrator import enabled_subagents

    for e in _entities(load_settings(args.config), args.entity):
        print(f"[{e}] 可用子代理：{', '.join(enabled_subagents(e)) or '無'}")
    return 0


def cmd_audit_verify(args) -> int:
    s = load_settings(args.config)
    ok, msg = AuditLog(s.resolve(s.audit_log)).verify()
    print(("✔ " if ok else "✘ ") + msg)
    return 0 if ok else 2


def cmd_mcp(args) -> int:
    import importlib

    from .mcp_servers import SERVERS

    importlib.import_module(SERVERS[args.server]).main()
    return 0


def cmd_fingerprint(args) -> int:
    from . import services

    print(json.dumps(services.fingerprint(args.entity).model_dump(), ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="idsec", description="AD + Entra ID 混合環境 AI 資安防護平台（MVP，唯讀）")
    ap.add_argument("--config", help="設定檔路徑（預設 config/settings.yaml 或 IDSEC_CONFIG）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("mock-gen", help="產生模擬資料")
    p.add_argument("--out")
    p.set_defaults(func=cmd_mock_gen)

    p = sub.add_parser("discover", help="Phase 0：盤點、指紋、能力矩陣")
    p.add_argument("entity", nargs="?", default="all")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("run", help="完整確定性流程並產出報告")
    p.add_argument("entity", nargs="?", default="all")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("fingerprint", help="輸出環境指紋 JSON")
    p.add_argument("entity")
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("agents", help="列出各法人依能力矩陣可用的子代理")
    p.add_argument("entity", nargs="?", default="all")
    p.set_defaults(func=cmd_agents)

    p = sub.add_parser("ask", help="以 Agent 自然語言問答（需 LiteLLM 與地端模型）")
    p.add_argument("entity")
    p.add_argument("question")
    p.add_argument("--agent", choices=["discovery", "assessment", "paths"], help="直接指定子代理")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("audit-verify", help="驗證稽核鏈完整性")
    p.set_defaults(func=cmd_audit_verify)

    p = sub.add_parser("mcp", help="以 stdio 啟動單一 MCP Server")
    p.add_argument("server", choices=["ad-discovery", "entra-graph", "bloodhound", "assessment-reports"])
    p.set_defaults(func=cmd_mcp)

    args = ap.parse_args(argv)
    if args.config:  # 讓 MCP 子行程與快取層讀到同一份設定
        os.environ["IDSEC_CONFIG"] = args.config
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
