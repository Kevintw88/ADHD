#!/usr/bin/env python3
"""MVP 驗收腳本：以模擬資料逐項驗證，輸出 PASS / FAIL 表，任一失敗則 exit 1。

用法：
  python scripts/verify_mvp.py              # V2–V7（不需模型）
  python scripts/verify_mvp.py --e2e        # 加 V8：樁模型跑 Agent 全流程
  python scripts/verify_mvp.py --llm        # 加 V10：接真實 LiteLLM + 地端模型（讀 ANTHROPIC_BASE_URL、LITELLM_API_KEY）

所有輸出寫到暫存目錄，不影響專案的 output/。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
import threading
import traceback
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

EXPECTED = {
    # 法人: (Profile, 啟用模組數, 缺口代號, 可達/總來源, 第一步修補的邊, 第一步後剩餘, 最高優先發現)
    "hq": ("A", 8, ["GAP-AUDIT"], (234, 234), ("Domain Users", "Enroll", "VPNUser"), 8, "A-CertTempCustomSubject"),
    "sub-a": ("B", 5, ["GAP-AUDIT", "GAP-SIEM", "GAP-ENTRA-INGEST", "GAP-SYSMON"], (77, 77),
              ("Domain Users", "AdminTo", "SUBA-WS005"), 33, "P-ControlPathIndirectEveryone"),
    "sub-b": ("C", 3, ["GAP-AUDIT", "GAP-SIEM", "GAP-SYSMON"], (37, 37),
              ("Domain Users", "AdminTo", "SRV-FILE01"), 0, "P-UnconstrainedDelegation"),
}

results: list[tuple[str, str, bool, str]] = []


def check(vid: str, name: str):
    def deco(fn):
        def run(*a, **kw):
            try:
                detail = fn(*a, **kw) or ""
                results.append((vid, name, True, detail))
            except AssertionError as e:
                results.append((vid, name, False, str(e)))
            except Exception as e:  # noqa: BLE001
                results.append((vid, name, False, f"{type(e).__name__}: {e}"))
                traceback.print_exc(file=sys.stderr)
        return run
    return deco


def digest(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(d)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def setup(tmp: Path):
    from idsec.mockgen import generate

    generate(tmp / "mock_data")
    cfg = yaml.safe_load((ROOT / "config" / "settings.yaml").read_text(encoding="utf-8"))
    cfg.update(output_dir=str(tmp / "output"), audit_log=str(tmp / "output" / "audit" / "audit.jsonl"),
               capability_matrix=str(ROOT / "config" / "capability_matrix.yaml"))
    cfg["entities"] = [e for e in cfg["entities"] if e.get("backend", "mock") == "mock"]
    for e in cfg["entities"]:
        e["data_dir"] = str(tmp / "mock_data" / e["id"])
        e["reports_dir"] = str(tmp / "mock_data" / e["id"] / "reports")
    path = tmp / "settings.yaml"
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    os.environ["IDSEC_CONFIG"] = str(path)
    from idsec import services
    from idsec.config import load_settings

    services.clear_caches()
    return load_settings(path)


@check("V2", "模擬資料可重現，且與 repo 內 mock_data 一致")
def v2(tmp: Path):
    from idsec.mockgen import generate

    generate(tmp / "regen")
    a, b, repo = digest(tmp / "mock_data"), digest(tmp / "regen"), digest(ROOT / "mock_data")
    assert a == b, "兩次產生結果不同"
    assert a == repo, "repo 內 mock_data 與產生器不一致，請重跑 idsec mock-gen 並提交"
    return f"sha256 {a[:12]}"


@check("V3", "盤點與能力矩陣：Profile、模組數、缺口")
def v3(settings):
    from idsec import services

    out = []
    for e, (prof, n, gaps, *_rest) in EXPECTED.items():
        c = services.capability(e)
        got = (c.profile, len(c.enabled_modules), [g.id for g in c.gaps])
        assert got == (prof, n, gaps), f"{e} 預期 {(prof, n, gaps)}，實得 {got}"
        out.append(f"{e}={prof}")
    assert "assess_entra" not in services.capability("sub-b").enabled_modules, "sub-b 無租戶卻啟用 Entra 評估"
    return " ".join(out)


@check("V4", "攻擊路徑：可達數、第一步修補、修補後剩餘")
def v4(settings):
    from idsec import services

    out = []
    for e, (_p, _n, _g, reach, edge, remain, _f) in EXPECTED.items():
        p = services.path_analysis(e)
        c = p.choke_points[0]
        got_edge = (p.name(c.edge.src), c.edge.kind, p.name(c.edge.dst))
        assert (p.sources_with_path, p.sources_total) == reach, f"{e} 可達數 {(p.sources_with_path, p.sources_total)}"
        assert got_edge == edge, f"{e} 第一步修補 {got_edge}"
        assert c.remaining_after == remain, f"{e} 修補後剩餘 {c.remaining_after}"
        out.append(f"{e}:{c.sources_cut_pct}%")
    return " ".join(out)


@check("V5", "評估發現：解析筆數與最高優先項目")
def v5(settings):
    from idsec import services

    counts = {"hq": 7, "sub-a": 5, "sub-b": 5}
    for e, exp in EXPECTED.items():
        f = services.findings(e)
        assert len(f) == counts[e], f"{e} 發現數 {len(f)}"
        assert f[0].id == exp[6], f"{e} 最高優先 {f[0].id}"
    return "hq 首項因落在 ESC1 路徑上加權"


@check("V6", "唯讀保證：MCP 標註、放行清單、寫入型 Cypher")
def v6(settings):
    from idsec.agent.hooks import READONLY_TOOLS, allowed_tool_names, make_pre_tool_use
    from idsec.mcp_servers import ad_discovery, assessment_reports, bloodhound, entra_graph

    mods = {"ad-discovery": ad_discovery, "entra-graph": entra_graph, "bloodhound": bloodhound,
            "assessment-reports": assessment_reports}

    async def run():
        total = 0
        for name, m in mods.items():
            tools = await m.server.list_tools()
            assert sorted(t.name for t in tools) == sorted(READONLY_TOOLS[name]), f"{name} 工具清單與放行清單不一致"
            assert all(t.annotations.read_only_hint for t in tools), f"{name} 有工具未標註唯讀"
            total += len(tools)
        r = await bloodhound.server.call_tool("run_readonly_cypher", {"entity": "hq", "query": "MATCH (n) DELETE n"})
        assert "PermissionError" in r.content[0].text, "寫入型 Cypher 未被 MCP 拒絕"
        hook = make_pre_tool_use(allowed_tool_names())
        for bad in ("Bash", "Write", "mcp__evil__drop"):
            d = await hook({"tool_name": bad, "tool_input": {}}, None, None)
            assert d["hookSpecificOutput"]["permissionDecision"] == "deny", f"{bad} 未被 Hook 拒絕"
        return total

    return f"{asyncio.run(run())} 個工具皆唯讀"


@check("V7", "稽核鏈：完整性與竄改偵測")
def v7(settings, tmp: Path):
    from idsec.audit import AuditLog
    from idsec.pipeline import run_entity

    for e in EXPECTED:
        run_entity(settings, e)
    log = AuditLog(settings.resolve(settings.audit_log))
    ok, msg = log.verify()
    assert ok, msg
    lines = log.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["data"]["entity"] = "tampered"
    bad = AuditLog(tmp / "tampered.jsonl")
    bad.path.write_text("\n".join([json.dumps(rec, ensure_ascii=False)] + lines[1:]) + "\n", encoding="utf-8")
    assert not bad.verify()[0], "竄改後仍驗證通過"
    return msg


@check("V8", "Agent 全流程（樁模型）：啟動 MCP、工具呼叫、內建工具封鎖")
def v8(settings):
    import stub_llm
    from idsec.agent.orchestrator import ask

    srv = stub_llm.serve(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ.setdefault("LITELLM_API_KEY", "stub")
    settings.models.base_url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        answer = asyncio.run(ask(settings, "hq", "哪些帳號能到 Tier 0？"))
    finally:
        srv.shutdown()
    assert answer.startswith("STUB-FINAL"), f"非預期回覆：{answer[:80]}"
    seen = {t for c in stub_llm.LOG for t in c["tools"]}
    assert "Bash" not in seen, "模型看得到 Bash"
    text = Path(settings.resolve(settings.audit_log)).read_text(encoding="utf-8")
    assert '"tool": "mcp__bloodhound__path_summary"' in text, "稽核鏈未記錄工具呼叫"
    return f"模型可見工具 {len(seen)} 個"


@check("V10", "真實地端模型：能正確呼叫工具並引用工具數字")
def v10(settings):
    from idsec.agent.orchestrator import ask

    base = os.environ.get("ANTHROPIC_BASE_URL")
    assert base, "請設定 ANTHROPIC_BASE_URL（LiteLLM 位址）與 LITELLM_API_KEY"
    settings.models.base_url = base
    q = "請用 bloodhound 工具查 hq 通往 Tier 0 的建議修補順序，只回答第一步要移除的邊與切斷的來源數。"
    answer = asyncio.run(ask(settings, "hq", q, agent="paths"))
    assert "VPNUser" in answer and "226" in answer, f"回覆未引用正確工具結果：{answer[:200]}"
    return answer.strip().splitlines()[0][:60]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--e2e", action="store_true", help="加跑 V8 樁模型 Agent 全流程")
    ap.add_argument("--llm", action="store_true", help="加跑 V10 真實 LiteLLM + 地端模型")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="idsec-verify-") as d:
        tmp = Path(d)
        settings = setup(tmp)
        v2(tmp)
        v3(settings)
        v4(settings)
        v5(settings)
        v6(settings)
        v7(settings, tmp)
        if args.e2e:
            v8(settings)
        if args.llm:
            v10(settings)

    width = max(len(n) for _, n, _, _ in results)
    for vid, name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {vid:<4} {name:<{width}}  {detail}")
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} 通過")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
