"""Write analysis outputs: findings.json (machine / local LLM), findings.md (people), graph.sqlite (queries / MCP)."""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import FINDINGS_SCHEMA, __version__
from .rules import SEVERITIES, SEVERITY_RANK, RuleResult

MD_AFFECTED_LIMIT = 25


def _findings(results: list[RuleResult]) -> list[dict[str, Any]]:
    out = [f.to_dict() for r in results for f in r.findings]
    out.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["ruleId"]))
    for i, f in enumerate(out, 1):
        f["findingId"] = f"F{i:03d}"
    return out


WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
_PRINCIPAL_KINDS = {"user", "computer", "group", "gmsa", "foreignPrincipal", "entraUser", "entraGroup",
                    "servicePrincipal", "application"}


def hotspots(ctx, findings: list[dict[str, Any]], limit: int = 15) -> list[dict[str, Any]]:
    """Identities (AD account merged with its synced Entra account) that appear in several findings."""
    g = ctx.graph
    agg: dict[str, dict[str, Any]] = {}

    def identity(nid: str) -> str:
        if g.kind(nid) == "application":            # App registration and its service principal are one identity
            for e in g.edges_out(nid, ["AppIdentity"]):
                return e.dst
        if nid.startswith("entra:"):
            for e in g.edges_in(nid, ["SyncedTo"]):
                return e.src
        return nid

    for f in findings:
        if f["severity"] == "info":
            continue
        ids = [a.get("id") for a in f["affected"]] + list((f.get("evidence") or {}).get("excludedUsers") or [])
        for nid in dict.fromkeys(i for i in ids if i):
            if g.kind(nid) not in _PRINCIPAL_KINDS:
                continue
            key = identity(nid)
            h = agg.setdefault(key, {"id": key, "accounts": set(), "findings": [], "rules": [], "severities": []})
            h["accounts"].add(nid)
            if f["findingId"] not in h["findings"]:
                h["findings"].append(f["findingId"])
                h["rules"].append(f["ruleId"] + ("（排除對象）" if nid not in [a.get("id") for a in f["affected"]] else ""))
                h["severities"].append(f["severity"])
    out = []
    for h in agg.values():
        if len(h["findings"]) < 2:
            continue
        accounts = sorted(h["accounts"] | {h["id"]}, key=lambda x: (x.startswith("entra:"), x))
        out.append({
            "id": h["id"], "label": " / ".join(dict.fromkeys(g.label(a) for a in accounts)),
            "accounts": accounts, "tier0": h["id"] in ctx.tier0,
            "score": sum(WEIGHT[s] for s in h["severities"]),
            "maxSeverity": min(h["severities"], key=SEVERITY_RANK.__getitem__),
            "findings": h["findings"], "rules": h["rules"],
        })
    out.sort(key=lambda h: (-h["score"], SEVERITY_RANK[h["maxSeverity"]], h["label"]))
    return out[:limit]


PATHS_LIMIT = 100


def _attack_paths(ctx) -> dict[str, Any] | None:
    """Attack-path summary when the PATH rules ran (adhd.paths memoises it on the context)."""
    res = getattr(ctx, "_attack_paths", None)
    if res is None:
        return None
    out = {k: v for k, v in res.items() if k != "entries"}
    out.update(entries=res["entries"][:PATHS_LIMIT], entriesTotal=len(res["entries"]))
    # kind / Tier0 status of every object on the listed routes, so viewers can draw them without the graph
    ag = getattr(ctx, "_attack_graph", (None,))[0]
    ids = {s[k] for e in out["entries"] for s in e["steps"] for k in ("from", "to")}
    ids |= {c[k] for c in out.get("chokepoints") or [] for k in ("from", "to")}
    out["nodes"] = {n: {"label": ctx.label(n), "kind": ctx.graph.kind(n),
                        "tier0": n in ctx.tier0 or bool(ag and n in ag.targets),
                        "tier0Reason": ag.targets.get(n) if ag else None} for n in sorted(ids)}
    return out


def build_document(ctx, results: list[RuleResult], accepted: list[dict[str, Any]] | None = None,
                   exception_warnings: list[str] | None = None) -> dict[str, Any]:
    findings = _findings(results)
    status = Counter(r.status for r in results)
    return {
        "schema": FINDINGS_SCHEMA,
        "analyzer": {"name": "adhd", "version": __version__},
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "asOfUtc": ctx.as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bundles": ctx.round.describe(),
        "scope": {"adDomain": ctx.domain_dns, "adDomainSid": ctx.domain_sid, "entraTenantId": ctx.tenant_id},
        "summary": {
            "findingsBySeverity": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
            "rules": {k: status.get(k, 0) for k in ("finding", "pass", "skipped", "error", "accepted")},
            "acceptedExceptions": len(accepted or []),
            "tier0Principals": len(ctx.tier0),
            "graph": ctx.graph.stats(),
        },
        "hotspots": hotspots(ctx, findings),
        "attackPaths": _attack_paths(ctx),
        "rules": [r.to_dict() for r in results],
        "findings": findings,
        "accepted": accepted or [],
        "exceptionWarnings": exception_warnings or [],
    }


def write_json(doc: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _fmt_detail(d: Any) -> str:
    if d in (None, "", [], {}):
        return ""
    if isinstance(d, dict):
        return "；".join(f"{k}={_fmt_detail(v) if isinstance(v, (dict, list)) else v}" for k, v in d.items() if v not in (None, "", [], {}))
    if isinstance(d, list):
        shown = ", ".join(str(x) for x in d[:8])
        return shown + (f" …(+{len(d) - 8})" if len(d) > 8 else "")
    return str(d)


def _md_escape(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


SEV_LABEL = {"critical": "嚴重", "high": "高", "medium": "中", "low": "低", "info": "資訊"}
STATUS_LABEL = {"finding": "有發現", "pass": "通過", "skipped": "略過", "error": "錯誤", "accepted": "已接受例外"}


def write_markdown(doc: dict[str, Any], path: Path) -> None:
    s = doc["summary"]
    lines = [f"# ADHD 評估報告 — {doc['scope'].get('adDomain') or doc['scope'].get('entraTenantId') or ''}", ""]
    lines.append(f"- 資料時間（收集完成）：{doc['asOfUtc']}　分析時間：{doc['generatedUtc']}　分析器 {doc['analyzer']['version']}")
    lines.append(f"- AD：{doc['scope'].get('adDomain')}（{doc['scope'].get('adDomainSid')}）　Entra tenant：{doc['scope'].get('entraTenantId')}")
    lines.append("- Bundles：" + "、".join(f"{b['bundle']}（{', '.join(b.get('modules') or [])}）" for b in doc["bundles"]))
    lines.append("- 帳號名稱為假名（u-xxxxxxxxxxxx），請以子公司保管的對照表還原。")
    lines += ["", "## 摘要", "", "| 嚴重 | 高 | 中 | 低 | 資訊 |", "|---|---|---|---|---|",
              "| " + " | ".join(str(s["findingsBySeverity"][k]) for k in SEVERITIES) + " |", ""]
    r = s["rules"]
    lines.append(f"規則：{r['finding']} 條有發現、{r['pass']} 條通過、{r['skipped']} 條因資料不足略過、{r['error']} 條錯誤"
                 + (f"、{r['accepted']} 條全數為已接受例外" if r.get("accepted") else "") + f"。Tier0 主體 {s['tier0Principals']} 個。"
                 + (f"已接受例外 {s['acceptedExceptions']} 筆（見文末）。" if s.get("acceptedExceptions") else ""))
    for w in doc.get("exceptionWarnings") or []:
        lines.append(f"- ⚠ {w}")
    if doc.get("hotspots"):
        lines += ["", "## 重點對象（同一身分出現在多條規則）", "",
                  "AD 帳號與其同步的 Entra 帳號視為同一身分。分數：嚴重 10、高 5、中 2、低 1。", "",
                  "| 對象 | Tier0 | 分數 | 最高嚴重度 | 相關發現 |", "|---|---|---|---|---|"]
        for h in doc["hotspots"]:
            rel = "、".join(f"{fid} {rid}" for fid, rid in zip(h["findings"], h["rules"]))
            lines.append(f"| {_md_escape(h['label'])} | {'是' if h['tier0'] else ''} | {h['score']} | "
                         f"{SEV_LABEL[h['maxSeverity']]} | {_md_escape(rel)} |")
    ap = doc.get("attackPaths")
    if ap and ap.get("entries"):
        lines += ["", "## 攻擊路徑（到 Tier0 的最短路徑）", "",
                  f"啟用中的帳號有 {ap['accountsWithPath']}/{ap['accountsTotal']} 個有通往 Tier0 的路徑。"
                  "起點是實際持有第一個可濫用權限的主體；「影響帳號」是透過群組成員關係共用這條路徑的帳號數。"
                  "每個起點只列最短的一條，切斷後可能仍有較長的替代路徑。", "",
                  "| 起點 | 廣泛群組 | 步數 | 影響帳號 | 路徑 |", "|---|---|---|---|---|"]
        for e in ap["entries"][:MD_AFFECTED_LIMIT]:
            lines.append(f"| {_md_escape(e['label'])} | {'是' if e['broad'] else ''} | {e['hops']} | {e['exposedAccounts']} | "
                         f"{_md_escape(e['path'])} |")
        if ap["entriesTotal"] > MD_AFFECTED_LIMIT:
            lines.append(f"| …另 {ap['entriesTotal'] - MD_AFFECTED_LIMIT} 個起點（見 findings.json / graph.sqlite） | | | | |")
        if ap.get("chokepoints"):
            lines += ["", "優先切斷（最多帳號的路徑經過的步驟）：", ""]
            for i, c in enumerate(ap["chokepoints"], 1):
                lines.append(f"{i}. {_md_escape(c['fromLabel'])} →[{c['action']}]→ {_md_escape(c['toLabel'])}（{c['accounts']} 個帳號）")
    lines += ["", "| # | 嚴重度 | 規則 | 標題 | 數量 |", "|---|---|---|---|---|"]
    for f in doc["findings"]:
        lines.append(f"| {f['findingId']} | {SEV_LABEL[f['severity']]} | {f['ruleId']} | {_md_escape(f['title'])} | {f['count']} |")
    lines += ["", "## 發現", ""]
    for f in doc["findings"]:
        lines.append(f"### {f['findingId']}【{SEV_LABEL[f['severity']]}】{f['ruleId']} {f['title']}")
        lines.append("")
        lines.append(f["summary"])
        if f.get("attack"):
            lines.append(f"\nATT&CK：{', '.join(f['attack'])}")
        if f["affected"]:
            lines += ["", "| 對象 | 類型 | 細節 |", "|---|---|---|"]
            for a in f["affected"][:MD_AFFECTED_LIMIT]:
                lines.append(f"| {_md_escape(a.get('label'))} | {a.get('kind')} | {_md_escape(_fmt_detail(a.get('detail')))} |")
            if len(f["affected"]) > MD_AFFECTED_LIMIT:
                lines.append(f"| …另 {len(f['affected']) - MD_AFFECTED_LIMIT} 筆（見 findings.json） | | |")
        lines += ["", f"**修補建議：** {f['remediation']}", ""]
    if doc.get("accepted"):
        lines += ["## 已接受的例外", "", "| 規則 | 嚴重度 | 對象 | 理由 | 負責人 | 到期 |", "|---|---|---|---|---|---|"]
        for a in doc["accepted"]:
            x = a["exception"]
            objs = "、".join(str(o.get("label")) for o in a["affected"]) or "（整條規則）"
            lines.append(f"| {a['ruleId']} | {SEV_LABEL[a['severity']]} | {_md_escape(objs)} | {_md_escape(x.get('reason'))} | "
                         f"{_md_escape(x.get('owner') or '')} | {x.get('expires') or ''} |")
        lines.append("")
    lines += ["## 規則執行狀態", "", "| 規則 | 標題 | 狀態 | 說明 |", "|---|---|---|---|"]
    for rr in doc["rules"]:
        reason = (rr.get("reason") or "").split("\n")[0]
        lines.append(f"| {rr['ruleId']} | {_md_escape(rr['title'])} | {STATUS_LABEL[rr['status']]} | {_md_escape(reason)} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_sqlite(ctx, doc: dict[str, Any], path: Path) -> None:
    if path.exists():
        path.unlink()
    con = sqlite3.connect(str(path))
    try:
        con.executescript("""
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE nodes(id TEXT PRIMARY KEY, kind TEXT, label TEXT, tier0 INTEGER, props TEXT);
            CREATE TABLE edges(src TEXT, dst TEXT, kind TEXT, props TEXT);
            CREATE TABLE findings(finding_id TEXT PRIMARY KEY, rule_id TEXT, severity TEXT, title TEXT, count INTEGER, data TEXT);
            CREATE TABLE affected(finding_id TEXT, node_id TEXT, label TEXT, detail TEXT);
            CREATE TABLE rules(rule_id TEXT PRIMARY KEY, title TEXT, category TEXT, status TEXT, reason TEXT);
            CREATE TABLE attack_steps(src TEXT, dst TEXT, kind TEXT, cost REAL, note TEXT);
            CREATE TABLE attack_targets(node_id TEXT PRIMARY KEY, reason TEXT);
            CREATE TABLE attack_paths(entry_id TEXT PRIMARY KEY, entry_label TEXT, broad INTEGER, hops INTEGER, cost REAL,
                                      exposed_accounts INTEGER, target_id TEXT, target_label TEXT, path TEXT, steps TEXT);
        """)
        meta = {"schema": doc["schema"], "asOfUtc": doc["asOfUtc"], "generatedUtc": doc["generatedUtc"],
                "scope": json.dumps(doc["scope"], ensure_ascii=False), "bundles": json.dumps(doc["bundles"], ensure_ascii=False)}
        con.executemany("INSERT INTO meta VALUES(?,?)", meta.items())
        con.executemany("INSERT INTO nodes VALUES(?,?,?,?,?)", [
            (n["id"], n["kind"], n.get("label"), 1 if n.get("tier0") else 0,
             json.dumps({k: v for k, v in n.items() if k not in ("id", "kind", "label", "tier0")}, ensure_ascii=False, default=str))
            for n in ctx.graph.nodes.values()])
        con.executemany("INSERT INTO edges VALUES(?,?,?,?)", [
            (e.src, e.dst, e.kind, json.dumps(e.props, ensure_ascii=False, default=str)) for e in ctx.graph.edges])
        con.executemany("INSERT INTO findings VALUES(?,?,?,?,?,?)", [
            (f["findingId"], f["ruleId"], f["severity"], f["title"], f["count"], json.dumps(f, ensure_ascii=False, default=str))
            for f in doc["findings"]])
        con.executemany("INSERT INTO affected VALUES(?,?,?,?)", [
            (f["findingId"], a.get("id"), a.get("label"), json.dumps(a.get("detail"), ensure_ascii=False, default=str))
            for f in doc["findings"] for a in f["affected"]])
        con.executemany("INSERT INTO rules VALUES(?,?,?,?,?)", [
            (r["ruleId"], r["title"], r["category"], r["status"], r.get("reason")) for r in doc["rules"]])
        res = getattr(ctx, "_attack_paths", None) or {}
        con.executemany("INSERT INTO attack_paths VALUES(?,?,?,?,?,?,?,?,?,?)", [
            (e["id"], e["label"], 1 if e["broad"] else 0, e["hops"], e["cost"], e["exposedAccounts"], e["target"],
             e["targetLabel"], e["path"], json.dumps(e["steps"], ensure_ascii=False)) for e in res.get("entries", [])])
        stored = getattr(ctx, "_attack_graph", None)
        if stored is not None:
            ag = stored[0]
            con.executemany("INSERT INTO attack_steps VALUES(?,?,?,?,?)", [
                (src, dst, kind, cost, note) for dst, steps in ag.rev.items() for src, kind, cost, note in steps])
            con.executemany("INSERT INTO attack_targets VALUES(?,?)", list(ag.targets.items()))
        con.executescript("""
            CREATE INDEX attack_steps_dst ON attack_steps(dst);
            CREATE INDEX edges_src ON edges(src, kind);
            CREATE INDEX edges_dst ON edges(dst, kind);
            CREATE INDEX nodes_kind ON nodes(kind);
        """)
        con.commit()
    finally:
        con.close()
