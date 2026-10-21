"""Check a model-written report against the deterministic analysis (lab side, no model needed).

The agent's report is only useful if every claim traces back to a finding.  This module checks, from
findings.json and graph.sqlite alone:

    citations      every [F###] exists, and when written together with a rule id ("F003 / AD-021") the pair matches
    coverage       every critical / high finding is cited (high: reported as a share, critical: required)
    names          every pseudonym (u-xxxxxxxxxxxx) and SID in the report exists in the analysed graph
    not assessed   skipped rules are not described as passed, and the report says what was not assessed
    uncited        paragraphs that state a risk without citing any finding

and returns issues the agent can fix in a revision round (evaluator-optimizer).
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

_FID = re.compile(r"\bF\d{3,4}\b")
_RID = re.compile(r"\b(?:AD|ADCS|EN|HY|PATH)-\d{3}\b")
_PAIR = re.compile(r"\b(F\d{3,4})\b\s*[/／|｜,，、]?\s*\b((?:AD|ADCS|EN|HY|PATH)-\d{3})\b")
_PSEUDO = re.compile(r"\bu-[0-9a-f]{12}\b")
_SID = re.compile(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b")
_PASSED = re.compile(r"通過|沒有問題|無問題|未發現|安全無虞|passed|no issues?", re.IGNORECASE)
_RISKY = re.compile(r"風險|弱點|可被|攻擊|入侵|權限過高|提權|外洩|critical|嚴重")
_NOT_ASSESSED = re.compile(r"未評估|未能評估|無法評估|資料不足|略過|not assessed|skipped", re.IGNORECASE)


def load_truth(report_dir: Path) -> dict[str, Any]:
    report_dir = Path(report_dir)
    doc = json.loads((report_dir / "findings.json").read_text(encoding="utf-8"))
    labels: set[str] = set()
    ids: set[str] = set()
    db = report_dir / "graph.sqlite"
    if db.is_file():
        con = sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro", uri=True)
        try:
            for nid, label in con.execute("SELECT id, label FROM nodes"):
                ids.add(str(nid))
                labels.add(str(label or ""))
        finally:
            con.close()
    known_pseudo = {m for text in labels | ids for m in _PSEUDO.findall(text)}
    for f in doc.get("findings", []):   # affected labels that never became graph nodes (e.g. Entra Connect detail)
        for a in f.get("affected", []):
            known_pseudo |= set(_PSEUDO.findall(json.dumps(a, ensure_ascii=False)))
    return {"doc": doc, "findings": {f["findingId"]: f for f in doc.get("findings", [])},
            "skipped": {r["ruleId"] for r in doc.get("rules", []) if r["status"] == "skipped"},
            "pseudonyms": known_pseudo, "sids": {i for i in ids if i.startswith("S-1-")}}


def _paragraphs(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n\s*\n|\n(?=#|\s*[-*]\s|\s*\d+\.\s)", text) if p.strip()]


def check(report: str, truth: dict[str, Any]) -> dict[str, Any]:
    findings = truth["findings"]
    issues: list[dict[str, Any]] = []
    cited = set(_FID.findall(report))
    for fid in sorted(cited - set(findings)):
        issues.append({"type": "unknown_finding", "severity": "error", "detail": f"{fid} 不存在於 findings.json"})
    for fid, rid in _PAIR.findall(report):
        if fid in findings and findings[fid]["ruleId"] != rid:
            issues.append({"type": "wrong_rule", "severity": "error",
                           "detail": f"{fid} 是 {findings[fid]['ruleId']}，報告寫成 {rid}"})
    for rid in sorted(set(_RID.findall(report))):
        if rid not in {f["ruleId"] for f in findings.values()} and rid not in truth["skipped"] and \
                rid not in {r["ruleId"] for r in truth["doc"].get("rules", [])}:
            issues.append({"type": "unknown_rule", "severity": "error", "detail": f"{rid} 不是已知的規則"})

    crit = [f for f in findings.values() if f["severity"] == "critical"]
    high = [f for f in findings.values() if f["severity"] == "high"]
    missing_crit = [f["findingId"] for f in crit if f["findingId"] not in cited]
    if missing_crit:
        issues.append({"type": "missing_critical", "severity": "error",
                       "detail": "未引用的嚴重發現：" + "、".join(missing_crit)})
    high_cov = (sum(1 for f in high if f["findingId"] in cited) / len(high)) if high else 1.0

    for p in sorted(set(_PSEUDO.findall(report)) - truth["pseudonyms"]):
        issues.append({"type": "unknown_name", "severity": "error", "detail": f"{p} 不存在於分析資料（可能是捏造的帳號）"})
    for s in sorted(set(_SID.findall(report))):
        if truth["sids"] and s not in truth["sids"] and not any(x.startswith(s + "-") for x in truth["sids"]):
            issues.append({"type": "unknown_sid", "severity": "error", "detail": f"{s} 不存在於分析資料"})

    for p in _paragraphs(report):
        for rid in set(_RID.findall(p)) & truth["skipped"]:
            if _PASSED.search(p) and not _NOT_ASSESSED.search(p):
                issues.append({"type": "skipped_as_passed", "severity": "error",
                               "detail": f"{rid} 因資料不足未評估，報告卻描述為通過：{p[:80]}"})
    if truth["skipped"] and not _NOT_ASSESSED.search(report):
        issues.append({"type": "no_scope_note", "severity": "warning",
                       "detail": f"有 {len(truth['skipped'])} 條規則未評估，報告沒有說明未評估的範圍"})
    uncited = [p for p in _paragraphs(report) if _RISKY.search(p) and not _FID.search(p) and len(p) > 40
               and not p.startswith("#") and not _NOT_ASSESSED.search(p)]
    for p in uncited[:10]:
        issues.append({"type": "uncited_claim", "severity": "warning", "detail": f"描述風險但未引用發現：{p[:80]}"})

    errors = sum(1 for i in issues if i["severity"] == "error")
    return {
        "passed": errors == 0,
        "errors": errors, "warnings": len(issues) - errors,
        "citedFindings": len(cited & set(findings)), "findingsTotal": len(findings),
        "criticalCoverage": f"{len(crit) - len(missing_crit)}/{len(crit)}",
        "highCoverage": round(high_cov, 2),
        "issues": issues,
    }


def feedback(result: dict[str, Any]) -> str:
    """Issues as an instruction for a revision round."""
    lines = ["檢查結果發現以下問題，請修正後輸出完整的新版報告（只能使用工具查得的資料，不要新增沒有依據的內容）："]
    for i in result["issues"]:
        lines.append(f"- [{i['type']}] {i['detail']}")
    return "\n".join(lines)
