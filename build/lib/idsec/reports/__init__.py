"""評估報告解析與優先排序。"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, PathAnalysis
from .pingcastle import parse_pingcastle

PARSERS = {"ad_hc_*.xml": parse_pingcastle}

SEVERITY_WEIGHT = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 0}
# 與攻擊路徑邊相關的發現，若圖譜中確實存在該類邊，提高優先序
EDGE_FOR_ATTACK = {
    "T1649": "ADCSESC1",          # AD CS 憑證濫用
    "T1003.006": "DCSync",
    "T1484": "GenericAll",
    "T1550": "HasSession",
}


def load_findings(reports_dir: Path | None) -> list[Finding]:
    if reports_dir is None or not reports_dir.exists():
        return []
    findings: list[Finding] = []
    for pattern, parser in PARSERS.items():
        for f in sorted(reports_dir.glob(pattern)):
            findings += parser(f)
    return findings


def prioritize(findings: list[Finding], paths: PathAnalysis | None) -> list[Finding]:
    """確定性排序：嚴重度 + 是否落在實際存在的攻擊路徑上 + 點數。"""
    edge_kinds = set()
    if paths:
        edge_kinds = {h.kind for p in paths.sample_paths for h in p.hops} | {c.edge.kind for c in paths.choke_points}
    for f in findings:
        score = SEVERITY_WEIGHT[f.severity] + min(f.points, 50) * 0.2
        reasons = [f"嚴重度 {f.severity}"]
        on_path = [t for t in f.attack if EDGE_FOR_ATTACK.get(t) in edge_kinds]
        if on_path:
            score += 25
            reasons.append(f"對應技術 {', '.join(on_path)} 出現在通往 Tier 0 的路徑上")
        f.priority = round(score, 1)
        f.priority_reason = "；".join(reasons)
    return sorted(findings, key=lambda f: (-f.priority, f.id))
