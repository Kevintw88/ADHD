"""MCP：assessment-reports（唯讀）——評估工具發現，已正規化並依攻擊路徑排序。"""

from __future__ import annotations

from .. import services
from ._common import READ_ONLY, audited, create_server

NAME = "assessment-reports"
server = create_server(NAME, "唯讀查詢 PingCastle 等評估工具的發現，已正規化並依是否落在攻擊路徑上排序。不提供任何寫入功能。")
ORDER = ["critical", "high", "medium", "low", "info"]


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_findings(entity: str, min_severity: str = "low", limit: int = 20) -> dict:
    """依優先序列出發現。min_severity：critical / high / medium / low / info。"""
    if min_severity not in ORDER:
        raise ValueError(f"min_severity 需為 {ORDER}")
    keep = set(ORDER[: ORDER.index(min_severity) + 1])
    rows = [f.model_dump(exclude={"rationale"}) for f in services.findings(entity) if f.severity in keep]
    return {"total": len(rows), "findings": rows[: max(1, min(limit, 100))]}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def get_finding(entity: str, finding_id: str) -> dict:
    """取得單一發現的完整內容（含評估工具原始說明）。"""
    for f in services.findings(entity):
        if f.id == finding_id:
            return f.model_dump()
    raise KeyError(f"找不到發現 {finding_id}")


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def findings_by_attack_technique(entity: str, technique: str) -> dict:
    """依 MITRE ATT&CK 技術代號（例如 T1649、T1558.003）篩選發現。"""
    rows = [f.model_dump(exclude={"rationale"}) for f in services.findings(entity)
            if any(a == technique or a.startswith(technique + ".") for a in f.attack)]
    return {"technique": technique, "count": len(rows), "findings": rows}


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
