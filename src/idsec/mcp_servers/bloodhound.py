"""MCP：bloodhound（唯讀）——攻擊路徑摘要、指定帳號的路徑、誰能到達某節點、唯讀 Cypher。

權限圖譜不整包回傳給模型，只回傳彙總與指定查詢的結果。
"""

from __future__ import annotations

import os
import re

import networkx as nx

from .. import services
from ._common import READ_ONLY, audited, create_server

NAME = "bloodhound"
server = create_server(NAME, "唯讀查詢身分攻擊路徑：摘要、建議修補順序、指定帳號路徑、反向可達分析。不提供任何寫入功能。")

WRITE_CYPHER = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|FOREACH|CALL\s+(dbms|db\.(create|drop)|apoc))\b",
    re.IGNORECASE)
MAX_ROWS = 200


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def path_summary(entity: str) -> dict:
    """通往 Tier 0 的路徑摘要：來源數、可達數、代表路徑、建議修補順序（每步實際移除後重算）。"""
    p = services.path_analysis(entity)
    return {
        "sources_total": p.sources_total,
        "sources_with_path": p.sources_with_path,
        "remediation_order": [
            {"step": i, "edge": f"{p.name(c.edge.src)} -[{c.edge.kind}]-> {p.name(c.edge.dst)}",
             "sources_cut": c.sources_cut, "pct": c.sources_cut_pct, "remaining_after": c.remaining_after}
            for i, c in enumerate(p.choke_points, 1)],
        "sample_paths": [{"shared_by": a.shared_by, "path": p.describe(a)} for a in p.sample_paths],
    }


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def path_from_principal(entity: str, principal: str) -> dict:
    """指定帳號（名稱）到最近 Tier 0 的最短路徑；找不到路徑時回傳空。"""
    g, names = services.nx_graph(entity)
    ids = services.resolve_node(entity, principal)
    if not ids:
        return {"found": False, "message": f"找不到名稱含 {principal!r} 的節點"}
    tier0 = {n for n, d in g.nodes(data=True) if d.get("tier0")}
    results = []
    for src in ids[:5]:
        best = None
        for t in tier0:
            try:
                path = nx.shortest_path(g, src, t)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if best is None or len(path) < len(best):
                best = path
        if best:
            hops = [f"{names[a]} -[{sorted(g[a][b].keys())[0]}]-> {names[b]}" for a, b in zip(best, best[1:])]
            results.append({"principal": names[src], "hops": hops, "length": len(hops)})
        else:
            results.append({"principal": names[src], "hops": [], "length": 0})
    return {"found": True, "results": results}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def who_can_reach(entity: str, target: str, limit: int = 50) -> dict:
    """反向分析：有哪些啟用中的使用者能到達指定節點（例如 SRV-AADC01、Domain Admins）。"""
    g, names = services.nx_graph(entity)
    ids = services.resolve_node(entity, target)
    if not ids:
        return {"found": False, "message": f"找不到名稱含 {target!r} 的節點"}
    tgt = ids[0]
    users = sorted(names[n] for n in nx.ancestors(g, tgt)
                   if g.nodes[n].get("kind") in {"User", "AZUser"} and g.nodes[n].get("enabled"))
    return {"found": True, "target": names[tgt], "users_count": len(users), "users": users[:max(1, min(limit, MAX_ROWS))]}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def run_readonly_cypher(entity: str, query: str) -> dict:
    """在 BloodHound CE 的 Neo4j 執行唯讀 Cypher（僅 live 且已設定 neo4j 時可用）。含寫入關鍵字一律拒絕。"""
    if WRITE_CYPHER.search(query):
        raise PermissionError("查詢含寫入或管理關鍵字，已拒絕")
    ent = services.settings().entity(entity)
    if ent.backend != "live" or ent.neo4j is None:
        raise RuntimeError("此法人未連接 BloodHound Neo4j（mock 模式請改用 path_summary / who_can_reach）")
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(ent.neo4j.uri, auth=(ent.neo4j.user, os.environ.get(ent.neo4j.password_env, "")))
    try:
        with driver.session(default_access_mode="READ") as s:
            rows = [r.data() for r in s.run(query).fetch(MAX_ROWS)]
    finally:
        driver.close()
    return {"rows": rows, "truncated": len(rows) >= MAX_ROWS}


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
