"""Phase 1：攻擊路徑分析（確定性）。

- 來源：啟用中、且本身不屬於 Tier 0 的使用者（地端與雲端）。
- 目標：圖譜中標記為 Tier 0 的節點。
- 瓶頸點：實際移除某條邊後重算，能切斷最多來源者優先。
"""

from __future__ import annotations

from collections import Counter, defaultdict

import networkx as nx

from .models import AttackPath, ChokePoint, GraphEdge, IdentityGraph, PathAnalysis

SINK = "__TIER0__"
SOURCE_KINDS = {"User", "AZUser"}
# 只靠這些邊就到得了 Tier 0 的帳號，本身就是 Tier 0 成員，不算攻擊來源
MEMBERSHIP_EDGES = {"MemberOf", "AZHasRole"}


def _build(graph: IdentityGraph) -> tuple[nx.MultiDiGraph, set[str]]:
    g = nx.MultiDiGraph()
    for n in graph.nodes:
        g.add_node(n.id, kind=n.kind, name=n.name, tier0=n.tier0, enabled=n.enabled)
    for e in graph.edges:
        if e.src in g and e.dst in g:
            g.add_edge(e.src, e.dst, key=e.kind, kind=e.kind)
    tier0 = {n.id for n in graph.nodes if n.tier0}
    for t in tier0:
        g.add_edge(t, SINK, key="Tier0", kind="Tier0")
    return g, tier0


def _membership_only_tier0(g: nx.MultiDiGraph, tier0: set[str]) -> set[str]:
    sub = nx.DiGraph()
    sub.add_nodes_from(g.nodes)
    sub.add_edges_from((u, v) for u, v, k in g.edges(keys=True) if k in MEMBERSHIP_EDGES)
    members: set[str] = set()
    for t in tier0:
        members |= nx.ancestors(sub, t)
    return members


def _reachable(g: nx.MultiDiGraph, sources: set[str]) -> set[str]:
    return nx.ancestors(g, SINK) & sources


def _edge_of(g: nx.MultiDiGraph, u: str, v: str) -> GraphEdge:
    # 兩節點間有多條邊時取一條代表；排序讓結果穩定
    kind = sorted(g[u][v].keys())[0]
    return GraphEdge(src=u, dst=v, kind=kind)


def _shortest(g: nx.MultiDiGraph, sources: set[str]) -> dict[str, list[GraphEdge]]:
    """反向 BFS：從 SINK 回推每個可達來源的一條最短路徑。"""
    pred_paths = nx.single_source_shortest_path(g.reverse(copy=False), SINK)
    out: dict[str, list[GraphEdge]] = {}
    for s in sorted(sources):
        if s in pred_paths:
            nodes = list(reversed(pred_paths[s]))[:-1]  # 去掉 SINK
            out[s] = [_edge_of(g, a, b) for a, b in zip(nodes, nodes[1:])]
    return out


def _best_cut(g: nx.MultiDiGraph, sources: set[str], tier0: set[str], shortest: dict[str, list[GraphEdge]],
              candidate_limit: int) -> tuple[tuple[str, str, str], frozenset] | None:
    """在目前最短路徑上找移除後切斷最多來源的邊（實際移除後重算）。"""
    freq: Counter = Counter()
    for hops in shortest.values():
        for h in hops:
            if not (h.src in tier0 and h.dst in tier0):
                freq[(h.src, h.dst, h.kind)] += 1
    reach = set(shortest)
    best = None
    for (u, v, k), _ in freq.most_common(candidate_limit):
        data = g.get_edge_data(u, v, key=k)
        g.remove_edge(u, v, key=k)
        cut = frozenset(reach - _reachable(g, sources))
        g.add_edge(u, v, key=k, **data)
        if best is None or len(cut) > len(best[1]):
            best = ((u, v, k), cut)
    return best


def analyze_paths(entity: str, graph: IdentityGraph, max_samples: int = 8, max_choke: int = 5,
                  candidate_limit: int = 15) -> PathAnalysis:
    g, tier0 = _build(graph)
    # 特權成員（例如 Domain Admins 的帳號）本身就是 Tier 0：拿到它等於拿到 Tier 0
    privileged = _membership_only_tier0(g, tier0) - tier0
    for p in privileged:
        g.add_edge(p, SINK, key="Tier0", kind="Tier0")
    tier0 = tier0 | privileged
    sources = {n for n, d in g.nodes(data=True)
               if d.get("kind") in SOURCE_KINDS and d.get("enabled") and n not in tier0}

    shortest = _shortest(g, sources)
    before = len(shortest)

    # 依「第一跳之後的路徑」分組，挑代表路徑
    groups: dict[tuple, list[str]] = defaultdict(list)
    for s, hops in shortest.items():
        groups[tuple((h.src, h.dst, h.kind) for h in hops[1:])].append(s)
    samples = []
    for _, members in sorted(groups.items(), key=lambda kv: (-len(kv[1]), len(kv[0])))[:max_samples]:
        rep = sorted(members)[0]
        hops = shortest[rep]
        samples.append(AttackPath(source=rep, target=hops[-1].dst if hops else rep, hops=hops,
                                  shared_by=len(members)))

    # 瓶頸點（貪婪修補順序）：每輪移除最有效的一條邊，再對剩下的路徑重算
    work = g.copy()
    chokes: list[ChokePoint] = []
    current = shortest
    for _ in range(max_choke):
        found = _best_cut(work, sources, tier0, current, candidate_limit)
        if not found or len(found[1]) < 2:  # 只切得斷單一帳號的邊不算瓶頸
            break
        (u, v, k), cut = found
        work.remove_edge(u, v, key=k)
        current = _shortest(work, sources)
        chokes.append(ChokePoint(edge=GraphEdge(src=u, dst=v, kind=k), sources_cut=len(cut),
                                 sources_cut_pct=round(len(cut) / before * 100, 1),
                                 remaining_after=len(current)))

    used = {n for p in samples for h in p.hops for n in (h.src, h.dst)} | \
           {n for c in chokes for n in (c.edge.src, c.edge.dst)}
    return PathAnalysis(
        entity=entity,
        tier0_nodes=sorted(tier0),
        sources_total=len(sources),
        sources_with_path=before,
        sample_paths=samples,
        choke_points=chokes,
        node_names={n: g.nodes[n].get("name", n) for n in used},
    )
