"""MCP Server 與 Agent 共用的快取查詢層（全部唯讀）。"""

from __future__ import annotations

from functools import lru_cache

import networkx as nx

from .backends import Backend, get_backend
from .capability import apply_matrix, load_matrix
from .config import Settings, load_settings
from .discovery import build_fingerprint
from .models import CapabilityResult, Finding, Fingerprint, IdentityGraph, PathAnalysis
from .paths import analyze_paths
from .reports import load_findings, prioritize


@lru_cache(maxsize=1)
def settings() -> Settings:
    return load_settings()


@lru_cache(maxsize=32)
def backend(entity: str) -> Backend:
    return get_backend(settings().entity(entity))


@lru_cache(maxsize=32)
def fingerprint(entity: str) -> Fingerprint:
    return build_fingerprint(entity, backend(entity))


@lru_cache(maxsize=32)
def capability(entity: str) -> CapabilityResult:
    return apply_matrix(fingerprint(entity), load_matrix(settings().resolve(settings().capability_matrix)))


@lru_cache(maxsize=32)
def graph(entity: str) -> IdentityGraph:
    g = backend(entity).identity_graph()
    if "paths_entra" not in capability(entity).enabled_modules:
        g.nodes = [n for n in g.nodes if not n.kind.startswith("AZ")]
    return g


@lru_cache(maxsize=32)
def path_analysis(entity: str) -> PathAnalysis:
    return analyze_paths(entity, graph(entity))


@lru_cache(maxsize=32)
def findings(entity: str) -> tuple[Finding, ...]:
    ent = settings().entity(entity)
    pa = path_analysis(entity) if "paths_ad" in capability(entity).enabled_modules else None
    return tuple(prioritize(load_findings(ent.path(ent.reports_dir)), pa))


@lru_cache(maxsize=32)
def nx_graph(entity: str) -> tuple[nx.MultiDiGraph, dict[str, str]]:
    g = nx.MultiDiGraph()
    names: dict[str, str] = {}
    ig = graph(entity)
    for n in ig.nodes:
        g.add_node(n.id, kind=n.kind, name=n.name, tier0=n.tier0, enabled=n.enabled)
        names[n.id] = n.name
    for e in ig.edges:
        if e.src in g and e.dst in g:
            g.add_edge(e.src, e.dst, key=e.kind)
    return g, names


def resolve_node(entity: str, name: str) -> list[str]:
    """以名稱（不分大小寫、可含 @ 網域）找節點 id。"""
    g, names = nx_graph(entity)
    key = name.strip().lower()
    exact = [i for i, n in names.items() if n.lower() == key]
    return exact or [i for i, n in names.items() if key in n.lower()][:10]


def clear_caches() -> None:
    for fn in (settings, backend, fingerprint, capability, graph, path_analysis, findings, nx_graph):
        fn.cache_clear()
