"""Minimal directed property graph (stdlib only).

Node ids
    AD principals            SID ("S-1-5-21-...-1105"); the domain object uses the domain SID
    other AD objects         "dn:" + lower-case DN (OU, container, CA, certificate template, unknown DN)
    GPO                      "gpo:" + lower-case GUID
    Entra directory objects  "entra:" + objectId (users, groups, service principals, applications)
    Entra directory roles    "entra-role:" + roleDefinitionId
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable, Iterator


class Edge:
    __slots__ = ("src", "dst", "kind", "props")

    def __init__(self, src: str, dst: str, kind: str, props: dict[str, Any]) -> None:
        self.src, self.dst, self.kind, self.props = src, dst, kind, props

    def __repr__(self) -> str:
        return f"Edge({self.src} -[{self.kind}]-> {self.dst})"


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.out: dict[str, list[Edge]] = defaultdict(list)
        self.inc: dict[str, list[Edge]] = defaultdict(list)
        self._index: dict[tuple[str, str, str], Edge] = {}

    # -- construction -------------------------------------------------------------------------
    def add_node(self, nid: str, kind: str, label: str | None = None, **props: Any) -> dict[str, Any]:
        node = self.nodes.get(nid)
        if node is None:
            node = {"id": nid, "kind": kind, "label": label or nid}
            self.nodes[nid] = node
        else:
            if node["kind"] == "unknown" and kind != "unknown":
                node["kind"] = kind
            if label and node["label"] == nid:
                node["label"] = label
        for k, v in props.items():
            if v is not None and (k not in node or node[k] in (None, "", [])):
                node[k] = v
        return node

    def add_edge(self, src: str, dst: str, kind: str, **props: Any) -> Edge:
        if src not in self.nodes:
            self.add_node(src, "unknown")
        if dst not in self.nodes:
            self.add_node(dst, "unknown")
        key = (src, dst, kind)
        edge = self._index.get(key)
        if edge is None:
            edge = Edge(src, dst, kind, dict(props))
            self._index[key] = edge
            self.out[src].append(edge)
            self.inc[dst].append(edge)
        else:
            for k, v in props.items():
                if k not in edge.props:
                    edge.props[k] = v
                elif isinstance(edge.props[k], list) and isinstance(v, list):
                    edge.props[k] = sorted(set(edge.props[k]) | set(v))
        return edge

    # -- queries ------------------------------------------------------------------------------
    @property
    def edges(self) -> Iterator[Edge]:
        return iter(self._index.values())

    def kind(self, nid: str) -> str:
        return self.nodes.get(nid, {}).get("kind", "unknown")

    def label(self, nid: str) -> str:
        return self.nodes.get(nid, {}).get("label", nid)

    def edges_out(self, nid: str, kinds: Iterable[str] | None = None) -> list[Edge]:
        ks = set(kinds) if kinds is not None else None
        return [e for e in self.out.get(nid, []) if ks is None or e.kind in ks]

    def edges_in(self, nid: str, kinds: Iterable[str] | None = None) -> list[Edge]:
        ks = set(kinds) if kinds is not None else None
        return [e for e in self.inc.get(nid, []) if ks is None or e.kind in ks]

    def members(self, group: str, kinds: Iterable[str] = ("MemberOf",)) -> set[str]:
        """Transitive members of *group* (following member -[MemberOf]-> group backwards)."""
        ks = set(kinds)
        seen: set[str] = set()
        queue = deque([group])
        while queue:
            g = queue.popleft()
            for e in self.inc.get(g, []):
                if e.kind in ks and e.src not in seen:
                    seen.add(e.src)
                    queue.append(e.src)
        seen.discard(group)
        return seen

    def memberships(self, nid: str, kinds: Iterable[str] = ("MemberOf",)) -> set[str]:
        """Transitive groups *nid* belongs to."""
        ks = set(kinds)
        seen: set[str] = set()
        queue = deque([nid])
        while queue:
            n = queue.popleft()
            for e in self.out.get(n, []):
                if e.kind in ks and e.dst not in seen:
                    seen.add(e.dst)
                    queue.append(e.dst)
        seen.discard(nid)
        return seen

    def stats(self) -> dict[str, Any]:
        nk: dict[str, int] = defaultdict(int)
        ek: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            nk[n["kind"]] += 1
        for e in self._index.values():
            ek[e.kind] += 1
        return {"nodes": len(self.nodes), "edges": len(self._index),
                "nodeKinds": dict(sorted(nk.items())), "edgeKinds": dict(sorted(ek.items()))}
