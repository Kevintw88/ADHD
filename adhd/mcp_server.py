"""Read-only MCP server over one analysis output (findings.json + graph.sqlite).

Standard library only, speaks MCP over stdio (newline-delimited JSON-RPC 2.0), so it runs on the
air-gapped analysis host next to a local model.  It never touches the raw collection bundles: the
model sees what the deterministic analysis produced (pseudonymised labels, findings with evidence,
the graph and the attack steps), and can query it, but cannot change anything.

    python3 tools/mcp_server.py /srv/adhd/reports/SubA-20261020

Tools: get_overview, list_findings, get_finding, list_rules, get_hotspots, search_nodes, get_node,
get_edges, list_attack_paths, path_to_tier0, who_can_reach.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

from . import __version__, known
from .paths import AttackGraph, hops, path_from, reach, render, shortest
from .rules import SEVERITY_RANK

SERVER_NAME = "adhd"
PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
MAX_TEXT = 60_000          # characters of JSON per tool result before lists are cut
INSTRUCTIONS = (
    "Read-only access to one ADHD assessment of an AD + Entra ID hybrid environment. "
    "Findings come from deterministic rules with evidence; report them, do not invent new ones. "
    "Account names are pseudonyms (u-xxxxxxxxxxxx) and must be kept as they are. "
    "Cite findingId and ruleId for every claim. Rules with status 'skipped' were NOT assessed: never call them passed. "
    "Attack paths are the cheapest route per principal; longer alternative routes may exist. "
    "Start with get_overview, then list_findings / get_finding; use search_nodes to turn a name into a node id "
    "before get_node, path_to_tier0 or who_can_reach."
)


class ToolError(Exception):
    """A tool could not answer (bad argument, unknown node): reported to the model as isError content."""


# ===========================================================================================
class Store:
    def __init__(self, report_dir: Path) -> None:
        self.dir = Path(report_dir)
        fj = self.dir / "findings.json"
        db = self.dir / "graph.sqlite"
        if not fj.is_file() or not db.is_file():
            raise FileNotFoundError(f"{self.dir} 需要 findings.json 與 graph.sqlite（tools/analyze.py 的輸出）")
        self.doc: dict[str, Any] = json.loads(fj.read_text(encoding="utf-8"))
        self.con = sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro", uri=True, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.findings = {f["findingId"]: f for f in self.doc.get("findings", [])}
        self._nodes: dict[str, tuple[str, str, bool, bool]] | None = None
        self._ag: AttackGraph | None = None
        self._tier0_route: tuple[dict, dict] | None = None

    # -- graph view (label / kind / skip) used by the path functions --------------------------
    def _load_nodes(self) -> dict[str, tuple[str, str, bool, bool]]:
        if self._nodes is None:
            out = {}
            for r in self.con.execute("SELECT id, kind, label, tier0, props FROM nodes"):
                orphan = '"orphan": true' in (r["props"] or "")
                out[r["id"]] = (r["kind"], r["label"] or r["id"], bool(r["tier0"]), orphan)
            self._nodes = out
        return self._nodes

    def label(self, nid: str) -> str:
        n = self._load_nodes().get(nid)
        return n[1] if n else nid

    def kind(self, nid: str) -> str:
        n = self._load_nodes().get(nid)
        return n[0] if n else "unknown"

    def skip(self, nid: str) -> bool:
        n = self._load_nodes().get(nid)
        return nid in known.SAFE_ACL_PRINCIPALS or bool(n and n[3])

    def attack_graph(self) -> AttackGraph:
        if self._ag is None:
            ag = AttackGraph(None)
            if self._has_table("attack_steps"):
                for r in self.con.execute("SELECT src, dst, kind, cost, note FROM attack_steps"):
                    ag.rev[r["dst"]].append((r["src"], r["kind"], r["cost"], r["note"]))
                    ag.fwd[r["src"]].append((r["dst"], r["kind"], r["cost"], r["note"]))
                for r in self.con.execute("SELECT node_id, reason FROM attack_targets"):
                    ag.targets[r["node_id"]] = r["reason"]
            self._ag = ag
        return self._ag

    def _has_table(self, name: str) -> bool:
        return self.con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

    def resolve(self, query: str) -> str:
        nodes = self._load_nodes()
        q = str(query or "").strip()
        if not q:
            raise ToolError("node 不可為空")
        if q in nodes:
            return q
        ql = q.lower()
        exact = [n for n, v in nodes.items() if v[1].lower() == ql]
        if len(exact) == 1:
            return exact[0]
        cands = exact or [n for n, v in nodes.items() if ql in v[1].lower() or ql in n.lower()]
        if not cands:
            raise ToolError(f"找不到符合「{q}」的物件；請先用 search_nodes 查詢")
        if len(cands) == 1:
            return cands[0]
        shown = [{"id": n, "label": nodes[n][1], "kind": nodes[n][0]} for n in cands[:10]]
        raise ToolError(f"「{q}」符合 {len(cands)} 個物件，請改用其中一個 id：" + json.dumps(shown, ensure_ascii=False))

    def ref(self, nid: str) -> dict[str, Any]:
        n = self._load_nodes().get(nid)
        tier0 = bool(n and n[2]) or nid in self.attack_graph().targets   # incl. Entra Tier0, Entra Connect / CA hosts
        return {"id": nid, "label": n[1] if n else nid, "kind": n[0] if n else "unknown", "tier0": tier0}


# ===========================================================================================
def _limit(args: dict, default: int = 20, cap: int = 200) -> int:
    try:
        v = int(args.get("limit", default))
    except (TypeError, ValueError):
        raise ToolError("limit 必須是整數")
    return max(1, min(cap, v))


def _offset(args: dict) -> int:
    try:
        return max(0, int(args.get("offset", 0)))
    except (TypeError, ValueError):
        raise ToolError("offset 必須是整數")


def t_overview(st: Store, args: dict) -> dict:
    d = st.doc
    ap = d.get("attackPaths") or {}
    skipped = [r["ruleId"] for r in d.get("rules", []) if r["status"] == "skipped"]
    paths = None
    if ap:
        paths = {k: v for k, v in ap.items() if k not in ("entries", "chokepoints")}
        paths["topEntries"] = [{k: e[k] for k in ("id", "label", "broad", "hops", "exposedAccounts", "targetLabel", "path")}
                               for e in (ap.get("entries") or [])[:5]]
        paths["chokepoints"] = (ap.get("chokepoints") or [])[:5]
    return {
        "scope": d.get("scope"), "asOfUtc": d.get("asOfUtc"), "generatedUtc": d.get("generatedUtc"),
        "analyzer": d.get("analyzer"), "bundles": d.get("bundles"), "summary": d.get("summary"),
        "attackPaths": paths,
        "topHotspots": (d.get("hotspots") or [])[:5],
        "skippedRules": skipped,
        "note": "skippedRules 是因資料不足未評估的規則，不代表通過。",
    }


def t_list_findings(st: Store, args: dict) -> dict:
    sev = args.get("min_severity")
    if sev and sev not in SEVERITY_RANK:
        raise ToolError(f"min_severity 必須是 {list(SEVERITY_RANK)} 之一")
    rule = str(args.get("rule_id") or "").upper()
    cat = str(args.get("category") or "").lower()
    text = str(args.get("contains") or "").lower()
    rows = []
    for f in st.doc.get("findings", []):
        if sev and SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[sev]:
            continue
        if rule and not f["ruleId"].upper().startswith(rule):
            continue
        if cat and f["category"].lower() != cat:
            continue
        if text and text not in (f["title"] + f["summary"]).lower() and not any(
                text in str(a.get("label", "")).lower() or text == str(a.get("id", "")).lower() for a in f["affected"]):
            continue
        rows.append({k: f[k] for k in ("findingId", "ruleId", "severity", "category", "title", "count", "summary")})
    off, lim = _offset(args), _limit(args, 30)
    return {"total": len(rows), "offset": off, "findings": rows[off:off + lim]}


def t_get_finding(st: Store, args: dict) -> dict:
    fid = str(args.get("finding_id") or "").upper()
    f = st.findings.get(fid)
    if f is None:
        raise ToolError(f"沒有 {fid}；請用 list_findings 查詢 findingId")
    lim = _limit(args, 50, 500)
    out = dict(f)
    out["affected"] = f["affected"][:lim]
    if len(f["affected"]) > lim:
        out["affectedTruncated"] = len(f["affected"]) - lim
    return out


def t_list_rules(st: Store, args: dict) -> dict:
    status = args.get("status")
    rows = [r for r in st.doc.get("rules", []) if not status or r["status"] == status]
    return {"total": len(rows), "rules": rows,
            "statusMeaning": {"finding": "有發現", "pass": "資料完整且沒有發現", "skipped": "資料不足，未評估",
                              "error": "規則執行錯誤", "accepted": "發現全數為已接受例外"}}


def t_hotspots(st: Store, args: dict) -> dict:
    hs = st.doc.get("hotspots") or []
    return {"total": len(hs), "hotspots": hs[:_limit(args, 15, 50)]}


def t_search_nodes(st: Store, args: dict) -> dict:
    q = str(args.get("query") or "").strip().lower()
    kind = args.get("kind")
    tier0 = args.get("tier0")
    lim = _limit(args, 20, 100)
    out = []
    for nid, (k, label, t0, _orph) in st._load_nodes().items():
        if kind and k != kind:
            continue
        if tier0 is not None and bool(tier0) != t0:
            continue
        if q and q not in label.lower() and q not in nid.lower():
            continue
        out.append({"id": nid, "label": label, "kind": k, "tier0": t0})
    out.sort(key=lambda x: (x["label"].lower() != q, len(x["label"]), x["label"]))
    return {"total": len(out), "nodes": out[:lim]}


def _props(raw: str | None) -> dict:
    try:
        props = json.loads(raw or "{}")
    except ValueError:
        return {}
    return {k: v for k, v in props.items() if v not in (None, "", [], {})}


def t_get_node(st: Store, args: dict) -> dict:
    nid = st.resolve(args.get("node"))
    row = st.con.execute("SELECT id, kind, label, tier0, props FROM nodes WHERE id=?", (nid,)).fetchone()
    refs = [{"findingId": r["finding_id"], "ruleId": st.findings.get(r["finding_id"], {}).get("ruleId"),
             "severity": st.findings.get(r["finding_id"], {}).get("severity"),
             "title": st.findings.get(r["finding_id"], {}).get("title")}
            for r in st.con.execute("SELECT DISTINCT finding_id FROM affected WHERE node_id=?", (nid,))]
    refs.sort(key=lambda x: SEVERITY_RANK.get(x["severity"] or "info", 9))
    counts = lambda col: {r["kind"]: r["n"] for r in st.con.execute(
        f"SELECT kind, count(*) AS n FROM edges WHERE {col}=? GROUP BY kind", (nid,))}
    ag = st.attack_graph()
    return {"node": st.ref(nid), "properties": _props(row["props"]) if row else {},
            "tier0Reason": ag.targets.get(nid), "findings": refs,
            "edgesOut": counts("src"), "edgesIn": counts("dst")}


def t_get_edges(st: Store, args: dict) -> dict:
    nid = st.resolve(args.get("node"))
    direction = args.get("direction", "out")
    if direction not in ("out", "in"):
        raise ToolError("direction 必須是 out 或 in")
    kinds = [str(k) for k in (args.get("kinds") or [])]
    col, other = ("src", "dst") if direction == "out" else ("dst", "src")
    sql = f"SELECT src, dst, kind, props FROM edges WHERE {col}=?"
    params: list[Any] = [nid]
    if kinds:
        sql += " AND kind IN (" + ",".join("?" * len(kinds)) + ")"
        params += kinds
    rows = list(st.con.execute(sql + " ORDER BY kind", params))
    lim = _limit(args, 50, 500)
    edges = [{"kind": r["kind"], "other": st.ref(r[other]), "props": _props(r["props"])} for r in rows[:lim]]
    return {"node": st.ref(nid), "direction": direction, "total": len(rows), "edges": edges,
            "note": "邊是收集到的事實（成員、ACL、委派、同步…）；能否被濫用請看 path_to_tier0 / who_can_reach。"}


def t_list_attack_paths(st: Store, args: dict) -> dict:
    sql = "SELECT * FROM attack_paths WHERE 1=1"
    params: list[Any] = []
    if args.get("broad_only"):
        sql += " AND broad=1"
    if args.get("max_hops") is not None:
        sql += " AND hops<=?"
        params.append(int(args["max_hops"]))
    if args.get("min_exposed") is not None:
        sql += " AND exposed_accounts>=?"
        params.append(int(args["min_exposed"]))
    if not st._has_table("attack_paths"):
        raise ToolError("這份分析沒有攻擊路徑資料（分析器 0.3.0 以後才有）")
    rows = list(st.con.execute(sql + " ORDER BY broad DESC, exposed_accounts DESC, cost, entry_label", params))
    off, lim = _offset(args), _limit(args, 20, 100)
    with_steps = bool(args.get("include_steps"))
    out = []
    for r in rows[off:off + lim]:
        e = {"entry": st.ref(r["entry_id"]), "broad": bool(r["broad"]), "hops": r["hops"], "cost": r["cost"],
             "exposedAccounts": r["exposed_accounts"], "target": st.ref(r["target_id"]), "path": r["path"]}
        if with_steps:
            e["steps"] = json.loads(r["steps"] or "[]")
        out.append(e)
    ap = st.doc.get("attackPaths") or {}
    return {"total": len(rows), "offset": off, "accountsWithPath": ap.get("accountsWithPath"),
            "accountsTotal": ap.get("accountsTotal"), "paths": out, "chokepoints": ap.get("chokepoints") or []}


def t_path_to_tier0(st: Store, args: dict) -> dict:
    nid = st.resolve(args.get("node"))
    ag = st.attack_graph()
    if nid in ag.targets:
        return {"node": st.ref(nid), "isTier0": True, "reason": ag.targets[nid], "steps": []}
    if st._tier0_route is None:
        st._tier0_route = shortest(ag, ag.targets)
    dist, nxt = st._tier0_route
    steps = path_from(st, nxt, nid)
    return {"node": st.ref(nid), "isTier0": False, "hasPath": bool(steps), "hops": hops(steps),
            "cost": round(dist[nid], 2) if nid in dist else None, "path": render(steps), "steps": steps,
            "target": st.ref(steps[-1]["to"]) if steps else None,
            "targetReason": ag.targets.get(steps[-1]["to"]) if steps else None,
            "note": "最短的一條；可能還有其他較長的路徑。" if steps else "以收集到的資料沒有找到通往 Tier0 的路徑。"}


def t_who_can_reach(st: Store, args: dict) -> dict:
    nid = st.resolve(args.get("node"))
    rows = reach(st, st.attack_graph(), nid, _limit(args, 20, 100))
    if not args.get("include_tier0", False):
        rows = [r for r in rows if not r["tier0"]]
    return {"node": st.ref(nid), "sources": rows,
            "note": "列出能取得此物件的主體（每個起點最短的一條）；預設不含本身已是 Tier0 的主體。"}


# ===========================================================================================
_NODE = {"type": "string", "description": "Node id (SID, 'entra:<objectId>', 'dn:...', 'gpo:...') or its exact label"}
_LIMIT = {"type": "integer", "minimum": 1, "description": "Maximum rows to return"}
_OFFSET = {"type": "integer", "minimum": 0, "description": "Rows to skip (paging)"}
TOOLS: list[dict[str, Any]] = [
    {"name": "get_overview", "title": "Assessment overview", "fn": t_overview,
     "description": "Scope, data time, finding counts by severity, rule status counts (incl. which rules were skipped), "
                    "Tier0 size, attack-path summary and top hotspots. Call this first.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "list_findings", "title": "List findings", "fn": t_list_findings,
     "description": "Findings sorted by severity. Filter by minimum severity, rule id prefix (e.g. 'AD-02', 'HY'), "
                    "category (AD, ADCS, Entra, Hybrid, Path) or text contained in the title, summary or an affected object.",
     "inputSchema": {"type": "object", "properties": {
         "min_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
         "rule_id": {"type": "string"}, "category": {"type": "string"}, "contains": {"type": "string"},
         "limit": _LIMIT, "offset": _OFFSET}, "additionalProperties": False}},
    {"name": "get_finding", "title": "Get one finding", "fn": t_get_finding,
     "description": "One finding with summary, affected objects (with per-object detail), evidence, remediation and ATT&CK ids.",
     "inputSchema": {"type": "object", "properties": {"finding_id": {"type": "string", "description": "e.g. F001"},
                                                      "limit": _LIMIT}, "required": ["finding_id"], "additionalProperties": False}},
    {"name": "list_rules", "title": "List rules and their status", "fn": t_list_rules,
     "description": "Every rule with status finding / pass / skipped / error / accepted and, for skipped, the missing datasets.",
     "inputSchema": {"type": "object", "properties": {
         "status": {"type": "string", "enum": ["finding", "pass", "skipped", "error", "accepted"]}}, "additionalProperties": False}},
    {"name": "get_hotspots", "title": "Hotspot identities", "fn": t_hotspots,
     "description": "Identities (AD account merged with its synced Entra account) that appear in several findings, by score.",
     "inputSchema": {"type": "object", "properties": {"limit": _LIMIT}, "additionalProperties": False}},
    {"name": "search_nodes", "title": "Search graph objects", "fn": t_search_nodes,
     "description": "Find users, groups, computers, OUs, GPOs, Entra users / groups / apps / roles by label or id substring.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string"}, "kind": {"type": "string", "description": "e.g. user, group, computer, ou, gpo, entraUser, "
                                                                              "entraGroup, servicePrincipal, entraRole"},
         "tier0": {"type": "boolean"}, "limit": _LIMIT}, "additionalProperties": False}},
    {"name": "get_node", "title": "Get one object", "fn": t_get_node,
     "description": "Collected properties of one object, whether and why it is Tier0, the findings that list it, and edge counts.",
     "inputSchema": {"type": "object", "properties": {"node": _NODE}, "required": ["node"], "additionalProperties": False}},
    {"name": "get_edges", "title": "Relationships of one object", "fn": t_get_edges,
     "description": "Collected relationships of one object: memberships, ACL rights, delegation, GPO links, sync links, roles. "
                    "direction 'out' = what it has / can do; 'in' = who has rights on it.",
     "inputSchema": {"type": "object", "properties": {
         "node": _NODE, "direction": {"type": "string", "enum": ["out", "in"]},
         "kinds": {"type": "array", "items": {"type": "string"}, "description": "e.g. MemberOf, GenericAll, ForceChangePassword"},
         "limit": _LIMIT}, "required": ["node"], "additionalProperties": False}},
    {"name": "list_attack_paths", "title": "Attack-path entry points", "fn": t_list_attack_paths,
     "description": "Entry points with a route to Tier0: broad groups first, then by accounts sharing the route and cost; "
                    "plus the chokepoint steps that cut the most routes.",
     "inputSchema": {"type": "object", "properties": {
         "broad_only": {"type": "boolean"}, "max_hops": {"type": "integer", "minimum": 0},
         "min_exposed": {"type": "integer", "minimum": 0}, "include_steps": {"type": "boolean"},
         "limit": _LIMIT, "offset": _OFFSET}, "additionalProperties": False}},
    {"name": "path_to_tier0", "title": "Route from an object to Tier0", "fn": t_path_to_tier0,
     "description": "The cheapest attack route from one principal to any Tier0 asset, step by step.",
     "inputSchema": {"type": "object", "properties": {"node": _NODE}, "required": ["node"], "additionalProperties": False}},
    {"name": "who_can_reach", "title": "Who can take over an object", "fn": t_who_can_reach,
     "description": "Principals with an attack route to the given object (e.g. a synced cloud admin, the Entra Connect server), "
                    "cheapest first, each with its route.",
     "inputSchema": {"type": "object", "properties": {
         "node": _NODE, "include_tier0": {"type": "boolean"}, "limit": _LIMIT}, "required": ["node"], "additionalProperties": False}},
]
_BY_NAME: dict[str, dict[str, Any]] = {t["name"]: t for t in TOOLS}
_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def _cut(result: dict) -> dict:
    """Keep a tool result under MAX_TEXT by shortening its longest list."""
    text = json.dumps(result, ensure_ascii=False, default=str)
    while len(text) > MAX_TEXT:
        lists = [(k, v) for k, v in result.items() if isinstance(v, list) and len(v) > 1]
        if not lists:
            break
        k, v = max(lists, key=lambda kv: len(json.dumps(kv[1], ensure_ascii=False, default=str)))
        result[k] = v[: max(1, len(v) // 2)]
        result["truncated"] = True
        text = json.dumps(result, ensure_ascii=False, default=str)
    return result


def call_tool(st: Store, name: str, arguments: dict | None) -> dict:
    tool = _BY_NAME[name]
    return _cut(tool["fn"](st, dict(arguments or {})))


# ===========================================================================================
class Server:
    def __init__(self, store: Store, log: Callable[[str], None] | None = None) -> None:
        self.store = store
        self.version = PROTOCOL_VERSIONS[0]
        self.log = log or (lambda m: print(m, file=sys.stderr, flush=True))

    def handle(self, msg: Any) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
                return None   # a response to something we never send: ignore
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        is_notification = "id" not in msg
        try:
            result = self._dispatch(method, params)
        except _RpcError as e:
            return None if is_notification else _error(mid, e.code, e.message)
        except Exception as exc:  # never let one request kill the server
            self.log(f"internal error in {method}: {exc}\n{traceback.format_exc(limit=3)}")
            return None if is_notification else _error(mid, -32603, f"Internal error: {type(exc).__name__}")
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _dispatch(self, method: str, params: dict) -> Any:
        if method == "initialize":
            req = params.get("protocolVersion")
            self.version = req if req in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            return {"protocolVersion": self.version, "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "title": "ADHD assessment (read-only)", "version": __version__},
                    "instructions": INSTRUCTIONS}
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return {}
        if method == "tools/list":
            tools = []
            for t in TOOLS:
                d = {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
                if self.version >= "2025-03-26":
                    d["annotations"] = dict(_ANNOTATIONS, title=t["title"])
                if self.version >= "2025-06-18":
                    d["title"] = t["title"]
                tools.append(d)
            return {"tools": tools}
        if method == "tools/call":
            name = params.get("name")
            if name not in _BY_NAME:
                raise _RpcError(-32602, f"Unknown tool: {name}")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                raise _RpcError(-32602, "arguments must be an object")
            try:
                result = call_tool(self.store, name, args)
            except ToolError as e:
                return {"content": [{"type": "text", "text": str(e)}], "isError": True}
            except (ValueError, TypeError) as e:
                return {"content": [{"type": "text", "text": f"參數錯誤：{e}"}], "isError": True}
            out: dict[str, Any] = {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, default=str)}],
                                   "isError": False}
            if self.version >= "2025-06-18":
                out["structuredContent"] = json.loads(json.dumps(result, default=str))
            return out
        raise _RpcError(-32601, f"Method not found: {method}")

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        for raw in stdin:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self._write(stdout, _error(None, -32700, "Parse error"))
                continue
            reply = self.handle(msg)
            if reply is not None:
                self._write(stdout, reply)

    @staticmethod
    def _write(stdout, obj: dict) -> None:
        stdout.write((json.dumps(obj, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
        stdout.flush()


class _RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def _error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Read-only MCP server (stdio) over an ADHD analysis output directory")
    ap.add_argument("report_dir", type=Path, help="directory with findings.json and graph.sqlite from tools/analyze.py")
    args = ap.parse_args(argv)
    try:
        store = Store(args.report_dir)
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"adhd MCP server {__version__}: {args.report_dir}（{len(store.findings)} 筆發現，唯讀）", file=sys.stderr, flush=True)
    Server(store).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
