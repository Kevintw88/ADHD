"""Attack paths: shortest multi-step routes from non-Tier0 principals to Tier0, across AD and Entra ID.

The property graph (adhd.load) records facts: memberships, ACEs, delegation, sync links.  This module
turns those facts into *attack steps* ("whoever controls A can take over B") and runs a reverse
Dijkstra from every Tier0 asset, so each principal gets its cheapest route to Tier0.

What becomes a step
    memberships            member -> group / role holder -> role (cost 0: holding membership is not an action)
    ACL rights             only rights that give control of that kind of object (ForceChangePassword on a user,
                           AddMember on a group, ReadLAPSPassword on a computer, ...)
    inherited ACEs         an ACE on an OU / container that is inherited by descendants becomes a step to each
                           matching descendant (inheritedObjectType, "Children" depth, protected DACLs and
                           adminCount=1 objects respected)
    container control      GenericAll / WriteDacl / WriteOwner / Owns on an OU: the holder can add an inheritable
                           ACE, so it reaches every unprotected object below it
    GPO                    control of a GPO reaches the users and computers it applies to (block inheritance /
                           enforced / disabled links respected)
    AdminSDHolder          control of AdminSDHolder reaches every adminCount=1 object (SDProp)
    delegation             RBCD (AllowedToAct), constrained delegation (AllowedToDelegate)
    Entra Connect          local administrators of the Entra Connect server -> the server -> the AD DS connector
                           account whose password is stored there
    ADCS                   enrol rights on an ESC1 template, or write rights on any published template (ESC4),
                           reach the domain; so does control of an enterprise CA host
    hybrid                 AD account -> the Entra account synced from it; Entra group / app / SP owners

Tier0 targets: AD Tier0 (privileged groups and members, DCs, krbtgt, DCSync holders), the domain object,
Entra Tier0 roles and their holders, and service principals with app permissions that escalate to tenant admin.

Paths are shortest by cost, so they are one route per principal, not every route; removing the steps
reported as chokepoints cuts those routes, but an alternative longer route may remain.
"""
from __future__ import annotations

import heapq
import itertools
from collections import Counter, defaultdict, deque
from typing import Any, Iterable

from . import known
from .load import rid_of

# kind -> (cost, how the step reads in a report)
STEP: dict[str, tuple[float, str]] = {
    "MemberOf": (0.0, "是成員"),
    "EntraMemberOf": (0.0, "是成員"),
    "HasRole": (0.0, "持有角色"),
    "AppIdentity": (0.0, "對應的服務主體"),
    "SyncedTo": (0.5, "同步為（掌控 AD 帳號即掌控雲端帳號）"),
    "GenericAll": (1.0, "完全控制"),
    "GenericWrite": (1.0, "可寫入屬性"),
    "WriteDacl": (1.0, "可修改權限"),
    "WriteOwner": (1.0, "可變更擁有者"),
    "Owns": (1.0, "是擁有者"),
    "WriteAllProperties": (1.0, "可寫入所有屬性"),
    "AllExtendedRights": (1.0, "具所有延伸權限"),
    "ForceChangePassword": (1.0, "可重設密碼"),
    "AddMember": (1.0, "可新增成員"),
    "AddSelf": (1.0, "可把自己加入"),
    "AddKeyCredentialLink": (1.0, "可寫入 Key Credential（Shadow Credentials）"),
    "WriteRBCD": (1.5, "可設定資源型委派"),
    "WriteSPN": (2.0, "可設定 SPN（定向 Kerberoasting，需破解密碼）"),
    "ReadLAPSPassword": (1.0, "可讀取 LAPS 密碼"),
    "ReadGMSAPassword": (1.0, "可讀取 gMSA 密碼"),
    "WriteGMSAMembership": (1.5, "可修改 gMSA 密碼讀取者"),
    "DCSync": (1.0, "可 DCSync（取得所有密碼雜湊）"),
    "AllowedToAct": (1.5, "資源型委派（可冒充任何使用者存取）"),
    "AllowedToDelegate": (2.0, "限制委派"),
    "AdminTo": (1.0, "是本機管理員"),
    "HasCredential": (1.0, "主機上保存此帳號的密碼"),
    "GPOAppliesTo": (1.0, "GPO 套用到"),
    "ControlsContainer": (1.5, "控制上層容器（可加入可繼承的權限）"),
    "SDProp": (1.0, "AdminSDHolder 權限會覆寫到受保護物件"),
    "Enroll": (1.0, "可申請憑證"),
    "ADCSImpersonate": (0.5, "憑證範本可冒充任何帳號"),
    "HostsCA": (1.0, "主機為企業 CA（可簽發任意憑證）"),
}
MEMBERSHIP = {"MemberOf", "EntraMemberOf", "HasRole", "AppIdentity"}

_WRITE = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteAllProperties"}
_FULL = {"GenericAll", "WriteDacl", "WriteOwner", "Owns"}
# which rights give control of which kind of object
CONTROL_ON: dict[str, set[str]] = {
    "user": _WRITE | {"AllExtendedRights", "ForceChangePassword", "AddKeyCredentialLink", "WriteSPN"},
    "computer": _WRITE | {"AllExtendedRights", "AddKeyCredentialLink", "WriteRBCD", "ReadLAPSPassword"},
    "group": _WRITE | {"AddMember", "AddSelf"},
    "gmsa": _FULL | {"ReadGMSAPassword", "WriteGMSAMembership", "GenericWrite", "WriteAllProperties"},
    "domain": _FULL | {"DCSync", "AllExtendedRights"},
    "gpo": set(_WRITE),
}
_CLASS_NAMES = {"user": {"user", "inetorgperson"}, "computer": {"computer"}, "group": {"group"},
                "gmsa": {"msds-groupmanagedserviceaccount"}}
_CONTAINERS = {"ou", "container", "domain"}
ACCOUNT_KINDS = {"user", "computer", "gmsa", "localAccount", "entraUser", "servicePrincipal"}
PRINCIPAL_KINDS = ACCOUNT_KINDS | {"group", "foreignPrincipal", "entraGroup", "application"}


class AttackGraph:
    """Reverse adjacency of attack steps plus the Tier0 target set."""

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.rev: dict[str, list[tuple[str, str, float, str | None]]] = defaultdict(list)
        self.fwd: dict[str, list[tuple[str, str, float, str | None]]] = defaultdict(list)
        self._seen: set[tuple[str, str, str]] = set()
        self.targets: dict[str, str] = {}
        self.protected: set[str] = set()

    def add(self, src: str, dst: str, kind: str, note: str | None = None, cost: float | None = None) -> None:
        if src == dst or (src, kind, dst) in self._seen:
            return
        self._seen.add((src, kind, dst))
        c = STEP[kind][0] if cost is None else cost
        self.rev[dst].append((src, kind, c, note))
        self.fwd[src].append((dst, kind, c, note))

    @property
    def steps(self) -> int:
        return len(self._seen)


# ===========================================================================================
def _skip_source(ctx, sid: str) -> bool:
    """Principals that are not an attacker foothold: SELF, CREATOR OWNER, SYSTEM, deleted (orphan) SIDs."""
    return sid in known.SAFE_ACL_PRINCIPALS or ctx.is_orphan(sid)


def _is_protected(ctx, nid: str) -> bool:
    node = ctx.graph.nodes.get(nid) or {}
    return bool(node.get("daclProtected")) or node.get("adminCount") == 1


def _descendants(ctx, root: str, *, children_only: bool = False, stop=None) -> Iterable[str]:
    """Objects below *root* along Contains edges; *stop(nid)* prunes a subtree (the node itself is not yielded)."""
    g = ctx.graph
    queue = deque([(root, 0)])
    seen = {root}
    while queue:
        n, depth = queue.popleft()
        for e in g.edges_out(n, ["Contains"]):
            c = e.dst
            if c in seen:
                continue
            seen.add(c)
            if stop is not None and stop(c):
                continue
            yield c
            if not children_only and g.kind(c) in _CONTAINERS:
                queue.append((c, depth + 1))


def _type_ok(ctx, nid: str, types: list[str]) -> bool:
    if not types or "any" in [str(t).lower() for t in types]:
        return True
    names = _CLASS_NAMES.get(ctx.graph.kind(nid), set())
    return any(str(t).lower() in names for t in types)


def _acl_steps(ctx, ag: AttackGraph) -> None:
    g = ctx.graph
    adminsdholder = None
    if ctx.domain.get("distinguishedName"):
        adminsdholder = ctx.dn_index.get(f"cn=adminsdholder,cn=system,{ctx.domain['distinguishedName']}".lower())
    cache: dict[tuple[str, bool], list[str]] = {}

    def below(root: str, children_only: bool) -> list[str]:
        key = (root, children_only)
        if key not in cache:
            cache[key] = list(_descendants(ctx, root, children_only=children_only, stop=lambda n: _is_protected(ctx, n)))
        return cache[key]

    for e in list(g.edges):
        if e.kind not in STEP or e.kind in ("HasRole",):
            continue
        src, dst, kind = e.src, e.dst, e.kind
        if src.startswith("S-1-") and _skip_source(ctx, src):
            continue
        dk = g.kind(dst)
        if kind in MEMBERSHIP or kind in ("SyncedTo", "AllowedToAct"):
            ag.add(src, dst, kind)
            continue
        if kind == "AllowedToDelegate":
            ag.add(src, dst, kind, cost=1.5 if e.props.get("protocolTransition") else 2.0)
            continue
        if kind in ("ReadGMSAPassword", "ReadLAPSPassword", "DCSync") and dk in CONTROL_ON and kind in CONTROL_ON[dk]:
            ag.add(src, dst, kind)
            continue
        inh = [str(i) for i in (e.props.get("inheritance") or ["None"])]
        applies_self = any(i in ("None", "All", "SelfAndChildren") for i in inh)
        inherits = [i for i in inh if i in ("All", "Descendents", "Children", "SelfAndChildren")]
        if applies_self and dk in CONTROL_ON and kind in CONTROL_ON[dk]:
            ag.add(src, dst, kind)
        if applies_self and dst == adminsdholder and kind in _WRITE:
            ag.add(src, dst, kind)
        if dk not in _CONTAINERS or dst == adminsdholder or src in ctx.tier0:
            continue   # Tier0 holders are targets already: expanding their inherited rights adds nothing to the paths
        label = ctx.label(dst)
        if inherits:   # inherited ACE: reaches matching descendants that do not block inheritance
            types = [t for t in (e.props.get("inheritedObjectType") or []) if t]
            only_children = all(i in ("Children", "SelfAndChildren") for i in inherits)
            for d in below(dst, only_children):
                dkind = g.kind(d)
                if dkind in CONTROL_ON and kind in CONTROL_ON[dkind] and _type_ok(ctx, d, types):
                    ag.add(src, d, kind, note=f"繼承自 {label}")
        if applies_self and kind in _FULL and dk != "domain":   # full control of the container itself
            for d in below(dst, False):
                if g.kind(d) in CONTROL_ON and g.kind(d) != "gpo":
                    ag.add(src, d, "ControlsContainer", note=f"經由 {label}")
    # SDProp: AdminSDHolder's DACL is stamped onto every adminCount=1 object
    if adminsdholder:
        for nid, node in g.nodes.items():
            if node.get("adminCount") == 1 and g.kind(nid) in ("user", "group", "computer", "gmsa"):
                ag.add(adminsdholder, nid, "SDProp")


def _gpo_steps(ctx, ag: AttackGraph) -> None:
    g = ctx.graph
    for e in list(g.edges):
        if e.kind != "GPLink" or e.props.get("enabled") is False:
            continue
        enforced = bool(e.props.get("enforced"))
        stop = None if enforced else (lambda n: g.kind(n) == "ou" and bool(g.nodes[n].get("blockInheritance")))
        for d in _descendants(ctx, e.dst, stop=stop):
            if g.kind(d) in ("user", "computer"):
                ag.add(e.src, d, "GPOAppliesTo", note=f"連結於 {ctx.label(e.dst)}")


def _host_index(ctx) -> dict[str, str]:
    idx = {}
    for c in ctx.computers():
        for h in (c.get("name"), c.get("dnsHostName")):
            if h:
                idx[str(h).lower()] = c["sid"]
                idx[str(h).lower().split(".", 1)[0]] = c["sid"]
    return idx


def _entra_connect_steps(ctx, ag: AttackGraph) -> None:
    from .rules.ad import connector_sids
    g = ctx.graph
    hosts = _host_index(ctx)
    connectors, _ = connector_sids(ctx)
    for srv in ctx.rows("entraconnect_server"):
        name = str(srv.get("computerName") or "")
        if not name:
            continue
        cid = hosts.get(name.lower())
        if cid is None:
            cid = f"host:{name.lower()}"
            g.add_node(cid, "computer", name)
        g.nodes[cid]["entraConnectServer"] = True
        for m in srv.get("localAdministrators") or []:
            msid = str(m.get("sid") or "")
            if not msid:
                continue
            in_domain = bool(ctx.domain_sid) and msid.startswith(ctx.domain_sid + "-")
            source = str(m.get("principalSource") or "").lower()
            local = source == "local" if source else (msid.startswith("S-1-5-21-") and not in_domain and msid not in g.nodes)
            if local and rid_of(msid) == 500:
                continue   # built-in local Administrator: reached through whoever can read its LAPS password
            if msid not in g.nodes:
                g.add_node(msid, "localAccount" if local else "foreignPrincipal", m.get("name") or msid)
            if not _skip_source(ctx, msid):
                ag.add(msid, cid, "AdminTo", note=f"{name} 的本機 Administrators")
        for c in connectors:
            ag.add(cid, c, "HasCredential", note="Entra Connect 的 AD DS connector 帳號")


def _adcs_steps(ctx, ag: AttackGraph) -> None:
    g = ctx.graph
    dom = ctx.domain_sid
    if not dom or dom not in g.nodes:
        return
    for t in ctx.rows("adcs_templates"):
        if not t.get("published"):
            continue
        tid = ctx.dn_index.get(str(t.get("distinguishedName") or "").lower())
        if not tid:
            continue
        esc1 = (not t.get("managerApproval") and not (t.get("authorizedSignaturesRequired") or 0)
                and t.get("enrolleeSuppliesSubject") and t.get("clientAuthCapable"))
        allowed = set(_WRITE) | ({"Enroll", "AllExtendedRights"} if esc1 else set())
        for e in g.edges_in(tid):
            if e.kind in allowed and not (e.src.startswith("S-1-") and _skip_source(ctx, e.src)):
                ag.add(e.src, tid, e.kind)
        ag.add(tid, dom, "ADCSImpersonate", note="ESC1" if esc1 else "ESC4：可改成 ESC1 再申請")
    hosts = {str(c.get("dnsHostName") or "").lower() for c in ctx.rows("adcs_cas")}
    for c in ctx.computers():
        if str(c.get("dnsHostName") or "").lower() in hosts:
            ag.add(c["sid"], dom, "HostsCA")


def _entra_steps(ctx, ag: AttackGraph) -> None:
    g = ctx.graph
    for e in list(g.edges):
        if e.kind == "Owns" and g.kind(e.dst) in ("entraGroup", "application", "servicePrincipal"):
            ag.add(e.src, e.dst, "Owns")
        elif e.kind == "HasRole":
            ag.add(e.src, e.dst, "HasRole")


def _targets(ctx, ag: AttackGraph) -> None:
    g = ctx.graph
    for sid in ctx.tier0:
        if sid in g.nodes:
            ag.targets[sid] = "AD Tier0"
    if ctx.domain_sid and ctx.domain_sid in g.nodes:
        ag.targets[ctx.domain_sid] = "網域（可 DCSync / 取得網域管理權限）"
    for nid, node in g.nodes.items():
        if node["kind"] == "entraRole":
            from .load import role_tier
            if role_tier(nid.split(":", 1)[1], node.get("label")) == "tier0":
                ag.targets[nid] = "Entra Tier0 角色"
    for nid, entries in ctx.entra_priv.items():
        if any(x["tier"] == "tier0" for x in entries):
            ag.targets[nid] = "持有 Entra Tier0 角色"
    for e in g.edges:
        if e.kind == "AppRole" and set(e.props.get("permission") or []) & known.TIER0_APP_PERMISSIONS:
            ag.targets[e.src] = "持有可提權為租用戶管理員的應用程式權限"
    # hosts whose compromise is domain compromise are Tier0 assets in their own right
    for nid, node in g.nodes.items():
        if node.get("entraConnectServer") and nid not in ag.targets:
            ag.targets[nid] = "Entra Connect 伺服器（保存 connector 帳號密碼，視同 Tier0）"
    for src, kind, _c, _n in ag.rev.get(ctx.domain_sid or "", []):
        if kind == "HostsCA" and src not in ag.targets:
            ag.targets[src] = "企業 CA 主機（可簽發任意帳號的憑證，視同 Tier0）"


IMPLICIT_GROUPS = ("S-1-1-0", "S-1-5-11")   # Everyone, Authenticated Users: every domain account, no member list


def _implicit_members(ctx, ag: AttackGraph) -> None:
    for grp in IMPLICIT_GROUPS:
        if not ag.fwd.get(grp):
            continue
        for ds in ("ad_users", "ad_computers", "ad_service_accounts"):
            for r in ctx.rows(ds):
                if r.get("sid") and r.get("enabled") is not False:
                    ag.add(r["sid"], grp, "MemberOf", note="隱含成員")


def build_attack_graph(ctx) -> AttackGraph:
    ag = AttackGraph(ctx)
    _acl_steps(ctx, ag)
    _gpo_steps(ctx, ag)
    _entra_connect_steps(ctx, ag)
    _adcs_steps(ctx, ag)
    _entra_steps(ctx, ag)
    _implicit_members(ctx, ag)
    _targets(ctx, ag)
    return ag


# ===========================================================================================
def shortest(ag: AttackGraph, targets: Iterable[str], *, stop_at_targets: bool = True
             ) -> tuple[dict[str, float], dict[str, tuple[str, str, str | None]]]:
    """Reverse Dijkstra from *targets*: cost to the nearest target and the next step towards it."""
    tset = set(targets)
    dist: dict[str, float] = {t: 0.0 for t in tset}
    nxt: dict[str, tuple[str, str, str | None]] = {}
    tie = itertools.count()
    heap = [(0.0, next(tie), t) for t in tset]
    heapq.heapify(heap)
    while heap:
        d, _, n = heapq.heappop(heap)
        if d > dist.get(n, float("inf")):
            continue
        for src, kind, cost, note in ag.rev.get(n, []):
            if stop_at_targets and src in tset:
                continue
            nd = d + cost
            if nd < dist.get(src, float("inf")) - 1e-9:
                dist[src] = nd
                nxt[src] = (n, kind, note)
                heapq.heappush(heap, (nd, next(tie), src))
    return dist, nxt


def path_from(ctx, nxt: dict[str, tuple[str, str, str | None]], start: str) -> list[dict[str, Any]]:
    steps, cur, guard = [], start, 0
    while cur in nxt and guard < 200:
        dst, kind, note = nxt[cur]
        step = {"from": cur, "fromLabel": ctx.label(cur), "kind": kind, "action": STEP[kind][1],
                "to": dst, "toLabel": ctx.label(dst)}
        if note:
            step["note"] = note
        steps.append(step)
        cur, guard = dst, guard + 1
    return steps


def hops(steps: list[dict[str, Any]]) -> int:
    return sum(1 for s in steps if s["kind"] not in MEMBERSHIP)


def render(steps: list[dict[str, Any]]) -> str:
    if not steps:
        return ""
    out = [steps[0]["fromLabel"]]
    for s in steps:
        out.append(f" →[{s['action']}{'；' + s['note'] if s.get('note') else ''}]→ {s['toLabel']}")
    return "".join(out)


def _entry(path: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """The principal that actually holds the first abusable right (after following memberships)."""
    for i, s in enumerate(path):
        if s["kind"] not in MEMBERSHIP:
            return s["from"], path[i:]
    return path[-1]["to"], []


def _active(ctx, nid: str) -> bool:
    g = ctx.graph
    kind = g.kind(nid)
    if kind not in ACCOUNT_KINDS:
        return False
    node = g.nodes.get(nid) or {}
    if kind in ("entraUser", "servicePrincipal"):
        return node.get("accountEnabled") is not False
    if kind == "localAccount":
        return True
    return node.get("enabled") is not False


def analyze(ctx) -> dict[str, Any]:
    """Attack-path summary for the round (memoised on the context)."""
    cached = getattr(ctx, "_attack_paths", None)
    if cached is not None:
        return cached
    ag = build_attack_graph(ctx)
    dist, nxt = shortest(ag, ag.targets)
    g = ctx.graph
    exposed: Counter = Counter()
    edge_use: Counter = Counter()
    accounts = [n for n in nxt if _active(ctx, n)]
    for a in accounts:
        p = path_from(ctx, nxt, a)
        entry, _ = _entry(p)
        exposed[entry] += 1
        for s in p:   # a right held by a principal (not "template -> domain" etc.) is what gets removed
            if s["kind"] not in MEMBERSHIP and g.kind(s["from"]) in PRINCIPAL_KINDS:
                edge_use[(s["from"], s["kind"], s["to"])] += 1
    entries: dict[str, dict[str, Any]] = {}
    for n in list(ag.fwd):
        if n in ag.targets or g.kind(n) not in PRINCIPAL_KINDS or (n.startswith("S-1-") and _skip_source(ctx, n)):
            continue
        best = None   # the principal's own abusable right with the cheapest onward route (memberships excluded)
        for dst, kind, cost, note in ag.fwd[n]:
            if kind in MEMBERSHIP or dst not in dist:
                continue
            total = cost + dist[dst]
            if best is None or total < best[0] - 1e-9:
                best = (total, dst, kind, note)
        if best is None:
            continue
        total, dst, kind, note = best
        onward = path_from(ctx, nxt, dst)
        if any(s["to"].startswith("S-1-") and ctx.is_broad(s["to"]) for s in onward):
            continue   # the route runs through Everyone / Domain Users / ...: that broad group is the real entry point
        first = {"from": n, "fromLabel": ctx.label(n), "kind": kind, "action": STEP[kind][1], "to": dst, "toLabel": ctx.label(dst)}
        if note:
            first["note"] = note
        rest = [first] + onward
        last = rest[-1]["to"]
        entries[n] = {
            "id": n, "label": ctx.label(n), "kind": g.kind(n), "broad": ctx.is_broad(n) if n.startswith("S-1-") else False,
            "target": last, "targetLabel": ctx.label(last), "targetReason": ag.targets.get(last),
            "hops": hops(rest), "cost": round(total, 2), "exposedAccounts": exposed.get(n, 0),
            "crossesAdEntra": any(s["kind"] == "SyncedTo" for s in rest)
                              or (n.startswith("S-1-") and last.startswith("entra")),
            "path": render(rest), "steps": rest,
        }
    ordered = sorted(entries.values(), key=lambda x: (not x["broad"], -x["exposedAccounts"], x["cost"], x["label"]))
    total_accounts = sum(1 for n in g.nodes if _active(ctx, n) and n not in ag.targets)
    chokepoints = [{"from": s, "fromLabel": ctx.label(s), "kind": k, "action": STEP[k][1], "to": d, "toLabel": ctx.label(d),
                    "accounts": c} for (s, k, d), c in edge_use.most_common(10)]
    result = {
        "targets": len(ag.targets), "attackSteps": ag.steps,
        "accountsWithPath": len(accounts), "accountsTotal": total_accounts,
        "entries": ordered, "chokepoints": chokepoints,
    }
    ctx._attack_paths = result
    ctx._attack_graph = (ag, dist, nxt)
    return result


def resolve(ctx, query: str) -> list[str]:
    """Node ids matching an id or (case-insensitive) label."""
    g = ctx.graph
    if query in g.nodes:
        return [query]
    q = query.lower()
    exact = [n for n, node in g.nodes.items() if str(node.get("label") or "").lower() == q]
    if exact:
        return exact
    return [n for n, node in g.nodes.items() if q in str(node.get("label") or "").lower()][:20]


def who_can_reach(ctx, target: str, limit: int = 20) -> list[dict[str, Any]]:
    """Principals with a route to *target* (any node), cheapest first."""
    if getattr(ctx, "_attack_graph", None) is None:
        analyze(ctx)
    ag = ctx._attack_graph[0]
    dist, nxt = shortest(ag, [target], stop_at_targets=True)
    out = []
    for n, d in sorted(dist.items(), key=lambda x: x[1]):
        if n == target or ctx.graph.kind(n) not in PRINCIPAL_KINDS:
            continue
        if n.startswith("S-1-") and _skip_source(ctx, n):
            continue
        p = path_from(ctx, nxt, n)
        entry, rest = _entry(p)
        if entry != n or not rest:
            continue
        out.append({"id": n, "label": ctx.label(n), "kind": ctx.graph.kind(n), "tier0": n in ag.targets,
                    "hops": hops(rest), "cost": round(d, 2), "path": render(rest), "steps": rest})
        if len(out) >= limit:
            break
    return out


def route_from(ctx, start: str) -> list[dict[str, Any]]:
    """Cheapest route from *start* to Tier0 (empty when there is none or *start* is Tier0)."""
    analyze(ctx)
    return path_from(ctx, ctx._attack_graph[2], start)
