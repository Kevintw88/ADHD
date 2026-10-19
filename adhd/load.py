"""Build the analysis context (graph + indexes) from a collection round."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from . import acl, known
from .bundle import Round, parse_ts
from .graph import Graph

_GPO_DN = re.compile(r"^cn=(\{[0-9a-f\-]{36}\}),cn=policies,cn=system,", re.IGNORECASE)
_HEAVY = {"aces", "members", "transitiveMembers", "owners", "rolePermissions", "appRoles", "scopes"}


def parent_dn(dn: str) -> str | None:
    esc = False
    for i, ch in enumerate(dn):
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ",":
            return dn[i + 1:]
    return None


def rid_of(sid: str | None) -> int:
    if not sid or not sid.startswith("S-1-5-21-"):
        return -1
    try:
        return int(sid.rsplit("-", 1)[1])
    except ValueError:
        return -1


def _light(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in _HEAVY}


class Context:
    """Everything a rule needs: the round, the graph and pre-computed indexes."""

    def __init__(self, rnd: Round) -> None:
        self.round = rnd
        self.graph = Graph()
        self.as_of: datetime = rnd.as_of
        scope = rnd.scope()
        self.domain_sid: str | None = scope.get("adDomainSid")
        self.domain_dns: str | None = scope.get("adDomain")
        self.tenant_id: str | None = scope.get("entraTenantId")
        self.domain: dict[str, Any] = (rnd.rows("ad_domain") or [{}])[0]
        if not self.domain_sid:
            self.domain_sid = self.domain.get("domainSid")
        self.by_sid: dict[str, dict[str, Any]] = {}
        self.dn_index: dict[str, str] = {}
        self.tier0_groups: dict[str, str] = {}
        self.tier0: set[str] = set()
        self.dc_sids: set[str] = set()
        self.entra: dict[str, dict[str, Any]] = {}
        self.role_names: dict[str, str] = {}
        self.entra_priv: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.pim_available = rnd.usable("entra_pim_eligibility") or rnd.usable("entra_pim_assignments")
        self.catalog: dict[str, str] = {}

    # -- dataset access -----------------------------------------------------------------------
    def usable(self, name: str) -> bool:
        return self.round.usable(name)

    def rows(self, name: str) -> list[dict[str, Any]]:
        return self.round.rows(name)

    # -- helpers ------------------------------------------------------------------------------
    def days_since(self, ts: Any) -> int | None:
        dt = parse_ts(ts) if not isinstance(ts, datetime) else ts
        if dt is None:
            return None
        return (self.as_of - dt).days

    def dsid(self, rid: int) -> str | None:
        return f"{self.domain_sid}-{rid}" if self.domain_sid else None

    def is_broad(self, sid: str) -> bool:
        return sid in known.BROAD_SIDS or (
            bool(self.domain_sid) and sid.startswith(self.domain_sid + "-") and rid_of(sid) in known.BROAD_DOMAIN_RIDS)

    def label(self, nid: str) -> str:
        return self.graph.label(nid)

    def ref(self, nid: str, detail: Any = None) -> dict[str, Any]:
        out = {"id": nid, "label": self.graph.label(nid), "kind": self.graph.kind(nid)}
        if detail not in (None, "", [], {}):
            out["detail"] = detail
        return out

    def users(self) -> list[dict[str, Any]]:
        return self.rows("ad_users")

    def computers(self) -> list[dict[str, Any]]:
        return self.rows("ad_computers")

    def is_tier0_user(self, sid: str) -> bool:
        return sid in self.tier0 and self.graph.kind(sid) in ("user", "gmsa")


# ===========================================================================================
def _sid_label(sid: str, domain_sid: str | None) -> str:
    if sid in known.WELL_KNOWN_SIDS:
        return known.WELL_KNOWN_SIDS[sid]
    rid = rid_of(sid)
    if rid in known.DOMAIN_RIDS and (domain_sid is None or sid.startswith(domain_sid + "-") or rid in (518, 519, 498, 527)):
        return known.DOMAIN_RIDS[rid] + ("" if domain_sid and sid.startswith(domain_sid + "-") else " (other domain)")
    return sid


def _node_for_dn(ctx: Context, dn: str, kind: str, label: str | None = None, **props: Any) -> str:
    key = dn.lower()
    nid = ctx.dn_index.get(key)
    if nid is None:
        m = _GPO_DN.match(dn)
        nid = f"gpo:{m.group(1).strip('{}').lower()}" if m else f"dn:{key}"
        ctx.dn_index[key] = nid
    ctx.graph.add_node(nid, kind, label or (dn.split(",", 1)[0].split("=", 1)[-1]), dn=dn, **props)
    return nid


def _load_ad(ctx: Context) -> None:
    g = ctx.graph
    dom_sid = ctx.domain_sid
    if ctx.domain:
        d = ctx.domain
        g.add_node(dom_sid or "domain", "domain", d.get("dnsRoot"), dn=d.get("distinguishedName"), **_light(d))
        if d.get("distinguishedName"):
            ctx.dn_index[d["distinguishedName"].lower()] = dom_sid or "domain"

    sources = [("ad_users", "user", "samAccountName"), ("ad_computers", "computer", "name"),
               ("ad_groups", "group", "name"), ("ad_service_accounts", "gmsa", "samAccountName")]
    for ds, kind, label_key in sources:
        for r in ctx.rows(ds):
            sid = r.get("sid")
            if not sid:
                continue
            ctx.by_sid[sid] = r
            g.add_node(sid, kind, r.get(label_key) or r.get("name") or sid, dn=r.get("distinguishedName"), **_light(r))
            if r.get("distinguishedName"):
                ctx.dn_index[r["distinguishedName"].lower()] = sid

    # group membership (+ primary group)
    for r in ctx.rows("ad_groups"):
        for m in r.get("members") or []:
            if isinstance(m, str) and m.startswith("DN:"):
                src = _node_for_dn(ctx, m[3:], "unknown")
            else:
                src = m
                if src not in g.nodes:
                    g.add_node(src, "foreignPrincipal", _sid_label(src, dom_sid))
            g.add_edge(src, r["sid"], "MemberOf")
    if dom_sid:
        for ds in ("ad_users", "ad_computers", "ad_service_accounts"):
            for r in ctx.rows(ds):
                pg = r.get("primaryGroupId")
                if r.get("sid") and isinstance(pg, int) and pg > 0:
                    gid = f"{dom_sid}-{pg}"
                    if gid not in g.nodes:
                        g.add_node(gid, "group", _sid_label(gid, dom_sid))
                    g.add_edge(r["sid"], gid, "MemberOf", primary=True)

    # OUs, GPOs, GPLinks
    for r in ctx.rows("ad_gpos"):
        g.add_node(f"gpo:{r['id']}", "gpo", r.get("displayName"), **_light(r))
    for r in ctx.rows("ad_ous"):
        dn = r.get("distinguishedName")
        if not dn:
            continue
        nid = ctx.dn_index.get(dn.lower()) if r.get("objectClass") == "domainDNS" else None
        if nid is None:
            nid = _node_for_dn(ctx, dn, "ou", r.get("name"), blockInheritance=r.get("blockInheritance"))
        for link in r.get("gpLinks") or []:
            gpo = f"gpo:{link['gpoGuid']}"
            if gpo not in g.nodes:
                g.add_node(gpo, "gpo", gpo)
            g.add_edge(gpo, nid, "GPLink", enabled=link.get("enabled"), enforced=link.get("enforced"))

    # ACLs
    for r in ctx.rows("ad_acls"):
        dn = r.get("distinguishedName")
        if not dn:
            continue
        target = ctx.dn_index.get(dn.lower())
        if target is None:
            kind = {"organizationalUnit": "ou", "groupPolicyContainer": "gpo", "container": "container",
                    "builtinDomain": "container"}.get(str(r.get("objectClass")), "unknown")
            target = _node_for_dn(ctx, dn, kind)
        g.add_node(target, g.kind(target), aclReason=r.get("reason"), daclProtected=r.get("daclProtected"))
        _add_ace_edges(ctx, target, r.get("owner"), r.get("aces") or [])

    # Contains (parent container -> child), by DN
    for key, nid in list(ctx.dn_index.items()):
        p = parent_dn(key)
        while p:
            pid = ctx.dn_index.get(p)
            if pid is not None:
                if g.kind(pid) in ("domain", "ou", "container"):
                    g.add_edge(pid, nid, "Contains")
                break
            p = parent_dn(p)

    # gMSA password readers, delegation
    host_index: dict[str, str] = {}
    for c in ctx.computers():
        for h in (c.get("dnsHostName"), c.get("name")):
            if h:
                host_index[str(h).lower()] = c["sid"]
        if c.get("isDomainController"):
            ctx.dc_sids.add(c["sid"])
    for r in ctx.rows("ad_service_accounts"):
        for p in r.get("principalsAllowedToRetrievePassword") or []:
            src = p if not str(p).startswith("DN:") else _node_for_dn(ctx, p[3:], "unknown")
            g.add_edge(src, r["sid"], "ReadGMSAPassword")
    for ds in ("ad_users", "ad_computers", "ad_service_accounts"):
        for r in ctx.rows(ds):
            sid = r.get("sid")
            for spn in r.get("allowedToDelegateTo") or []:
                host = str(spn).split("/", 1)[-1].split(":", 1)[0].split("/", 1)[0].lower()
                tgt = host_index.get(host) or host_index.get(host.split(".", 1)[0])
                if tgt:
                    g.add_edge(sid, tgt, "AllowedToDelegate", spn=[spn],
                               protocolTransition="TRUSTED_TO_AUTH_FOR_DELEGATION" in (r.get("uacFlags") or []))
            for p in r.get("rbcdAllowedPrincipals") or []:
                g.add_edge(p, sid, "AllowedToAct")


def _add_ace_edges(ctx: Context, target: str, owner: str | None, aces: list[dict[str, Any]]) -> None:
    g = ctx.graph
    if owner:
        if owner not in g.nodes:
            g.add_node(owner, "foreignPrincipal", _sid_label(owner, ctx.domain_sid))
        g.add_edge(owner, target, "Owns")
    repl: dict[str, set[str]] = defaultdict(set)
    for ace in aces:
        p = ace.get("principal")
        if not p:
            continue
        kinds = acl.classify(ace)
        if not kinds:
            continue
        if p not in g.nodes:
            g.add_node(p, "foreignPrincipal", _sid_label(p, ctx.domain_sid))
        self_applies = acl.applies_to_self(ace)
        for k in kinds:
            if k in ("GetChanges", "GetChangesAll"):
                if self_applies:
                    repl[p].add(k)
                continue
            if k in ("GenericAll", "AllExtendedRights") and self_applies and g.kind(target) == "domain":
                repl[p].add("GetChanges")
                repl[p].add("GetChangesAll")
            g.add_edge(p, target, k, inheritance=[str(ace.get("inheritanceType") or "None")],
                       appliesToSelf=self_applies,
                       inheritedObjectType=[ace.get("inheritedObjectTypeName") or "any"] if not self_applies else [],
                       right=[ace.get("objectTypeName") or ace.get("rights")])
    for p, rights in repl.items():
        if {"GetChanges", "GetChangesAll"} <= rights and g.kind(target) == "domain":
            g.add_edge(p, target, "DCSync")


def _load_adcs(ctx: Context) -> None:
    for r in ctx.rows("adcs_cas"):
        nid = _node_for_dn(ctx, r["distinguishedName"], "enterpriseCA", r.get("name"), dnsHostName=r.get("dnsHostName"))
        _add_ace_edges(ctx, nid, r.get("owner"), r.get("aces") or [])
    for r in ctx.rows("adcs_templates"):
        nid = _node_for_dn(ctx, r["distinguishedName"], "certTemplate", r.get("name"), **_light(r))
        _add_ace_edges(ctx, nid, r.get("owner"), r.get("aces") or [])
    for r in ctx.rows("adcs_containers"):
        nid = _node_for_dn(ctx, r["distinguishedName"], "pkiContainer", r.get("name"))
        _add_ace_edges(ctx, nid, r.get("owner"), r.get("aces") or [])
    for r in ctx.rows("adcs_cas"):
        ca = ctx.dn_index[r["distinguishedName"].lower()]
        for tname in r.get("certificateTemplates") or []:
            for t in ctx.rows("adcs_templates"):
                if t.get("name") == tname:
                    ctx.graph.add_edge(ca, ctx.dn_index[t["distinguishedName"].lower()], "Publishes")


def _load_entra(ctx: Context) -> None:
    g = ctx.graph
    for r in ctx.rows("entra_users"):
        nid = f"entra:{r['id']}"
        ctx.entra[nid] = r
        g.add_node(nid, "entraUser", r.get("userPrincipalName") or r.get("displayName"), **_light(r))
        sid = r.get("onPremisesSecurityIdentifier")
        if sid and r.get("onPremisesSyncEnabled") and sid in g.nodes:
            g.add_edge(sid, nid, "SyncedTo")
    for r in ctx.rows("entra_groups"):
        nid = f"entra:{r['id']}"
        ctx.entra[nid] = r
        g.add_node(nid, "entraGroup", r.get("displayName"), **_light(r))
    for r in ctx.rows("entra_service_principals"):
        nid = f"entra:{r['id']}"
        ctx.entra[nid] = r
        g.add_node(nid, "servicePrincipal", r.get("displayName"), **_light(r))
    sp_by_appid = {r.get("appId"): f"entra:{r['id']}" for r in ctx.rows("entra_service_principals") if r.get("appId")}
    for r in ctx.rows("entra_applications"):
        nid = f"entra:{r['id']}"
        ctx.entra[nid] = r
        g.add_node(nid, "application", r.get("displayName"), **_light(r))
        if r.get("appId") in sp_by_appid:
            g.add_edge(nid, sp_by_appid[r["appId"]], "AppIdentity")

    for r in ctx.rows("entra_group_memberships"):
        gid = f"entra:{r['groupId']}"
        for m in r.get("transitiveMembers") or []:
            g.add_edge(f"entra:{m['id']}", gid, "EntraMemberOf")
        for o in r.get("owners") or []:
            g.add_edge(f"entra:{o['id']}", gid, "Owns")
    for ds, key in (("entra_application_owners", "applicationId"), ("entra_sp_owners", "servicePrincipalId")):
        for r in ctx.rows(ds):
            for o in r.get("owners") or []:
                g.add_edge(f"entra:{o['id']}", f"entra:{r[key]}", "Owns")

    # permission catalog: appRole / scope id -> value
    for r in ctx.rows("entra_permission_catalog"):
        for a in r.get("appRoles") or []:
            ctx.catalog[str(a.get("id"))] = str(a.get("value"))
    for r in ctx.rows("entra_app_role_assignments"):
        perm = ctx.catalog.get(str(r.get("appRoleId")), str(r.get("appRoleId")))
        g.add_edge(f"entra:{r['principalId']}", f"entra:{r['resourceId']}", "AppRole", permission=[perm])
    for r in ctx.rows("entra_oauth2_grants"):
        g.add_edge(f"entra:{r['clientId']}", f"entra:{r['resourceId']}", "OAuthGrant",
                   consentType=[r.get("consentType")], scope=sorted(set(str(r.get("scope") or "").split())))

    # directory roles
    for r in ctx.rows("entra_role_definitions"):
        ctx.role_names[r["id"]] = r.get("displayName") or r["id"]
    permanent: dict[tuple[str, str], bool] = {}
    for r in ctx.rows("entra_pim_assignments"):
        exp = ((r.get("scheduleInfo") or {}).get("expiration") or {}).get("type")
        permanent[(r.get("principalId"), r.get("roleDefinitionId"))] = (exp in (None, "noExpiration")) and r.get("assignmentType") != "Activated"
    for ds, source in (("entra_role_assignments", "active"), ("entra_pim_eligibility", "eligible")):
        for r in ctx.rows(ds):
            rd = r.get("roleDefinitionId")
            pid = r.get("principalId")
            if not rd or not pid:
                continue
            name = ctx.role_names.get(rd) or known.ENTRA_TIER0_ROLES.get(rd) or known.ENTRA_HIGH_ROLES.get(rd) or rd
            role = f"entra-role:{rd}"
            g.add_node(role, "entraRole", name)
            g.add_edge(f"entra:{pid}", role, "HasRole", source=[source], scope=[r.get("directoryScopeId") or "/"])
            tier = role_tier(rd, name)
            if tier is None:
                continue
            perm = permanent.get((pid, rd)) if source == "active" else False
            entry = {"roleId": rd, "role": name, "tier": tier, "source": source,
                     "scope": r.get("directoryScopeId") or "/", "permanent": perm, "via": None}
            ctx.entra_priv[f"entra:{pid}"].append(entry)
            for m in g.members(f"entra:{pid}", kinds=("EntraMemberOf",)):
                ctx.entra_priv[m].append(dict(entry, via=f"entra:{pid}"))


def role_tier(role_id: str, name: str | None = None) -> str | None:
    if role_id in known.ENTRA_TIER0_ROLES or (name and name in known.ENTRA_TIER0_ROLES.values()):
        return "tier0"
    if role_id in known.ENTRA_HIGH_ROLES or (name and name in known.ENTRA_HIGH_ROLES.values()):
        return "high"
    return None


def _compute_tier0(ctx: Context) -> None:
    g = ctx.graph
    for nid, node in g.nodes.items():
        if not nid.startswith("S-1-"):
            continue
        rid = rid_of(nid)
        name = str(node.get("label") or "").lower()
        if (nid in known.TIER0_BUILTIN_SIDS or (rid in known.TIER0_DOMAIN_RIDS and node["kind"] in ("group", "foreignPrincipal"))
                or (node["kind"] == "group" and name in known.TIER0_GROUP_NAMES)):
            ctx.tier0_groups[nid] = node["label"]
    for gid in ctx.tier0_groups:
        ctx.tier0.add(gid)
        ctx.tier0 |= {m for m in g.members(gid) if m.startswith("S-1-")}
    ctx.tier0 |= ctx.dc_sids
    # Anyone who can DCSync holds every password hash in the domain: Tier0-equivalent.
    if ctx.domain_sid:
        for e in g.edges_in(ctx.domain_sid, ["DCSync"]):
            if e.src.startswith("S-1-"):
                ctx.tier0.add(e.src)
                ctx.tier0 |= {m for m in g.members(e.src) if m.startswith("S-1-")}
    if ctx.domain_sid:
        ctx.tier0.add(f"{ctx.domain_sid}-502")  # krbtgt
    for sid in ctx.tier0:
        if sid in g.nodes:
            g.nodes[sid]["tier0"] = True


def build_context(rnd: Round) -> Context:
    ctx = Context(rnd)
    _load_ad(ctx)
    _load_adcs(ctx)
    _load_entra(ctx)
    _compute_tier0(ctx)
    return ctx
