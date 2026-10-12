"""實機後端（唯讀）。

⚠ 本模組尚未在實機 AD / Entra 驗證，請先於 LAB 測試。

- AD：ldap3 分頁查詢，只用 search，不呼叫任何 modify / add / delete。
- Entra：Microsoft Graph，只呼叫 GET；建議以憑證驗證的唯讀 App
  （Directory.Read.All、Policy.Read.All、RoleManagement.Read.Directory、
  Application.Read.All、Organization.Read.All）。
- 身分圖譜：優先讀 BloodHound CE 的 Neo4j；未設定時退回快照推導（無 ACL 邊）。
- LDAP 讀不到的資訊（稽核原則、Sysmon 覆蓋率、AD FS / PTA 主機、SIEM 現況）
  由 IT 填寫 tooling_file（YAML，欄位見 config/tooling.example.yaml）。
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from functools import cached_property
from typing import Any

import yaml

from ..config import EntityConfig
from ..models import (
    ADCS, ADComputer, ADSnapshot, ADUser, CAPolicy, CertTemplate, Domain, DomainController,
    EntraSnapshot, GraphEdge, GraphNode, IdentityGraph, RoleAssignment, ServicePrincipal,
    SyncInfo, Tooling, Trust,
)
from .graph_builder import build_graph

log = logging.getLogger(__name__)

UAC_DISABLED = 0x2
UAC_SERVER_TRUST = 0x2000
UAC_DONT_EXPIRE = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000

FUNCTIONAL_LEVELS = {0: "2000", 1: "2003 interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012",
                     6: "2012 R2", 7: "2016", 10: "2025"}
CLIENT_AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0"}
MSOL_DESC = re.compile(r"running on computer (\S+)", re.IGNORECASE)


def _cn(dn: str) -> str:
    m = re.match(r"CN=((?:\\,|[^,])+)", dn, re.IGNORECASE)
    return m.group(1).replace("\\,", ",") if m else dn


def _val(entry: Any, attr: str, default: Any = None) -> Any:
    try:
        v = entry[attr].value
    except (KeyError, IndexError, AttributeError):
        return default
    return default if v in (None, []) else v


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _days_since(v: Any) -> int | None:
    if isinstance(v, datetime):
        if v.year < 1700:
            return None
        return (datetime.now(timezone.utc) - v.astimezone(timezone.utc)).days
    return None


class _Ldap:
    def __init__(self, entity: EntityConfig):
        from ldap3 import ALL, NTLM, SIMPLE, Connection, Server

        cfg = entity.ldap
        assert cfg is not None
        user = os.environ.get(cfg.user_env)
        password = os.environ.get(cfg.password_env)
        server = Server(cfg.server, use_ssl=cfg.use_ssl, get_info=ALL)
        auth = NTLM if user and "\\" in user else SIMPLE
        self.conn = Connection(server, user=user, password=password, authentication=auth,
                               read_only=True, auto_bind=True)
        self.base = cfg.base_dn
        self.config_nc = f"CN=Configuration,{self.base}"
        self.info = server.info

    def search(self, filt: str, attrs: list[str], base: str | None = None) -> list:
        from ldap3 import SUBTREE

        entries = self.conn.extend.standard.paged_search(
            base or self.base, filt, search_scope=SUBTREE, attributes=attrs, paged_size=500, generator=False)
        return [e for e in entries if e.get("type") == "searchResEntry"]


class LiveBackend:
    def __init__(self, entity: EntityConfig):
        self.entity = entity

    # ------------------------------------------------------------ tooling 檔
    @cached_property
    def _tooling_raw(self) -> dict:
        p = self.entity.path(self.entity.tooling_file)
        if p is None or not p.exists():
            log.warning("未提供 tooling_file，工具與遙測欄位將視為未知")
            return {}
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    def tooling(self) -> Tooling:
        raw = {k: v for k, v in self._tooling_raw.items() if k in Tooling.model_fields}
        t = Tooling.model_validate(raw)
        if not t.mdi and any("ATA" in s or "DEFENDER_FOR_IDENTITY" in s for s in self.entra_snapshot().licenses):
            log.info("租戶有 MDI 授權，但 tooling_file 標示未部署，以 tooling_file 為準")
        return t

    # ------------------------------------------------------------ AD
    @cached_property
    def _ad(self) -> ADSnapshot:
        if self.entity.ldap is None:
            raise ValueError(f"{self.entity.id} 未設定 ldap")
        l = _Ldap(self.entity)
        domain_name = ".".join(p.split("=", 1)[1] for p in self.entity.ldap.base_dn.split(","))
        level = None
        if l.info and l.info.other.get("domainFunctionality"):
            level = FUNCTIONAL_LEVELS.get(int(l.info.other["domainFunctionality"][0]))

        users: list[ADUser] = []
        for e in l.search("(&(objectCategory=person)(objectClass=user))",
                          ["sAMAccountName", "userAccountControl", "adminCount", "servicePrincipalName",
                           "lastLogonTimestamp", "memberOf"]):
            a = e["attributes"]
            uac = int(a.get("userAccountControl") or 0)
            users.append(ADUser(
                sam=a.get("sAMAccountName"),
                enabled=not uac & UAC_DISABLED,
                admin_count=bool(a.get("adminCount")),
                spns=[s for s in _as_list(a.get("servicePrincipalName"))],
                pwd_never_expires=bool(uac & UAC_DONT_EXPIRE),
                dont_require_preauth=bool(uac & UAC_DONT_REQ_PREAUTH),
                last_logon_days=_days_since(a.get("lastLogonTimestamp")),
                groups=[_cn(g) for g in _as_list(a.get("memberOf"))],
            ))

        group_parents: dict[str, list[str]] = {}
        for e in l.search("(&(objectClass=group)(memberOf=*))", ["cn", "memberOf"]):
            a = e["attributes"]
            group_parents[a.get("cn")] = [_cn(g) for g in _as_list(a.get("memberOf"))]

        hybrid_hosts = self._tooling_raw.get("hybrid_hosts", {})
        role_override = {h.lower(): role for role, hosts in hybrid_hosts.items() for h in hosts}
        for e in l.search("(&(objectClass=user)(sAMAccountName=MSOL_*))", ["description"]):
            m = MSOL_DESC.search(str(e["attributes"].get("description") or ""))
            if m:
                role_override.setdefault(m.group(1).lower(), "entra-connect")

        cas, ca_hosts, published = [], set(), set()
        pki = f"CN=Public Key Services,CN=Services,{l.config_nc}"
        try:
            for e in l.search("(objectClass=pKIEnrollmentService)", ["cn", "dNSHostName", "certificateTemplates"],
                              base=f"CN=Enrollment Services,{pki}"):
                a = e["attributes"]
                cas.append(a.get("cn"))
                if a.get("dNSHostName"):
                    ca_hosts.add(str(a["dNSHostName"]).split(".")[0].lower())
                published.update(_as_list(a.get("certificateTemplates")))
        except Exception as exc:  # 沒有 AD CS 時容器不存在
            log.info("未找到 AD CS：%s", exc)

        templates = []
        if published:
            for e in l.search("(objectClass=pKICertificateTemplate)",
                              ["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage"],
                              base=f"CN=Certificate Templates,{pki}"):
                a = e["attributes"]
                if a.get("cn") not in published:
                    continue
                ekus = set(_as_list(a.get("pKIExtendedKeyUsage")))
                templates.append(CertTemplate(
                    name=a.get("cn"),
                    enrollee_supplies_subject=bool(int(a.get("msPKI-Certificate-Name-Flag") or 0) & 1),
                    client_auth=not ekus or bool(ekus & CLIENT_AUTH_EKUS),
                    manager_approval=bool(int(a.get("msPKI-Enrollment-Flag") or 0) & 2),
                    # 註冊權需解析 nTSecurityDescriptor；MVP 交由 BloodHound CE / Locksmith 判定
                    enroll_principals=[],
                ))

        computers: list[ADComputer] = []
        dcs: list[DomainController] = []
        for e in l.search("(objectClass=computer)", ["cn", "operatingSystem", "userAccountControl"]):
            a = e["attributes"]
            name, uac = a.get("cn"), int(a.get("userAccountControl") or 0)
            os_name = a.get("operatingSystem") or ""
            if uac & UAC_SERVER_TRUST:
                role = "dc"
                dcs.append(DomainController(name=name, os=os_name))
            elif name.lower() in role_override:
                role = role_override[name.lower()]
            elif name.lower() in ca_hosts:
                role = "ca"
            elif name.upper() == "AZUREADSSOACC":
                role = "seamless-sso"
            else:
                role = "server" if "server" in os_name.lower() else "workstation"
            computers.append(ADComputer(name=name, os=os_name, role=role,
                                        unconstrained_delegation=bool(uac & UAC_TRUSTED_FOR_DELEGATION)
                                        and role != "dc"))

        trusts = [
            Trust(source=domain_name, target=e["attributes"].get("trustPartner"),
                  direction={1: "inbound", 2: "outbound", 3: "bidirectional"}.get(
                      int(e["attributes"].get("trustDirection") or 0), "unknown"),
                  sid_filtering=bool(int(e["attributes"].get("trustAttributes") or 0) & 0x4))
            for e in l.search("(objectClass=trustedDomain)", ["trustPartner", "trustDirection", "trustAttributes"])
        ]

        gmsa = len(l.search("(objectClass=msDS-GroupManagedServiceAccount)", ["cn"]))
        return ADSnapshot(
            forest=domain_name,
            domains=[Domain(name=domain_name, functional_level=level or "", dcs=dcs)],
            trusts=trusts, users=users, group_parents=group_parents, computers=computers,
            gmsa_count=gmsa, adcs=ADCS(present=bool(cas), cas=cas, templates=templates),
            audit_policy=self._tooling_raw.get("audit_policy"),
        )

    def ad_snapshot(self) -> ADSnapshot:
        return self._ad

    # ------------------------------------------------------------ Entra
    @cached_property
    def _entra(self) -> EntraSnapshot:
        if self.entity.graph is None:
            return EntraSnapshot(tenant_present=False)
        g = _Graph(self.entity)
        org = (g.get_all("/organization") or [{}])[0]
        domains = g.get_all("/domains")
        federated = any(d.get("authenticationType") == "Federated" for d in domains)
        phs = False
        try:
            sync = g.get_all("/directory/onPremisesSynchronization")
            feats = (sync[0] if sync else {}).get("features", {})
            phs = bool(feats.get("passwordSyncEnabled"))
        except Exception as exc:
            log.info("無法讀取 onPremisesSynchronization：%s", exc)
        hybrid_hosts = self._tooling_raw.get("hybrid_hosts", {})
        auth = "ADFS" if federated else "PTA" if hybrid_hosts.get("pta") else "PHS" if phs else "None"
        seamless = any(c.role == "seamless-sso" for c in self.ad_snapshot().computers) if self.entity.ldap else False

        ca = [CAPolicy(
            name=p.get("displayName", ""),
            state=p.get("state", "enabled"),
            includes_all_users="All" in (p.get("conditions", {}).get("users", {}).get("includeUsers") or []),
            requires_mfa="mfa" in ((p.get("grantControls") or {}).get("builtInControls") or []),
            excluded_users=p.get("conditions", {}).get("users", {}).get("excludeUsers") or [],
        ) for p in g.get_all("/identity/conditionalAccess/policies")]

        roles = []
        for r in g.get_all("/directoryRoles?$expand=members"):
            roles.append(RoleAssignment(role=r.get("displayName", ""),
                                        members=[m.get("userPrincipalName") or m.get("displayName", "")
                                                 for m in r.get("members", [])]))
        try:
            by_role: dict[str, list[str]] = {}
            for s in g.get_all("/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition"):
                rn = (s.get("roleDefinition") or {}).get("displayName", "")
                pr = s.get("principal") or {}
                by_role.setdefault(rn, []).append(pr.get("userPrincipalName") or pr.get("displayName", ""))
            for ra in roles:
                ra.pim_eligible = by_role.pop(ra.role, [])
            roles += [RoleAssignment(role=k, pim_eligible=v) for k, v in by_role.items()]
        except Exception as exc:
            log.info("無法讀取 PIM 資格（可能缺授權或權限）：%s", exc)

        sps = []
        graph_sp = g.get_all("/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'")
        if graph_sp:
            role_map = {r["id"]: r["value"] for r in graph_sp[0].get("appRoles", [])}
            for sp in g.get_all("/servicePrincipals?$select=id,displayName&$top=999"):
                perms = [role_map.get(a.get("appRoleId"), a.get("appRoleId"))
                         for a in g.get_all(f"/servicePrincipals/{sp['id']}/appRoleAssignments")
                         if a.get("resourceId") == graph_sp[0]["id"]]
                if not perms:
                    continue
                owners = [o.get("userPrincipalName") or o.get("displayName", "")
                          for o in g.get_all(f"/servicePrincipals/{sp['id']}/owners")]
                sps.append(ServicePrincipal(name=sp.get("displayName", ""), app_permissions=perms, owners=owners))

        guests = g.count("/users/$count?$filter=userType eq 'Guest'")
        return EntraSnapshot(
            tenant_present=True, tenant_id=org.get("id", self.entity.graph.tenant_id),
            sync=SyncInfo(tool="EntraConnect" if org.get("onPremisesSyncEnabled") else "None",
                          auth=auth, seamless_sso=seamless),
            licenses=[s.get("skuPartNumber", "") for s in g.get_all("/subscribedSkus")],
            conditional_access=ca, privileged_roles=roles, service_principals=sps, guests_count=guests,
        )

    def entra_snapshot(self) -> EntraSnapshot:
        return self._entra

    # ------------------------------------------------------------ 圖譜
    def identity_graph(self) -> IdentityGraph:
        if self.entity.neo4j is None:
            log.warning("未設定 BloodHound Neo4j，改用快照推導圖譜（缺 ACL 與 Session 邊，路徑會被低估）")
            return build_graph(self.ad_snapshot(), self.entra_snapshot())
        return _neo4j_graph(self.entity)


class _Graph:
    BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self, entity: EntityConfig):
        import httpx
        import msal

        cfg = entity.graph
        assert cfg is not None
        if cfg.cert_path:
            cred: Any = {"private_key": open(cfg.cert_path, encoding="utf-8").read(),
                         "thumbprint": cfg.cert_thumbprint}
        else:
            cred = os.environ.get(cfg.secret_env)
        app = msal.ConfidentialClientApplication(
            cfg.client_id, authority=f"https://login.microsoftonline.com/{cfg.tenant_id}", client_credential=cred)
        token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in token:
            raise RuntimeError(f"Graph 取得權杖失敗：{token.get('error_description')}")
        self.client = httpx.Client(headers={"Authorization": f"Bearer {token['access_token']}"}, timeout=60)

    def get_all(self, path: str) -> list[dict]:
        url, items = self.BASE + path, []
        while url:
            r = self.client.get(url)  # 只有 GET
            r.raise_for_status()
            data = r.json()
            if "value" not in data:
                return [data]
            items += data["value"]
            url = data.get("@odata.nextLink")
        return items

    def count(self, path: str) -> int:
        r = self.client.get(self.BASE + path, headers={"ConsistencyLevel": "eventual"})
        return int(r.text) if r.status_code == 200 else 0


def _neo4j_graph(entity: EntityConfig) -> IdentityGraph:
    from neo4j import GraphDatabase

    cfg = entity.neo4j
    assert cfg is not None
    driver = GraphDatabase.driver(cfg.uri, auth=(cfg.user, os.environ.get(cfg.password_env, "")))
    nodes, edges = [], []
    with driver.session(default_access_mode="READ") as s:
        for rec in s.run(
            "MATCH (n) WHERE n.objectid IS NOT NULL "
            "RETURN n.objectid AS id, labels(n) AS labels, coalesce(n.name, n.objectid) AS name, "
            "coalesce(n.system_tags, '') CONTAINS 'admin_tier_0' AS tier0, coalesce(n.enabled, true) AS enabled"
        ):
            kind = next((lb for lb in rec["labels"] if lb not in {"Base", "AZBase"}), "Base")
            nodes.append(GraphNode(id=rec["id"], kind=kind, name=rec["name"], tier0=rec["tier0"],
                                   enabled=rec["enabled"]))
        for rec in s.run("MATCH (a)-[r]->(b) WHERE a.objectid IS NOT NULL AND b.objectid IS NOT NULL "
                         "RETURN a.objectid AS src, type(r) AS kind, b.objectid AS dst"):
            edges.append(GraphEdge(src=rec["src"], dst=rec["dst"], kind=rec["kind"]))
    driver.close()
    return IdentityGraph(nodes=nodes, edges=edges)
