"""模擬資料產生器：三個法人，各自對應 Profile A / B / C，並刻意埋入可驗證的弱點。

hq     混合（Entra Connect + PHS + Seamless SSO）、MDI、SIEM、AD CS ESC1 範本、雲端 App 提權路徑
sub-a  混合（AD FS）、無 MDI、無 SIEM、ACL 濫用路徑
sub-b  純地端、遙測未知、無限制委派 + 本機管理員路徑

所有名稱皆為虛構。固定亂數種子，輸出可重現。
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from .backends.graph_builder import build_graph, uid
from .models import (
    ADCS, ADComputer, ADSnapshot, ADUser, CAPolicy, CertTemplate, Domain, DomainController,
    EntraSnapshot, GraphEdge, RoleAssignment, ServicePrincipal, SyncInfo, Tooling, SiemIngest, Trust,
)

FULL_AUDIT = {s: "Success,Failure" for s in [
    "Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations",
    "User Account Management", "Security Group Management", "Computer Account Management",
    "Directory Service Access", "Directory Service Changes", "Logon", "Special Logon",
]}


def _users(rng: random.Random, n: int, depts: list[str], stale: int, disabled: int, asrep: int) -> list[ADUser]:
    users = []
    for i in range(1, n + 1):
        users.append(ADUser(sam=f"u{i:04d}", groups=[rng.choice(depts)],
                            last_logon_days=rng.randint(0, 30)))
    for u in rng.sample(users, stale):
        u.last_logon_days = rng.randint(120, 600)
    for u in rng.sample(users, disabled):
        u.enabled = False
    for u in rng.sample([u for u in users if u.enabled], asrep):
        u.dont_require_preauth = True
    return users


def _workstations(prefix: str, n: int) -> list[ADComputer]:
    return [ADComputer(name=f"{prefix}{i:03d}", os="Windows 11 Enterprise", role="workstation") for i in range(1, n + 1)]


def _rule(rid: str, points: int, category: str, model: str, rationale: str) -> str:
    return (f"    <HealthcheckRiskRule>\n      <Points>{points}</Points>\n      <Category>{category}</Category>\n"
            f"      <Model>{model}</Model>\n      <RiskId>{rid}</RiskId>\n      <Rationale>{rationale}</Rationale>\n"
            f"    </HealthcheckRiskRule>")


def _pingcastle(domain: str, rules: list[tuple]) -> str:
    body = "\n".join(_rule(*r) for r in rules)
    score = min(100, sum(r[1] for r in rules))
    return (f'<?xml version="1.0" encoding="utf-8"?>\n<HealthcheckData>\n  <DomainFQDN>{domain}</DomainFQDN>\n'
            f"  <GenerationDate>2026-10-01T09:00:00</GenerationDate>\n  <GlobalScore>{score}</GlobalScore>\n"
            f"  <RiskRules>\n{body}\n  </RiskRules>\n</HealthcheckData>\n")


def _synced_edges(ad: ADSnapshot, entra: EntraSnapshot, dom: str) -> list[GraphEdge]:
    """PHS / AD FS 下，地端帳號被控制即等同控制同名雲端帳號。"""
    upns = [m for r in entra.privileged_roles for m in r.members + r.pim_eligible]
    upns += [o for sp in entra.service_principals for o in sp.owners]
    by_local = {upn.split("@")[0].lower(): upn for upn in upns}
    return [GraphEdge(src=uid("USER", u.sam, dom), dst=uid("AZUSER", by_local[u.sam.lower()], dom),
                      kind="SyncedToEntraUser")
            for u in ad.users if u.sam.lower() in by_local]


def _graph(ad: ADSnapshot, entra: EntraSnapshot, planted: list[tuple[str, str, str]]) -> dict:
    dom = ad.domains[0].name
    g = build_graph(ad, entra)
    ids = {n.id for n in g.nodes}
    for src, dst, kind in planted:
        for x in (src, dst):
            if x not in ids:
                raise ValueError(f"埋入的邊引用不存在的節點：{x}")
        g.edges.append(GraphEdge(src=src, dst=dst, kind=kind))
    if entra.tenant_present and entra.sync.auth in {"PHS", "ADFS", "PTA"}:
        g.edges += [e for e in _synced_edges(ad, entra, dom) if e.dst in ids]
    return g.model_dump()


# ------------------------------------------------------------------ 總公司
def _hq(rng: random.Random) -> dict:
    dom = "hq.corp.example"
    depts = ["RD", "Sales", "HR", "Finance", "Manufacturing"]
    users = _users(rng, 240, depts, stale=28, disabled=14, asrep=2)
    users += [
        ADUser(sam="adm.chen", admin_count=True, groups=["Domain Admins"], last_logon_days=1),
        ADUser(sam="adm.wang", admin_count=True, pwd_never_expires=True, groups=["Domain Admins"], last_logon_days=3),
        ADUser(sam="svc_sql", admin_count=True, spns=["MSSQLSvc/srv-sql01.hq.corp.example:1433"],
               pwd_never_expires=True, groups=["Domain Admins"], last_logon_days=0),
        ADUser(sam="svc_backup", admin_count=True, spns=["backup/srv-bak01.hq.corp.example"],
               groups=["Backup Operators"], last_logon_days=0),
        ADUser(sam="svc_web", spns=["HTTP/intranet.hq.corp.example"], groups=["Server-Admins"], last_logon_days=0),
        ADUser(sam="helpdesk.lee", groups=["IT-Helpdesk"], last_logon_days=0),
        ADUser(sam="helpdesk.wu", groups=["IT-Helpdesk"], last_logon_days=2),
        ADUser(sam="ops.kao", groups=["IT-Ops"], last_logon_days=1),
        ADUser(sam="dev.lin", groups=["RD"], last_logon_days=0),
        ADUser(sam="it-cloudadmin", groups=["IT-Ops"], last_logon_days=4),
    ]
    computers = [
        ADComputer(name="DC01", os="Windows Server 2022 Standard", role="dc"),
        ADComputer(name="DC02", os="Windows Server 2022 Standard", role="dc"),
        ADComputer(name="SRV-AADC01", os="Windows Server 2022 Standard", role="entra-connect"),
        ADComputer(name="SRV-CA01", os="Windows Server 2019 Standard", role="ca"),
        ADComputer(name="AZUREADSSOACC", role="seamless-sso"),
        ADComputer(name="SRV-APP01", os="Windows Server 2016 Standard", role="server", unconstrained_delegation=True),
        ADComputer(name="SRV-SQL01", os="Windows Server 2019 Standard", role="server"),
    ] + _workstations("HQ-WS", 40)
    ad = ADSnapshot(
        forest=dom,
        domains=[Domain(name=dom, functional_level="2016",
                        dcs=[DomainController(name="DC01", os="Windows Server 2022 Standard"),
                             DomainController(name="DC02", os="Windows Server 2022 Standard")])],
        trusts=[Trust(source=dom, target="suba.corp.example", direction="bidirectional", sid_filtering=True),
                Trust(source=dom, target="legacy.local", direction="bidirectional", sid_filtering=False)],
        users=users,
        group_parents={"Server-Admins": ["IT-Ops"]},
        computers=computers,
        gmsa_count=3,
        adcs=ADCS(present=True, cas=["HQ-ISSUING-CA"], templates=[
            CertTemplate(name="User", client_auth=True, enroll_principals=["Domain Users"]),
            CertTemplate(name="WebServer", enrollee_supplies_subject=True, enroll_principals=["Server-Admins"]),
            CertTemplate(name="VPNUser", enrollee_supplies_subject=True, client_auth=True,
                         enroll_principals=["Domain Users"]),
        ]),
        audit_policy={**FULL_AUDIT, "Certification Services": ""},
    )
    entra = EntraSnapshot(
        tenant_present=True, tenant_id="hq-tenant",
        sync=SyncInfo(tool="EntraConnect", auth="PHS", seamless_sso=True),
        licenses=["SPE_E5"],
        conditional_access=[
            CAPolicy(name="全員 MFA", includes_all_users=True, requires_mfa=True, excluded_users=["breakglass01"]),
            CAPolicy(name="封鎖舊版驗證", includes_all_users=True),
        ],
        privileged_roles=[
            RoleAssignment(role="Global Administrator", members=["it-cloudadmin@hq.corp.example",
                                                                 "breakglass01@hq.corp.example"],
                           pim_eligible=["adm.chen@hq.corp.example"]),
            RoleAssignment(role="Application Administrator", members=["helpdesk.lee@hq.corp.example"]),
        ],
        service_principals=[
            ServicePrincipal(name="HR-Sync-App", app_permissions=["User.Read.All", "RoleManagement.ReadWrite.Directory"],
                             owners=["dev.lin@hq.corp.example"]),
            ServicePrincipal(name="Reporting-App", app_permissions=["Reports.Read.All"]),
        ],
        guests_count=37,
    )
    tooling = Tooling(mdi=True, edr="Defender for Endpoint", siem="Splunk",
                      siem_ingest=SiemIngest(dc_security=True, entra_signin=True, entra_audit=True),
                      sysmon_coverage=0.7)
    U = lambda k, n: uid(k, n, dom)  # noqa: E731
    planted = [
        (U("GROUP", "IT-Helpdesk"), U("GROUP", "IT-Ops"), "GenericAll"),
        (U("GROUP", "IT-Ops"), U("COMPUTER", "SRV-APP01"), "AdminTo"),
        (U("COMPUTER", "SRV-APP01"), U("USER", "adm.wang"), "HasSession"),
        (U("GROUP", "Server-Admins"), U("COMPUTER", "SRV-AADC01"), "AdminTo"),
        (U("AZROLE", "Application Administrator"), U("AZSP", "HR-Sync-App"), "AZAddSecret"),
    ]
    rules = [
        ("A-CertTempCustomSubject", 50, "Anomalies", "PrivilegeEscalation",
         "At least one certificate template used for authentication can have its subject modified when used (VPNUser)."),
        ("P-ServiceDomainAdmin", 20, "PrivilegedAccounts", "AccountTakeOver",
         "A service account with an SPN is member of Domain Admins (svc_sql)."),
        ("P-Kerberoasting", 20, "PrivilegedAccounts", "AccountTakeOver",
         "Privileged accounts can be attacked by Kerberoasting: 2 accounts."),
        ("P-UnconstrainedDelegation", 15, "PrivilegedAccounts", "DelegationCheck",
         "Presence of unconstrained delegation on computers other than DC: 1 (SRV-APP01)."),
        ("T-SIDFiltering", 15, "Trusts", "SIDFiltering",
         "Trust with legacy.local has SID Filtering disabled."),
        ("S-NoPreAuth", 10, "StaleObjects", "ObjectConfig",
         "Accounts do not require Kerberos pre-authentication: 2."),
        ("S-PwdNeverExpires", 1, "StaleObjects", "ObjectConfig",
         "Accounts with password never expires: 2."),
    ]
    return {"domain": dom, "ad": ad, "entra": entra, "tooling": tooling, "planted": planted, "rules": rules}


# ------------------------------------------------------------------ 子公司 A
def _sub_a(rng: random.Random) -> dict:
    dom = "suba.corp.example"
    users = _users(rng, 80, ["Sales", "Ops", "IT"], stale=12, disabled=5, asrep=0)
    users += [
        ADUser(sam="adm.huang", admin_count=True, pwd_never_expires=True, groups=["Domain Admins"], last_logon_days=2),
        ADUser(sam="it.chou", groups=["IT"], last_logon_days=0),
        ADUser(sam="svc_erp", spns=["HTTP/erp.suba.corp.example"], groups=["Ops"], last_logon_days=0),
    ]
    computers = [
        ADComputer(name="SUBA-DC01", os="Windows Server 2016 Standard", role="dc"),
        ADComputer(name="SRV-ADFS01", os="Windows Server 2016 Standard", role="adfs"),
        ADComputer(name="SRV-AADC-A", os="Windows Server 2019 Standard", role="entra-connect"),
    ] + _workstations("SUBA-WS", 15)
    audit = {k: v for k, v in FULL_AUDIT.items()
             if k not in {"Kerberos Service Ticket Operations", "Directory Service Access", "Directory Service Changes",
                          "Security Group Management", "Special Logon"}}
    ad = ADSnapshot(
        forest=dom,
        domains=[Domain(name=dom, functional_level="2012 R2",
                        dcs=[DomainController(name="SUBA-DC01", os="Windows Server 2016 Standard")])],
        trusts=[Trust(source=dom, target="hq.corp.example", direction="bidirectional", sid_filtering=True)],
        users=users, computers=computers, gmsa_count=0, audit_policy=audit,
    )
    entra = EntraSnapshot(
        tenant_present=True, tenant_id="suba-tenant",
        sync=SyncInfo(tool="EntraConnect", auth="ADFS", seamless_sso=False),
        licenses=["AAD_PREMIUM"],
        conditional_access=[CAPolicy(name="管理員 MFA", state="enabledForReportingButNotEnforced", requires_mfa=True)],
        privileged_roles=[RoleAssignment(role="Global Administrator",
                                         members=["adm.huang@suba.corp.example", "it.chou@suba.corp.example",
                                                  "vendor.support@suba.corp.example"])],
        guests_count=8,
    )
    tooling = Tooling(mdi=False, edr="Trend Micro Apex One", siem=None, sysmon_coverage=0.1)
    U = lambda k, n: uid(k, n, dom)  # noqa: E731
    planted = [
        (U("GROUP", "IT"), U("USER", "adm.huang"), "GenericAll"),
        (U("GROUP", "Domain Users"), U("COMPUTER", "SUBA-WS005"), "AdminTo"),
        (U("COMPUTER", "SUBA-WS005"), U("USER", "adm.huang"), "HasSession"),
    ]
    rules = [
        ("P-ControlPathIndirectEveryone", 30, "PrivilegedAccounts", "ControlPath",
         "Non-privileged group IT has GenericAll on a Domain Admin account."),
        ("A-DCLdapSign", 15, "Anomalies", "NetworkSniffing", "LDAP signing is not required on domain controllers."),
        ("A-LAPS-NotInstalled", 15, "Anomalies", "PassTheCredential", "LAPS is not deployed."),
        ("S-SMB-v1", 10, "StaleObjects", "OldAuthenticationProtocols", "SMB v1 is enabled on SUBA-DC01."),
        ("P-AdminPwdTooOld", 10, "PrivilegedAccounts", "AccountTakeOver",
         "The password of a Domain Admin account has not been changed for more than 3 years."),
    ]
    return {"domain": dom, "ad": ad, "entra": entra, "tooling": tooling, "planted": planted, "rules": rules}


# ------------------------------------------------------------------ 子公司 B
def _sub_b(rng: random.Random) -> dict:
    dom = "subb.local"
    users = _users(rng, 40, ["Plant", "Admin"], stale=9, disabled=3, asrep=1)
    users += [
        ADUser(sam="administrator", admin_count=True, pwd_never_expires=True, groups=["Domain Admins"],
               last_logon_days=0),
        ADUser(sam="svc_mes", admin_count=True, spns=["MES/srv-mes01.subb.local"], groups=["Domain Admins"],
               pwd_never_expires=True, last_logon_days=0),
    ]
    computers = [
        ADComputer(name="SUBB-DC01", os="Windows Server 2012 R2 Standard", role="dc"),
        ADComputer(name="SRV-FILE01", os="Windows Server 2012 R2 Standard", role="server",
                   unconstrained_delegation=True),
        ADComputer(name="SRV-MES01", os="Windows Server 2016 Standard", role="server"),
    ] + _workstations("SUBB-WS", 10)
    ad = ADSnapshot(
        forest=dom,
        domains=[Domain(name=dom, functional_level="2008 R2",
                        dcs=[DomainController(name="SUBB-DC01", os="Windows Server 2012 R2 Standard")])],
        users=users, computers=computers, audit_policy=None,
    )
    entra = EntraSnapshot(tenant_present=False)
    tooling = Tooling(mdi=False, edr=None, siem=None, sysmon_coverage=None)
    U = lambda k, n: uid(k, n, dom)  # noqa: E731
    planted = [
        (U("GROUP", "Domain Users"), U("COMPUTER", "SRV-FILE01"), "AdminTo"),
        (U("COMPUTER", "SRV-FILE01"), U("USER", "administrator"), "HasSession"),
    ]
    rules = [
        ("P-ServiceDomainAdmin", 20, "PrivilegedAccounts", "AccountTakeOver",
         "A service account with an SPN is member of Domain Admins (svc_mes)."),
        ("P-UnconstrainedDelegation", 15, "PrivilegedAccounts", "DelegationCheck",
         "Presence of unconstrained delegation on computers other than DC: 1 (SRV-FILE01)."),
        ("A-LAPS-NotInstalled", 15, "Anomalies", "PassTheCredential", "LAPS is not deployed."),
        ("S-SMB-v1", 10, "StaleObjects", "OldAuthenticationProtocols", "SMB v1 is enabled on SUBB-DC01."),
        ("A-NoServicePolicy", 5, "Anomalies", "PasswordPolicy",
         "No password policy for service accounts found (MinimumPasswordLength >= 20)."),
    ]
    return {"domain": dom, "ad": ad, "entra": entra, "tooling": tooling, "planted": planted, "rules": rules}


ENTITIES = {"hq": _hq, "sub-a": _sub_a, "sub-b": _sub_b}


def generate(out_root: str | Path, seed: int = 20261012) -> list[Path]:
    out_root = Path(out_root)
    written = []
    for name, fn in ENTITIES.items():
        rng = random.Random(f"{seed}-{name}")
        spec = fn(rng)
        d = out_root / name
        (d / "reports").mkdir(parents=True, exist_ok=True)
        files = {
            "ad.json": spec["ad"].model_dump(),
            "entra.json": spec["entra"].model_dump(),
            "tooling.json": spec["tooling"].model_dump(),
            "graph.json": _graph(spec["ad"], spec["entra"], spec["planted"]),
        }
        for fname, data in files.items():
            (d / fname).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
            written.append(d / fname)
        xml = d / "reports" / f"ad_hc_{spec['domain']}.xml"
        xml.write_text(_pingcastle(spec["domain"], spec["rules"]), encoding="utf-8")
        written.append(xml)
    return written
