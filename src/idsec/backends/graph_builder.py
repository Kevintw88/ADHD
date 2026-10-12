"""由 AD / Entra 快照推導身分圖譜。

用途：
1. 模擬資料產生器的基礎圖（再疊加 ACL 類邊）。
2. live 環境尚未接 BloodHound 時的退而求其次：只有群組成員、AD CS
   註冊權與 Entra 角色，沒有 ACL 與 Session，路徑會被低估。
"""

from __future__ import annotations

from ..models import ADSnapshot, EntraSnapshot, GraphEdge, GraphNode, IdentityGraph

TIER0_GROUPS = {"domain admins", "enterprise admins", "administrators", "schema admins", "key admins",
                "enterprise key admins", "backup operators", "server operators", "account operators"}
TIER0_ROLES = {"global administrator", "privileged role administrator", "hybrid identity administrator",
               "privileged authentication administrator", "security administrator"}
TIER0_COMPUTER_ROLES = {"dc", "adfs", "entra-connect", "pta", "ca"}

# Entra 應用程式權限中，可直接或間接提升為全域管理員的權限
DANGEROUS_APP_PERMS = {"RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
                       "Application.ReadWrite.All", "Directory.ReadWrite.All"}


def uid(kind: str, name: str, domain: str) -> str:
    return f"{kind}:{name}@{domain}".upper()


class _Builder:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: set[tuple[str, str, str]] = set()

    def node(self, node_id: str, kind: str, name: str, tier0: bool = False, enabled: bool = True) -> str:
        if node_id in self.nodes:
            n = self.nodes[node_id]
            n.tier0 = n.tier0 or tier0
        else:
            self.nodes[node_id] = GraphNode(id=node_id, kind=kind, name=name, tier0=tier0, enabled=enabled)
        return node_id

    def edge(self, src: str, dst: str, kind: str) -> None:
        self.edges.add((src, dst, kind))

    def build(self) -> IdentityGraph:
        return IdentityGraph(
            nodes=sorted(self.nodes.values(), key=lambda n: n.id),
            edges=[GraphEdge(src=s, dst=d, kind=k) for s, d, k in sorted(self.edges)],
        )


def build_graph(ad: ADSnapshot, entra: EntraSnapshot | None = None) -> IdentityGraph:
    b = _Builder()
    dom = ad.domains[0].name if ad.domains else ad.forest
    domain_node = b.node(uid("DOMAIN", dom, dom), "Domain", dom, tier0=True)

    def group(name: str) -> str:
        return b.node(uid("GROUP", name, dom), "Group", name, tier0=name.lower() in TIER0_GROUPS)

    # Tier 0 群組對網域有完全控制
    for g in ("Domain Admins", "Enterprise Admins", "Administrators"):
        b.edge(group(g), domain_node, "GenericAll")
    domain_users = group("Domain Users")

    for u in ad.users:
        n = b.node(uid("USER", u.sam, dom), "User", u.sam, enabled=u.enabled)
        b.edge(n, domain_users, "MemberOf")
        for g in u.groups:
            b.edge(n, group(g), "MemberOf")

    for child, parents in ad.group_parents.items():
        for p in parents:
            b.edge(group(child), group(p), "MemberOf")

    for c in ad.computers:
        tier0 = c.role in TIER0_COMPUTER_ROLES
        n = b.node(uid("COMPUTER", c.name, dom), "Computer", c.name, tier0=tier0)
        if c.role == "dc":
            b.edge(n, domain_node, "DCSync")
        if c.role in {"entra-connect", "adfs", "pta"} and entra and entra.tenant_present:
            tenant = b.node(uid("AZTENANT", entra.tenant_id or "tenant", dom), "AZTenant",
                            entra.tenant_id or "tenant", tier0=True)
            # 同步層主機可取得雲端身分控制權（PHS 雜湊、AD FS 簽章、PTA 驗證）
            b.edge(n, tenant, "HybridControl")

    if ad.adcs.present:
        for t in ad.adcs.templates:
            if t.enrollee_supplies_subject and t.client_auth and not t.manager_approval:
                tpl = b.node(uid("CERTTEMPLATE", t.name, dom), "CertTemplate", t.name)
                b.edge(tpl, domain_node, "ADCSESC1")
                for p in t.enroll_principals:
                    b.edge(group(p), tpl, "Enroll")

    if entra and entra.tenant_present:
        tenant = b.node(uid("AZTENANT", entra.tenant_id or "tenant", dom), "AZTenant",
                        entra.tenant_id or "tenant", tier0=True)
        for ra in entra.privileged_roles:
            role = b.node(uid("AZROLE", ra.role, dom), "AZRole", ra.role, tier0=ra.role.lower() in TIER0_ROLES)
            if ra.role.lower() in TIER0_ROLES:
                b.edge(role, tenant, "AZGlobalControl")
            for m in ra.members + ra.pim_eligible:
                u = b.node(uid("AZUSER", m, dom), "AZUser", m)
                b.edge(u, role, "AZHasRole")
        for sp in entra.service_principals:
            spn = b.node(uid("AZSP", sp.name, dom), "AZServicePrincipal", sp.name)
            if DANGEROUS_APP_PERMS & set(sp.app_permissions):
                b.edge(spn, tenant, "AZDangerousAppPermission")
            for o in sp.owners:
                b.edge(b.node(uid("AZUSER", o, dom), "AZUser", o), spn, "AZOwns")

    return b.build()
