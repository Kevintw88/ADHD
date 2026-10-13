"""MCP：entra-graph（唯讀）——租戶概況、特權角色、條件式存取、高風險服務主體。"""

from __future__ import annotations

from .. import services
from ..backends.graph_builder import DANGEROUS_APP_PERMS, TIER0_ROLES
from ._common import READ_ONLY, audited, create_server

NAME = "entra-graph"
server = create_server(NAME, "唯讀查詢各法人 Entra ID 租戶設定、特權角色、條件式存取與服務主體權限。不提供任何寫入功能。")


def _entra(entity: str):
    e = services.backend(entity).entra_snapshot()
    if not e.tenant_present:
        raise ValueError(f"{entity} 沒有 Entra 租戶")
    return e


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def get_tenant_overview(entity: str) -> dict:
    """租戶概況：同步工具、驗證方式、Seamless SSO、授權、訪客數。"""
    e = _entra(entity)
    return {"tenant_id": e.tenant_id, "sync": e.sync.model_dump(), "licenses": e.licenses,
            "guests": e.guests_count, "ca_policies": len(e.conditional_access)}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_privileged_roles(entity: str) -> dict:
    """特權角色成員：常駐指派與 PIM 合格指派，並標示是否為 Tier 0 角色。"""
    e = _entra(entity)
    return {"roles": [{"role": r.role, "tier0": r.role.lower() in TIER0_ROLES,
                       "permanent": r.members, "pim_eligible": r.pim_eligible} for r in e.privileged_roles]}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def review_conditional_access(entity: str) -> dict:
    """條件式存取原則與常見缺口：僅報告模式、排除帳號、未涵蓋全員的 MFA。"""
    e = _entra(entity)
    issues = []
    for p in e.conditional_access:
        if p.state != "enabled":
            issues.append(f"「{p.name}」為 {p.state}，未實際強制")
        if p.excluded_users:
            issues.append(f"「{p.name}」排除 {len(p.excluded_users)} 個帳號：{', '.join(p.excluded_users)}")
    if not any(p.state == "enabled" and p.requires_mfa and p.includes_all_users for p in e.conditional_access):
        issues.append("沒有對全員強制 MFA 的已啟用原則")
    return {"policies": [p.model_dump() for p in e.conditional_access], "issues": issues}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_risky_service_principals(entity: str) -> dict:
    """具可提權應用程式權限的服務主體及其擁有者（擁有者可新增密鑰取得該權限）。"""
    e = _entra(entity)
    rows = [{"name": sp.name, "dangerous_permissions": sorted(DANGEROUS_APP_PERMS & set(sp.app_permissions)),
             "owners": sp.owners}
            for sp in e.service_principals if DANGEROUS_APP_PERMS & set(sp.app_permissions)]
    return {"count": len(rows), "service_principals": rows}


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
