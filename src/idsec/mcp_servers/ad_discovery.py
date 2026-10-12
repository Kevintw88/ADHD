"""MCP：ad-discovery（唯讀）——法人清單、環境指紋、能力矩陣、AD 帳號與委派現況。"""

from __future__ import annotations

from .. import services
from ._common import READ_ONLY, audited, create_server

NAME = "ad-discovery"
server = create_server(NAME, "唯讀查詢各法人 AD 環境指紋、能力矩陣判定、特權帳號與委派設定。不提供任何寫入功能。")


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_entities() -> dict:
    """列出已設定的法人（總公司與子公司）及其後端類型。"""
    return {"entities": [{"id": e.id, "name": e.name, "backend": e.backend} for e in services.settings().entities]}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def get_fingerprint(entity: str) -> dict:
    """取得法人的環境指紋：AD 結構、混合同步、身分規模、AD CS、工具與遙測覆蓋。"""
    return services.fingerprint(entity).model_dump()


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def get_capability(entity: str) -> dict:
    """取得能力矩陣判定：Profile、啟用與未啟用模組（含原因）、缺口、額外 Tier 0。"""
    return services.capability(entity).model_dump()


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_privileged_accounts(entity: str) -> dict:
    """列出啟用中的特權帳號（adminCount=1）及其風險屬性。"""
    ad = services.backend(entity).ad_snapshot()
    rows = [{"sam": u.sam, "groups": u.groups, "has_spn": bool(u.spns), "pwd_never_expires": u.pwd_never_expires,
             "last_logon_days": u.last_logon_days}
            for u in ad.users if u.enabled and u.admin_count]
    return {"count": len(rows), "accounts": rows}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_kerberoastable(entity: str, privileged_only: bool = False) -> dict:
    """列出設有 SPN 的啟用帳號（可被 Kerberoasting）。privileged_only=True 只列特權帳號。"""
    ad = services.backend(entity).ad_snapshot()
    rows = [{"sam": u.sam, "spns": u.spns, "privileged": u.admin_count, "pwd_never_expires": u.pwd_never_expires}
            for u in ad.users if u.enabled and u.spns and u.sam.lower() != "krbtgt"
            and (u.admin_count or not privileged_only)]
    return {"count": len(rows), "accounts": rows}


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def list_delegation_and_tier0_hosts(entity: str) -> dict:
    """列出非 DC 的無限制委派主機，以及 DC、AD FS、Entra Connect、PTA、CA 等 Tier 0 主機。"""
    ad = services.backend(entity).ad_snapshot()
    return {
        "unconstrained_delegation": [c.name for c in ad.computers if c.unconstrained_delegation],
        "tier0_hosts": [{"name": c.name, "role": c.role} for c in ad.computers
                        if c.role in {"dc", "adfs", "entra-connect", "pta", "ca", "seamless-sso"}],
    }


@server.tool(annotations=READ_ONLY)
@audited(NAME)
def get_audit_policy_status(entity: str) -> dict:
    """DC 進階稽核原則與遙測覆蓋：缺哪些必要子類別、Sysmon 覆蓋、SIEM 收集狀態。"""
    return services.fingerprint(entity).telemetry


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
