"""共用資料模型。

所有後端（mock 與 live）都輸出同一份正規化結構，下游的指紋、能力矩陣、
路徑分析與報告只認這些模型，不直接碰 LDAP / Graph / Neo4j。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- AD 快照
class DomainController(BaseModel):
    name: str
    os: str = ""


class Domain(BaseModel):
    name: str
    functional_level: str = ""
    dcs: list[DomainController] = Field(default_factory=list)


class Trust(BaseModel):
    source: str
    target: str
    direction: str = "bidirectional"
    sid_filtering: bool = True


class ADUser(BaseModel):
    sam: str
    enabled: bool = True
    admin_count: bool = False
    spns: list[str] = Field(default_factory=list)
    pwd_never_expires: bool = False
    dont_require_preauth: bool = False
    last_logon_days: int | None = None
    groups: list[str] = Field(default_factory=list)


class ADComputer(BaseModel):
    name: str
    os: str = ""
    unconstrained_delegation: bool = False
    role: str = ""  # dc / adfs / entra-connect / pta / ca / server / workstation


class CertTemplate(BaseModel):
    name: str
    enrollee_supplies_subject: bool = False
    client_auth: bool = False
    manager_approval: bool = False
    enroll_principals: list[str] = Field(default_factory=list)


class ADCS(BaseModel):
    present: bool = False
    cas: list[str] = Field(default_factory=list)
    templates: list[CertTemplate] = Field(default_factory=list)


class ADSnapshot(BaseModel):
    forest: str
    domains: list[Domain] = Field(default_factory=list)
    trusts: list[Trust] = Field(default_factory=list)
    users: list[ADUser] = Field(default_factory=list)
    group_parents: dict[str, list[str]] = Field(default_factory=dict)  # 群組 -> 其所屬的上層群組
    computers: list[ADComputer] = Field(default_factory=list)
    gmsa_count: int = 0
    adcs: ADCS = Field(default_factory=ADCS)
    # 進階稽核原則：子類別 -> "Success" / "Failure" / "Success,Failure" / ""（未知為 None）
    audit_policy: dict[str, str] | None = None


# ---------------------------------------------------------------- Entra 快照
class SyncInfo(BaseModel):
    tool: Literal["EntraConnect", "CloudSync", "None"] = "None"
    auth: Literal["PHS", "PTA", "ADFS", "None"] = "None"
    seamless_sso: bool = False


class CAPolicy(BaseModel):
    name: str
    state: Literal["enabled", "disabled", "enabledForReportingButNotEnforced"] = "enabled"
    includes_all_users: bool = False
    requires_mfa: bool = False
    excluded_users: list[str] = Field(default_factory=list)


class RoleAssignment(BaseModel):
    role: str
    members: list[str] = Field(default_factory=list)
    pim_eligible: list[str] = Field(default_factory=list)


class ServicePrincipal(BaseModel):
    name: str
    app_permissions: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)


class EntraSnapshot(BaseModel):
    tenant_present: bool = False
    tenant_id: str = ""
    sync: SyncInfo = Field(default_factory=SyncInfo)
    licenses: list[str] = Field(default_factory=list)
    conditional_access: list[CAPolicy] = Field(default_factory=list)
    privileged_roles: list[RoleAssignment] = Field(default_factory=list)
    service_principals: list[ServicePrincipal] = Field(default_factory=list)
    guests_count: int = 0


# ---------------------------------------------------------------- 工具與遙測
class SiemIngest(BaseModel):
    dc_security: bool = False
    entra_signin: bool = False
    entra_audit: bool = False


class Tooling(BaseModel):
    mdi: bool = False
    edr: str | None = None
    siem: str | None = None
    siem_ingest: SiemIngest = Field(default_factory=SiemIngest)
    sysmon_coverage: float | None = None  # 0.0 - 1.0，未知為 None


# ---------------------------------------------------------------- 身分圖譜
class GraphNode(BaseModel):
    id: str
    kind: str
    name: str
    tier0: bool = False
    enabled: bool = True


class GraphEdge(BaseModel):
    src: str
    dst: str
    kind: str


class IdentityGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


# ---------------------------------------------------------------- 產出物
class Fingerprint(BaseModel):
    entity: str
    generated_at: str = Field(default_factory=utcnow)
    ad: dict
    hybrid: dict
    identity: dict
    services: dict
    tooling: dict
    telemetry: dict


class Gap(BaseModel):
    id: str
    title: str
    blocks: list[str] = Field(default_factory=list)  # 被這個缺口擋住的模組
    remediation: str = ""


class CapabilityResult(BaseModel):
    entity: str
    profile: str
    profile_name: str
    enabled_modules: list[str]
    disabled_modules: dict[str, str]  # module id -> 未啟用原因
    gaps: list[Gap]
    tier0_extra: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    source: str
    id: str
    title: str
    category: str = ""
    severity: Severity = "medium"
    points: int = 0
    rationale: str = ""
    scope: str = ""
    attack: list[str] = Field(default_factory=list)  # MITRE ATT&CK 技術
    priority: float = 0.0
    priority_reason: str = ""


class AttackPath(BaseModel):
    source: str
    target: str
    hops: list[GraphEdge]
    shared_by: int = 1  # 共用同一段路徑（扣除起點第一跳）的來源數

    @property
    def length(self) -> int:
        return len(self.hops)


class ChokePoint(BaseModel):
    edge: GraphEdge
    sources_cut: int
    sources_cut_pct: float
    remaining_after: int = 0  # 依序修補到這一步後，仍有路徑的來源數


class PathAnalysis(BaseModel):
    entity: str
    tier0_nodes: list[str]
    sources_total: int
    sources_with_path: int
    sample_paths: list[AttackPath]
    choke_points: list[ChokePoint]
    node_names: dict[str, str] = Field(default_factory=dict)

    def name(self, node_id: str) -> str:
        return self.node_names.get(node_id, node_id)

    def describe(self, path: AttackPath) -> str:
        parts = [self.name(path.source)]
        for h in path.hops:
            parts.append(f"-[{h.kind}]-> {self.name(h.dst)}")
        return " ".join(parts)
