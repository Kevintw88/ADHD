"""Phase 0：環境盤點，產出環境指紋。

完全確定性、不呼叫 LLM。指紋是能力矩陣與後續所有模組的輸入。
"""

from __future__ import annotations

from collections import Counter

from .backends import Backend
from .models import ADSnapshot, EntraSnapshot, Fingerprint, Tooling

REQUIRED_AUDIT = [
    "Credential Validation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "User Account Management",
    "Security Group Management",
    "Computer Account Management",
    "Directory Service Access",
    "Directory Service Changes",
    "Logon",
    "Special Logon",
]
STALE_DAYS = 90
P2_SKUS = ("AAD_PREMIUM_P2", "SPE_E5", "ENTERPRISEPREMIUM", "EMSPREMIUM", "IDENTITY_THREAT_PROTECTION")
P1_SKUS = ("AAD_PREMIUM", "SPE_E3", "ENTERPRISEPACK", "EMS")
MDI_SKUS = ("ATA", "DEFENDER_FOR_IDENTITY", "IDENTITY_THREAT_PROTECTION", "SPE_E5")


def _has(licenses: list[str], keys: tuple[str, ...]) -> bool:
    return any(k in lic for lic in licenses for k in keys)


def _ad_section(ad: ADSnapshot) -> dict:
    dcs = [dc for d in ad.domains for dc in d.dcs]
    return {
        "forest": ad.forest,
        "domains": len(ad.domains),
        "domain_names": [d.name for d in ad.domains],
        "functional_levels": sorted({d.functional_level for d in ad.domains if d.functional_level}),
        "dc_count": len(dcs),
        "dc_os": dict(Counter(dc.os or "unknown" for dc in dcs)),
        "trusts": len(ad.trusts),
        "trusts_without_sid_filtering": sum(1 for t in ad.trusts if not t.sid_filtering),
    }


def _hybrid_section(ad: ADSnapshot, entra: EntraSnapshot) -> dict:
    hosts: dict[str, list[str]] = {}
    for c in ad.computers:
        if c.role in {"entra-connect", "adfs", "pta", "seamless-sso"}:
            hosts.setdefault(c.role, []).append(c.name)
    return {
        "tenant_present": entra.tenant_present,
        "sync_tool": entra.sync.tool,
        "auth_method": entra.sync.auth,
        "seamless_sso": entra.sync.seamless_sso,
        "sync_hosts": hosts,
        "is_hybrid": entra.tenant_present and entra.sync.tool != "None",
    }


def _identity_section(ad: ADSnapshot, entra: EntraSnapshot) -> dict:
    enabled = [u for u in ad.users if u.enabled]
    privileged = [u for u in enabled if u.admin_count]
    kerberoastable = [u.sam for u in enabled if u.spns and u.sam.lower() != "krbtgt"]
    roles = Counter(c.role or "unknown" for c in ad.computers)
    return {
        "users_total": len(ad.users),
        "users_enabled": len(enabled),
        "privileged_enabled": len(privileged),
        "kerberoastable": len(kerberoastable),
        "kerberoastable_privileged": sum(1 for u in privileged if u.spns),
        "asrep_roastable": sum(1 for u in enabled if u.dont_require_preauth),
        "privileged_pwd_never_expires": sum(1 for u in privileged if u.pwd_never_expires),
        "stale_enabled": sum(1 for u in enabled if (u.last_logon_days or 0) > STALE_DAYS),
        "gmsa": ad.gmsa_count,
        "computers_by_role": dict(roles),
        "unconstrained_delegation_non_dc": sum(1 for c in ad.computers if c.unconstrained_delegation),
        "entra_guests": entra.guests_count,
        "entra_privileged_role_members": sum(len(r.members) for r in entra.privileged_roles),
        "entra_pim_eligible": sum(len(r.pim_eligible) for r in entra.privileged_roles),
        "entra_service_principals_with_app_perms": len(entra.service_principals),
    }


def _services_section(ad: ADSnapshot) -> dict:
    esc1 = [t.name for t in ad.adcs.templates
            if t.enrollee_supplies_subject and t.client_auth and not t.manager_approval]
    return {
        "adcs_present": ad.adcs.present,
        "ca_count": len(ad.adcs.cas),
        "templates_published": len(ad.adcs.templates),
        "esc1_candidates": esc1,
    }


def _tooling_section(tooling: Tooling, entra: EntraSnapshot) -> dict:
    return {
        "mdi": tooling.mdi,
        "mdi_licensed": _has(entra.licenses, MDI_SKUS),
        "edr": tooling.edr,
        "siem": tooling.siem,
        "entra_p1": _has(entra.licenses, P1_SKUS + P2_SKUS),
        "entra_p2": _has(entra.licenses, P2_SKUS),
    }


def _telemetry_section(ad: ADSnapshot, entra: EntraSnapshot, tooling: Tooling) -> dict:
    required = REQUIRED_AUDIT + (["Certification Services"] if ad.adcs.present else [])
    known = ad.audit_policy is not None
    missing = [s for s in required if "Success" not in (ad.audit_policy or {}).get(s, "")] if known else required
    audit_ratio = (len(required) - len(missing)) / len(required)
    parts = [audit_ratio, tooling.sysmon_coverage or 0.0, 1.0 if tooling.siem_ingest.dc_security else 0.0]
    if entra.tenant_present:
        parts.append(1.0 if tooling.siem_ingest.entra_signin else 0.0)
    return {
        "audit_policy_known": known,
        "audit_required": len(required),
        "audit_missing": missing,
        "audit_ratio": round(audit_ratio, 2),
        "sysmon_coverage": tooling.sysmon_coverage,
        "siem_ingest": tooling.siem_ingest.model_dump(),
        "coverage_score": round(sum(parts) / len(parts), 2),
    }


def build_fingerprint(entity_id: str, backend: Backend) -> Fingerprint:
    ad, entra, tooling = backend.ad_snapshot(), backend.entra_snapshot(), backend.tooling()
    return Fingerprint(
        entity=entity_id,
        ad=_ad_section(ad),
        hybrid=_hybrid_section(ad, entra),
        identity=_identity_section(ad, entra),
        services=_services_section(ad),
        tooling=_tooling_section(tooling, entra),
        telemetry=_telemetry_section(ad, entra, tooling),
    )
