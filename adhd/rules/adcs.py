"""AD Certificate Services rules (template / CA object level: ESC1-5, ESC9)."""
from __future__ import annotations

from typing import Any

from .. import known
from . import rule

ANY_PURPOSE = "2.5.29.37.0"
CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
_ENROLL = {"Enroll", "GenericAll", "AllExtendedRights"}
_WRITE = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteAllProperties", "Owns"}
_REMEDIATE_TEMPLATE = ("取消發佈不需要的範本；需要的範本關閉「在要求中提供」(ENROLLEE_SUPPLIES_SUBJECT)、啟用 CA 管理員核准，"
                       "並將 Enroll 權限限縮到實際需要的群組（不要給 Domain Users / Domain Computers / Authenticated Users）。")


def _template_id(ctx, t: dict[str, Any]) -> str:
    return ctx.dn_index[t["distinguishedName"].lower()]


def _effective_ekus(t: dict[str, Any]) -> list[str]:
    return list(t.get("applicationPolicies") or []) or list(t.get("extendedKeyUsage") or [])


def _enrollers(ctx, nid: str) -> list[str]:
    return sorted({e.src for e in ctx.graph.edges_in(nid, _ENROLL)
                   if e.src not in ctx.tier0 and e.src not in known.SAFE_ACL_PRINCIPALS})


def _no_gate(t: dict[str, Any]) -> bool:
    return t.get("published") and not t.get("managerApproval") and not (t.get("authorizedSignaturesRequired") or 0)


def _ca_hosts(ctx) -> set[str]:
    hosts = {str(c.get("dnsHostName") or "").lower() for c in ctx.rows("adcs_cas")}
    return {c["sid"] for c in ctx.computers() if str(c.get("dnsHostName") or "").lower() in hosts}


def _report(ctx, hits, found: list[tuple[dict[str, Any], list[str]]], what: str, base_sev: str) -> None:
    if not found:
        return
    broad = any(ctx.is_broad(p) for _, ps in found for p in ps)
    items = [ctx.ref(_template_id(ctx, t), {"enrollers": [ctx.label(p) for p in ps],
                                            "ekus": _effective_ekus(t)}) for t, ps in found]
    hits.add(f"{len(found)} 個已發佈範本{what}。", items, "critical" if broad else base_sev)


@rule("ADCS-001", "ESC1：可自行指定憑證主體的驗證用範本", category="ADCS", severity="high",
      requires=["adcs_templates", "adcs_cas", "ad_groups"], attack=["T1649"], remediation=_REMEDIATE_TEMPLATE)
def esc1(ctx, hits):
    """申請者可在要求中填入任意 UPN / SAN，申請到網域管理員的驗證憑證。"""
    found = []
    for t in ctx.rows("adcs_templates"):
        if _no_gate(t) and t.get("enrolleeSuppliesSubject") and t.get("clientAuthCapable"):
            ps = _enrollers(ctx, _template_id(ctx, t))
            if ps:
                found.append((t, ps))
    _report(ctx, hits, found, "允許非 Tier0 主體申請並自行指定主體（可冒充任何帳號）", "high")


@rule("ADCS-002", "ESC2：任何用途 / 無 EKU 的範本", category="ADCS", severity="high",
      requires=["adcs_templates", "adcs_cas", "ad_groups"], attack=["T1649"], remediation=_REMEDIATE_TEMPLATE)
def esc2(ctx, hits):
    """Any Purpose 或沒有 EKU 的憑證可用於用戶端驗證，也可作為下級 CA 簽發其他憑證。"""
    found = []
    for t in ctx.rows("adcs_templates"):
        ekus = _effective_ekus(t)
        if _no_gate(t) and (not ekus or ANY_PURPOSE in ekus):
            ps = _enrollers(ctx, _template_id(ctx, t))
            if ps:
                found.append((t, ps))
    _report(ctx, hits, found, "為 Any Purpose / 無 EKU 且非 Tier0 主體可申請", "high")


@rule("ADCS-003", "ESC3：註冊代理（Certificate Request Agent）範本", category="ADCS", severity="high",
      requires=["adcs_templates", "adcs_cas", "ad_groups"], attack=["T1649"],
      remediation="限制註冊代理範本的 Enroll 權限，並在 CA 上設定註冊代理限制（Enrollment Agent Restrictions）。")
def esc3(ctx, hits):
    """取得註冊代理憑證後，可代替任何使用者申請其他範本的憑證。"""
    found = []
    for t in ctx.rows("adcs_templates"):
        if _no_gate(t) and CERT_REQUEST_AGENT in _effective_ekus(t):
            ps = _enrollers(ctx, _template_id(ctx, t))
            if ps:
                found.append((t, ps))
    _report(ctx, hits, found, "為註冊代理且非 Tier0 主體可申請", "high")


@rule("ADCS-004", "ESC4：非 Tier0 主體可修改憑證範本", category="ADCS", severity="high",
      requires=["adcs_templates", "ad_groups"], attack=["T1649"],
      remediation="範本的寫入、WriteDacl、WriteOwner、擁有者只保留 Enterprise Admins / Domain Admins / SYSTEM。")
def esc4(ctx, hits):
    """能修改範本即可把它改成 ESC1 再申請憑證。"""
    has_ca = bool(ctx.rows("adcs_cas"))
    groups: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for t in ctx.rows("adcs_templates"):
        nid = _template_id(ctx, t)
        ps = sorted({e.src for e in ctx.graph.edges_in(nid, _WRITE)
                     if e.src not in ctx.tier0 and e.src not in known.SAFE_ACL_PRINCIPALS})
        if not ps:
            continue
        live = [p for p in ps if not ctx.is_orphan(p)]
        if not has_ca or not live:
            sev = "low"           # nothing can issue from it / only deleted principals hold the right
        elif not t.get("published"):
            sev = "medium"        # attacker also needs a CA to publish it
        else:
            sev = "critical" if any(ctx.is_broad(p) for p in live) else "high"
        groups[sev].append(ctx.ref(nid, {"writers": [ctx.label(p) for p in ps], "published": t.get("published")}))
    notes = {
        "critical": "已發佈且可被廣泛群組修改（改成 ESC1 即可冒充任何帳號）",
        "high": "已發佈且可被非 Tier0 主體修改",
        "medium": "未發佈但可被非 Tier0 主體修改（需同時能在 CA 上發佈才可利用）",
        "low": "可修改者僅為孤立 SID，或網域中沒有 Enterprise CA（目前無法用於簽發，屬 ACL 清理項目）",
    }
    for sev in ("critical", "high", "medium", "low"):
        if groups[sev]:
            hits.add(f"{len(groups[sev])} 個範本{notes[sev]}。", groups[sev], sev,
                     {"enterpriseCAs": len(ctx.rows("adcs_cas"))})


@rule("ADCS-005", "ESC5：非 Tier0 主體可控制 PKI 物件", category="ADCS", severity="high",
      requires=["adcs_containers", "adcs_cas", "ad_groups"], attack=["T1649"],
      remediation="Public Key Services 容器、NTAuthCertificates 與 CA 物件的控制權只保留給 Tier0（Enterprise Admins / Domain Admins / SYSTEM / CA 主機本身）。")
def esc5(ctx, hits):
    """能修改 NTAuthCertificates、CA 物件或範本容器，即可讓自製的 CA 或範本被網域信任。"""
    allowed = set(ctx.tier0) | known.SAFE_ACL_PRINCIPALS | _ca_hosts(ctx)
    cert_publishers = ctx.dsid(517)
    if cert_publishers:
        allowed.add(cert_publishers)
    found = []
    for ds in ("adcs_containers", "adcs_cas"):
        for r in ctx.rows(ds):
            nid = ctx.dn_index[r["distinguishedName"].lower()]
            ps = sorted({e.src for e in ctx.graph.edges_in(nid, _WRITE) if e.src not in allowed})
            if ps:
                found.append(ctx.ref(nid, {"writers": [ctx.label(p) for p in ps]}))
    if found:
        hits.add(f"{len(found)} 個 PKI 物件可被非 Tier0 主體控制。", found)


@rule("ADCS-006", "ESC9：不含安全性延伸的驗證範本", category="ADCS", severity="medium",
      requires=["adcs_templates", "adcs_cas", "ad_groups"], attack=["T1649"],
      remediation="移除範本的 CT_FLAG_NO_SECURITY_EXTENSION，並確認所有 DC 的 StrongCertificateBindingEnforcement = 2（完全強制）。")
def esc9(ctx, hits):
    """憑證不含 SID 延伸時，搭配可改寫 UPN 的帳號即可取得他人身分的憑證（DC 未完全強制強式對應時）。"""
    found = []
    for t in ctx.rows("adcs_templates"):
        if t.get("published") and t.get("noSecurityExtension") and t.get("clientAuthCapable"):
            ps = _enrollers(ctx, _template_id(ctx, t))
            if ps:
                found.append((t, ps))
    _report(ctx, hits, found, "不含安全性延伸（szOID_NTDS_CA_SECURITY_EXT）且非 Tier0 主體可申請", "medium")


@rule("ADCS-007", "ADCS 伺服器端設定未評估（ESC6 / ESC7 / ESC8 / ESC11）", category="ADCS", severity="info",
      requires=["adcs_cas"], attack=["T1649"],
      remediation="於 CA 主機檢查：EDITF_ATTRIBUTESUBJECTALTNAME2（ESC6）、CA 管理員 / 憑證管理員權限（ESC7）、Web Enrollment 是否啟用 NTLM 且未強制 EPA（ESC8）、RPC 介面是否強制加密（ESC11）。")
def adcs_coverage(ctx, hits):
    """這些弱點設定在 CA 主機的登錄機碼與服務上，本版收集器未收集。"""
    cas = ctx.rows("adcs_cas")
    if cas:
        hits.add(f"網域中有 {len(cas)} 個 Enterprise CA；ESC6 / 7 / 8 / 11 需另行在 CA 主機上檢查。",
                 [ctx.ref(ctx.dn_index[c["distinguishedName"].lower()], c.get("dnsHostName")) for c in cas])
