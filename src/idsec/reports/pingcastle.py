"""PingCastle Health Check XML（ad_hc_<domain>.xml）解析。

只讀取 RiskRules 區段：每條 HealthcheckRiskRule 含 Points、Category、Model、RiskId、Rationale。
XML 以 defusedxml 風格的安全設定解析（停用 DTD / 外部實體）。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Finding

# 常見 RiskId → MITRE ATT&CK（不完整，依需要擴充）
ATTACK_MAP = {
    "A-CertTempAnyone": ["T1649"],
    "A-CertTempCustomSubject": ["T1649"],
    "A-CertEnrollHttp": ["T1649"],
    "P-Kerberoasting": ["T1558.003"],
    "P-ServiceDomainAdmin": ["T1558.003"],
    "S-NoPreAuth": ["T1558.004"],
    "P-UnconstrainedDelegation": ["T1550"],
    "P-DelegationDCt2a4d": ["T1550"],
    "P-DCOwner": ["T1484"],
    "P-ControlPathIndirectEveryone": ["T1484"],
    "P-DangerousExtendedRight": ["T1003.006"],
    "A-LAPS-NotInstalled": ["T1078.003"],
    "A-DCLdapSign": ["T1557"],
    "A-DCLdapsChannelBinding": ["T1557"],
    "S-SMB-v1": ["T1210"],
    "A-NoServicePolicy": ["T1110"],
    "S-PwdNeverExpires": ["T1078"],
    "P-AdminPwdTooOld": ["T1078"],
    "T-SIDFiltering": ["T1134.005"],
}


def _severity(points: int) -> str:
    if points >= 50:
        return "critical"
    if points >= 20:
        return "high"
    if points >= 5:
        return "medium"
    if points > 0:
        return "low"
    return "info"


def _safe_parse(path: Path) -> ET.Element:
    text = path.read_text(encoding="utf-8-sig")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError(f"{path.name} 含 DTD / ENTITY，拒絕解析")
    return ET.fromstring(text)


def parse_pingcastle(path: Path) -> list[Finding]:
    root = _safe_parse(path)
    domain = (root.findtext("DomainFQDN") or "").strip()
    findings = []
    for rule in root.iter("HealthcheckRiskRule"):
        rid = (rule.findtext("RiskId") or "").strip()
        points = int((rule.findtext("Points") or "0").strip() or 0)
        rationale = (rule.findtext("Rationale") or "").strip()
        findings.append(Finding(
            source="PingCastle",
            id=rid,
            title=rationale.split(".")[0][:160] if rationale else rid,
            category=(rule.findtext("Category") or "").strip(),
            severity=_severity(points),
            points=points,
            rationale=rationale[:500],
            scope=domain,
            attack=ATTACK_MAP.get(rid, []),
        ))
    return findings
