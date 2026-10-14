#!/usr/bin/env python3
"""ADHD bundle sanity check — is a (verified) bundle actually complete enough to analyse?

verify_bundle.py answers "is this bundle intact and free of secrets?".
This tool answers "did collection quietly degrade?" — the failure modes that only show up on
real environments:

  * datasets that failed / were skipped, with the usual cause for each
  * AD group members that could not be resolved to a SID (DN: entries)
  * ACEs whose objectType GUID was not resolved to a name (GUID map incomplete)
  * users that were not pseudonymised, pseudonym-key mismatch across bundles
  * Entra users whose onPremisesSecurityIdentifier does not match any collected AD user
  * a short "first look" of common findings, to prove the data is analysable

Pass every bundle from one collection round (domain host + Entra Connect + logs) together so
the cross-bundle checks can run. Standard library only.

Usage:
    python3 tools/bundle_sanity.py ADHD-Collect-SubA-*.zip ADHD-Collect-SubA-AADC-*.zip
    python3 tools/bundle_sanity.py bundles/SubA/* --json sanity-report.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_bundle import find_bundle_root, safe_extract  # noqa: E402

PSEUDO_RE = re.compile(r"^u-[0-9a-f]{12}(@.*)?$")
INFRA_RE = re.compile(r"(?i)^(MSOL_|Sync_|AAD_|AZUREADSSOACC|provAgentgMSA|ADToAADSyncServiceAccount|krbtgt)")
DCSYNC_RIGHTS = {"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"}
EXPECTED_DCSYNC_RIDS = {"498", "516", "521", "512", "519"}  # (E)RODC / DC / Domain & Enterprise Admins

KNOWN_CAUSES = {
    "AD": "未安裝 RSAT-AD、連不到 DC 的 ADWS（TCP 9389，例如未連 VPN）、或未以網域帳號登入；確切原因見訊息",
    "ADACL": "未安裝 RSAT-AD、連不到 DC 的 ADWS（TCP 9389，例如未連 VPN）、或未以網域帳號登入；確切原因見訊息",
    "GPO": "未安裝 RSAT-AD、連不到 DC 的 ADWS（TCP 9389，例如未連 VPN）、或未以網域帳號登入；確切原因見訊息",
    "ADCS": "未安裝 RSAT-AD、連不到 DC 的 ADWS（TCP 9389，例如未連 VPN）、或未以網域帳號登入；確切原因見訊息",
    "ad_password_policies": "FGPP 預設只有 Domain Admins 可讀（預設原則仍會收）",
    "gpo_gpp_cpassword": "執行主機無法存取 \\\\<domain>\\SYSVOL",
    "gpo_reports": "未安裝 GPMC / RSAT Group Policy，或帳號無法讀取部分 GPO",
    "entra_pim_eligibility": "需要 Entra ID P2，或帳號缺 RoleManagement.Read.Directory 同意",
    "entra_pim_assignments": "需要 Entra ID P2",
    "entra_risky_users": "需要 Entra ID P2",
    "entra_risk_detections": "需要 Entra ID P2",
    "entra_signins": "需要 Entra ID P1，且 AuditLog.Read.All 已同意",
    "entra_directory_audits": "AuditLog.Read.All 未同意",
    "entra_user_registration": "需要 Entra ID P1，或 UserAuthenticationMethod.Read.All 未同意",
    "entra_ca_policies": "Policy.Read.All 未同意，或租用戶沒有 P1",
    "dc_security_events": "帳號不在 Event Log Readers，或 DC 防火牆未開遠端事件記錄管理",
}


class Bundle:
    def __init__(self, root: Path, source: str) -> None:
        self.root = root
        self.source = source
        self.manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        self.status = {d["name"]: d for d in self.manifest.get("datasets", [])}

    def rows(self, name: str) -> list[dict[str, Any]]:
        ds = self.status.get(name)
        if not ds or ds.get("format") != "jsonl" or not ds.get("file"):
            return []
        path = self.root / ds["file"]
        if not path.is_file():
            return []
        with path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


class Out:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.facts: dict[str, Any] = {}

    def head(self, title: str) -> None:
        print(f"\n== {title} " + "=" * max(0, 60 - len(title)))

    def line(self, label: str, value: Any, key: str | None = None) -> None:
        print(f"  {label:<44} {value}")
        if key:
            self.facts[key] = value

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        print(f"  WARN  {msg}")


def pct(n: int, d: int) -> str:
    return "n/a" if d == 0 else f"{n}/{d} ({100.0 * n / d:.1f}%)"


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load(paths: list[Path], workdir: Path) -> list[Bundle]:
    bundles = []
    for i, p in enumerate(paths):
        if p.is_file() and zipfile.is_zipfile(p):
            dest = workdir / f"b{i}"
            dest.mkdir()
            safe_extract(p, dest)
            bundles.append(Bundle(find_bundle_root(dest), str(p)))
        elif p.is_dir():
            bundles.append(Bundle(find_bundle_root(p), str(p)))
        else:
            raise FileNotFoundError(f"not a bundle folder or zip: {p}")
    return bundles


def collect(bundles: list[Bundle], name: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in bundles:
        out.extend(b.rows(name))
    return out


def check_scope(bundles: list[Bundle], o: Out) -> None:
    o.head("範圍與收集環境")
    key_ids, pseudo_flags = set(), set()
    for b in bundles:
        m = b.manifest
        sc, rc, ps = m.get("scope", {}), m.get("runContext", {}), m.get("pseudonymization", {})
        print(f"  [{m.get('bundle')}]")
        o.line("  collector / schema", f"{m.get('collector', {}).get('version')} / {m.get('schema')}")
        o.line("  執行主機 / 帳號 / PowerShell", f"{rc.get('computer')} / {rc.get('user')} / {rc.get('psVersion')} {rc.get('psEdition')}")
        o.line("  AD domain / SID / 查詢 DC", f"{sc.get('adDomain')} / {sc.get('adDomainSid')} / {sc.get('adQueriedDc')}")
        o.line("  Entra tenant / Graph 帳號", f"{sc.get('entraTenantId')} / {sc.get('graphAccount')}")
        o.line("  模組", ", ".join(rc.get("parameters", {}).get("include", [])))
        o.line("  假名化 / keyId", f"{ps.get('enabled')} / {ps.get('keyId')}")
        pseudo_flags.add(bool(ps.get("enabled")))
        if ps.get("enabled"):
            key_ids.add(ps.get("keyId"))
        if sc.get("graphScopes") and "Directory.Read.All" not in sc["graphScopes"]:
            o.warn(f"{m.get('bundle')}: Graph 權杖沒有 Directory.Read.All，Entra 資料多半不完整")
    if len(key_ids) > 1:
        o.warn(f"多個 bundle 使用不同的假名化金鑰 {sorted(key_ids)} —— 跨 bundle 假名無法對應，請用同一把金鑰重收")
    if len(pseudo_flags) > 1:
        o.warn("部分 bundle 有假名化、部分沒有")
    tenants = {b.manifest.get("scope", {}).get("entraTenantId") for b in bundles} - {None}
    if len(tenants) > 1:
        o.warn(f"同一輪混入多個 tenant：{sorted(tenants)}")


def check_status(bundles: list[Bundle], o: Out) -> None:
    o.head("資料集狀態")
    counter: Counter[str] = Counter()
    for b in bundles:
        for name, d in b.status.items():
            st = d.get("status")
            counter[st] += 1
            if st in ("error", "partial", "skipped"):
                cause = KNOWN_CAUSES.get(name, "見 collection.log")
                o.warn(f"{name}: {st} — {d.get('message') or ''}".rstrip(" —") + f"｜常見原因：{cause}")
    o.line("ok / partial / error / skipped",
           f"{counter['ok']} / {counter['partial']} / {counter['error']} / {counter['skipped']}", "datasetStatus")
    for b in bundles:
        msgs = list(dict.fromkeys(b.manifest.get("warnings") or []))
        if not msgs:
            continue
        print(f"  收集端訊息 [{b.manifest.get('bundle')}]（manifest.warnings，共 {len(msgs)} 則）：")
        for m in msgs[:12]:
            print(f"    - {m}")
        if len(msgs) > 12:
            print(f"    ...其餘見 collection.log")


def check_ad(bundles: list[Bundle], o: Out) -> dict[str, dict[str, Any]]:
    users = collect(bundles, "ad_users")
    computers = collect(bundles, "ad_computers")
    groups = collect(bundles, "ad_groups")
    gmsa = collect(bundles, "ad_service_accounts")
    by_sid = {r["sid"]: r for r in users + computers + groups + gmsa if r.get("sid")}
    if not users:
        return by_sid
    o.head("AD 完整性")
    o.line("users（enabled）", f"{len(users)}（{sum(1 for u in users if u.get('enabled'))}）", "adUsers")
    o.line("computers（enabled）", f"{len(computers)}（{sum(1 for c in computers if c.get('enabled'))}）", "adComputers")
    o.line("groups / gMSA", f"{len(groups)} / {len(gmsa)}", "adGroups")

    members = [m for g in groups for m in (g.get("members") or [])]
    unresolved = [m for m in members if isinstance(m, str) and m.startswith("DN:")]
    foreign = [m for m in members if isinstance(m, str) and m.startswith("S-1-") and m not in by_sid]
    o.line("群組成員總數", len(members))
    o.line("無法解析為 SID（DN:）", pct(len(unresolved), len(members)), "unresolvedMembers")
    o.line("外部 / 其他網域 SID", len(foreign))
    if members and len(unresolved) / len(members) > 0.05:
        sample = Counter(re.sub(r"^DN:CN=[^,]+,", "", m) for m in unresolved).most_common(3)
        o.warn(f"超過 5% 群組成員無法解析，常見容器：{sample}（contact / 其他網域物件屬正常；大量則可能是讀取權限不足）")

    by_name = {(g.get("name") or "").lower(): g for g in groups}
    da = by_name.get("domain admins")
    if da is None:
        o.warn("找不到 Domain Admins 群組（非英文網域請確認 RID 512 的群組）")
    elif not da.get("members"):
        o.warn("Domain Admins 成員為空 —— 若不符預期，代表 member 屬性讀取失敗")

    builtin_cnt = sum(1 for u in users if u.get("isBuiltin"))
    o.line("內建帳號（RID<1000）", builtin_cnt)
    if not any((u.get("samAccountName") or "").lower() == "krbtgt" for u in users):
        o.warn("ad_users 沒有 krbtgt —— 使用者清單可能不完整")
    return by_sid


def check_acl(bundles: list[Bundle], o: Out, by_sid: dict[str, dict[str, Any]]) -> None:
    acls = collect(bundles, "ad_acls")
    if not acls:
        return
    o.head("ACL 與 GUID 解析")
    guid_map = collect(bundles, "ad_guid_map")
    aces = [a for r in acls for a in (r.get("aces") or [])]
    typed = [a for a in aces if a.get("objectType")]
    unresolved = [a for a in typed if not a.get("objectTypeName")]
    o.line("ACL 目標物件 / 明確 ACE", f"{len(acls)} / {len(aces)}", "aclObjects")
    o.line("GUID 對照表", len(guid_map))
    o.line("objectType 未解析名稱", pct(len(unresolved), len(typed)), "unresolvedAceTypes")
    if len(guid_map) < 1000:
        o.warn(f"GUID 對照表只有 {len(guid_map)} 筆（一般網域 > 1500）—— schema 讀取可能被截斷")
    if typed and len(unresolved) / len(typed) > 0.02:
        o.warn("超過 2% ACE 的 objectType 無法解析 —— Extended-Rights 容器可能讀取失敗")
    reasons = Counter(r.get("reason") for r in acls)
    o.line("各類目標", dict(reasons))
    if not reasons.get("domainRoot"):
        o.warn("缺少 domain root 的 ACL —— 無法分析 DCSync")
        return

    root = next(r for r in acls if r.get("reason") == "domainRoot")
    holders: dict[str, set[str]] = {}
    for a in root.get("aces") or []:
        if a.get("type") != "Allow":
            continue
        name = a.get("objectTypeName")
        rights = a.get("rights") or ""
        if name in DCSYNC_RIGHTS or ("GenericAll" in rights):
            holders.setdefault(a["principal"], set()).add(name or rights)
    print("  可 DCSync 的主體（Get-Changes-All 或 GenericAll on domain root）：")
    for sid, rights in sorted(holders.items()):
        if "DS-Replication-Get-Changes-All" not in rights and not any("GenericAll" in r for r in rights):
            continue
        obj = by_sid.get(sid, {})
        label = obj.get("samAccountName") or obj.get("name") or "?"
        rid = sid.rsplit("-", 1)[-1]
        if rid in EXPECTED_DCSYNC_RIDS or sid in ("S-1-5-32-544", "S-1-5-18", "S-1-5-9"):
            tag = "預期"
        elif re.match(r"(?i)^MSOL_", label):
            tag = "預期（Entra Connect PHS）"
        else:
            tag = "需確認"
        print(f"    {tag:<22} {sid:<48} {label}")


def check_pseudonymization(bundles: list[Bundle], o: Out) -> None:
    users = collect(bundles, "ad_users")
    entra = collect(bundles, "entra_users")
    if not users and not entra:
        return
    o.head("假名化覆蓋")
    if not any(b.manifest.get("pseudonymization", {}).get("enabled") for b in bundles):
        o.line("狀態", "未啟用（略過）")
        return
    eligible = [u for u in users if not u.get("isBuiltin") and not INFRA_RE.match(u.get("samAccountName") or "")]
    plain = [u for u in eligible if not PSEUDO_RE.match(u.get("samAccountName") or "")]
    o.line("AD 一般使用者帳號已假名化", pct(len(eligible) - len(plain), len(eligible)), "adPseudonymized")
    if plain:
        o.warn(f"{len(plain)} 個 AD 使用者帳號仍為原文（例：SID {plain[0].get('sid')}）")
    disp_plain = [u for u in eligible if u.get("displayName") and not PSEUDO_RE.match(u["displayName"])]
    if disp_plain:
        o.warn(f"{len(disp_plain)} 個 AD 使用者 displayName 仍為原文")
    e_eligible = [u for u in entra if not INFRA_RE.match((u.get("userPrincipalName") or "").split("@")[0])]
    e_plain = [u for u in e_eligible if u.get("userPrincipalName") and not PSEUDO_RE.match(u["userPrincipalName"])]
    o.line("Entra 使用者 UPN 已假名化", pct(len(e_eligible) - len(e_plain), len(e_eligible)), "entraPseudonymized")
    if e_plain:
        o.warn(f"{len(e_plain)} 個 Entra UPN 仍為原文（例：id {e_plain[0].get('id')}）")
    print("  提醒：請另以幾個你知道的真實姓名 / 帳號 grep 整個 bundle，確認不存在（見下方說明）")


def check_hybrid(bundles: list[Bundle], o: Out, by_sid: dict[str, dict[str, Any]]) -> None:
    entra = collect(bundles, "entra_users")
    if not entra:
        return
    o.head("混合身分關聯（Entra ↔ AD）")
    synced = [u for u in entra if u.get("onPremisesSyncEnabled")]
    with_sid = [u for u in synced if u.get("onPremisesSecurityIdentifier")]
    matched = [u for u in with_sid if u["onPremisesSecurityIdentifier"] in by_sid]
    o.line("Entra 使用者 / 由地端同步", f"{len(entra)} / {len(synced)}", "entraUsers")
    if not by_sid:
        o.line("同步帳號可對應到本次 AD 使用者", "n/a（本輪沒有 AD 資料，無法比對）", "hybridJoinRate")
    else:
        o.line("同步帳號可對應到本次 AD 使用者", pct(len(matched), len(with_sid)), "hybridJoinRate")
    if by_sid and with_sid and len(matched) / len(with_sid) < 0.9:
        domains = Counter(u.get("onPremisesDomainName") for u in with_sid if u["onPremisesSecurityIdentifier"] not in by_sid)
        o.warn(f"有同步帳號對應不到 AD —— 來源網域分布 {dict(domains.most_common(5))}（其他網域請另外收一份 AD bundle）")
    o.line("含 signInActivity", pct(sum(1 for u in entra if u.get("signInActivity")), len(entra)))
    roles = collect(bundles, "entra_role_assignments")
    o.line("目錄角色指派 / CA 原則", f"{len(roles)} / {len(collect(bundles, 'entra_ca_policies'))}")


def first_look(bundles: list[Bundle], o: Out) -> None:
    users = collect(bundles, "ad_users")
    computers = collect(bundles, "ad_computers")
    tpls = collect(bundles, "adcs_templates")
    domain = collect(bundles, "ad_domain")
    if not (users or computers or tpls):
        return
    o.head("First look（證明資料可分析，非完整評估）")
    now = datetime.now(timezone.utc)

    def flags(r: dict[str, Any]) -> list[str]:
        return r.get("uacFlags") or []

    enabled_users = [u for u in users if u.get("enabled")]
    o.line("Kerberoastable（啟用、有 SPN、非 krbtgt）",
           sum(1 for u in enabled_users if u.get("servicePrincipalNames") and (u.get("samAccountName") or "").lower() != "krbtgt"), "kerberoastable")
    o.line("AS-REP roastable（DONT_REQ_PREAUTH）", sum(1 for u in enabled_users if "DONT_REQ_PREAUTH" in flags(u)), "asrepRoastable")
    o.line("PASSWD_NOTREQD（啟用）", sum(1 for u in enabled_users if "PASSWD_NOTREQD" in flags(u)))
    o.line("密碼永不過期（啟用）", sum(1 for u in enabled_users if "DONT_EXPIRE_PASSWORD" in flags(u)))
    o.line("具 sIDHistory 的使用者", sum(1 for u in users if u.get("sidHistory")))
    o.line("description 疑似含密碼", sum(1 for u in users if u.get("descriptionHasSecretHint") or u.get("infoHasSecretHint")))
    o.line("非 DC 的無限制委派", sum(1 for r in users + computers
                                  if "TRUSTED_FOR_DELEGATION" in flags(r) and not r.get("isDomainController")), "unconstrainedNonDc")
    o.line("RBCD 設定物件", sum(1 for r in users + computers if r.get("rbcdAllowedPrincipals")))
    enabled_ws = [c for c in computers if c.get("enabled") and not c.get("isDomainController")]
    o.line("啟用中電腦有 LAPS", pct(sum(1 for c in enabled_ws if c.get("hasLaps")), len(enabled_ws)), "lapsCoverage")
    if domain:
        d = domain[0]
        o.line("ms-DS-MachineAccountQuota", d.get("machineAccountQuota"))
        k = parse_ts(d.get("krbtgtPwdLastSet"))
        if k:
            o.line("krbtgt 密碼天數", (now - k).days, "krbtgtAgeDays")
    esc1 = [t for t in tpls if t.get("published") and t.get("enrolleeSuppliesSubject") and t.get("clientAuthCapable")
            and not t.get("managerApproval") and not t.get("authorizedSignaturesRequired")]
    o.line("ESC1 候選範本（尚未檢查 Enroll 權限）", ", ".join(t.get("name", "?") for t in esc1) or 0, "esc1Candidates")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Semantic sanity check for ADHD bundles from one collection round.")
    ap.add_argument("bundles", nargs="+", type=Path, help="bundle folders or .zip files (already passed verify_bundle.py)")
    ap.add_argument("--json", type=Path, help="write facts and warnings as JSON")
    args = ap.parse_args(argv)

    o = Out()
    with tempfile.TemporaryDirectory(prefix="adhd-sanity-") as tmpdir:
        try:
            bundles = load(args.bundles, Path(tmpdir))
        except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        check_scope(bundles, o)
        check_status(bundles, o)
        by_sid = check_ad(bundles, o)
        check_acl(bundles, o, by_sid)
        check_pseudonymization(bundles, o)
        check_hybrid(bundles, o, by_sid)
        first_look(bundles, o)

    print(f"\n結果：{len(o.warnings)} 項警告")
    if args.json:
        args.json.write_text(json.dumps({"facts": o.facts, "warnings": o.warnings}, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
