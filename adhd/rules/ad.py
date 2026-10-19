"""Active Directory rules."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .. import acl, known
from ..load import rid_of
from . import rule

STALE_DAYS = 90
_OU_DIRECT = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteAllProperties", "WriteGPLink"}


def _flags(r: dict[str, Any]) -> set[str]:
    return set(r.get("uacFlags") or [])


def _enabled(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if r.get("enabled")]


def _pwd_age(ctx, r) -> int | None:
    return ctx.days_since(r.get("pwdLastSet"))


def _connector_accounts(ctx) -> set[str]:
    """Lower-case account names the Entra Connect AD DS connectors log in with."""
    names = set()
    for c in ctx.rows("entraconnect_connectors"):
        for k, v in (c.get("connectivityParameters") or {}).items():
            if re.search(r"(?i)login-user|user-?name$", k) and v:
                names.add(str(v).rsplit("\\", 1)[-1].lower())
    return names


def _is_connector(ctx, sid: str, names: set[str]) -> bool:
    r = ctx.by_sid.get(sid) or {}
    sam = str(r.get("samAccountName") or "").lower()
    upn = str(r.get("userPrincipalName") or "").lower()
    return bool(sam and (sam in names or upn in names or sam.startswith("msol_")))


# ---------------------------------------------------------------------------------------------
@rule("AD-001", "krbtgt 密碼過久未重設", category="AD", severity="medium", requires=["ad_domain"],
      attack=["T1558.001"],
      remediation="以 Microsoft 提供的 krbtgt 重設程序分兩次重設（兩次間隔需大於最長票證存留時間與 AD 複寫完成時間），之後每 180 天例行重設。")
def krbtgt_age(ctx, hits):
    """krbtgt 密碼越久未換，遭竊後偽造的 Golden Ticket 可用越久。"""
    days = ctx.days_since(ctx.domain.get("krbtgtPwdLastSet"))
    if days is None or days <= 180:
        return
    sev = "high" if days > 365 else "medium"
    sid = ctx.dsid(502)
    hits.add(f"krbtgt 密碼已 {days} 天未重設。", [ctx.ref(sid, f"{days} 天")] if sid else [], sev, {"days": days})


@rule("AD-002", "一般使用者可自行將電腦加入網域（MachineAccountQuota > 0）", category="AD", severity="medium",
      requires=["ad_domain"], attack=["T1136.002"],
      remediation="將 ms-DS-MachineAccountQuota 設為 0，加入網域改由委派權限的專用帳號或群組執行。")
def machine_account_quota(ctx, hits):
    """任何驗證過的使用者可建立電腦帳號，常被用於 RBCD、KrbRelay、noPac 等攻擊鏈。"""
    maq = ctx.domain.get("machineAccountQuota")
    if isinstance(maq, int) and maq > 0:
        hits.add(f"ms-DS-MachineAccountQuota = {maq}：每個網域使用者都能建立 {maq} 個電腦帳號。",
                 [ctx.ref(ctx.domain_sid or "domain", f"MAQ={maq}")], evidence={"machineAccountQuota": maq})


@rule("AD-003", "可被 Kerberoasting 的使用者帳號", category="AD", severity="medium", requires=["ad_users"],
      attack=["T1558.003"],
      remediation="服務帳號改用 gMSA；無法改用時設定 25 字元以上的隨機密碼、僅允許 AES（msDS-SupportedEncryptionTypes=0x18），並移除不必要的 SPN。特權帳號不應設定 SPN。")
def kerberoastable(ctx, hits):
    """任何網域使用者都能為有 SPN 的帳號請求服務票證並離線破解其密碼。"""
    t0, other = [], []
    for u in _enabled(ctx.users()):
        if not u.get("servicePrincipalNames") or rid_of(u.get("sid")) == 502:
            continue
        enc = u.get("supportedEncryptionTypes")
        rc4 = enc is None or (isinstance(enc, int) and (enc & 0x4 or enc == 0))
        age = _pwd_age(ctx, u)
        detail = {"spn": len(u["servicePrincipalNames"]), "passwordAgeDays": age, "rc4Allowed": bool(rc4)}
        (t0 if u["sid"] in ctx.tier0 else other).append(ctx.ref(u["sid"], detail))
    if t0:
        hits.add(f"{len(t0)} 個 Tier0 帳號設有 SPN，可被離線破解密碼並直接取得網域控制權。", t0, "critical")
    if other:
        sev = "high" if any((a["detail"].get("passwordAgeDays") or 0) > 365 for a in other) else "medium"
        hits.add(f"{len(other)} 個啟用中的使用者帳號設有 SPN。", other, sev)


@rule("AD-004", "不需 Kerberos 預先驗證的帳號（AS-REP Roasting）", category="AD", severity="high",
      requires=["ad_users"], attack=["T1558.004"],
      remediation="移除帳號的「不需要 Kerberos 預先驗證」(DONT_REQ_PREAUTH) 設定；若應用程式確實需要，改用強密碼並限制帳號權限。")
def asrep(ctx, hits):
    """攻擊者不需任何憑證即可取得這些帳號可離線破解的加密資料。"""
    found = [u for u in _enabled(ctx.users()) if "DONT_REQ_PREAUTH" in _flags(u)]
    if found:
        t0 = any(u["sid"] in ctx.tier0 for u in found)
        hits.add(f"{len(found)} 個啟用中的帳號未要求 Kerberos 預先驗證。",
                 [ctx.ref(u["sid"], {"tier0": u["sid"] in ctx.tier0, "passwordAgeDays": _pwd_age(ctx, u)}) for u in found],
                 "critical" if t0 else "high")


@rule("AD-005", "非網域控制站設定無限制委派", category="AD", severity="high", requires=["ad_users", "ad_computers"],
      attack=["T1558", "T1187"],
      remediation="移除無限制委派（TRUSTED_FOR_DELEGATION），改用限制委派或資源型限制委派；Tier0 帳號設定「機密帳戶，無法委派」或加入 Protected Users。")
def unconstrained(ctx, hits):
    """任何對這些主機進行驗證的帳號（含 DC 經 Printer Bug 強制驗證）都會留下可重用的 TGT。"""
    found = [r for r in _enabled(ctx.users() + ctx.computers())
             if "TRUSTED_FOR_DELEGATION" in _flags(r) and not r.get("isDomainController")]
    if found:
        hits.add(f"{len(found)} 個非 DC 的帳號設定無限制委派。",
                 [ctx.ref(r["sid"], {"objectClass": r.get("objectClass"), "operatingSystem": r.get("operatingSystem")}) for r in found],
                 "critical" if any(r["sid"] in ctx.tier0 for r in found) else "high")


@rule("AD-006", "限制委派（含協定轉換）", category="AD", severity="medium", requires=["ad_users", "ad_computers"],
      attack=["T1558"],
      remediation="檢視每個委派目標是否必要；移除協定轉換（TRUSTED_TO_AUTH_FOR_DELEGATION），委派到 DC 服務的設定應移除或改由 Tier0 管控。")
def constrained(ctx, hits):
    """設有 msDS-AllowedToDelegateTo 的帳號被取得後，可冒用任何使用者存取委派目標。"""
    to_dc, transition, plain = [], [], []
    for r in _enabled(ctx.users() + ctx.computers() + ctx.rows("ad_service_accounts")):
        spns = r.get("allowedToDelegateTo") or []
        if not spns or r.get("isDomainController"):
            continue
        targets = [e.dst for e in ctx.graph.edges_out(r["sid"], ["AllowedToDelegate"])]
        pt = "TRUSTED_TO_AUTH_FOR_DELEGATION" in _flags(r)
        item = ctx.ref(r["sid"], {"delegateTo": spns[:10], "protocolTransition": pt})
        if any(t in ctx.dc_sids for t in targets):
            to_dc.append(item)
        elif pt:
            transition.append(item)
        else:
            plain.append(item)
    if to_dc:
        hits.add(f"{len(to_dc)} 個帳號可委派到網域控制站上的服務（取得即等同 Tier0）。", to_dc, "critical")
    if transition:
        hits.add(f"{len(transition)} 個帳號設定含協定轉換的限制委派（不需使用者實際驗證即可冒用）。", transition, "high")
    if plain:
        hits.add(f"{len(plain)} 個帳號設定限制委派。", plain, "low")


@rule("AD-007", "資源型限制委派（RBCD）設定", category="AD", severity="medium", requires=["ad_computers"],
      attack=["T1134"],
      remediation="移除不必要的 msDS-AllowedToActOnBehalfOfOtherIdentity；Tier0 主機上不應存在 RBCD。")
def rbcd(ctx, hits):
    """列在 msDS-AllowedToActOnBehalfOfOtherIdentity 的主體可冒用任何使用者存取目標主機。"""
    t0, other = [], []
    for r in ctx.users() + ctx.computers() + ctx.rows("ad_service_accounts"):
        allowed = r.get("rbcdAllowedPrincipals") or []
        if not allowed:
            continue
        item = ctx.ref(r["sid"], {"allowed": [ctx.label(p) for p in allowed]})
        (t0 if r["sid"] in ctx.tier0 else other).append(item)
    if t0:
        hits.add(f"{len(t0)} 個 Tier0 物件設有 RBCD。", t0, "critical")
    if other:
        hits.add(f"{len(other)} 個物件設有 RBCD，請確認是否必要。", other, "low")


@rule("AD-008", "啟用中的帳號允許空白密碼（PASSWD_NOTREQD）", category="AD", severity="medium",
      requires=["ad_users"], attack=["T1078.002"],
      remediation="移除 userAccountControl 的 PASSWD_NOTREQD 旗標並確認帳號已設定符合原則的密碼。")
def passwd_notreqd(ctx, hits):
    """設有此旗標的帳號可被設定為空白密碼，不受密碼原則限制。"""
    found = [u for u in _enabled(ctx.users()) if "PASSWD_NOTREQD" in _flags(u)]
    if found:
        hits.add(f"{len(found)} 個啟用中的帳號設有 PASSWD_NOTREQD。", [ctx.ref(u["sid"]) for u in found],
                 "high" if any(u["sid"] in ctx.tier0 for u in found) else "medium")


@rule("AD-009", "密碼以可還原加密方式儲存", category="AD", severity="high",
      requires=["ad_users", "ad_password_policies"], attack=["T1003"],
      remediation="關閉「使用可還原加密來存放密碼」（帳號旗標與密碼原則），並重設受影響帳號的密碼。")
def reversible(ctx, hits):
    """可還原加密的密碼等同明文，取得 NTDS 或 DCSync 即可還原。"""
    users = [u for u in _enabled(ctx.users()) if "ENCRYPTED_TEXT_PWD_ALLOWED" in _flags(u)]
    pols = [p for p in ctx.rows("ad_password_policies") if p.get("reversibleEncryptionEnabled")]
    if users:
        hits.add(f"{len(users)} 個帳號允許可還原加密。", [ctx.ref(u["sid"]) for u in users])
    if pols:
        hits.add(f"{len(pols)} 個密碼原則啟用可還原加密。",
                 [{"id": p.get("name"), "label": p.get("name"), "kind": "passwordPolicy", "detail": p.get("kind")} for p in pols])


@rule("AD-010", "Tier0 帳號密碼永不過期", category="AD", severity="medium", requires=["ad_users"],
      attack=["T1078.002"],
      remediation="Tier0 帳號移除「密碼永不過期」，定期輪替；或改用智慧卡 / Windows Hello 並定期輪替雜湊。")
def tier0_never_expires(ctx, hits):
    """密碼永不過期的特權帳號一旦外洩，攻擊者可長期使用。"""
    found = [u for u in _enabled(ctx.users()) if u["sid"] in ctx.tier0 and "DONT_EXPIRE_PASSWORD" in _flags(u)]
    if found:
        hits.add(f"{len(found)} 個 Tier0 帳號設為密碼永不過期。",
                 [ctx.ref(u["sid"], {"passwordAgeDays": _pwd_age(ctx, u)}) for u in found])


@rule("AD-011", "Tier0 帳號可被委派", category="AD", severity="medium", requires=["ad_users", "ad_groups"],
      attack=["T1558"],
      remediation="Tier0 使用者加入 Protected Users，或設定「機密帳戶，無法委派」（NOT_DELEGATED）。")
def tier0_delegatable(ctx, hits):
    """未受保護的特權帳號登入有委派設定的主機時，其票證可被冒用。"""
    pu = ctx.dsid(525)
    protected = ctx.graph.members(pu) if pu else set()
    found = [u for u in _enabled(ctx.users())
             if u["sid"] in ctx.tier0 and rid_of(u["sid"]) != 502
             and "NOT_DELEGATED" not in _flags(u) and u["sid"] not in protected]
    if found:
        hits.add(f"{len(found)} 個 Tier0 帳號未設定 NOT_DELEGATED 且不在 Protected Users。", [ctx.ref(u["sid"]) for u in found])


@rule("AD-012", "長期未使用的 Tier0 帳號", category="AD", severity="medium", requires=["ad_users", "ad_groups"],
      attack=["T1078.002"],
      remediation="停用或移出特權群組；保留的緊急帳號應使用強密碼、離線保管並監控登入。")
def stale_tier0(ctx, hits):
    """仍啟用但長期未登入的特權帳號容易被忽略，是常見的持久化與橫向移動目標。"""
    found = []
    for u in _enabled(ctx.users()):
        if u["sid"] not in ctx.tier0 or rid_of(u["sid"]) in (500, 502):
            continue
        d = ctx.days_since(u.get("lastLogonTimestamp"))
        if d is None or d > STALE_DAYS:
            found.append(ctx.ref(u["sid"], {"lastLogonDays": d}))
    if found:
        hits.add(f"{len(found)} 個 Tier0 帳號超過 {STALE_DAYS} 天未登入（或從未登入）。", found)


@rule("AD-013", "帳號帶有 sIDHistory", category="AD", severity="medium", requires=["ad_users"],
      attack=["T1134.005"],
      remediation="完成遷移後清除 sIDHistory；對外部信任啟用 SID filtering。")
def sid_history(ctx, hits):
    """sIDHistory 讓帳號在存取時帶有其他 SID 的權限，含特權 SID 時等同隱藏的管理員。"""
    priv_rids = {500, 512, 516, 518, 519, 498, 521, 526, 527}
    crit, other = [], []
    for r in ctx.users() + ctx.computers():
        sh = r.get("sidHistory") or []
        if not sh:
            continue
        bad = [s for s in sh if rid_of(s) in priv_rids or s in known.TIER0_BUILTIN_SIDS
               or (ctx.domain_sid and s.startswith(ctx.domain_sid + "-"))]
        item = ctx.ref(r["sid"], {"sidHistory": sh})
        (crit if bad else other).append(item)
    if crit:
        hits.add(f"{len(crit)} 個帳號的 sIDHistory 含特權或本網域 SID。", crit, "critical")
    if other:
        hits.add(f"{len(other)} 個帳號帶有 sIDHistory。", other, "medium")


@rule("AD-014", "Tier0 成員盤點", category="AD", severity="info", requires=["ad_groups", "ad_users"],
      attack=["T1078.002"],
      remediation="Tier0 群組只保留必要的專用管理帳號；Account / Server / Backup / Print Operators 應保持空白。")
def tier0_inventory(ctx, hits):
    """列出 Tier0 群組的遞移成員，作為後續分析的基準。"""
    g = ctx.graph
    groups = []
    users_all = set()
    for gid, name in sorted(ctx.tier0_groups.items(), key=lambda kv: kv[1]):
        users = {m for m in g.members(gid) if g.kind(m) == "user"}
        users_all |= users
        groups.append(ctx.ref(gid, {"users": len(users), "direct": len(g.edges_in(gid, ["MemberOf"]))}))
    if groups:
        hits.add(f"{len(ctx.tier0_groups)} 個 Tier0 群組，共 {len(users_all)} 個不重複使用者帳號。", groups, "info",
                 {"tier0Users": sorted(users_all)})
    ops = [ctx.ref(s, {"members": len(g.members(s))}) for s in known.OPERATOR_SIDS if s in g.nodes and g.members(s)]
    if ops:
        hits.add(f"{len(ops)} 個 Operators 群組有成員（皆有提權到網域管理員的已知路徑）。", ops, "medium",
                 title="Operators 群組非空白")
    if len(users_all) > 15:
        hits.add(f"Tier0 使用者帳號共 {len(users_all)} 個，數量偏多。", [], "medium", title="Tier0 帳號數量偏多")


@rule("AD-015", "LAPS 未部署或覆蓋不完整", category="AD", severity="medium", requires=["ad_computers", "ad_domain"],
      attack=["T1078.003"],
      remediation="部署 Windows LAPS（或舊版 LAPS）到所有加入網域的 Windows 主機，並限制可讀取密碼的群組。")
def laps(ctx, hits):
    """沒有 LAPS 的主機通常共用本機管理員密碼，一台失守即可橫向移動到其他主機。"""
    ws = [c for c in _enabled(ctx.computers())
          if not c.get("isDomainController") and "windows" in str(c.get("operatingSystem") or "").lower()
          and str(c.get("name") or "").upper() != "AZUREADSSOACC"]
    if not ws:
        return
    if not ctx.domain.get("lapsLegacySchema") and not ctx.domain.get("lapsWindowsSchema"):
        hits.add("網域未延伸 LAPS schema：所有主機的本機管理員密碼皆未受 LAPS 管理。", [], "high",
                 {"computers": len(ws)})
        return
    missing = [c for c in ws if not c.get("hasLaps")]
    if missing:
        hits.add(f"{len(missing)}/{len(ws)} 台啟用中的 Windows 主機沒有 LAPS 密碼。",
                 [ctx.ref(c["sid"], {"os": c.get("operatingSystem"), "lastLogonDays": ctx.days_since(c.get("lastLogonTimestamp"))})
                  for c in missing], "high" if len(missing) / len(ws) > 0.5 else "medium",
                 {"coverage": round(1 - len(missing) / len(ws), 3)})


@rule("AD-016", "網域密碼原則偏弱", category="AD", severity="medium", requires=["ad_password_policies"],
      attack=["T1110"],
      remediation="最短密碼長度至少 12（建議 14 以上或改用密碼片語）、啟用帳戶鎖定（例如 10 次 / 15 分鐘），並搭配禁用密碼清單。")
def password_policy(ctx, hits):
    """預設密碼原則過弱時，密碼噴灑與暴力破解的成功率明顯提高。"""
    p = next((r for r in ctx.rows("ad_password_policies") if r.get("kind") == "default"), None)
    if not p:
        return
    issues = []
    ml = p.get("minPasswordLength") or 0
    if ml < 12:
        issues.append(f"最短密碼長度 {ml}")
    if not p.get("lockoutThreshold"):
        issues.append("未啟用帳戶鎖定")
    if not p.get("complexityEnabled"):
        issues.append("未要求密碼複雜度")
    if issues:
        hits.add("預設網域密碼原則：" + "、".join(issues) + "。",
                 [{"id": "default-password-policy", "label": "Default Domain Policy", "kind": "passwordPolicy", "detail": issues}],
                 "high" if ml < 8 or not p.get("lockoutThreshold") else "medium", {"policy": p})


_LEGACY_OS = re.compile(r"(?i)windows\s+(xp|vista|7\b|8\b|8\.1|nt|2000)|server\s+(2000|2003|2008|2012)")


@rule("AD-017", "仍在使用已終止支援的作業系統", category="AD", severity="high", requires=["ad_computers"],
      attack=["T1210"],
      remediation="汰換或升級；無法汰換的主機隔離網段並限制可登入的帳號。")
def legacy_os(ctx, hits):
    """已終止支援的系統不再有安全更新，常是入侵與橫向移動的起點。"""
    active, idle = [], []
    for c in _enabled(ctx.computers()):
        os_ = str(c.get("operatingSystem") or "")
        if not _LEGACY_OS.search(os_):
            continue
        d = ctx.days_since(c.get("lastLogonTimestamp"))
        (active if d is not None and d <= STALE_DAYS else idle).append(ctx.ref(c["sid"], {"os": os_, "lastLogonDays": d}))
    if active:
        hits.add(f"{len(active)} 台近 {STALE_DAYS} 天仍在使用的主機執行已終止支援的作業系統。", active, "high")
    if idle:
        hits.add(f"{len(idle)} 個已終止支援作業系統的電腦帳號仍為啟用（長期未登入）。", idle, "low")


@rule("AD-018", "物件描述疑似含有密碼", category="AD", severity="high", requires=["ad_users"],
      attack=["T1552"],
      remediation="移除 description / info 欄位中的密碼，並重設相關帳號的密碼（任何網域使用者都能讀取這些欄位）。")
def secret_hint(ctx, hits):
    """收集器只記錄「疑似含密碼」旗標，不收值；任何網域使用者都能讀取這些欄位。"""
    found = []
    for ds in ("ad_users", "ad_computers", "ad_groups", "ad_service_accounts"):
        for r in ctx.rows(ds):
            if r.get("descriptionHasSecretHint") or r.get("infoHasSecretHint"):
                found.append(ctx.ref(r["sid"], "description" if r.get("descriptionHasSecretHint") else "info"))
    for r in ctx.rows("ad_ous"):
        if r.get("descriptionHasSecretHint"):
            found.append({"id": r.get("distinguishedName"), "label": r.get("name"), "kind": "ou", "detail": "description"})
    for r in ctx.rows("ad_gpos"):
        if r.get("descriptionHasSecretHint"):
            found.append(ctx.ref(f"gpo:{r['id']}", "description"))
    if found:
        hits.add(f"{len(found)} 個物件的描述欄位疑似含有密碼。", found)


@rule("AD-019", "SYSVOL 中的 GPP 密碼（cpassword）", category="AD", severity="critical", requires=["gpo_gpp_cpassword"],
      attack=["T1552.006"],
      remediation="刪除含 cpassword 的 GPP 設定檔，並立即重設其中設定的所有帳號密碼（金鑰已公開，任何網域使用者都能解密）。")
def gpp_cpassword(ctx, hits):
    """GPP 密碼以公開金鑰加密，任何能讀 SYSVOL 的使用者都能解出明文。"""
    rows = ctx.rows("gpo_gpp_cpassword")
    if rows:
        hits.add(f"{len(rows)} 個 GPP 檔案含有 cpassword。",
                 [ctx.ref(f"gpo:{r['gpoGuid']}", {"file": r.get("file"), "occurrences": r.get("occurrences")}) for r in rows])


def _tier0_targets(ctx) -> dict[str, str]:
    """node id -> why it is a Tier0 target."""
    g = ctx.graph
    out: dict[str, str] = {}
    if ctx.domain_sid and ctx.domain_sid in g.nodes:
        out[ctx.domain_sid] = "domain root"
    dom_dn = str(ctx.domain.get("distinguishedName") or "").lower()
    asd = ctx.dn_index.get(f"cn=adminsdholder,cn=system,{dom_dn}")
    if asd:
        out[asd] = "AdminSDHolder"
    for sid in ctx.tier0:
        if sid in g.nodes and g.kind(sid) in ("user", "group", "computer", "gmsa"):
            out.setdefault(sid, "Tier0 " + g.kind(sid))
    dc_containers = set()
    for dc in ctx.dc_sids:
        for e in g.edges_in(dc, ["Contains"]):
            dc_containers.add(e.src)
    for c in dc_containers:
        if g.kind(c) in ("ou", "container"):
            out.setdefault(c, "contains domain controllers")
    linked_to = set(dc_containers) | ({ctx.domain_sid} if ctx.domain_sid else set())
    for e in [e for e in g.edges if e.kind == "GPLink" and e.dst in linked_to and e.props.get("enabled", True)]:
        out.setdefault(e.src, "GPO linked to " + ("domain root" if e.dst == ctx.domain_sid else g.label(e.dst)))
    return out


@rule("AD-020", "非 Tier0 主體對 Tier0 物件有控制權限", category="AD", severity="high",
      requires=["ad_acls", "ad_groups"], attack=["T1098", "T1484.001"],
      remediation="移除這些 ACE 或擁有者設定；確實需要的委派改由 Tier0 管理帳號執行。Exchange 相關群組在 domain root 的 WriteDacl 應依 Microsoft 指引移除（split permissions）。")
def tier0_acl(ctx, hits):
    """對 Tier0 物件有 GenericAll / WriteDacl / WriteOwner / 改密碼 / 加成員等權限，等同可取得網域控制權。"""
    g = ctx.graph
    targets = _tier0_targets(ctx)
    by_principal: dict[str, list[str]] = defaultdict(list)
    crit = set()
    for tid, why in targets.items():
        for e in g.edges_in(tid):
            if e.kind not in acl.CONTROL_KINDS or e.kind == "DCSync":
                continue
            p = e.src
            if p in ctx.tier0 or p in known.SAFE_ACL_PRINCIPALS or not p.startswith(("S-1-", "dn:")):
                continue
            if why == "contains domain controllers":
                # On the OU itself only full control / gPLink matter; other rights matter when they inherit to the DCs.
                inheritable = any(i != "None" for i in e.props.get("inheritance") or [])
                if e.kind not in _OU_DIRECT and not inheritable:
                    continue
            by_principal[p].append(f"{e.kind} → {g.label(tid)}（{why}）")
            if ctx.is_broad(p) or why in ("domain root", "AdminSDHolder"):
                crit.add(p)
    if not by_principal:
        return
    items = [ctx.ref(p, sorted(set(v))[:15]) for p, v in sorted(by_principal.items(), key=lambda kv: (kv[0] not in crit, ctx.label(kv[0])))]
    hits.add(f"{len(by_principal)} 個非 Tier0 主體對 Tier0 物件（domain root、AdminSDHolder、DC、Tier0 群組 / 帳號、連結到 DC 的 GPO）有控制權限。",
             items, "critical" if crit else "high", {"criticalPrincipals": sorted(crit)})


@rule("AD-021", "具 DCSync 權限的非預設主體", category="AD", severity="critical", requires=["ad_acls", "ad_groups"],
      attack=["T1003.006"],
      remediation="移除非必要主體的 DS-Replication-Get-Changes(-All) 權限。Entra Connect 的 AD DS connector 帳號需要此權限：視同 Tier0 保護（強密碼、禁止互動式登入、不加入其他群組、監控非 DC 來源的 4662 複寫事件），Entra Connect 伺服器視同 DC 管理。")
def dcsync(ctx, hits):
    """持有 Get-Changes + Get-Changes-All 的主體可從 DC 複寫出所有帳號（含 krbtgt）的密碼雜湊。"""
    if not ctx.domain_sid:
        return
    expected = set(ctx.tier0_groups) | {"S-1-5-18", "S-1-5-9"}
    connectors = _connector_accounts(ctx)
    bad, conn = [], []
    for e in ctx.graph.edges_in(ctx.domain_sid, ["DCSync"]):
        if e.src in expected:
            continue
        if _is_connector(ctx, e.src, connectors):
            conn.append(ctx.ref(e.src, "Entra Connect AD DS connector 帳號"))
        else:
            bad.append(ctx.ref(e.src, {"tier0Member": e.src in ctx.tier0}))
    if bad:
        hits.add(f"{len(bad)} 個非預設主體可執行 DCSync。", bad, "critical")
    if conn:
        hits.add("Entra Connect connector 帳號具 DCSync 權限（密碼雜湊同步所需）。此帳號已納入 Tier0 評估；"
                 "它與 Entra Connect 伺服器都必須以 Tier0 標準保護。",
                 conn, "info", title="Entra Connect connector 帳號具 DCSync 權限（等同 Tier0）")


@rule("AD-022", "網域信任設定風險", category="AD", severity="high", requires=["ad_trusts"],
      attack=["T1482", "T1134.005"],
      remediation="外部信任啟用 SID filtering（quarantine）；樹系信任不要啟用 SID history（TREAT_AS_EXTERNAL）與 TGT 委派；跨組織信任考慮選擇性驗證。")
def trusts(ctx, hits):
    """信任設定不當時，對方網域的入侵可透過 SID history 或 TGT 委派延伸到本網域。"""
    out = []
    for t in ctx.rows("ad_trusts"):
        if t.get("intraForest"):
            continue
        attrs = int(t.get("trustAttributes") or 0)
        forest = bool(attrs & 0x8) or t.get("forestTransitive")
        issues = []
        if not forest and not (attrs & 0x4) and not t.get("sidFilteringQuarantined"):
            issues.append("外部信任未啟用 SID filtering")
        if forest and attrs & 0x40:
            issues.append("樹系信任啟用 SID history（TREAT_AS_EXTERNAL）")
        if attrs & 0x800 or t.get("tgtDelegation"):
            issues.append("允許跨信任 TGT 委派")
        if t.get("usesRC4Encryption") and not t.get("usesAESKeys"):
            issues.append("信任僅使用 RC4")
        if issues:
            out.append({"id": f"trust:{t.get('target')}", "label": t.get("target"), "kind": "trust",
                        "detail": {"direction": t.get("direction"), "issues": issues}})
    if out:
        hits.add(f"{len(out)} 個外部信任有設定風險。", out,
                 "high" if any(i for o in out for i in o["detail"]["issues"] if "RC4" not in i) else "low")


@rule("AD-023", "gMSA 密碼可被非 Tier0 主體讀取", category="AD", severity="medium",
      requires=["ad_service_accounts", "ad_groups"], attack=["T1555"],
      remediation="PrincipalsAllowedToRetrieveManagedPassword 只保留實際執行服務的主機；Tier0 用途的 gMSA 只允許 Tier0 主機讀取。")
def gmsa_readers(ctx, hits):
    """能讀取 gMSA 密碼即可以該服務帳號身分登入。由執行服務的主機讀取是正常設計，只回報 Tier0 gMSA 與廣泛群組可讀的情況。"""
    g = ctx.graph
    out, sev = [], "high"
    for r in ctx.rows("ad_service_accounts"):
        readers = [e.src for e in g.edges_in(r["sid"], ["ReadGMSAPassword"]) if e.src not in ctx.tier0]
        t0 = r["sid"] in ctx.tier0
        broad = [p for p in readers if ctx.is_broad(p)]
        if not readers or not (t0 or broad):
            continue
        if t0:
            sev = "critical"
        out.append(ctx.ref(r["sid"], {"tier0": t0, "readers": [ctx.label(p) for p in readers]}))
    if out:
        hits.add(f"{len(out)} 個 gMSA 的密碼可被廣泛群組讀取，或為 Tier0 用途卻可被非 Tier0 主體讀取。", out, sev)


@rule("AD-024", "Tier0 帳號帶有 Key Credential（可能的 Shadow Credentials）", category="AD", severity="medium",
      requires=["ad_users", "ad_groups"], attack=["T1556"],
      remediation="確認每個 msDS-KeyCredentialLink 是否為合法的 Windows Hello for Business 註冊；不明的項目移除並調查。")
def shadow_creds(ctx, hits):
    """攻擊者寫入 msDS-KeyCredentialLink 後可用 PKINIT 以該帳號身分取得票證。注意：低權限收集帳號可能讀不到此屬性。"""
    found = [u for u in _enabled(ctx.users()) if u["sid"] in ctx.tier0 and (u.get("keyCredentialLinkCount") or 0) > 0]
    if found:
        hits.add(f"{len(found)} 個 Tier0 使用者帶有 Key Credential。",
                 [ctx.ref(u["sid"], {"keyCredentials": u.get("keyCredentialLinkCount")}) for u in found])


@rule("AD-025", "網域功能等級與 AD 資源回收筒", category="AD", severity="low", requires=["ad_domain", "ad_forest"],
      attack=[],
      remediation="提升網域 / 樹系功能等級到 Windows Server 2016 以上，並啟用 AD 資源回收筒。")
def functional_level(ctx, hits):
    """較舊的功能等級無法使用 Protected Users 的完整保護、Kerberos armoring 等功能。"""
    issues = []
    mode = str(ctx.domain.get("domainMode") or "")
    m = re.search(r"(\d{4})", mode)
    if m and int(m.group(1)) < 2016:
        issues.append(f"網域功能等級 {mode}")
    forest = (ctx.rows("ad_forest") or [{}])[0]
    rb = [f for f in forest.get("optionalFeatures") or [] if "Recycle Bin" in str(f.get("name"))]
    if rb and not rb[0].get("enabled"):
        issues.append("AD 資源回收筒未啟用")
    if issues:
        hits.add("、".join(issues) + "。", [ctx.ref(ctx.domain_sid or "domain", issues)])


@rule("AD-026", "dSHeuristics 放寬安全設定", category="AD", severity="high", requires=["ad_domain"],
      attack=["T1087.002"],
      remediation="還原 dSHeuristics：第 7 碼不應為 2（匿名 LDAP 操作）；第 16 碼（dwAdminSDExMask）不應排除任何 Operators 群組。")
def ds_heuristics(ctx, hits):
    """dSHeuristics 可開放匿名 LDAP 存取，或讓特定特權群組不受 AdminSDHolder 保護。"""
    h = str(ctx.domain.get("dsHeuristics") or "")
    issues = []
    if len(h) >= 7 and h[6] == "2":
        issues.append("允許匿名 LDAP 操作（第 7 碼 = 2）")
    if len(h) >= 16 and h[15] not in ("0", ""):
        issues.append(f"AdminSDHolder 排除 Operators 群組（第 16 碼 = {h[15]}）")
    if issues:
        hits.add("、".join(issues) + "。", [ctx.ref(ctx.domain_sid or "domain", {"dsHeuristics": h})],
                 "high" if any("匿名" in i for i in issues) else "medium")


@rule("AD-027", "Pre-Windows 2000 相容存取群組包含匿名或 Everyone", category="AD", severity="medium",
      requires=["ad_groups"], attack=["T1087.002"],
      remediation="從 Pre-Windows 2000 Compatible Access 移除 Everyone 與 ANONYMOUS LOGON。")
def pre2000(ctx, hits):
    """此群組有網域物件的大範圍讀取權，包含匿名時等同未驗證即可列舉網域。"""
    members = ctx.graph.members("S-1-5-32-554")
    bad = [m for m in members if m in ("S-1-1-0", "S-1-5-7")]
    if bad:
        hits.add("Pre-Windows 2000 Compatible Access 包含 " + "、".join(ctx.label(b) for b in bad) + "。",
                 [ctx.ref("S-1-5-32-554", [ctx.label(b) for b in bad])])


@rule("AD-028", "長期未使用但仍啟用的帳號", category="AD", severity="low", requires=["ad_users", "ad_computers"],
      attack=["T1078.002"],
      remediation="建立帳號生命週期流程：超過 90 天未登入的帳號停用，再經一段觀察期後刪除。")
def inactive(ctx, hits):
    """閒置帳號沒有人注意其異常登入，常被用於持久化。"""
    def stale(r):
        d = ctx.days_since(r.get("lastLogonTimestamp"))
        created = ctx.days_since(r.get("whenCreated"))
        return (d is None and (created or 0) > STALE_DAYS) or (d is not None and d > STALE_DAYS)
    users = [u for u in _enabled(ctx.users()) if stale(u) and rid_of(u["sid"]) not in (500, 502)]
    comps = [c for c in _enabled(ctx.computers()) if stale(c) and not c.get("isDomainController")
             and str(c.get("name") or "").upper() != "AZUREADSSOACC"]
    if users:
        hits.add(f"{len(users)} 個啟用中的使用者超過 {STALE_DAYS} 天未登入。",
                 [ctx.ref(u["sid"], {"lastLogonDays": ctx.days_since(u.get("lastLogonTimestamp"))}) for u in users],
                 title="長期未使用但仍啟用的使用者帳號")
    if comps:
        hits.add(f"{len(comps)} 個啟用中的電腦帳號超過 {STALE_DAYS} 天未登入。",
                 [ctx.ref(c["sid"], {"lastLogonDays": ctx.days_since(c.get("lastLogonTimestamp"))}) for c in comps],
                 title="長期未使用但仍啟用的電腦帳號")


@rule("AD-029", "adminCount=1 但已不在特權群組", category="AD", severity="low", requires=["ad_users", "ad_groups"],
      attack=[],
      remediation="清除 adminCount 並重新啟用 ACL 繼承，讓物件回到一般的委派管理。")
def admincount_orphans(ctx, hits):
    """曾經是特權成員的帳號保留 adminCount 與鎖定的 ACL，常是遺留的特權帳號或權限漂移的跡象。"""
    found = [u for u in ctx.users() if u.get("adminCount") == 1 and u["sid"] not in ctx.tier0 and rid_of(u["sid"]) != 502]
    if found:
        hits.add(f"{len(found)} 個帳號 adminCount=1 但目前不在 Tier0 群組。",
                 [ctx.ref(u["sid"], {"enabled": u.get("enabled")}) for u in found])


@rule("AD-030", "內建 Guest 帳號已啟用", category="AD", severity="medium", requires=["ad_users"],
      attack=["T1078.001"], remediation="停用內建 Guest 帳號。")
def guest_enabled(ctx, hits):
    """啟用的 Guest 帳號允許不具名存取。"""
    g = [u for u in _enabled(ctx.users()) if rid_of(u["sid"]) == 501]
    if g:
        hits.add("內建 Guest 帳號為啟用狀態。", [ctx.ref(u["sid"]) for u in g])
