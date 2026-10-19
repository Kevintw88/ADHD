"""Entra ID rules."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .. import known
from ..bundle import parse_ts
from ..load import rid_of
from . import rule

STALE_DAYS = 90


# -- helpers ------------------------------------------------------------------------------------
def _priv(ctx, tiers=("tier0", "high"), kinds=("entraUser",)) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for nid, entries in ctx.entra_priv.items():
        es = [e for e in entries if e["tier"] in tiers]
        if es and ctx.graph.kind(nid) in kinds:
            out[nid] = es
    return out


def _roles(ctx, entries: list[dict[str, Any]]) -> list[str]:
    return sorted({e["role"] + ("（合格）" if e["source"] == "eligible" else "")
                   + (f"（經由群組 {ctx.label(e['via'])}）" if e.get("via") else "") for e in entries})


def _sec_defaults(ctx) -> bool:
    return any(r.get("isEnabled") for r in ctx.rows("entra_security_defaults"))


def _enabled_ca(ctx) -> list[dict[str, Any]]:
    return [p for p in ctx.rows("entra_ca_policies") if p.get("state") == "enabled"]


def _cond(p, key) -> dict[str, Any]:
    return ((p.get("conditions") or {}).get(key)) or {}


def _grants(p) -> list[str]:
    return list((p.get("grantControls") or {}).get("builtInControls") or [])


def _requires_mfa(p) -> bool:
    gc = p.get("grantControls") or {}
    return "mfa" in _grants(p) or bool(gc.get("authenticationStrength"))


def _all_apps(p) -> bool:
    return "All" in (_cond(p, "applications").get("includeApplications") or [])


def _all_users(p) -> bool:
    return "All" in (_cond(p, "users").get("includeUsers") or [])


def _ca_ref(p, detail=None) -> dict[str, Any]:
    out = {"id": f"ca:{p.get('id')}", "label": p.get("displayName"), "kind": "caPolicy"}
    if detail:
        out["detail"] = detail
    return out


def _last_signin(u: dict[str, Any]):
    sia = u.get("signInActivity") or {}
    times = [parse_ts(sia.get(k)) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")]
    times = [t for t in times if t]
    return max(times) if times else None


# ---------------------------------------------------------------------------------------------
@rule("EN-001", "Global Administrator 人數", category="Entra", severity="medium",
      requires=["entra_role_assignments", "entra_users"], attack=["T1078.004"],
      remediation="Global Administrator 維持 2–4 個（含 2 個雲端專用、排除在 CA 之外並受監控的緊急存取帳號），其餘改用最小權限角色並透過 PIM 啟用。")
def ga_count(ctx, hits):
    """Global Administrator 過多會擴大攻擊面；少於 2 個則沒有緊急存取備援。"""
    gas = [nid for nid, es in _priv(ctx, ("tier0",)).items() if any(e["roleId"] == known.GLOBAL_ADMIN for e in es)]
    items = [ctx.ref(n, _roles(ctx, [e for e in ctx.entra_priv[n] if e["roleId"] == known.GLOBAL_ADMIN])) for n in gas]
    if len(gas) > 5:
        hits.add(f"共 {len(gas)} 個使用者具 Global Administrator（含合格指派）。", items, "medium")
    elif len(gas) < 2:
        hits.add(f"只有 {len(gas)} 個使用者具 Global Administrator，缺少緊急存取備援。", items, "low",
                 title="Global Administrator 少於 2 個")


@rule("EN-002", "特權角色持有者未註冊 MFA", category="Entra", severity="high",
      requires=["entra_role_assignments", "entra_user_registration"], attack=["T1078.004", "T1110"],
      remediation="要求所有特權角色持有者註冊抗網路釣魚的 MFA（FIDO2 / Windows Hello / 憑證），並以 CA 的驗證強度強制。")
def priv_no_mfa(ctx, hits):
    """未註冊 MFA 的特權帳號只靠密碼保護。"""
    reg = {f"entra:{r['id']}": r for r in ctx.rows("entra_user_registration")}
    t0, high = [], []
    for nid, es in _priv(ctx).items():
        r = reg.get(nid)
        if r is None or r.get("isMfaRegistered"):
            continue
        item = ctx.ref(nid, {"roles": _roles(ctx, es), "methods": r.get("methodsRegistered")})
        (t0 if any(e["tier"] == "tier0" for e in es) else high).append(item)
    if t0:
        hits.add(f"{len(t0)} 個 Tier0 角色持有者未註冊 MFA。", t0, "critical")
    if high:
        hits.add(f"{len(high)} 個高權限角色持有者未註冊 MFA。", high, "high")


@rule("EN-003", "來賓帳號持有特權角色", category="Entra", severity="high",
      requires=["entra_role_assignments", "entra_users"], attack=["T1078.004"],
      remediation="移除來賓帳號的特權角色；需要外部人員管理時改用 GDAP 或在本租用戶建立受控帳號。")
def guest_priv(ctx, hits):
    """來賓帳號的驗證與生命週期由對方租用戶控制。"""
    found = [ctx.ref(n, _roles(ctx, es)) for n, es in _priv(ctx).items() if (ctx.entra.get(n) or {}).get("userType") == "Guest"]
    if found:
        hits.add(f"{len(found)} 個來賓帳號持有特權角色。", found)


@rule("EN-004", "服務主體持有特權目錄角色", category="Entra", severity="high",
      requires=["entra_role_assignments", "entra_service_principals"], attack=["T1098.001", "T1078.004"],
      remediation="移除服務主體的特權目錄角色，改用範圍最小的 Graph 應用程式權限；保留者限制擁有者並監控其憑證新增。")
def sp_priv(ctx, hits):
    """服務主體不受 MFA / CA 保護，取得其憑證即可以特權角色操作租用戶。"""
    sps = _priv(ctx, kinds=("servicePrincipal",))
    if sps:
        t0 = any(e["tier"] == "tier0" for es in sps.values() for e in es)
        hits.add(f"{len(sps)} 個服務主體持有特權目錄角色。", [ctx.ref(n, _roles(ctx, es)) for n, es in sps.items()],
                 "critical" if t0 else "high")


@rule("EN-005", "特權角色常駐指派（未透過 PIM 啟用）", category="Entra", severity="medium",
      requires=["entra_role_assignments"], attack=["T1078.004"],
      remediation="Tier0 角色改為 PIM 合格指派，啟用時要求 MFA、理由與核准；只保留緊急存取帳號為常駐。")
def permanent_priv(ctx, hits):
    """常駐的特權角色在帳號遭入侵時立即可用，也無法留下啟用紀錄。"""
    if not ctx.pim_available:
        hits.add("無法讀取 PIM 指派排程（通常是租用戶沒有 Entra ID P2），無法區分常駐與 PIM 啟用中的指派。", [], "info",
                 title="PIM 資料不可用")
        return
    found = []
    for n, es in _priv(ctx, ("tier0",), kinds=("entraUser", "entraGroup", "servicePrincipal")).items():
        perm = [e for e in es if e["source"] == "active" and e.get("permanent") and not e.get("via")]
        if perm:
            found.append(ctx.ref(n, _roles(ctx, perm)))
    if found:
        hits.add(f"{len(found)} 個主體以常駐方式持有 Tier0 角色。", found)


@rule("EN-006", "未強制 MFA", category="Entra", severity="high",
      requires=[("entra_ca_policies", "entra_security_defaults")], attack=["T1078.004", "T1110.003"],
      remediation="建立對所有使用者、所有雲端應用程式要求 MFA 的 CA 原則（排除 1–2 個緊急存取帳號），並對管理員角色另設抗網路釣魚驗證強度。")
def mfa_enforcement(ctx, hits):
    """沒有 Security Defaults 也沒有要求 MFA 的 CA 原則時，帳號只靠密碼保護。"""
    if _sec_defaults(ctx):
        return
    if not ctx.usable("entra_ca_policies"):
        hits.add("Security Defaults 已關閉，且無法讀取條件式存取原則（可能沒有 P1）。", [], "high")
        return
    pols = [p for p in _enabled_ca(ctx) if _requires_mfa(p) and _all_apps(p)]
    all_users = [p for p in pols if _all_users(p)]
    admin = [p for p in pols if known.GLOBAL_ADMIN in (_cond(p, "users").get("includeRoles") or [])]
    if not all_users and not admin:
        hits.add("Security Defaults 已關閉，且沒有任何啟用中的 CA 原則對所有使用者或管理員角色要求 MFA。", [], "critical")
    elif not all_users:
        hits.add("只有管理員角色受 MFA 原則保護，一般使用者未強制 MFA。", [_ca_ref(p) for p in admin], "high")


@rule("EN-007", "未封鎖舊式驗證", category="Entra", severity="high",
      requires=[("entra_ca_policies", "entra_security_defaults")], attack=["T1110.003"],
      remediation="建立封鎖舊式驗證（Exchange ActiveSync 與其他用戶端）的 CA 原則，套用所有使用者。")
def legacy_auth(ctx, hits):
    """舊式驗證協定不支援 MFA，是密碼噴灑最常用的入口。"""
    if _sec_defaults(ctx):
        return
    for p in _enabled_ca(ctx):
        types = set((p.get("conditions") or {}).get("clientAppTypes") or [])
        if {"exchangeActiveSync", "other"} <= types and "block" in _grants(p) and _all_users(p):
            return
    hits.add("沒有啟用中的 CA 原則對所有使用者封鎖舊式驗證，Security Defaults 也已關閉。", [])


@rule("EN-008", "條件式存取原則的排除對象", category="Entra", severity="medium",
      requires=["entra_ca_policies"], attack=["T1078.004"],
      remediation="排除清單只保留緊急存取帳號；其他例外改用更精確的條件，並定期覆核。")
def ca_exclusions(ctx, hits):
    """被排除的帳號不受 MFA / 封鎖原則保護，常成為攻擊者的目標。"""
    g = ctx.graph
    items, users_all = [], set()
    for p in _enabled_ca(ctx):
        if not (_requires_mfa(p) or "block" in _grants(p)):
            continue
        u = _cond(p, "users")
        ex_users = [f"entra:{x}" for x in u.get("excludeUsers") or [] if x not in ("GuestsOrExternalUsers",)]
        ex_groups = [f"entra:{x}" for x in u.get("excludeGroups") or []]
        members = set(ex_users)
        for gid in ex_groups:
            members |= {m for m in g.members(gid, ("EntraMemberOf",)) if g.kind(m) == "entraUser"}
        if not members and not ex_groups:
            continue
        users_all |= members
        items.append(_ca_ref(p, {"excludedUsers": [g.label(x) for x in ex_users],
                                 "excludedGroups": [f"{g.label(x)}（{len(g.members(x, ('EntraMemberOf',)))} 人）" for x in ex_groups],
                                 "effectiveUsers": len(members)}))
    if items:
        few = len(users_all) <= 2
        hits.add(f"{len(items)} 條 MFA / 封鎖原則有排除對象，合計 {len(users_all)} 個使用者不受保護"
                 + ("（人數符合緊急存取帳號的建議做法，請確認身分）。" if few else "。"), items,
                 "info" if few else "medium", {"excludedUsers": sorted(users_all)})


@rule("EN-009", "未啟用或僅報告模式的條件式存取原則", category="Entra", severity="info",
      requires=["entra_ca_policies"], attack=[],
      remediation="確認報告模式原則的評估結果後啟用，停用的原則若不再需要則刪除。")
def ca_not_enforced(ctx, hits):
    """報告模式與停用的原則不會產生任何保護。"""
    items = [_ca_ref(p, p.get("state")) for p in ctx.rows("entra_ca_policies") if p.get("state") != "enabled"]
    if items:
        hits.add(f"{len(items)} 條 CA 原則未強制執行。", items)


@rule("EN-010", "一般使用者可註冊應用程式", category="Entra", severity="medium",
      requires=["entra_authorization_policy"], attack=["T1098.001"],
      remediation="將「使用者可以註冊應用程式」設為否，應用程式改由 Application Developer 角色或流程建立。")
def users_create_apps(ctx, hits):
    """任何使用者建立的 App 都可要求權限並成為網路釣魚同意攻擊或持久化的載體。"""
    ap = (ctx.rows("entra_authorization_policy") or [{}])[0]
    if (ap.get("defaultUserRolePermissions") or {}).get("allowedToCreateApps"):
        hits.add("defaultUserRolePermissions.allowedToCreateApps = true。", [])


@rule("EN-011", "使用者可自行同意應用程式權限", category="Entra", severity="high",
      requires=["entra_authorization_policy"], attack=["T1528"],
      remediation="使用者同意改為「只允許已驗證發行者的低風險權限」或完全關閉，並啟用管理員同意要求流程。")
def user_consent(ctx, hits):
    """使用者可同意任意 App 的委派權限時，同意網路釣魚（illicit consent grant）即可取得信箱與檔案存取。"""
    ap = (ctx.rows("entra_authorization_policy") or [{}])[0]
    ids = ap.get("permissionGrantPolicyIdsAssignedToDefaultUserRole") or \
        (ap.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or []
    if any("microsoft-user-default-legacy" in str(i) for i in ids):
        hits.add("使用者可同意任何應用程式的委派權限（microsoft-user-default-legacy）。", [], "high", {"policies": ids})
    elif any("microsoft-user-default-low" in str(i) for i in ids):
        hits.add("使用者可同意已驗證發行者的低風險權限（microsoft-user-default-low）。", [], "low", {"policies": ids})


@rule("EN-012", "來賓存取設定寬鬆", category="Entra", severity="medium",
      requires=["entra_authorization_policy"], attack=["T1078.004"],
      remediation="來賓使用者存取設為「受限」，邀請權限限縮到管理員或特定角色。")
def guest_settings(ctx, hits):
    """來賓權限與成員相同時可列舉整個目錄；任何人都能邀請時無法控管外部帳號。"""
    ap = (ctx.rows("entra_authorization_policy") or [{}])[0]
    issues = []
    if ap.get("guestUserRoleId") == known.GUEST_ROLE_SAME_AS_MEMBER:
        issues.append("來賓與成員權限相同")
    if ap.get("allowInvitesFrom") == "everyone":
        issues.append("任何人（含來賓）都能邀請來賓")
    if issues:
        hits.add("、".join(issues) + "。", [], "high" if "來賓與成員權限相同" in issues else "medium", {"settings": issues})


@rule("EN-013", "服務主體持有高風險應用程式權限", category="Entra", severity="high",
      requires=["entra_app_role_assignments", "entra_service_principals"], attack=["T1098.001", "T1528"],
      remediation="移除不必要的應用程式權限；保留者改用範圍限制（例如 Exchange RBAC for Applications、Sites.Selected），限制擁有者並監控憑證新增。")
def dangerous_app_perms(ctx, hits):
    """應用程式權限不需使用者登入、不受 CA / MFA 限制；部分權限可直接提升為 Global Administrator。"""
    t0, high = [], []
    by_sp: dict[str, set[str]] = defaultdict(set)
    for e in ctx.graph.edges:
        if e.kind == "AppRole" and ctx.graph.kind(e.src) == "servicePrincipal":
            by_sp[e.src] |= set(e.props.get("permission") or [])
    for sp, perms in by_sp.items():
        r = ctx.entra.get(sp) or {}
        p0 = sorted(perms & known.TIER0_APP_PERMISSIONS)
        ph = sorted(perms & known.HIGH_APP_PERMISSIONS)
        detail = {"permissions": p0 + ph, "type": r.get("servicePrincipalType"),
                  "ownedByTenant": r.get("appOwnerOrganizationId") == ctx.tenant_id}
        if p0:
            t0.append(ctx.ref(sp, detail))
        elif ph:
            high.append(ctx.ref(sp, detail))
    if t0:
        hits.add(f"{len(t0)} 個服務主體持有可提權為租用戶管理員的應用程式權限。", t0, "critical")
    if high:
        hits.add(f"{len(high)} 個服務主體持有可大範圍存取資料的應用程式權限。", high, "high")


@rule("EN-014", "應用程式憑證衛生", category="Entra", severity="medium",
      requires=["entra_applications", "entra_service_principals"], attack=["T1098.001"],
      remediation="Client secret 存留期不超過 1 年並優先改用憑證或 workload identity federation；清除過期憑證；服務主體層級的密碼除 SAML 簽章外應移除並調查。")
def app_credentials(ctx, hits):
    """長效 secret 外洩風險高；服務主體層級的密碼不顯示在 App 註冊頁面，常被用作後門。"""
    long_lived, expired, sp_pw = [], [], []
    for r in ctx.rows("entra_applications"):
        nid = f"entra:{r['id']}"
        for c in (r.get("passwordCredentials") or []) + (r.get("keyCredentials") or []):
            start, end = parse_ts(c.get("startDateTime")), parse_ts(c.get("endDateTime"))
            if end and end < ctx.as_of:
                expired.append(ctx.ref(nid, {"keyId": c.get("keyId"), "expired": c.get("endDateTime")}))
            elif start and end and (end - start).days > 730 and c in (r.get("passwordCredentials") or []):
                long_lived.append(ctx.ref(nid, {"keyId": c.get("keyId"), "lifetimeDays": (end - start).days}))
    system_sp = []
    for r in ctx.rows("entra_service_principals"):
        if r.get("passwordCredentials") and r.get("preferredSingleSignOnMode") != "saml" \
                and r.get("appOwnerOrganizationId") == ctx.tenant_id:
            item = ctx.ref(f"entra:{r['id']}", {"passwords": len(r["passwordCredentials"])})
            (system_sp if r.get("displayName") in known.SYSTEM_SERVICE_PRINCIPALS else sp_pw).append(item)
    if sp_pw:
        hits.add(f"{len(sp_pw)} 個服務主體設有服務主體層級的密碼。", sp_pw, "medium", title="服務主體層級的密碼")
    if system_sp:
        hits.add("系統自動建立的服務主體帶有服務主體層級的憑證（例如 P2P Server 用於 Entra 加入裝置間的 RDP），"
                 "通常由服務自動產生；請確認憑證建立時間與裝置使用情況一致。", system_sp, "info",
                 title="系統服務主體的憑證")
    if long_lived:
        hits.add(f"{len(long_lived)} 個 client secret 存留期超過 2 年。", long_lived, "medium", title="長效 client secret")
    if expired:
        hits.add(f"{len(expired)} 個應用程式憑證已過期未清除。", expired, "low", title="過期的應用程式憑證")


@rule("EN-015", "管理員同意的高風險委派權限", category="Entra", severity="high",
      requires=["entra_oauth2_grants"], attack=["T1528"],
      remediation="覆核以「代表組織同意」(AllPrincipals) 授予的高風險委派權限，移除不需要的同意。")
def risky_delegated(ctx, hits):
    """代表整個組織同意的委派權限，讓 App 能以任何登入使用者的身分存取資料（仍受該使用者本身權限限制）。"""
    by_client: dict[str, list[str]] = defaultdict(list)
    for e in ctx.graph.edges:
        if e.kind != "OAuthGrant" or "AllPrincipals" not in (e.props.get("consentType") or []):
            continue
        risky = sorted(set(e.props.get("scope") or []) & known.HIGH_DELEGATED_SCOPES)
        if risky:
            by_client[e.src].append(f"{ctx.label(e.dst)}: {', '.join(risky)}")
    first_party, other = [], []
    for sp, grants in by_client.items():
        owner = (ctx.entra.get(sp) or {}).get("appOwnerOrganizationId")
        item = ctx.ref(sp, {"grants": sorted(grants), "owner": "Microsoft" if owner in known.MICROSOFT_TENANTS
                            else ("本租用戶" if owner == ctx.tenant_id else "第三方")})
        (first_party if owner in known.MICROSOFT_TENANTS else other).append(item)
    if other:
        hits.add(f"{len(other)} 個本租用戶 / 第三方應用程式取得代表組織同意的高風險委派權限。", other, "high")
    if first_party:
        hits.add(f"{len(first_party)} 個 Microsoft 第一方應用程式有代表組織同意的高風險委派權限"
                 "（多為 SharePoint / Office 功能自動建立或管理員曾同意，請確認仍在使用）。", first_party, "low",
                 title="Microsoft 第一方應用程式的組織同意")


@rule("EN-016", "Identity Protection 風險使用者", category="Entra", severity="high",
      requires=["entra_risky_users"], attack=["T1078.004"],
      remediation="調查並處理風險使用者（重設密碼、撤銷工作階段、確認登入紀錄），並以使用者風險 CA 原則自動處理。")
def risky_users(ctx, hits):
    """Identity Protection 判定帳號可能已遭入侵。"""
    found, confirmed = [], False
    for r in ctx.rows("entra_risky_users"):
        if r.get("riskState") in ("atRisk", "confirmedCompromised") and r.get("riskLevel") in ("high", "medium"):
            confirmed = confirmed or r.get("riskState") == "confirmedCompromised"
            found.append(ctx.ref(f"entra:{r['id']}", {"riskLevel": r.get("riskLevel"), "riskState": r.get("riskState"),
                                                     "privileged": f"entra:{r['id']}" in ctx.entra_priv}))
    if found:
        hits.add(f"{len(found)} 個使用者為中 / 高風險且尚未處理。", found, "critical" if confirmed else "high")


@rule("EN-017", "長期未登入的來賓帳號", category="Entra", severity="low", requires=["entra_users"],
      attack=["T1078.004"],
      remediation="以存取權檢閱定期清除長期未登入或未接受邀請的來賓帳號。")
def stale_guests(ctx, hits):
    """閒置的來賓帳號保留對租用戶資源的存取，且沒有人監控。"""
    guests = [u for u in ctx.rows("entra_users") if u.get("userType") == "Guest" and u.get("accountEnabled")]
    if not guests or not any("signInActivity" in u for u in ctx.rows("entra_users")):
        return
    found = []
    for u in guests:
        last = _last_signin(u)
        age = (ctx.as_of - last).days if last else None
        if (age is None and (ctx.days_since(u.get("createdDateTime")) or 0) > 30) or (age is not None and age > STALE_DAYS):
            found.append(ctx.ref(f"entra:{u['id']}", {"lastSignInDays": age, "state": u.get("externalUserState")}))
    if found:
        hits.add(f"{len(found)}/{len(guests)} 個啟用中的來賓超過 {STALE_DAYS} 天未登入或從未登入。", found)


@rule("EN-018", "特權物件的擁有者不是特權帳號", category="Entra", severity="high",
      requires=["entra_role_assignments", "entra_group_memberships"], attack=["T1098", "T1098.001"],
      remediation="移除可指派角色群組、特權 App / 服務主體的非特權擁有者；擁有者等同可取得該物件的權限。")
def priv_owners(ctx, hits):
    """群組擁有者可加自己為成員；App / 服務主體擁有者可新增憑證並以其身分操作。"""
    g = ctx.graph
    privileged_targets: dict[str, str] = {}
    for nid, es in ctx.entra_priv.items():
        if any(e["tier"] in ("tier0", "high") and not e.get("via") for e in es) and g.kind(nid) in ("entraGroup", "servicePrincipal"):
            privileged_targets[nid] = "持有特權角色"
    for e in g.edges:
        if e.kind == "AppRole" and set(e.props.get("permission") or []) & known.TIER0_APP_PERMISSIONS:
            privileged_targets.setdefault(e.src, "持有 Tier0 應用程式權限")
    for e in list(g.edges):  # application -> service principal
        if e.kind == "AppIdentity" and e.dst in privileged_targets:
            privileged_targets.setdefault(e.src, "其服務主體" + privileged_targets[e.dst])
    found = []
    for tid, why in privileged_targets.items():
        owners = [e.src for e in g.edges_in(tid, ["Owns"])
                  if not any(x["tier"] == "tier0" for x in ctx.entra_priv.get(e.src, []))]
        if owners:
            found.append(ctx.ref(tid, {"reason": why, "owners": [ctx.label(o) for o in owners]}))
    if found:
        hits.add(f"{len(found)} 個特權群組 / App / 服務主體由非 Tier0 帳號擁有。", found)


@rule("EN-019", "Entra Connect 伺服器的本機管理員不是 Tier0", category="Entra", severity="high",
      requires=["entraconnect_server", "ad_groups"], attack=["T1003.006", "T1078.002"],
      remediation="Entra Connect 伺服器視同網域控制站：本機 Administrators 只保留 Tier0 群組，管理帳號與跳板也需為 Tier0。")
def aadc_admins(ctx, hits):
    """Entra Connect 伺服器保存具 DCSync 權限的 connector 帳號憑證，本機管理員即可取得。"""
    found = []
    for srv in ctx.rows("entraconnect_server"):
        for m in srv.get("localAdministrators") or []:
            sid = m.get("sid") or ""
            local = ctx.domain_sid and not sid.startswith(ctx.domain_sid + "-") and sid.startswith("S-1-5-21-")
            if sid in ctx.tier0 or (local and rid_of(sid) == 500) or sid in ("S-1-5-32-544",):
                continue
            found.append({"id": sid, "label": m.get("name"), "kind": m.get("objectClass"),
                          "detail": {"server": srv.get("computerName"), "source": m.get("principalSource")}})
    if found:
        hits.add(f"Entra Connect 伺服器有 {len(found)} 個非 Tier0 的本機管理員。", found)


@rule("EN-020", "Seamless SSO 金鑰（AZUREADSSOACC）久未輪替", category="Entra", severity="medium",
      requires=["ad_computers"], attack=["T1558.002"],
      remediation="以 Update-AzureADSSOForest 輪替 AZUREADSSOACC 的 Kerberos 解密金鑰，Microsoft 建議至少每 30 天一次；不再使用 Seamless SSO 時移除該電腦帳號。")
def seamless_sso(ctx, hits):
    """取得 AZUREADSSOACC 的金鑰即可為任何同步使用者偽造登入 Entra ID 的 Kerberos 票證（Silver Ticket）。"""
    for c in ctx.computers():
        if str(c.get("name") or "").upper() == "AZUREADSSOACC":
            days = ctx.days_since(c.get("pwdLastSet"))
            if days is not None and days > 30:
                hits.add(f"AZUREADSSOACC 金鑰已 {days} 天未輪替。", [ctx.ref(c["sid"], f"{days} 天")],
                         "high" if days > 365 else "medium", {"days": days})


@rule("EN-021", "長期未登入的特權帳號（Entra）", category="Entra", severity="medium",
      requires=["entra_role_assignments", "entra_users"], attack=["T1078.004"],
      remediation="移除長期未使用帳號的特權角色；緊急存取帳號除外，但需定期測試並監控登入。")
def stale_priv(ctx, hits):
    """閒置的特權帳號容易被忽略，且常沒有現行的 MFA 註冊。"""
    if not any("signInActivity" in u for u in ctx.rows("entra_users")):
        return
    found = []
    for nid, es in _priv(ctx).items():
        u = ctx.entra.get(nid) or {}
        if not u.get("accountEnabled"):
            continue
        last = _last_signin(u)
        age = (ctx.as_of - last).days if last else None
        if age is None or age > STALE_DAYS:
            found.append(ctx.ref(nid, {"roles": _roles(ctx, es), "lastSignInDays": age}))
    if found:
        hits.add(f"{len(found)} 個特權帳號超過 {STALE_DAYS} 天未登入（或無登入紀錄）。", found)


@rule("EN-022", "同盟驗證網域", category="Entra", severity="info", requires=["entra_domains"],
      attack=["T1606.002"],
      remediation="同盟（AD FS 等）的權杖簽章憑證與伺服器視同 Tier0；無需同盟時改為受管理驗證（PHS / PTA）。")
def federated(ctx, hits):
    """同盟網域的登入由外部 IdP 簽發權杖，取得簽章金鑰即可偽造任何使用者（Golden SAML）。"""
    fed = [d for d in ctx.rows("entra_domains") if d.get("authenticationType") == "Federated"]
    if fed:
        hits.add(f"{len(fed)} 個網域使用同盟驗證。",
                 [{"id": f"domain:{d['id']}", "label": d["id"], "kind": "entraDomain"} for d in fed])
