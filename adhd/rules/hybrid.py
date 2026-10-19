"""Hybrid identity rules — where AD and Entra ID meet."""
from __future__ import annotations

import re

from ..load import rid_of
from . import rule
from .entra import _priv, _roles

_INFRA = re.compile(r"(?i)^(MSOL_|Sync_|AAD_|AZUREADSSOACC)")


@rule("HY-001", "雲端特權角色由地端同步帳號持有", category="Hybrid", severity="high",
      requires=["entra_role_assignments", "entra_users"], attack=["T1078.002", "T1078.004"],
      remediation="Entra 特權角色改由雲端專用帳號持有（不從 AD 同步）；同步帳號的特權角色移除。")
def cloud_admin_synced(ctx, hits):
    """同步帳號的密碼與狀態由 AD 決定：能重設該 AD 帳號密碼的人（含 AD 的服務台委派）即可取得雲端特權。"""
    t0, high = [], []
    for nid, es in _priv(ctx).items():
        u = ctx.entra.get(nid) or {}
        if not u.get("onPremisesSyncEnabled"):
            continue
        sid = u.get("onPremisesSecurityIdentifier")
        item = ctx.ref(nid, {"roles": _roles(ctx, es), "adSid": sid, "adTier0": sid in ctx.tier0 if sid else None})
        (t0 if any(e["tier"] == "tier0" for e in es) else high).append(item)
    if t0:
        hits.add(f"{len(t0)} 個 Entra Tier0 角色由 AD 同步帳號持有（AD 入侵可直接延伸為租用戶入侵）。", t0, "high")
    if high:
        hits.add(f"{len(high)} 個 Entra 高權限角色由 AD 同步帳號持有。", high, "medium")


@rule("HY-002", "AD Tier0 帳號同步到 Entra ID", category="Hybrid", severity="medium",
      requires=["ad_users", "ad_groups", "entra_users"], attack=["T1078.002"],
      remediation="以同步範圍（OU 篩選或屬性篩選）排除 AD 特權帳號；AD 管理員使用不同步的專用帳號。")
def ad_tier0_synced(ctx, hits):
    """AD 特權帳號同步後，其密碼雜湊也同步到雲端，雲端端的釣魚或權杖竊取會直接威脅 AD Tier0。"""
    found = []
    for u in ctx.users():
        sid = u["sid"]
        if sid not in ctx.tier0 or rid_of(sid) == 502 or _INFRA.match(str(u.get("samAccountName") or "")):
            continue
        for e in ctx.graph.edges_out(sid, ["SyncedTo"]):
            found.append(ctx.ref(sid, {"entra": ctx.label(e.dst), "enabled": u.get("enabled")}))
    if found:
        hits.add(f"{len(found)} 個 AD Tier0 帳號同步到 Entra ID。", found)


@rule("HY-003", "Entra Connect 組態摘要", category="Hybrid", severity="info",
      requires=["entraconnect_server"], attack=["T1003.006"],
      remediation="Entra Connect 伺服器、ADSync 服務帳號與 connector 帳號皆視同 Tier0 管理；保持版本更新並啟用 staging 伺服器作為備援。")
def aadc_summary(ctx, hits):
    """彙整 Entra Connect 的伺服器、版本、同步模式與 connector 帳號，供後續分析與報告使用。"""
    feats = (ctx.rows("entraconnect_features") or [{}])[0]
    sched = (ctx.rows("entraconnect_scheduler") or [{}])[0]
    items = []
    for srv in ctx.rows("entraconnect_server"):
        items.append({"id": f"host:{srv.get('computerName')}", "label": srv.get("computerName"), "kind": "entraConnectServer",
                      "detail": {"products": srv.get("products"), "serviceAccount": srv.get("adsyncServiceAccount"),
                                 "localAdministrators": len(srv.get("localAdministrators") or [])}})
    for c in ctx.rows("entraconnect_connectors"):
        if (c.get("type") or "").upper() == "AD":
            params = c.get("connectivityParameters") or {}
            login = next((v for k, v in params.items() if re.search(r"(?i)login-user|user-?name$", k)), None)
            items.append({"id": f"connector:{c.get('name')}", "label": c.get("name"), "kind": "adConnector",
                          "detail": {"loginAccount": login, "passwordHashSync": c.get("passwordHashSyncEnabled")}})
    modes = [label for key, label, src in (("PasswordHashSync", "密碼雜湊同步", feats), ("StagingModeEnabled", "Staging mode", sched),
                                         ("UserWriteback", "使用者回寫", feats), ("DeviceWriteback", "裝置回寫", feats)) if src.get(key)]
    hits.add("Entra Connect 組態：" + ("、".join(modes) if modes else "未偵測到特殊模式") + "。", items, "info",
             {"features": feats, "scheduler": sched})


@rule("HY-004", "Entra Connect 的 AD DS connector 帳號權限過高或被當成一般帳號使用", category="Hybrid", severity="critical",
      requires=["entraconnect_connectors", "ad_users", "ad_groups", "ad_acls"], attack=["T1003.006", "T1555", "T1078.002"],
      remediation="建立專用的 connector 帳號（不加入任何特權群組，只授予 Entra Connect 需要的權限，不同步到雲端、"
                  "禁止互動式登入，例如以 GPO 的「拒絕本機登入 / 遠端桌面登入」），在 Entra Connect 精靈中更換；"
                  "移除原帳號的 Windows Hello 金鑰並調查其使用紀錄；Entra Connect 伺服器的本機管理員只保留 Tier0。")
def connector_privileged(ctx, hits):
    """connector 帳號的密碼保存在 Entra Connect 伺服器上，該伺服器的本機管理員可以取出。帳號若是 Tier0 群組成員，取得伺服器即取得網域。"""
    from .ad import _account_context, connector_sids
    sids, how = connector_sids(ctx)
    if not sids:
        return
    servers = ctx.rows("entraconnect_server")
    admins = [m for s in servers for m in (s.get("localAdministrators") or [])
              if (m.get("sid") or "") not in ctx.tier0 and rid_of(m.get("sid") or "") != 500]
    crit, high = [], []
    for sid in sids:
        d = _account_context(ctx, sid, set())
        d["identifiedBy"] = "名稱比對" if how == "matched" else "推斷（唯一的非預設 DCSync 持有者）"
        if admins:
            d["nonTier0LocalAdminsOnServer"] = [m.get("name") for m in admins]
        issues = []
        if d.get("inTier0Group"):
            issues.append("是 Tier0 群組成員")
        if d.get("keyCredentials"):
            issues.append("帶有 Windows Hello 金鑰（有互動式使用或 Shadow Credentials 跡象）")
        if d.get("syncedToEntra"):
            issues.append("同步到 Entra ID")
        if not issues:
            continue
        d["issues"] = issues
        (crit if d.get("inTier0Group") else high).append(ctx.ref(sid, d))
    server = "、".join(str(s.get("computerName")) for s in servers) or "Entra Connect 伺服器"
    path = (f"；{server} 上有 {len(admins)} 個非 Tier0 的本機管理員可取出其密碼" if admins else "")
    if crit:
        hits.add(f"AD DS connector 帳號是 Tier0 群組成員：其密碼保存在 {server}，取得該伺服器即可取得網域管理權限{path}。",
                 crit, "critical")
    if high:
        hits.add(f"AD DS connector 帳號有不該出現的使用跡象（Windows Hello 金鑰 / 同步到雲端）{path}。", high, "high")


@rule("HY-005", "AD 已停用但 Entra 仍啟用的同步帳號", category="Hybrid", severity="high",
      requires=["ad_users", "entra_users"], attack=["T1078.004"],
      remediation="檢查 Entra Connect 同步規則：預設的「In from AD – User AccountEnabled」是否被覆寫或停用、accountEnabled 是否被屬性篩選排除；"
                  "確認後先在 Entra 停用不該使用的帳號並撤銷工作階段；離職流程同時處理雲端帳號（停用、撤銷工作階段、移除授權）。")
def disabled_in_ad_enabled_in_entra(ctx, hits):
    """Entra Connect 預設會把 AD 的停用狀態同步到 Entra。兩邊不一致代表「在 AD 停用帳號」（一般的離職流程）沒有關閉雲端存取。"""
    from .entra import _last_signin
    found, recent, priv = [], 0, 0
    sync_ages = []
    for u in ctx.rows("entra_users"):
        sid = u.get("onPremisesSecurityIdentifier")
        ad = ctx.by_sid.get(sid) if sid else None
        if not u.get("onPremisesSyncEnabled") or ad is None or ad.get("enabled") or not u.get("accountEnabled"):
            continue
        last = _last_signin(u)
        days = (ctx.as_of - last).days if last else None
        sync_age = ctx.days_since(u.get("onPremisesLastSyncDateTime"))
        if sync_age is not None:
            sync_ages.append(sync_age)
        nid = f"entra:{u['id']}"
        is_priv = nid in ctx.entra_priv
        recent += 1 if days is not None and days <= 30 else 0
        priv += 1 if is_priv else 0
        found.append(ctx.ref(nid, {"adAccount": ctx.label(sid), "lastSignInDays": days, "objectLastSyncDays": sync_age,
                                   "privileged": is_priv or None}))
    if not found:
        return
    org = (ctx.rows("entra_organization") or [{}])[0]
    tenant_sync = ctx.days_since(org.get("onPremisesLastSyncDateTime"))
    if tenant_sync is not None and tenant_sync <= 1:
        why = "租用戶的目錄同步仍在運作，較可能是同步規則沒有把 AD 的停用狀態帶到 Entra（自訂規則或屬性篩選）"
    elif tenant_sync is not None:
        why = f"租用戶最後一次目錄同步是 {tenant_sync} 天前，同步可能已停止"
    else:
        why = "無法取得租用戶最後同步時間"
    found.sort(key=lambda a: (a["detail"].get("lastSignInDays") is None, a["detail"].get("lastSignInDays") or 0))
    hits.add(f"{len(found)} 個帳號在 AD 已停用，但對應的 Entra 帳號仍啟用；其中 {recent} 個近 30 天仍有雲端登入"
             + (f"、{priv} 個持有特權角色" if priv else "") + f"。{why}。",
             found, "high" if recent or priv else "medium",
             {"recentCloudSignIns": recent, "privileged": priv, "tenantLastSyncDays": tenant_sync,
              "objectLastSyncDays": {"min": min(sync_ages), "max": max(sync_ages)} if sync_ages else None})
