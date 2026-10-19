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
