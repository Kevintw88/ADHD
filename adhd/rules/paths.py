"""Attack-path rules: multi-step routes to Tier0 (see adhd/paths.py for how steps are derived)."""
from __future__ import annotations

from ..paths import analyze
from . import rule

_REQUIRES = ["ad_users", "ad_groups", "ad_acls"]


def _item(ctx, e: dict) -> dict:
    return ctx.ref(e["id"], {"path": e["path"], "hops": e["hops"], "target": e["targetLabel"],
                             "exposedAccounts": e["exposedAccounts"] or None,
                             "crossesAdEntra": e["crossesAdEntra"] or None})


@rule("PATH-001", "非 Tier0 主體有通往 Tier0 的攻擊路徑", category="Path", severity="high", requires=_REQUIRES,
      attack=["T1078", "T1098", "T1484", "T1003.006"],
      remediation="從報告中 exposedAccounts 最多、步數最少的路徑開始處理：移除路徑第一步的權限（或把該主體移出群組），"
                  "並確認 PATH-002 列出的關鍵步驟已切斷。處理後重新收集分析，確認路徑消失且沒有其他替代路徑。")
def attack_paths(ctx, hits):
    """單看一條權限常常只是「中」，串起來才看得出某個普通帳號只要幾步就能拿到網域或租用戶的最高權限。每個起點只列最便宜的一條路徑（成員關係不計步數）；起點是實際持有第一個可濫用權限的主體，透過群組成員關係共用同一路徑的帳號計入 exposedAccounts。"""
    res = analyze(ctx)
    entries = res["entries"]
    if not entries:
        return
    ev = {"accountsWithPath": res["accountsWithPath"], "accountsTotal": res["accountsTotal"],
          "targets": res["targets"], "attackSteps": res["attackSteps"]}
    share = f"{res['accountsWithPath']}/{res['accountsTotal']}"
    broad = [e for e in entries if e["broad"]]
    rest = [e for e in entries if not e["broad"]]
    if broad:
        hits.add(f"{len(broad)} 個廣泛群組（所有使用者 / 電腦都是成員）有通往 Tier0 的路徑：任何一個帳號被入侵即可取得 Tier0。"
                 f"全部啟用中的帳號有 {share} 個有路徑。", [_item(ctx, e) for e in broad], "critical",
                 dict(ev, entries=len(broad)))
    if rest:
        short = sum(1 for e in rest if e["hops"] <= 2)
        cross = sum(1 for e in rest if e["crossesAdEntra"])
        hits.add(f"{len(rest)} 個非 Tier0 主體有通往 Tier0 的路徑，其中 {short} 個在 2 步以內"
                 + (f"、{cross} 個跨越 AD 與 Entra ID" if cross else "")
                 + f"；啟用中的帳號有 {share} 個有路徑。", [_item(ctx, e) for e in rest], "high",
                 dict(ev, entries=len(rest)))


@rule("PATH-002", "攻擊路徑的關鍵步驟（優先切斷）", category="Path", severity="info", requires=_REQUIRES,
      attack=["T1078"],
      remediation="依序移除這些權限 / 成員關係 / 主機上的憑證；每切斷一條，重新分析確認被影響的帳號數下降。")
def chokepoints(ctx, hits):
    """最多帳號的最短路徑都經過的步驟：處理一條就能切斷最多路徑。"""
    res = analyze(ctx)
    cps = [c for c in res["chokepoints"] if c["accounts"] > 0]
    if not cps:
        return
    items = [{"id": f"step:{c['from']}|{c['kind']}|{c['to']}", "label": f"{c['fromLabel']} →[{c['action']}]→ {c['toLabel']}",
              "kind": "attackStep", "detail": {"accounts": c["accounts"], "from": c["from"], "to": c["to"], "right": c["kind"]}}
             for c in cps]
    hits.add(f"{len(cps)} 個步驟承載最多帳號的最短路徑；第一個步驟影響 {cps[0]['accounts']} 個帳號。", items, "info")
