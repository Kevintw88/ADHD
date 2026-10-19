#!/usr/bin/env python3
"""Diagnose AD vs Entra account-enabled mismatches in a collection round (lab side, read-only).

Answers, from the bundles alone:
  * do the AD 'enabled' flag and the raw userAccountControl agree?   (collector consistency)
  * for synced users disabled in AD but enabled in Entra: when were they changed in AD (mass disable?),
    which OU are they in, when did Entra last sync them, are they still signing in to the cloud?
and writes the SIDs to a file the subsidiary can feed to collectors/powershell/diagnostics/Test-ADHDEnabledState.ps1
(SIDs are the subsidiary's own identifiers and are not pseudonymised).

    python3 tools/diag_enabled.py /srv/adhd/intake/ADHD-Collect-SubA*20261015*.zip --sids-out mismatch-sids.txt
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.bundle import open_round, parse_ts  # noqa: E402


def _ou(dn: str) -> str:
    """Parent container of a DN, without the (pseudonymised) CN."""
    parts = re.split(r"(?<!\\),", dn or "", maxsplit=1)
    return parts[1] if len(parts) == 2 else "?"


def _day(ts) -> str:
    dt = parse_ts(ts)
    return dt.strftime("%Y-%m-%d") if dt else "（無）"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("bundles", nargs="+", type=Path)
    ap.add_argument("--sids-out", type=Path, help="write SIDs of AD-disabled / Entra-enabled synced users to this file")
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="adhd-diag-") as tmp:
        rnd = open_round(args.bundles, Path(tmp))
        users = rnd.rows("ad_users")
        entra = rnd.rows("entra_users")
        org = (rnd.rows("entra_organization") or [{}])[0]
        as_of = rnd.as_of

    def age(ts):
        dt = parse_ts(ts)
        return (as_of - dt).days if dt else None

    print(f"資料時間：{as_of:%Y-%m-%d %H:%M} UTC　AD 使用者 {len(users)}　Entra 使用者 {len(entra)}")

    # 1. collector consistency: Enabled vs raw userAccountControl
    bad = [u for u in users if isinstance(u.get("userAccountControl"), int)
           and bool(u.get("enabled")) == bool(u["userAccountControl"] & 0x2)]
    uac_dist = Counter(u.get("userAccountControl") for u in users)
    print("\n== 1. AD 啟用狀態的內部一致性 ==")
    print(f"  enabled=True {sum(1 for u in users if u.get('enabled'))}　enabled=False {sum(1 for u in users if not u.get('enabled'))}")
    print(f"  enabled 與 userAccountControl 的 ACCOUNTDISABLE 位元矛盾：{len(bad)}" + ("（收集器判讀問題，請回報）" if bad else "（一致）"))
    print("  userAccountControl 分布：" + "、".join(f"{k}×{v}" for k, v in uac_dist.most_common(6)))
    print("    （512=一般啟用、514=一般停用、66048=啟用+密碼永不過期、66050=停用+密碼永不過期）")

    # 2. the mismatch population
    by_sid = {u["sid"]: u for u in users}
    mism = []
    for e in entra:
        sid = e.get("onPremisesSecurityIdentifier")
        a = by_sid.get(sid)
        if e.get("onPremisesSyncEnabled") and a and not a.get("enabled") and e.get("accountEnabled"):
            mism.append((a, e))
    print(f"\n== 2. AD 停用、Entra 啟用的同步帳號：{len(mism)} 個 ==")
    if not mism:
        return 0
    print(f"  租用戶最後同步：{_day(org.get('onPremisesLastSyncDateTime'))}（{age(org.get('onPremisesLastSyncDateTime'))} 天前）")

    changed = Counter(_day(a.get("whenChanged")) for a, _ in mism)
    print("  AD whenChanged（最後修改日）最集中的日期：" + "、".join(f"{d}×{n}" for d, n in changed.most_common(5)))
    top = changed.most_common(1)[0]
    if top[1] >= max(10, len(mism) // 2):
        print(f"    → {top[1]}/{len(mism)} 個在同一天被修改：很可能是一次性的批次停用（例如遷移或整併）")

    ous = Counter(_ou(a.get("distinguishedName")) for a, _ in mism)
    print("  所在 OU：" + "、".join(f"{o}×{n}" for o, n in ous.most_common(5)))

    sync = [age(e.get("onPremisesLastSyncDateTime")) for _, e in mism]
    sync = [s for s in sync if s is not None]
    pairs = [(parse_ts(e.get("onPremisesLastSyncDateTime")), parse_ts(a.get("whenChanged"))) for a, e in mism]
    pairs = [(s, c) for s, c in pairs if s and c]
    after = sum(1 for s, c in pairs if s > c)
    if sync:
        print(f"  Entra 物件最後同步：最近 {min(sync)} 天前、最久 {max(sync)} 天前")
    if pairs:
        print(f"  Entra 最後同步晚於 AD 最後修改的帳號：{after}/{len(pairs)}"
              + ("（同步發生在 AD 修改之後卻沒有帶過去 → 指向同步規則 / 屬性篩選）" if after > len(pairs) // 2 else
                 "（AD 修改之後就沒再同步過 → 指向同步停止、匯出錯誤或物件已不在同步範圍）"))
    else:
        print("  無法比較 Entra 同步時間與 AD 修改時間（缺少時間欄位）")

    signin = []
    for _, e in mism:
        sia = e.get("signInActivity") or {}
        ts = [parse_ts(sia.get(k)) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")]
        ts = [t for t in ts if t]
        signin.append((as_of - max(ts)).days if ts else None)
    buckets = Counter("≤30 天" if d is not None and d <= 30 else ("31–90 天" if d is not None and d <= 90 else
                      (">90 天" if d is not None else "無紀錄")) for d in signin)
    print("  雲端最後登入：" + "、".join(f"{k} {buckets.get(k, 0)}" for k in ("≤30 天", "31–90 天", ">90 天", "無紀錄")))
    ll = Counter("有" if a.get("lastLogonTimestamp") else "無" for a, _ in mism)
    print(f"  AD lastLogonTimestamp：有值 {ll.get('有', 0)}、無值 {ll.get('無', 0)}"
          "（無值代表從未對 AD 驗證過，常見於 Entra 加入的電腦）")

    if args.sids_out:
        args.sids_out.write_text("".join(a["sid"] + "\n" for a, _ in mism), encoding="utf-8")
        print(f"\n已寫出 {len(mism)} 個 SID：{args.sids_out}（交給子公司搭配 Test-ADHDEnabledState.ps1 -SidFile 使用）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
