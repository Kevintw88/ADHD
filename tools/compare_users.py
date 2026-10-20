#!/usr/bin/env python3
"""Compare AD user state between two collection rounds (lab side, read-only).

Answers "did the account really change, or did one of the collections read it wrongly?":
  * how each round's AD bundle was collected (collector version, host, PowerShell edition, queried DC)
  * per round: enabled vs raw userAccountControl contradictions
  * per account: enabled / userAccountControl / lastLogonTimestamp in each round, grouped by what changed
Prints only counts, SIDs and states; no names.  Both rounds should use the same pseudonymisation key.

    python3 tools/compare_users.py --old /srv/adhd/intake/ADHD-Collect-SubA*20261015*.zip \\
        --new /srv/adhd/intake/ADHD-Collect-SubA-FullAcl-20261020*.zip --sids mismatch-sids.txt
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.bundle import open_round, parse_ts  # noqa: E402


def _disabled_bit(u: dict) -> bool | None:
    uac = u.get("userAccountControl")
    return bool(uac & 0x2) if isinstance(uac, int) else None


def _describe(label: str, rnd) -> dict:
    print(f"== {label} ==")
    for b in rnd.bundles:
        if b.rows("ad_users"):
            m = b.manifest
            rc = m.get("runContext") or {}
            sc = m.get("scope") or {}
            print(f"  {b.name}：collector {(m.get('collector') or {}).get('version')}，"
                  f"主機 {rc.get('computer')}，PowerShell {rc.get('psVersion')} {rc.get('psEdition')}，"
                  f"AD 模組 {(rc.get('modules') or {}).get('ActiveDirectory')}，查詢 DC {sc.get('adQueriedDc')}，金鑰 {b.key_id}")
    users = {u["sid"]: u for u in rnd.rows("ad_users")}
    bad = sum(1 for u in users.values() if _disabled_bit(u) is not None and bool(u.get("enabled")) == _disabled_bit(u))
    print(f"  AD 使用者 {len(users)}：enabled=True {sum(1 for u in users.values() if u.get('enabled'))}；"
          f"UAC 停用位元 {sum(1 for u in users.values() if _disabled_bit(u))}；enabled 與 UAC 矛盾 {bad}")
    return users


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--old", nargs="+", type=Path, required=True, help="bundles of the earlier round")
    ap.add_argument("--new", nargs="+", type=Path, required=True, help="bundles of the later round")
    ap.add_argument("--sids", type=Path, help="only these SIDs (one per line), e.g. from diag_enabled.py --sids-out")
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="adhd-cmp-") as tmp:
        old = _describe("較早一輪", open_round(args.old, Path(tmp) / "old"))
        new = _describe("較新一輪", open_round(args.new, Path(tmp) / "new"))

    sids = sorted(set(old) | set(new))
    if args.sids:
        wanted = {s.strip() for s in args.sids.read_text(encoding="utf-8-sig").splitlines() if s.strip()}
        sids = [s for s in sids if s in wanted]
        print(f"\n只比較 {args.sids.name} 中的 {len(wanted)} 個 SID（兩輪都找得到 {sum(1 for s in wanted if s in old and s in new)}）")

    kinds = Counter()
    examples: dict[str, list[str]] = {}
    for s in sids:
        a, b = old.get(s), new.get(s)
        if not a or not b:
            k = "只在較早一輪" if a else "只在較新一輪"
        else:
            parts = []
            if bool(a.get("enabled")) != bool(b.get("enabled")):
                parts.append(f"enabled {a.get('enabled')}→{b.get('enabled')}")
            if a.get("userAccountControl") != b.get("userAccountControl"):
                parts.append(f"UAC {a.get('userAccountControl')}→{b.get('userAccountControl')}")
            if not parts:
                parts.append(f"沒有變化（enabled {b.get('enabled')}，UAC {b.get('userAccountControl')}）")
            k = "；".join(parts)
        kinds[k] += 1
        examples.setdefault(k, []).append(s)

    print("\n== 兩輪之間的變化 ==")
    for k, n in kinds.most_common():
        print(f"  {n:4d}  {k}　例：{', '.join(examples[k][:2])}")

    # where both rounds have the account: did lastLogonTimestamp move, and when relative to the old round?
    both = [(old[s], new[s]) for s in sids if s in old and s in new]
    if both:
        moved = sum(1 for a, b in both if parse_ts(b.get("lastLogonTimestamp")) and parse_ts(b.get("lastLogonTimestamp")) != parse_ts(a.get("lastLogonTimestamp")))
        old_none = sum(1 for a, _ in both if not a.get("lastLogonTimestamp"))
        print(f"\n  lastLogonTimestamp：較早一輪無值 {old_none}／{len(both)}；兩輪之間有更新 {moved}／{len(both)}")

    print("\n判讀：")
    print("  enabled False→True 且 UAC 514→512 ：兩輪之間真的被重新啟用（到 DC 查事件 4722）")
    print("  enabled False→True 但 UAC 沒變（512）：較早一輪的收集判讀錯誤，看上面兩輪的 PowerShell / 主機差異並回報")
    print("  沒有變化（enabled True）              ：AD 端一直是啟用，問題在 lab 端比對，請回報")
    return 0


if __name__ == "__main__":
    sys.exit(main())
