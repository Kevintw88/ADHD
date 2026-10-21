#!/usr/bin/env python3
"""Query attack paths in a collection round (lab side, read-only).

    # summary: entry points to Tier0 and the steps to cut first
    python3 tools/paths.py /srv/adhd/intake/ADHD-Collect-SubA*20261020*.zip

    # cheapest route from one principal to Tier0 (id or pseudonymised label)
    python3 tools/paths.py <bundles> --from u-3b6a98551f47

    # who can reach a given object (e.g. a synced Global Administrator, or the Entra Connect server)
    python3 tools/paths.py <bundles> --to CA-TWCA-01

Add --json for machine-readable output (the same structures the MCP tools will return).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.bundle import BundleError, open_round  # noqa: E402
from adhd.load import build_context  # noqa: E402
from adhd.paths import analyze, render, resolve, route_from, who_can_reach  # noqa: E402


def _pick(ctx, query: str) -> str | None:
    found = resolve(ctx, query)
    if len(found) == 1:
        return found[0]
    if not found:
        print(f"找不到：{query}", file=sys.stderr)
    else:
        print(f"「{query}」符合 {len(found)} 個物件，請改用 id：", file=sys.stderr)
        for n in found:
            print(f"  {n}  {ctx.label(n)}（{ctx.graph.kind(n)}）", file=sys.stderr)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("bundles", nargs="+", type=Path)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--from", dest="start", help="principal id or label: its cheapest route to Tier0")
    g.add_argument("--to", dest="target", help="object id or label: who can reach it")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="adhd-paths-") as tmp:
        try:
            ctx = build_context(open_round(args.bundles, Path(tmp)))
        except (BundleError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        res = analyze(ctx)

        if args.start:
            nid = _pick(ctx, args.start)
            if nid is None:
                return 2
            steps = route_from(ctx, nid)
            out = {"from": nid, "label": ctx.label(nid), "tier0": nid in ctx._attack_graph[0].targets, "steps": steps}
            if args.json:
                print(json.dumps(out, ensure_ascii=False, indent=2))
            elif out["tier0"]:
                print(f"{ctx.label(nid)} 本身就是 Tier0（{ctx._attack_graph[0].targets[nid]}）")
            elif not steps:
                print(f"{ctx.label(nid)} 沒有通往 Tier0 的路徑（以目前收集到的資料）")
            else:
                print(render(steps))
                for i, s in enumerate(steps, 1):
                    print(f"  {i}. {s['fromLabel']} —{s['action']}{'（' + s['note'] + '）' if s.get('note') else ''}→ {s['toLabel']}")
            return 0

        if args.target:
            nid = _pick(ctx, args.target)
            if nid is None:
                return 2
            rows = who_can_reach(ctx, nid, args.limit)
            if args.json:
                print(json.dumps({"to": nid, "label": ctx.label(nid), "sources": rows}, ensure_ascii=False, indent=2))
            else:
                print(f"可以取得 {ctx.label(nid)} 的主體（最短的 {len(rows)} 個）：")
                for r in rows:
                    print(f"  [{r['hops']} 步{'，Tier0' if r['tier0'] else ''}] {r['path']}")
            return 0

        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        print(f"Tier0 目標 {res['targets']} 個；攻擊步驟 {res['attackSteps']} 條；"
              f"啟用中的帳號有 {res['accountsWithPath']}/{res['accountsTotal']} 個有路徑")
        print(f"\n起點（共 {len(res['entries'])} 個，依廣泛群組、影響帳號數、步數排序）：")
        for e in res["entries"][:args.limit]:
            tag = "廣泛群組，" if e["broad"] else ""
            print(f"  [{tag}{e['hops']} 步，影響 {e['exposedAccounts']} 個帳號] {e['path']}")
        if res["chokepoints"]:
            print("\n優先切斷：")
            for c in res["chokepoints"]:
                print(f"  {c['accounts']:4d} 個帳號  {c['fromLabel']} →[{c['action']}]→ {c['toLabel']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
