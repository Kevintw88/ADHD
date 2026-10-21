#!/usr/bin/env python3
"""Detection engineering CLI: Sigma rules in detections/sigma, offline, standard library only.

    # replay the synthetic / recorded test cases in detections/tests (run after every rule change)
    python3 tools/detect.py selftest

    # rule hygiene: required attributes, ATT&CK tags, every rule covered by a firing test case
    python3 tools/detect.py lint

    # run the rules over the events in a collection round (DCLogs / EntraLogs / SecurityAlerts),
    # with environment placeholders and context from the posture analysis of the same round
    python3 tools/detect.py run /srv/adhd/intake/ADHD-Collect-SubA*20261020*.zip --out /srv/adhd/reports/SubA-20261020

    # replay recorded events (JSONL) from a lab run, e.g. Windows Security events exported with the collector
    python3 tools/detect.py run <bundles for environment> --events windows/security=lab-attack.jsonl --out ...

    # environment-specific copies of the rules (placeholders filled with SIDs / host names) for the SIEM
    python3 tools/detect.py tune /srv/adhd/intake/ADHD-Collect-SubA*20261020*.zip --out /srv/adhd/tuned/SubA
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd import detect  # noqa: E402
from adhd.bundle import BundleError, open_round  # noqa: E402
from adhd.load import build_context  # noqa: E402
from adhd.sigma import SigmaError, YamlError, load_rules  # noqa: E402


def _events_arg(values: list[str]) -> list[tuple[tuple[str, str], Path]]:
    out = []
    for v in values:
        if "=" not in v or "/" not in v.split("=", 1)[0]:
            raise SystemExit(f"--events expects product/service=FILE, got {v!r}")
        src, path = v.split("=", 1)
        prod, svc = src.lower().split("/", 1)
        if (prod, svc) not in detect.SOURCES:
            raise SystemExit(f"unknown log source {src}; known: {', '.join('/'.join(k) for k in detect.SOURCES)}")
        out.append(((prod, svc), Path(path)))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="replay detections/tests against the rules")
    sub.add_parser("lint", help="rule hygiene checks")
    sub.add_parser("catalog", help="print the rule catalogue as Markdown (docs/detection-rules.md)")
    r = sub.add_parser("run", help="run the rules over a round's events and / or recorded events")
    r.add_argument("bundles", nargs="*", type=Path)
    r.add_argument("--events", action="append", default=[], metavar="PRODUCT/SERVICE=FILE.jsonl")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--rules", type=Path, help="rules directory (default: detections/sigma)")
    t = sub.add_parser("tune", help="write environment-specific rules")
    t.add_argument("bundles", nargs="+", type=Path)
    t.add_argument("--out", type=Path, required=True)
    t.add_argument("--rules", type=Path)
    args = ap.parse_args(argv)

    try:
        if args.cmd == "selftest":
            rows = detect.selftest()
            bad = [x for x in rows if not x["ok"]]
            for x in rows:
                print(f"{'ok  ' if x['ok'] else 'FAIL'}  {x['file']:<26} {x['case']}")
                if not x["ok"]:
                    print(f"        預期 {x['want']}  實際 {x['got']}" + (f"  未知規則 {x['unknownRuleIds']}" if x["unknownRuleIds"] else ""))
            print(f"\n{len(rows) - len(bad)}/{len(rows)} 個案例通過")
            return 1 if bad else 0
        if args.cmd == "catalog":
            print(detect.catalog_markdown())
            return 0
        if args.cmd == "lint":
            problems = detect.lint()
            rules, corrs = load_rules(detect.rule_files())
            for p in problems:
                print(p)
            print(f"{len(rules)} 條規則、{len(corrs)} 條關聯規則；{len(problems)} 個問題")
            return 1 if problems else 0
    except (SigmaError, YamlError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="adhd-detect-") as tmp:
        rnd = ctx = None
        if args.bundles:
            try:
                rnd = open_round(args.bundles, Path(tmp))
            except (BundleError, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            ctx = build_context(rnd)
        env = detect.environment(ctx) if ctx is not None else {}

        if args.cmd == "tune":
            label = ctx.domain_dns or ctx.tenant_id or "environment"
            files = detect.tune(env, args.out, args.rules, label)
            print("環境資料：" + "、".join(f"{k} {len(v)}" for k, v in env.items()))
            print(f"已寫出 {len(files)} 個規則檔與 environment.json：{args.out}")
            print("占位符已換成 SID / 主機名稱（不受假名化影響），可直接用 sigma-cli / pySigma 轉成 SIEM 查詢。")
            return 0

        try:
            rules, corrs = load_rules(detect.rule_files(args.rules))
        except (SigmaError, YamlError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        events = detect.load_events(rnd, _events_arg(args.events))
        context = detect.EntityContext(ctx) if ctx is not None else None
        hits = detect.run(rules, corrs, events, env, context)
        cov = detect.coverage(rules, corrs, events, env, rnd, hits)
        scope = {"adDomain": ctx.domain_dns, "adDomainSid": ctx.domain_sid, "entraTenantId": ctx.tenant_id} if ctx else {}
        as_of = ctx.as_of.strftime("%Y-%m-%dT%H:%M:%SZ") if ctx else ""
        doc = detect.build_document(hits, cov, env, scope, as_of, events)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "detections.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    detect.write_markdown(doc, args.out / "detections.md")
    s = doc["summary"]
    print("事件：" + ("、".join(f"{k} {v}" for k, v in doc["events"].items()) or "無"))
    print("告警：" + "、".join(f"{detect.LEVEL_ZH[k]} {v}" for k, v in s["hitsByLevel"].items())
          + f"（{s['raised']} 筆因涉及 Tier0 / 攻擊路徑而提高）")
    st = {"evaluated": "已評估", "no-events": "無事件", "not-collected": "未收集", "needs-env": "缺環境資料"}
    print("規則：" + "、".join(f"{st.get(k, k)} {v}" for k, v in s["rulesByStatus"].items()))
    for h in doc["hits"][:10]:
        print(f"  [{detect.LEVEL_ZH[h['level']]}] {h['titleZh'] or h['title']}（{h['first']}，{h['events']} 筆事件）")
    print(f"輸出：{args.out}/detections.md、detections.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
