"""CLI: analyse one collection round and write findings.json / findings.md / graph.sqlite.

    python3 tools/analyze.py ADHD-Collect-SubA*20261015*.zip --out reports/SubA-20261015
    python3 tools/analyze.py --list-rules
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from .bundle import BundleError, open_round
from .load import build_context
from .report import SEV_LABEL, STATUS_LABEL, build_document, write_json, write_markdown, write_sqlite
from .rules import SEVERITIES, all_rules, run_rules


def list_rules(markdown: bool = False) -> None:
    if markdown:
        print("# ADHD 規則目錄\n")
        print("由 `python3 tools/analyze.py --list-rules --markdown` 產生，請勿手動編輯。\n")
        cat = None
        for r in all_rules():
            if r.category != cat:
                cat = r.category
                print(f"\n## {cat}\n\n| 規則 | 預設嚴重度 | 標題 | 說明 | 需要的資料集 | ATT&CK |\n|---|---|---|---|---|---|")
            req = "<br>".join(x if isinstance(x, str) else " 或 ".join(x) for x in r.requires) or "—"
            print(f"| {r.id} | {SEV_LABEL[r.severity]} | {r.title} | {r.description.replace(chr(10), ' ')} | {req} | {', '.join(r.attack) or '—'} |")
        return
    for r in all_rules():
        req = ", ".join(x if isinstance(x, str) else "|".join(x) for x in r.requires)
        print(f"{r.id:<9} {r.category:<7} {r.severity:<8} {r.title}")
        print(f"{'':<26}需要：{req or '—'}　ATT&CK：{', '.join(r.attack) or '—'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Analyse ADHD collection bundles (one round) and report findings.")
    ap.add_argument("bundles", nargs="*", type=Path, help="bundle folders or .zip files from one collection round")
    ap.add_argument("--out", type=Path, help="output directory (created if missing)")
    ap.add_argument("--only", nargs="*", help="run only these rule ids or categories (AD, ADCS, Entra, Hybrid)")
    ap.add_argument("--allow-mixed-keys", action="store_true",
                    help="analyse bundles pseudonymised with different keys (pseudonyms will not line up)")
    ap.add_argument("--no-sqlite", action="store_true", help="skip graph.sqlite")
    ap.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    ap.add_argument("--markdown", action="store_true", help="with --list-rules: print as a Markdown table")
    args = ap.parse_args(argv)

    if args.list_rules:
        list_rules(args.markdown)
        return 0
    if not args.bundles or not args.out:
        ap.error("bundles and --out are required")

    with tempfile.TemporaryDirectory(prefix="adhd-analyze-") as tmp:
        try:
            rnd = open_round(args.bundles, Path(tmp))
        except (BundleError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if len(rnd.key_ids) > 1 and not args.allow_mixed_keys:
            print(f"error: bundles use different pseudonymisation keys {sorted(rnd.key_ids)}; "
                  "analyse one round at a time (or pass --allow-mixed-keys)", file=sys.stderr)
            return 2
        ctx = build_context(rnd)
        results = run_rules(ctx, args.only)
        doc = build_document(ctx, results)

    args.out.mkdir(parents=True, exist_ok=True)
    write_json(doc, args.out / "findings.json")
    write_markdown(doc, args.out / "findings.md")
    if not args.no_sqlite:
        write_sqlite(ctx, doc, args.out / "graph.sqlite")

    s = doc["summary"]
    print(f"範圍：{doc['scope'].get('adDomain')} / tenant {doc['scope'].get('entraTenantId')}　資料時間 {doc['asOfUtc']}")
    print(f"圖：{s['graph']['nodes']} 節點、{s['graph']['edges']} 邊；Tier0 主體 {s['tier0Principals']} 個")
    print("發現：" + "、".join(f"{SEV_LABEL[k]} {s['findingsBySeverity'][k]}" for k in SEVERITIES))
    print("規則：" + "、".join(f"{STATUS_LABEL[k]} {v}" for k, v in s["rules"].items()))
    for r in doc["rules"]:
        if r["status"] == "error":
            print(f"  ERROR {r['ruleId']}: {(r['reason'] or '').splitlines()[0]}", file=sys.stderr)
    print(f"輸出：{args.out}/findings.md、findings.json" + ("" if args.no_sqlite else "、graph.sqlite"))
    return 1 if s["rules"]["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
