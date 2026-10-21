#!/usr/bin/env python3
"""Compare local models on the same analysis: run the report task N times per model and score each run.

    python3 tools/eval_agent.py --report-dir /srv/adhd/reports/SubA-20261020 \\
        --base-url http://gpu01:8000/v1 --model qwen-served-name --model glm-served-name --runs 3

Each run is checked with adhd.verify (invented findings / names, rule mismatches, critical coverage,
skipped rules described as passed).  Writes every run's answer, verification and transcript under --out,
plus summary.json, and prints a table.  Use one --base-url per model with --base-url-for MODEL=URL when the
models are served by different vLLM instances.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.agent import ChatClient, LlmError, McpError, run  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report-dir", type=Path, required=True)
    ap.add_argument("--base-url", default="http://localhost:8000/v1")
    ap.add_argument("--base-url-for", action="append", default=[], metavar="MODEL=URL")
    ap.add_argument("--model", action="append", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--revisions", type=int, default=1)
    ap.add_argument("--task", default="report")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--api-key")
    args = ap.parse_args(argv)
    urls = dict(x.split("=", 1) for x in args.base_url_for)
    out = args.out or args.report_dir / time.strftime("eval-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    summary = []
    for model in args.model:
        runs = []
        for i in range(1, args.runs + 1):
            d = out / model.replace("/", "_") / f"run{i}"
            d.mkdir(parents=True, exist_ok=True)
            t0 = time.time()
            try:
                res = run(args.task, args.report_dir, ChatClient(urls.get(model, args.base_url), model, args.api_key),
                          revisions=args.revisions, transcript=d / "transcript.jsonl")
            except (LlmError, McpError) as exc:
                runs.append({"run": i, "error": str(exc)})
                print(f"{model} run{i}: error {exc}", file=sys.stderr)
                continue
            v = res["verification"] or {}
            (d / "answer.md").write_text(res["answer"] + "\n", encoding="utf-8")
            (d / "verification.json").write_text(json.dumps(v, ensure_ascii=False, indent=2), encoding="utf-8")
            runs.append({"run": i, "seconds": round(time.time() - t0, 1), "steps": res["steps"], "toolCalls": res["toolCalls"],
                         "passed": v.get("passed"), "errors": v.get("errors"), "warnings": v.get("warnings"),
                         "criticalCoverage": v.get("criticalCoverage"), "highCoverage": v.get("highCoverage")})
            print(f"{model} run{i}: {'pass' if v.get('passed') else 'FAIL'} errors={v.get('errors')} "
                  f"crit={v.get('criticalCoverage')} high={v.get('highCoverage')} {runs[-1]['seconds']}s", file=sys.stderr)
        ok = [r for r in runs if "error" not in r]
        summary.append({
            "model": model, "runs": len(runs), "failedToRun": len(runs) - len(ok),
            "passRate": round(sum(1 for r in ok if r["passed"]) / len(runs), 2) if runs else 0,
            "meanErrors": round(statistics.mean(r["errors"] or 0 for r in ok), 2) if ok else None,
            "meanHighCoverage": round(statistics.mean(r["highCoverage"] or 0 for r in ok), 2) if ok else None,
            "meanSeconds": round(statistics.mean(r["seconds"] for r in ok), 1) if ok else None,
            "meanToolCalls": round(statistics.mean(r["toolCalls"] for r in ok), 1) if ok else None,
            "details": runs,
        })
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n{'模型':<32}{'通過率':>8}{'平均錯誤':>10}{'高嚴重度覆蓋':>14}{'平均秒數':>10}{'工具呼叫':>10}")
    for s in summary:
        print(f"{s['model']:<32}{s['passRate']:>8}{str(s['meanErrors']):>10}{str(s['meanHighCoverage']):>14}"
              f"{str(s['meanSeconds']):>10}{str(s['meanToolCalls']):>10}")
    print(f"\n輸出：{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
