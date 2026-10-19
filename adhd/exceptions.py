"""Accepted exceptions (已確認例外 / 風險接受).

A JSON file listing objects that were reviewed and accepted, e.g. emergency-access accounts:

    {
      "exceptions": [
        {"id": "entra:52726a76-...", "rules": ["EN-005", "EN-008", "EN-021"],
         "reason": "緊急存取帳號（break-glass），雲端專用、FIDO2、登入監控", "owner": "IT 資安", "expires": "2027-06-30"},
        {"id": "*", "rules": ["EN-012"], "reason": "合作專案期間允許成員邀請來賓", "expires": "2026-12-31"}
      ]
    }

`id` is an affected object's id as it appears in findings.json (SID, entra:<objectId>, ...), or "*" to accept
the whole finding of the listed rules. `reason` is required; an expired exception is ignored and reported.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from .bundle import parse_ts


class ExceptionFileError(Exception):
    pass


def load_exceptions(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExceptionFileError(f"cannot read exceptions file {path}: {exc}") from exc
    items = data.get("exceptions") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ExceptionFileError("exceptions file must contain a list under \"exceptions\"")
    for i, x in enumerate(items):
        if not isinstance(x, dict) or not x.get("id") or not x.get("rules") or not str(x.get("reason") or "").strip():
            raise ExceptionFileError(f"exception #{i + 1}: id, rules and reason are required")
        if not isinstance(x["rules"], list):
            raise ExceptionFileError(f"exception #{i + 1}: rules must be a list")
        if x.get("expires") and parse_ts(_as_ts(x["expires"])) is None:
            raise ExceptionFileError(f"exception #{i + 1}: expires must be YYYY-MM-DD")
    return items


def _as_ts(value: str) -> str:
    return f"{value}T00:00:00Z" if len(value) == 10 else value


def _matches(x: dict[str, Any], rule_id: str, obj_id: str) -> bool:
    rules = {str(r).upper() for r in x["rules"]}
    return ("*" in rules or rule_id.upper() in rules) and (x["id"] == obj_id)


def apply_exceptions(results: list[Any], exceptions: list[dict[str, Any]], as_of) -> tuple[list[dict[str, Any]], list[str]]:
    """Move accepted affected objects / findings out of *results* (in place). Returns (accepted, warnings)."""
    warnings: list[str] = []
    active = []
    for x in exceptions:
        exp = x.get("expires")
        if exp and parse_ts(_as_ts(exp)) + timedelta(days=1) <= as_of:
            warnings.append(f"例外已過期未套用：{x['id']}（{', '.join(x['rules'])}，到期 {exp}）")
            continue
        active.append(x)
    used = [False] * len(active)
    accepted: list[dict[str, Any]] = []

    def find(rule_id: str, obj_id: str) -> int | None:
        for i, x in enumerate(active):
            if _matches(x, rule_id, obj_id):
                return i
        return None

    for r in results:
        kept_findings = []
        for f in r.findings:
            whole = find(f.rule_id, "*")
            if whole is not None:
                used[whole] = True
                accepted.append(_entry(f, f.affected, active[whole]))
                continue
            kept, moved = [], {}
            for a in f.affected:
                i = find(f.rule_id, str(a.get("id")))
                if i is None:
                    kept.append(a)
                else:
                    used[i] = True
                    moved.setdefault(i, []).append(a)
            for i, objs in moved.items():
                accepted.append(_entry(f, objs, active[i]))
            if moved and not kept:
                continue
            if moved:
                n = sum(len(v) for v in moved.values())
                f.affected = kept
                f.summary += f"（另 {n} 筆已列為例外）"
            kept_findings.append(f)
        r.accepted = len(r.findings) - len(kept_findings) if r.findings else 0
        r.findings = kept_findings
        if r.status == "finding" and not kept_findings:
            r.status = "accepted"
    for i, ok in enumerate(used):
        if not ok:
            warnings.append(f"例外未比對到任何發現（可能已修正，可移除）：{active[i]['id']}（{', '.join(active[i]['rules'])}）")
    return accepted, warnings


def _entry(f: Any, affected: list[dict[str, Any]], x: dict[str, Any]) -> dict[str, Any]:
    return {"ruleId": f.rule_id, "title": f.title, "severity": f.severity, "affected": affected,
            "exception": {k: x.get(k) for k in ("id", "reason", "owner", "expires") if x.get(k)}}
