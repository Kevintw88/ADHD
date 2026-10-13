"""能力矩陣引擎：指紋 + YAML 規則 → Profile、啟用模組、缺口、額外 Tier 0。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import CapabilityResult, Fingerprint, Gap

_MISSING = object()
OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: a is not None and a > b,
    "gte": lambda a, b: a is not None and a >= b,
    "lt": lambda a, b: a is not None and a < b,
    "lte": lambda a, b: a is not None and a <= b,
    "in": lambda a, b: a in b,
    "nonempty": lambda a, b: bool(a) == bool(b),
    "empty": lambda a, b: (not a) == bool(b),
}


def lookup(data: dict, path: str) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def evaluate(cond: dict, data: dict) -> bool:
    if "all" in cond:
        return all(evaluate(c, data) for c in cond["all"])
    if "any" in cond:
        return any(evaluate(c, data) for c in cond["any"])
    if "not" in cond:
        return not evaluate(cond["not"], data)
    value = lookup(data, cond["path"])
    ops = [k for k in cond if k in OPS]
    if len(ops) != 1:
        raise ValueError(f"條件需恰好一個運算子：{cond}")
    return OPS[ops[0]](value, cond[ops[0]])


def render(text: str, data: dict) -> str:
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key.startswith("len:"):
            v = lookup(data, key[4:])
            return str(len(v) if v else 0)
        v = lookup(data, key)
        if isinstance(v, list):
            return "、".join(map(str, v)) if v else "無"
        return "未知" if v is None else str(v)

    return re.sub(r"\{([a-zA-Z0-9_.:]+)\}", sub, text)


def load_matrix(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def apply_matrix(fp: Fingerprint, matrix: dict) -> CapabilityResult:
    data = fp.model_dump()

    profile = next(p for p in matrix["profiles"] if evaluate(p["when"], data))

    gaps = [
        Gap(id=g["id"], title=render(g["title"], data), blocks=g.get("blocks", []),
            remediation=render(g.get("remediation", ""), data))
        for g in matrix.get("gaps", []) if evaluate(g["when"], data)
    ]

    enabled, disabled = [], {}
    for m in matrix["modules"]:
        if evaluate(m["when"], data):
            enabled.append(m["id"])
        else:
            blocking = [g.title for g in gaps if m["id"] in g.blocks]
            disabled[m["id"]] = "；".join(blocking) if blocking else m.get("unmet", "條件未符合")

    tier0 = [t["label"] for t in matrix.get("tier0_extra", []) if evaluate(t["when"], data)]
    return CapabilityResult(entity=fp.entity, profile=profile["id"], profile_name=profile["name"],
                            enabled_modules=enabled, disabled_modules=disabled, gaps=gaps, tier0_extra=tier0)


def module_catalog(matrix: dict) -> dict[str, dict]:
    return {m["id"]: m for m in matrix["modules"]}
