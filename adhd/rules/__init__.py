"""Rule registry and runner.

A rule declares the datasets it needs. When any required dataset is missing or failed in the
round, the rule is reported as *skipped* (with the reason) instead of silently passing — this is
how "偵測後運行" works: the same rule set runs everywhere and the report shows what could not be
assessed.
"""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Rule:
    id: str
    title: str
    category: str
    severity: str
    requires: Sequence[str | tuple[str, ...]]
    attack: Sequence[str]
    remediation: str
    description: str
    func: Callable[[Any, "Hits"], None]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    summary: str
    affected: list[dict[str, Any]]
    remediation: str
    attack: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id, "title": self.title, "severity": self.severity, "category": self.category,
            "summary": self.summary, "count": len(self.affected), "affected": self.affected,
            "remediation": self.remediation, "attack": list(self.attack), "evidence": self.evidence,
        }


@dataclass
class RuleResult:
    rule: Rule
    status: str  # finding | pass | skipped | error | accepted
    reason: str | None = None
    findings: list[Finding] = field(default_factory=list)
    accepted: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"ruleId": self.rule.id, "title": self.rule.title, "category": self.rule.category,
                "status": self.status, "reason": self.reason, "findings": len(self.findings), "accepted": self.accepted}


class Hits:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.findings: list[Finding] = []

    def add(self, summary: str, affected: Iterable[dict[str, Any]] = (), severity: str | None = None,
            evidence: dict[str, Any] | None = None, title: str | None = None) -> None:
        sev = severity or self.rule.severity
        assert sev in SEVERITY_RANK, sev
        self.findings.append(Finding(
            rule_id=self.rule.id, title=title or self.rule.title, severity=sev, category=self.rule.category,
            summary=summary, affected=list(affected), remediation=self.rule.remediation,
            attack=list(self.rule.attack), evidence=evidence or {},
        ))


REGISTRY: list[Rule] = []


def rule(rule_id: str, title: str, *, category: str, severity: str, requires: Sequence[str | tuple[str, ...]] = (),
         attack: Sequence[str] = (), remediation: str = "", description: str = "") -> Callable:
    def deco(func: Callable[[Any, Hits], None]) -> Callable[[Any, Hits], None]:
        if any(r.id == rule_id for r in REGISTRY):
            raise ValueError(f"duplicate rule id {rule_id}")
        REGISTRY.append(Rule(rule_id, title, category, severity, tuple(requires), tuple(attack),
                             remediation, description or (func.__doc__ or "").strip(), func))
        return func
    return deco


def _missing(ctx: Any, requires: Sequence[str | tuple[str, ...]]) -> list[str]:
    out = []
    for req in requires:
        options = req if isinstance(req, tuple) else (req,)
        if not any(ctx.usable(o) for o in options):
            out.append(" | ".join(f"{o}({ctx.round.status(o) or '未收集'})" for o in options))
    return out


def all_rules() -> list[Rule]:
    from . import ad, adcs, entra, hybrid  # noqa: F401  (registration side effects)
    return sorted(REGISTRY, key=lambda r: r.id)


def run_rules(ctx: Any, only: Iterable[str] | None = None) -> list[RuleResult]:
    wanted = {o.upper() for o in only} if only else None
    results = []
    for r in all_rules():
        if wanted and r.id not in wanted and r.category.upper() not in wanted:
            continue
        missing = _missing(ctx, r.requires)
        if missing:
            results.append(RuleResult(r, "skipped", "缺少資料集：" + "、".join(missing)))
            continue
        hits = Hits(r)
        try:
            r.func(ctx, hits)
        except Exception as exc:  # a broken rule must not hide the others
            results.append(RuleResult(r, "error", f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"))
            continue
        results.append(RuleResult(r, "finding" if hits.findings else "pass", None, hits.findings))
    return results
