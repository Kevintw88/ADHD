"""Detection engineering: run the Sigma rules in detections/sigma against collected / recorded events.

    events      DC Security events (DCLogs), Entra sign-ins / directory audits / risk detections (EntraLogs),
                Defender alerts (SecurityAlerts) from collection bundles, or any JSONL of recorded events
    environment placeholders (%tier0_accounts%, %dcsync_expected%, ...) filled from the posture analysis, so
                rules know the environment's Tier0, domain controllers and Entra Connect connector
    context     every hit is enriched with what the posture analysis knows about the accounts / hosts in it
                (Tier0, attack-path entry point, accounts sharing the route) and raised one level when it
                involves Tier0 or an attack-path entry
    coverage    for every rule: evaluated / no matching events / source not collected / needs environment data
    tuning      environment-specific copies of the rules with the placeholders filled in (SIDs, not names:
                pseudonymisation does not touch SIDs, so the tuned rules can be deployed as they are)
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .bundle import Round, parse_ts
from .sigma import Correlation, Rule, flatten, load_all, load_rules

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "detections" / "sigma"
TESTS_DIR = REPO / "detections" / "tests"
SCHEMA = "adhd.detections/1"
LEVELS = ["informational", "low", "medium", "high", "critical"]
LEVEL_ZH = {"informational": "資訊", "low": "低", "medium": "中", "high": "高", "critical": "嚴重"}

# logsource -> (dataset, timestamp field)
SOURCES: dict[tuple[str, str], tuple[str, str]] = {
    ("windows", "security"): ("dc_security_events", "TimeCreated"),
    ("azure", "signinlogs"): ("entra_signins", "createdDateTime"),
    ("azure", "auditlogs"): ("entra_directory_audits", "activityDateTime"),
    ("azure", "riskdetection"): ("entra_risk_detections", "detectedDateTime"),
    ("m365defender", "alerts"): ("security_alerts", "createdDateTime"),
}


def source_of(rule: Rule) -> tuple[str, str]:
    return (rule.logsource.get("product", ""), rule.logsource.get("service", ""))


# ===========================================================================================
def normalize(source: tuple[str, str], row: dict[str, Any]) -> dict[str, Any]:
    """A collected record -> the flat event the rules see."""
    if source == ("windows", "security"):
        ev = {"EventID": row.get("eventId"), "Computer": row.get("machineName") or row.get("dc"),
              "TimeCreated": row.get("timeCreated"), "Channel": "Security", "Outcome": row.get("outcome")}
        for k, v in (row.get("data") or {}).items():
            ev.setdefault(k, v)
        return ev
    return flatten(row)


def _norm_any(source: tuple[str, str], row: dict[str, Any]) -> dict[str, Any]:
    """Recorded events may be in collector form ({eventId, data:{...}}) or already flat (Sigma field names)."""
    if source == ("windows", "security"):
        return normalize(source, row) if "eventId" in row else row
    return normalize(source, row)


def load_events(rnd: Round | None = None, jsonl: Iterable[tuple[tuple[str, str], Path]] = ()) -> dict[tuple[str, str], list[dict]]:
    out: dict[tuple[str, str], list[dict]] = defaultdict(list)
    if rnd is not None:
        for src, (ds, _ts) in SOURCES.items():
            for row in rnd.rows(ds):
                out[src].append(normalize(src, row))
    for src, path in jsonl:
        with Path(path).open(encoding="utf-8-sig") as fh:
            for line in fh:
                if line.strip():
                    out[src].append(_norm_any(src, json.loads(line)))
    return out


def event_time(source: tuple[str, str], ev: dict[str, Any]) -> datetime:
    ts = parse_ts(ev.get(SOURCES.get(source, ("", "TimeCreated"))[1]) or ev.get("TimeCreated") or ev.get("@timestamp"))
    return ts or datetime(1970, 1, 1, tzinfo=timezone.utc)


# ===========================================================================================
def environment(ctx) -> dict[str, list[str]]:
    """Placeholder values from the posture analysis (SIDs / object ids / host names, never pseudonyms)."""
    from .paths import analyze
    from .rules.ad import connector_sids
    g = ctx.graph
    dcs = sorted(ctx.dc_sids)
    connectors, _ = connector_sids(ctx)
    msol = [u["sid"] for u in ctx.users() if str(u.get("samAccountName") or "").lower().startswith("msol_")]
    tier0_groups = sorted(s for s in ctx.tier0 if g.kind(s) == "group" and s.startswith("S-1-"))
    tier0_accounts = sorted(s for s in ctx.tier0 if g.kind(s) in ("user", "gmsa", "computer") and s.startswith("S-1-"))
    entra_t0 = sorted(n.split(":", 1)[1] for n, es in ctx.entra_priv.items()
                      if any(e["tier"] == "tier0" for e in es) and g.kind(n) == "entraUser")
    hosts: set[str] = set()
    for c in ctx.computers():
        if c.get("isDomainController"):
            hosts |= {str(c.get("dnsHostName") or "").lower(), str(c.get("name") or "").lower()}
    by_name = {str(c.get("name") or "").lower(): c for c in ctx.computers()}
    for s in ctx.rows("entraconnect_server"):
        name = str(s.get("computerName") or "").lower()
        hosts |= {name, str((by_name.get(name) or {}).get("dnsHostName") or "").lower()}
    ca = {str(c.get("dnsHostName") or "").lower() for c in ctx.rows("adcs_cas")}
    hosts |= ca | {h.split(".", 1)[0] for h in ca}
    analyze(ctx)
    return {
        "dc_accounts": dcs,
        "dcsync_expected": sorted(set(dcs) | set(connectors) | set(msol)),
        "keycred_writers": sorted(set(connectors) | set(msol)),
        "tier0_groups": tier0_groups,
        "tier0_accounts": tier0_accounts,
        "entra_tier0_users": entra_t0,
        "tier0_hosts": sorted(h for h in hosts if h),
    }


class EntityContext:
    """What the posture analysis knows about an account / host seen in an event."""

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        from .paths import analyze
        res = analyze(ctx)
        self.entries = {e["id"]: e for e in res["entries"]}
        ag = ctx._attack_graph[0]
        self.targets = ag.targets
        self.hosts: dict[str, str] = {}
        for c in ctx.computers():
            for h in (c.get("dnsHostName"), c.get("name")):
                if h:
                    self.hosts[str(h).lower()] = c["sid"]
        self.sam: dict[str, str] = {}
        for ds in ("ad_users", "ad_computers", "ad_service_accounts"):
            for r in ctx.rows(ds):
                if r.get("samAccountName"):
                    self.sam[str(r["samAccountName"]).lower()] = r["sid"]
        self.upn: dict[str, str] = {}
        for nid, r in ctx.entra.items():
            if r.get("userPrincipalName"):
                self.upn[str(r["userPrincipalName"]).lower()] = nid
            self.upn[nid.split(":", 1)[1].lower()] = nid

    def describe(self, nid: str) -> dict[str, Any] | None:
        g = self.ctx.graph
        if nid not in g.nodes:
            return None
        out: dict[str, Any] = {"id": nid, "label": g.label(nid), "kind": g.kind(nid)}
        if nid in self.targets:
            out["tier0"] = self.targets[nid]
        e = self.entries.get(nid)
        if e:
            out["attackPath"] = {"hops": e["hops"], "target": e["targetLabel"], "exposedAccounts": e["exposedAccounts"], "path": e["path"]}
        for sync in g.edges_out(nid, ["SyncedTo"]):
            if sync.dst in self.targets:
                out["syncedTo"] = {"id": sync.dst, "label": g.label(sync.dst), "tier0": self.targets[sync.dst]}
        return out

    def entities(self, ev: dict[str, Any]) -> list[dict[str, Any]]:
        seen, out = set(), []

        def take(nid: str | None) -> None:
            if nid and nid not in seen:
                d = self.describe(nid)
                if d:
                    seen.add(nid)
                    out.append(d)
        for k, v in ev.items():
            vals = v if isinstance(v, list) else [v]
            kl = k.lower()
            for x in vals:
                if not isinstance(x, str) or not x:
                    continue
                if kl.endswith("sid") and x.startswith("S-1-"):
                    take(x)
                elif kl in ("targetusername", "subjectusername", "evidence.useraccount.accountname"):
                    name = x.split("\\")[-1].split("@")[0].lower()        # DOMAIN\\name, name@REALM
                    take(self.sam.get(name))
                elif kl in ("workstationname", "evidence.devicednsname", "devicednsname"):   # not "Computer": that is the DC that logged it
                    take(self.hosts.get(x.lower()) or self.hosts.get(x.lower().split(".", 1)[0]))
                elif kl in ("userid", "userprincipalname", "evidence.useraccount.azureaduserid",
                            "evidence.useraccount.userprincipalname", "initiatedby.user.id", "initiatedby.user.userprincipalname"):
                    take(self.upn.get(x.lower()))
        return out


def _bump(level: str) -> str:
    i = LEVELS.index(level) if level in LEVELS else 2
    return LEVELS[min(len(LEVELS) - 1, i + 1)]


def _summary(ev: dict[str, Any]) -> dict[str, Any]:
    keep = ("EventID", "TimeCreated", "Computer", "SubjectUserName", "SubjectUserSid", "TargetUserName", "TargetSid",
            "ServiceName", "ServiceSid", "IpAddress", "ObjectDN", "AttributeLDAPDisplayName", "TicketEncryptionType",
            "createdDateTime", "activityDateTime", "userPrincipalName", "userId", "ipAddress", "appDisplayName",
            "clientAppUsed", "status.errorCode", "riskLevelDuringSignIn", "activityDisplayName",
            "initiatedBy.user.userPrincipalName", "targetResources.displayName", "title", "serviceSource", "severity",
            "evidence.deviceDnsName", "evidence.userAccount.accountName")
    return {k: ev[k] for k in keep if k in ev and ev[k] not in (None, "", [])}


# ===========================================================================================
def run(rules: list[Rule], corrs: list[Correlation], events: dict[tuple[str, str], list[dict]],
        env: dict[str, list[str]] | None = None, context: EntityContext | None = None) -> list[dict[str, Any]]:
    env = env or {}
    suppressed = {r for c in corrs if not c.generate for r in c.rules}
    by_ref: dict[str, list[tuple[datetime, dict, tuple]]] = defaultdict(list)
    hits: list[dict[str, Any]] = []
    for r in rules:
        src = source_of(r)
        for ev in events.get(src, []):
            if not r.match(ev, env):
                continue
            ts = event_time(src, ev)
            for ref in {r.id, r.name} - {None}:
                by_ref[ref].append((ts, ev, src))
            if r.id in suppressed or (r.name and r.name in suppressed):
                continue
            hits.append(_hit(r.doc, r.id, r.level, "rule", ts, ts, [ev], {}, context))
    for c in corrs:
        matches: list[tuple[datetime, dict]] = []
        for ref in c.rules:
            matches.extend((ts, ev) for ts, ev, _ in by_ref.get(ref, []))
        for h in c.evaluate(matches):
            hits.append(_hit(c.doc, c.id, c.level, "correlation", h["first"], h["last"], h["events"],
                             {"group": h["group"], "count": h["count"]}, context))
    hits.sort(key=lambda h: (-LEVELS.index(h["level"]), h["first"]))
    return hits


def _hit(doc: dict, rid: str, level: str, kind: str, first: datetime, last: datetime, evs: list[dict],
         extra: dict, context: EntityContext | None) -> dict[str, Any]:
    adhd = doc.get("adhd") or {}
    ents: list[dict[str, Any]] = []
    if context is not None:
        seen = set()
        for ev in evs[:50]:
            for e in context.entities(ev):
                if e["id"] not in seen:
                    seen.add(e["id"])
                    ents.append(e)
    raised = None
    if any(e.get("tier0") or e.get("syncedTo") for e in ents):
        raised = "涉及 Tier0"
    elif any(e.get("attackPath") for e in ents):
        raised = "涉及攻擊路徑起點"
    out = {
        "ruleId": rid, "title": doc.get("title"), "titleZh": adhd.get("title_zh"), "kind": kind,
        "ruleLevel": level, "level": _bump(level) if raised else level, "raisedBecause": raised,
        "first": first.strftime("%Y-%m-%dT%H:%M:%SZ"), "last": last.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "events": len(evs), "samples": [_summary(e) for e in evs[:5]], "entities": ents,
        "attack": [t for t in doc.get("tags") or [] if str(t).startswith("attack.")],
        "response": adhd.get("response_zh"),
    }
    out.update(extra)
    return out


# ===========================================================================================
def coverage(rules: list[Rule], corrs: list[Correlation], events: dict[tuple[str, str], list[dict]],
             env: dict[str, list[str]], rnd: Round | None, hits: list[dict]) -> list[dict[str, Any]]:
    by_rule = Counter(h["ruleId"] for h in hits)
    collected_ids = None
    if rnd is not None:
        for b in rnd.bundles:
            ids = ((b.manifest.get("runContext") or {}).get("parameters") or {}).get("eventIds")
            if ids and "dc_security_events" in b.datasets:
                collected_ids = set(collected_ids or set()) | {int(i) for i in ids}
    seen_ids = Counter(int(e.get("EventID")) for e in events.get(("windows", "security"), []) if str(e.get("EventID", "")).isdigit())
    out = []
    for r in rules:
        src = source_of(r)
        ds = SOURCES.get(src, ("?", ""))[0]
        need_ids = sorted({int(v) for s in r.selections.values() for alt in s.alternatives for t in alt
                           if t.field.lower() == "eventid" for v in t.values if str(v).isdigit()})
        missing_env = sorted(p for p in r.placeholders if not env.get(p))
        status, note = "evaluated", None
        if rnd is not None and not rnd.usable(ds) and not events.get(src):
            status, note = "not-collected", f"沒有收集 {ds}（{rnd.status(ds) or '未收集'}）"
        elif need_ids and collected_ids is not None and not set(need_ids) & collected_ids:
            status, note = "not-collected", f"收集時沒有包含事件 {', '.join(map(str, need_ids))}（Collect-ADHD.ps1 -EventIds）"
        elif need_ids and not any(seen_ids.get(i) for i in need_ids) and src == ("windows", "security"):
            status, note = "no-events", f"期間內沒有事件 {', '.join(map(str, need_ids))}：可能未啟用對應的稽核原則"
        elif not events.get(src):
            status, note = "no-events", f"期間內沒有 {ds} 的資料"
        required = (r.doc.get("adhd") or {}).get("requires_env") or []
        if any(not env.get(p) for p in required):
            status, note = "needs-env", "需要分析結果提供的環境資料：" + "、".join(p for p in required if not env.get(p))
        elif missing_env and status == "evaluated":
            note = "環境資料不足，部分排除條件未套用：" + "、".join(missing_env)
        out.append({"ruleId": r.id, "title": r.title, "titleZh": (r.doc.get("adhd") or {}).get("title_zh"),
                    "level": r.level, "source": "/".join(src), "eventIds": need_ids, "status": status, "note": note,
                    "hits": by_rule.get(r.id, 0), "attack": [t for t in r.doc.get("tags") or [] if str(t).startswith("attack.")]})
    for c in corrs:
        base = [x for x in out if x["ruleId"] in c.rules or any(r.name in c.rules and r.id == x["ruleId"] for r in rules)]
        st = "evaluated" if base and all(b["status"] == "evaluated" for b in base) else (base[0]["status"] if base else "no-events")
        out.append({"ruleId": c.id, "title": c.title, "titleZh": (c.doc.get("adhd") or {}).get("title_zh"), "level": c.level,
                    "source": base[0]["source"] if base else "", "eventIds": [], "status": st,
                    "note": f"關聯：{c.type}，{', '.join(c.group_by) or '全部'}，{c.op} {c.threshold}，{c.doc['correlation'].get('timespan')}",
                    "hits": by_rule.get(c.id, 0), "attack": [t for t in c.doc.get("tags") or [] if str(t).startswith("attack.")]})
    return out


# ===========================================================================================
def rule_files(rules_dir: Path | None = None) -> list[Path]:
    return sorted((rules_dir or RULES_DIR).rglob("*.yml"))


def selftest(rules_dir: Path | None = None, tests_dir: Path | None = None) -> list[dict[str, Any]]:
    """Replay every test case in detections/tests against the rules; returns one row per case."""
    rules, corrs = load_rules(rule_files(rules_dir))
    ids = {r.id for r in rules} | {c.id for c in corrs}
    results = []
    for tf in sorted((tests_dir or TESTS_DIR).glob("*.json")):
        spec = json.loads(tf.read_text(encoding="utf-8"))
        src = tuple(spec["logsource"].split("/"))
        for case in spec["cases"]:
            env = dict(spec.get("env") or {}, **(case.get("env") or {}))
            evs = [_norm_any(src, e) for e in case["events"]]
            hits = run(rules, corrs, {src: evs}, env)
            got = Counter(h["ruleId"] for h in hits)
            want = {k: int(v) for k, v in case["expect"].items()}
            unknown = [k for k in want if k not in ids]
            # rules not mentioned in expect must stay silent for this source, so false positives are caught too
            extra = {k: v for k, v in got.items() if k not in want}
            ok = not unknown and all(got.get(k, 0) == v for k, v in want.items()) and not extra
            results.append({"file": tf.name, "case": case["name"], "ok": ok, "want": want, "got": dict(got),
                            "unexpected": extra, "unknownRuleIds": unknown})
    return results


def lint(rules_dir: Path | None = None, tests_dir: Path | None = None) -> list[str]:
    """Rule hygiene: required attributes, ATT&CK tags, level, a test file covering every rule id."""
    problems = []
    rules, corrs = load_rules(rule_files(rules_dir))
    tested: set[str] = set()
    for tf in sorted((tests_dir or TESTS_DIR).glob("*.json")):
        for case in json.loads(tf.read_text(encoding="utf-8"))["cases"]:
            tested |= {k for k, v in case["expect"].items() if int(v) > 0}
    for r in list(rules) + list(corrs):
        d = r.doc
        for key in ("title", "id", "status", "description", "author", "date", "tags", "level"):
            if not d.get(key):
                problems.append(f"{r.path}: {r.id} 缺少 {key}")
        if d.get("level") not in LEVELS:
            problems.append(f"{r.path}: {r.id} level 不合法：{d.get('level')}")
        passthrough = isinstance(r, Rule) and r.logsource.get("product") == "m365defender"   # alerts carry their own technique
        if not any(str(t).startswith("attack.t") for t in d.get("tags") or []) and isinstance(r, Rule) and r.level != "low" \
                and not passthrough:
            problems.append(f"{r.path}: {r.id} 沒有 ATT&CK technique 標籤")
        if not (d.get("adhd") or {}).get("title_zh"):
            problems.append(f"{r.path}: {r.id} 缺少 adhd.title_zh")
        suppressed_base = isinstance(r, Rule) and any(r.name in c.rules and not c.generate for c in corrs)
        if r.id not in tested and not suppressed_base:
            problems.append(f"{r.path}: {r.id} 沒有任何會觸發它的測試案例")
    return problems


# ===========================================================================================
def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    return "'" + s.replace("'", "''") + "'"


def dump_yaml(obj: Any, indent: int = 0) -> str:
    pad = " " * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            key = k if all(c not in str(k) for c in ":#'\"{}[],&*!|>%@`") or "|" in str(k) and ":" not in str(k) else _yaml_scalar(k)
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{key}:")
                lines.append(dump_yaml(v, indent + 4))
            elif isinstance(v, str) and "\n" in v:
                lines.append(f"{pad}{key}: |")
                lines.extend(f"{pad}    {x}" for x in v.rstrip("\n").split("\n"))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(v) if not isinstance(v, (dict, list)) else ('{}' if isinstance(v, dict) else '[]')}")
        return "\n".join(lines)
    if isinstance(obj, list):
        lines = []
        for v in obj:
            if isinstance(v, dict) and v:
                inner = dump_yaml(v, indent + 2).split("\n")
                lines.append(f"{pad}- {inner[0].lstrip()}")
                lines.extend(inner[1:])
            elif isinstance(v, list) and v:
                lines.append(f"{pad}-")
                lines.append(dump_yaml(v, indent + 4))
            else:
                lines.append(f"{pad}- {_yaml_scalar(v)}")
        return "\n".join(lines)
    return pad + _yaml_scalar(obj)


def _fill(spec: Any, env: dict[str, list[str]], unresolved: set[str]) -> Any:
    if isinstance(spec, list):
        return [_fill(x, env, unresolved) for x in spec]
    if not isinstance(spec, dict):
        return spec
    out = {}
    for key, val in spec.items():
        parts = str(key).split("|")
        if "expand" in [p.lower() for p in parts[1:]]:
            names = [str(v).strip("%") for v in (val if isinstance(val, list) else [val])]
            values = [x for n in names for x in env.get(n, [])]
            if values:
                out["|".join(p for p in parts if p.lower() != "expand")] = values
                continue
            unresolved.update(names)
        out[key] = val
    return out


def tune(env: dict[str, list[str]], out_dir: Path, rules_dir: Path | None = None, label: str = "") -> list[Path]:
    """Environment-specific rule copies with placeholders filled in, plus environment.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for f in rule_files(rules_dir):
        docs = load_all(f.read_text(encoding="utf-8"))
        parts = []
        for d in docs:
            d = json.loads(json.dumps(d, default=str))
            if "detection" in d:
                unresolved: set[str] = set()
                d["detection"] = {k: (v if k == "condition" else _fill(v, env, unresolved)) for k, v in d["detection"].items()}
                d.setdefault("adhd", {})["tuned_for"] = label or "environment"
                if unresolved:
                    d["adhd"]["unresolved_placeholders"] = sorted(unresolved)
            parts.append(dump_yaml(d))
        target = out_dir / f.relative_to(rules_dir or RULES_DIR)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n---\n".join(parts) + "\n", encoding="utf-8")
        written.append(target)
    (out_dir / "environment.json").write_text(json.dumps(env, ensure_ascii=False, indent=2), encoding="utf-8")
    return written


# ===========================================================================================
def build_document(hits: list[dict], cov: list[dict], env: dict[str, list[str]], scope: dict, as_of: str,
                   events: dict[tuple[str, str], list[dict]]) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "analyzer": {"name": "adhd", "version": __version__},
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "asOfUtc": as_of, "scope": scope,
        "events": {"/".join(k): len(v) for k, v in events.items()},
        "summary": {"hitsByLevel": {lv: sum(1 for h in hits if h["level"] == lv) for lv in reversed(LEVELS)},
                    "rulesByStatus": dict(Counter(c["status"] for c in cov)),
                    "raised": sum(1 for h in hits if h["raisedBecause"])},
        "environment": {k: len(v) for k, v in env.items()},
        "hits": hits, "coverage": cov,
    }


def write_markdown(doc: dict[str, Any], path: Path) -> None:
    s = doc["summary"]
    L = [f"# ADHD 偵測結果 — {doc['scope'].get('adDomain') or doc['scope'].get('entraTenantId') or ''}", "",
         f"- 資料時間：{doc['asOfUtc']}　分析時間：{doc['generatedUtc']}　分析器 {doc['analyzer']['version']}",
         "- 事件數：" + "、".join(f"{k} {v}" for k, v in doc["events"].items()),
         "- 環境資料（來自姿態分析）：" + "、".join(f"{k} {v}" for k, v in doc["environment"].items()), "",
         "| 嚴重 | 高 | 中 | 低 | 資訊 | 因涉及 Tier0 / 攻擊路徑而提高 |", "|---|---|---|---|---|---|",
         "| " + " | ".join(str(s["hitsByLevel"][lv]) for lv in ("critical", "high", "medium", "low", "informational"))
         + f" | {s['raised']} |", "", "## 告警", ""]
    if not doc["hits"]:
        L.append("沒有規則觸發。")
    for h in doc["hits"]:
        L.append(f"### 【{LEVEL_ZH.get(h['level'], h['level'])}】{h['titleZh'] or h['title']}")
        L.append("")
        L.append(f"- 規則：{h['ruleId']}（{h['title']}，{'關聯' if h['kind'] == 'correlation' else '單一事件'}）"
                 + (f"；原等級{LEVEL_ZH.get(h['ruleLevel'])}，{h['raisedBecause']}而提高" if h["raisedBecause"] else ""))
        L.append(f"- 時間：{h['first']}" + (f" ～ {h['last']}" if h["last"] != h["first"] else "") + f"；事件 {h['events']} 筆"
                 + (f"；分組 {json.dumps(h.get('group'), ensure_ascii=False)}，計數 {h.get('count')}" if h["kind"] == "correlation" else ""))
        for e in h["entities"]:
            bits = [e["label"]]
            if e.get("tier0"):
                bits.append(f"Tier0（{e['tier0']}）")
            if e.get("attackPath"):
                bits.append(f"攻擊路徑起點：{e['attackPath']['path']}")
            if e.get("syncedTo"):
                bits.append(f"同步為 {e['syncedTo']['label']}（{e['syncedTo']['tier0']}）")
            L.append("- 對象：" + "；".join(bits))
        if h["samples"]:
            L.append("- 事件範例：`" + json.dumps(h["samples"][0], ensure_ascii=False)[:400] + "`")
        if h.get("response"):
            L.append(f"- 建議處置：{h['response']}")
        L.append("")
    L += ["## 偵測涵蓋範圍", "", "| 規則 | 名稱 | 來源 | 狀態 | 觸發 | 說明 |", "|---|---|---|---|---|---|"]
    st = {"evaluated": "已評估", "no-events": "無事件", "not-collected": "未收集", "needs-env": "缺環境資料"}
    for c in doc["coverage"]:
        L.append(f"| {c['ruleId'][:8]} | {(c['titleZh'] or c['title'] or '').replace('|', '/')} | {c['source']} | "
                 f"{st.get(c['status'], c['status'])} | {c['hits']} | {(c['note'] or '').replace('|', '/')} |")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


AUDIT_POLICY = {
    4768: "Audit Kerberos Authentication Service", 4771: "Audit Kerberos Authentication Service",
    4769: "Audit Kerberos Service Ticket Operations", 4625: "Audit Logon",
    4662: "Audit Directory Service Access + domain object SACL", 5136: "Audit Directory Service Changes + SACL",
    4728: "Audit Security Group Management", 4732: "Audit Security Group Management", 4756: "Audit Security Group Management",
    4724: "Audit User Account Management", 4794: "Audit User Account Management", 4719: "Audit Audit Policy Change",
    1102: "（一律記錄）",
}


def catalog_markdown() -> str:
    rules, corrs = load_rules(rule_files())
    lines = ["# ADHD 偵測規則目錄", "", "由 `python3 tools/detect.py catalog` 產生，請勿手動編輯。", "",
             "| 規則 | 等級 | 來源 | 事件 / 條件 | 需要的稽核原則 | 環境資料 | ATT&CK |", "|---|---|---|---|---|---|---|"]
    for r in rules:
        adhd = r.doc.get("adhd") or {}
        ids = sorted({int(v) for s in r.selections.values() for alt in s.alternatives for t in alt
                      if t.field.lower() == "eventid" for v in t.values if str(v).isdigit()})
        suppressed = any(r.name in c.rules and not c.generate for c in corrs)
        lines.append(f"| {adhd.get('title_zh') or r.title}<br>`{r.id}`{'（只供關聯使用）' if suppressed else ''} | {LEVEL_ZH.get(r.level, r.level)} | "
                     f"{'/'.join(source_of(r))} | {', '.join(map(str, ids)) or '—'} | "
                     f"{'<br>'.join(sorted({AUDIT_POLICY.get(i, '') for i in ids} - {''})) or '—'} | "
                     f"{', '.join(sorted(r.placeholders)) or '—'} | "
                     f"{', '.join(t[7:].upper() for t in r.doc.get('tags') or [] if str(t).startswith('attack.t'))} |")
    for c in corrs:
        adhd = c.doc.get("adhd") or {}
        cond = c.doc["correlation"]
        lines.append(f"| {adhd.get('title_zh') or c.title}<br>`{c.id}` | {LEVEL_ZH.get(c.level, c.level)} | 關聯 | "
                     f"{c.type}：{', '.join(c.group_by)} 在 {cond.get('timespan')} 內 {c.op} {c.threshold}"
                     f"{'（' + c.field + '）' if c.field else ''} | 同基礎規則 | — | "
                     f"{', '.join(t[7:].upper() for t in c.doc.get('tags') or [] if str(t).startswith('attack.t'))} |")
    return "\n".join(lines)
