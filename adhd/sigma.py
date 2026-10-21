"""Sigma rules, standard library only: a YAML-subset loader, a rule matcher and correlation (Sigma 2.0).

Supported (enough for the rules in detections/sigma and most community rules of the same shape):

    YAML        block mappings / sequences, plain / quoted scalars, '|' and '>' block scalars, flow sequences
                [a, b], comments, multi-document files.  PyYAML is used instead when it is installed.
    detection   named selections (map = AND, list of maps = OR, list of strings = keywords), field lists (OR),
                null values; modifiers contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte, exists,
                expand (placeholders); '*' / '?' wildcards; case-insensitive string matching
    condition   and / or / not / parentheses, '1 of x*', 'all of x*', '1 of them', 'all of them'
    correlation event_count, value_count (group-by, timespan, gte / gt / lte / lt / eq), generate

Events are flat dicts.  Nested values are reached with dotted names ("status.errorCode"); a field whose
value is a list matches when any element matches.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

# ===========================================================================================
# YAML subset
# ===========================================================================================


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                if quote == "'" and line[i + 1:i + 2] == "'":
                    out.append("''")
                    i += 2
                    continue
                quote = None
            elif ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i:i + 2])
                i += 2
                continue
        elif ch in "'\"" and (i == 0 or line[i - 1] in " :-[,"):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


_INT = re.compile(r"^[-+]?(0|[1-9][0-9]*)$")
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
_FLOAT = re.compile(r"^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$")


def _scalar(text: str) -> Any:
    t = text.strip()
    if t == "":
        return None
    if t[0] == "'":
        if not t.endswith("'") or len(t) < 2:
            raise YamlError(f"unterminated quote: {t}")
        return t[1:-1].replace("''", "'")
    if t[0] == '"':
        if not t.endswith('"') or len(t) < 2:
            raise YamlError(f"unterminated quote: {t}")
        import json
        try:
            return json.loads(t)
        except ValueError:
            raise YamlError(f"bad double-quoted string: {t}") from None
    if t[0] == "[":
        if not t.endswith("]"):
            raise YamlError(f"unterminated flow sequence: {t}")
        inner = t[1:-1].strip()
        return [_scalar(x) for x in _split_flow(inner)] if inner else []
    if t[0] == "{":
        raise YamlError("flow mappings are not supported")
    low = t.lower()
    if low in ("null", "~"):
        return None
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if _INT.match(t):
        return int(t)
    if _HEX.match(t):
        return int(t, 16)
    if _FLOAT.match(t):
        return float(t)
    return t


def _split_flow(s: str) -> list[str]:
    parts, cur, quote = [], [], None
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch == ",":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _key_split(content: str) -> tuple[str, str] | None:
    """'key: value' -> (key, value); None when the line is not a mapping entry."""
    if content[:1] in "'\"":
        q = content[0]
        end = content.find(q, 1)
        while end != -1 and q == "'" and content[end:end + 2] == "''":
            end = content.find(q, end + 2)
        if end == -1:
            return None
        rest = content[end + 1:]
        if rest.startswith(":") and (len(rest) == 1 or rest[1] == " "):
            return _scalar(content[:end + 1]), rest[1:].strip()
        return None
    m = re.match(r"^([^:#\[\]{},'\"]|:(?! |$))+?:(?: |$)", content)
    if not m:
        return None
    key = m.group(0).rstrip()[:-1].strip()
    return key, content[m.end():].strip()


class _Lines:
    def __init__(self, text: str) -> None:
        self.raw = text.split("\n")
        self.items: list[tuple[int, str, int]] = []   # (indent, content, raw index)
        for n, line in enumerate(self.raw):
            if "\t" in line[: len(line) - len(line.lstrip())]:
                raise YamlError(f"line {n + 1}: tabs are not allowed for indentation")
            s = _strip_comment(line)
            if s.strip():
                self.items.append((len(s) - len(s.lstrip(" ")), s.strip(), n))


def _parse_block(L: _Lines, i: int, indent: int) -> tuple[Any, int]:
    if i >= len(L.items):
        return None, i
    ind, content, _ = L.items[i]
    if ind < indent:
        return None, i
    if content == "-" or content.startswith("- "):
        return _parse_seq(L, i, ind)
    return _parse_map(L, i, ind)


def _block_scalar(L: _Lines, i: int, parent_indent: int, style: str) -> tuple[str, int]:
    raw_start = L.items[i][2] + 1
    lines, j = [], raw_start
    while j < len(L.raw):
        line = L.raw[j]
        if line.strip() and len(line) - len(line.lstrip(" ")) <= parent_indent:
            break
        lines.append(line)
        j += 1
    while lines and not lines[-1].strip():
        lines.pop()
    pad = min((len(x) - len(x.lstrip(" ")) for x in lines if x.strip()), default=0)
    body = [x[pad:] for x in lines]
    text = "\n".join(body) if style.startswith("|") else " ".join(x.strip() for x in body if x.strip())
    if not style.endswith("-"):
        text += "\n"
    k = i + 1
    while k < len(L.items) and L.items[k][2] < j:
        k += 1
    return text, k


def _parse_map(L: _Lines, i: int, indent: int) -> tuple[dict, int]:
    out: dict[str, Any] = {}
    while i < len(L.items):
        ind, content, n = L.items[i]
        if ind < indent:
            break
        if ind > indent:
            raise YamlError(f"line {n + 1}: unexpected indentation")
        kv = _key_split(content)
        if kv is None:
            raise YamlError(f"line {n + 1}: expected 'key: value', got {content!r}")
        key, val = kv
        if val in ("|", "|-", ">", ">-", "|+", ">+"):
            out[key], i = _block_scalar(L, i, indent, val.replace("+", ""))
            continue
        i += 1
        if val == "":
            if i < len(L.items) and (L.items[i][0] > indent or
                                     (L.items[i][0] == indent and (L.items[i][1] == "-" or L.items[i][1].startswith("- ")))):
                child_indent = L.items[i][0]
                out[key], i = _parse_block(L, i, child_indent)
            else:
                out[key] = None
        else:
            out[key] = _scalar(val)
    return out, i


def _parse_seq(L: _Lines, i: int, indent: int) -> tuple[list, int]:
    out: list[Any] = []
    while i < len(L.items):
        ind, content, n = L.items[i]
        if ind != indent or not (content == "-" or content.startswith("- ")):
            if ind > indent:
                raise YamlError(f"line {n + 1}: unexpected indentation")
            break
        rest = content[1:].strip()
        if rest == "":
            i += 1
            val, i = _parse_block(L, i, indent + 1) if i < len(L.items) and L.items[i][0] > indent else (None, i)
            out.append(val)
            continue
        if rest == "-" or rest.startswith("- "):
            # "- - x": a nested sequence starting on the dash line
            L.items[i] = (indent + 2, rest, n)
            val, i = _parse_seq(L, i, indent + 2)
            out.append(val)
            continue
        if _key_split(rest) is not None and not rest.startswith(("'", '"', "[")) or (
                rest[:1] in "'\"" and _key_split(rest) is not None):
            # "- key: value" starts a mapping whose keys sit two columns right of the dash
            L.items[i] = (indent + 2, rest, n)
            val, i = _parse_map(L, i, indent + 2)
            out.append(val)
            continue
        out.append(_scalar(rest))
        i += 1
    return out, i


def load_all(text: str) -> list[Any]:
    """All YAML documents in *text* (PyYAML when available, else the subset parser)."""
    try:
        import yaml  # type: ignore
        return [d for d in yaml.safe_load_all(text) if d is not None]
    except ImportError:
        pass
    docs, cur = [], []
    for line in text.split("\n"):
        if line.strip() == "---" or line.startswith("--- "):
            docs.append("\n".join(cur))
            cur = []
        else:
            cur.append(line)
    docs.append("\n".join(cur))
    out = []
    for d in docs:
        L = _Lines(d)
        if not L.items:
            continue
        val, i = _parse_block(L, 0, L.items[0][0])
        if i != len(L.items):
            raise YamlError(f"line {L.items[i][2] + 1}: could not parse {L.items[i][1]!r}")
        out.append(val)
    return out


def load_subset(text: str) -> list[Any]:
    """The subset parser only (used by tests to compare against PyYAML)."""
    import sys
    saved = sys.modules.get("yaml")
    sys.modules["yaml"] = None  # type: ignore[assignment]
    try:
        return load_all(text)
    finally:
        if saved is None:
            del sys.modules["yaml"]
        else:
            sys.modules["yaml"] = saved


# ===========================================================================================
# Events
# ===========================================================================================

def flatten(obj: Any, prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    """Nested dicts -> dotted keys; lists of dicts merge into dotted keys holding lists of leaf values."""
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list) and any(isinstance(x, (dict, list)) for x in obj):
        sub: dict[str, list] = {}
        for x in obj:
            for k, v in flatten(x, prefix).items():
                sub.setdefault(k, [])
                if isinstance(v, list):
                    sub[k].extend(v)
                else:
                    sub[k].append(v)
        for k, v in sub.items():
            out[k] = v
    else:
        out[prefix] = obj
    return out


def _get(event: dict[str, Any], name: str) -> Any:
    if name in event:
        return event[name]
    low = name.lower()
    for k, v in event.items():
        if k.lower() == low:
            return v
    return _MISSING


_MISSING = object()

# ===========================================================================================
# Rules
# ===========================================================================================


class SigmaError(ValueError):
    pass


def _wildcard(value: str) -> re.Pattern:
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        s = str(v).strip()
        return float(int(s, 16)) if s.lower().startswith("0x") else float(s)
    except (TypeError, ValueError):
        return None


@dataclass
class FieldTest:
    field: str
    mods: list[str]
    values: list[Any]

    def match(self, event: dict[str, Any], env: dict[str, list]) -> bool:
        raw = _get(event, self.field)
        mods = [m for m in self.mods if m not in ("all", "expand", "cased")]
        values: list[Any] = []
        for v in self.values:
            if "expand" in self.mods and isinstance(v, str) and v.startswith("%") and v.endswith("%"):
                values.extend(env.get(v.strip("%"), []))
            else:
                values.append(v)
        if "exists" in mods:
            want = bool(values[0]) if values else True
            return (raw is not _MISSING and raw is not None) == want
        if not values:
            return False                               # unresolved placeholder: matches nothing
        items = raw if isinstance(raw, list) else [raw]
        need_all = "all" in self.mods

        def one(v: Any) -> bool:
            return any(self._cmp(x, v, mods) for x in items)
        return all(one(v) for v in values) if need_all else any(one(v) for v in values)

    @staticmethod
    def _cmp(actual: Any, want: Any, mods: list[str]) -> bool:
        if want is None:
            return actual is _MISSING or actual is None or actual == ""
        if actual is _MISSING or actual is None:
            return False
        for m in mods:
            if m in ("gt", "gte", "lt", "lte"):
                a, w = _num(actual), _num(want)
                if a is None or w is None:
                    return False
                return {"gt": a > w, "gte": a >= w, "lt": a < w, "lte": a <= w}[m]
            if m == "cidr":
                try:
                    return ipaddress.ip_address(str(actual).strip()) in ipaddress.ip_network(str(want), strict=False)
                except ValueError:
                    return False
            if m == "re":
                return re.search(str(want), str(actual)) is not None
        a = str(actual).lower() if not isinstance(actual, bool) else str(actual).lower()
        w = str(want).lower() if not isinstance(want, bool) else str(want).lower()
        if isinstance(want, (int, float)) and not isinstance(want, bool):
            n = _num(actual)
            return n is not None and n == float(want)
        if "contains" in mods:
            return w in a
        if "startswith" in mods:
            return a.startswith(w)
        if "endswith" in mods:
            return a.endswith(w)
        if "*" in w or "?" in w:
            return _wildcard(str(want)).match(str(actual)) is not None
        return a == w


@dataclass
class Selection:
    name: str
    alternatives: list[list[FieldTest]] = field(default_factory=list)   # OR of ANDs
    keywords: list[str] = field(default_factory=list)

    def match(self, event: dict[str, Any], env: dict[str, list]) -> bool:
        if self.keywords:
            hay = " ".join(str(v) for v in event.values()).lower()
            return any(k.lower() in hay for k in self.keywords)
        return any(all(t.match(event, env) for t in alt) for alt in self.alternatives)


def _tests(m: dict[str, Any]) -> list[FieldTest]:
    out = []
    for key, val in m.items():
        parts = str(key).split("|")
        vals = val if isinstance(val, list) else [val]
        out.append(FieldTest(parts[0], [p.lower() for p in parts[1:]], vals))
    return out


def _selection(name: str, spec: Any) -> Selection:
    if isinstance(spec, dict):
        return Selection(name, [_tests(spec)])
    if isinstance(spec, list):
        if all(isinstance(x, dict) for x in spec):
            return Selection(name, [_tests(x) for x in spec])
        if all(isinstance(x, (str, int)) for x in spec):
            return Selection(name, keywords=[str(x) for x in spec])
    raise SigmaError(f"selection {name}: unsupported shape")


_TOKEN = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\b1 of\b|\ball of\b|\bany of\b|[A-Za-z0-9_*]+)", re.IGNORECASE)


class _Cond:
    def __init__(self, text: str, names: list[str]) -> None:
        self.tokens = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN.match(text, pos)
            if not m or m.end() == pos:
                raise SigmaError(f"condition: cannot parse near {text[pos:]!r}")
            self.tokens.append(m.group(1).lower() if m.group(1).lower() in ("not", "and", "or", "1 of", "all of", "any of")
                               else m.group(1))
            pos = m.end()
        self.names = names
        self.i = 0
        self.tree = self._or()
        if self.i != len(self.tokens):
            raise SigmaError(f"condition: unexpected {self.tokens[self.i]!r}")

    def _peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self.i += 1
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self.i += 1
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self.i += 1
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t is None:
            raise SigmaError("condition: unexpected end")
        self.i += 1
        if t == "(":
            node = self._or()
            if self._peek() != ")":
                raise SigmaError("condition: missing ')'")
            self.i += 1
            return node
        if t in ("1 of", "any of", "all of"):
            target = self._peek()
            self.i += 1
            if target is None:
                raise SigmaError("condition: missing target after 'of'")
            if target.lower() == "them":
                names = [n for n in self.names if not n.startswith("_")]
            else:
                rx = _wildcard(target)
                names = [n for n in self.names if rx.match(n)]
            if not names:
                raise SigmaError(f"condition: '{target}' matches no selection")
            return ("all" if t == "all of" else "any", names)
        if t not in self.names:
            raise SigmaError(f"condition: unknown selection {t!r}")
        return ("sel", t)

    def eval(self, hit: Callable[[str], bool], node=None) -> bool:
        node = self.tree if node is None else node
        op = node[0]
        if op == "sel":
            return hit(node[1])
        if op == "not":
            return not self.eval(hit, node[1])
        if op == "and":
            return self.eval(hit, node[1]) and self.eval(hit, node[2])
        if op == "or":
            return self.eval(hit, node[1]) or self.eval(hit, node[2])
        if op == "any":
            return any(hit(n) for n in node[1])
        return all(hit(n) for n in node[1])


@dataclass
class Rule:
    doc: dict[str, Any]
    path: str = ""

    def __post_init__(self) -> None:
        d = self.doc
        for req in ("title", "id", "logsource", "detection"):
            if req not in d:
                raise SigmaError(f"{self.path}: missing '{req}'")
        det = dict(d["detection"])
        cond = det.pop("condition", None)
        if not cond:
            raise SigmaError(f"{self.path}: detection.condition is required")
        det.pop("timeframe", None)
        self.selections = {k: _selection(k, v) for k, v in det.items()}
        conds = cond if isinstance(cond, list) else [cond]
        self.conditions = [_Cond(str(c), list(self.selections)) for c in conds]
        self.id = str(d["id"])
        self.name = d.get("name")
        self.title = d["title"]
        self.level = d.get("level", "medium")
        self.logsource = {k: str(v).lower() for k, v in (d.get("logsource") or {}).items()}

    def applies_to(self, logsource: dict[str, str]) -> bool:
        return all(logsource.get(k) == v for k, v in self.logsource.items() if k in ("product", "service", "category"))

    def match(self, event: dict[str, Any], env: dict[str, list] | None = None) -> bool:
        env = env or {}
        cache: dict[str, bool] = {}

        def hit(n: str) -> bool:
            if n not in cache:
                cache[n] = self.selections[n].match(event, env)
            return cache[n]
        return any(c.eval(hit) for c in self.conditions)

    @property
    def placeholders(self) -> set[str]:
        out = set()
        for s in self.selections.values():
            for alt in s.alternatives:
                for t in alt:
                    if "expand" in t.mods:
                        out |= {str(v).strip("%") for v in t.values if isinstance(v, str) and v.startswith("%")}
        return out


_SPAN = re.compile(r"^(\d+)([smhd])$")


def parse_timespan(s: str) -> timedelta:
    m = _SPAN.match(str(s).strip())
    if not m:
        raise SigmaError(f"bad timespan {s!r}")
    n, u = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[u]: n})


@dataclass
class Correlation:
    doc: dict[str, Any]
    path: str = ""

    def __post_init__(self) -> None:
        c = self.doc.get("correlation") or {}
        self.id = str(self.doc.get("id"))
        self.title = self.doc.get("title")
        self.level = self.doc.get("level", "high")
        self.type = c.get("type")
        if self.type not in ("event_count", "value_count"):
            raise SigmaError(f"{self.path}: correlation type {self.type!r} is not supported")
        self.rules = [str(r) for r in (c.get("rules") or [])]
        if not self.rules:
            raise SigmaError(f"{self.path}: correlation.rules is required")
        gb = c.get("group-by") or []
        self.group_by = gb if isinstance(gb, list) else [gb]
        self.timespan = parse_timespan(c.get("timespan") or "1h")
        self.generate = bool(c.get("generate", False))
        cond = c.get("condition") or {}
        self.field = cond.get("field")
        if self.type == "value_count" and not self.field:
            raise SigmaError(f"{self.path}: value_count needs condition.field")
        ops = [k for k in ("gte", "gt", "lte", "lt", "eq") if k in cond]
        if len(ops) != 1:
            raise SigmaError(f"{self.path}: condition needs exactly one of gte / gt / lte / lt / eq")
        self.op, self.threshold = ops[0], cond[ops[0]]

    def _ok(self, n: int) -> bool:
        t = self.threshold
        return {"gte": n >= t, "gt": n > t, "lte": n <= t, "lt": n < t, "eq": n == t}[self.op]

    def evaluate(self, matches: list[tuple[datetime, dict[str, Any]]]) -> list[dict[str, Any]]:
        """matches: (time, event) of the referenced rules.  One hit per group and non-overlapping window."""
        groups: dict[tuple, list[tuple[datetime, dict]]] = {}
        for ts, ev in matches:
            key = tuple(str(_get(ev, g)) if _get(ev, g) is not _MISSING else "" for g in self.group_by)
            groups.setdefault(key, []).append((ts, ev))
        hits = []
        for key, evs in groups.items():
            evs.sort(key=lambda x: x[0])
            start = 0
            j = 0
            while j < len(evs):
                while evs[j][0] - evs[start][0] > self.timespan:
                    start += 1
                window = evs[start:j + 1]
                n = len(window) if self.type == "event_count" else len(
                    {str(_get(e, self.field)) for _, e in window if _get(e, self.field) not in (_MISSING, None, "")})
                if self._ok(n) and self.op in ("gte", "gt", "eq"):
                    hits.append({"group": dict(zip(self.group_by, key)), "count": n, "first": window[0][0], "last": window[-1][0],
                                 "events": [e for _, e in window]})
                    start = j = j + 1          # next window starts after this one
                    if start < len(evs):
                        continue
                    break
                j += 1
            if self.op in ("lte", "lt"):
                n = len(evs) if self.type == "event_count" else len({str(_get(e, self.field)) for _, e in evs})
                if self._ok(n):
                    hits.append({"group": dict(zip(self.group_by, key)), "count": n, "first": evs[0][0], "last": evs[-1][0],
                                 "events": [e for _, e in evs]})
        return hits


def load_rules(paths: Iterable[Path]) -> tuple[list[Rule], list[Correlation]]:
    rules, corrs = [], []
    seen: set[str] = set()
    for p in sorted(paths):
        for doc in load_all(Path(p).read_text(encoding="utf-8")):
            if not isinstance(doc, dict):
                raise SigmaError(f"{p}: document is not a mapping")
            rid = str(doc.get("id"))
            if rid in seen:
                raise SigmaError(f"{p}: duplicate id {rid}")
            seen.add(rid)
            (corrs if "correlation" in doc else rules).append(
                Correlation(doc, str(p)) if "correlation" in doc else Rule(doc, str(p)))
    names = {r.name for r in rules if r.name} | {r.id for r in rules}
    for c in corrs:
        missing = [r for r in c.rules if r not in names]
        if missing:
            raise SigmaError(f"{c.path}: correlation refers to unknown rules {missing}")
    return rules, corrs
