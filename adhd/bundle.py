"""Read collection bundles (schema adhd.collect/1) from folders or zips.

A *round* is every bundle collected for one environment at one point in time — typically the
domain-member host (AD + Entra), the Entra Connect server, and optionally a logs bundle.
Datasets with the same name are concatenated across the bundles of a round.
"""
from __future__ import annotations

import json
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA_PREFIX = "adhd.collect/1"
USABLE = ("ok", "partial")


class BundleError(Exception):
    pass


_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_ts(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp. Accepts 'Z', any number of fractional digits (Graph uses 7) — Python 3.8+."""
    if not isinstance(value, str) or not value:
        return None
    m = _TS.match(value.strip())
    if not m:
        return None
    date, time, frac, tz = m.groups()
    text = f"{date}T{time}" + (f".{(frac + '000000')[:6]}" if frac else "")
    if tz and tz != "Z":
        text += tz if ":" in tz else f"{tz[:3]}:{tz[3:]}"
    else:
        text += "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip, rejecting absolute paths / traversal; accept Windows backslash entry names."""
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
                raise BundleError(f"unsafe path in archive {zip_path.name}: {info.filename!r}")
            target = dest.joinpath(*parts)
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def find_bundle_root(path: Path) -> Path:
    if (path / "manifest.json").is_file():
        return path
    candidates = [p.parent for p in path.glob("*/manifest.json")]
    if len(candidates) == 1:
        return candidates[0]
    raise BundleError(f"manifest.json not found under {path}")


class Bundle:
    def __init__(self, root: Path, source: str) -> None:
        self.root = root
        self.source = source
        try:
            self.manifest: dict[str, Any] = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BundleError(f"cannot read manifest of {source}: {exc}") from exc
        schema = str(self.manifest.get("schema") or "")
        if not schema.startswith(SCHEMA_PREFIX):
            raise BundleError(f"{source}: unsupported schema {schema!r}")
        self.name: str = self.manifest.get("bundle") or root.name
        self.datasets: dict[str, dict[str, Any]] = {d["name"]: d for d in self.manifest.get("datasets", [])}

    @property
    def key_id(self) -> str | None:
        p = self.manifest.get("pseudonymization") or {}
        return p.get("keyId") if p.get("enabled") else None

    @property
    def pseudonymized(self) -> bool:
        return bool((self.manifest.get("pseudonymization") or {}).get("enabled"))

    @property
    def finished(self) -> datetime | None:
        return parse_ts(self.manifest.get("finishedUtc")) or parse_ts(self.manifest.get("startedUtc"))

    def rows(self, name: str) -> list[dict[str, Any]]:
        ds = self.datasets.get(name)
        if not ds or ds.get("format") != "jsonl" or not ds.get("file") or ds.get("status") not in USABLE:
            return []
        path = self.root / ds["file"]
        if not path.is_file():
            return []
        out = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
        return out


def _source(b: Bundle, dataset: str) -> str | None:
    """What a dataset is a snapshot of.  Two bundles with the same dataset from the same source overlap
    (e.g. a re-collection); different sources (another domain, a second Entra Connect server) are merged."""
    scope = b.manifest.get("scope") or {}
    if dataset.startswith("entraconnect"):
        return "aadc:" + str(((b.manifest.get("runContext") or {}).get("computer") or "")).lower()
    if dataset.startswith(("ad_", "dc_")):
        return "ad:" + str(scope.get("adDomainSid") or scope.get("adDomain") or "").lower()
    if dataset.startswith("entra_"):
        return "entra:" + str(scope.get("entraTenantId") or "").lower()
    return None


class Round:
    """All bundles of one collection round, with datasets merged by name.

    When the same dataset of the same source appears in more than one bundle (a re-collection passed together
    with the original), only the most recently finished bundle's copy is used, so rows are never doubled;
    ``superseded`` lists what was set aside."""

    def __init__(self, bundles: list[Bundle]) -> None:
        if not bundles:
            raise BundleError("no bundles given")
        self.bundles = bundles
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self.superseded: list[dict[str, str]] = []
        self._use: dict[str, list[Bundle]] = {}
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        names = {n for b in bundles for n in b.datasets}
        for name in sorted(names):
            have = [b for b in bundles if b.datasets.get(name, {}).get("status") in USABLE]
            groups: dict[Any, list[Bundle]] = {}
            for b in have:
                src = _source(b, name)
                groups.setdefault(src if src is not None else id(b), []).append(b)
            use = []
            for grp in groups.values():
                grp = sorted(grp, key=lambda x: x.finished or epoch)
                use.append(grp[-1])
                for old in grp[:-1]:
                    self.superseded.append({"dataset": name, "bundle": old.name, "usedInstead": grp[-1].name})
            self._use[name] = [b for b in bundles if b in use]

    @property
    def key_ids(self) -> set[str]:
        return {b.key_id for b in self.bundles if b.key_id}

    @property
    def as_of(self) -> datetime:
        times = [b.finished for b in self.bundles if b.finished]
        return max(times) if times else datetime.now(timezone.utc)

    def status(self, name: str) -> str | None:
        """Best status of a dataset across bundles: ok > partial > error > skipped > None (never collected)."""
        order = ["ok", "partial", "error", "skipped"]
        pool = self._use.get(name) or self.bundles
        found = [b.datasets[name].get("status") for b in pool if name in b.datasets]
        for st in order:
            if st in found:
                return st
        return None

    def usable(self, name: str) -> bool:
        return self.status(name) in USABLE

    def rows(self, name: str) -> list[dict[str, Any]]:
        if name not in self._cache:
            merged: list[dict[str, Any]] = []
            for b in self._use.get(name, []):
                merged.extend(b.rows(name))
            self._cache[name] = merged
        return self._cache[name]

    def scope(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for b in self.bundles:
            for k, v in (b.manifest.get("scope") or {}).items():
                if v not in (None, "", []) and k not in out:
                    out[k] = v
        return out

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "bundle": b.name,
                "collector": (b.manifest.get("collector") or {}).get("version"),
                "modules": ((b.manifest.get("runContext") or {}).get("parameters") or {}).get("include"),
                "finishedUtc": b.manifest.get("finishedUtc"),
                "keyId": b.key_id,
                "supersededDatasets": [x["dataset"] for x in self.superseded if x["bundle"] == b.name],
            }
            for b in self.bundles
        ]


def open_round(paths: Iterable[Path], workdir: Path) -> Round:
    """Open bundle folders / zips. Zips are extracted under *workdir* (caller owns its lifetime)."""
    bundles = []
    for i, p in enumerate(paths):
        p = Path(p)
        if p.is_file() and zipfile.is_zipfile(p):
            dest = workdir / f"bundle{i}"
            dest.mkdir(parents=True, exist_ok=True)
            safe_extract(p, dest)
            bundles.append(Bundle(find_bundle_root(dest), str(p)))
        elif p.is_dir():
            bundles.append(Bundle(find_bundle_root(p), str(p)))
        else:
            raise BundleError(f"not a bundle folder or zip: {p}")
    return Round(bundles)
