#!/usr/bin/env python3
"""ADHD bundle intake check — run in the lab before a collected bundle enters the analysis pipeline.

Verifies a bundle produced by collectors/powershell/Collect-ADHD.ps1 (schema adhd.collect/1):

  * manifest.json is present and uses a supported schema
  * every dataset file exists, its SHA-256 matches, and its record count matches
  * every JSONL line parses as JSON
  * no forbidden field names (LAPS / password / secret material) appear anywhere
  * no secret patterns (GPP cpassword values, private keys) appear in any file
  * the pseudonymization key / mapping file did not travel with the bundle
  * when pseudonymization is enabled, no un-pseudonymized e-mail addresses remain

Exit code: 0 = pass, 1 = errors found (or warnings with --strict), 2 = usage / unreadable bundle.
Standard library only, so it runs on an air-gapped analysis host.

Usage:
    python3 tools/verify_bundle.py ADHD-Collect-SubA-20261013T010203Z.zip
    python3 tools/verify_bundle.py path/to/bundle-folder --json report.json --strict
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

SUPPORTED_SCHEMA_PREFIX = "adhd.collect/1"

# Keep in sync with $script:ForbiddenKeys in Collect-ADHD.ps1
FORBIDDEN_KEYS = {
    k.lower()
    for k in (
        "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
        "msFVE-RecoveryPassword", "msFVE-KeyPackage", "msTPM-OwnerInformation",
        "unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials",
        "userPassword", "unixUserPassword", "msDS-ManagedPassword",
        "cpassword", "password", "secretText", "clientSecret", "privateKey", "hint", "key",
    )
}

SECRET_PATTERNS = [
    (re.compile(rb'cpassword\s*=\s*"[^"]+"', re.IGNORECASE), "GPP cpassword value"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----"), "private key block"),
]

EMAIL_RE = re.compile(r"(?<![\w.%+\-#/])([\w.%+\-#]+)@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})")
PSEUDO_LOCAL_RE = re.compile(r"^u-[0-9a-f]{12}$")
KEY_MATERIAL_NAME_RE = re.compile(r"ADHD-pseudonym(?:-map-.*\.csv|\.key)$", re.IGNORECASE)


@dataclass
class Report:
    bundle: str
    schema: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip, rejecting absolute paths and traversal; tolerate Windows backslash entry names."""
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
                raise ValueError(f"unsafe path in archive: {info.filename!r}")
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
    raise FileNotFoundError(f"manifest.json not found under {path}")


def walk_keys(obj: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, f"{path}.{k}"
            yield from walk_keys(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_keys(v, f"{path}[{i}]")


def walk_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v)


def mask_email(local: str, domain: str) -> str:
    return f"{local[:1]}***@{domain}"


def check_jsonl(path: Path, name: str, expected_records: int, pseudo: bool, report: Report) -> int:
    count = 0
    leaked: list[str] = []
    forbidden_hits: set[str] = set()
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            count += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                report.error(f"{name}: line {lineno} is not valid JSON ({exc.msg})")
                continue
            for key, where in walk_keys(row):
                if key.lower() in FORBIDDEN_KEYS:
                    forbidden_hits.add(where.split("[")[0] if "[" in where else where)
            if pseudo:
                for s in walk_strings(row):
                    if "@" not in s:
                        continue
                    for m in EMAIL_RE.finditer(s):
                        if not PSEUDO_LOCAL_RE.match(m.group(1)):
                            leaked.append(mask_email(m.group(1), m.group(2)))
    if count != expected_records:
        report.error(f"{name}: manifest says {expected_records} records, file has {count}")
    for where in sorted(forbidden_hits):
        report.error(f"{name}: forbidden field present at {where}")
    if leaked:
        sample = ", ".join(sorted(set(leaked))[:5])
        report.warn(f"{name}: {len(leaked)} e-mail address(es) not pseudonymized (e.g. {sample})")
    return count


def verify(bundle_arg: Path) -> Report:
    report = Report(bundle=str(bundle_arg))
    tmp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if bundle_arg.is_file() and zipfile.is_zipfile(bundle_arg):
            tmp = tempfile.TemporaryDirectory(prefix="adhd-verify-")
            safe_extract(bundle_arg, Path(tmp.name))
            root = find_bundle_root(Path(tmp.name))
        elif bundle_arg.is_dir():
            root = find_bundle_root(bundle_arg)
        else:
            raise FileNotFoundError(f"not a bundle folder or zip: {bundle_arg}")

        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        report.schema = manifest.get("schema")
        if not str(report.schema or "").startswith(SUPPORTED_SCHEMA_PREFIX):
            report.error(f"unsupported schema {report.schema!r} (expected {SUPPORTED_SCHEMA_PREFIX})")
        pseudo = bool((manifest.get("pseudonymization") or {}).get("enabled"))
        if not pseudo:
            report.warn("pseudonymization was disabled at collection time — confirm the data owner approved this")

        listed: set[str] = {"manifest.json", "collection.log"}
        for ds in manifest.get("datasets", []):
            name, status, fmt, rel = ds.get("name"), ds.get("status"), ds.get("format"), ds.get("file")
            entry = {"name": name, "module": ds.get("module"), "status": status, "records": ds.get("records")}
            report.datasets.append(entry)
            if status in ("error", "partial"):
                report.warn(f"{name}: collected with status '{status}' — {ds.get('message') or 'no message'}")
            elif status == "skipped":
                report.warn(f"{name}: skipped — {ds.get('message') or 'no reason given'}")
            if not rel:
                continue
            if fmt == "jsonl":
                listed.add(rel)
                path = root / rel
                if not path.is_file():
                    report.error(f"{name}: file {rel} missing")
                    continue
                if ds.get("sha256") and sha256_file(path) != ds["sha256"]:
                    report.error(f"{name}: SHA-256 mismatch for {rel}")
                check_jsonl(path, name, int(ds.get("records") or 0), pseudo, report)
            elif fmt == "dir":
                for f in ds.get("files", []):
                    fpath = root / PurePosixPath(f["path"])
                    listed.add(f["path"])
                    if not fpath.is_file():
                        report.error(f"{name}: file {f['path']} missing")
                    elif sha256_file(fpath) != f.get("sha256"):
                        report.error(f"{name}: SHA-256 mismatch for {f['path']}")

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if KEY_MATERIAL_NAME_RE.search(path.name):
                report.error(f"pseudonymization key/mapping must stay with the data owner: {rel}")
            elif rel not in listed:
                report.warn(f"file not listed in manifest: {rel}")
            data = path.read_bytes()
            for pattern, label in SECRET_PATTERNS:
                if pattern.search(data):
                    report.error(f"{rel}: contains {label}")
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        report.error(f"cannot read bundle: {exc}")
    finally:
        if tmp is not None:
            tmp.cleanup()
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify an ADHD collection bundle before analysis.")
    ap.add_argument("bundle", type=Path, help="bundle folder or .zip produced by Collect-ADHD.ps1")
    ap.add_argument("--json", type=Path, help="write the verification report as JSON to this path")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    args = ap.parse_args(argv)

    if not args.bundle.exists():
        print(f"error: {args.bundle} does not exist", file=sys.stderr)
        return 2

    report = verify(args.bundle)

    print(f"Bundle : {report.bundle}")
    print(f"Schema : {report.schema}")
    width = max((len(d["name"] or "") for d in report.datasets), default=10)
    for d in report.datasets:
        print(f"  {d['name']:<{width}}  {d['status']:<8} {d['records']:>8}")
    for w in report.warnings:
        print(f"WARN   {w}")
    for e in report.errors:
        print(f"ERROR  {e}")
    failed = bool(report.errors) or (args.strict and bool(report.warnings))
    print(f"Result : {'FAIL' if failed else 'PASS'} ({len(report.errors)} error(s), {len(report.warnings)} warning(s))")

    if args.json:
        args.json.write_text(
            json.dumps(
                {"bundle": report.bundle, "schema": report.schema, "passed": not failed,
                 "errors": report.errors, "warnings": report.warnings, "datasets": report.datasets},
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
