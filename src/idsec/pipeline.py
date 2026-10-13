"""確定性流程：盤點 → 能力矩陣 → 評估 → 路徑 → 報告。

每一步都寫入稽核鏈，產出物存於 output/<entity>/。模組未被能力矩陣啟用時跳過。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog
from .backends import get_backend
from .capability import apply_matrix, load_matrix
from .config import Settings
from .discovery import build_fingerprint
from .models import CapabilityResult, Finding, Fingerprint, PathAnalysis
from .paths import analyze_paths
from .reports import load_findings, prioritize


@dataclass
class EntityResult:
    entity: str
    name: str
    fingerprint: Fingerprint
    capability: CapabilityResult
    findings: list[Finding] = field(default_factory=list)
    paths: PathAnalysis | None = None
    out_dir: Path | None = None


def _write(path: Path, model) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(model, "model_dump_json"):
        path.write_text(model.model_dump_json(indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")


def output_dir(settings: Settings, entity_id: str) -> Path:
    return settings.resolve(settings.output_dir) / entity_id


def discover(settings: Settings, entity_id: str, audit: AuditLog | None = None) -> tuple[Fingerprint, CapabilityResult]:
    audit = audit or AuditLog(settings.resolve(settings.audit_log))
    ent = settings.entity(entity_id)
    backend = get_backend(ent)
    fp = build_fingerprint(entity_id, backend)
    cap = apply_matrix(fp, load_matrix(settings.resolve(settings.capability_matrix)))
    out = output_dir(settings, entity_id)
    _write(out / "fingerprint.json", fp)
    _write(out / "capability.json", cap)
    audit.append("pipeline", "discovery.completed",
                 {"entity": entity_id, "backend": ent.backend, "profile": cap.profile,
                  "enabled": cap.enabled_modules, "gaps": [g.id for g in cap.gaps]})
    return fp, cap


def run_entity(settings: Settings, entity_id: str) -> EntityResult:
    audit = AuditLog(settings.resolve(settings.audit_log))
    ent = settings.entity(entity_id)
    fp, cap = discover(settings, entity_id, audit)
    out = output_dir(settings, entity_id)
    result = EntityResult(entity=entity_id, name=ent.name, fingerprint=fp, capability=cap, out_dir=out)

    if "paths_ad" in cap.enabled_modules:
        graph = get_backend(ent).identity_graph()
        if "paths_entra" not in cap.enabled_modules:
            graph.nodes = [n for n in graph.nodes if not n.kind.startswith("AZ")]
        result.paths = analyze_paths(entity_id, graph)
        _write(out / "paths.json", result.paths)
        audit.append("pipeline", "paths.completed",
                     {"entity": entity_id, "sources_total": result.paths.sources_total,
                      "sources_with_path": result.paths.sources_with_path,
                      "choke_points": len(result.paths.choke_points)})

    if "assess_ad" in cap.enabled_modules:
        result.findings = prioritize(load_findings(ent.path(ent.reports_dir)), result.paths)
        _write(out / "findings.json", [f.model_dump() for f in result.findings])
        audit.append("pipeline", "assessment.completed",
                     {"entity": entity_id, "findings": len(result.findings)})

    from .report import render_markdown

    (out / "report.md").write_text(render_markdown(result), encoding="utf-8")
    audit.append("pipeline", "report.written", {"entity": entity_id, "path": str(out / "report.md")})
    return result
