import hashlib
import json

import pytest

from idsec import services
from idsec.audit import AuditLog
from idsec.capability import evaluate, render
from idsec.mockgen import generate
from idsec.models import GraphEdge, GraphNode, IdentityGraph
from idsec.paths import analyze_paths
from idsec.pipeline import run_entity
from idsec.reports import prioritize
from idsec.reports.pingcastle import parse_pingcastle


# ------------------------------------------------------------ 能力矩陣
@pytest.mark.parametrize("entity,profile", [("hq", "A"), ("sub-a", "B"), ("sub-b", "C")])
def test_profiles(env, entity, profile):
    assert services.capability(entity).profile == profile


def test_modules_follow_environment(env):
    hq, suba, subb = (services.capability(e) for e in ("hq", "sub-a", "sub-b"))
    assert {"assess_adcs", "paths_entra", "detect_mdi_triage"} <= set(hq.enabled_modules)
    assert "assess_adcs" not in suba.enabled_modules and "assess_adcs" in suba.disabled_modules
    assert not {"assess_entra", "paths_entra"} & set(subb.enabled_modules)
    assert {"GAP-SIEM", "GAP-SYSMON"} <= {g.id for g in suba.gaps}
    # 被缺口擋住的模組，未啟用原因要寫出缺口
    assert "SIEM" in subb.disabled_modules["detect_sigma_dc"]


def test_tier0_extra(env):
    hq = " ".join(services.capability("hq").tier0_extra)
    assert "Entra Connect" in hq and "AZUREADSSOACC" in hq and "AD CS" in hq
    assert "AD FS" in " ".join(services.capability("sub-a").tier0_extra)
    assert services.capability("sub-b").tier0_extra == []


def test_condition_engine():
    data = {"a": {"b": 1, "c": [], "d": None}}
    assert evaluate({"path": "a.b", "gte": 1}, data)
    assert evaluate({"path": "a.c", "empty": True}, data)
    assert evaluate({"path": "a.d", "empty": True}, data)
    assert not evaluate({"path": "a.d", "lt": 0.5}, data)
    assert evaluate({"any": [{"path": "a.b", "eq": 2}, {"not": {"path": "a.b", "eq": 2}}]}, data)
    assert render("{len:a.c} / {a.b} / {a.x}", data) == "0 / 1 / 未知"
    with pytest.raises(ValueError):
        evaluate({"path": "a.b"}, data)


# ------------------------------------------------------------ 攻擊路徑
def test_hq_esc1_is_first_fix(env):
    p = services.path_analysis("hq")
    first = p.choke_points[0]
    assert first.edge.kind in {"Enroll", "ADCSESC1"}
    assert first.sources_cut_pct > 90
    assert [c.remaining_after for c in p.choke_points] == sorted((c.remaining_after for c in p.choke_points), reverse=True)


def test_hybrid_pivot_found(env):
    p = services.path_analysis("hq")
    kinds = {h.kind for a in p.sample_paths for h in a.hops}
    assert "SyncedToEntraUser" in kinds or "AZAddSecret" in kinds


def test_sub_b_single_fix_clears_all(env):
    p = services.path_analysis("sub-b")
    assert p.sources_with_path == p.sources_total > 0
    assert p.choke_points[0].remaining_after == 0


def test_privileged_members_are_targets_not_sources():
    g = IdentityGraph(
        nodes=[GraphNode(id="DA", kind="Group", name="Domain Admins", tier0=True),
               GraphNode(id="admin", kind="User", name="admin"),
               GraphNode(id="u1", kind="User", name="u1"),
               GraphNode(id="u2", kind="User", name="u2"),
               GraphNode(id="u3", kind="User", name="u3"),
               GraphNode(id="G", kind="Group", name="Helpdesk")],
        edges=[GraphEdge(src="admin", dst="DA", kind="MemberOf"),
               GraphEdge(src="u1", dst="G", kind="MemberOf"),
               GraphEdge(src="u2", dst="G", kind="MemberOf"),
               GraphEdge(src="G", dst="admin", kind="GenericAll")])
    p = analyze_paths("t", g)
    assert p.sources_total == 3 and p.sources_with_path == 2
    assert p.choke_points[0].edge.kind == "GenericAll" and p.choke_points[0].remaining_after == 0


# ------------------------------------------------------------ 評估報告
def test_pingcastle_parse_and_prioritize(env):
    ent = env.entity("hq")
    files = list(ent.path(ent.reports_dir).glob("ad_hc_*.xml"))
    findings = parse_pingcastle(files[0])
    assert len(findings) == 7
    esc = next(f for f in findings if f.id == "A-CertTempCustomSubject")
    assert esc.severity == "critical" and "T1649" in esc.attack
    ranked = prioritize(findings, services.path_analysis("hq"))
    assert ranked[0].id == "A-CertTempCustomSubject" and "路徑" in ranked[0].priority_reason


def test_pingcastle_rejects_dtd(tmp_path):
    bad = tmp_path / "ad_hc_x.xml"
    bad.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "x">]><HealthcheckData/>', encoding="utf-8")
    with pytest.raises(ValueError):
        parse_pingcastle(bad)


# ------------------------------------------------------------ 稽核鏈
def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(3):
        log.append("t", "e", {"i": i})
    assert log.verify()[0]
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["data"]["i"] = 99
    lines[1] = json.dumps(rec)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert not ok and "竄改" in msg
    (tmp_path / "a.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, msg = log.verify()
    assert not ok and "prev_hash" in msg


# ------------------------------------------------------------ 流程與模擬資料
def test_pipeline_outputs(env):
    r = run_entity(env, "sub-a")
    for f in ("fingerprint.json", "capability.json", "paths.json", "findings.json", "report.md"):
        assert (r.out_dir / f).exists()
    report = (r.out_dir / "report.md").read_text(encoding="utf-8")
    assert "建議修補順序" in report and "GAP-SIEM" in report
    assert AuditLog(env.resolve(env.audit_log)).verify()[0]


def test_mockgen_is_deterministic(tmp_path):
    def digest(d):
        return hashlib.sha256(b"".join(p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file())).hexdigest()

    generate(tmp_path / "a")
    generate(tmp_path / "b")
    assert digest(tmp_path / "a") == digest(tmp_path / "b")
