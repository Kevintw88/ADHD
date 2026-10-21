"""Tests for the offline analysis (stdlib unittest; run: python3 -m unittest discover -s tests/python -v)."""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from adhd import acl  # noqa: E402
from adhd.analyze import main as analyze_main  # noqa: E402
from adhd.bundle import open_round  # noqa: E402
from adhd.load import build_context, parent_dn  # noqa: E402
from adhd.rules import SEVERITY_RANK, all_rules, run_rules  # noqa: E402

import fixtures as fx  # noqa: E402

# rule -> most severe finding expected in the vulnerable round
EXPECTED_VULNERABLE = {
    "AD-001": "high", "AD-002": "medium", "AD-003": "critical", "AD-004": "high", "AD-005": "high",
    "AD-006": "critical", "AD-007": "critical", "AD-008": "medium", "AD-009": "high", "AD-010": "medium",
    "AD-011": "medium", "AD-012": "medium", "AD-013": "critical", "AD-014": "medium", "AD-015": "high",
    "AD-016": "high", "AD-017": "high", "AD-018": "high", "AD-019": "critical", "AD-020": "critical",
    "AD-021": "critical", "AD-022": "high", "AD-023": "high", "AD-024": "medium", "AD-025": "low",
    "AD-026": "high", "AD-027": "medium", "AD-028": "low", "AD-029": "low", "AD-030": "medium",
    "ADCS-001": "critical", "ADCS-002": "high", "ADCS-003": "high", "ADCS-004": "critical", "ADCS-005": "high",
    "ADCS-006": "medium", "ADCS-007": "info",
    "EN-002": "critical", "EN-003": "high", "EN-004": "critical", "EN-005": "medium", "EN-006": "high",
    "EN-007": "high", "EN-008": "medium", "EN-009": "info", "EN-010": "medium", "EN-011": "high", "EN-012": "high",
    "EN-013": "critical", "EN-014": "medium", "EN-015": "high", "EN-016": "high", "EN-017": "low", "EN-018": "high",
    "EN-019": "high", "EN-020": "medium", "EN-021": "medium", "EN-022": "info",
    "HY-001": "high", "HY-002": "medium", "HY-003": "info", "HY-004": "high", "HY-005": "high",
}
# rules that legitimately produce informational output in a tidy environment
INFO_IN_CLEAN = {"AD-014", "AD-021", "ADCS-007", "EN-008", "EN-009", "EN-014", "HY-003"}


def _top(result):
    return min((f.severity for f in result.findings), key=SEVERITY_RANK.__getitem__)


class RoundCase(unittest.TestCase):
    vulnerable = True

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.paths = fx.make_round(root / "b", cls.vulnerable)
        cls.ctx = build_context(open_round(cls.paths, root / "x"))
        cls.results = {r.rule.id: r for r in run_rules(cls.ctx)}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def finding(self, rule_id, contains=None):
        for f in self.results[rule_id].findings:
            if contains is None or contains in f.summary or contains in f.title:
                return f
        self.fail(f"{rule_id}: no finding matching {contains!r}")


class VulnerableRound(RoundCase):
    vulnerable = True

    def test_no_rule_errors(self):
        errors = {k: r.reason for k, r in self.results.items() if r.status == "error"}
        self.assertEqual(errors, {})

    def test_every_rule_has_an_expectation(self):
        known = {r.id for r in all_rules()}
        self.assertEqual(sorted(known - set(EXPECTED_VULNERABLE) - {"EN-001"}), [])

    def test_each_planted_weakness_is_found(self):
        for rule_id, sev in EXPECTED_VULNERABLE.items():
            with self.subTest(rule=rule_id):
                r = self.results[rule_id]
                self.assertEqual(r.status, "finding", r.reason)
                self.assertEqual(_top(r), sev)

    def test_tier0_closure(self):
        t0 = self.ctx.tier0
        for s in (fx.sid(500), fx.sid(1101), fx.sid(1000), fx.sid(502), fx.sid(1103)):  # 1103 via Account Operators
            self.assertIn(s, t0)
        self.assertIn(fx.sid(1106), t0, "DCSync holder must be Tier0")
        self.assertNotIn(fx.sid(1102), t0)
        self.assertNotIn(fx.sid(1201), t0)

    def test_dcsync_edges(self):
        holders = {e.src for e in self.ctx.graph.edges_in(fx.DOM, ["DCSync"])}
        self.assertIn(fx.sid(1107), holders)
        self.assertIn(fx.sid(1106), holders)
        self.assertIn("S-1-5-32-544", holders)
        self.assertNotIn("S-1-5-9", holders)          # Get-Changes only
        self.assertNotIn(fx.sid(1201), holders)       # inherit-only ACE does not grant DCSync on the root
        self.assertIn(fx.sid(512), holders)           # GenericAll on the domain root implies DCSync

    def test_dcsync_connector_vs_unknown(self):
        bad = self.finding("AD-021", "非預設主體")
        self.assertEqual([a["id"] for a in bad.affected], [fx.sid(1107)])
        conn = self.finding("AD-021", "connector")
        self.assertEqual(conn.severity, "info")
        self.assertEqual([a["id"] for a in conn.affected], [fx.sid(1106)])

    def test_tier0_acl_principals(self):
        f = self.finding("AD-020")
        ids = {a["id"] for a in f.affected}
        self.assertEqual(ids, {fx.sid(1500), fx.sid(1201), fx.sid(1104)})
        details = " ".join(" ".join(a["detail"]) for a in f.affected)
        for expected in ("WriteDacl", "GenericAll", "ForceChangePassword", "WriteGPLink", "GenericWrite"):
            self.assertIn(expected, details)
        self.assertNotIn("S-1-5-11", ids)      # default read ACEs ignored
        self.assertNotIn(fx.sid(527), ids)     # Key Admins are Tier0

    def test_non_tier0_ou_delegation_not_reported(self):
        f = self.finding("AD-020")
        self.assertFalse(any("Workstations" in d for a in f.affected for d in a["detail"]))

    def test_constrained_delegation_to_dc(self):
        f = self.finding("AD-006")
        self.assertEqual(f.affected[0]["id"], fx.sid(1102))

    def test_adcs_details(self):
        self.assertEqual(self.finding("ADCS-001").affected[0]["label"], "ESC1")
        self.assertEqual({a["label"] for a in self.finding("ADCS-005").affected}, {"NTAuthCertificates"})
        self.assertEqual(self.finding("ADCS-004").affected[0]["label"], "ESC4")

    def test_entra_details(self):
        self.assertEqual({a["id"] for a in self.finding("EN-002", "Tier0").affected}, {"entra:e-cloudadmin"})
        self.assertEqual({a["id"] for a in self.finding("EN-018").affected}, {"entra:g-priv", "entra:a-1"})
        self.assertEqual({a["id"] for a in self.finding("HY-001").affected}, {"entra:e-cloudadmin"})
        self.assertEqual({a["id"] for a in self.finding("EN-019").affected}, {fx.sid(1102)})
        self.assertEqual(self.finding("EN-005").affected[0]["id"], "entra:e-ga1")

    def test_calibrations_from_suba(self):
        # built-in RODC groups mention "password" in their default description
        self.assertNotIn(fx.sid(571), {a["id"] for a in self.finding("AD-018").affected})
        # DCSync detail reports real Tier0-group membership, not the DCSync-derived Tier0 flag
        bad = self.finding("AD-021", "非預設主體").affected[0]
        self.assertFalse(bad["detail"]["inTier0Group"])
        # orphan SIDs are labelled
        self.assertIn("孤立", self.ctx.label(fx.sid(2104)))
        # ESC4: published + broad = critical, orphan-only writer = low
        sev = {f.severity: [a["label"] for a in f.affected] for f in self.results["ADCS-004"].findings}
        self.assertEqual(sev["critical"], ["ESC4"])
        self.assertEqual(sev["low"], ["OrphanACL"])
        # EN-015: Microsoft first-party grants are low and aggregated per client
        by_sev = {f.severity: f for f in self.results["EN-015"].findings}
        self.assertEqual([a["id"] for a in by_sev["low"].affected], ["entra:sp-photos"])
        self.assertEqual([a["id"] for a in by_sev["high"].affected], ["entra:sp-app"])
        # LAPS: Tier0 server separated (high), stale host excluded
        laps = {f.title: f for f in self.results["AD-015"].findings}
        self.assertEqual([a["label"] for a in laps["Tier0 伺服器沒有 LAPS"].affected], ["CA-AADC"])
        self.assertFalse(any(a["label"] == "OLD-PC" for f in laps.values() for a in f.affected))
        # P2P Server is a system service principal (info)
        p2p = [f for f in self.results["EN-014"].findings if any(a["id"] == "entra:sp-p2p" for a in f.affected)]
        self.assertEqual([f.severity for f in p2p], ["info"])

    def test_disabled_in_ad_enabled_in_entra(self):
        f = self.finding("HY-005")
        self.assertEqual([a["id"] for a in f.affected], ["entra:e-left"])
        self.assertEqual(f.evidence["recentCloudSignIns"], 1)
        self.assertIn("同步規則", f.summary)            # tenant sync is running -> rule / filter hypothesis

    def test_connector_key_credential(self):
        f = self.finding("HY-004")
        a = f.affected[0]
        self.assertEqual(a["id"], fx.sid(1106))
        self.assertEqual(a["detail"]["identifiedBy"], "名稱比對")
        self.assertIn("CORP\\u-svc", a["detail"]["nonTier0LocalAdminsOnServer"])

    def test_hotspots_merge_ad_and_entra(self):
        from adhd.report import build_document
        doc = build_document(self.ctx, list(self.results.values()))
        hs = {h["id"]: h for h in doc["hotspots"]}
        self.assertIn(fx.sid(1105), hs, "synced cloud admin should be merged under its AD SID")
        h = hs[fx.sid(1105)]
        self.assertIn("entra:e-cloudadmin", h["accounts"])
        self.assertTrue({"EN-002", "HY-001"} <= {r.split("（")[0] for r in h["rules"]})

    def test_finding_shape(self):
        for r in self.results.values():
            for f in r.findings:
                d = f.to_dict()
                self.assertTrue(d["remediation"], f.rule_id)
                json.dumps(d, ensure_ascii=False)


class CleanRound(RoundCase):
    vulnerable = False

    def test_no_rule_errors(self):
        self.assertEqual({k: r.reason for k, r in self.results.items() if r.status == "error"}, {})

    def test_no_actionable_findings(self):
        for rule_id, r in self.results.items():
            with self.subTest(rule=rule_id):
                self.assertNotEqual(r.status, "skipped", r.reason)
                if rule_id in INFO_IN_CLEAN:
                    self.assertTrue(all(f.severity == "info" for f in r.findings),
                                    [(f.severity, f.summary) for f in r.findings])
                else:
                    self.assertEqual(r.status, "pass", [(f.severity, f.summary, f.affected[:3]) for f in r.findings])


class CoverageAndCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_entra_connect_only_round_skips_ad_rules(self):
        paths = fx.make_round(self.root / "b", True)
        ctx = build_context(open_round([paths[1]], self.root / "x"))
        res = {r.rule.id: r for r in run_rules(ctx)}
        self.assertEqual(res["AD-003"].status, "skipped")
        self.assertIn("ad_users(未收集)", res["AD-003"].reason)
        self.assertEqual(res["HY-003"].status, "finding")

    def test_privileged_connector_inferred_from_cleartext_login(self):
        """SubA case: 0.1.1 AADC bundle (cleartext login 'ithd'), connector account is a Domain Admin."""
        data = fx._ad_common(True)
        for g in data["ad_groups"]:
            if g["sid"] == fx.sid(512):
                g["members"].append(fx.sid(1106))
        for r in data["ad_acls"]:
            if r["reason"] == "domainRoot":
                r["aces"] = [a for a in r["aces"] if a["principal"] != fx.sid(1107)]
        aadc = fx._aadc(True)
        aadc["entraconnect_connectors"][0]["connectivityParameters"]["forest-login-user"] = "ithd"
        aadc["entraconnect_connectors"].append({"name": "corp.onmicrosoft.com - AAD", "type": "Extensible2",
                                                "connectivityParameters": {"UserName": "{guid}@corp.onmicrosoft.com"}})
        b1 = fx.write_bundle(self.root / "b", "ad", data, scope={"adDomainSid": fx.DOM})
        b2 = fx.write_bundle(self.root / "b", "aadc", aadc)
        res = {r.rule.id: r for r in run_rules(build_context(open_round([b1, b2], self.root / "x")))}
        hy = res["HY-004"].findings
        self.assertEqual([f.severity for f in hy], ["critical"])
        d = hy[0].affected[0]["detail"]
        self.assertEqual(hy[0].affected[0]["id"], fx.sid(1106))
        self.assertTrue(d["inTier0Group"])
        self.assertIn("推斷", d["identifiedBy"])
        bad = [f for f in res["AD-021"].findings if f.severity == "critical"][0]
        self.assertTrue(bad.affected[0]["detail"]["likelyConnector"])
        self.assertNotIn("{guid}", bad.summary)          # Entra-side connector account is not an AD login

    def test_esc4_without_enterprise_ca_is_low(self):
        data = fx._ad_common(True)
        data["adcs_cas"] = []
        for t in data["adcs_templates"]:
            t["published"] = False
        b = fx.write_bundle(self.root / "b", "no-ca", data, scope={"adDomainSid": fx.DOM})
        res = {r.rule.id: r for r in run_rules(build_context(open_round([b], self.root / "x")))}
        self.assertEqual({f.severity for f in res["ADCS-004"].findings}, {"low"})
        self.assertEqual(res["ADCS-001"].status, "pass")

    def test_failed_dataset_marks_rule_skipped(self):
        data = fx._ad_common(True)
        data["gpo_gpp_cpassword"] = ("error", "無法存取 SYSVOL")
        b = fx.write_bundle(self.root / "b", "only-ad", data, scope={"adDomainSid": fx.DOM})
        res = {r.rule.id: r for r in run_rules(build_context(open_round([b], self.root / "x")))}
        self.assertEqual(res["AD-019"].status, "skipped")
        self.assertIn("gpo_gpp_cpassword(error)", res["AD-019"].reason)

    def test_cli_outputs_and_mixed_key_guard(self):
        paths = fx.make_round(self.root / "b", True)
        out = self.root / "out"
        self.assertEqual(analyze_main([str(p) for p in paths] + ["--out", str(out)]), 0)
        doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "adhd.findings/1")
        self.assertEqual(doc["summary"]["rules"]["error"], 0)
        self.assertTrue(doc["findings"][0]["severity"] == "critical")
        md = (out / "findings.md").read_text(encoding="utf-8")
        self.assertIn("## 規則執行狀態", md)
        con = sqlite3.connect(str(out / "graph.sqlite"))
        try:
            n = con.execute("SELECT count(*) FROM edges WHERE kind='DCSync'").fetchone()[0]
            self.assertGreaterEqual(n, 3)
            t0 = con.execute("SELECT count(*) FROM nodes WHERE tier0=1").fetchone()[0]
            self.assertGreater(t0, 5)
        finally:
            con.close()
        other = fx.write_bundle(self.root / "c", "other-key", fx._aadc(True), key_id="different")
        self.assertEqual(analyze_main([str(paths[0]), str(other), "--out", str(self.root / "o2")]), 2)

    def test_powershell_collector_bundles(self):
        """End-to-end with real collector output: set ADHD_SMOKE_BUNDLES to the zips from Invoke-CollectorSmokeTest.ps1."""
        import os
        paths = [Path(p) for p in os.environ.get("ADHD_SMOKE_BUNDLES", "").split(os.pathsep) if p]
        if not paths:
            self.skipTest("ADHD_SMOKE_BUNDLES not set")
        ctx = build_context(open_round(paths, self.root / "x"))
        res = run_rules(ctx)
        self.assertEqual([r.rule.id for r in res if r.status == "error"], [])
        self.assertIn("S-1-5-21-1-2-3-512", ctx.tier0)
        self.assertTrue(any(r.rule.id == "ADCS-001" and r.status == "finding" for r in res))


class Exceptions(unittest.TestCase):
    def test_apply_exceptions(self):
        from adhd.exceptions import apply_exceptions
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = fx.make_round(root / "b", True)
            ctx = build_context(open_round(paths, root / "x"))
            results = run_rules(ctx)
            exc = [
                {"id": "entra:e-ga1", "rules": ["EN-005"], "reason": "break-glass", "expires": "2027-01-01"},
                {"id": "*", "rules": ["EN-012"], "reason": "project", "owner": "IT"},
                {"id": "entra:nobody", "rules": ["*"], "reason": "stale entry"},
                {"id": "S-1-5-21-10-20-30-1102", "rules": ["AD-004"], "reason": "expired", "expires": "2026-01-01"},
            ]
            accepted, warnings = apply_exceptions(results, exc, ctx.as_of)
            res = {r.rule.id: r for r in results}
            self.assertEqual(res["EN-005"].status, "accepted")
            self.assertEqual(res["EN-012"].status, "accepted")
            self.assertEqual(res["AD-004"].status, "finding")          # expired exception not applied
            self.assertEqual({a["ruleId"] for a in accepted}, {"EN-005", "EN-012"})
            self.assertTrue(any("已過期" in w for w in warnings))
            self.assertTrue(any("未比對" in w and "entra:nobody" in w for w in warnings))


class Helpers(unittest.TestCase):
    def test_overlapping_bundles_use_newest(self):
        def stamp(path, finished, scope):
            m = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
            m["finishedUtc"], m["scope"] = finished, scope
            (path / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
        dom = {"adDomainSid": "S-1-5-21-10-20-30"}
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            old = fx.write_bundle(r, "old", {"ad_users": [fx.user(1101, "a", enabled=False), fx.user(1102, "b")]})
            new = fx.write_bundle(r, "new", {"ad_users": [fx.user(1101, "a")]})
            other = fx.write_bundle(r, "other", {"ad_users": [fx.user(1201, "c")]})
            stamp(old, "2026-10-15T07:00:00.000Z", dom)
            stamp(new, "2026-10-20T07:00:00.000Z", dom)
            stamp(other, "2026-10-14T07:00:00.000Z", {"adDomainSid": "S-1-5-21-99-99-99"})
            rnd = open_round([old, new, other], r / "x")
            users = {u["sid"]: u for u in rnd.rows("ad_users")}
            self.assertEqual(len(rnd.rows("ad_users")), 2)            # old copy dropped, other domain kept
            self.assertTrue(users[fx.sid(1101)]["enabled"])
            self.assertEqual(rnd.superseded, [{"dataset": "ad_users", "bundle": "old", "usedInstead": "new"}])
            self.assertEqual([d["supersededDatasets"] for d in rnd.describe()], [["ad_users"], [], []])

    def test_parent_dn_with_escaped_comma(self):
        self.assertEqual(parent_dn(r"CN=Doe\, John,OU=Staff,DC=corp,DC=local"), "OU=Staff,DC=corp,DC=local")
        self.assertIsNone(parent_dn("DC=local"))

    def test_acl_classify(self):
        c = acl.classify
        self.assertEqual(c(fx.ace("x", "GenericAll")), ["GenericAll"])
        self.assertEqual(c(fx.ace("x", "ReadProperty, WriteProperty", "g", "member")), ["AddMember"])
        self.assertEqual(c(fx.ace("x", "WriteProperty")), ["WriteAllProperties"])
        self.assertEqual(c(fx.ace("x", "ReadProperty, WriteProperty", "g", "userCertificate")), [])
        self.assertEqual(c(fx.ace("x", "ExtendedRight", "g", "User-Change-Password")), [])
        self.assertEqual(c(fx.ace("x", "ExtendedRight", "g", "User-Force-Change-Password")), ["ForceChangePassword"])
        self.assertEqual(c(fx.ace("x", "ReadProperty, ExtendedRight", "g", "ms-Mcs-AdmPwd")), ["ReadLAPSPassword"])
        self.assertEqual(c({**fx.ace("x", "GenericAll"), "type": "Deny"}), [])


if __name__ == "__main__":
    unittest.main()
