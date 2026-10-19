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
    "AD-011": "medium", "AD-012": "medium", "AD-013": "critical", "AD-014": "medium", "AD-015": "medium",
    "AD-016": "high", "AD-017": "high", "AD-018": "high", "AD-019": "critical", "AD-020": "critical",
    "AD-021": "critical", "AD-022": "high", "AD-023": "high", "AD-024": "medium", "AD-025": "low",
    "AD-026": "high", "AD-027": "medium", "AD-028": "low", "AD-029": "low", "AD-030": "medium",
    "ADCS-001": "critical", "ADCS-002": "high", "ADCS-003": "high", "ADCS-004": "critical", "ADCS-005": "high",
    "ADCS-006": "medium", "ADCS-007": "info",
    "EN-002": "critical", "EN-003": "high", "EN-004": "critical", "EN-005": "medium", "EN-006": "high",
    "EN-007": "high", "EN-008": "medium", "EN-009": "info", "EN-010": "medium", "EN-011": "high", "EN-012": "high",
    "EN-013": "critical", "EN-014": "medium", "EN-015": "high", "EN-016": "high", "EN-017": "low", "EN-018": "high",
    "EN-019": "high", "EN-020": "medium", "EN-021": "medium", "EN-022": "info",
    "HY-001": "high", "HY-002": "medium", "HY-003": "info",
}
# rules that legitimately produce informational output in a tidy environment
INFO_IN_CLEAN = {"AD-014", "AD-021", "ADCS-007", "EN-008", "EN-009", "HY-003"}


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


class Helpers(unittest.TestCase):
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
