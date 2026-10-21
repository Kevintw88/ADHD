"""Detection engineering tests: the Sigma subset (YAML, matching, conditions, correlations), the shipped
rules against their replay cases, environment tuning, context enrichment and the CLI."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures as fx  # noqa: E402
from adhd import detect  # noqa: E402
from adhd.bundle import open_round  # noqa: E402
from adhd.load import build_context  # noqa: E402
from adhd.sigma import (Correlation, Rule, SigmaError, YamlError, flatten, load_all, load_rules,  # noqa: E402
                        load_subset)


def rule(detection: dict, **extra) -> Rule:
    doc = {"title": "t", "id": "r1", "logsource": {"product": "windows", "service": "security"}, "detection": detection}
    doc.update(extra)
    return Rule(doc)


class Yaml(unittest.TestCase):
    def test_shipped_rules_parse_like_pyyaml(self):
        files = detect.rule_files()
        self.assertGreater(len(files), 5)
        try:
            import yaml
        except ImportError:
            yaml = None
        for f in files:
            text = f.read_text(encoding="utf-8")
            mine = load_subset(text)
            self.assertTrue(mine and all(isinstance(d, dict) for d in mine), f.name)
            if yaml is not None:
                norm = lambda x: json.loads(json.dumps(x, default=str))   # PyYAML turns dates into date objects
                self.assertEqual(norm(mine), norm([d for d in yaml.safe_load_all(text) if d is not None]), f.name)

    def test_subset_features(self):
        text = ("a: 'it''s # not a comment'  # comment\nb: \"x \\\"y\\\"\"\nc: [1, 'two', three]\nd: |\n  l1\n  l2\n"
                "e:\n  - - x\n    - y\n  - k: v\n    k2: 0x17\nf:\ng: -3\n---\nsecond: true\n")
        docs = load_subset(text)
        self.assertEqual(docs[0]["a"], "it's # not a comment")
        self.assertEqual(docs[0]["b"], 'x "y"')
        self.assertEqual(docs[0]["c"], [1, "two", "three"])
        self.assertEqual(docs[0]["d"], "l1\nl2\n")
        self.assertEqual(docs[0]["e"], [["x", "y"], {"k": "v", "k2": 23}])
        self.assertIsNone(docs[0]["f"])
        self.assertEqual(docs[0]["g"], -3)
        self.assertEqual(docs[1], {"second": True})
        with self.assertRaises(YamlError):
            load_subset("a: {x: 1}\n")
        with self.assertRaises(YamlError):
            load_subset("a: 1\n  b: 2\n")


class Matching(unittest.TestCase):
    def test_modifiers_and_values(self):
        ev = {"EventID": 4769, "ServiceName": "MSSQLSvc/sql01", "Ip": "10.1.2.3", "Count": "12", "Props": "a b c",
              "List": ["x", "Y"], "Empty": ""}
        cases = [
            ({"ServiceName|contains": "sql"}, True), ({"ServiceName|startswith": "mssql"}, True),
            ({"ServiceName|endswith": "$"}, False), ({"ServiceName": "mssqlsvc/*"}, True), ({"ServiceName": "MSSQLSvc/sql0?"}, True),
            ({"Props|contains|all": ["a", "c"]}, True), ({"Props|contains|all": ["a", "z"]}, False),
            ({"ServiceName|re": "^MSSQL.*01$"}, True), ({"Ip|cidr": "10.1.0.0/16"}, True), ({"Ip|cidr": "192.168.0.0/16"}, False),
            ({"Count|gte": 10}, True), ({"Count|lt": 10}, False), ({"EventID": [4768, 4769]}, True), ({"EventID": "4769"}, True),
            ({"List": "y"}, True), ({"Missing": None}, True), ({"Empty": None}, True), ({"ServiceName": None}, False),
            ({"Missing|exists": False}, True), ({"ServiceName|exists": True}, True),
            ({"ServiceName|expand": "%svc%"}, True), ({"ServiceName|expand": "%nothing%"}, False),
        ]
        for det, want in cases:
            with self.subTest(det=det):
                r = rule({"sel": det, "condition": "sel"})
                self.assertEqual(r.match(ev, {"svc": ["mssqlsvc/sql01"]}), want)

    def test_conditions(self):
        det = {"a": {"X": 1}, "b": {"Y": 2}, "f_1": {"Z": 3}, "f_2": {"W": 4}}
        ev = {"X": 1, "Y": 2, "Z": 0, "W": 4}
        for cond, want in [("a and b", True), ("a and not b", False), ("a and not 1 of f_*", False), ("a and not all of f_*", True),
                           ("(a or f_1) and b", True), ("1 of them", True), ("all of them", False), ("not (a and b)", False)]:
            with self.subTest(cond=cond):
                self.assertEqual(rule(dict(det, condition=cond)).match(ev), want)
        for bad in ("a and", "a and nope", "1 of zz*", "a ) b"):
            with self.assertRaises(SigmaError):
                rule(dict(det, condition=bad))
        # list of maps = OR, keywords
        self.assertTrue(rule({"s": [{"X": 9}, {"Y": 2}], "condition": "s"}).match(ev))
        self.assertTrue(rule({"k": ["mimikatz"], "condition": "k"}).match({"CommandLine": "run Mimikatz.exe"}))

    def test_flatten(self):
        f = flatten({"status": {"errorCode": 0}, "targetResources": [{"modifiedProperties": [{"newValue": "a"}, {"newValue": "b"}]}]})
        self.assertEqual(f["status.errorCode"], 0)
        self.assertEqual(f["targetResources.modifiedProperties.newValue"], ["a", "b"])


class Correlations(unittest.TestCase):
    def corr(self, **c):
        doc = {"title": "c", "id": "c1", "level": "high",
               "correlation": dict({"type": "event_count", "rules": ["base"], "group-by": ["U"], "timespan": "10m",
                                    "condition": {"gte": 3}}, **c)}
        return Correlation(doc)

    def series(self, minutes, **kw):
        t0 = datetime(2026, 10, 20, 1, 0, tzinfo=timezone.utc)
        return [(t0 + timedelta(minutes=m), dict({"U": "a", "S": f"s{i}"}, **kw)) for i, m in enumerate(minutes)]

    def test_event_count_windows(self):
        c = self.corr()
        self.assertEqual(len(c.evaluate(self.series([0, 1, 2]))), 1)
        self.assertEqual(len(c.evaluate(self.series([0, 20, 40]))), 0)               # spread out
        self.assertEqual(len(c.evaluate(self.series([0, 1, 2, 3, 4, 5]))), 2)         # two separate bursts of three
        self.assertEqual(len(c.evaluate(self.series([0, 1]) + self.series([2], U="b"))), 0)   # grouped by U

    def test_value_count(self):
        c = self.corr(type="value_count", condition={"gte": 3, "field": "S"})
        same = [(ts, dict(e, S="one")) for ts, e in self.series([0, 1, 2, 3])]
        self.assertEqual(len(c.evaluate(same)), 0)
        self.assertEqual(len(c.evaluate(self.series([0, 1, 2]))), 1)
        with self.assertRaises(SigmaError):
            self.corr(type="value_count", condition={"gte": 3})
        with self.assertRaises(SigmaError):
            self.corr(type="temporal")


class ShippedRules(unittest.TestCase):
    def test_replay_cases(self):
        rows = detect.selftest()
        self.assertGreaterEqual(len(rows), 20)
        bad = [r for r in rows if not r["ok"]]
        self.assertEqual(bad, [])

    def test_lint_clean(self):
        self.assertEqual(detect.lint(), [])

    def test_every_rule_has_unique_uuid_and_known_source(self):
        rules, corrs = load_rules(detect.rule_files())
        ids = [r.id for r in rules] + [c.id for c in corrs]
        self.assertEqual(len(ids), len(set(ids)))
        for r in rules:
            self.assertIn(detect.source_of(r), detect.SOURCES, r.title)


class Environment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.paths = fx.make_round(root / "b", True)
        cls.ctx = build_context(open_round(cls.paths, root / "x"))
        cls.env = detect.environment(cls.ctx)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_placeholders_from_posture(self):
        e = self.env
        self.assertIn(fx.sid(1106), e["dcsync_expected"])             # Entra Connect connector
        self.assertIn(fx.sid(1000), e["dc_accounts"])
        self.assertIn(fx.sid(512), e["tier0_groups"])
        self.assertIn(fx.sid(1101), e["tier0_accounts"])
        self.assertIn("ca-aadc.corp.local", e["tier0_hosts"])
        self.assertIn("e-ga1", e["entra_tier0_users"])
        self.assertTrue(all(v.startswith("S-1-") for k in ("tier0_groups", "tier0_accounts") for v in e[k]))

    def test_tuned_rules_have_values_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = detect.tune(self.env, Path(tmp), label="corp.local")
            text = "\n".join(f.read_text(encoding="utf-8") for f in files)
            self.assertNotIn("%dcsync_expected%", text)
            self.assertIn(fx.sid(1106), text)
            rules, corrs = load_rules(files)
            self.assertEqual(len(rules) + len(corrs), sum(len(load_all(f.read_text(encoding="utf-8"))) for f in detect.rule_files()))
            dcsync = next(r for r in rules if r.id == "414fdf36-f2c5-501b-8ccf-ed878f5554e1")
            self.assertFalse(dcsync.placeholders)
            ev = {"EventID": 4662, "AccessMask": "0x100", "Properties": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
                  "SubjectUserName": "svc-aadc", "SubjectUserSid": fx.sid(1106)}
            self.assertFalse(dcsync.match(ev))                           # connector excluded without any env at runtime
            self.assertTrue(dcsync.match(dict(ev, SubjectUserSid=fx.sid(1102), SubjectUserName="u-svc")))
            self.assertTrue(json.loads((Path(tmp) / "environment.json").read_text(encoding="utf-8"))["tier0_accounts"])

    def test_context_raises_level_and_names_entities(self):
        rules, corrs = load_rules(detect.rule_files())
        D = fx.DOM
        evs = {("windows", "security"): [detect.normalize(("windows", "security"), {
            "eventId": 4724, "timeCreated": "2026-10-15T07:40:00Z", "machineName": "dc01.corp.local",
            "data": {"SubjectUserSid": f"{D}-1201", "TargetSid": f"{D}-1101"}})]}
        hits = detect.run(rules, corrs, evs, self.env, detect.EntityContext(self.ctx))
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual((h["ruleLevel"], h["level"], h["raisedBecause"]), ("high", "critical", "涉及 Tier0"))
        ids = {e["id"]: e for e in h["entities"]}
        self.assertIn("attackPath", ids[f"{D}-1201"])                   # Helpdesk is an attack-path entry
        self.assertIn("tier0", ids[f"{D}-1101"])

    def test_cli_run_with_recorded_events(self):
        from tools_detect import main  # noqa: F401
        D = fx.DOM
        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp) / "lab.jsonl"
            ev.write_text("\n".join(json.dumps({"eventId": 4662, "timeCreated": f"2026-10-15T07:{i:02d}:00Z", "machineName": "dc01",
                                                "data": {"SubjectUserName": "u-svc", "SubjectUserSid": f"{D}-1102", "AccessMask": "0x100",
                                                         "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"}}) for i in range(2)),
                          encoding="utf-8")
            out = Path(tmp) / "out"
            rc = main(["run", *map(str, self.paths), "--events", f"windows/security={ev}", "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads((out / "detections.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "adhd.detections/1")
            self.assertEqual(sum(1 for h in doc["hits"] if h["ruleId"] == "414fdf36-f2c5-501b-8ccf-ed878f5554e1"), 2)
            cov = {c["ruleId"]: c["status"] for c in doc["coverage"]}
            self.assertEqual(cov["414fdf36-f2c5-501b-8ccf-ed878f5554e1"], "evaluated")
            self.assertEqual(cov["0f3746b1-3bc5-52ff-8836-9b6fa0944154"], "not-collected")   # no Entra sign-ins in this round
            self.assertIn("## 偵測涵蓋範圍", (out / "detections.md").read_text(encoding="utf-8"))
            tuned = Path(tmp) / "tuned"
            self.assertEqual(main(["tune", *map(str, self.paths), "--out", str(tuned)]), 0)
            self.assertTrue((tuned / "environment.json").is_file())


if __name__ == "__main__":
    unittest.main()
