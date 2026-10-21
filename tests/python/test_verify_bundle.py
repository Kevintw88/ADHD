"""verify_bundle: person-name fields must be pseudonymised (regression for the logs-only collection gap)."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures as fx  # noqa: E402

_spec = importlib.util.spec_from_file_location("verify_bundle", Path(__file__).resolve().parents[2] / "tools" / "verify_bundle.py")
vb = importlib.util.module_from_spec(_spec)
sys.modules["verify_bundle"] = vb
_spec.loader.exec_module(vb)


class PersonNames(unittest.TestCase):
    def bundle(self, root: Path, display: str):
        return fx.write_bundle(root, "b", {
            "entra_signins": [{"id": "s1", "userPrincipalName": "u-0123456789ab@corp.com", "userDisplayName": display,
                               "status": {"errorCode": 0}}],
            "entra_directory_audits": [{"id": "a1", "activityDisplayName": "Update user",
                                        "initiatedBy": {"user": {"displayName": "u-0123456789ab"}},
                                        "targetResources": [{"type": "User", "displayName": display},
                                                            {"type": "Group", "displayName": "Finance Team"}]}],
        })

    def test_plain_names_fail_and_are_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = vb.verify(self.bundle(Path(tmp), "John Doe"))
        self.assertEqual(len(r.errors), 2, r.errors)
        self.assertTrue(all("沒有假名化" in e for e in r.errors))
        self.assertFalse(any("John Doe" in e for e in r.errors))        # never echo the name itself

    def test_pseudonyms_and_service_names_pass(self):
        for display in ("u-0123456789ab", "On-Premises Directory Synchronization Service Account"):
            with self.subTest(display=display), tempfile.TemporaryDirectory() as tmp:
                r = vb.verify(self.bundle(Path(tmp), display))
                self.assertEqual(r.errors, [])
                self.assertTrue(any(c.startswith("entra_signins: 1 個人名欄位皆已假名化") for c in r.checks), r.checks)


if __name__ == "__main__":
    unittest.main()
