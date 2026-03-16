import json
from pathlib import Path
import tempfile
import unittest


import privaxxy


class TestPrefParsing(unittest.TestCase):
    def test_parse_pref_value_bool_int_float_string(self):
        self.assertEqual(privaxxy.parse_pref_value("true"), True)
        self.assertEqual(privaxxy.parse_pref_value("false"), False)
        self.assertEqual(privaxxy.parse_pref_value("42"), 42)
        self.assertEqual(privaxxy.parse_pref_value("0x10"), 16)
        self.assertEqual(privaxxy.parse_pref_value("3.14"), 3.14)
        self.assertEqual(privaxxy.parse_pref_value('"hello"'), "hello")
        self.assertEqual(privaxxy.parse_pref_value('"a\\n\\t\\\"b"'), "a\n\t\"b")

    def test_read_prefs_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "prefs.js"
            p.write_text(
                '\n'.join(
                    [
                        'user_pref("toolkit.telemetry.enabled", true);',
                        'user_pref("browser.newtabpage.activity-stream.showSponsored", false);',
                        'not a pref line',
                    ]
                ),
                encoding="utf-8",
            )
            prefs = privaxxy.read_prefs_file(p, "prefs.js")
            self.assertIn("toolkit.telemetry.enabled", prefs)
            self.assertEqual(prefs["toolkit.telemetry.enabled"].value, True)
            self.assertEqual(prefs["toolkit.telemetry.enabled"].source, "prefs.js")


class TestChecks(unittest.TestCase):
    def test_evaluate_checks_deterministic_sort(self):
        prefs = {
            "toolkit.telemetry.enabled": privaxxy.PrefValue(True, "prefs.js"),
            "app.shield.optoutstudies.enabled": privaxxy.PrefValue(False, "user.js"),
        }
        findings = privaxxy.evaluate_checks(prefs)
        ids = [f.id for f in findings]
        self.assertEqual(ids, sorted(ids))
        # Ensure one fail and one pass among these two keys.
        by_id = {f.id: f for f in findings}
        self.assertEqual(by_id["telemetry.toolkit.enabled"].status, "fail")
        self.assertEqual(by_id["studies.shield"].status, "pass")

    def test_build_report_json_stable(self):
        with tempfile.TemporaryDirectory() as td:
            profile = Path(td)
            (profile / "prefs.js").write_text(
                'user_pref("toolkit.telemetry.enabled", true);\n', encoding="utf-8"
            )
            report = privaxxy.build_report(
                profile_dir=profile,
                profile_name=None,
                policies_path=None,
                policies={},
            )
            s1 = json.dumps(report, sort_keys=True, indent=2)
            s2 = json.dumps(report, sort_keys=True, indent=2)
            self.assertEqual(s1, s2)


if __name__ == "__main__":
    unittest.main()
