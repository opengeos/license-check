import copy
import json
import unittest

from olc import spdx
from olc.policy import PolicyError, default_policy_path, load_policy

POLICY = load_policy(default_policy_path())


def ev(expr):
    return spdx.evaluate(expr, POLICY)


class SpdxTests(unittest.TestCase):
    def test_and_unions_obligations(self):
        r = ev("Apache-2.0 AND BSD-3-Clause")
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(set(r["obligations"]), {"include-license-text", "include-notice-file",
                                                 "state-changes", "include-copyright-notice"})

    def test_and_takes_worst_class(self):
        self.assertEqual(ev("MIT AND GPL-3.0-only")["verdict"], "deny")
        self.assertEqual(ev("MIT AND MPL-2.0")["verdict"], "review")

    def test_or_selects_best_and_keeps_only_its_obligations(self):
        r = ev("GPL-3.0-only OR MIT")
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(r["selected"], "MIT")
        self.assertNotIn("source-offer", r["obligations"])
        self.assertEqual([a["class"] for a in r["alternatives"]], ["deny", "allow"])

    def test_or_tie_goes_leftmost(self):
        self.assertEqual(ev("Apache-2.0 OR MIT")["selected"], "Apache-2.0")

    def test_precedence(self):
        r = ev("(MIT OR GPL-2.0-only) AND Apache-2.0")
        self.assertEqual(r["selected"], "MIT AND Apache-2.0")
        r = ev("MIT OR GPL-2.0-only AND Apache-2.0")  # AND binds tighter
        self.assertEqual([a["expression"] for a in r["alternatives"]],
                         ["MIT", "GPL-2.0-only AND Apache-2.0"])

    def test_only_or_later_and_plus_stay_distinct(self):
        profile = {"classes": {"GPL-2.0-or-later": "allow"}}
        raw = {"schema": 1, "id": "t", "obligations": {}, "profiles": {"p": profile}}
        p = load_policy(raw)
        self.assertEqual(spdx.evaluate("GPL-2.0-or-later", p)["verdict"], "allow")
        self.assertEqual(spdx.evaluate("GPL-2.0-only", p)["verdict"], "review")
        self.assertEqual(spdx.evaluate("GPL-2.0+", p)["verdict"], "review")
        self.assertEqual(spdx.evaluate("gpl-2.0-OR-LATER", p)["normalized"], "GPL-2.0-or-later")

    def test_with_pairs(self):
        known = ev("Apache-2.0 WITH LLVM-exception")
        self.assertEqual(known["verdict"], "allow")
        unknown = ev("MIT WITH Some-exception")
        self.assertEqual(unknown["verdict"], "review")
        self.assertEqual(unknown["reasons"][0]["code"], "unknown-with-pair")
        self.assertEqual(unknown["normalized"], "MIT WITH Some-exception")

    def test_license_ref_is_review(self):
        self.assertEqual(ev("LicenseRef-custom")["verdict"], "review")
        self.assertEqual(ev("DocumentRef-x:LicenseRef-y")["verdict"], "review")

    def test_unlisted_is_review(self):
        self.assertEqual(ev("NOASSERTION")["verdict"], "review")

    def test_bounds(self):
        self.assertIn("too-long", ev("MIT AND " * 70 + "MIT")["reasons"][0]["code"])
        terms = " AND ".join(["A"] * 65)
        self.assertEqual(ev(terms)["reasons"][0]["code"], "spdx-too-many-terms")
        deep = "(" * 17 + "MIT" + ")" * 17
        self.assertEqual(ev(deep)["reasons"][0]["code"], "spdx-too-deep")
        wide = " AND ".join(["(MIT OR ISC)"] * 6)  # 64 alternatives
        r = ev(wide)
        self.assertEqual(r["reasons"][0]["code"], "spdx-too-many-alternatives")
        self.assertEqual(r["verdict"], "review")
        self.assertEqual(r["expression"], wide)

    def test_parse_errors_are_review(self):
        for bad in ["", "MIT AND", "(MIT", "MIT)", "MIT ISC", "MIT WITH", "MIT/ISC", "AND MIT"]:
            with self.subTest(bad=bad):
                r = ev(bad)
                self.assertEqual(r["verdict"], "review")
                self.assertIsNone(r["normalized"])

    def test_deny_list(self):
        for i in ["AGPL-3.0-only", "SSPL-1.0", "BUSL-1.1", "CC-BY-NC-4.0", "GPL-3.0-or-later"]:
            self.assertEqual(ev(i)["verdict"], "deny", i)


class PolicyTests(unittest.TestCase):
    def test_bundled_policy_loads_and_hashes(self):
        self.assertEqual(POLICY.id, "opengeos/1")
        self.assertEqual(len(POLICY.sha256), 64)

    def test_rejects_bad_policy(self):
        raw = json.loads(default_policy_path().read_text())
        for mutate in [lambda r: r.update(schema=2),
                       lambda r: r["obligations"].update(MIT=["be-nice"]),
                       lambda r: r["profiles"]["permissive-package"]["classes"].update(X="maybe"),
                       lambda r: r.update(extra=1)]:
            bad = copy.deepcopy(raw)
            mutate(bad)
            with self.assertRaises(PolicyError):
                load_policy(bad)


if __name__ == "__main__":
    unittest.main()


class InstalledPolicyTests(unittest.TestCase):
    def test_installed_policy_uses_environment_data_directory(self):
        from unittest.mock import patch
        from olc.policy import default_policy_path
        with patch("olc.policy.Path.is_file", return_value=False), patch("olc.policy.sys.prefix", "/isolated-env"):
            self.assertEqual(str(default_policy_path()), "/isolated-env/share/opengeos-license-checks/policy.json")
