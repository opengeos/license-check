import unittest

from olc.versions import InvalidRule, InvalidVersion, is_prerelease, matches, version_key


class Pep440Tests(unittest.TestCase):
    def test_ordering(self):
        ordered = ["0.9", "1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0+local.1",
                   "1.0.post1", "1.0.1", "2.0", "1!0.1"]
        keys = [version_key(v, "pypi") for v in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))

    def test_normalized_forms(self):
        same = [("1.0", "1.0.0"), ("1.0RC1", "1.0rc1"), ("v1.0", "1.0"), ("1.0-1", "1.0.post1"),
                ("1.0.alpha1", "1.0a1"), ("1.0-dev", "1.0.dev0")]
        for a, b in same:
            self.assertEqual(version_key(a, "pypi"), version_key(b, "pypi"), (a, b))

    def test_invalid(self):
        for bad in ["", "abc", "1.0-foo", "1..0", "x" * 200]:
            with self.assertRaises(InvalidVersion):
                version_key(bad, "pypi")

    def test_prerelease(self):
        self.assertTrue(is_prerelease("1.0rc1", "pypi"))
        self.assertTrue(is_prerelease("1.0.dev2", "pypi"))
        self.assertFalse(is_prerelease("1.0.post1", "pypi"))

    def test_matches(self):
        rule = ">=0.20,<0.64.0"
        self.assertTrue(matches("0.63.1", rule, "pypi"))
        self.assertTrue(matches("0.30.0rc1", rule, "pypi"))  # pre-releases are not excluded
        self.assertFalse(matches("0.64.0", rule, "pypi"))
        self.assertFalse(matches("0.19.9", rule, "pypi"))
        self.assertTrue(matches("1.4.2", "==1.4.*", "pypi"))
        self.assertFalse(matches("1.5", "==1.4.*", "pypi"))
        self.assertTrue(matches("1.9", "~=1.4", "pypi"))
        self.assertFalse(matches("2.0", "~=1.4", "pypi"))
        self.assertFalse(matches("1.5", "!=1.5", "pypi"))
        self.assertTrue(matches("1.0+abc", "<=1.0", "pypi"))
        self.assertTrue(matches("1.0", "", "pypi") and matches("1.0", "*", "pypi"))
        for bad in ["=>1.0", ">=1.0;", "~=1", ">=1.*"]:
            with self.assertRaises(InvalidRule):
                matches("1.0", bad, "pypi")


class SemverTests(unittest.TestCase):
    def test_ordering(self):
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                   "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0"]
        keys = [version_key(v, "npm") for v in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(version_key("1.0.0+build", "npm"), version_key("1.0.0", "npm"))

    def test_invalid(self):
        for bad in ["1.0", "01.0.0", "1.0.0-", "1.0.0.0"]:
            with self.assertRaises(InvalidVersion):
                version_key(bad, "npm")

    def test_matches(self):
        self.assertTrue(matches("0.6.1", "<0.7.0", "npm"))
        self.assertTrue(matches("0.6.9", "^0.6.0", "npm"))
        self.assertFalse(matches("0.7.0", "^0.6.0", "npm"))
        self.assertTrue(matches("1.9.0", "^1.2.3", "npm"))
        self.assertFalse(matches("2.0.0-beta.1", "^1.2.3", "npm"))
        self.assertTrue(matches("1.2.9", "~1.2.3", "npm"))
        self.assertTrue(matches("1.5.0", "1.0.0 - 2.0.0", "npm"))
        self.assertTrue(matches("3.0.0", "<1.0.0 || >=3.0.0", "npm"))
        self.assertTrue(matches("1.1.0", ">= 1.0.0, < 2.0.0", "npm"))
        self.assertTrue(matches("0.7.0-rc.1", ">=0.6.0 <0.7.0-rc.2", "npm"))
        with self.assertRaises(InvalidRule):
            matches("1.0.0", "1.x", "npm")

    def test_unknown_ecosystem(self):
        with self.assertRaises(ValueError):
            version_key("1.0", "conda")


if __name__ == "__main__":
    unittest.main()
