import json
import subprocess
import sys
import unittest
from pathlib import Path

from olc import result
from olc.errors import InputError
from olc.inspect import inspect_artifacts
from olc.policy import default_policy_path, load_policy
from tests import helpers as H

ROOT = Path(__file__).resolve().parent.parent
POLICY = load_policy(default_policy_path())
FONT = H.rule("forbidden_asset", match=["(?i)^Examplesans$"])


class ResultTests(unittest.TestCase):
    def test_aggregation_precedence(self):
        agg = result.aggregate
        self.assertEqual(agg(["pass", "review", "incomplete", "fail"]), "fail")
        self.assertEqual(agg(["pass", "review", "incomplete"]), "incomplete")
        self.assertEqual(agg(["pass", "review"]), "review")
        self.assertEqual(agg(["pass"]), "pass")
        self.assertEqual(agg([]), "incomplete")

    def test_exit_codes(self):
        self.assertEqual([result.exit_code(v) for v in ("pass", "fail", "review", "incomplete")],
                         [0, 1, 2, 3])


class InspectTests(unittest.TestCase):
    def setUp(self):
        self.w = H.Workdir()

    def tearDown(self):
        self.w.cleanup()

    def font_wheel(self, name, family):
        return self.w.zip(name, {"pkg/f.ttf": H.sfnt(family)})

    def test_result_shape_and_digests(self):
        art = self.font_wheel("a.whl", H.REPLACEMENT)
        art["digest_match"] = False  # input claims are ignored
        r = inspect_artifacts([art], H.rules(FONT), POLICY)
        self.assertEqual(r["schema"], "olc.result/1")
        rec = r["target"]["artifacts"][0]
        self.assertEqual((rec["digest_match"], rec["examined"]), (True, True))
        self.assertEqual(rec["sha256"], art["published_digest"]["value"])
        self.assertEqual(r["target"]["package"], "examplepkg")
        self.assertEqual(r["rules"]["sha256"], result.canonical_sha256(H.rules(FONT)))
        self.assertEqual(r["policy"]["id"], "opengeos/1")
        self.assertEqual(r["coverage"]["members_examined"], 1)
        self.assertEqual(r["verdict"], "pass")

    def test_one_bad_artifact_fails_the_version(self):
        good = self.font_wheel("a.whl", H.REPLACEMENT)
        bad = self.w.tgz("a.tar.gz", {"a-1/f.ttf": H.sfnt(H.FORBIDDEN)}, cls="sdist")
        r = inspect_artifacts([good, bad], H.rules(FONT), POLICY)
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual({x["artifact"] for x in H.check(r)["reasons"] if x["level"] == "fail"},
                         {"a.tar.gz"})

    def test_missing_published_digest_is_incomplete_but_examined(self):
        art = self.font_wheel("a.whl", H.FORBIDDEN)
        art["published_digest"] = None
        r = inspect_artifacts([art], H.rules(FONT), POLICY)
        chk = H.check(r)
        self.assertIn("no-published-digest", H.codes(chk, "incomplete"))
        self.assertEqual(chk["verdict"], "fail")  # the bytes were still read
        art2 = self.font_wheel("b.whl", H.REPLACEMENT)
        art2["published_digest"] = None
        self.assertEqual(inspect_artifacts([art2], H.rules(FONT), POLICY)["verdict"], "incomplete")

    def test_digest_mismatch_is_incomplete_and_not_examined(self):
        art = self.font_wheel("a.whl", H.FORBIDDEN)
        art["published_digest"]["value"] = "0" * 64
        r = inspect_artifacts([art], H.rules(FONT), POLICY)
        self.assertEqual(r["verdict"], "incomplete")
        self.assertEqual(r["target"]["artifacts"][0]["digest_match"], False)
        self.assertFalse(r["target"]["artifacts"][0]["examined"])
        self.assertIn("digest-mismatch", H.codes(H.check(r)))

    def test_sha512_base64_digest(self):
        art = self.w.tgz("p.tgz", {"package/f.ttf": H.sfnt(H.REPLACEMENT)})
        art = self.w.artifact(art["path"], "npm-tarball", digest="sha512")
        r = inspect_artifacts([art], H.rules(FONT), POLICY)
        self.assertTrue(r["target"]["artifacts"][0]["digest_match"])
        self.assertEqual(len(r["target"]["artifacts"][0]["sha512"]), 128)
        self.assertEqual(r["verdict"], "pass")

    def test_size_mismatch_and_missing_file(self):
        art = self.font_wheel("a.whl", H.REPLACEMENT)
        art["size"] += 1
        self.assertIn("size-mismatch", H.codes(H.check(inspect_artifacts([art], H.rules(FONT)))))
        art = {**art, "path": str(self.w.path / "nope.whl")}
        self.assertIn("artifact-missing", H.codes(H.check(inspect_artifacts([art], H.rules(FONT)))))

    def test_zero_artifacts_or_rules(self):
        self.assertEqual(inspect_artifacts([], H.rules(FONT))["verdict"], "incomplete")
        art = self.font_wheel("a.whl", H.REPLACEMENT)
        r = inspect_artifacts([art], H.rules())
        self.assertEqual((r["verdict"], r["finding_verdict"]), ("incomplete", "incomplete"))

    def test_bad_input(self):
        art = self.font_wheel("a.whl", H.REPLACEMENT)
        for bad in [{**art, "class": ""}, {**art, "published_digest": {"alg": "md5", "value": "x"}},
                    {**art, "size": -1}]:
            with self.assertRaises(InputError):
                inspect_artifacts([bad], H.rules(FONT))
        with self.assertRaises(InputError):
            inspect_artifacts([art, {**art, "version": "2.0"}], H.rules(FONT))

    def test_rule_exception_becomes_incomplete(self):
        from unittest import mock
        from olc.rules.forbidden_asset import ForbiddenAsset
        art = self.font_wheel("a.whl", H.REPLACEMENT)
        with mock.patch.object(ForbiddenAsset, "member", side_effect=RecursionError):
            r = inspect_artifacts([art], H.rules(FONT), POLICY)
        self.assertEqual(r["verdict"], "incomplete")
        self.assertIn("rule-error", H.codes(H.check(r)))

    def test_cli_round_trip_and_exit_code(self):
        art = self.font_wheel("a.whl", H.FORBIDDEN)
        art["path"] = "a.whl"
        (self.w.path / "A.json").write_text(json.dumps({"artifacts": [art]}))
        (self.w.path / "R.json").write_text(json.dumps(H.rules(FONT)))
        out = self.w.path / "out.json"
        cmd = [sys.executable, "-I", str(ROOT / "bin" / "olc"), "inspect",
               "--rules", str(self.w.path / "R.json"),
               "--artifacts", str(self.w.path / "A.json"), "--out", str(out)]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(json.loads(out.read_text())["verdict"], "fail")
        proc = subprocess.run(cmd, cwd=self.w.path, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 4, proc.stderr)  # refuses to run inside the artifacts' directory


if __name__ == "__main__":
    unittest.main()
