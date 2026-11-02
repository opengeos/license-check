import unittest

from olc.archive import CHUNK
from olc.inspect import inspect_artifacts
from olc.policy import default_policy_path, load_policy
from olc.rules import RulesError
from tests import helpers as H

POLICY = load_policy(default_policy_path())
FONT_RULE = dict(match=["(?i)^Examplesans$", "(?i)Acme Type"])


class Base(unittest.TestCase):
    def setUp(self):
        self.w = H.Workdir()

    def tearDown(self):
        self.w.cleanup()

    def run_rules(self, arts, *rule_list, policy=POLICY, limits=None):
        return inspect_artifacts(arts if isinstance(arts, list) else [arts], H.rules(*rule_list),
                                 policy, limits)


class RequiresDistTests(Base):
    RULE = dict(forbid=[{"name": "Bad_Dep", "extras": "*"}],
                require=[{"extra": "Geo", "name": "good-dep"}])

    def wheel(self, requires, name="w.whl"):
        return self.w.zip(name, {"examplepkg-1.0.dist-info/METADATA": H.metadata(requires=requires),
                                 "examplepkg/__init__.py": b""})

    def sdist(self, requires, mv="2.2", dynamic=(), extra=None):
        members = {"examplepkg-1.0/PKG-INFO": H.metadata(requires=requires, mv=mv, dynamic=dynamic),
                   "examplepkg-1.0/src/examplepkg.egg-info/PKG-INFO": H.metadata(requires=requires)}
        members.update(extra or {})
        return self.w.tgz("s.tar.gz", members, cls="sdist")

    def verdict(self, art, **params):
        r = self.run_rules(art, H.rule("requires_dist", **(params or self.RULE)))
        return H.check(r), r

    def test_forbidden_in_extra_fails_with_pep503_names(self):
        chk, _ = self.verdict(self.wheel(['bad.dep>=1; extra == "geo"', 'good-dep; extra == "geo"']))
        self.assertEqual(chk["verdict"], "fail")
        self.assertIn("forbidden-requirement", H.codes(chk, "fail"))

    def test_required_extra_present_passes(self):
        reqs = ['Good_Dep[x]>=2 ; extra == "geo" and python_version >= "3.10"', "numpy"]
        chk, _ = self.verdict(self.wheel(reqs))
        self.assertEqual(chk["verdict"], "pass", chk["reasons"])
        req = chk["evidence"]["metadata"][0]["requirements"][0]
        self.assertEqual((req["name"], req["for_extras"], req["extras"]), ("good-dep", ["geo"], ["x"]))

    def test_required_missing_fails(self):
        chk, _ = self.verdict(self.wheel(["good-dep"]))  # base dependency, not for the extra
        self.assertIn("required-requirement-missing", H.codes(chk, "fail"))

    def test_forbid_by_listed_extras_only(self):
        chk, _ = self.verdict(self.wheel(['bad-dep; extra == "other"']),
                              forbid=[{"name": "bad-dep", "extras": ["geo"]}])
        self.assertEqual(chk["verdict"], "pass")

    def test_unparsable_marker_is_incomplete(self):
        chk, _ = self.verdict(self.wheel(['good-dep; extra === "geo" ((']))
        self.assertEqual(chk["verdict"], "incomplete")
        self.assertIn("unparsable-marker", H.codes(chk))

    def test_self_reference_reported_not_expanded(self):
        reqs = ['good-dep; extra == "geo"', 'examplepkg[geo]; extra == "all"']
        chk, _ = self.verdict(self.wheel(reqs))
        self.assertEqual(chk["verdict"], "pass")
        self.assertIn("self-reference", H.codes(chk, "info"))

    def test_sdist_authoritative_and_nested_egg_info_is_not_a_duplicate(self):
        chk, _ = self.verdict(self.sdist(['good-dep; extra == "geo"']))
        self.assertEqual(chk["verdict"], "pass", chk["reasons"])
        self.assertEqual(chk["evidence"]["metadata"][0]["nested_metadata"],
                         ["examplepkg-1.0/src/examplepkg.egg-info/PKG-INFO"])

    def test_old_or_dynamic_sdist_is_review(self):
        for kwargs in ({"mv": "2.1"}, {"dynamic": ["Requires-Dist"]}):
            chk, _ = self.verdict(self.sdist(['good-dep; extra == "geo"'], **kwargs))
            self.assertEqual(chk["verdict"], "review", kwargs)
            self.assertIn("sdist-deps-not-authoritative", H.codes(chk))

    def test_old_sdist_declaring_forbidden_still_fails(self):
        chk, _ = self.verdict(self.sdist(['bad-dep; extra == "geo"'], mv="1.2"))
        self.assertEqual(chk["verdict"], "fail")

    def test_missing_or_ambiguous_metadata_is_incomplete(self):
        art = self.w.zip("w.whl", {"examplepkg/__init__.py": b""})
        chk, _ = self.verdict(art)
        self.assertEqual(chk["verdict"], "incomplete")
        art = self.w.zip("w2.whl", {"a-1.dist-info/METADATA": H.metadata(),
                                    "b-1.dist-info/METADATA": H.metadata()})
        chk, _ = self.verdict(art)
        self.assertIn("metadata-ambiguous", H.codes(chk, "incomplete"))

    def test_malformed_metadata_cannot_hide_forbidden_dependency(self):
        content = (b'Metadata-Version: 2.4\nName: examplepkg\nVersion: 1.0\n'
                   b'Requires-Dist: good-dep; extra == "geo"\nBROKEN HEADER\n'
                   b'Requires-Dist: bad-dep\n')
        artifact = self.w.zip("malformed.whl", {"examplepkg-1.0.dist-info/METADATA": content})
        check, _ = self.verdict(artifact)
        self.assertEqual(check["verdict"], "incomplete")
        self.assertIn("metadata-malformed", H.codes(check))

    def test_conflicting_extra_literals_need_review(self):
        check, _ = self.verdict(self.wheel(
            ['good-dep; extra == "geo" and extra == "different"']))
        self.assertEqual(check["verdict"], "review")
        self.assertNotEqual(check["verdict"], "pass")

    def test_uncovered_artifact_blocks_finding_verdict(self):
        wheel = self.wheel(['good-dep; extra == "geo"'])
        unsupported = dict(self.w.zip("other.zip", {"data": b"opaque"}), **{"class": "other"})
        result = self.run_rules([wheel, unsupported], H.rule("requires_dist", **self.RULE))
        self.assertEqual(result["finding_verdict"], "incomplete")
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(result["target"]["artifacts"][1]["finding_rules"], [])

    def test_scope_excluding_metadata_is_incomplete(self):
        result = self.run_rules(self.wheel(['good-dep; extra == "geo"']),
                                H.rule("requires_dist", members=["unrelated/*"], **self.RULE))
        self.assertEqual(result["finding_verdict"], "incomplete")

    def test_npm_class_in_scope_is_harmless(self):
        art = self.wheel(['good-dep; extra == "geo"'])
        npm = {**self.w.tgz("p.tgz", {"package/package.json": b"{}"}), "ecosystem": "pypi"}
        r = self.run_rules([art, npm], H.rule("requires_dist", classes=["wheel", "sdist", "npm-tarball"],
                                              **self.RULE))
        self.assertEqual(H.check(r)["verdict"], "pass")
        self.assertEqual(r["finding_verdict"], "incomplete")


class ForbiddenAssetTests(Base):
    def verdict(self, members, name="w.whl", **kw):
        art = self.w.zip(name, members)
        r = self.run_rules(art, H.rule("forbidden_asset", **(kw or FONT_RULE)))
        return H.check(r)

    def test_renamed_forbidden_font_still_fails(self):
        chk = self.verdict({"pkg/data/x.bin": H.sfnt(H.FORBIDDEN)})
        self.assertEqual(chk["verdict"], "fail")
        self.assertIn("name-record-match", H.codes(chk, "fail"))

    def test_replacement_font_passes_and_is_listed(self):
        chk = self.verdict({"pkg/fonts/free.ttf": H.sfnt(H.REPLACEMENT), "pkg/a.py": b""})
        self.assertEqual(chk["verdict"], "pass", chk["reasons"])
        self.assertEqual(chk["evidence"]["fonts"][0]["family"], "Freesans")

    def test_name_stripped_font_is_review(self):
        chk = self.verdict({"pkg/f.otf": H.sfnt({}, version=b"OTTO")})
        self.assertEqual(chk["verdict"], "review")
        self.assertIn("font-unidentified", H.codes(chk))

    def test_woff1_is_decoded(self):
        for compress in (True, False):
            chk = self.verdict({"pkg/f.woff": H.woff(H.FORBIDDEN, compress)})
            self.assertEqual(chk["verdict"], "fail", compress)

    def test_woff2_is_incomplete(self):
        chk = self.verdict({"pkg/f.woff2": b"wOF2" + b"\x00" * 60})
        self.assertEqual(chk["verdict"], "incomplete")
        self.assertIn("woff2-unsupported", H.codes(chk))

    def test_collection_is_read(self):
        chk = self.verdict({"pkg/f.ttc": H.ttc([H.REPLACEMENT, H.FORBIDDEN])})
        self.assertEqual(chk["verdict"], "fail")
        self.assertEqual(len(chk["evidence"]["fonts"]), 2)

    def test_name_only_match_is_review_never_fail(self):
        chk = self.verdict({"pkg/fonts/Examplesans.ttf": H.sfnt(H.REPLACEMENT)})
        self.assertEqual(chk["verdict"], "review")
        self.assertIn("name-only-match", H.codes(chk))
        chk = self.verdict({"pkg/fonts/examplesans.ttf": b"not a font at all"})
        self.assertEqual(chk["verdict"], "review")

    def test_digest_match(self):
        import hashlib
        data = b"some asset"
        chk = self.verdict({"pkg/a.dat": data}, sha256=[hashlib.sha256(data).hexdigest()])
        self.assertIn("digest-match", H.codes(chk, "fail"))

    def test_malformed_font_is_incomplete(self):
        font = H.sfnt(H.FORBIDDEN)
        chk = self.verdict({"pkg/f.ttf": font[:40]})
        self.assertEqual(chk["verdict"], "incomplete")

    def test_random_bytes_with_sfnt_magic_are_not_fonts(self):
        chk = self.verdict({"pkg/blob.bin": b"\x00\x01\x00\x00" + b"\xff" * 100})
        self.assertEqual(chk["verdict"], "pass")

    def test_nested_archive_in_scope_is_incomplete(self):
        chk = self.verdict({"pkg/fonts.zip": b"PK\x03\x04rest"})
        self.assertEqual(chk["verdict"], "incomplete")
        self.assertIn("unexamined-in-scope", H.codes(chk))

    def test_font_over_content_cap_is_incomplete(self):
        art = self.w.zip("w.whl", {"pkg/f.ttf": H.sfnt(H.REPLACEMENT) + b"\x00" * 4000})
        r = self.run_rules(art, H.rule("forbidden_asset", **FONT_RULE), limits={"content_cap": 1000})
        self.assertIn("font-too-large", H.codes(H.check(r)))

    def test_scope_members_limit_targets(self):
        art = self.w.zip("w.whl", {"pkg/f.ttf": H.sfnt(H.FORBIDDEN)})
        r = self.run_rules(art, H.rule("forbidden_asset", members=["other/*"], **FONT_RULE))
        chk = H.check(r)
        self.assertEqual(chk["verdict"], "incomplete")
        self.assertIn("no-target", H.codes(chk))


class RequiredTextTests(Base):
    RULE = dict(file=["package/LICENSE*"], expect="any",
                entries=[{"id": "grant", "text": "Permission is hereby\n granted"}])

    def verdict(self, members, **kw):
        art = self.w.tgz("p.tgz", members)
        return H.check(self.run_rules(art, H.rule("required_text", **(kw or self.RULE))))

    def test_present_with_collapsed_whitespace_and_case(self):
        chk = self.verdict({"package/License.md": b"PERMISSION   is\r\nhereby GRANTED, free"})
        self.assertEqual(chk["verdict"], "pass", chk["reasons"])

    def test_entry_missing(self):
        chk = self.verdict({"package/LICENSE": b"All rights reserved"})
        self.assertIn("entry-missing", H.codes(chk, "fail"))

    def test_file_missing(self):
        chk = self.verdict({"package/README": b"Permission is hereby granted"})
        self.assertIn("file-missing", H.codes(chk, "fail"))

    def test_more_than_one_candidate_with_expect_one(self):
        chk = self.verdict({"package/LICENSE": b"Permission is hereby granted",
                            "package/LICENSE-2": b"x"}, **{**self.RULE, "expect": "one"})
        self.assertEqual(chk["verdict"], "review")
        self.assertIn("multiple-files", H.codes(chk))

    def test_undecodable_is_incomplete(self):
        chk = self.verdict({"package/LICENSE": b"\x00\x01binary"})
        self.assertEqual(chk["verdict"], "incomplete")

    def test_utf16_and_latin1(self):
        chk = self.verdict({"package/LICENSE": "Permission is hereby granted".encode("utf-16")})
        self.assertEqual(chk["verdict"], "pass")
        chk = self.verdict({"package/LICENSE": b"\xa9 Permission is hereby granted"})
        self.assertEqual(chk["verdict"], "pass")

    def test_truncated_archive_never_claims_absence(self):
        art = self.w.tgz("p.tgz", {"package/a": bytes(range(256)) * 400,
                                   "package/LICENSE": b"Permission is hereby granted"})
        with open(art["path"], "rb") as f:
            data = f.read()
        with open(art["path"], "wb") as f:
            f.write(data[:len(data) // 3])
        art = self.w.artifact(art["path"], "npm-tarball")
        chk = H.check(self.run_rules(art, H.rule("required_text", **self.RULE)))
        self.assertEqual(chk["verdict"], "incomplete")
        self.assertNotIn("file-missing", H.codes(chk))


class StringProbeTests(Base):
    def test_absent_found_fails_as_observation(self):
        art = self.w.tgz("p.tgz", {"package/m.wasm": b"\x00asm..evalfoo-13.2.."})
        r = self.run_rules(art, H.rule("string_probe", strength="observation", members=["*.wasm"],
                                       absent=[r"evalfoo-1[2-9]\."]))
        chk = H.check(r)
        self.assertEqual((chk["verdict"], chk["strength"]), ("fail", "observation"))
        self.assertEqual(r["finding_verdict"], "incomplete")  # no finding checks at all

    def test_present_and_absent_pass(self):
        art = self.w.tgz("p.tgz", {"package/m.wasm": b"marker-ok", "package/x.js": b"evalfoo-13."})
        r = self.run_rules(art, H.rule("string_probe", strength="observation", members=["*.wasm"],
                                       present=["marker-ok"], absent=[r"evalfoo-1[2-9]\."]))
        chk = H.check(r)
        self.assertEqual(chk["verdict"], "pass")
        self.assertEqual(chk["evidence"]["members_examined"], 1)

    def test_present_not_found(self):
        art = self.w.tgz("p.tgz", {"package/m.wasm": b"nothing"})
        chk = H.check(self.run_rules(art, H.rule("string_probe", strength="observation",
                                                 present=["marker"])))
        self.assertIn("pattern-not-found", H.codes(chk, "fail"))

    def test_streams_past_content_cap_and_across_chunks(self):
        payload = b"a" * (CHUNK - 3) + b"evalfoo-14.0" + b"b" * (2 * CHUNK)
        art = self.w.tgz("p.tgz", {"package/big.wasm": payload})
        r = self.run_rules(art, H.rule("string_probe", strength="observation",
                                       absent=[r"evalfoo-1[2-9]\."]), limits={"content_cap": 1024})
        self.assertIn("pattern-found", H.codes(H.check(r), "fail"))

    def test_member_over_stream_limit_is_incomplete(self):
        art = self.w.tgz("p.tgz", {"package/big.wasm": b"x" * 5000})
        r = self.run_rules(art, H.rule("string_probe", strength="observation", members=["*.wasm"],
                                       absent=["evalfoo"]), limits={"max_member_bytes": 1000})
        self.assertEqual(H.check(r)["verdict"], "incomplete")

    def test_finding_strength_is_rejected(self):
        with self.assertRaises(RulesError):
            self.run_rules([], H.rule("string_probe", strength="finding", absent=["x"]))


class LicenseMetadataTests(Base):
    def wheel(self, headers):
        return self.w.zip("w.whl", {"examplepkg-1.0.dist-info/METADATA":
                                    H.metadata(extra_headers=headers),
                                    "examplepkg-1.0.dist-info/licenses/LICENSE": b"text"})

    def verdict(self, art, policy=POLICY):
        r = self.run_rules(art, H.rule("license_metadata", strength="observation"), policy=policy)
        return H.check(r)

    def test_expression_allowed(self):
        chk = self.verdict(self.wheel(["License-Expression: MIT"]))
        self.assertEqual(chk["verdict"], "pass")
        self.assertEqual(chk["evidence"]["declared"][0]["license_files"],
                         ["examplepkg-1.0.dist-info/licenses/LICENSE"])

    def test_denied_and_free_text(self):
        self.assertEqual(self.verdict(self.wheel(["License-Expression: AGPL-3.0-only"]))["verdict"], "fail")
        chk = self.verdict(self.wheel(["License: MIT License",
                                       "Classifier: License :: OSI Approved :: MIT License"]))
        self.assertEqual(chk["verdict"], "review")
        self.assertIn("license-not-spdx", H.codes(chk))
        self.assertIn("license-undeclared", H.codes(self.verdict(self.wheel([])), "review"))

    def test_npm_package_json(self):
        art = self.w.tgz("p.tgz", {"package/package.json": b'{"license": "MIT OR Apache-2.0"}'})
        self.assertEqual(self.verdict(art)["verdict"], "pass")
        art = self.w.tgz("q.tgz", {"package/package.json": b'{"license": {"type": "MIT"}}'})
        self.assertEqual(self.verdict(art)["verdict"], "review")

    def test_no_policy_is_review(self):
        self.assertIn("no-policy", H.codes(self.verdict(self.wheel(["License-Expression: MIT"]),
                                                        policy=None)))

    def test_observation_review_does_not_change_finding_verdict(self):
        art = self.w.zip("w.whl", {"examplepkg-1.0.dist-info/METADATA": H.metadata(),
                                   "pkg/f.ttf": H.sfnt(H.REPLACEMENT)})
        r = self.run_rules(art, H.rule("forbidden_asset", **FONT_RULE),
                           H.rule("license_metadata", rid="lm", strength="observation"))
        self.assertEqual(H.check(r, "lm")["verdict"], "review")
        self.assertEqual(r["verdict"], "review")
        self.assertEqual(r["finding_verdict"], "pass")
        self.assertEqual(r["observation_verdict"], "review")


class RuleShapeTests(Base):
    def test_params_top_level_or_nested(self):
        art = self.w.zip("w.whl", {"pkg/a": b""})
        nested = H.rule("forbidden_asset")
        nested["params"] = FONT_RULE
        r1 = self.run_rules(art, nested)
        r2 = self.run_rules(art, H.rule("forbidden_asset", **FONT_RULE))
        self.assertEqual(H.check(r1)["verdict"], H.check(r2)["verdict"])
        both = H.rule("forbidden_asset", **FONT_RULE)
        both["params"] = {"match": ["x"]}
        with self.assertRaises(RulesError):
            self.run_rules(art, both)

    def test_invalid_rules(self):
        bad = [
            H.rule("unknown_type"),
            H.rule("forbidden_asset", strength="strong", **FONT_RULE),
            H.rule("forbidden_asset", typo=1, **FONT_RULE),
            H.rule("forbidden_asset", match=["("]),
            H.rule("required_text", file="LICENSE"),
            H.rule("requires_dist"),
            {**H.rule("forbidden_asset", **FONT_RULE), "claim": ""},
        ]
        for spec in bad:
            with self.subTest(spec=spec), self.assertRaises(RulesError):
                self.run_rules([], spec)
        with self.assertRaises(RulesError):
            self.run_rules([], H.rule("license_metadata", strength="observation"),
                           H.rule("license_metadata", strength="observation"))
        with self.assertRaises(RulesError):
            inspect_artifacts([], {"schema": 2, "id": "x", "rules": []})

    def test_every_rule_without_target_is_incomplete(self):
        art = self.w.zip("w.whl", {})
        specs = [H.rule("requires_dist", rid="a", forbid=[{"name": "x"}]),
                 H.rule("forbidden_asset", rid="b", **FONT_RULE),
                 H.rule("string_probe", rid="d", strength="observation", absent=["x"]),
                 H.rule("license_metadata", rid="e", strength="observation")]
        r = self.run_rules(art, *specs)
        for spec in specs:
            self.assertEqual(H.check(r, spec["id"])["verdict"], "incomplete", spec["id"])
        rt = self.run_rules(art, H.rule("required_text", rid="c", classes=["sdist"], file=["x"]))
        self.assertIn("no-target", H.codes(H.check(rt, "c")))


if __name__ == "__main__":
    unittest.main()
