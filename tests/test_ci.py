"""Synthetic trust-boundary regressions for the nonexecuting CI adapter."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from olc.ci import confined, inspect_build, main, safe_summary
from olc.errors import InputError
from olc.inspect import inspect_artifacts

ROOT = Path(__file__).resolve().parent.parent


class CITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.art = self.root / "art"
        self.base = self.root / "base"
        self.head = self.root / "head"
        self.art.mkdir()
        self.rules = {"schema": 1, "id": "test", "rules": [{"id": "notice", "type": "required_text",
            "strength": "finding", "claim": "notice", "file": ["LICENSE"],
            "entries": [{"id": "notice", "text": "Synthetic notice"}]}]}
        for tree in (self.base, self.head):
            (tree / ".olc").mkdir(parents=True)
            (tree / ".olc/rules.json").write_text(json.dumps(self.rules))
            (tree / ".olc/policy.json").write_bytes((ROOT / "policy/policy.json").read_bytes())
        self.make_artifact()

    def make_artifact(self, good=True):
        path = self.art / "package.whl"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("LICENSE", "Synthetic notice" if good else "missing")
            z.writestr("setup.py", "raise RuntimeError('must never execute')")
        self.manifest = {"schema": "olc.ci-artifacts/1", "artifacts": [{"path": path.name,
            "class": "wheel", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]}
        self.write_manifest()

    def write_manifest(self):
        (self.art / "manifest.json").write_text(json.dumps(self.manifest))

    def inspect(self):
        return inspect_build(self.art, self.base, self.head, "a" * 40)

    def test_success_and_violation(self):
        self.assertEqual(self.inspect()["verdict"], "pass")
        self.make_artifact(False)
        self.assertEqual(self.inspect()["verdict"], "fail")

    def test_missing_registry_digest_stays_incomplete(self):
        out = inspect_artifacts([{"path": str(self.art / "package.whl"), "class": "wheel",
                                 "filename": "package.whl"}], self.rules)
        self.assertEqual(out["verdict"], "incomplete")

    def test_mismatch_blocks_inspection(self):
        self.manifest["artifacts"][0]["sha256"] = "0" * 64
        self.write_manifest()
        out = self.inspect()
        self.assertEqual(out["verdict"], "incomplete")
        self.assertFalse(out["target"]["artifacts"][0]["examined"])

    def test_traversal_absolute_symlink_and_empty_rejected(self):
        for path in ("../base/.olc/rules.json", "/etc/passwd", "a/../package.whl", "a\\b"):
            with self.subTest(path=path), self.assertRaises(InputError):
                confined(self.art, path)
        (self.art / "link").symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(InputError):
            confined(self.art, "link/.olc/rules.json")
        (self.art / "link").unlink()
        self.manifest["artifacts"] = []
        self.write_manifest()
        with self.assertRaises(InputError):
            self.inspect()

    def test_extra_files_and_manifest_authority_rejected(self):
        (self.art / "omitted.whl").write_bytes(b"payload")
        with self.assertRaises(InputError):
            self.inspect()
        (self.art / "omitted.whl").unlink()
        self.manifest["artifacts"][0]["published_digest"] = {"source": "registry"}
        self.write_manifest()
        with self.assertRaises(InputError):
            self.inspect()

    def test_candidate_cannot_change_rules(self):
        (self.head / ".olc/rules.json").write_text("{}")
        out = self.inspect()
        self.assertEqual(out["verdict"], "review")
        self.assertEqual(out["checks"][0]["verdict"], "pass")

    def test_summary_has_no_artifact_text(self):
        out = self.inspect()
        out["target"]["package"] = "::error::\n<script>"
        self.assertNotIn("::error", safe_summary(out))
        self.assertNotIn("<script>", safe_summary(out))

    def test_output_cannot_overwrite_input(self):
        args = ["--artifacts", str(self.art), "--baseline", str(self.base), "--candidate", str(self.head),
                "--engine-commit", "a" * 40, "--report-root", str(self.art / "report")]
        self.assertEqual(main(args), 4)
        self.assertFalse((self.art / "report").exists())
