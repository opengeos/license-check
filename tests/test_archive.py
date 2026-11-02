import io
import tarfile
import unittest
import zipfile

from olc import archive
from olc.archive import make_limits, read_archive
from olc.errors import InputError
from tests.helpers import Workdir


class Recorder(archive.Visitor):
    def __init__(self):
        self.members = []

    def wants_content(self, name, head):
        return True

    def member(self, m):
        self.members.append((m.name, m.content))


def read(path, **limits):
    rec = Recorder()
    return read_archive(path, rec, make_limits(limits)), rec


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.w = Workdir()

    def tearDown(self):
        self.w.cleanup()

    def unexamined(self, summary):
        return dict(summary.unexamined)

    def test_zip_reads_members_without_extracting(self):
        art = self.w.zip("a.whl", {"pkg/a.py": b"x = 1\n", "pkg/b.txt": b"hello"})
        s, rec = read(art["path"])
        self.assertIsNone(s.problem)
        self.assertEqual(s.members_total, 2)
        self.assertEqual(dict(rec.members)["pkg/b.txt"], b"hello")
        self.assertEqual(sorted(p.name for p in self.w.path.iterdir()), ["a.whl"])

    def test_zip_slip_and_absolute_paths_are_unexamined(self):
        art = self.w.zip("a.whl", {"../evil.py": b"x", "/abs.py": b"y", "ok/../../up": b"z",
                                   "C:/win.py": b"w"})
        s, rec = read(art["path"])
        why = self.unexamined(s)
        self.assertEqual(why["../evil.py"], "bad-path:parent-component")
        self.assertEqual(why["ok/../../up"], "bad-path:parent-component")
        self.assertEqual(why["C:/win.py"], "bad-path:drive-letter")
        self.assertEqual(why["/abs.py"], "bad-path:absolute")
        self.assertNotIn("../evil.py", dict(rec.members))

    def test_tar_slip_is_unexamined(self):
        art = self.w.tgz("a.tgz", {"package/../../etc/x": b"a", "package/ok": b"b"})
        s, rec = read(art["path"])
        self.assertEqual(self.unexamined(s)["package/../../etc/x"], "bad-path:parent-component")
        self.assertEqual([n for n, _ in rec.members], ["package/ok"])

    def test_tar_special_members_are_not_content(self):
        items = []
        for name, kind in [("package/link", tarfile.SYMTYPE), ("package/hard", tarfile.LNKTYPE),
                           ("package/dev", tarfile.CHRTYPE), ("package/fifo", tarfile.FIFOTYPE)]:
            ti = tarfile.TarInfo(name)
            ti.type = kind
            ti.linkname = "package/target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            items.append(ti)
        items.append(("package/target", b"data"))
        art = self.w.tgz("a.tgz", items)
        s, rec = read(art["path"])
        self.assertEqual(dict(s.not_content), {"package/link": "symlink", "package/hard": "hardlink",
                                               "package/dev": "device", "package/fifo": "fifo"})
        self.assertEqual([n for n, _ in rec.members], ["package/target"])

    def test_tar_sparse_member_is_unexamined(self):
        ti = tarfile.TarInfo("package/sparse.bin")
        ti.type = tarfile.GNUTYPE_SPARSE
        ti.size = 0
        art = self.w.tgz("a.tgz", [ti, ("package/ok", b"x")])
        s, _ = read(art["path"])
        self.assertEqual(self.unexamined(s), {"package/sparse.bin": "sparse"})

    def test_zip_symlink_is_not_content(self):
        path = self.w.path / "a.whl"
        with zipfile.ZipFile(path, "w") as zf:
            info = zipfile.ZipInfo("pkg/link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "target")
        s, rec = read(path)
        self.assertEqual(dict(s.not_content), {"pkg/link": "symlink"})
        self.assertEqual(rec.members, [])

    def test_encrypted_zip_member_is_unexamined(self):
        path = self.w.path / "a.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("pkg/secret.ttf", b"not really encrypted")
        data = bytearray(path.read_bytes())  # set the encryption flag in both headers
        data[6] |= 1
        data[data.rfind(b"PK\x01\x02") + 8] |= 1
        path.write_bytes(bytes(data))
        s, _ = read(path)
        self.assertEqual(self.unexamined(s), {"pkg/secret.ttf": "encrypted"})

    def test_unsupported_compression_is_unexamined(self):
        path = self.w.path / "a.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr(zipfile.ZipInfo("pkg/b.bin"), b"x" * 100, compress_type=zipfile.ZIP_BZIP2)
        s, _ = read(path)
        self.assertEqual(self.unexamined(s), {"pkg/b.bin": "compression-12"})

    def test_duplicates_after_normalization(self):
        art = self.w.zip("a.whl", [("pkg/Caf\u00e9.txt", b"1"), ("pkg/cafe\u0301.TXT", b"2")])
        s, rec = read(art["path"])
        self.assertEqual(len(s.duplicates), 1)
        self.assertEqual(len(rec.members), 2)  # both still examined

    def test_too_many_members_zip_checked_before_parsing(self):
        art = self.w.zip("a.whl", {f"f{i}": b"" for i in range(5)})
        s, _ = read(art["path"], max_members=3)
        self.assertEqual(s.problem, "member-limit")

    def test_too_many_members_tar(self):
        art = self.w.tgz("a.tgz", {f"package/f{i}": b"" for i in range(5)})
        s, _ = read(art["path"], max_members=3)
        self.assertEqual(s.problem, "member-limit")

    def test_member_over_byte_limit_is_counted_not_trusted(self):
        for builder, name in [(self.w.zip, "a.whl"), (self.w.tgz, "a.tgz")]:
            art = builder(name, {"package/big": b"a" * 5000, "package/small": b"b"})
            s, rec = read(art["path"], max_member_bytes=1000)
            self.assertEqual(self.unexamined(s), {"package/big": "too-large"}, name)
            self.assertEqual([n for n, _ in rec.members], ["package/small"])

    def test_content_cap_keeps_hash_but_drops_content(self):
        rec = Recorder()
        art = self.w.zip("a.whl", {"pkg/big": b"a" * 5000})
        captured = []
        rec.member = lambda m: captured.append(m)
        read_archive(art["path"], rec, make_limits({"content_cap": 1000}))
        self.assertIsNone(captured[0].content)
        self.assertTrue(captured[0].content_over_cap)
        self.assertEqual(captured[0].size, 5000)

    def test_total_cap(self):
        art = self.w.tgz("a.tgz", {f"package/f{i}": b"a" * 3000 for i in range(4)})
        s, _ = read(art["path"], max_total_bytes=5000)
        self.assertEqual(s.problem, "total-limit")

    def test_nested_archive_hashed_not_opened(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("x.ttf", b"font")
        art = self.w.zip("a.whl", {"pkg/data.zip": inner.getvalue(),
                                   "pkg/renamed.bin": inner.getvalue()})
        s, rec = read(art["path"], max_nested_depth=0)
        self.assertEqual(self.unexamined(s), {"pkg/data.zip": "nested-depth-limit",
                                              "pkg/renamed.bin": "nested-depth-limit"})
        self.assertEqual(rec.members, [])

    def test_empty_and_unsupported_archives(self):
        empty = self.w.zip("e.whl", {})
        s, _ = read(empty["path"])
        self.assertEqual((s.problem, s.members_total), (None, 0))
        other = self.w.path / "x.tar.bz2"
        other.write_bytes(b"BZh91AY&SY")
        s, _ = read(other)
        self.assertEqual(s.problem, "unsupported-archive")

    def test_corrupt_archives(self):
        bad = self.w.path / "bad.whl"
        bad.write_bytes(b"PK\x03\x04" + b"\x00" * 50)
        s, _ = read(bad)
        self.assertEqual(s.problem, "archive-unreadable")
        art = self.w.tgz("t.tgz", {"package/a": b"a" * 100000})
        with open(art["path"], "rb") as f:
            data = f.read()
        trunc = self.w.path / "trunc.tgz"
        trunc.write_bytes(data[: len(data) // 2])
        s, _ = read(trunc)
        self.assertEqual(s.problem, "archive-unreadable")

    def test_limits_can_only_be_lowered(self):
        with self.assertRaises(InputError):
            make_limits({"max_members": 10 ** 9})
        with self.assertRaises(InputError):
            make_limits({"nonsense": 1})
        self.assertEqual(make_limits({"max_members": 5})["max_members"], 5)


if __name__ == "__main__":
    unittest.main()
