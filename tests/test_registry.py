"""Registry clients against hand-written response shapes (no real responses)."""

import base64
import copy
import hashlib
import unittest

from olc import net
from olc.registry import npm, pypi

SHA_A = hashlib.sha256(b"a").hexdigest()
SHA_B = hashlib.sha256(b"b").hexdigest()
INTEGRITY = base64.b64encode(hashlib.sha512(b"t").digest()).decode()


class FakeTransport(net.Transport):
    def __init__(self, routes):
        super().__init__()
        self.routes, self.calls = routes, []

    def get_json(self, url, *, accept="application/json"):
        self.validate_url(url)
        self.calls.append(url)
        if url not in self.routes:
            raise AssertionError(f"unexpected GET {url}")
        r = self.routes[url]
        if isinstance(r, Exception):
            raise r
        return copy.deepcopy(r)


def pfile(name, ptype, sha, yanked=False, host="files.pythonhosted.org"):
    return {"filename": name, "url": f"https://{host}/packages/{name}", "packagetype": ptype,
            "size": 10, "digests": {"sha256": sha, "md5": "x"}, "yanked": yanked,
            "yanked_reason": "broken" if yanked else None,
            "upload_time_iso_8601": "2026-01-02T03:04:05.000000Z"}


PYPI_PACKAGE = {
    "info": {"name": "Example_Pkg", "version": "1.0"},
    "releases": {
        "0.9": [pfile("example_pkg-0.9.tar.gz", "sdist", SHA_A, yanked=True)],
        "1.0": [pfile("example_pkg-1.0-py3-none-any.whl", "bdist_wheel", SHA_A),
                pfile("example_pkg-1.0.tar.gz", "sdist", SHA_B)],
        "1.1rc1": [pfile("example_pkg-1.1rc1.tar.gz", "sdist", SHA_B)],
        "1.0.1": [pfile("example_pkg-1.0.1.tar.gz", "sdist", SHA_B, yanked=True)],
        "not a version": [],
    },
}
PYPI_VERSION = {"info": {"yanked": False, "yanked_reason": None},
                "urls": [pfile("example_pkg-1.0-py3-none-any.whl", "bdist_wheel", SHA_A),
                         pfile("example_pkg-1.0.tar.gz", "sdist", "not-hex"),
                         pfile("example_pkg-1.0-py3.egg", "bdist_egg", SHA_B, host="evil.example")]}


class PyPITests(unittest.TestCase):
    BASE = "https://pypi.org/pypi/example-pkg"

    def test_all_versions_from_releases(self):
        t = FakeTransport({f"{self.BASE}/json": PYPI_PACKAGE})
        out = pypi.collect("Example_Pkg", transport=t)
        self.assertEqual((out["package"], out["name"]), ("example-pkg", "Example_Pkg"))
        self.assertEqual(out["current"], "1.0")  # 1.0.1 fully yanked, 1.1rc1 pre-release
        self.assertEqual(out["unparsable_versions"], ["not a version"])
        by = {v["version"]: v for v in out["versions"]}
        self.assertEqual([v["version"] for v in out["versions"]][:4], ["0.9", "1.0", "1.0.1", "1.1rc1"])
        self.assertTrue(by["0.9"]["yanked"])
        files = by["1.0"]["files"]
        self.assertEqual([f["class"] for f in files], ["wheel", "sdist"])
        self.assertEqual(files[0]["published_digest"],
                         {"alg": "sha256", "value": SHA_A, "encoding": "hex", "source": "pypi-json"})
        self.assertEqual(by["1.0"]["files_source"], "pypi-json-releases")

    def test_requested_versions_use_version_json(self):
        t = FakeTransport({f"{self.BASE}/json": PYPI_PACKAGE, f"{self.BASE}/1.0/json": PYPI_VERSION,
                           f"{self.BASE}/2.0/json": net.NetError("http-404", f"{self.BASE}/2.0/json", 404)})
        out = pypi.collect("example-pkg", ["1.0", "2.0"], transport=t)
        self.assertEqual(out["missing_versions"], ["2.0"])
        (v,) = out["versions"]
        self.assertEqual(v["files_source"], "pypi-version-json")
        wheel, sdist, egg = v["files"]
        self.assertIsNone(sdist["published_digest"])  # malformed digest is absent, not trusted
        self.assertEqual((egg["class"], egg["url"], egg["url_rejected"]), ("other", None, True))

    def test_other_errors_propagate(self):
        t = FakeTransport({f"{self.BASE}/json": PYPI_PACKAGE,
                           f"{self.BASE}/1.0/json": net.NetError("rate-limited", None, 429)})
        with self.assertRaises(net.NetError):
            pypi.collect("example-pkg", ["1.0"], transport=t)

    def test_version_list_falls_back_to_simple_api(self):
        pkg = {"info": {"name": "example-pkg", "version": "2.0"}}
        t = FakeTransport({f"{self.BASE}/json": pkg,
                           "https://pypi.org/simple/example-pkg/": {"versions": ["1.0", "2.0"]}})
        out = pypi.collect("example-pkg", transport=t)
        self.assertEqual([v["version"] for v in out["versions"]], ["1.0", "2.0"])
        self.assertEqual(out["current"], "2.0")


def npm_version(v, deprecated=None, integrity=True):
    dist = {"tarball": f"https://registry.npmjs.org/@acme/example/-/example-{v}.tgz",
            "shasum": "0" * 40, "fileCount": 3, "unpackedSize": 1234}
    if integrity:
        dist["integrity"] = f"sha512-{INTEGRITY} sha1-AAAA"
    if v == "0.2.0":
        dist["attestations"] = {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x"}
    rec = {"name": "@acme/example", "version": v, "dist": dist}
    if deprecated is not None:
        rec["deprecated"] = deprecated
    return rec


PACKUMENT = {
    "name": "@acme/example",
    "dist-tags": {"latest": "0.2.0", "next": "0.3.0-beta.1"},
    "versions": {"0.1.0": npm_version("0.1.0", deprecated="use 0.2"),
                 "0.2.0": npm_version("0.2.0", deprecated=""),
                 "0.3.0-beta.1": npm_version("0.3.0-beta.1", integrity=False)},
    "time": {"created": "2026-01-01T00:00:00Z", "modified": "2026-02-01T00:00:00Z",
             "0.0.1": "2025-12-31T00:00:00Z", "0.1.0": "2026-01-01T00:00:00Z",
             "0.2.0": "2026-01-15T00:00:00Z", "0.3.0-beta.1": "2026-02-01T00:00:00Z"},
}


class NpmTests(unittest.TestCase):
    URL = "https://registry.npmjs.org/@acme%2Fexample"

    def test_packument(self):
        t = FakeTransport({self.URL: PACKUMENT})
        out = npm.collect("@acme/example", transport=t)
        self.assertEqual(t.calls, [self.URL])
        self.assertEqual(out["current"], "0.2.0")
        self.assertEqual(out["unpublished_versions"], ["0.0.1"])
        by = {v["version"]: v for v in out["versions"]}
        self.assertEqual(by["0.1.0"]["deprecated"], "use 0.2")
        self.assertIsNone(by["0.2.0"]["deprecated"])
        self.assertTrue(by["0.2.0"]["attestations"])
        self.assertFalse(by["0.1.0"]["attestations"])
        f = by["0.2.0"]["files"][0]
        self.assertEqual((f["filename"], f["class"], f["size"]), ("example-0.2.0.tgz", "npm-tarball", None))
        self.assertEqual(f["published_digest"], {"alg": "sha512", "value": INTEGRITY,
                                                 "encoding": "base64", "source": "npm-packument"})
        self.assertIsNone(by["0.3.0-beta.1"]["files"][0]["published_digest"])

    def test_requested_versions_and_missing(self):
        t = FakeTransport({self.URL: PACKUMENT})
        out = npm.collect("@acme/example", ["0.2.0", "9.9.9"], transport=t)
        self.assertEqual([v["version"] for v in out["versions"]], ["0.2.0"])
        self.assertEqual(out["missing_versions"], ["9.9.9"])

    def test_current_skips_prerelease_latest_tag(self):
        pk = copy.deepcopy(PACKUMENT)
        pk["dist-tags"]["latest"] = "0.3.0-beta.1"
        out = npm.collect("@acme/example", transport=FakeTransport({self.URL: pk}))
        self.assertEqual(out["current"], "0.2.0")


if __name__ == "__main__":
    unittest.main()
