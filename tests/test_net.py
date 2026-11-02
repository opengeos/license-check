import io
import json
import os
import unittest
from unittest import mock

from olc import net
from tests.helpers import Workdir

ADDR = {"pypi.org": ["151.101.0.223"], "files.pythonhosted.org": ["151.101.1.63"],
        "registry.npmjs.org": ["104.16.1.35", "2606:4700::6810:123"]}


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None):
        self.status, self.body, self.headers = status, body, headers
        self._body = io.BytesIO(body)
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}

    def getheader(self, name, default=None):
        return self._headers.get(name.lower(), default)

    def read(self, n=-1):
        return self._body.read(n)


class FakeServer:
    """Routes (host, target) to a list of responses, popped in order. Anything else fails."""

    def __init__(self, routes):
        self.routes = {k: list(v) if isinstance(v, list) else [v] for k, v in routes.items()}
        self.calls = []

    def factory(self, host, address, timeout):
        server = self

        class Conn:
            def request(self, method, target, headers):
                server.calls.append({"host": host, "address": address, "method": method,
                                     "target": target, "headers": headers})
                queue = server.routes.get((host, target))
                if not queue:
                    raise AssertionError(f"unexpected request {host}{target}")
                resp = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(resp, FakeResponse):  # fresh body for each request
                    resp = FakeResponse(resp.status, resp.body, resp.headers)
                self.resp = resp

            def getresponse(self):
                if isinstance(self.resp, BaseException):
                    raise self.resp
                return self.resp

            def close(self):
                pass

        return Conn()


def transport(server, resolver=None, **kw):
    kw.setdefault("min_interval", 0)
    sleeps = []
    t = net.Transport(resolver=resolver or (lambda h: ADDR[h]), connection_factory=server.factory,
                      sleep=sleeps.append, clock=lambda: 0.0, **kw)
    return t, sleeps


def ok_json(obj):
    return FakeResponse(200, json.dumps(obj).encode())


class NetTests(unittest.TestCase):
    def assertNetError(self, code, fn, *args, **kw):
        with self.assertRaises(net.NetError) as cm:
            fn(*args, **kw)
        self.assertEqual(cm.exception.code, code)
        return cm.exception

    def test_get_json_headers_and_pinned_address(self):
        s = FakeServer({("pypi.org", "/pypi/x/json"): ok_json({"a": 1})})
        t, _ = transport(s)
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://10.0.0.1:3128",
                                          "https_proxy": "http://10.0.0.1:3128"}):
            self.assertEqual(t.get_json("https://pypi.org/pypi/x/json"), {"a": 1})
        call = s.calls[0]
        self.assertEqual((call["host"], call["address"], call["method"]),
                         ("pypi.org", "151.101.0.223", "GET"))
        self.assertEqual(call["headers"], {"User-Agent": f"opengeos-license-checks/{net.__version__}",
                                           "Accept": "application/json",
                                           "Accept-Encoding": "identity"})

    def test_default_connection_is_pinned_and_ignores_proxies(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://10.0.0.1:3128"}):
            conn = net._default_factory("pypi.org", "151.101.0.223", 5)
        self.assertEqual((conn.host, conn.port, conn._address), ("pypi.org", 443, "151.101.0.223"))
        self.assertIsNone(conn._tunnel_host)

    def test_rejected_urls(self):
        t, _ = transport(FakeServer({}))
        cases = {"https://example.com/x": "disallowed-host",
                 "http://pypi.org/x": "bad-url",
                 "https://pypi.org:8443/x": "bad-url",
                 "https://user:pw@pypi.org/x": "bad-url",
                 "https://pypi.org.evil.example/x": "disallowed-host",
                 "https://151.101.0.223/x": "disallowed-host",
                 "https://pypi.org/x y": "bad-url"}
        for url, code in cases.items():
            with self.subTest(url=url):
                self.assertNetError(code, t.get_json, url)

    def test_non_global_addresses(self):
        for addrs in (["10.0.0.5"], ["127.0.0.1"], ["169.254.1.1"], ["151.101.0.223", "::1"],
                      ["fd00::1"], ["224.0.0.1"], ["::ffff:127.0.0.1"]):
            with self.subTest(addrs=addrs):
                t, _ = transport(FakeServer({}), resolver=lambda h, a=addrs: a)
                self.assertNetError("disallowed-address", t.get_json, "https://pypi.org/x")

    def test_redirects_revalidated_and_bounded(self):
        s = FakeServer({("pypi.org", "/a"): FakeResponse(302, headers={"Location": "https://evil.example/b"})})
        t, _ = transport(s)
        self.assertNetError("disallowed-host", t.get_json, "https://pypi.org/a")
        s = FakeServer({("pypi.org", "/a"): FakeResponse(301, headers={"Location": "/a"})})
        t, _ = transport(s)
        self.assertNetError("redirect-limit", t.get_json, "https://pypi.org/a")
        self.assertEqual(len(s.calls), 4)
        s = FakeServer({("pypi.org", "/a"): FakeResponse(302, headers={
            "Location": "https://files.pythonhosted.org/b"}),
            ("files.pythonhosted.org", "/b"): ok_json([1])})
        t, _ = transport(s)
        self.assertEqual(t.get_json("https://pypi.org/a"), [1])

    def test_size_limits(self):
        s = FakeServer({("pypi.org", "/a"): FakeResponse(200, b"[]", {"Content-Length": "999999"}),
                        ("pypi.org", "/b"): FakeResponse(200, b"[" + b"1," * 600 + b"1]")})
        t, _ = transport(s, max_json_bytes=1000)
        self.assertNetError("too-large", t.get_json, "https://pypi.org/a")
        self.assertNetError("too-large", t.get_json, "https://pypi.org/b")

    def test_429_and_403_stop_the_host(self):
        s = FakeServer({("pypi.org", "/a"): FakeResponse(429),
                        ("registry.npmjs.org", "/b"): ok_json({})})
        t, _ = transport(s)
        self.assertNetError("rate-limited", t.get_json, "https://pypi.org/a")
        self.assertNetError("host-blocked", t.get_json, "https://pypi.org/a")
        self.assertEqual(len(s.calls), 1)
        self.assertEqual(t.get_json("https://registry.npmjs.org/b"), {})
        s = FakeServer({("pypi.org", "/a"): FakeResponse(403)})
        t, _ = transport(s)
        self.assertNetError("http-403", t.get_json, "https://pypi.org/a")
        self.assertNetError("host-blocked", t.get_json, "https://pypi.org/a")

    def test_retries_5xx_and_connection_errors_with_backoff(self):
        s = FakeServer({("pypi.org", "/a"): [FakeResponse(503), ConnectionResetError(), ok_json(1)]})
        t, sleeps = transport(s)
        self.assertEqual(t.get_json("https://pypi.org/a"), 1)
        self.assertEqual(sleeps, [2, 4])
        s = FakeServer({("pypi.org", "/a"): FakeResponse(502)})
        t, _ = transport(s)
        self.assertNetError("http-502", t.get_json, "https://pypi.org/a")
        self.assertEqual(len(s.calls), 3)

    def test_404_is_not_retried(self):
        s = FakeServer({("pypi.org", "/a"): FakeResponse(404)})
        t, _ = transport(s)
        self.assertNetError("http-404", t.get_json, "https://pypi.org/a")
        self.assertEqual(len(s.calls), 1)

    def test_rate_limit_per_host(self):
        s = FakeServer({("pypi.org", "/a"): ok_json(1), ("registry.npmjs.org", "/a"): ok_json(1)})
        t, sleeps = transport(s, min_interval=1.0)
        t.get_json("https://pypi.org/a")
        t.get_json("https://registry.npmjs.org/a")
        t.get_json("https://pypi.org/a")
        self.assertEqual(sleeps, [1.0])

    def test_errors_are_sanitized(self):
        s = FakeServer({("pypi.org", "/a?token=SECRETVALUE"): FakeResponse(500, b"body SECRETBODY")})
        t, _ = transport(s, retries=0)
        err = self.assertNetError("http-500", t.get_json, "https://pypi.org/a?token=SECRETVALUE")
        self.assertNotIn("SECRET", str(err))
        self.assertEqual(err.url, "https://pypi.org/a")

    def test_malformed_json(self):
        s = FakeServer({("pypi.org", "/a"): FakeResponse(200, b"{not json")})
        t, _ = transport(s)
        self.assertNetError("malformed", t.get_json, "https://pypi.org/a")

    def test_download_hashes_and_cleans_up(self):
        w = Workdir()
        try:
            body = b"artifact bytes" * 100
            s = FakeServer({("files.pythonhosted.org", "/p/a.whl"): FakeResponse(200, body),
                            ("files.pythonhosted.org", "/p/big.whl"): FakeResponse(200, body)})
            t, _ = transport(s)
            info = t.download("https://files.pythonhosted.org/p/a.whl", w.path)
            self.assertEqual(info["path"].read_bytes(), body)
            self.assertEqual(info["path"].name, info["sha256"])
            self.assertEqual(info["size"], len(body))
            again = t.download("https://files.pythonhosted.org/p/a.whl", w.path)
            self.assertEqual(again["path"], info["path"])
            self.assertNetError("too-large", t.download, "https://files.pythonhosted.org/p/big.whl",
                                w.path, max_bytes=100)
            self.assertEqual([p.name for p in w.path.iterdir()], [info["sha256"]])
        finally:
            w.cleanup()


if __name__ == "__main__":
    unittest.main()
