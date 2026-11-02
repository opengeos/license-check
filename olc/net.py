"""The only module that touches the network: a constrained HTTPS GET transport.

- HTTPS GET to an allowlist of registry hosts; no port, userinfo or other scheme.
- Each host name is resolved here, every address must be global, and the TCP connection is made
  to that vetted address with TLS verified against the host name. Nothing re-resolves the name
  between the check and the connection.
- Redirects are followed by hand and re-validated. Environment proxies, cookies, auth and
  .netrc are never consulted (http.client reads none of them).
- Bounded sizes and times, one request per second per host, retries on transient errors, and a
  host is blocked for the transport's lifetime after a 403 or 429.
- Errors are typed and never carry response bodies, query strings or header values.
"""

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import time
import urllib.parse
from pathlib import Path

from olc import __version__

DEFAULT_HOSTS = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org")
USER_AGENT = f"opengeos-license-checks/{__version__}"
REDIRECTS = (301, 302, 303, 307, 308)
CHUNK = 256 * 1024


class NetError(Exception):
    def __init__(self, code, url=None, status=None, detail=None):
        self.code, self.url, self.status = code, sanitize_url(url) if url else None, status
        msg = code + (f" {self.url}" if self.url else "") + (f" ({detail})" if detail else "")
        super().__init__(msg)


def sanitize_url(url):
    """scheme://host/path only, truncated: no userinfo, port, query or fragment."""
    try:
        p = urllib.parse.urlsplit(str(url))
        host = p.hostname or ""
        return f"{p.scheme}://{host}{p.path}"[:300]
    except ValueError:
        return "<unparsable-url>"


def quote(segment):
    """Quote one path segment (for package names, including npm `@scope/name`)."""
    return urllib.parse.quote(segment, safe="@")


def url_basename(url):
    """The last path segment of a URL, or ''."""
    try:
        return urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
    except ValueError:
        return ""


def host_of(url):
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _system_resolver(host):
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


class _PinnedConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-validated address, verifying the certificate for `host`."""

    def __init__(self, host, address, timeout, context):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _default_factory(host, address, timeout):
    return _PinnedConnection(host, address, timeout, ssl.create_default_context())


class Transport:
    def __init__(self, *, allowed_hosts=DEFAULT_HOSTS, timeout=30, min_interval=1.0, retries=2,
                 max_json_bytes=20_000_000, max_redirects=3, deadline=1800,
                 resolver=None, connection_factory=None, sleep=time.sleep,
                 clock=time.monotonic):
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.timeout, self.min_interval, self.retries = timeout, min_interval, retries
        self.max_json_bytes, self.max_redirects, self.deadline = (
            max_json_bytes, max_redirects, deadline)
        self._resolve = resolver or _system_resolver
        self._factory = connection_factory or _default_factory
        self._sleep, self._clock = sleep, clock
        self._last = {}
        self.blocked = {}

    # -- validation -----------------------------------------------------------------------
    def validate_url(self, url):
        """(host, request target) or NetError. Public so callers can vet registry URLs."""
        if not isinstance(url, str) or len(url) > 2048 or any(
                c.isspace() or ord(c) < 32 or ord(c) > 126 for c in url):
            raise NetError("bad-url", None)
        try:
            p = urllib.parse.urlsplit(url)
            port = p.port
        except ValueError:
            raise NetError("bad-url", url) from None
        if p.scheme != "https":
            raise NetError("bad-url", url, detail="https only")
        if p.username is not None or p.password is not None or "@" in p.netloc:
            raise NetError("bad-url", url, detail="userinfo")
        if port is not None:
            raise NetError("bad-url", url, detail="explicit port")
        host = (p.hostname or "").lower()
        if host not in self.allowed_hosts:
            raise NetError("disallowed-host", url)
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        return host, target

    def allowed(self, url):
        try:
            self.validate_url(url)
            return True
        except NetError:
            return False

    def _address(self, host, url):
        try:
            addresses = self._resolve(host)
        except (OSError, UnicodeError):
            raise NetError("dns", url) from None
        if not addresses:
            raise NetError("dns", url)
        for a in addresses:
            try:
                ip = ipaddress.ip_address(str(a).split("%", 1)[0])
            except ValueError:
                raise NetError("disallowed-address", url) from None
            if not ip.is_global or ip.is_multicast:
                raise NetError("disallowed-address", url, detail="non-global address")
        return str(addresses[0]).split("%", 1)[0]

    # -- requests -------------------------------------------------------------------------
    def _wait(self, host):
        last = self._last.get(host)
        if last is not None:
            gap = self.min_interval - (self._clock() - last)
            if gap > 0:
                self._sleep(gap)
        self._last[host] = self._clock()

    def _attempt(self, host, target, url, accept):
        last_error = None
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(2 ** attempt)
            if host in self.blocked:
                raise NetError("host-blocked", url, detail=self.blocked[host])
            self._wait(host)
            address = self._address(host, url)
            conn = self._factory(host, address, self.timeout)
            try:
                conn.request("GET", target, headers={
                    "User-Agent": USER_AGENT, "Accept": accept,
                    "Accept-Encoding": "identity"})
                resp = conn.getresponse()
            except (TimeoutError, socket.timeout):
                conn.close()
                last_error = NetError("timeout", url)
                continue
            except (ssl.SSLError, ssl.CertificateError):
                conn.close()
                raise NetError("tls", url) from None
            except (OSError, http.client.HTTPException):
                conn.close()
                last_error = NetError("connection", url)
                continue
            if 500 <= resp.status < 600 and attempt < self.retries:
                conn.close()
                last_error = NetError(f"http-{resp.status}", url, resp.status)
                continue
            return conn, resp
        raise last_error

    def _open(self, url, accept):
        for _ in range(self.max_redirects + 1):
            host, target = self.validate_url(url)
            conn, resp = self._attempt(host, target, url, accept)
            status = resp.status
            if status in REDIRECTS:
                location = resp.getheader("Location")
                conn.close()
                if not location:
                    raise NetError("malformed", url, status, "redirect without location")
                url = urllib.parse.urljoin(url, location)
                continue
            if 200 <= status < 300:
                return conn, resp, url
            conn.close()
            if status in (403, 429):
                self.blocked[host] = f"http-{status}"
                raise NetError("rate-limited" if status == 429 else "http-403", url, status)
            raise NetError(f"http-{status}", url, status)
        raise NetError("redirect-limit", url)

    def _stream(self, resp, url, max_bytes):
        length = resp.getheader("Content-Length")
        if length and length.isdigit() and int(length) > max_bytes:
            raise NetError("too-large", url, detail=f"declared {length} bytes")
        start, total = self._clock(), 0
        while True:
            try:
                chunk = resp.read(CHUNK)
            except (TimeoutError, socket.timeout):
                raise NetError("timeout", url) from None
            except (OSError, http.client.HTTPException):
                raise NetError("connection", url) from None
            if not chunk:
                return
            total += len(chunk)
            if total > max_bytes:
                raise NetError("too-large", url, detail=f"over {max_bytes} bytes")
            if self._clock() - start > self.deadline:
                raise NetError("timeout", url, detail="overall deadline")
            yield chunk

    def get_json(self, url, *, accept="application/json"):
        conn, resp, final = self._open(url, accept)
        try:
            body = b"".join(self._stream(resp, final, self.max_json_bytes))
        finally:
            conn.close()
        try:
            return json.loads(body)
        except (ValueError, RecursionError):
            raise NetError("malformed", final, resp.status, "invalid JSON") from None

    def download(self, url, destination_dir, *, max_bytes=300_000_000):
        dest = Path(destination_dir)
        if not dest.is_dir():
            raise NetError("bad-url", None, detail="destination is not a directory")
        conn, resp, final = self._open(url, "application/octet-stream")
        tmp = dest / f".part-{secrets.token_hex(8)}"
        h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
        try:
            with open(tmp, "xb") as out:
                for chunk in self._stream(resp, final, max_bytes):
                    out.write(chunk)
                    h256.update(chunk)
                    h512.update(chunk)
                    size += len(chunk)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        finally:
            conn.close()
        path = dest / h256.hexdigest()
        if path.exists():
            existing = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(CHUNK):
                    existing.update(chunk)
            existing = existing.hexdigest()
            tmp.unlink(missing_ok=True)
            if existing != h256.hexdigest():
                raise NetError("exists", final, detail="a different file has that name")
        else:
            os.replace(tmp, path)
        return {"path": path, "size": size, "sha256": h256.hexdigest(),
                "sha512": h512.hexdigest(),
                "sha512_b64": base64.b64encode(h512.digest()).decode("ascii"),
                "url": sanitize_url(final)}
