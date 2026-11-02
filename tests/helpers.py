"""Synthetic fixture builders: fonts, wheels, sdists and npm tarballs, built in memory."""

import base64
import hashlib
import io
import json
import struct
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path


def name_table(records):
    recs, strings = [], b""
    for nid, text in records.items():
        data = text.encode("utf-16-be")
        recs.append(struct.pack(">HHHHHH", 3, 1, 0x409, nid, len(data), len(strings)))
        strings += data
    return struct.pack(">HHH", 0, len(recs), 6 + 12 * len(recs)) + b"".join(recs) + strings


def sfnt(records, version=b"\x00\x01\x00\x00", base=0):
    tables = [(b"head", b"\x00" * 54), (b"name", name_table(records))]
    num = len(tables)
    pow2 = 1 << (num.bit_length() - 1)
    header = version + struct.pack(">HHHH", num, pow2 * 16, pow2.bit_length() - 1,
                                   num * 16 - pow2 * 16)
    offset = base + 12 + 16 * num
    directory, body = b"", b""
    for tag, data in tables:
        directory += struct.pack(">4sIII", tag, 0, offset + len(body), len(data))
        body += data + b"\x00" * (-len(data) % 4)
    return header + directory + body


def ttc(faces):
    header_len = 12 + 4 * len(faces)
    out, offsets = b"", []
    for records in faces:
        offsets.append(header_len + len(out))
        out += sfnt(records, base=header_len + len(out))
    return b"ttcf" + struct.pack(">HHI", 1, 0, len(faces)) + \
        b"".join(struct.pack(">I", o) for o in offsets) + out


def woff(records, compress=True):
    table = name_table(records)
    data = zlib.compress(table) if compress else table
    offset = 44 + 20
    body = struct.pack(">4sIIII", b"name", offset, len(data), len(table), 0) + data
    header = b"wOFF" + b"\x00\x01\x00\x00" + struct.pack(">IHHIHHIIIII", 44 + len(body), 1, 0,
                                                         0, 1, 0, 0, 0, 0, 0, 0)
    return header + body


FORBIDDEN = {0: "Copyright Acme Type Foundry", 1: "Examplesans", 4: "Examplesans Regular",
             7: "Examplesans is a trademark of Acme Type Foundry"}
REPLACEMENT = {0: "Copyright Open Letters Project", 1: "Freesans", 4: "Freesans Regular"}


def metadata(name="examplepkg", version="1.0", requires=(), mv="2.1", dynamic=(),
             extra_headers=()):
    lines = [f"Metadata-Version: {mv}", f"Name: {name}", f"Version: {version}"]
    lines += [f"Dynamic: {d}" for d in dynamic]
    lines += [f"Requires-Dist: {r}" for r in requires]
    lines += list(extra_headers)
    return ("\n".join(lines) + "\n\nLong description here.\n").encode()


class Workdir:
    """A fresh temp directory for one test, holding archives and the artifacts list."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)

    def cleanup(self):
        self._tmp.cleanup()

    def zip(self, filename, members, cls="wheel"):
        """members: {name: bytes} or list of (ZipInfo|name, bytes)."""
        path = self.path / filename
        items = members.items() if isinstance(members, dict) else members
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in items:
                zf.writestr(name, data)
        return self.artifact(path, cls)

    def tgz(self, filename, members, cls="npm-tarball"):
        """members: {name: bytes} or list of TarInfo/(name, bytes)."""
        path = self.path / filename
        items = members.items() if isinstance(members, dict) else members
        with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as tf:
            for item in items:
                if isinstance(item, tarfile.TarInfo):
                    tf.addfile(item)
                    continue
                name, data = item
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return self.artifact(path, cls)

    def artifact(self, path, cls, digest="sha256"):
        data = Path(path).read_bytes()
        if digest == "sha256":
            pd = {"alg": "sha256", "value": hashlib.sha256(data).hexdigest(), "source": "test"}
        elif digest == "sha512":
            pd = {"alg": "sha512", "value": base64.b64encode(hashlib.sha512(data).digest()).decode(),
                  "encoding": "base64", "source": "test"}
        else:
            pd = None
        return {"path": str(path), "filename": Path(path).name, "class": cls,
                "size": len(data), "published_digest": pd,
                "ecosystem": "pypi" if cls in ("wheel", "sdist") else "npm",
                "package": "examplepkg", "version": "1.0"}


def rules(*rule_list, rid="example-rules"):
    return {"schema": 1, "id": rid, "rules": list(rule_list)}


def rule(rtype, rid="r1", strength="finding", members=("*",), classes=None, **params):
    spec = {"id": rid, "type": rtype, "strength": strength, "claim": f"test claim for {rid}",
            "scope": {"members": list(members)}}
    if classes:
        spec["scope"]["artifact_classes"] = list(classes)
    spec.update(params)
    return spec


def check(result, rid="r1"):
    return next(c for c in result["checks"] if c["rule"] == rid)


def codes(chk, level=None):
    return {r["code"] for r in chk["reasons"] if level is None or r["level"] == level}


def dumps(obj):
    return json.dumps(obj)
