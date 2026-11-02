"""Bounded, non-extracting reader for ZIP and gzip-tar archives.

Nothing is written to disk. Each member is streamed once: hashed, its first bytes kept, its
content kept in memory only when a visitor asks for it and only up to the content cap, and its
chunks fed to any stream scanners. Declared sizes are never trusted; the reader counts the bytes
it actually reads. Hitting a limit marks the affected scope unexamined; nothing is skipped
silently.
"""

import gzip
import hashlib
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, field

from olc.errors import InputError

MiB = 1024 * 1024
DEFAULT_LIMITS = {
    "max_artifact_bytes": 300_000_000,
    "max_members": 50_000,
    "max_member_bytes": 512 * MiB,
    "max_total_bytes": 4 * 1024 * MiB,
    "content_cap": 16 * MiB,
    "max_name_records": 1_000,
    "max_ttc_fonts": 16,
    "max_font_tables": 64,
}
CHUNK = 1 * MiB
HEAD = 64
# Bytes tarfile may read outside member data (headers, long names, pax records) per member.
MAX_HEADER_BYTES = 64 * MiB

NESTED_SUFFIXES = (".zip", ".whl", ".jar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst",
                   ".egg", ".nupkg", ".7z", ".rar")
NESTED_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd",
                b"7z\xbc\xaf\x27\x1c", b"Rar!")


def make_limits(overrides=None):
    """Defaults, optionally lowered. Raising a limit is an InputError."""
    limits = dict(DEFAULT_LIMITS)
    for key, value in (overrides or {}).items():
        if key not in DEFAULT_LIMITS:
            raise InputError(f"unknown limit {key}")
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise InputError(f"limit {key} must be a positive integer")
        if value > DEFAULT_LIMITS[key]:
            raise InputError(f"limit {key} can only be lowered (default {DEFAULT_LIMITS[key]})")
        limits[key] = value
    return limits


@dataclass
class Member:
    name: str
    kind: str = "file"            # file | symlink | hardlink | device | fifo | other
    size: int = 0                 # bytes actually read
    declared_size: int | None = None
    sha256: str | None = None     # None when the member was not read to the end
    head: bytes = b""
    content: bytes | None = None  # kept only on request and within the content cap
    content_over_cap: bool = False
    unexamined: str | None = None  # why, when the member's bytes cannot be used
    streams: list = field(default_factory=list)


@dataclass
class Summary:
    format: str | None = None
    members_total: int = 0
    members_examined: int = 0
    not_content: list = field(default_factory=list)   # [(member, why)]
    unexamined: list = field(default_factory=list)    # [(member, why)]
    duplicates: list = field(default_factory=list)    # [(first, second)]
    problem: str | None = None                        # archive-level: no member list is complete
    problem_detail: str | None = None
    bytes_streamed: int = 0


class Visitor:
    """Interface the reader calls. Subclass and override what you need."""

    def wants_content(self, name, head):
        return False

    def streams(self, name):
        """Objects with .feed(bytes), fed every chunk of the member."""
        return []

    def member(self, member):
        """Called once per regular, usable member after it is fully read."""


class _Stop(Exception):
    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


def bad_path(name):
    """A reason the member path is unsafe or undecodable, or None."""
    if not name:
        return "empty"
    if "\x00" in name:
        return "nul"
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return "undecodable"
    if name.startswith(("/", "\\")):
        return "absolute"
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return "drive-letter"
    parts = name.replace("\\", "/").split("/")
    if ".." in parts:
        return "parent-component"
    return None


def is_nested_archive(name, head):
    lower = name.lower()
    if lower.endswith(NESTED_SUFFIXES) or ".tar." in lower.rsplit("/", 1)[-1]:
        return True
    return head.startswith(NESTED_MAGIC)


def sniff_format(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if magic[:2] == b"\x1f\x8b":
        return "tar.gz"
    return None


def read_archive(path, visitor, limits):
    """Stream every member of the archive at `path` through `visitor`. Returns a Summary."""
    summary = Summary(format=sniff_format(path))
    state = _State(summary, visitor, limits)
    try:
        if summary.format == "zip":
            _read_zip(path, state)
        elif summary.format == "tar.gz":
            _read_tar(path, state)
        else:
            summary.problem = "unsupported-archive"
    except _Stop as stop:
        summary.problem, summary.problem_detail = stop.code, stop.detail
    except (OSError, EOFError, zlib.error, zipfile.BadZipFile, tarfile.TarError,
            gzip.BadGzipFile, struct.error, ValueError, NotImplementedError) as e:
        summary.problem = "archive-unreadable"
        summary.problem_detail = type(e).__name__
    return summary


class _State:
    def __init__(self, summary, visitor, limits):
        self.summary, self.visitor, self.limits = summary, visitor, limits
        self.seen = {}

    def count_member(self, name):
        self.summary.members_total += 1
        if self.summary.members_total > self.limits["max_members"]:
            raise _Stop("member-limit", f"more than {self.limits['max_members']} members")
        key = unicodedata.normalize("NFC", name).casefold()
        if key in self.seen:
            self.summary.duplicates.append((self.seen[key], name))
        else:
            self.seen[key] = name

    def not_content(self, name, why):
        self.summary.not_content.append((name, why))

    def unexamined(self, member, why):
        member.unexamined = why
        self.summary.unexamined.append((member.name, why))

    def stream(self, member, read):
        """Read a member through `read(n)`, honouring every limit."""
        lim = self.limits
        digest = hashlib.sha256()
        buf, keep = None, None
        while True:
            chunk = read(CHUNK)
            if not chunk:
                break
            member.size += len(chunk)
            self.summary.bytes_streamed += len(chunk)
            if self.summary.bytes_streamed > lim["max_total_bytes"]:
                raise _Stop("total-limit", f"more than {lim['max_total_bytes']} bytes streamed")
            if member.size > lim["max_member_bytes"]:
                self.unexamined(member, "too-large")
                return False
            digest.update(chunk)
            if keep is None:
                member.head = chunk[:HEAD]
                bad = member.unexamined
                keep = not bad and self.visitor.wants_content(member.name, member.head)
                member.streams = [] if bad else list(self.visitor.streams(member.name))
                buf = bytearray() if keep else None
            for s in member.streams:
                s.feed(chunk)
            if buf is not None:
                if len(buf) + len(chunk) > lim["content_cap"]:
                    buf, member.content_over_cap = None, True
                else:
                    buf += chunk
        if keep is None:  # empty member
            bad = member.unexamined
            member.streams = [] if bad else list(self.visitor.streams(member.name))
            if not bad and self.visitor.wants_content(member.name, b""):
                buf = bytearray()
        member.sha256 = digest.hexdigest()
        member.content = bytes(buf) if buf is not None else None
        return True

    def finish(self, member):
        if member.unexamined:
            return
        if is_nested_archive(member.name, member.head):
            self.unexamined(member, "nested-archive")
            return
        self.summary.members_examined += 1
        self.visitor.member(member)


# --- ZIP ---------------------------------------------------------------------------------

def _zip_entry_count(path):
    """Entry count from the end-of-central-directory record, read before zipfile parses the
    whole directory (which it keeps in memory)."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65_557))
        tail = f.read()
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or pos + 22 > len(tail):
        return None
    count = struct.unpack_from("<H", tail, pos + 10)[0]
    loc = tail.rfind(b"PK\x06\x07", 0, pos)
    if count == 0xFFFF and loc >= 0 and loc + 20 <= len(tail):
        offset = struct.unpack_from("<Q", tail, loc + 8)[0]
        with open(path, "rb") as f:
            f.seek(offset)
            rec = f.read(56)
        if rec[:4] == b"PK\x06\x06" and len(rec) == 56:
            count = struct.unpack_from("<Q", rec, 32)[0]
    return count


def _read_zip(path, state):
    count = _zip_entry_count(path)
    if count is not None and count > state.limits["max_members"]:
        raise _Stop("member-limit", f"{count} entries declared")
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir():
                continue
            state.count_member(name)
            mode = info.external_attr >> 16
            if info.create_system == 3 and stat.S_ISLNK(mode):
                state.not_content(name, "symlink")
                continue
            member = Member(name=name, declared_size=info.file_size)
            if info.flag_bits & 0x1:
                state.unexamined(member, "encrypted")
                continue
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                state.unexamined(member, f"compression-{info.compress_type}")
                continue
            bad = bad_path(name)
            if bad:
                state.unexamined(member, f"bad-path:{bad}")
            try:
                with zf.open(info) as fh:
                    complete = state.stream(member, fh.read)
            except _Stop:
                raise
            except (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError) as e:
                if not member.unexamined:
                    state.unexamined(member, f"read-error:{type(e).__name__}")
                continue
            if complete:
                state.finish(member)


# --- gzip tar ----------------------------------------------------------------------------

class _CountingReader:
    """Decompressed bytes as tarfile sees them, counted against the total and header limits."""

    def __init__(self, raw, state):
        self.raw, self.state = raw, state
        self.in_member = False
        self.outside = 0

    def read(self, n=-1):
        if n is None or n < 0:
            n = CHUNK
        data = self.raw.read(n)
        if not self.in_member:
            self.outside += len(data)
            if self.outside > MAX_HEADER_BYTES:
                raise _Stop("oversized-header", "tar header data exceeds 64 MiB")
            self.state.summary.bytes_streamed += len(data)
            if self.state.summary.bytes_streamed > self.state.limits["max_total_bytes"]:
                raise _Stop("total-limit", "")
        return data


_TAR_KINDS = (
    ("issym", "symlink"), ("islnk", "hardlink"), ("ischr", "device"), ("isblk", "device"),
    ("isfifo", "fifo"),
)


def _read_tar(path, state):
    with open(path, "rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as gz:
        reader = _CountingReader(gz, state)
        with tarfile.open(fileobj=reader, mode="r|") as tf:
            for ti in tf:
                if ti.isdir():
                    continue
                name = ti.name
                state.count_member(name)
                kind = next((k for attr, k in _TAR_KINDS if getattr(ti, attr)()), None)
                if kind:
                    state.not_content(name, kind)
                    continue
                member = Member(name=name, declared_size=ti.size)
                if not ti.isreg():
                    state.unexamined(member, "unsupported-member-type")
                    continue
                if ti.issparse():
                    state.unexamined(member, "sparse")
                bad = bad_path(name)
                if bad:
                    state.unexamined(member, f"bad-path:{bad}")
                fh = tf.extractfile(ti)
                reader.in_member, reader.outside = True, 0
                try:
                    complete = state.stream(member, fh.read) if fh else False
                    if not complete and fh:
                        # Too large: drain through the counter so tarfile never skips
                        # unbounded data on its own.
                        while chunk := fh.read(CHUNK):
                            state.summary.bytes_streamed += len(chunk)
                            if state.summary.bytes_streamed > state.limits["max_total_bytes"]:
                                raise _Stop("total-limit", "")
                finally:
                    reader.in_member = False
                if complete:
                    state.finish(member)
