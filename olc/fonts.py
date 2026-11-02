"""Bounded reader for font name records: sfnt (TrueType/OpenType), TTC collections and WOFF1.

WOFF2 needs Brotli, which is not in the standard library, so it is reported as unsupported.
Only the `name` table is read; nothing else in the font is interpreted.
"""

import struct
import zlib

# copyright, family, full name, PostScript name, trademark, licence description,
# typographic family
NAME_IDS = (0, 1, 4, 6, 7, 13, 16)
NAME_FIELDS = {0: "copyright", 1: "family", 4: "full_name", 6: "postscript_name",
               7: "trademark", 13: "license", 16: "typographic_family"}
MAX_STRING = 65_535

SFNT_VERSIONS = (b"\x00\x01\x00\x00", b"OTTO", b"true")


class FontError(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _plausible_sfnt(head):
    """Table count and searchRange must agree, so arbitrary data starting with 00 01 00 00 is
    not mistaken for a font."""
    if len(head) < 12:
        return False
    num, search = struct.unpack_from(">HH", head, 4)
    if not 1 <= num <= 4096:
        return False
    pow2 = 1 << (num.bit_length() - 1)
    return search == pow2 * 16


def sniff(head):
    """'sfnt', 'ttc', 'woff', 'woff2' or None, from the first bytes."""
    magic = head[:4]
    if magic in SFNT_VERSIONS and _plausible_sfnt(head):
        return "sfnt"
    if magic == b"ttcf":
        return "ttc"
    if magic == b"wOFF":
        return "woff"
    if magic == b"wOF2":
        return "woff2"
    return None


def read_names(data, limits):
    """{'format', 'faces': [{field: [strings]}]} or FontError(code)."""
    fmt = sniff(data[:64])
    if fmt == "sfnt":
        return {"format": fmt, "faces": [_sfnt_names(data, 0, limits)]}
    if fmt == "ttc":
        return {"format": fmt, "faces": _ttc_names(data, limits)}
    if fmt == "woff":
        return {"format": fmt, "faces": [_woff_names(data, limits)]}
    if fmt == "woff2":
        raise FontError("woff2-unsupported", "WOFF2 needs Brotli, not in the standard library")
    raise FontError("not-a-font")


def _unpack(fmt, data, offset):
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error:
        raise FontError("font-malformed", f"truncated at {offset}") from None


def _sfnt_names(data, base, limits):
    num_tables = _unpack(">H", data, base + 4)[0]
    if num_tables > limits["max_font_tables"]:
        raise FontError("font-malformed", f"{num_tables} tables")
    for i in range(num_tables):
        tag, _, offset, length = _unpack(">4sIII", data, base + 12 + 16 * i)
        if tag == b"name":
            if offset + length > len(data):
                raise FontError("font-malformed", "name table out of bounds")
            return _parse_name_table(data[offset:offset + length], limits)
    return {}


def _ttc_names(data, limits):
    num_fonts = _unpack(">I", data, 8)[0]
    if num_fonts == 0 or num_fonts > limits["max_ttc_fonts"]:
        raise FontError("font-malformed", f"{num_fonts} fonts in collection")
    faces = []
    for i in range(num_fonts):
        offset = _unpack(">I", data, 12 + 4 * i)[0]
        if data[offset:offset + 4] not in SFNT_VERSIONS:
            raise FontError("font-malformed", f"collection member {i} is not sfnt")
        faces.append(_sfnt_names(data, offset, limits))
    return faces


def _woff_names(data, limits):
    num_tables = _unpack(">H", data, 12)[0]
    if num_tables > limits["max_font_tables"]:
        raise FontError("font-malformed", f"{num_tables} tables")
    for i in range(num_tables):
        tag, offset, comp_len, orig_len, _ = _unpack(">4sIIII", data, 44 + 20 * i)
        if tag != b"name":
            continue
        if offset + comp_len > len(data) or orig_len > MAX_STRING * 64:
            raise FontError("font-malformed", "name table out of bounds")
        raw = data[offset:offset + comp_len]
        if comp_len < orig_len:
            try:
                d = zlib.decompressobj()
                raw = d.decompress(raw, orig_len)
            except zlib.error:
                raise FontError("font-malformed", "name table does not inflate") from None
        if len(raw) != orig_len:
            raise FontError("font-malformed", "name table length mismatch")
        return _parse_name_table(raw, limits)
    return {}


def _parse_name_table(table, limits):
    _, count, string_offset = _unpack(">HHH", table, 0)
    if count > limits["max_name_records"]:
        raise FontError("font-malformed", f"{count} name records")
    out = {}
    for i in range(count):
        platform, encoding, _, name_id, length, offset = _unpack(">HHHHHH", table, 6 + 12 * i)
        if name_id not in NAME_IDS:
            continue
        start = string_offset + offset
        raw = table[start:start + length]
        if len(raw) != length:
            raise FontError("font-malformed", "name record out of bounds")
        text = _decode(platform, encoding, raw)
        if text is None:
            continue
        text = text.strip("\x00").strip()
        if not text:
            continue
        values = out.setdefault(NAME_FIELDS[name_id], [])
        if text not in values:
            values.append(text)
    return out


def _decode(platform, encoding, raw):
    if platform in (0, 3):
        if len(raw) % 2:
            return None
        return raw.decode("utf-16-be", errors="replace")
    if platform == 1 and encoding == 0:
        return raw.decode("mac_roman", errors="replace")
    return None
