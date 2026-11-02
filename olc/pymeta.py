"""Python core metadata (METADATA / PKG-INFO) and restricted PEP 508 requirement parsing.

Only what the rules need: the requirement name (PEP 503-normalized), its own extras, and the
extras its marker selects (`extra == "x"`). Markers are parsed, not evaluated.
"""

import email.parser
import email.policy
import re

MAX_MARKER = 1000


class MetaError(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def normalize(name):
    """PEP 503 (and PEP 685 for extras)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_metadata(content):
    """A header -> [values] dict from METADATA/PKG-INFO bytes. MetaError if undecodable."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise MetaError("metadata-undecodable") from None
    msg = email.parser.Parser(policy=email.policy.compat32).parsestr(text, headersonly=True)
    if msg.defects:
        raise MetaError("metadata-malformed", type(msg.defects[0]).__name__)
    out = {}
    for key, value in msg.items():
        out.setdefault(key.lower(), []).append(str(value))
    return out


def metadata_version(meta):
    raw = (meta.get("metadata-version") or [""])[0].strip()
    m = re.fullmatch(r"(\d+)\.(\d+)", raw)
    return (int(m.group(1)), int(m.group(2))) if m else None


_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*")
_EXTRAS = re.compile(r"\[([^\]]*)\]\s*")
_MARKER_TOKEN = re.compile(
    r"\s*(?:(\()|(\))|(===|==|!=|<=|>=|~=|<|>|not\s+in\b|in\b)|(and\b|or\b)"
    r"|'([^']*)'|\"([^\"]*)\"|([A-Za-z_][A-Za-z0-9_.]*))")
MARKER_VARS = {
    "python_version", "python_full_version", "os_name", "sys_platform", "platform_release",
    "platform_system", "platform_version", "platform_machine", "platform_python_implementation",
    "implementation_name", "implementation_version", "extra", "os.name", "sys.platform",
    "platform.version", "platform.machine", "platform.python_implementation",
    "python_implementation", "dependency_groups",
}


class Requirement:
    def __init__(self, line, name, extras, marker, marker_extras, extra_complex):
        self.line = line
        self.name = normalize(name)
        self.display_name = name
        self.extras = extras              # the requirement's own [extras]
        self.marker = marker
        self.marker_extras = marker_extras  # extras this line is installed for; empty = base
        self.extra_complex = extra_complex  # 'extra' used other than `extra == "x"`

    def to_dict(self):
        return {"line": self.line, "name": self.name, "extras": sorted(self.extras),
                "for_extras": sorted(self.marker_extras), "complex_extra": self.extra_complex}


def parse_requirement(line):
    """A Requirement, or MetaError('unparsable-requirement' | 'unparsable-marker')."""
    req, _, marker = line.partition(";")
    m = _NAME.match(req)
    if not m:
        raise MetaError("unparsable-requirement", line[:200])
    name, rest = m.group(1), req[m.end():]
    extras = set()
    em = _EXTRAS.match(rest)
    if em:
        for e in em.group(1).split(","):
            e = e.strip()
            if e:
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", e):
                    raise MetaError("unparsable-requirement", line[:200])
                extras.add(normalize(e))
        rest = rest[em.end():]
    rest = rest.strip()
    if rest and not (rest.startswith("@") or rest.startswith("(")
                     or re.match(r"(===|==|!=|<=|>=|~=|<|>)", rest)):
        raise MetaError("unparsable-requirement", line[:200])
    marker = marker.strip()
    marker_extras, complex_extra = set(), False
    if marker:
        marker_extras, complex_extra = _marker_extras(marker)
    return Requirement(line, name, extras, marker or None, marker_extras, complex_extra)


def _marker_extras(marker):
    """Parse a PEP 508 marker; return (extras selected by `extra == "x"`, complex flag)."""
    if len(marker) > MAX_MARKER:
        raise MetaError("unparsable-marker", "too long")
    tokens, pos = [], 0
    while pos < len(marker):
        if not marker[pos:].strip():
            break
        m = _MARKER_TOKEN.match(marker, pos)
        if not m or m.end() == pos:
            raise MetaError("unparsable-marker", marker[:200])
        pos = m.end()
        if m.group(1):
            tokens.append(("(", None))
        elif m.group(2):
            tokens.append((")", None))
        elif m.group(3):
            tokens.append(("op", " ".join(m.group(3).split())))
        elif m.group(4):
            tokens.append(("bool", m.group(4)))
        elif m.group(5) is not None or m.group(6) is not None:
            tokens.append(("str", m.group(5) if m.group(5) is not None else m.group(6)))
        else:
            if m.group(7) not in MARKER_VARS:
                raise MetaError("unparsable-marker", f"unknown variable {m.group(7)}")
            tokens.append(("var", m.group(7)))
    extras, complex_flag = set(), [False]
    i = _parse_or(tokens, 0, extras, complex_flag, 0)
    if i != len(tokens):
        raise MetaError("unparsable-marker", marker[:200])
    # Multiple different extra literals need boolean reasoning outside this restricted
    # parser; retain the declaration but do not use it as proof for a required extra.
    return extras, complex_flag[0] or len(extras) > 1


def _parse_or(tokens, i, extras, cf, depth):
    i = _parse_and(tokens, i, extras, cf, depth)
    while i < len(tokens) and tokens[i] == ("bool", "or"):
        i = _parse_and(tokens, i + 1, extras, cf, depth)
    return i


def _parse_and(tokens, i, extras, cf, depth):
    i = _parse_atom(tokens, i, extras, cf, depth)
    while i < len(tokens) and tokens[i] == ("bool", "and"):
        i = _parse_atom(tokens, i + 1, extras, cf, depth)
    return i


def _parse_atom(tokens, i, extras, cf, depth):
    if i < len(tokens) and tokens[i][0] == "(":
        if depth > 16:
            raise MetaError("unparsable-marker", "too deep")
        i = _parse_or(tokens, i + 1, extras, cf, depth + 1)
        if i >= len(tokens) or tokens[i][0] != ")":
            raise MetaError("unparsable-marker", "unbalanced")
        return i + 1
    if i + 3 > len(tokens):
        raise MetaError("unparsable-marker", "incomplete comparison")
    left, op, right = tokens[i], tokens[i + 1], tokens[i + 2]
    if op[0] != "op" or {left[0], right[0]} not in ({"var", "str"}, {"var"}):
        raise MetaError("unparsable-marker", "bad comparison")
    if "extra" in (left[1] if left[0] == "var" else None, right[1] if right[0] == "var" else None):
        value = right[1] if left[0] == "var" else left[1]
        if op[1] == "==" and value is not None and {left[0], right[0]} == {"var", "str"}:
            extras.add(normalize(value))
        else:
            cf[0] = True
    return i + 3
