"""Restricted PEP 440 and SemVer ordering, and candidate-rule matching.

Matching is plain interval arithmetic: pre-releases are not excluded, because a published
pre-release is still a published artifact.
"""

import re


class VersionError(ValueError):
    code = "invalid-version"


class InvalidVersion(VersionError):
    code = "invalid-version"


class InvalidRule(VersionError):
    code = "invalid-rule"


# --- PEP 440 -----------------------------------------------------------------------------

_PEP440 = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""", re.VERBOSE | re.IGNORECASE)
_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
MAX_LEN = 128


def _pep440(version):
    if not isinstance(version, str) or len(version) > MAX_LEN:
        raise InvalidVersion(str(version)[:MAX_LEN])
    m = _PEP440.match(version)
    if not m:
        raise InvalidVersion(version)
    release = tuple(int(x) for x in m.group("release").split("."))
    pre = None
    if m.group("pre_l"):
        pre = (_PRE[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    post = None
    if m.group("post_n1") is not None:
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n2") or 0)
    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
    local = m.group("local")
    return int(m.group("epoch") or 0), release, pre, post, dev, local


def _pep440_key(version):
    epoch, release, pre, post, dev, local = _pep440(version)
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    if pre is None and post is None and dev is not None:
        pre_k = (-1, 0)          # 1.0.dev1 sorts before 1.0a1
    elif pre is None:
        pre_k = (3, 0)           # final release after any pre-release
    else:
        pre_k = pre
    post_k = (-1,) if post is None else (0, post)
    dev_k = (1, 0) if dev is None else (0, dev)
    local_k = () if local is None else tuple(
        (1, int(p), "") if p.isdigit() else (0, 0, p.lower()) for p in re.split(r"[-_.]", local))
    return (epoch, tuple(trimmed), pre_k, post_k, dev_k, local_k)


# --- SemVer ------------------------------------------------------------------------------

_SEMVER = re.compile(r"^\s*v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                     r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
                     r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\s*$")


def _semver(version):
    if not isinstance(version, str) or len(version) > MAX_LEN:
        raise InvalidVersion(str(version)[:MAX_LEN])
    m = _SEMVER.match(version)
    if not m:
        raise InvalidVersion(version)
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)


def _semver_key(version):
    major, minor, patch, pre = _semver(version)
    if pre is None:
        pre_k = (1,)
    else:
        pre_k = (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p)
                          for p in pre.split(".")))
    return (major, minor, patch, pre_k)


# --- public ------------------------------------------------------------------------------

def _eco(ecosystem):
    if ecosystem not in ("pypi", "npm"):
        raise VersionError(f"unsupported ecosystem {ecosystem!r}")
    return ecosystem


def version_key(version, ecosystem):
    return _pep440_key(version) if _eco(ecosystem) == "pypi" else _semver_key(version)


def is_prerelease(version, ecosystem):
    if _eco(ecosystem) == "pypi":
        _, _, pre, _, dev, _ = _pep440(version)
        return pre is not None or dev is not None
    return _semver(version)[3] is not None


def matches(version, candidate_rule, ecosystem):
    key = version_key(version, ecosystem)
    if not isinstance(candidate_rule, str):
        raise InvalidRule("candidate rule must be a string")
    rule = candidate_rule.strip()
    if rule in ("", "*"):
        return True
    if ecosystem == "pypi":
        return all(_pep440_spec(version, key, s.strip()) for s in rule.split(","))
    return any(_npm_set(key, alt.strip()) for alt in rule.split("||"))


_SPEC = re.compile(r"^(===|==|!=|<=|>=|~=|<|>)\s*(\S+)$")


def _pep440_spec(version, key, spec):
    m = _SPEC.match(spec)
    if not m:
        raise InvalidRule(spec)
    op, target = m.groups()
    if op == "===":
        return version.strip().lower() == target.lower()
    if target.endswith(".*"):
        if op not in ("==", "!="):
            raise InvalidRule(spec)
        try:
            t_epoch, t_release, *_ = _pep440(target[:-2])
        except InvalidVersion:
            raise InvalidRule(spec) from None
        epoch, release = key[0], _pep440(version)[1]
        padded = release + (0,) * max(0, len(t_release) - len(release))
        hit = epoch == t_epoch and padded[:len(t_release)] == t_release
        return hit if op == "==" else not hit
    try:
        tkey = _pep440_key(target)
    except InvalidVersion:
        raise InvalidRule(spec) from None
    if op == "~=":
        release = _pep440(target)[1]
        if len(release) < 2:
            raise InvalidRule(spec)
        prefix = ".".join(map(str, release[:-1])) + ".*"
        return key >= tkey and _pep440_spec(version, key, f"=={prefix}")
    # Ordered comparisons ignore the local label of the candidate, per PEP 440.
    if op in ("<", "<=", ">", ">=") and tkey[5] == ():
        key = key[:5] + ((),)
    return {"==": key == tkey, "!=": key != tkey, "<": key < tkey, "<=": key <= tkey,
            ">": key > tkey, ">=": key >= tkey}[op]


_NPM_CMP = re.compile(r"^(<=|>=|<|>|=|\^|~)?\s*(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")


def _npm_set(key, alt):
    if alt in ("", "*"):
        return True
    hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alt)
    if hyphen:
        return _npm_cmp(key, ">=" + hyphen.group(1)) and _npm_cmp(key, "<=" + hyphen.group(2))
    parts = re.split(r"[\s,]+", alt)
    # Allow a space between operator and version: ">= 1.0.0".
    joined, i = [], 0
    while i < len(parts):
        if parts[i] in ("<", "<=", ">", ">=", "=", "^", "~") and i + 1 < len(parts):
            joined.append(parts[i] + parts[i + 1])
            i += 2
        else:
            joined.append(parts[i])
            i += 1
    return all(_npm_cmp(key, p) for p in joined if p)


def _npm_cmp(key, comp):
    m = _NPM_CMP.match(comp)
    if not m:
        raise InvalidRule(comp)
    op, target = m.group(1) or "=", m.group(2)
    try:
        tkey = _semver_key(target)
        major, minor, patch, _ = _semver(target)
    except InvalidVersion:
        raise InvalidRule(comp) from None
    if op == "^":
        upper = (f"{major + 1}.0.0" if major else f"0.{minor + 1}.0" if minor
                 else f"0.0.{patch + 1}")
        return key >= tkey and key < _semver_key(upper + "-0")
    if op == "~":
        return key >= tkey and key < _semver_key(f"{major}.{minor + 1}.0-0")
    return {"=": key == tkey, "<": key < tkey, "<=": key <= tkey, ">": key > tkey,
            ">=": key >= tkey}[op]
