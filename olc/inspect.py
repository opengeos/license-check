"""`inspect_artifacts`: run rules over local artifact files and produce an `olc.result/1` dict.

No network access. Artifacts are read as data; nothing in them is imported, run or extracted.
"""

import base64
import hashlib
import os
from pathlib import Path

from olc import __version__, archive, result
from olc.errors import InputError
from olc.policy import load_policy
from olc.result import FINDING, INCOMPLETE, OBSERVATION
from olc.rules import build, load_rules

IDENTITY_KEYS = ("ecosystem", "package", "version")


def _guarded(rule, fn, *args, member=None, default=None):
    """Run a rule hook; a bug or unforeseen input becomes `incomplete`, never a crash."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001 - hostile content must not abort the whole run
        rule.add("rule-error", INCOMPLETE, member, type(e).__name__)
        return default


class _Fanout(archive.Visitor):
    def __init__(self, rules):
        self.rules = rules

    def wants_content(self, name, head):
        return any(_guarded(r, r.wants_content, name, head, member=name, default=True)
                   for r in self.rules)

    def streams(self, name):
        return [s for r in self.rules for s in _guarded(r, r.streams, name, member=name, default=[])]

    def member(self, member):
        for r in self.rules:
            _guarded(r, r.member, member, member=member.name)


def _check_artifact(art, i):
    if not isinstance(art, dict):
        raise InputError(f"artifact {i} is not an object")
    for key in ("path", "filename", "class"):
        if not isinstance(art.get(key), str) or not art[key]:
            raise InputError(f"artifact {i}: {key} must be a non-empty string")
    expected = art.get("expected_digest")
    if expected is not None:
        if art.get("published_digest") is not None or art.get("authority") != {"kind": "ci-artifact"}:
            raise InputError("CI digest requires explicit ci-artifact authority and no published digest")
        if not isinstance(expected, dict) or set(expected) != {"alg", "value"} \
                or expected.get("alg") != "sha256" or not isinstance(expected.get("value"), str) \
                or len(expected["value"]) != 64 \
                or any(c not in "0123456789abcdef" for c in expected["value"]):
            raise InputError("CI expected digest must be lowercase sha256 hex")
    elif art.get("authority") is not None:
        raise InputError("authority requires an expected digest")
    pd = art.get("published_digest")
    if pd is not None:
        if not isinstance(pd, dict) or pd.get("alg") not in ("sha256", "sha512") \
                or not isinstance(pd.get("value"), str) or not pd["value"]:
            raise InputError(f"artifact {i}: published_digest needs alg sha256|sha512 and value")
        if pd.get("encoding", "hex") not in ("hex", "base64"):
            raise InputError(f"artifact {i}: published_digest encoding is hex or base64")
    size = art.get("size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise InputError(f"artifact {i}: size must be a non-negative integer")


def _expected_bytes(pd):
    enc = pd.get("encoding") or ("hex" if pd["alg"] == "sha256" else "base64")
    value = pd["value"].strip()
    try:
        if enc == "hex":
            return bytes.fromhex(value)
        return base64.b64decode(value, validate=True)
    except ValueError:
        return None


def _hash_file(path, limit):
    h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
    with open(path, "rb") as f:
        while chunk := f.read(archive.CHUNK):
            size += len(chunk)
            if size > limit:
                return None
            h256.update(chunk)
            h512.update(chunk)
    return size, h256, h512


def _identity(art, limits):
    """The artifact's output record, and the problems that block or qualify examination."""
    rec = {"filename": art["filename"], "class": art["class"], "path": art["path"],
           "size": None, "declared_size": art.get("size"), "sha256": None,
           "published_digest": art.get("published_digest"),
           "expected_digest": art.get("expected_digest"), "authority": art.get("authority"),
           "digest_match": None,
           "examined": False, "problems": []}
    path = Path(art["path"])
    if not path.is_file():
        return rec, "artifact-missing", []
    try:
        hashed = _hash_file(path, limits["max_artifact_bytes"])
    except OSError as e:
        return rec, "artifact-unreadable", [type(e).__name__]
    if hashed is None:
        return rec, "artifact-too-large", [f"over {limits['max_artifact_bytes']} bytes"]
    size, h256, h512 = hashed
    rec["size"], rec["sha256"] = size, h256.hexdigest()
    pd = art.get("published_digest") or art.get("expected_digest")
    qualifiers = []
    if pd is None:
        qualifiers.append("no-published-digest")
    else:
        if pd["alg"] == "sha512":
            rec["sha512"] = h512.hexdigest()
        actual = (h256 if pd["alg"] == "sha256" else h512).digest()
        expected = _expected_bytes(pd)
        rec["digest_match"] = expected == actual
        if not rec["digest_match"]:
            return rec, "digest-mismatch", [f"{pd['alg']} differs from expected value"]
    if art.get("size") is not None and art["size"] != size:
        qualifiers.append("size-mismatch")
    return rec, None, qualifiers


def inspect_artifacts(artifacts, rules, policy=None, limits=None, *, target=None,
                      engine_rev=None):
    rules_id, specs = load_rules(rules)
    pol = load_policy(policy) if policy is not None else None
    lim = archive.make_limits(limits)
    if not isinstance(artifacts, list):
        raise InputError("artifacts must be a list")
    for i, art in enumerate(artifacts):
        _check_artifact(art, i)
    tgt = dict(target or {})
    for key in IDENTITY_KEYS:
        values = {a[key] for a in artifacts if a.get(key) is not None}
        if len(values) > 1:
            raise InputError(f"artifacts disagree on {key}: {sorted(map(str, values))}")
        if key not in tgt:
            tgt[key] = values.pop() if values else None
    checks = [build(spec, pol, lim) for spec in specs]
    engine_rev = engine_rev or {}

    coverage = {"artifacts_expected": len(artifacts), "artifacts_examined": 0,
                "members_total": 0, "members_examined": 0,
                "members_not_content": [], "unexamined": [], "lists_truncated": False}
    records = []
    for art in artifacts:
        rec, blocker, qualifiers = _identity(art, lim)
        records.append(rec)
        applicable = [c for c in checks if c.applies(art["class"])]
        rec["finding_rules"] = [c.id for c in applicable if c.strength == FINDING]
        rec["problems"] = ([blocker] if blocker else []) + qualifiers
        if blocker:
            for c in applicable:
                c.blocked(art["filename"], blocker, "; ".join(qualifiers) or None)
            continue
        for c in applicable:
            c.begin(art["filename"], art["class"])
            for q in qualifiers:
                c.add(q, INCOMPLETE)
        summary = archive.read_archive(Path(art["path"]), _Fanout(applicable), lim)
        for c in applicable:
            _guarded(c, c.end, summary)
        rec["examined"] = True
        rec["archive"] = {"format": summary.format, "problem": summary.problem,
                          "nested_archives": summary.nested_archives[:result.LIST_CAP],
                          "nested_archives_count": len(summary.nested_archives)}
        if summary.problem:
            rec["problems"].append(f"archive-{summary.problem}")
            coverage["unexamined"].append({"artifact": art["filename"], "member": "*",
                                           "why": summary.problem})
        coverage["artifacts_examined"] += 1
        coverage["members_total"] += summary.members_total
        coverage["members_examined"] += summary.members_examined
        coverage["members_not_content"] += [
            {"artifact": art["filename"], "member": n, "why": w} for n, w in summary.not_content]
        coverage["unexamined"] += [
            {"artifact": art["filename"], "member": n, "why": w} for n, w in summary.unexamined]
    for key in ("members_not_content", "unexamined"):
        coverage[f"{key}_count"] = len(coverage[key])
        coverage[key], dropped = result.cap(coverage[key])
        coverage["lists_truncated"] |= bool(dropped)

    check_results = [c.result() for c in checks]
    by_strength = {s: [c["verdict"] for c in check_results if c["strength"] == s]
                   for s in (FINDING, OBSERVATION)}
    no_input = not artifacts or not checks
    has_findings = bool(by_strength[FINDING])
    uncovered = has_findings and any(not a["finding_rules"] for a in records)

    def overall(verdicts):
        return INCOMPLETE if no_input else result.aggregate(verdicts)

    out = {
        "schema": result.SCHEMA,
        "engine": {"version": __version__, "git_rev": engine_rev.get("git"),
                   "dirty": engine_rev.get("dirty")},
        "rules": {"id": rules_id, "sha256": result.canonical_sha256(rules)},
        "policy": {"id": pol.id, "sha256": pol.sha256} if pol else None,
        "target": {**tgt, "artifacts": records},
        "coverage": coverage,
        "checks": check_results,
        "verdict": result.aggregate([overall([c["verdict"] for c in check_results]),
                                     INCOMPLETE] if uncovered else
                                    [overall([c["verdict"] for c in check_results])]),
        "finding_verdict": INCOMPLETE if uncovered else overall(by_strength[FINDING]),
        "observation_verdict": overall(by_strength[OBSERVATION]),
        "notes": [],
    }
    if uncovered:
        out["notes"].append({"code": "artifacts-uncovered-by-finding-rules",
                             "level": INCOMPLETE})
    if not artifacts:
        out["notes"].append({"code": "no-artifacts", "level": INCOMPLETE})
    if not checks:
        out["notes"].append({"code": "no-rules", "level": INCOMPLETE})
    return out


def cwd_inside(paths):
    """True when the working directory is the directory of any artifact."""
    cwd = Path(os.getcwd()).resolve()
    return any(Path(p).resolve().parent == cwd for p in paths)
