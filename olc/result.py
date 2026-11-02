"""The `olc.result/1` contract: verdicts, reasons, aggregation and exit codes."""

import hashlib
import json

SCHEMA = "olc.result/1"

PASS, FAIL, REVIEW, INCOMPLETE = "pass", "fail", "review", "incomplete"
VERDICTS = (PASS, FAIL, REVIEW, INCOMPLETE)
INFO = "info"
LEVELS = (FAIL, REVIEW, INCOMPLETE, INFO)

FINDING, OBSERVATION = "finding", "observation"

EXIT_CODES = {PASS: 0, FAIL: 1, REVIEW: 2, INCOMPLETE: 3}
EXIT_INVALID = 4
EXIT_INTERNAL = 5

# Fail reason codes that rest on artifact content, so a control may count them.
CONTENT_FAIL_CODES = frozenset({
    "name-record-match", "digest-match", "forbidden-requirement",
    "required-requirement-missing", "entry-missing", "file-missing",
})

LIST_CAP = 1000


def aggregate(verdicts):
    """fail > incomplete > review > pass. An empty list is incomplete."""
    verdicts = list(verdicts)
    if not verdicts:
        return INCOMPLETE
    for v in (FAIL, INCOMPLETE, REVIEW):
        if v in verdicts:
            return v
    return PASS


def verdict_from_reasons(reasons):
    """A check's verdict from its reasons' levels; info reasons do not count."""
    levels = {r["level"] for r in reasons}
    for v in (FAIL, INCOMPLETE, REVIEW):
        if v in levels:
            return v
    return PASS


def exit_code(verdict):
    return EXIT_CODES[verdict]


def reason(code, level, artifact=None, member=None, detail=None):
    if level not in LEVELS:
        raise ValueError(f"unknown level {level}")
    return {"code": code, "level": level, "artifact": artifact, "member": member,
            "detail": detail}


def cap(items, limit=LIST_CAP):
    """(kept, dropped_count)."""
    items = list(items)
    return items[:limit], max(0, len(items) - limit)


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(obj):
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
