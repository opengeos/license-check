"""Shared rule machinery: scope, reasons, the generic handling of unexamined members."""

import fnmatch
import re

from olc.errors import InputError
from olc.result import FINDING, INCOMPLETE, INFO, LIST_CAP, OBSERVATION, REVIEW, cap, reason
from olc.result import verdict_from_reasons


class RulesError(InputError):
    code = "invalid-rules"


GENERIC_KEYS = {"id", "type", "strength", "claim", "scope", "params", "notes"}


class Rule:
    TYPE = None
    PARAMS = {}               # name -> required?
    CLASSES = None            # artifact classes the type understands; None = all
    OBSERVATION_ONLY = False

    def __init__(self, spec, policy, limits):
        self.id = spec["id"]
        self.strength = spec["strength"]
        self.claim = spec["claim"]
        scope = spec.get("scope") or {}
        self.members = scope.get("members", ["*"])
        self.classes = scope.get("artifact_classes")
        self.policy, self.limits = policy, limits
        self.reasons, self.evidence = [], {}
        self.artifacts_examined, self.targets = 0, 0
        self.art = None
        self.art_class = None
        self.configure(spec["params"])

    # -- configuration --------------------------------------------------------------------
    def configure(self, params):
        """Validate and store type parameters. Raise RulesError."""

    # -- scope ----------------------------------------------------------------------------
    def applies(self, art_class):
        if self.classes is not None and art_class not in self.classes:
            return False
        return self.CLASSES is None or art_class in self.CLASSES

    def in_scope(self, name):
        return any(fnmatch.fnmatchcase(name, g) for g in self.members)

    def relevant(self, name):
        """Members whose absence of examination would make this rule unsure."""
        return self.in_scope(name)

    # -- visitor hooks (per artifact) -----------------------------------------------------
    def begin(self, art_name, art_class):
        self.art, self.art_class = art_name, art_class
        self.artifacts_examined += 1

    def wants_content(self, name, head):
        return False

    def streams(self, name):
        return []

    def member(self, m):
        pass

    def end(self, summary):
        complete = summary.problem is None
        if not complete:
            self.add(f"archive-{summary.problem}", INCOMPLETE,
                     detail=summary.problem_detail or "member list incomplete")
        for name, why in summary.unexamined:
            if self.relevant(name):
                self.add("unexamined-in-scope", INCOMPLETE, name, why)
        for first, second in summary.duplicates:
            if self.relevant(first) or self.relevant(second):
                self.add("duplicate-member", REVIEW, second, f"collides with {first}")
        self.finish_artifact(complete)

    def finish_artifact(self, complete):
        """Per-artifact conclusions. Absence-based conclusions need `complete`."""

    def blocked(self, art_name, code, detail=None):
        """The artifact could not be examined at all."""
        self.add(code, INCOMPLETE, detail=detail, artifact=art_name)

    # -- output ---------------------------------------------------------------------------
    def add(self, code, level, member=None, detail=None, artifact=None):
        self.reasons.append(reason(code, level, artifact or self.art, member, detail))

    def add_evidence(self, key, item):
        self.evidence.setdefault(key, []).append(item)

    def result(self):
        reasons = list(self.reasons)
        if self.targets == 0:
            reasons.append(reason("no-target", INCOMPLETE, None, None,
                                  "the rule's scope matched nothing to examine"))
        verdict = verdict_from_reasons(reasons)
        # Keep the reasons that decide the verdict ahead of info when capping.
        order = {"fail": 0, "incomplete": 1, "review": 2, INFO: 3}
        reasons.sort(key=lambda r: order[r["level"]])
        kept, dropped = cap(reasons)
        evidence = {}
        for key, value in self.evidence.items():
            if isinstance(value, list):
                value, more = cap(value, LIST_CAP)
                if more:
                    evidence[f"{key}_truncated"] = more
            evidence[key] = value
        return {"rule": self.id, "type": self.TYPE, "strength": self.strength,
                "claim": self.claim, "verdict": verdict, "reasons": kept,
                "reasons_truncated": dropped,
                "examined": {"artifacts": self.artifacts_examined, "targets": self.targets},
                "evidence": evidence}


# -- parameter helpers -------------------------------------------------------------------

def need_list(params, key, rule_id, item=str, required=True):
    value = params.get(key)
    if value is None:
        if required:
            raise RulesError(f"rule {rule_id}: {key} is required")
        return []
    if not isinstance(value, list) or not all(isinstance(v, item) for v in value):
        raise RulesError(f"rule {rule_id}: {key} must be a list")
    return value


def compile_regex(pattern, rule_id, as_bytes=False):
    if not isinstance(pattern, str) or not pattern:
        raise RulesError(f"rule {rule_id}: a regex must be a non-empty string")
    try:
        return re.compile(pattern.encode("utf-8") if as_bytes else pattern)
    except re.error as e:
        raise RulesError(f"rule {rule_id}: bad regex {pattern!r}: {e}") from None


def validate_spec(spec, types):
    """Check the generic shape and split type parameters out. Returns a normalized spec."""
    if not isinstance(spec, dict):
        raise RulesError("each rule must be an object")
    rid = spec.get("id")
    if not isinstance(rid, str) or not rid:
        raise RulesError("each rule needs a non-empty string id")
    rtype = spec.get("type")
    if rtype not in types:
        raise RulesError(f"rule {rid}: unknown type {rtype!r}; known {sorted(types)}")
    cls = types[rtype]
    strength = spec.get("strength")
    if strength not in (FINDING, OBSERVATION):
        raise RulesError(f"rule {rid}: strength must be finding or observation")
    if cls.OBSERVATION_ONLY and strength != OBSERVATION:
        raise RulesError(f"rule {rid}: {rtype} is observation strength only")
    claim = spec.get("claim")
    if not isinstance(claim, str) or not claim.strip():
        raise RulesError(f"rule {rid}: claim must be a non-empty string")
    scope = spec.get("scope", {})
    if not isinstance(scope, dict) or set(scope) - {"members", "artifact_classes"}:
        raise RulesError(f"rule {rid}: scope takes members and artifact_classes only")
    for key in ("members", "artifact_classes"):
        if key in scope:
            v = scope[key]
            if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
                raise RulesError(f"rule {rid}: scope.{key} must be a non-empty list of strings")
    nested = spec.get("params", {})
    if not isinstance(nested, dict):
        raise RulesError(f"rule {rid}: params must be an object")
    top = {k: v for k, v in spec.items() if k not in GENERIC_KEYS}
    both = set(top) & set(nested)
    if both:
        raise RulesError(f"rule {rid}: {sorted(both)} given both top-level and in params")
    params = {**top, **nested}
    unknown = set(params) - set(cls.PARAMS)
    if unknown:
        raise RulesError(f"rule {rid}: unknown keys {sorted(unknown)} for {rtype}")
    for key, required in cls.PARAMS.items():
        if required and key not in params:
            raise RulesError(f"rule {rid}: {key} is required for {rtype}")
    return {"id": rid, "type": rtype, "strength": strength, "claim": claim, "scope": scope,
            "params": params}
