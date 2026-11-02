"""Rule types and the rules-file loader. The rules format is documented in docs/rules.md."""

from olc.rules.base import RulesError, validate_spec
from olc.rules.forbidden_asset import ForbiddenAsset
from olc.rules.license_metadata import LicenseMetadata
from olc.rules.required_text import RequiredText
from olc.rules.requires_dist import RequiresDist
from olc.rules.string_probe import StringProbe

TYPES = {cls.TYPE: cls for cls in (RequiresDist, ForbiddenAsset, RequiredText, StringProbe,
                                   LicenseMetadata)}

__all__ = ["RulesError", "TYPES", "load_rules", "build"]


def load_rules(obj):
    """Validate a rules object. Returns (id, [normalized specs])."""
    if not isinstance(obj, dict):
        raise RulesError("rules must be an object")
    unknown = set(obj) - {"schema", "id", "rules", "revision_reason", "notes"}
    if unknown:
        raise RulesError(f"unknown keys {sorted(unknown)}")
    if obj.get("schema") != 1:
        raise RulesError("rules schema must be 1")
    if not isinstance(obj.get("id"), str) or not obj["id"]:
        raise RulesError("rules id must be a non-empty string")
    if not isinstance(obj.get("rules"), list):
        raise RulesError("rules must be a list")
    specs, seen = [], set()
    for spec in obj["rules"]:
        spec = validate_spec(spec, TYPES)
        if spec["id"] in seen:
            raise RulesError(f"duplicate rule id {spec['id']}")
        seen.add(spec["id"])
        specs.append(spec)
    return obj["id"], specs


def build(spec, policy, limits):
    return TYPES[spec["type"]](spec, policy, limits)
