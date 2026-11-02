"""Policy loading: obligations per licence id and profiles that class ids as allow/review/deny.

A profile is an organizational rule for one context, not a compatibility solver.
"""

import json
import sys
from pathlib import Path

from olc.errors import InputError
from olc.result import canonical_sha256

OBLIGATIONS = frozenset({
    "include-license-text", "include-copyright-notice", "include-notice-file",
    "state-changes", "source-offer",
})
CLASSES = ("allow", "review", "deny")


class PolicyError(InputError):
    code = "invalid-policy"


def default_policy_path():
    checkout = Path(__file__).resolve().parent.parent / "policy" / "policy.json"
    if checkout.is_file():
        return checkout
    return Path(sys.prefix) / "share" / "opengeos-license-checks" / "policy.json"


class Profile:
    def __init__(self, name, raw):
        if not isinstance(raw, dict):
            raise PolicyError(f"profile {name}: not an object")
        unknown = set(raw) - {"description", "classes", "with_pairs"}
        if unknown:
            raise PolicyError(f"profile {name}: unknown keys {sorted(unknown)}")
        self.name = name
        self._classes = _class_map(raw.get("classes", {}), f"profile {name} classes")
        self._pairs = _class_map(raw.get("with_pairs", {}), f"profile {name} with_pairs")
        for key in self._pairs:
            if " with " not in key:
                raise PolicyError(f"profile {name}: with_pairs key must be '<id> WITH <exception>'")

    def license_class(self, ident):
        return self._classes.get(ident.lower())

    def with_pair_class(self, key):
        return self._pairs.get(" ".join(key.split()).lower())


def _class_map(raw, where):
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: not an object")
    out = {}
    for ident, cls in raw.items():
        if cls not in CLASSES:
            raise PolicyError(f"{where}: {ident} has class {cls!r}")
        key = " ".join(ident.split()).lower()
        if key in out:
            raise PolicyError(f"{where}: {ident} listed twice (ids are case-insensitive)")
        out[key] = cls
    return out


class Policy:
    def __init__(self, raw):
        if not isinstance(raw, dict):
            raise PolicyError("policy is not an object")
        if raw.get("schema") != 1:
            raise PolicyError("policy schema must be 1")
        unknown = set(raw) - {"schema", "id", "description", "obligations", "profiles",
                              "default_profile"}
        if unknown:
            raise PolicyError(f"unknown policy keys {sorted(unknown)}")
        if not isinstance(raw.get("id"), str) or not raw["id"]:
            raise PolicyError("policy id must be a non-empty string")
        self.raw = raw
        self.id = raw["id"]
        self.sha256 = canonical_sha256(raw)
        obligations = raw.get("obligations", {})
        if not isinstance(obligations, dict):
            raise PolicyError("obligations must be an object")
        self._obligations, self._canon = {}, {}
        for ident, obls in obligations.items():
            if not isinstance(obls, list) or any(o not in OBLIGATIONS for o in obls):
                raise PolicyError(f"obligations for {ident}: use {sorted(OBLIGATIONS)}")
            key = " ".join(ident.split()).lower()
            self._obligations[key] = list(obls)
            for part in ident.split(" WITH "):
                self._canon[part.strip().lower()] = part.strip()
        profiles = raw.get("profiles")
        if not isinstance(profiles, dict) or not profiles:
            raise PolicyError("profiles must be a non-empty object")
        self.profiles = {name: Profile(name, p) for name, p in profiles.items()}
        for p in profiles.values():
            for ident in list(p.get("classes", {})) + [
                    s for k in p.get("with_pairs", {}) for s in k.split(" WITH ")]:
                self._canon.setdefault(ident.strip().lower(), ident.strip())
        self.default_profile = raw.get("default_profile", next(iter(profiles)))
        if self.default_profile not in self.profiles:
            raise PolicyError(f"default_profile {self.default_profile} is not defined")

    def profile(self, name=None):
        name = name or self.default_profile
        if name not in self.profiles:
            raise PolicyError(f"no profile {name}")
        return self.profiles[name]

    def obligations_for(self, key):
        return list(self._obligations.get(" ".join(key.split()).lower(), []))

    def canonical_id(self, ident):
        return self._canon.get(ident.lower(), ident)


def load_policy(source):
    """A Policy from a path, a dict, or a Policy (returned as is)."""
    if isinstance(source, Policy):
        return source
    if isinstance(source, (str, Path)):
        try:
            raw = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise PolicyError(f"cannot read policy: {e}") from None
        return Policy(raw)
    return Policy(source)
