"""`requires_dist`: forbidden and required Requires-Dist lines in wheel and sdist metadata."""

import re

from olc import pymeta
from olc.result import FAIL, INCOMPLETE, INFO, REVIEW
from olc.rules.base import Rule, RulesError, need_list

WHEEL_META = re.compile(r"^[^/]+\.dist-info/METADATA$")
SDIST_META = re.compile(r"^[^/]+/PKG-INFO$")
NESTED_META = re.compile(r"\.egg-info/PKG-INFO$")


class RequiresDist(Rule):
    TYPE = "requires_dist"
    PARAMS = {"forbid": False, "require": False}
    CLASSES = {"wheel", "sdist"}

    def configure(self, params):
        self.forbid, self.require = [], []
        for item in need_list(params, "forbid", self.id, dict, required=False):
            name, extras = item.get("name"), item.get("extras", "*")
            if not isinstance(name, str) or not name or set(item) - {"name", "extras"}:
                raise RulesError(f"rule {self.id}: forbid items are {{name, extras}}")
            if extras != "*" and not (isinstance(extras, list)
                                      and all(isinstance(e, str) for e in extras)):
                raise RulesError(f"rule {self.id}: forbid extras is \"*\" or a list")
            self.forbid.append((pymeta.normalize(name),
                                "*" if extras == "*" else {pymeta.normalize(e) for e in extras}))
        for item in need_list(params, "require", self.id, dict, required=False):
            name, extra = item.get("name"), item.get("extra")
            if not all(isinstance(v, str) and v for v in (name, extra)) or set(item) - {"name", "extra"}:
                raise RulesError(f"rule {self.id}: require items are {{extra, name}}")
            self.require.append((pymeta.normalize(extra), pymeta.normalize(name)))
        if not self.forbid and not self.require:
            raise RulesError(f"rule {self.id}: give forbid or require")

    def _pattern(self):
        return WHEEL_META if self.art_class == "wheel" else SDIST_META

    def relevant(self, name):
        return self.in_scope(name) and bool(self._pattern().match(name))

    def begin(self, art_name, art_class):
        super().begin(art_name, art_class)
        self.found, self.nested = [], []

    def wants_content(self, name, head):
        return self.relevant(name)

    def member(self, m):
        if self.relevant(m.name):
            self.found.append(m)
        elif self.art_class == "sdist" and NESTED_META.search(m.name):
            self.nested.append(m.name)

    def finish_artifact(self, complete):
        if not self.found:
            if complete:
                self.add("metadata-missing", INCOMPLETE, detail="no core metadata file")
            return
        self.targets += 1
        if len(self.found) > 1:
            self.add("metadata-ambiguous", INCOMPLETE, detail=f"{len(self.found)} metadata files")
            return
        m = self.found[0]
        if m.content is None:
            self.add("metadata-too-large", INCOMPLETE, m.name)
            return
        try:
            meta = pymeta.parse_metadata(m.content)
        except pymeta.MetaError as e:
            self.add(e.code, INCOMPLETE, m.name)
            return
        authoritative = True
        version = pymeta.metadata_version(meta)
        if self.art_class == "sdist":
            dynamic = {d.strip().lower() for d in meta.get("dynamic", [])}
            authoritative = version is not None and version >= (2, 2) \
                and "requires-dist" not in dynamic
            if not authoritative:
                self.add("sdist-deps-not-authoritative", REVIEW, m.name,
                         f"Metadata-Version {version}, Dynamic {sorted(dynamic)}")
        own = pymeta.normalize((meta.get("name") or [""])[0].strip())
        reqs, unparsed = [], False
        for line in meta.get("requires-dist", []):
            try:
                reqs.append(pymeta.parse_requirement(line))
            except pymeta.MetaError as e:
                unparsed = True
                self.add(e.code, INCOMPLETE, m.name, line[:200])
        for r in reqs:
            if own and r.name == own:
                self.add("self-reference", INFO, m.name, f"not expanded: {r.line[:200]}")
        for name, extras in self.forbid:
            for r in reqs:
                if r.name != name:
                    continue
                if extras == "*" or r.marker_extras & extras:
                    self.add("forbidden-requirement", FAIL, m.name, r.line[:200])
                elif r.extra_complex:
                    self.add("complex-extra-marker", REVIEW, m.name, r.line[:200])
        for extra, name in self.require:
            ok = any(r.name == name and extra in r.marker_extras and not r.extra_complex
                     for r in reqs)
            if not ok:
                level = FAIL if authoritative else REVIEW
                if any(r.name == name and r.extra_complex for r in reqs):
                    level = REVIEW
                if unparsed:  # the unreadable line might be the required one
                    level = INCOMPLETE
                self.add("required-requirement-missing", level, m.name,
                         f"no {name} line for extra {extra}")
        self.add_evidence("metadata", {
            "artifact": self.art, "member": m.name, "sha256": m.sha256,
            "metadata_version": ".".join(map(str, version)) if version else None,
            "authoritative": authoritative, "nested_metadata": self.nested[:50],
            "requirements": [r.to_dict() for r in reqs][:500]})
