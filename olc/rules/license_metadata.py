"""`license_metadata`: the declared licence, evaluated by the policy, and licence files present.

Observation strength in v1: it reports what the package declares, which says nothing about the
licence of bundled files.
"""

import json
import posixpath
import re

from olc import pymeta, spdx
from olc.result import FAIL, INCOMPLETE, INFO, REVIEW
from olc.rules.base import Rule

META = {"wheel": re.compile(r"^[^/]+\.dist-info/METADATA$"),
        "sdist": re.compile(r"^[^/]+/PKG-INFO$"),
        "npm-tarball": re.compile(r"^[^/]+/package\.json$")}
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|notice|copyright|third[-_ ]party)", re.I)


class LicenseMetadata(Rule):
    TYPE = "license_metadata"
    CLASSES = set(META)
    OBSERVATION_ONLY = True

    def relevant(self, name):
        return bool(META[self.art_class].match(name))

    def wants_content(self, name, head):
        return self.relevant(name)

    def begin(self, art_name, art_class):
        super().begin(art_name, art_class)
        self.found, self.license_files = [], []

    def member(self, m):
        if self.relevant(m.name):
            self.found.append(m)
        if self.in_scope(m.name) and (LICENSE_FILE.match(posixpath.basename(m.name))
                                      or ".dist-info/licenses/" in m.name):
            self.license_files.append(m.name)

    def finish_artifact(self, complete):
        if not self.found:
            if complete:
                self.add("metadata-missing", INCOMPLETE)
            return
        self.targets += 1
        if len(self.found) > 1:
            self.add("metadata-ambiguous", INCOMPLETE, detail=f"{len(self.found)} files")
            return
        m = self.found[0]
        if m.content is None:
            self.add("metadata-too-large", INCOMPLETE, m.name)
            return
        declared = self._declared(m)
        if declared is None:
            return
        source, value = declared
        entry = {"artifact": self.art, "member": m.name, "source": source,
                 "declared": value if isinstance(value, str) else json.dumps(value)[:300],
                 "license_files": self.license_files[:100]}
        if source in ("License-Expression", "package.json license") and isinstance(value, str):
            if self.policy is None:
                self.add("no-policy", REVIEW, m.name, "no policy given; declared licence not classed")
            else:
                ev = spdx.evaluate(value, self.policy)
                entry["evaluation"] = ev
                level, code = {"allow": (INFO, "license-allowed"),
                               "review": (REVIEW, "license-review"),
                               "deny": (FAIL, "license-denied")}[ev["verdict"]]
                self.add(code, level, m.name, f"{value[:200]} -> {ev['verdict']}")
        elif source == "none":
            self.add("license-undeclared", REVIEW, m.name)
        else:
            self.add("license-not-spdx", REVIEW, m.name, f"{source}: {entry['declared'][:200]}")
        self.add_evidence("declared", entry)

    def _declared(self, m):
        if self.art_class == "npm-tarball":
            try:
                pkg = json.loads(m.content.decode("utf-8-sig"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                self.add("package-json-unreadable", INCOMPLETE, m.name)
                return None
            if not isinstance(pkg, dict):
                self.add("package-json-unreadable", INCOMPLETE, m.name)
                return None
            if "license" in pkg:
                lic = pkg["license"]
                return ("package.json license" if isinstance(lic, str)
                        else "package.json license object", lic)
            if "licenses" in pkg:
                return "package.json licenses", pkg["licenses"]
            return "none", None
        try:
            meta = pymeta.parse_metadata(m.content)
        except pymeta.MetaError as e:
            self.add(e.code, INCOMPLETE, m.name)
            return None
        if meta.get("license-expression"):
            return "License-Expression", meta["license-expression"][0].strip()
        classifiers = [c for c in meta.get("classifier", []) if c.startswith("License ::")]
        text = (meta.get("license") or [""])[0].strip()
        if text or classifiers:
            return "License/classifiers", {"license": text[:300], "classifiers": classifiers}
        return "none", None
