"""`forbidden_asset`: fonts identified by their name records or digest, whatever the file name.

The scope is every in-scope member whose magic bytes are a font. A font whose name records were
deliberately altered would not match; every identified font is listed in the evidence so a
reviewer can see what was found.
"""

import posixpath
import re

from olc import fonts
from olc.result import FAIL, INCOMPLETE, REVIEW
from olc.rules.base import Rule, RulesError, compile_regex, need_list

FONT_SUFFIXES = (".ttf", ".otf", ".ttc", ".otc", ".woff", ".woff2", ".eot", ".pfb", ".pfa",
                 ".afm", ".dfont")


class ForbiddenAsset(Rule):
    TYPE = "forbidden_asset"
    PARAMS = {"match": False, "sha256": False}

    def configure(self, params):
        self.matchers = []
        for item in need_list(params, "match", self.id, (str, dict), required=False):
            if isinstance(item, str):
                item = {"regex": item}
            if set(item) - {"regex", "name_ids"}:
                raise RulesError(f"rule {self.id}: match items are a regex or {{regex, name_ids}}")
            ids = item.get("name_ids", list(fonts.NAME_IDS))
            if not isinstance(ids, list) or any(i not in fonts.NAME_FIELDS for i in ids):
                raise RulesError(f"rule {self.id}: name_ids must be within {list(fonts.NAME_IDS)}")
            fields = {fonts.NAME_FIELDS[i] for i in ids}
            self.matchers.append((compile_regex(item.get("regex"), self.id), fields))
        digests = need_list(params, "sha256", self.id, str, required=False)
        if any(not re.fullmatch(r"[0-9a-fA-F]{64}", d) for d in digests):
            raise RulesError(f"rule {self.id}: sha256 entries are 64 hex characters")
        self.digests = {d.lower() for d in digests}
        if not self.matchers and not self.digests:
            raise RulesError(f"rule {self.id}: give match or sha256")

    def wants_content(self, name, head):
        return self.in_scope(name) and fonts.sniff(head) is not None

    def member(self, m):
        if not self.in_scope(m.name):
            return
        self.targets += 1
        content_hit = False
        if m.sha256 in self.digests:
            self.add("digest-match", FAIL, m.name, m.sha256)
            content_hit = True
        fmt = fonts.sniff(m.head)
        if fmt is not None:
            content_hit = self._font(m, fmt) or content_hit
        if not content_hit and m.name.lower().endswith(FONT_SUFFIXES):
            stem = posixpath.basename(m.name).rsplit(".", 1)[0]
            hits = [rx.pattern for rx, _ in self.matchers if rx.search(stem)]
            if hits:
                self.add("name-only-match", REVIEW, m.name,
                         f"file name matches {hits[0]!r} but content does not")

    def _font(self, m, fmt):
        if fmt == "woff2":
            self.add("woff2-unsupported", INCOMPLETE, m.name, "WOFF2 name records not read")
            return False
        if m.content is None:
            self.add("font-too-large", INCOMPLETE, m.name, "over the content cap")
            return False
        try:
            info = fonts.read_names(m.content, self.limits)
        except fonts.FontError as e:
            self.add(e.code, INCOMPLETE, m.name, str(e))
            return False
        hit = False
        for face in info["faces"]:
            entry = {"artifact": self.art, "member": m.name, "sha256": m.sha256,
                     "format": info["format"]}
            entry.update({k: v[0][:300] for k, v in face.items()})
            if not face:
                self.add("font-unidentified", REVIEW, m.name, "no usable name records")
            for rx, fields in self.matchers:
                for field in sorted(fields & set(face)):
                    for value in face[field]:
                        if rx.search(value):
                            self.add("name-record-match", FAIL, m.name,
                                     f"{field}={value[:200]!r} matches {rx.pattern!r}")
                            entry["matched"] = True
                            hit = True
            self.add_evidence("fonts", entry)
        return hit
