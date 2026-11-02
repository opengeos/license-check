"""`required_text`: listed entries are present in a notice file of every artifact.

The claim is presence of the listed entries only, never completeness of the notices. Matching
ignores case and collapses whitespace; file globs ignore case.
"""

import fnmatch

from olc.result import FAIL, INCOMPLETE, REVIEW
from olc.rules.base import Rule, RulesError, need_list


def normalize_text(text):
    return " ".join(text.casefold().split())


def decode(content):
    """Text, or None when the bytes do not look like text."""
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return content.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in content:
        return None
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")


class RequiredText(Rule):
    TYPE = "required_text"
    PARAMS = {"file": True, "expect": False, "entries": False}

    def configure(self, params):
        self.files = [g.lower() for g in need_list(params, "file", self.id)]
        if not self.files:
            raise RulesError(f"rule {self.id}: file needs at least one glob")
        self.expect = params.get("expect", "any")
        if self.expect not in ("one", "any"):
            raise RulesError(f"rule {self.id}: expect is one or any")
        self.entries = []
        for e in need_list(params, "entries", self.id, dict, required=False):
            if set(e) != {"id", "text"} or not all(isinstance(e[k], str) and e[k] for k in e):
                raise RulesError(f"rule {self.id}: entries are {{id, text}}")
            self.entries.append((e["id"], normalize_text(e["text"])))

    def relevant(self, name):
        return self.in_scope(name) and any(fnmatch.fnmatchcase(name.lower(), g)
                                           for g in self.files)

    def wants_content(self, name, head):
        return self.relevant(name)

    def begin(self, art_name, art_class):
        super().begin(art_name, art_class)
        self.matched = []

    def member(self, m):
        if self.relevant(m.name):
            self.matched.append(m)

    def finish_artifact(self, complete):
        self.targets += 1
        if not self.matched:
            if complete:
                self.add("file-missing", FAIL, detail=f"no member matches {self.files}")
            return
        if self.expect == "one" and len(self.matched) > 1:
            self.add("multiple-files", REVIEW, detail=", ".join(m.name for m in self.matched[:20]))
        texts, unreadable = [], False
        for m in self.matched:
            if m.content is None:
                self.add("file-too-large", INCOMPLETE, m.name)
                unreadable = True
                continue
            text = decode(m.content)
            if text is None:
                self.add("undecodable", INCOMPLETE, m.name)
                unreadable = True
                continue
            texts.append(normalize_text(text))
        found = {}
        for entry_id, text in self.entries:
            found[entry_id] = any(text in t for t in texts)
            if not found[entry_id] and not unreadable:
                self.add("entry-missing", FAIL, detail=f"entry {entry_id!r} not found in "
                         + ", ".join(m.name for m in self.matched[:20]))
            elif not found[entry_id]:
                self.add("entry-unknown", INCOMPLETE, detail=f"entry {entry_id!r}: a candidate "
                         "file could not be read")
        self.add_evidence("files", {"artifact": self.art,
                                    "members": [{"member": m.name, "sha256": m.sha256}
                                                for m in self.matched[:50]],
                                    "entries_found": found})
