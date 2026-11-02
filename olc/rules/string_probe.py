"""`string_probe`: byte patterns present or absent in members. Always observation strength.

Members are scanned as a stream, so a member larger than the content cap is still covered.
A match longer than `max_match_bytes` that straddles a chunk boundary can be missed; the
evidence states the window used.
"""

from olc.result import FAIL
from olc.rules.base import Rule, RulesError, compile_regex, need_list

MAX_WINDOW = 65_536


class Scanner:
    def __init__(self, patterns, window):
        self.patterns, self.window = patterns, window
        self.found = set()
        self.tail = b""

    def feed(self, chunk):
        data = self.tail + chunk
        for i, rx in enumerate(self.patterns):
            if i not in self.found and rx.search(data):
                self.found.add(i)
        self.tail = data[-self.window:]


class StringProbe(Rule):
    TYPE = "string_probe"
    PARAMS = {"present": False, "absent": False, "max_match_bytes": False}
    OBSERVATION_ONLY = True

    def configure(self, params):
        present = need_list(params, "present", self.id, required=False)
        absent = need_list(params, "absent", self.id, required=False)
        if not present and not absent:
            raise RulesError(f"rule {self.id}: give present or absent")
        self.kinds = ["present"] * len(present) + ["absent"] * len(absent)
        self.sources = present + absent
        self.patterns = [compile_regex(p, self.id, as_bytes=True) for p in self.sources]
        window = params.get("max_match_bytes", 4096)
        if not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= MAX_WINDOW:
            raise RulesError(f"rule {self.id}: max_match_bytes is 1..{MAX_WINDOW}")
        self.window = window
        self.found_in = [[] for _ in self.patterns]
        self._current = None
        self.evidence = {"window_bytes": window}

    def streams(self, name):
        if not self.in_scope(name):
            return []
        self._current = (name, Scanner(self.patterns, self.window))
        return [self._current[1]]

    def begin(self, art_name, art_class):
        super().begin(art_name, art_class)
        self.art_members = 0
        self.art_found = [False] * len(self.patterns)

    def member(self, m):
        if not self.in_scope(m.name):
            return
        self.targets += 1
        self.art_members += 1
        scanner = self._current[1] if self._current and self._current[0] == m.name else None
        if scanner is None:
            scanner = Scanner(self.patterns, self.window)  # empty member: nothing was streamed
        for i in scanner.found:
            self.art_found[i] = True
            self.found_in[i].append({"artifact": self.art, "member": m.name})
            if self.kinds[i] == "absent":
                self.add("pattern-found", FAIL, m.name, f"{self.sources[i]!r} found")
        self._current = None

    def finish_artifact(self, complete):
        if not self.art_members:
            return
        for i, kind in enumerate(self.kinds):
            if kind == "present" and not self.art_found[i] and complete:
                self.add("pattern-not-found", FAIL,
                         detail=f"{self.sources[i]!r} not found in {self.art_members} examined members")

    def result(self):
        self.evidence["patterns"] = [
            {"pattern": src, "expect": kind, "found_count": len(found), "found_in": found[:50]}
            for src, kind, found in zip(self.sources, self.kinds, self.found_in)]
        self.evidence["members_examined"] = self.targets
        return super().result()
