"""SPDX license expressions (SPDX 2.3 Annex D): a bounded parser and a policy evaluator.

Precedence: WITH binds tighter than AND, which binds tighter than OR. Ids match
case-insensitively but are never normalized into one another: `-only`, `-or-later` and the
deprecated `+` stay distinct. Anything over the bounds, or unparsable, is `review` with the
original string kept.
"""

import re

MAX_LENGTH = 512
MAX_TERMS = 64
MAX_DEPTH = 16
MAX_ALTERNATIVES = 32

ALLOW, REVIEW, DENY = "allow", "review", "deny"
_RANK = {ALLOW: 0, REVIEW: 1, DENY: 2}

_TOKEN = re.compile(r"\s*(?:(\()|(\))|([A-Za-z0-9.\-:+]+))")
_ID = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.\-]+:)?LicenseRef-[A-Za-z0-9.\-]+$|^[A-Za-z0-9.\-]+\+?$")
_EXC = re.compile(r"^[A-Za-z0-9.\-]+$|^(?:DocumentRef-[A-Za-z0-9.\-]+:)?AdditionRef-[A-Za-z0-9.\-]+$")
_OPS = ("AND", "OR", "WITH")


class ParseError(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# AST: ("id", text) | ("with", id, exc) | ("and", [nodes]) | ("or", [nodes])

def tokenize(text):
    tokens, pos = [], 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ParseError("bad-character", f"at offset {pos}")
        pos = m.end()
        tokens.append(m.group(1) or m.group(2) or m.group(3))
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i, self.terms = tokens, 0, 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def is_op(self, tok, op):
        return tok is not None and tok.upper() == op

    def parse(self):
        if not self.tokens:
            raise ParseError("empty")
        node = self.or_expr(0)
        if self.peek() is not None:
            raise ParseError("trailing-token", self.peek())
        return node

    def or_expr(self, depth):
        parts = [self.and_expr(depth)]
        while self.is_op(self.peek(), "OR"):
            self.take()
            parts.append(self.and_expr(depth))
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_expr(self, depth):
        parts = [self.with_expr(depth)]
        while self.is_op(self.peek(), "AND"):
            self.take()
            parts.append(self.with_expr(depth))
        return parts[0] if len(parts) == 1 else ("and", parts)

    def with_expr(self, depth):
        tok = self.peek()
        if tok == "(":
            if depth + 1 > MAX_DEPTH:
                raise ParseError("too-deep")
            self.take()
            node = self.or_expr(depth + 1)
            if self.take() != ")":
                raise ParseError("unbalanced-parenthesis")
            if self.is_op(self.peek(), "WITH"):
                raise ParseError("with-after-group")
            return node
        if tok is None or tok == ")" or tok.upper() in _OPS:
            raise ParseError("expected-license", str(tok))
        self.take()
        if not _ID.match(tok):
            raise ParseError("bad-license-id", tok)
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise ParseError("too-many-terms")
        if self.is_op(self.peek(), "WITH"):
            self.take()
            exc = self.take()
            if exc is None or exc in ("(", ")") or exc.upper() in _OPS or not _EXC.match(exc):
                raise ParseError("bad-exception-id", str(exc))
            return ("with", tok, exc)
        return ("id", tok)


def parse(text):
    if not isinstance(text, str):
        raise ParseError("not-a-string")
    if len(text) > MAX_LENGTH:
        raise ParseError("too-long", f"{len(text)} > {MAX_LENGTH}")
    return _Parser(tokenize(text)).parse()


def render(node, canon=lambda s: s, top=True):
    kind = node[0]
    if kind == "id":
        return canon(node[1])
    if kind == "with":
        return f"{canon(node[1])} WITH {canon(node[2])}"
    inner = f" {kind.upper()} ".join(render(n, canon, False) for n in node[1])
    # Parenthesize an OR inside an AND; AND inside OR binds tighter anyway.
    return inner if top or kind == "and" else f"({inner})"


def _render_and(terms, canon):
    return " AND ".join(render(t, canon, False) for t in terms)


def alternatives(node):
    """Expand to disjunctive normal form: a list of term lists. Bounded."""
    kind = node[0]
    if kind in ("id", "with"):
        return [[node]]
    if kind == "or":
        out = []
        for child in node[1]:
            out.extend(alternatives(child))
            if len(out) > MAX_ALTERNATIVES:
                raise ParseError("too-many-alternatives")
        return out
    out = [[]]
    for child in node[1]:
        out = [a + b for a in out for b in alternatives(child)]
        if len(out) > MAX_ALTERNATIVES:
            raise ParseError("too-many-alternatives")
    return out


def evaluate(expression, policy, profile=None):
    """Evaluate an expression against a policy profile.

    AND: worst class, union of obligations. OR: best alternative (leftmost on ties), and only
    its obligations. Unknown ids, LicenseRef-* and unlisted WITH pairs are `review`.
    """
    prof = policy.profile(profile)
    out = {"expression": expression, "normalized": None, "verdict": REVIEW, "selected": None,
           "alternatives": [], "obligations": [], "reasons": []}
    try:
        tree = parse(expression)
        alts = alternatives(tree)
    except ParseError as e:
        out["reasons"].append({"code": "spdx-" + e.code, "detail": str(e)})
        return out
    canon = policy.canonical_id
    out["normalized"] = render(tree, canon)
    best = None
    for terms in alts:
        cls, obligations, reasons = ALLOW, [], []
        for term in terms:
            tcls, tobl, treason = _classify(term, policy, prof)
            if _RANK[tcls] > _RANK[cls]:
                cls = tcls
            for o in tobl:
                if o not in obligations:
                    obligations.append(o)
            if treason:
                reasons.append(treason)
        alt = {"expression": _render_and(terms, canon), "class": cls,
               "obligations": obligations, "reasons": reasons}
        out["alternatives"].append(alt)
        if best is None or _RANK[cls] < _RANK[best["class"]]:
            best = alt
    out["selected"] = best["expression"]
    out["verdict"] = best["class"]
    out["obligations"] = list(best["obligations"])
    out["reasons"] = list(best["reasons"])
    return out


def _classify(term, policy, prof):
    if term[0] == "with":
        key = f"{policy.canonical_id(term[1])} WITH {policy.canonical_id(term[2])}"
        cls = prof.with_pair_class(key)
        if cls is None:
            return REVIEW, [], {"code": "unknown-with-pair", "detail": key}
        return cls, policy.obligations_for(key), None
    ident = term[1]
    if ident.lower().startswith(("licenseref-", "documentref-")):
        return REVIEW, [], {"code": "license-ref", "detail": ident}
    cls = prof.license_class(ident)
    if cls is None:
        return REVIEW, [], {"code": "unlisted-license", "detail": ident}
    reason = None if cls == ALLOW else {"code": f"license-{cls}", "detail": policy.canonical_id(ident)}
    return cls, policy.obligations_for(ident), reason
