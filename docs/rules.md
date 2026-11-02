# Rules

A rules file states, before the checker runs, what would show that a claim holds for a set of
published artifacts. Write the rules from the claim, then run them on the candidate fix. If you
change a rule after seeing results, say why in `revision_reason`; the rules hash changes with it.

```json
{"schema": 1, "id": "example-rules", "revision_reason": "optional",
 "rules": [
  {"id": "no-example-font", "type": "forbidden_asset", "strength": "finding",
   "claim": "No member of any examined artifact is a font whose name records identify Examplesans or Acme Type Foundry. Fonts with altered name records are outside this claim.",
   "scope": {"members": ["*"], "artifact_classes": ["wheel", "sdist"]},
   "match": ["(?i)^Examplesans$", "(?i)Acme Type"]}]}
```

Common keys: `id`, `type`, `strength` (`finding` or `observation`), `claim` (plain text: what a
`pass` means and what it does not), `scope`, and type parameters, given either top-level or under
`params`. `notes` is free text. Unknown keys are errors.

`scope.members` globs use `fnmatch` (case-sensitive, `*` also matches `/`). Members of npm tarballs
start with `package/`; sdist members start with `<name>-<version>/`.

## Verdicts and reasons

Each reason has a `level`. A check is `fail` if any reason is `fail`, else `incomplete`, else
`review`, else `pass`; `info` reasons never change the verdict. A rule that matched nothing is
`incomplete: no-target`.

Reasons every rule can give:

| Code | Level | Meaning |
|---|---|---|
| `no-target` | incomplete | nothing in scope to examine |
| `artifact-missing`, `artifact-unreadable`, `artifact-too-large` | incomplete | the file could not be read |
| `digest-mismatch` | incomplete | bytes differ from the published digest; not examined |
| `no-published-digest` | incomplete | examined, but identity is not established |
| `size-mismatch` | incomplete | actual size differs from the declared size |
| `archive-<problem>` | incomplete | `unsupported-archive`, `archive-unreadable`, `member-limit`, `total-limit`, `oversized-header`: the member list is incomplete, so no absence-based conclusion is drawn |
| `unexamined-in-scope` | incomplete | a member the rule depends on was not read (`detail` says why: `nested-archive`, `too-large`, `encrypted`, `compression-N`, `sparse`, `bad-path:*`, `read-error:*`) |
| `duplicate-member` | review | two member names collide after NFC normalization and case folding |
| `rule-error` | incomplete | the rule raised on this member (`detail` is the exception type); report it as a checker bug |

## `requires_dist` (finding)

Reads each wheel's single top-level `*.dist-info/METADATA` and each sdist's single top-level
`<dir>/PKG-INFO`. Other artifact classes are not targets. Nested `*.egg-info/PKG-INFO` files are
listed in the evidence only.

Parameters: `forbid: [{"name", "extras": "*" | [..]}]` and `require: [{"extra", "name"}]`. Names
and extras are normalized (PEP 503/685). `extras` means the extra a line belongs to
(`; extra == "x"`); `"*"` matches every line, base or extra. Markers are parsed, not evaluated;
self-references (`pkg[a]; extra == "all"`) are reported and never expanded.

| Code | Level |
|---|---|
| `forbidden-requirement` | fail |
| `required-requirement-missing` | fail (review for a non-authoritative sdist or a complex marker; incomplete if a line could not be parsed) |
| `sdist-deps-not-authoritative` | review: PKG-INFO `Metadata-Version` < 2.2 or `Requires-Dist` is `Dynamic` |
| `complex-extra-marker` | review: `extra` used other than `extra == "x"` |
| `metadata-missing`, `metadata-ambiguous`, `metadata-too-large`, `metadata-undecodable`, `unparsable-requirement`, `unparsable-marker` | incomplete |
| `self-reference` | info |

## `forbidden_asset` (finding)

The scope is every in-scope member whose magic bytes are a font (sfnt `00010000`/`OTTO`/`true`,
`ttcf`, `wOFF`, `wOF2`), whatever its file name. Name records 0, 1, 4, 6, 7, 13 and 16 are read from
sfnt, TTC and WOFF1 fonts.

Parameters: `match: [regex | {"regex", "name_ids": [..]}]` (searched in every listed record) and
`sha256: [hex]` (any in-scope member).

| Code | Level |
|---|---|
| `name-record-match`, `digest-match` | fail |
| `font-unidentified` | review: a font with no usable name records |
| `name-only-match` | review: a font-like file name matches but the content does not; never a fail |
| `woff2-unsupported`, `font-malformed`, `font-too-large` | incomplete |

Every font read is listed in `evidence.fonts`. A font whose name records were deliberately altered
would not match; say so in the claim.

## `required_text` (finding)

Parameters: `file: [glob]` (matched case-insensitively, within `scope.members`), `expect: "one" |
"any"` (default `any`), `entries: [{"id", "text"}]`. Text matching ignores case and collapses
whitespace; comment markers inside the text are not removed. Files are decoded as UTF-16 (with a
BOM), UTF-8 or Latin-1; a file containing NUL bytes otherwise is undecodable. Each entry must
appear in at least one matched file of each artifact.

| Code | Level |
|---|---|
| `file-missing`, `entry-missing` | fail |
| `multiple-files` | review (`expect: "one"`) |
| `undecodable`, `file-too-large`, `entry-unknown` | incomplete |

The claim is presence of the listed entries, never completeness of the notices.

## `string_probe` (observation only)

Parameters: `present: [regex]`, `absent: [regex]` (bytes regexes over in-scope members),
`max_match_bytes` (default 4096, at most 65 536). Members are streamed, so members larger than the
content cap are still scanned. A match longer than `max_match_bytes` that straddles a 1 MiB chunk
boundary can be missed.

| Code | Level |
|---|---|
| `pattern-found` (an `absent` pattern) | fail |
| `pattern-not-found` (a `present` pattern, per artifact with in-scope members) | fail |

A probe says only "found / not found in N examined members". It cannot show that code was or
was not copied, and it never confirms or corrects anything.

## `license_metadata` (observation only)

Reads the declared licence (`License-Expression`; else `License`/classifiers; npm `license`) and
evaluates an SPDX expression against the policy. Lists licence-like files (`LICENSE*`,
`COPYING*`, `NOTICE*`, `*.dist-info/licenses/*`, …) in the evidence.

| Code | Level |
|---|---|
| `license-allowed` | info |
| `license-review`, `license-not-spdx`, `license-undeclared`, `no-policy` | review |
| `license-denied` | fail |
| `metadata-missing`, `metadata-ambiguous`, `package-json-unreadable` | incomplete |

The declared licence says nothing about the licences of bundled files.
