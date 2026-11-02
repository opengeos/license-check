# `olc` public API

This is the interface the checker promises to its callers. A caller is anything that imports
`olc`, such as a private register or a CI job. Everything here is stdlib-only Python ≥ 3.11 and
works from a plain checkout; no installation is needed. Import it with the checkout on
`sys.path` (or an editable install); run the CLI as `python3 -I <checkout>/bin/olc …`, which adds
only the checkout to `sys.path` (`-I` ignores `PYTHONPATH` and the working directory, so
`python -I -m olc` works only where `olc` is installed).

Anything not listed here is internal and may change.

## Errors

| Exception | Raised when | CLI exit |
|---|---|---|
| `olc.errors.InputError` | malformed artifacts list, limits, or arguments | 4 |
| `olc.rules.RulesError` (subclass of `InputError`) | the rules object is invalid | 4 |
| `olc.policy.PolicyError` (subclass of `InputError`) | the policy object is invalid | 4 |
| `olc.net.NetError` | any network failure (see codes below) | 3 for `registry`/`download` |
| `olc.versions.VersionError` | an unparsable version (`InvalidVersion`) or candidate rule (`InvalidRule`) | 4 |

Every error has a short `code` attribute and a message that never contains a response body,
query string, userinfo or header value.

## `olc.inspect.inspect_artifacts`

```python
inspect_artifacts(artifacts, rules, policy=None, limits=None, *, target=None, engine_rev=None) -> dict
```

Reads local artifact files as data and returns an `olc.result/1` dict. No network access; it
never imports, runs or extracts the target's files. Raises `InputError`/`RulesError`/
`PolicyError` for invalid input; never raises for hostile artifact *content* (that becomes
`incomplete` or `review`).

### `artifacts`: list of dicts

| Key | Required | Meaning |
|---|---|---|
| `path` | yes | local file path |
| `filename` | yes | the registry's filename (reported; need not equal the path's basename) |
| `class` | yes | `wheel`, `sdist`, `npm-tarball`, or any other string (no rule type handles other classes specially) |
| `published_digest` | no | `{"alg": "sha256"\|"sha512", "value": "…", "encoding": "hex"\|"base64", "source": "…"}`. `encoding` defaults to `hex` for sha256 and `base64` for sha512. Missing or `null` → every applicable check gets `incomplete: no-published-digest`, but the bytes are still examined |
| `size` | no | the registry's declared size; a different actual size gives `incomplete: size-mismatch` |
| `ecosystem`, `package`, `version` | no | identity, copied into `target` (they must agree across artifacts) |
| any other key | no | ignored |

`olc` computes sha256 (and sha512 when the published digest is sha512) itself. Any
`digest_match` or `sha256` in the input is ignored. A **digest mismatch** means the bytes are not
the published ones, so the artifact is **not examined**; every applicable check gets
`incomplete: digest-mismatch`.

### `rules`: dict (the rules file)

```json
{"schema": 1, "id": "<caller's id>", "revision_reason": "optional text",
 "rules": [{"id": "…", "type": "…", "strength": "finding|observation", "claim": "…",
            "scope": {"members": ["*"], "artifact_classes": ["wheel", "sdist"]},
            "…type parameters…": "…"}]}
```

- `schema` must be `1`; `id` a non-empty string; `rules` a list (empty → overall `incomplete:
  no-rules`). Rule ids must be unique.
- Type parameters may be given top-level in the rule **or** inside a `"params": {…}` object, not
  both for the same key. Unknown keys are a `RulesError` (catches typos).
- `scope.members`: globs (`fnmatch`, case-sensitive, `*` crosses `/`), default `["*"]`.
  `scope.artifact_classes`: default all classes. A rule type only targets classes it understands:
  `requires_dist` targets `wheel` and `sdist`; listing `npm-tarball` for it is accepted and simply
  matches nothing on npm artifacts (no reason is emitted).
- `string_probe` and `license_metadata` must have `strength: "observation"`.
- The rules hash in the result is `olc.result.canonical_sha256(rules)`: sha256 of
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` in UTF-8.

Rule types and parameters (details and reason codes in `docs/rules.md`):

| Type | Parameters |
|---|---|
| `requires_dist` | `forbid: [{"name": str, "extras": "*" \| [str]}]`, `require: [{"extra": str, "name": str}]` |
| `forbidden_asset` | `match: [regex \| {"regex": str, "name_ids": [int]}]`, `sha256: [hex]` |
| `required_text` | `file: [glob]`, `expect: "one" \| "any"` (default `any`), `entries: [{"id": str, "text": str}]` |
| `string_probe` | `present: [regex]`, `absent: [regex]` (bytes regexes; at least one list non-empty), `max_match_bytes: int` (default 4096) |
| `license_metadata` | none |

Points callers rely on:
- **requires_dist metadata:** a wheel needs exactly one `<x>.dist-info/METADATA` at top level; an
  sdist needs exactly one top-level `<dir>/PKG-INFO`. Nested `*.egg-info/PKG-INFO` files are
  listed in evidence but are neither the authority nor a duplicate. An sdist whose PKG-INFO has
  `Metadata-Version` < 2.2 or lists `Requires-Dist` in `Dynamic` gives
  `review: sdist-deps-not-authoritative` unless a forbidden requirement is actually declared
  (that is still `fail`, since the shipped file declares it).
- `forbid.extras` names the extra a requirement line belongs to (`; extra == "x"`), not the
  requirement's own `[extras]`. `"*"` matches every line, base or extra.
- `forbidden_asset` scope is every in-scope member whose **magic bytes** are a font; file names
  never decide a `fail`. A file-name hint alone gives `review: name-only-match`.
- `required_text` globs are matched **case-insensitively** (a missing-file failure should not hinge on
  `License` vs `LICENSE`), within `scope.members`. With `expect: "any"` each entry must appear in at
  least one matched file of the artifact.

### `policy`

`None`, or a dict in the format of `policy/policy.json`. `license_metadata` without a policy
gives `review: no-policy`. `olc.policy.load_policy(path_or_dict)` validates;
`olc.policy.default_policy_path()` returns the checkout policy, or the environment data file installed by the wheel.

### `limits`

`None` or a dict that may only **lower** the defaults (`olc.archive.DEFAULT_LIMITS`); raising one
is an `InputError`. Keys: `max_artifact_bytes` (300 MB), `max_members` (50 000),
`max_member_bytes` (512 MiB), `max_total_bytes` (4 GiB), `content_cap` (16 MiB),
`max_name_records` (1 000), `max_ttc_fonts` (16), `max_font_tables` (64),
`max_nested_depth` (2; zero disables nested inspection).

Nested ZIP/KMZ and gzip-tar members are inspected in memory under the same member
and expanded-byte budgets as their parent. Their virtual names use `parent.zip!/child`.
Each nested archive is capped by `content_cap` before opening; unsupported formats,
corrupt members, and depth limits remain explicit incomplete coverage.

### `target`, `engine_rev`

`target`: optional `{"ecosystem", "package", "version"}`; otherwise taken from the artifacts.
`engine_rev`: optional `{"git": sha, "dirty": bool}` recorded verbatim as `engine.git_rev`/`dirty`
(olc does not shell out to git). Callers that need clean-revision evidence pass it.

### Result (`olc.result/1`)

```json
{"schema": "olc.result/1",
 "engine": {"version": "0.1.0", "git_rev": null, "dirty": null},
 "rules": {"id": "…", "sha256": "…"}, "policy": {"id": "…", "sha256": "…"} | null,
 "target": {"ecosystem": "…", "package": "…", "version": "…",
   "artifacts": [{"filename": "…", "class": "wheel", "path": "…", "size": 123, "declared_size": 123,
                  "sha256": "…", "sha512": "…|absent", "published_digest": {…} | null,
                  "digest_match": true | false | null, "examined": true, "problems": ["…"],
                  "archive": {"format": "zip|tar.gz|null", "problem": null}}]},
 "coverage": {"artifacts_expected": 2, "artifacts_examined": 2,
   "members_total": 0, "members_examined": 0, "members_not_content": [{"artifact", "member", "why"}],
   "unexamined": [{"artifact", "member", "why"}], "members_not_content_count": 0,
   "unexamined_count": 0, "lists_truncated": false},
 "checks": [{"rule": "…", "type": "…", "strength": "finding|observation", "claim": "…",
             "verdict": "pass|fail|review|incomplete",
             "reasons": [{"code", "level": "fail|review|incomplete|info", "artifact", "member", "detail"}],
             "reasons_truncated": 0,
             "examined": {"artifacts": 1, "targets": 3},
             "evidence": {…type specific…}}],
 "verdict": "…", "finding_verdict": "…", "observation_verdict": "…",
 "notes": [{"code": "no-artifacts|no-rules", "level": "incomplete"}]}
```

- `problems` on an artifact: `artifact-missing`, `artifact-unreadable`, `artifact-too-large`,
  `digest-mismatch` (these block examination), `no-published-digest`, `size-mismatch`,
  `archive-<problem>`. `archive` is present only when the artifact was examined.
- An archive-level problem also appears in `coverage.unexamined` with `member: "*"`.

- Each artifact lists `finding_rules`, the finding-strength rules applicable to its class.
  When finding rules exist, an artifact with none makes `finding_verdict` and the overall
  verdict incomplete. A metadata check on wheels cannot cover an additional unsupported artifact.
- `checks` is **flat: one entry per rule**, aggregated across all artifacts; each reason names its
  artifact.
- Check verdict: `fail` if any reason has level `fail`, else `incomplete`, else `review`, else
  `pass`. A check that matched no target is `incomplete: no-target`.
- `verdict` aggregates **all** checks. `finding_verdict` aggregates only `strength: finding`
  checks and `observation_verdict` only observation checks (each `incomplete` when it has no
  checks, or when there are no artifacts). A correction decision should read
  `finding_verdict` and the finding checks, so an observation's `review` (for example a declared
  licence) does not block it, and an observation's `pass` never confirms anything.
- Reason codes a control may rely on as **content-based** fails: `name-record-match`,
  `digest-match`, `forbidden-requirement`, `required-requirement-missing`, `entry-missing`,
  `file-missing`. `name-only-match` is review only. `string_probe` fails use
  `pattern-found`/`pattern-not-found` and are observation strength.
- Lists (`unexamined`, `members_not_content`, per-check `reasons`, evidence lists) are capped
  at 1 000 items; counts and verdicts are computed before capping, and truncation is flagged.

`olc.result.exit_code(verdict)`: `pass` 0, `fail` 1, `review` 2, `incomplete` 3. Invalid input 4,
internal error 5.

## `olc.net.Transport`

```python
Transport(*, allowed_hosts=("pypi.org", "files.pythonhosted.org", "registry.npmjs.org"),
          timeout=30, min_interval=1.0, retries=2, max_json_bytes=20_000_000, max_redirects=3)
t.get_json(url, *, accept="application/json") -> object
t.download(url, destination_dir, *, max_bytes=300_000_000) -> {"path": Path, "size": int,
          "sha256": hex, "sha512": hex, "sha512_b64": str, "url": sanitized final URL}
```

- HTTPS GET only to the allowlist; no port, userinfo or non-https scheme. Each host is resolved,
  every resolved address must be global, and the connection is made to the vetted address with
  TLS verified against the host name, so there is no resolve-then-connect gap. Redirects are
  followed by hand (≤ 3), each target re-validated. Environment proxies, cookies and auth are
  never used; the only headers sent are `User-Agent: opengeos-license-checks/<version>`,
  `Accept` and `Accept-Encoding: identity`.
- One request per second per host; 2 retries with backoff on connection errors, timeouts and 5xx.
  A 403 or 429 blocks that host for the life of the `Transport` (`host-blocked` afterwards).
- `download` streams to `destination_dir/<sha256>` (an existing directory), via a temporary
  `.part` file that is removed on error. An existing file of that name is left as is if its
  content matches, else `NetError("exists")`.
- `NetError.code`: `bad-url`, `disallowed-host`, `disallowed-address`, `dns`, `connection`,
  `timeout`, `tls`, `http-<status>`, `rate-limited` (429), `host-blocked`, `redirect-limit`,
  `too-large`, `malformed`, `exists`. Attributes: `code`, `url` (sanitized), `status` (or None).

## `olc.registry.pypi.collect` / `olc.registry.npm.collect`

```python
collect(package, versions=None, transport=None) -> dict
```

`transport` defaults to a new `Transport()`. `versions=None` collects every version; a list
collects only those (plus `current`'s facts in the top level). Network errors raise `NetError`.

```json
{"ecosystem": "pypi|npm", "package": "<normalized>", "name": "<registry display name>",
 "current": "<version or null>", "registry_latest": "<registry's own latest or null>",
 "versions": [{"version": "…", "published_at": "ISO-8601|null", "yanked": false,
               "yanked_reason": null, "deprecated": null,
               "files_source": "pypi-version-json|pypi-json-releases|npm-packument",
               "files": [{"filename": "…", "url": "…|null", "class": "wheel|sdist|npm-tarball|other",
                          "size": 123 | null, "uploaded_at": "…|null", "yanked": false,
                          "published_digest": {"alg": "sha256", "value": "<hex>", "encoding": "hex",
                                               "source": "pypi-json"} | null}],
               "...ecosystem extras": "…"}],
 "missing_versions": ["requested but not published"],
 "unparsable_versions": ["published but not PEP 440 / SemVer"]}
```

- **PyPI:** `GET https://pypi.org/pypi/<name>/json` gives the version list (`releases`). With
  `versions=None` the files come from that response (`files_source: pypi-json-releases`). For each
  requested version, files come from `GET /pypi/<name>/<version>/json` field `urls`
  (`files_source: pypi-version-json`), which is the listing a verification should use. `class`
  is `wheel` for `bdist_wheel`, `sdist` for `sdist`, else `other` (`packagetype` kept). A
  release's `yanked` is true when every file is yanked. A file URL whose host is not on the
  allowlist is kept as `url: null` with `url_rejected: true`.
- **npm:** one `GET https://registry.npmjs.org/<name>` (scoped names are `%2f`-encoded). Each
  version has one `npm-tarball` file; `size` is `null` (npm does not publish tarball size);
  `published_digest` is `{"alg": "sha512", "value": "<base64>", "encoding": "base64", "source":
  "npm-packument"}` from `dist.integrity`, or `null` if there is no sha512 integrity. Extra
  version keys: `deprecated` (message or null), `file_count`, `unpacked_size`, `attestations`
  (bool, presence only), `shasum`. Top level adds `dist_tags` and `unpublished_versions`
  (versions in `time` but no longer in `versions`).
- **`current`**: PyPI, the highest non-prerelease version with at least one non-yanked file;
  npm, `dist-tags.latest` when it is a valid non-prerelease version, else the highest
  non-prerelease, non-deprecated version.
- A digest match proves the file is what the registry lists over the same TLS channel; it does
  not prove independent integrity.

## `olc.versions`

```python
version_key(version, ecosystem) -> tuple        # sortable; raises InvalidVersion
is_prerelease(version, ecosystem) -> bool
matches(version, candidate_rule, ecosystem) -> bool   # raises InvalidVersion / InvalidRule
```

- `ecosystem` is `"pypi"` (PEP 440, normalized forms accepted: `1.0RC1`, `v1.0`, `1.0-post1`) or
  `"npm"` (SemVer 2.0.0, optional leading `v`).
- PyPI rules: comma-separated specifiers `==`, `!=`, `<`, `<=`, `>`, `>=`, `~=`, `===`, with
  `==X.*`/`!=X.*`. npm rules: space- or comma-separated comparators (`<`, `<=`, `>`, `>=`, `=`,
  bare version), `^x.y.z`, `~x.y.z`, `a - b`, alternatives joined by `||`. `*` or an empty rule
  matches everything.
- **Plain interval arithmetic:** pre-releases are *not* excluded (unlike pip/npm resolution),
  because a published pre-release is still a published artifact. Local versions compare per
  PEP 440 ordering.

## `olc.spdx` / `olc.policy`

```python
olc.spdx.evaluate(expression, policy, profile=None) -> {"expression", "normalized", "verdict":
    "allow|review|deny", "selected", "alternatives": [{"expression", "class", "obligations"}],
    "obligations": [...], "reasons": [...]}
olc.policy.load_policy(path_or_dict) -> Policy   # Policy.id, Policy.sha256, Policy.raw
```

## CLI

```
python3 -I bin/olc inspect --rules R.json --artifacts A.json --out result.json [--policy P.json] [--limits L.json]
python3 -I bin/olc spdx "<expression>" [--policy P.json] [--profile NAME]
python3 -I bin/olc registry pypi|npm <package> [--version V ...] [--out F]
python3 -I bin/olc download <url> <destination-dir>
```

(`python -m olc …` is the same CLI.)

`A.json` is either the artifacts list or `{"artifacts": [...], "target": {...}, "engine_rev": {...}}`;
relative `path`s are resolved against A.json's directory. `inspect` refuses to run (exit 4) when the
working directory is the directory of any artifact. `--policy` defaults to the bundled
`policy/policy.json`. Exit codes as above.

## Unpublished CI artifact identity

An artifact may instead supply `expected_digest: {"alg":"sha256","value":"<64 lowercase hex>"}`
and `authority: {"kind":"ci-artifact"}` together, with no `published_digest`. This checks bytes
against the build manifest, and suppresses only `no-published-digest`; a mismatch still blocks
inspection as `incomplete: digest-mismatch`. Both fields are retained in the output record.
This authority proves neither registry publication, provenance nor publisher identity. Registry
callers continue to use `published_digest`; callers must not use CI authority for registry
verification or correction decisions. The CI adapter permits no manifest-supplied policy,
exceptions, registry identity or output paths.
