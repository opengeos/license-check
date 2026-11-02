# opengeos-license-checks

A non-executing checker for published Python and npm package artifacts. Given a rules file and
the wheels, sdists or npm tarballs of one release, it reports which rule passed or failed on which
bytes: forbidden or required dependencies, fonts identified by their name records, required notice
text, byte-pattern observations and the declared licence.

It is engineering triage tooling, not legal advice. It never says a package is clean or
compliant; it says what was checked, on which files, and what could not be checked.

## What it does not do

- It never installs, builds, imports or runs the packages it reads. Archives are streamed in memory
  and never extracted.
- Only ZIP (wheels, old sdists) and gzip tar (sdists, npm tarballs) are read. Nested archives,
  WOFF2 fonts and encrypted members are reported as unexamined, not opened.
- Registry access is limited to anonymous HTTPS GETs to `pypi.org`, `files.pythonhosted.org`
  and `registry.npmjs.org`. `olc inspect` itself does no network access.
- A digest match shows the file is the one the registry lists; it does not verify signatures or
  attestations.
- Copied code and bundled dependencies cannot be judged by byte patterns; `string_probe` results
  are observations only.

## Use

Standard library only, Python 3.11 or later. No installation is needed.

```sh
python3 -I bin/olc registry pypi examplepkg --version 1.0 --out facts.json
python3 -I bin/olc download https://files.pythonhosted.org/packages/…/examplepkg-1.0.tar.gz /path/to/empty-dir
python3 -I bin/olc inspect --rules rules.json --artifacts artifacts.json --out result.json
python3 -I bin/olc spdx "MIT OR Apache-2.0"
```

Run `inspect` from a directory other than the one holding the artifacts. See
[API.md](API.md) for the Python API and file formats, [docs/rules.md](docs/rules.md) for rule
types and reason codes, [docs/result-contract.md](docs/result-contract.md) for what verdicts mean,
and [docs/ci-trust-contract.md](docs/ci-trust-contract.md) for the bar a future CI job must meet.

The bundled policy, `policy/policy.json`, classes declared licences for one context: a published
permissive package. It is an organizational rule, not a compatibility solver.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

Fixtures are synthetic and built in memory; network tests use a fake server.

## Limits

| Limit | Default |
|---|---|
| Artifact size | 300 MB |
| Members per archive | 50 000 |
| Bytes streamed per member | 512 MiB |
| Bytes streamed per archive | 4 GiB |
| Content kept for text and font rules | 16 MiB per member |
| Font name records / TTC faces / tables | 1 000 / 16 / 64 |

Limits can be lowered, never raised, by the caller. Hitting one makes the affected scope
`incomplete`; nothing is skipped silently.

## License

MIT; see [LICENSE](LICENSE).
