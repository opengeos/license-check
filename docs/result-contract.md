# Result contract: `olc.result/1`

The exact fields are in [API.md](../API.md#result-olcresult1). This page states what they mean.

## Verdicts

| Verdict | Meaning |
|---|---|
| `pass` | the rule's stated claim was observed to hold across its full declared scope |
| `fail` | the rule was demonstrably violated; the reason names the artifact, member and code |
| `review` | everything was observed, but the rule cannot decide (an unidentified font, a declared licence outside the profile) |
| `incomplete` | a required observation could not be made (unsupported archive, unread member in scope, no target, a limit, a digest mismatch or a missing published digest) |

Overall verdicts: `fail` if any check failed, else `incomplete` if any was incomplete, else `review`,
else `pass`. Zero artifacts or zero rules give `incomplete`.

`verdict` covers every check. `finding_verdict` covers only `finding`-strength checks and
`observation_verdict` only observation checks. Observation checks are reported beside the
findings; they never confirm or correct anything, and their `review` or `fail` does not change
`finding_verdict`.

## Known bad versus absence

A `fail` from `name-record-match`, `digest-match`, `forbidden-requirement`,
`required-requirement-missing`, `entry-missing` or `file-missing` rests on content that was read.
A `pass` is a statement about absence, and holds only within the scope that was examined:
`coverage` lists every member that was not content (symlinks, devices) or not examined (unsupported nested
archives, depth/byte limits, encryption, bad paths), and any unexamined member a rule depends on makes that
rule `incomplete`. When an archive's member list itself is incomplete, no rule draws an
absence-based conclusion (`file-missing`, `pattern-not-found`).

## Digests

The checker computes sha256 (and sha512 for npm) itself. A digest match shows the bytes are the
ones the registry lists, over the same TLS channel that delivered them; it corroborates transport
and registry identity, not independent integrity. A mismatch means the bytes were not examined.

## Exit codes

`0` pass, `1` fail, `2` review, `3` incomplete, `4` invalid rules, policy, input or arguments (no
verdict), `5` internal error. Whether a verdict blocks anything is the caller's setting, not part
of the result.

Reports state what was checked on which bytes. They never say a package is clean or compliant.
This is engineering triage, not legal advice.
