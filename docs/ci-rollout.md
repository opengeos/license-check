# Artifact CI rollout proposal

This is local preparation, not deployed CI. The workflow has a `.yml.proposed` suffix so GitHub
cannot discover it. `UNPUBLISHED_ENGINE_COMMIT` must be replaced with a reviewed immutable
40-character commit before enabling it. Never deploy the marker.

The useful initial scope is checking actual package archives produced by a separate unprivileged
build job. That job runs on an ephemeral hosted runner with no secrets or write permissions,
no shared caches, and credential persistence disabled. Its fixed repository-specific build steps
are reviewed in the caller; the checker accepts no build command. The caller uses `pull_request`,
its build job uploads `olc-package-artifacts`, and its inspection job uses `needs: build` and
calls the reusable workflow at a full protected commit SHA. No secrets are inherited. The caller
must protect workflow changes and immutable checker pin updates with required review. A PR can
otherwise edit its own caller and skip the check: this proposal alone is not a branch-protection
or required-workflow enforcement mechanism.

The download contains package files and `manifest.json`:

```json
{"schema":"olc.ci-artifacts/1","artifacts":[{"path":"dist/example.whl","class":"wheel","sha256":"<64 lowercase hex>"}]}
```

Every downloaded file except the root manifest must be listed once. Paths are relative, no
symlinks, traversal, absolute names or alternate manifest keys. Classes are wheel, sdist and
npm-tarball; unsupported content or finding-rule coverage stays incomplete. The producer hashes
its package files; this manifest establishes only which build bytes were inspected. It does not
prove who produced them, reproducibility, source correspondence or registry publication.
GitHub artifact download digest validation is transport checking, not publisher integrity.
The adapter records `unpublished-local-build` and uses the explicit `ci-artifact` identity;
registry verification still requires actual registry digest evidence.

The protected base revision contains `.olc/rules.json` and `.olc/policy.json`. Declarations and
exceptions, if present, are compared with the candidate too. Changes become review requests;
candidate configuration never supplies authority, even when package contents pass. Declaration
and exception application is not implemented: they cannot suppress observed conflicts. All
artifacts are rescanned under baseline rules. Rule scope changes need review for completeness.
The candidate checkout is never imported, installed, executed or used as the working directory.
Reports go to a fresh trusted output directory outside input trees. Only fixed text and the
validated verdict enter Markdown; artifact names and evidence remain JSON data. Nothing writes
GitHub outputs, comments, labels or annotations from artifact strings.

`python3 -I <engine>/bin/olc-ci --artifacts <download> --baseline <base> --candidate <head>
--engine-commit <immutable-sha> --report-root <fresh-directory>` exits pass 0, fail 1, review 2,
incomplete 3, invalid/unavailable input 4. A CI pass means the configured rules passed for the
manifest's exact local-build bytes, within recorded coverage. It is not a legal opinion or a
published-release verification. The workflow uploads JSON and its safe summary even on failure.
No extra `actions: read` permission is requested: download is within the caller's current run,
using the action's same-run runtime access, with no cross-run token supplied.

## Approval and validation sequence

1. Review code, baseline scope, local synthetic pass/fail/incomplete/review tests and malicious
   path, omission, policy-change and report injection cases.
2. Commit checker code as revision A. In a later revision B replace both engine markers with A.
   A reusable workflow's `github` context describes its caller, so `github.workflow_sha` must
   never be used as the checker revision. Pin caller reuse to B and engine checkout to A.
3. Obtain explicit approval before any public push, PR, comment, sandbox repository change or
   workflow execution. Publishing checker code and running a disposable sandbox are separate
   choices; neither has occurred as part of this preparation.
4. In the approved sandbox exercise fork PRs, omitted and mismatched artifacts, policy changes,
   workflow edits, malicious filenames, expired/missing uploads, and reports from failing jobs.
   Confirm token scope and no credential persistence. No privileged triggers or shared caches.
5. Adopt in one pilot repository only after sandbox execution passes and maintainers choose
   baseline finding rules and enforcement. Keep observations distinct and coverage gaps visible.

Local unit tests do not verify GitHub runtime extraction, caller trust enforcement, artifact
permissions, fork availability or hosted action execution. These remain explicit adoption gaps.

GitHub primary references (consulted 2026-11-02):
[reusing workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
[reusable workflow context](https://github.com/github/docs/blob/main/content/actions/reference/workflows-and-actions/reusing-workflow-configurations.md),
[artifact digest validation](https://docs.github.com/en/actions/tutorials/store-and-share-data).
Action SHAs were resolved read-only from official `actions/checkout`, `actions/download-artifact`
and `actions/upload-artifact` v4 Git refs; pins require continued security review before adoption.
