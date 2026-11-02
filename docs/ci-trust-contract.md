# CI trust contract (design only)

There is no workflow file in this repository. This is the bar a future reusable workflow that runs
the checker on pull requests must meet before anyone adopts it.

- **Trigger and runners:** `pull_request` only, never `pull_request_target`, or `workflow_run`
  running pull request code; ephemeral GitHub-hosted runners.
- **Permissions and credentials:** `permissions: contents: read`; `actions/checkout` with
  `persist-credentials: false`; no secrets; no caches shared with trusted workflows.
- **Pinning:** the checker and its policy are checked out at pinned immutable commit SHAs chosen by
  the calling repository's protected default branch, never from a pull-request-controlled input,
  into a directory separate from the target.
- **Target code is data:** the checker never imports or runs it. Any build is a separate job with
  no access to the checker's outputs; the checker inspects only the uploaded artifacts.
- **Untrusted input:** no `build-command` input. No untrusted value is interpolated into `run:`;
  values pass through environment variables and are quoted. Reports escape Markdown and HTML.
- **Policy and exceptions:** the baseline policy, declarations and exceptions are read from the
  base revision. Changes to them in the pull request are reported as requests needing approval
  (`review`), and coverage of the affected paths is rescanned.
- **Declarations** need the pinned upstream source and path, the observed licence evidence, the
  copyright holders, a modification note where relevant, and a mapping from each obligation to the
  shipped artifact path. A declaration never silences a conflicting observed signal.
- **Validation:** before adoption, the trust boundary is tested in a sandbox repository. Schema
  validation of the workflow file alone does not meet this bar.
