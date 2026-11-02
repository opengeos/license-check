# Artifact checker

Treat target artifacts as data; never import, build, install, or execute their contents.
Keep private findings and project-specific evidence outside this repository. Preserve
explicit pass, fail, review, and incomplete results and their coverage limits.

During task preparation, obtain the task owner's approval before publication or changes
to external repositories, registries, organization settings, CI deployment, or scheduling.
Follow the environment's host queue and scratch-storage rules for tests and downloads.
Preserve publication guards and hooks; check them before committing or publishing.

Read API.md before changing a public interface, and docs/result-contract.md before changing
verdict semantics. Run the unit suite after relevant code changes. The CI trust contract
in docs/ci-trust-contract.md governs any future workflow; this version has no deployed CI.
