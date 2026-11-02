"""Nonexecuting CI adapter. All paths in the manifest are hostile data.

Unpublished builds have explicit local-build identity, never registry authority.
The manifest digest identifies inspected bytes without establishing publisher integrity.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import stat

from olc.errors import InputError
from olc.inspect import inspect_artifacts
from olc.result import aggregate, exit_code


MAX_MANIFEST = 1024 * 1024


def confined(root, name):
    """Require a regular file below root with no symlink in any path component."""
    if not isinstance(name, str) or not name or "\\" in name:
        raise InputError("invalid relative file path")
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(p in ("", ".", "..") for p in name.split("/")):
        raise InputError("invalid relative file path")
    cursor = Path(root)
    if cursor.is_symlink() or not cursor.is_dir():
        raise InputError("invalid input root")
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise InputError("symlink input rejected")
    if not stat.S_ISREG(cursor.stat().st_mode):
        raise InputError("input must be a regular file")
    return cursor


def load_json(path):
    if path.stat().st_size > MAX_MANIFEST:
        raise InputError("configuration too large")
    return json.loads(path.read_text(encoding="utf-8"))


def inspect_build(artifact_root, baseline_root, candidate_root, engine_commit):
    """Read fixed baseline configuration and confined artifact paths, never target code.

    Caller must supply trusted baseline and immutable engine; this local adapter cannot
    establish GitHub branch protection or authenticate a caller's supplied revision.
    """
    if len(engine_commit) != 40 or any(c not in "0123456789abcdef" for c in engine_commit):
        raise InputError("engine commit must be a full lowercase SHA")
    artifact_root, baseline_root = Path(artifact_root), Path(baseline_root)
    manifest = load_json(confined(artifact_root, "manifest.json"))
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "artifacts"} \
            or manifest["schema"] != "olc.ci-artifacts/1":
        raise InputError("invalid CI manifest")
    entries = manifest["artifacts"]
    if not isinstance(entries, list) or not entries or len(entries) > 1000:
        raise InputError("manifest needs 1..1000 artifacts")
    artifacts, seen = [], set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"path", "class", "sha256"} \
                or item.get("class") not in ("wheel", "sdist", "npm-tarball"):
            raise InputError("artifact needs path, supported class and sha256")
        path = confined(artifact_root, item["path"])
        if path in seen or item["path"] == "manifest.json":
            raise InputError("duplicate or manifest artifact")
        seen.add(path)
        artifacts.append({"path": str(path), "filename": item["path"], "class": item["class"],
                          "expected_digest": {"alg": "sha256", "value": item["sha256"]},
                          "authority": {"kind": "ci-artifact"}})
    actual_files = set()
    for count, path in enumerate(artifact_root.rglob("*"), 1):
        if count > 10000:
            raise InputError("too many artifact directory entries")
        if path.is_symlink():
            raise InputError("symlink input rejected")
        if not path.is_dir() and not path.is_file():
            raise InputError("special artifact file rejected")
        if path.is_file() and path != artifact_root / "manifest.json":
            actual_files.add(path)
    if actual_files != seen:
        raise InputError("manifest must cover every artifact file")
    rules_path = confined(baseline_root, ".olc/rules.json")
    policy_path = confined(baseline_root, ".olc/policy.json")
    out = inspect_artifacts(artifacts, load_json(rules_path), load_json(policy_path),
                            engine_rev={"git": engine_commit, "dirty": False})
    changed = []
    for name in ("rules.json", "policy.json", "declarations.json", "exceptions.json"):
        relative = ".olc/" + name
        base = Path(baseline_root) / relative
        candidate = Path(candidate_root) / relative
        # Any missing/unsafe candidate is a review request, never authority.
        try:
            candidate_file = confined(candidate_root, relative)
            if candidate_file.stat().st_size > MAX_MANIFEST:
                raise InputError("candidate configuration too large")
            candidate_bytes = candidate_file.read_bytes()
            base_bytes = confined(baseline_root, relative).read_bytes()
            same = candidate_bytes == base_bytes
        except (OSError, InputError):
            same = not base.exists() and not candidate.exists() and not candidate.is_symlink()
        if not same:
            changed.append(name)
    out["ci"] = {"authority": "unpublished-local-build", "policy_changes": changed,
                 "transport_digest_is_publisher_integrity": False}
    if changed:
        out["verdict"] = aggregate([out["verdict"], "review"])
        out["notes"].append({"code": "baseline-change-needs-approval", "level": "review"})
    return out


def safe_summary(out):
    """No artifact-controlled strings enter Markdown or GitHub command channels."""
    verdict = out["verdict"]
    if verdict not in ("pass", "fail", "review", "incomplete"):
        raise InputError("invalid verdict")
    return ("Artifact license inspection: **" + verdict + "**.\n\n"
            "Authority: unpublished local build; transport digests do not establish publisher integrity.\n"
            "See the JSON report for content evidence and coverage limits.\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ("artifacts", "baseline", "candidate", "engine-commit", "report-root"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        out = inspect_build(args.artifacts, args.baseline, args.candidate, args.engine_commit)
        report_root = Path(args.report_root)
        # Must be a fresh directory, controlled by the trusted workflow, outside target inputs.
        resolved = report_root.resolve()
        for root in (args.artifacts, args.baseline, args.candidate):
            if resolved.is_relative_to(Path(root).resolve()):
                raise InputError("report root must be outside input trees")
        report_root.mkdir(parents=False, exist_ok=False)
        (report_root / "result.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        (report_root / "summary.md").write_text(safe_summary(out), encoding="utf-8")
        print("Artifact inspection finished; inspect the report files.")
        return exit_code(out["verdict"])
    except (InputError, OSError, ValueError, TypeError):
        print("Artifact inspection rejected invalid or unavailable input.")
        return 4
