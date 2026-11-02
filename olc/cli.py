"""Command line: `python -I -m olc <command>`. Exit codes are in olc.result."""

import argparse
import json
import sys
from pathlib import Path

from olc import result
from olc.errors import InputError


def _load_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read {what} {path}: {e}") from None


def _write(obj, out):
    text = json.dumps(obj, indent=1, ensure_ascii=False) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def cmd_inspect(args):
    from olc.inspect import cwd_inside, inspect_artifacts
    from olc.policy import default_policy_path

    spec = _load_json(args.artifacts, "artifacts")
    base = Path(args.artifacts).resolve().parent
    target = engine_rev = None
    if isinstance(spec, dict):
        target, engine_rev = spec.get("target"), spec.get("engine_rev")
        spec = spec.get("artifacts")
    if not isinstance(spec, list):
        raise InputError("artifacts file must hold a list or {\"artifacts\": [...]}")
    for art in spec:
        if isinstance(art, dict) and isinstance(art.get("path"), str):
            art["path"] = str(base / art["path"])
    if cwd_inside(a["path"] for a in spec if isinstance(a, dict) and "path" in a):
        raise InputError("run inspect from a directory other than the artifacts' directory")
    rules = _load_json(args.rules, "rules")
    policy = _load_json(args.policy or default_policy_path(), "policy")
    limits = _load_json(args.limits, "limits") if args.limits else None
    out = inspect_artifacts(spec, rules, policy, limits, target=target, engine_rev=engine_rev)
    _write(out, args.out)
    print(f"{out['verdict']} (finding checks: {out['finding_verdict']})", file=sys.stderr)
    return result.exit_code(out["verdict"])


def cmd_spdx(args):
    from olc import spdx
    from olc.policy import default_policy_path, load_policy

    policy = load_policy(args.policy or default_policy_path())
    out = spdx.evaluate(args.expression, policy, args.profile)
    _write(out, None)
    return {"allow": 0, "deny": 1, "review": 2}[out["verdict"]]


def cmd_registry(args):
    from olc.registry import npm, pypi

    module = {"pypi": pypi, "npm": npm}[args.ecosystem]
    _write(module.collect(args.package, args.version or None), args.out)
    return 0


def cmd_download(args):
    from olc import net

    info = net.Transport().download(args.url, args.destination)
    _write({**info, "path": str(info["path"])}, None)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="olc", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inspect", help="run rules over local artifacts (no network)")
    p.add_argument("--rules", required=True)
    p.add_argument("--artifacts", required=True)
    p.add_argument("--policy")
    p.add_argument("--limits")
    p.add_argument("--out")
    p.set_defaults(func=cmd_inspect)
    p = sub.add_parser("spdx", help="evaluate an SPDX expression against the policy")
    p.add_argument("expression")
    p.add_argument("--policy")
    p.add_argument("--profile")
    p.set_defaults(func=cmd_spdx)
    p = sub.add_parser("registry", help="print normalized registry facts (network GET)")
    p.add_argument("ecosystem", choices=["pypi", "npm"])
    p.add_argument("package")
    p.add_argument("--version", action="append")
    p.add_argument("--out")
    p.set_defaults(func=cmd_registry)
    p = sub.add_parser("download", help="download one allowlisted URL into a directory")
    p.add_argument("url")
    p.add_argument("destination")
    p.set_defaults(func=cmd_download)
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return result.EXIT_INVALID if e.code else 0
    from olc.net import NetError
    from olc.versions import VersionError
    try:
        return args.func(args)
    except (InputError, VersionError) as e:
        print(f"invalid input: {e}", file=sys.stderr)
        return result.EXIT_INVALID
    except NetError as e:
        print(f"network error: {e}", file=sys.stderr)
        return result.EXIT_CODES[result.INCOMPLETE]
    except Exception as e:  # noqa: BLE001 - the contract maps anything else to exit 5
        print(f"internal error: {type(e).__name__}: {e}", file=sys.stderr)
        return result.EXIT_INTERNAL
