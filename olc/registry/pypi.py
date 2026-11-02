"""PyPI facts: versions, files, sha256 digests and yanks, from the JSON API."""

import re

from olc import net
from olc.pymeta import normalize
from olc.registry import highest_final, sort_versions

BASE = "https://pypi.org"
SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
CLASSES = {"bdist_wheel": "wheel", "sdist": "sdist"}


def _file(f, transport):
    url = f.get("url")
    ok = isinstance(url, str) and transport.allowed(url)
    sha = (f.get("digests") or {}).get("sha256")
    digest = None
    if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        digest = {"alg": "sha256", "value": sha.lower(), "encoding": "hex", "source": "pypi-json"}
    ptype = f.get("packagetype")
    size = f.get("size")
    out = {"filename": str(f.get("filename") or ""), "url": url if ok else None,
           "class": CLASSES.get(ptype, "other"), "packagetype": ptype,
           "size": size if isinstance(size, int) and not isinstance(size, bool) else None,
           "uploaded_at": f.get("upload_time_iso_8601") or f.get("upload_time"),
           "yanked": bool(f.get("yanked")), "yanked_reason": f.get("yanked_reason"),
           "published_digest": digest}
    if url and not ok:
        out["url_rejected"] = True
    return out


def _version(version, files, source, info=None):
    times = sorted(f["uploaded_at"] for f in files if f["uploaded_at"])
    yanked = bool(files) and all(f["yanked"] for f in files)
    reason = next((f["yanked_reason"] for f in files if f["yanked_reason"]), None)
    if info is not None and "yanked" in info:
        yanked = bool(info.get("yanked"))
        reason = info.get("yanked_reason") or reason
    return {"version": version, "published_at": times[0] if times else None,
            "yanked": yanked, "yanked_reason": reason, "deprecated": None,
            "files_source": source, "files": files}


def collect(package, versions=None, transport=None):
    t = transport or net.Transport()
    name = normalize(package)
    data = t.get_json(f"{BASE}/pypi/{net.quote(name)}/json")
    if not isinstance(data, dict):
        raise net.NetError("malformed", f"{BASE}/pypi/{name}/json")
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    releases = data.get("releases")
    if isinstance(releases, dict):
        all_files = {v: [_file(f, t) for f in fs if isinstance(f, dict)]
                     for v, fs in releases.items() if isinstance(fs, list)}
        names = list(all_files)
    else:
        simple = t.get_json(f"{BASE}/simple/{net.quote(name)}/", accept=SIMPLE_ACCEPT)
        names = [v for v in (simple.get("versions") or []) if isinstance(v, str)] \
            if isinstance(simple, dict) else []
        all_files = None
    ordered, unparsable = sort_versions(names, "pypi")
    fully_yanked = {v for v, fs in (all_files or {}).items() if not fs or all(f["yanked"] for f in fs)}
    out = {"ecosystem": "pypi", "package": name, "name": info.get("name"),
           "current": highest_final(names, "pypi", exclude=fully_yanked),
           "registry_latest": info.get("version"), "versions": [],
           "missing_versions": [], "unparsable_versions": unparsable}
    if versions is None:
        for v in ordered + unparsable:
            files = (all_files or {}).get(v, [])
            out["versions"].append(_version(v, files, "pypi-json-releases" if all_files is not None
                                            else "none"))
        return out
    for v in versions:
        try:
            vdata = t.get_json(f"{BASE}/pypi/{net.quote(name)}/{net.quote(v)}/json")
        except net.NetError as e:
            if e.code == "http-404":
                out["missing_versions"].append(v)
                continue
            raise
        if not isinstance(vdata, dict) or not isinstance(vdata.get("urls"), list):
            raise net.NetError("malformed", f"{BASE}/pypi/{name}/{v}/json")
        vinfo = vdata.get("info") if isinstance(vdata.get("info"), dict) else {}
        files = [_file(f, t) for f in vdata["urls"] if isinstance(f, dict)]
        out["versions"].append(_version(v, files, "pypi-version-json", vinfo))
    return out
