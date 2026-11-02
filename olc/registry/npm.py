"""npm facts: versions, tarballs, sha512 integrity, deprecations, attestation presence."""

import base64

from olc import net
from olc.registry import highest_final, sort_versions

BASE = "https://registry.npmjs.org"


def _integrity(text):
    if not isinstance(text, str):
        return None
    for part in text.split():
        alg, _, value = part.partition("-")
        if alg == "sha512" and value:
            try:
                if len(base64.b64decode(value, validate=True)) == 64:
                    return value
            except ValueError:
                return None
    return None


def _version(version, record, times, transport):
    dist = record.get("dist") if isinstance(record.get("dist"), dict) else {}
    url = dist.get("tarball")
    ok = isinstance(url, str) and transport.allowed(url)
    filename = net.url_basename(url) if isinstance(url, str) else ""
    sha512 = _integrity(dist.get("integrity"))
    deprecated = record.get("deprecated")
    file = {"filename": filename, "url": url if ok else None, "class": "npm-tarball",
            "size": None, "uploaded_at": times.get(version), "yanked": False,
            "published_digest": {"alg": "sha512", "value": sha512, "encoding": "base64",
                                 "source": "npm-packument"} if sha512 else None}
    if url and not ok:
        file["url_rejected"] = True
    return {"version": version, "published_at": times.get(version), "yanked": False,
            "yanked_reason": None,
            "deprecated": deprecated if isinstance(deprecated, str) and deprecated else None,
            "files_source": "npm-packument", "files": [file] if url else [],
            "file_count": dist.get("fileCount"), "unpacked_size": dist.get("unpackedSize"),
            "attestations": bool(dist.get("attestations")), "shasum": dist.get("shasum")}


def collect(package, versions=None, transport=None):
    t = transport or net.Transport()
    data = t.get_json(f"{BASE}/{net.quote(package)}")
    if not isinstance(data, dict):
        raise net.NetError("malformed", f"{BASE}/{package}")
    records = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    times = data.get("time") if isinstance(data.get("time"), dict) else {}
    tags = data.get("dist-tags") if isinstance(data.get("dist-tags"), dict) else {}
    ordered, unparsable = sort_versions(list(records), "npm")
    deprecated = {v for v, r in records.items()
                  if isinstance(r, dict) and isinstance(r.get("deprecated"), str) and r["deprecated"]}
    latest = tags.get("latest")
    current = latest if latest in records and highest_final([latest], "npm") == latest \
        else highest_final(list(records), "npm", exclude=deprecated)
    out = {"ecosystem": "npm", "package": package, "name": data.get("name"),
           "current": current, "registry_latest": latest,
           "dist_tags": {k: v for k, v in tags.items() if isinstance(v, str)},
           "versions": [], "missing_versions": [], "unparsable_versions": unparsable,
           "unpublished_versions": sorted(
               k for k in times if k not in ("created", "modified", "unpublished")
               and k not in records)}
    wanted = ordered + unparsable if versions is None else versions
    for v in wanted:
        record = records.get(v)
        if not isinstance(record, dict):
            out["missing_versions"].append(v)
            continue
        out["versions"].append(_version(v, record, times, t))
    return out
