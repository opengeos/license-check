"""Registry clients. They return normalized facts, never raw response bodies."""

from olc import versions as V


def sort_versions(names, ecosystem):
    """(sorted parsable versions, unparsable versions)."""
    good, bad = [], []
    for name in names:
        try:
            good.append((V.version_key(name, ecosystem), name))
        except V.VersionError:
            bad.append(name)
    return [n for _, n in sorted(good)], sorted(bad)


def highest_final(names, ecosystem, exclude=()):
    best = None
    for name in names:
        if name in exclude:
            continue
        try:
            if V.is_prerelease(name, ecosystem):
                continue
            key = V.version_key(name, ecosystem)
        except V.VersionError:
            continue
        if best is None or key > best[0]:
            best = (key, name)
    return best[1] if best else None
