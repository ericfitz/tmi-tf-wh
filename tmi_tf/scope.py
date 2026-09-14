"""Environment scope parsing and matching (see spec 2026-09-13)."""

from fnmatch import fnmatchcase

LATEST = "latest"
ALL = "all"


def normalize_scope(value: str | None) -> str:
    """None/blank -> "latest"; otherwise stripped, lower-cased."""
    if value is None or not value.strip():
        return LATEST
    return value.strip().lower()


def match_environments(
    scope: str, names: list[str]
) -> tuple[list[str], list[tuple[str, str]]]:
    """Return (matched, skipped) where skipped is [(name, reason)].

    scope "all": every name matched. scope "latest": raises ValueError (caller
    resolves latest with git; see Task 5). Otherwise: comma-separated
    fnmatch patterns, case-insensitive; a name is matched if any pattern
    matches; reason for skipped names is "not in scope"; patterns that
    matched nothing are returned as skipped entries ("<pattern>", "pattern
    matched no environment").
    """
    scope = normalize_scope(scope)
    if scope == LATEST:
        raise ValueError("latest scope must be resolved with git history")
    if scope == ALL:
        return list(names), []

    patterns = [p.strip() for p in scope.split(",") if p.strip()]
    matched: list[str] = []
    skipped: list[tuple[str, str]] = []
    used: set[str] = set()
    for name in names:
        hits = [p for p in patterns if fnmatchcase(name.lower(), p)]
        if hits:
            matched.append(name)
            used.update(hits)
        else:
            skipped.append((name, "not in scope"))
    for p in patterns:
        if p not in used:
            skipped.append((p, "pattern matched no environment"))
    return matched, skipped
