"""Check every extracted value against the structured field it cites.

The classifier is told to copy package names, ecosystems, ranges and fixed
versions character for character from the context, and to name the path it
copied each one from. This module holds it to that, offline:

* **exact**: the cited path resolves, names a structured field, and holds
  exactly the value given.
* **bad path**: the citation does not resolve, or is not a path at all.
* **free text**: the citation resolves to a description, summary or URL field,
  which the prompt forbids as a source.
* **whitespace**: the cited field holds the same text with different
  whitespace, such as a no-break space typed as a space. Not exact, because
  the prompt asks for a character-for-character copy, and not invented.
* **mismatch**: the path resolves to a structured field holding something else.
* **invented**: the value appears in no structured field anywhere in the
  context, even with whitespace normalised. This is the failure that matters
  most: a package or version the model made up, which a maintainer could paste
  into a pin.

It also compares the *set* of package names the model listed with the set the
prompt's rule asks for (`context.expected_package_names`: GHSA and OSV registry
names, else NVD's CNA products), so an answer that copies one package correctly
and silently drops a second one does not score as perfect.
"""

from __future__ import annotations

from typing import Any

from benchmarks.cve_prescreen.context import (
    STRUCTURED_LEAVES,
    PathError,
    expected_package_names,
    parse_path,
    resolve_path,
    structured_values,
)

KINDS = ("name", "ecosystem", "ranges", "fixed_versions")


def _norm(text: str) -> str:
    """Whitespace collapsed; `str.split` treats a no-break space as whitespace."""
    return " ".join(text.split())


def check_value(
    context: dict[str, Any],
    cited: Any,
    index: dict[str, list[str]],
    normalised: set[str] | None = None,
) -> dict[str, Any]:
    """One `{value, source}` pair, judged."""
    if not isinstance(cited, dict):
        return {"value": None, "source": None, "verdict": "malformed"}
    value = cited.get("value")
    source = cited.get("source")
    out: dict[str, Any] = {"value": value, "source": source}
    norm_index = normalised if normalised is not None else {_norm(k) for k in index}
    present = isinstance(value, str) and (value in index or _norm(value) in norm_index)
    try:
        tokens = parse_path(str(source or ""))
    except PathError:
        tokens = []
    found, held = resolve_path(context, str(source or "")) if tokens else (False, None)
    last_key = next((t for t in reversed(tokens) if isinstance(t, str)), "")
    if not found:
        out["verdict"] = "bad-path" if present else "invented"
    elif last_key not in STRUCTURED_LEAVES:
        out["verdict"] = "free-text" if not present else "free-text-but-present"
    elif held == value:
        out["verdict"] = "exact"
    elif isinstance(held, str) and isinstance(value, str) and _norm(held) == _norm(value):
        out["verdict"] = "whitespace"
    else:
        out["verdict"] = "mismatch" if present else "invented"
    out["value_in_structured_fields"] = present
    return out


def verify_affected(context: dict[str, Any], affected: Any) -> dict[str, Any]:
    """Judge a whole `affected` list. Returns counts plus every per-value verdict."""
    index = structured_values(context)
    normalised = {_norm(k) for k in index}
    checks: list[dict[str, Any]] = []
    names: list[str] = []
    if not isinstance(affected, list):
        affected = []
    for pkg in affected:
        if not isinstance(pkg, dict):
            checks.append({"kind": "package", "verdict": "malformed"})
            continue
        for kind in KINDS:
            raw = pkg.get(kind)
            if raw is None:
                continue
            items = raw if isinstance(raw, list) else [raw]
            for cited in items:
                verdict = check_value(context, cited, index, normalised)
                verdict["kind"] = kind
                checks.append(verdict)
                if kind == "name" and isinstance(verdict.get("value"), str):
                    names.append(verdict["value"])

    counts: dict[str, int] = {}
    for item in checks:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    expected = expected_package_names(context)
    listed = sorted(set(names))
    return {
        "values": len(checks),
        "exact": counts.get("exact", 0),
        "verdicts": dict(sorted(counts.items())),
        "all_exact": bool(checks) and counts.get("exact", 0) == len(checks),
        "invented": counts.get("invented", 0),
        "packages_expected": expected,
        "packages_listed": listed,
        "package_set_exact": listed == expected,
        "packages_missing": [n for n in expected if n not in listed],
        "packages_extra": [n for n in listed if n not in expected],
        "checks": checks,
    }
