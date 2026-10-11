"""The compact, citable context a classifier sees for one CVE.

Pure functions only: raw NVD / GHSA / OSV JSON in, one small JSON object out.
No network and no clock, so a fixture test can pin the exact output.

Why compact. A raw NVD record carries scoring metadata, SSVC blocks and long
reference lists; a GHSA description is free markdown with tables and proof of
concept code; an OSV record built from a git range lists every tag. None of it
helps decide a disposition, all of it costs tokens, and the free text is the
part a prompt injection would ride in on. The context keeps the fields a
maintainer reads when triaging (description, CWEs, CPE and CNA ranges, the
structured affected packages, fixed versions, references) and drops the rest.

Why citable. The classifier must copy a package, ecosystem, range or fixed
version from a structured field and name that field. The names here are the
contract for those citations: `resolve_path(context, "ghsa[0].vulnerabilities[1].name")`
returns the value the model claims to have copied, and `verify_citation` checks
it character for character. Field names follow their source (a repository
advisory says `patched_versions`, a global one `first_patched_version`), so a
citation reads as provenance, not as a schema this module invented.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA = "aak-cve-prescreen-context/1"

#: Caps keep one record's context bounded whatever the advisory looks like.
MAX_REFERENCES = 30
MAX_GHSA_REFERENCES = 15
MAX_EVENTS_PER_RANGE = 12
MAX_CPE_MATCHES = 25
DESCRIPTION_EXCERPT_CHARS = 1500

#: Fields whose values an extraction may cite. Everything else in the context
#: (descriptions, summaries, URLs) is free text or metadata, and a package name
#: copied out of prose is exactly the invention the citation rule forbids.
STRUCTURED_LEAVES = frozenset({
    "vendor", "product", "version", "lessThan", "lessThanOrEqual",
    "packageName", "criteria", "version_start_including", "version_start_excluding",
    "version_end_including", "version_end_excluding",
    "ecosystem", "name", "purl", "vulnerable_version_range",
    "first_patched_version", "patched_versions",
    "introduced", "fixed", "last_affected", "limit",
})


def _en_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            return str(entry.get("value") or "")
    return ""


def _cwes_from_nvd(cve: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "")
            if value.startswith("CWE-"):
                found.add(value)
    return sorted(found)


def _cvss_from_nvd(cve: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            out.append({
                "version": str(data.get("version") or ""),
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "source": metric.get("source"),
                "type": metric.get("type"),
            })
    return out


def _nvd_affected(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """The CNA's own affected block, which NVD 2.0 now carries verbatim."""
    out: list[dict[str, Any]] = []
    for block in cve.get("affected") or []:
        for item in block.get("affectedData") or []:
            versions = []
            for ver in item.get("versions") or []:
                kept = {
                    k: ver[k]
                    for k in ("version", "lessThan", "lessThanOrEqual", "status", "versionType")
                    if k in ver
                }
                versions.append(kept)
            entry: dict[str, Any] = {
                "vendor": item.get("vendor"),
                "product": item.get("product"),
                "versions": versions,
            }
            for extra in ("packageName", "collectionURL", "defaultStatus"):
                if item.get(extra):
                    entry[extra] = item[extra]
            out.append(entry)
    return out


def _cpe_matches(cve: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                out.append({
                    "criteria": match.get("criteria"),
                    "vulnerable": bool(match.get("vulnerable")),
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                })
                if len(out) >= MAX_CPE_MATCHES:
                    return out
    return out


def _nvd_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for ref in (cve.get("references") or [])[:MAX_REFERENCES]:
        item: dict[str, Any] = {"url": ref.get("url")}
        if ref.get("tags"):
            item["tags"] = list(ref["tags"])
        out.append(item)
    return out


def nvd_section(nvd_payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """The NVD half of the context, or None when NVD has no record."""
    if not nvd_payload:
        return None
    vulns = nvd_payload.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    return {
        "status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "source_identifier": cve.get("sourceIdentifier"),
        "description": _en_description(cve),
        "cwes": _cwes_from_nvd(cve),
        "cvss": _cvss_from_nvd(cve),
        "affected": _nvd_affected(cve),
        "cpe_matches": _cpe_matches(cve),
        "references": _nvd_references(cve),
    }


def _ghsa_cwes(advisory: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for cwe in advisory.get("cwes") or []:
        if isinstance(cwe, dict) and cwe.get("cwe_id"):
            found.add(str(cwe["cwe_id"]))
    for cwe_id in advisory.get("cwe_ids") or []:
        found.add(str(cwe_id))
    return sorted(found)


def _ghsa_references(advisory: dict[str, Any]) -> list[str]:
    refs = advisory.get("references") or []
    out: list[str] = []
    for ref in refs[:MAX_GHSA_REFERENCES]:
        url = ref.get("url") if isinstance(ref, dict) else ref
        if url:
            out.append(str(url))
    return out


def ghsa_entry(advisory: dict[str, Any], kind: str) -> dict[str, Any]:
    """One advisory: a global one from `/advisories`, or a repository one.

    The two endpoints name the fix differently (`first_patched_version` against
    `patched_versions`). Both keys are kept as the source spells them.
    """
    vulns = []
    for vuln in advisory.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        item: dict[str, Any] = {
            "ecosystem": pkg.get("ecosystem"),
            "name": pkg.get("name"),
            "vulnerable_version_range": vuln.get("vulnerable_version_range"),
        }
        if "first_patched_version" in vuln:
            fpv = vuln.get("first_patched_version")
            # Older payloads nest it as {"identifier": "1.2.3"}.
            if isinstance(fpv, dict):
                fpv = fpv.get("identifier")
            item["first_patched_version"] = fpv
        if "patched_versions" in vuln:
            item["patched_versions"] = vuln.get("patched_versions")
        vulns.append(item)
    description = str(advisory.get("description") or "")
    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "kind": kind,
        "type": advisory.get("type"),
        "summary": advisory.get("summary"),
        "severity": advisory.get("severity"),
        "cwes": _ghsa_cwes(advisory),
        "source_code_location": advisory.get("source_code_location"),
        "published_at": advisory.get("published_at"),
        "withdrawn_at": advisory.get("withdrawn_at"),
        "vulnerabilities": vulns,
        "references": _ghsa_references(advisory),
        "description_excerpt": description[:DESCRIPTION_EXCERPT_CHARS],
        "description_truncated": len(description) > DESCRIPTION_EXCERPT_CHARS,
    }


def _osv_range(rng: dict[str, Any]) -> dict[str, Any]:
    events = []
    for event in (rng.get("events") or [])[:MAX_EVENTS_PER_RANGE]:
        events.append({k: event[k] for k in ("introduced", "fixed", "last_affected", "limit") if k in event})
    item: dict[str, Any] = {"type": rng.get("type"), "events": events}
    if rng.get("repo"):
        item["repo"] = rng["repo"]
    extracted = (rng.get("database_specific") or {}).get("extracted_events")
    if extracted:
        item["extracted_events"] = [
            {k: e[k] for k in ("introduced", "fixed", "last_affected", "limit") if k in e}
            for e in extracted[:MAX_EVENTS_PER_RANGE]
        ]
    return item


def osv_entry(record: dict[str, Any]) -> dict[str, Any]:
    affected = []
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        item: dict[str, Any] = {
            "ecosystem": pkg.get("ecosystem"),
            "name": pkg.get("name"),
            "ranges": [_osv_range(r) for r in aff.get("ranges") or []],
            "versions_listed": len(aff.get("versions") or []),
        }
        if pkg.get("purl"):
            item["purl"] = pkg["purl"]
        affected.append(item)
    return {
        "id": record.get("id"),
        "aliases": sorted(record.get("aliases") or []),
        "summary": record.get("summary"),
        "withdrawn": record.get("withdrawn"),
        "affected": affected,
    }


def build_context(
    cve_id: str,
    nvd_payload: dict[str, Any] | None,
    ghsa_global: list[dict[str, Any]],
    ghsa_repository: list[dict[str, Any]],
    osv_records: list[dict[str, Any]],
    source_status: dict[str, str],
) -> dict[str, Any]:
    """Assemble the context. Ordering is deterministic so the digest is stable."""
    ghsa = [ghsa_entry(a, "global") for a in sorted(ghsa_global, key=lambda a: str(a.get("ghsa_id")))]
    seen = {g["ghsa_id"] for g in ghsa}
    for adv in sorted(ghsa_repository, key=lambda a: str(a.get("ghsa_id"))):
        if adv.get("ghsa_id") not in seen:
            ghsa.append(ghsa_entry(adv, "repository"))
            seen.add(adv.get("ghsa_id"))
    # The CVE's own OSV record first, then the rest by id.
    osv_sorted = sorted(osv_records, key=lambda r: (r.get("id") != cve_id, str(r.get("id"))))
    return {
        "schema": SCHEMA,
        "cve_id": cve_id,
        "sources": dict(sorted(source_status.items())),
        "nvd": nvd_section(nvd_payload),
        "ghsa": ghsa,
        "osv": [osv_entry(r) for r in osv_sorted],
    }


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def context_digest(context: dict[str, Any]) -> str:
    """SHA-256 of the canonical context: what a result row says it was given."""
    return hashlib.sha256(canonical_json(context).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Citation paths: `nvd.affected[0].versions[1].version`
# ---------------------------------------------------------------------------


class PathError(ValueError):
    """A citation that is not a well-formed path."""


def parse_path(path: str) -> list[str | int]:
    """Split `a.b[2].c` into `["a", "b", 2, "c"]`.

    A hand-rolled scanner rather than a regex: a citation is model output, so
    the parser should be linear on any input and reject anything unusual
    instead of guessing what it meant.
    """
    tokens: list[str | int] = []
    i, n = 0, len(path)
    if n == 0 or n > 300:
        raise PathError("empty or overlong path")
    expect_key = True
    while i < n:
        ch = path[i]
        if ch == "[":
            j = path.find("]", i + 1)
            if j == -1 or j == i + 1 or not path[i + 1:j].isdigit():
                raise PathError(f"bad index at {i}")
            tokens.append(int(path[i + 1:j]))
            i = j + 1
            expect_key = False
        elif ch == ".":
            if expect_key:
                raise PathError(f"empty key at {i}")
            i += 1
            expect_key = True
        else:
            j = i
            while j < n and (path[j].isalnum() or path[j] == "_"):
                j += 1
            if j == i:
                raise PathError(f"unexpected {ch!r} at {i}")
            if tokens and not expect_key:
                raise PathError(f"missing separator at {i}")
            tokens.append(path[i:j])
            i = j
            expect_key = False
    if expect_key:
        raise PathError("trailing separator")
    return tokens


def resolve_path(context: Any, path: str) -> tuple[bool, Any]:
    """`(True, value)` when the path exists in the context, else `(False, None)`."""
    try:
        tokens = parse_path(path)
    except PathError:
        return False, None
    node = context
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(node, list) or token >= len(node):
                return False, None
            node = node[token]
        else:
            if not isinstance(node, dict) or token not in node:
                return False, None
            node = node[token]
    return True, node


def structured_values(context: dict[str, Any]) -> dict[str, list[str]]:
    """Every citable leaf: value -> the paths that hold it.

    Used to tell a wrong citation (the value exists, under another path) from an
    invented value (it exists nowhere in the structured fields).
    """
    out: dict[str, list[str]] = {}

    def walk(node: Any, path: str, key: str | None) -> None:
        if isinstance(node, dict):
            for k in sorted(node):
                walk(node[k], f"{path}.{k}" if path else k, k)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                walk(item, f"{path}[{idx}]", key)
        elif isinstance(node, str) and key in STRUCTURED_LEAVES and node:
            out.setdefault(node, []).append(path)

    walk(context, "", None)
    return out


#: What a CNA writes when it has no product name. Not a package.
PLACEHOLDER_PRODUCTS = frozenset({"n/a", "na", "-", "*", "unknown", "unspecified", "not applicable"})


def expected_package_names(context: dict[str, Any]) -> list[str]:
    """The names a faithful extraction lists, by the prompt's own rule.

    Registry names from GHSA and OSV; only when neither names a package, the
    products NVD's CNA block names, minus placeholders such as `n/a`. Sorted,
    unique.
    """
    registry = sorted({name for _, name in structured_packages(context)})
    if registry:
        return registry
    nvd = context.get("nvd") or {}
    return sorted({
        str(a["product"]) for a in nvd.get("affected") or []
        if a.get("product") and str(a["product"]).strip().lower() not in PLACEHOLDER_PRODUCTS
    })


def structured_packages(context: dict[str, Any]) -> list[tuple[str, str]]:
    """`(ecosystem, name)` pairs the structured sources name, sorted, unique.

    GHSA and OSV ECOSYSTEM packages only: those are the sources that carry a
    registry identity. NVD's CNA block names a vendor and product, which is not
    a registry name, and a GIT range in OSV names a repository.
    """
    pairs: set[tuple[str, str]] = set()
    for adv in context.get("ghsa") or []:
        for vuln in adv.get("vulnerabilities") or []:
            if vuln.get("name"):
                pairs.add((str(vuln.get("ecosystem") or ""), str(vuln["name"])))
    for rec in context.get("osv") or []:
        for aff in rec.get("affected") or []:
            if aff.get("name"):
                pairs.add((str(aff.get("ecosystem") or ""), str(aff["name"])))
    return sorted(pairs)
