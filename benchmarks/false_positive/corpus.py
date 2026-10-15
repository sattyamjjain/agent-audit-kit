#!/usr/bin/env python3
"""Benign-slice derivation for the false-positive benchmark.

Derives a BENIGN SLICE from the committed corpus manifest
(`research/state-of-mcp-2026/corpus/registry-manifest.json`) via an explicit,
pre-registered, NON-CIRCULAR predicate. "Benign" is a property of the server's
own published metadata — it is deliberately NOT defined as "AAK found nothing".

Pre-registered predicate — a server is in the benign slice iff ALL hold:

  1. It is an **official MCP Registry** latest-version server (`source = registry`
     in the manifest; the manifest already filtered to `isLatest = true`).
  2. Its registry `status` is **active**.
  3. It **declares an auth mode** — `auth_mode` is one of
     {`static-credential`, `header-nonsecret`, `local-stdio`}, i.e. NOT `none`
     and NOT `unknown`. Declaring auth (or being a local stdio server that keeps
     secrets in env) is a curation signal that the deployment is intentional.
  4. It is **not present in any CVE / advisory feed AgentAuditKit ships**
     (`agent_audit_kit/data/vuln_db.json` package names + the CVE version-pin
     package names in `mcp_cve_pins_2026_07`), matched by the server's name /
     package identifier.

Substitution note (honesty): the suggested "repo >= N stars" conjunct is NOT
used. Neither the MCP Registry API nor the cached raw data exposes GitHub stars
or a repository URL, and fetching stars for hundreds of repos would require a
networked GitHub-API pass — this benchmark is offline by construction. Predicate
(1)+(2) (official, active, latest) is the offline curation proxy that replaces
the stars signal. This substitution is disclosed in README + RESULTS.md.

This module is pure: it reads committed files, hits no network, writes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[1]
MANIFEST = _REPO / "research" / "state-of-mcp-2026" / "corpus" / "registry-manifest.json"
_VULN_DB = _REPO / "agent_audit_kit" / "data" / "vuln_db.json"

_DECLARED_AUTH = frozenset({"static-credential", "header-nonsecret", "local-stdio"})

PREDICATE = (
    "official MCP Registry latest-version server AND status=active AND "
    "auth_mode in {static-credential, header-nonsecret, local-stdio} AND "
    "not in AAK's shipped CVE/advisory feed (vuln_db.json + CVE-pin package names)"
)


def cve_feed_identifiers() -> frozenset[str]:
    """Package identifiers AAK ships as known-vulnerable — the exclusion set.

    Reuses `agent_audit_kit/data/vuln_db.json` (npm/python/rust keys +
    dmca_blocklist) and the CVE version-pin package names in
    `mcp_cve_pins_2026_07._PINS`. Lower-cased for case-insensitive matching.
    """
    ids: set[str] = set()
    try:
        db = json.loads(_VULN_DB.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        db = {}
    for ecosystem in ("npm", "python", "rust"):
        for pkg in (db.get(ecosystem) or {}):
            ids.add(str(pkg).lower())
    for pkg in db.get("dmca_blocklist") or []:
        ids.add(str(pkg).lower())
    try:
        from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS
        for pin in _PINS:
            for name in pin.names:
                ids.add(str(name).lower())
    except ImportError:
        pass
    return frozenset(ids)


def _package_name(token: str) -> str:
    """A launch argument without its version: `@scope/pkg@1.2.3` -> `@scope/pkg`.

    Since report v1.1 the manifest's configs launch the version the registry
    record states (`npx -y pkg@1.2.3`, `uvx pkg@1.2.3`), and the CVE feed names
    bare packages. Matching the versioned spec would let a package the feed
    names into the slice: 8 servers on the 2026-07-26 snapshot.
    """
    token = token.split("==", 1)[0]
    at = token.find("@", 1)
    return token if at == -1 else token[:at]


def _server_identifiers(server: dict[str, Any]) -> set[str]:
    """Candidate package/name tokens for a server, for CVE-feed matching."""
    out: set[str] = set()
    name = str(server.get("name") or "").lower()
    if name:
        out.add(name)
        out.add(name.split("/")[-1])
    cfg = server.get("config") or {}
    for entry in (cfg.get("mcpServers") or {}).values():
        if not isinstance(entry, dict):
            continue
        args = entry.get("args") or []
        for a in args:
            tok = _package_name(str(a).strip().lower())
            if tok and not tok.startswith("-"):
                out.add(tok)
                out.add(tok.split("/")[-1])
    return {t for t in out if t}


def is_benign(server: dict[str, Any], cve_ids: frozenset[str]) -> bool:
    """The pre-registered benign predicate. Pure function of its inputs."""
    if server.get("registry_status") != "active":
        return False
    if server.get("auth_mode") not in _DECLARED_AUTH:
        return False
    if _server_identifiers(server) & cve_ids:
        return False
    return True


def benign_slice(manifest_path: Path | None = None) -> list[dict[str, Any]]:
    """Return the benign-slice servers, sorted by name (deterministic)."""
    path = manifest_path or MANIFEST
    data = json.loads(path.read_text(encoding="utf-8"))
    cve_ids = cve_feed_identifiers()
    slice_ = [s for s in data.get("servers", []) if is_benign(s, cve_ids)]
    return sorted(slice_, key=lambda s: str(s.get("name")))


# Fields carried into the published slice manifest. `config` is deliberately
# excluded: it is derived from the upstream record and would double the file for
# no provenance value. Everything here is the server's own registry metadata.
_PROVENANCE_FIELDS = (
    "name",
    "version",
    "transport",
    "auth_mode",
    "source_url",
    "registry_status",
    "published_at",
    "fetched_at",
)


def slice_manifest(manifest_path: Path | None = None) -> dict[str, Any]:
    """The benign slice as a citable, auditable artifact.

    The predicate makes the slice *re-derivable*; this makes it *inspectable*.
    Without it a reader has to run the code to learn which servers were measured,
    which is the difference between a reproducible number and a checkable one.

    Provenance per server is the registry's own: `source_url` (the endpoint the
    server publishes), `version`, `registry_status`, `published_at`, and the
    `fetched_at` date of the snapshot it was read from. Corpus-level provenance
    is the upstream API URL carried through from the manifest.
    """
    path = manifest_path or MANIFEST
    upstream = json.loads(path.read_text(encoding="utf-8"))
    servers = benign_slice(path)
    from collections import Counter

    return {
        "predicate": PREDICATE,
        "source": upstream.get("source"),
        "source_fetched_at": upstream.get("fetched_at"),
        "upstream_servers": len(upstream.get("servers") or []),
        "n": len(servers),
        "auth_mode_distribution": dict(
            sorted(Counter(s.get("auth_mode") for s in servers).items())
        ),
        "transport_distribution": dict(
            sorted(Counter(s.get("transport") for s in servers).items())
        ),
        "servers": [
            {k: s.get(k) for k in _PROVENANCE_FIELDS if s.get(k) is not None}
            for s in servers
        ],
    }


SLICE_JSON = _HERE / "benign-slice.json"


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Derive and inspect the benign slice.")
    ap.add_argument(
        "--write", action="store_true", help="(Re)write benign-slice.json."
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if benign-slice.json is stale vs a fresh derivation.",
    )
    args = ap.parse_args()

    data = slice_manifest()
    blob = json.dumps(data, indent=2, sort_keys=True) + "\n"

    if args.check:
        current = SLICE_JSON.read_text(encoding="utf-8") if SLICE_JSON.is_file() else ""
        if current != blob:
            print(
                "benign-slice.json is stale vs the corpus manifest - run "
                "'make fp' and commit",
                flush=True,
            )
            return 1
        print(f"benign-slice.json is up to date (n = {data['n']})")
        return 0

    if args.write:
        SLICE_JSON.write_text(blob, encoding="utf-8")
        print(f"wrote {SLICE_JSON.name} (n = {data['n']})")

    print(f"benign slice: n = {data['n']}")
    print("predicate:", PREDICATE)
    print("auth_mode dist:", data["auth_mode_distribution"])
    print("transport dist:", data["transport_distribution"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
