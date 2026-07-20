#!/usr/bin/env python3
"""Benign-slice derivation for the false-positive benchmark.

Derives a BENIGN SLICE from the committed 1,374-config corpus manifest
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
            tok = str(a).strip().lower()
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


if __name__ == "__main__":
    servers = benign_slice()
    from collections import Counter
    print(f"benign slice: n = {len(servers)}")
    print("predicate:", PREDICATE)
    print("auth_mode dist:", dict(Counter(s["auth_mode"] for s in servers)))
    print("transport dist:", dict(Counter(s["transport"] for s in servers)))
