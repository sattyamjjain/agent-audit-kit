#!/usr/bin/env python3
"""Corpus builder: fetch public MCP servers from the official MCP Registry.

Pulls latest-version servers from https://registry.modelcontextprotocol.io
(cursor pagination, rate-limited, raw pages cached), converts each to a
scannable `.mcp.json`-shaped config, and records provenance — server name,
version, transport, auth mode, source URL, and fetch date — into
`corpus/registry-manifest.json`.

This is the ONLY network step. The report harness (`run_report.py`) scans the
cached manifest offline and deterministically, so every number in REPORT.md is
reproducible from the committed manifest without hitting the network.

Usage:
    python research/state-of-mcp-2026/fetch_registry.py --target 5000
    # re-convert the raw pages cached by an earlier fetch, offline, keeping its date
    python research/state-of-mcp-2026/fetch_registry.py --from-cache --fetched-at 2026-07-26
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
CACHE_DIR = HERE / "cache"
MANIFEST = CORPUS_DIR / "registry-manifest.json"

_SECRET_HEADER_NAMES = {"authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "token"}


def _http_get(url: str, timeout: int = 30) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "agent-audit-kit state-of-mcp-2026"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _transport_of(server: dict[str, Any]) -> str:
    for r in server.get("remotes") or []:
        t = (r.get("type") or "").lower()
        if "http" in t:
            return "streamable-http"
        if t == "sse":
            return "sse"
    for p in server.get("packages") or []:
        tr = p.get("transport")
        ttype = tr.get("type") if isinstance(tr, dict) else tr
        if ttype:
            return str(ttype).lower()
    return "unknown"


def _auth_mode(server: dict[str, Any]) -> str:
    remotes = server.get("remotes") or []
    if remotes:
        any_headers = False
        for r in remotes:
            headers = r.get("headers") or []
            if headers:
                any_headers = True
                for h in headers:
                    name = (h.get("name") or "").lower()
                    if h.get("isSecret") or name in _SECRET_HEADER_NAMES:
                        return "static-credential"
        return "header-nonsecret" if any_headers else "none"
    if server.get("packages"):
        return "local-stdio"
    return "unknown"


def _launch_spec(registry: str, ident: str, version: str | None) -> str:
    """The package spec a converted config launches, at the version the record states.

    A registry package names one release (`packages[].version`), and that is
    the release a client following the record installs. Up to report v1.0 the
    conversion dropped it, so all 161 npm and PyPI configs in the 2026-07-26
    snapshot were unpinned launches by construction, and the corpus measured
    the converter rather than the servers.

    npm takes `name@1.2.3`. PyPI takes uvx's own spelling, `name@1.2.3`:
    AAK-SUPPLY-001 reads it as an exact pin, as it does `name==1.2.3`, but
    AAK-MCP-007 counts any argument without an `@` as unpinned. An OCI image
    takes `:1.2.3` only when its reference names neither a tag nor a digest
    (a `:` before the last `/` is a registry port). An identifier that
    already carries a version, and a record that states none, are left as
    they are.
    """
    if not version:
        return ident
    if registry == "npm":
        return ident if "@" in ident[1:] else f"{ident}@{version}"
    if registry == "pypi":
        return ident if any(c in ident for c in "@=<>!~") else f"{ident}@{version}"
    if registry == "oci":
        has_tag = ":" in ident.rsplit("/", 1)[-1]
        return ident if has_tag or "@" in ident else f"{ident}:{version}"
    return ident


def _to_config(server: dict[str, Any]) -> dict[str, Any] | None:
    """Synthesise a scannable `.mcp.json`-shaped config from a registry server."""
    name = server.get("name") or "server"
    key = name.split("/")[-1].replace(".", "_") or "server"
    remotes = server.get("remotes") or []
    if remotes:
        # Prefer the first remote that DECLARES headers, not simply the first
        # remote. `_auth_mode` already looks across every remote, so taking
        # `remotes[0]` unconditionally could label a server `static-credential`
        # while handing the scanner a config with no auth on it at all.
        #
        # That is not hypothetical. It cost two false positives in the
        # 2026-08-24 benign-slice measurement: `co.huggingface/hf-mcp-server`
        # publishes its `?login` OAuth entry point first and its
        # `Authorization`-bearing endpoint second, and `co.curie/commerce` does
        # the same. Both were reported "without authentication" because the
        # conversion dropped the half of the record that carried the auth.
        r = next((x for x in remotes if x.get("headers")), remotes[0])
        ttype = (r.get("type") or "").lower()
        entry: dict[str, Any] = {
            "type": "http" if "http" in ttype else "sse",
            "url": r.get("url"),
        }
        headers = r.get("headers") or []
        if headers:
            entry["headers"] = {h.get("name") or "X-Auth": "${SECRET}" for h in headers}
        return {"mcpServers": {key: entry}}
    packages = server.get("packages") or []
    if packages:
        p = packages[0]
        reg = (p.get("registryType") or p.get("registry_name") or "").lower()
        ident = p.get("identifier") or name
        spec = _launch_spec(reg, ident, p.get("version"))
        if reg == "npm":
            cmd, args = "npx", ["-y", spec]
        elif reg == "pypi":
            cmd, args = "uvx", [spec]
        elif reg == "oci":
            cmd, args = "docker", ["run", "-i", "--rm", spec]
        else:
            cmd, args = ident, []
        env = {}
        for ev in p.get("environmentVariables") or p.get("environment_variables") or []:
            env[ev.get("name") or "VAR"] = ev.get("value") or "${VALUE}"
        entry = {"command": cmd, "args": args}
        if env:
            entry["env"] = env
        return {"mcpServers": {key: entry}}
    return None


def _collect(data: dict[str, Any], records: dict[str, dict[str, Any]]) -> None:
    """Fold one raw registry page into `records` (name -> latest active record)."""
    for e in data.get("servers", []):
        server = e.get("server") or {}
        meta = (e.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        if not meta.get("isLatest"):
            continue
        if meta.get("status") and meta["status"] != "active":
            continue
        name = server.get("name")
        if not name:
            continue
        config = _to_config(server)
        if config is None:
            continue
        src = None
        if server.get("remotes"):
            src = (server["remotes"][0] or {}).get("url")
        src = src or f"{REGISTRY}?search={name}"
        records[name] = {
            "name": name,
            "version": server.get("version"),
            "transport": _transport_of(server),
            "auth_mode": _auth_mode(server),
            "source_url": src,
            "registry_status": meta.get("status"),
            "published_at": meta.get("publishedAt"),
            "fetched_at": data.get("_fetched_at"),
            "config": config,
        }


def from_cache(cache_dir: Path) -> list[dict[str, Any]]:
    """Rebuild the records offline from the raw pages a previous `fetch` cached.

    Pages are folded in page order, the order `fetch` walked them, so a server
    listed on two pages keeps the record `fetch` kept. This re-converts a
    snapshot without touching the network: the registry's servers, versions
    and metadata are the ones on the cached pages, and only the conversion
    is today's. The pages record no fetch date, so the caller supplies it.
    """
    pages = sorted(cache_dir.glob("page-*.json"))
    if not pages:
        raise SystemExit(f"no cached registry pages (page-*.json) in {cache_dir}")
    records: dict[str, dict[str, Any]] = {}
    for path in pages:
        _collect(json.loads(path.read_text(encoding="utf-8")), records)
    return list(records.values())


def fetch(target: int, page_size: int = 100, max_pages: int = 40, sleep: float = 0.4) -> list[dict[str, Any]]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    records: dict[str, dict[str, Any]] = {}  # name -> record (latest only)
    cursor: str | None = None
    for page in range(max_pages):
        url = f"{REGISTRY}?limit={page_size}"
        if cursor:
            url += f"&cursor={urllib.parse.quote(cursor, safe='')}"
        data = _http_get(url)
        (CACHE_DIR / f"page-{page:03d}.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        _collect(data, records)
        cursor = (data.get("metadata") or {}).get("nextCursor")
        print(f"page {page}: {len(records)} distinct latest servers so far"
              f" (cursor={'…' if cursor else 'END'})")
        if len(records) >= target or not cursor:
            break
        time.sleep(sleep)
    return list(records.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=int, default=5000,
                        help="Stop once this many distinct latest servers are collected. "
                             "The canonical value is 5000 — large enough to walk the whole "
                             "registry to cursor-exhaustion (the published run collected "
                             "1641 distinct latest servers on 2026-07-26) rather than stop "
                             "early. Kept in sync with the Makefile + the docs by "
                             "tests/test_corpus_target_consistency.py.")
    parser.add_argument("--fetched-at", default=None,
                        help="Override the fetch date stamp (ISO, for reproducibility).")
    parser.add_argument("--from-cache", nargs="?", const=str(CACHE_DIR), default=None,
                        metavar="DIR",
                        help="Rebuild the manifest offline from the raw pages cached in DIR "
                             "(default: cache/ beside this script) instead of fetching. "
                             "Needs --fetched-at: the pages record no fetch date, and the "
                             "manifest keeps the snapshot's, not today's.")
    parser.add_argument("--out", type=Path, default=MANIFEST,
                        help="Where to write the manifest (default: corpus/registry-manifest.json).")
    args = parser.parse_args()

    if args.from_cache is not None:
        if not args.fetched_at:
            parser.error("--from-cache needs --fetched-at (the date the cached pages were fetched)")
        records = from_cache(Path(args.from_cache))
    else:
        records = fetch(args.target)
    stamp = args.fetched_at or time.strftime("%Y-%m-%d", time.gmtime())
    for r in records:
        r["fetched_at"] = stamp
    manifest = {
        "source": REGISTRY,
        "fetched_at": stamp,
        "distinct_latest_servers": len(records),
        "servers": sorted(records, key=lambda r: r["name"]),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} — {len(records)} distinct latest-version servers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
