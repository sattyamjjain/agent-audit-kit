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
    python research/state-of-mcp-2026/fetch_registry.py --target 700
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


def _to_config(server: dict[str, Any]) -> dict[str, Any] | None:
    """Synthesise a scannable `.mcp.json`-shaped config from a registry server."""
    name = server.get("name") or "server"
    key = name.split("/")[-1].replace(".", "_") or "server"
    remotes = server.get("remotes") or []
    if remotes:
        r = remotes[0]
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
        if reg == "npm":
            cmd, args = "npx", ["-y", ident]
        elif reg == "pypi":
            cmd, args = "uvx", [ident]
        elif reg == "oci":
            cmd, args = "docker", ["run", "-i", "--rm", ident]
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
        cursor = (data.get("metadata") or {}).get("nextCursor")
        print(f"page {page}: {len(records)} distinct latest servers so far"
              f" (cursor={'…' if cursor else 'END'})")
        if len(records) >= target or not cursor:
            break
        time.sleep(sleep)
    return list(records.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=int, default=700,
                        help="Stop once this many distinct latest servers are collected.")
    parser.add_argument("--fetched-at", default=None,
                        help="Override the fetch date stamp (ISO, for reproducibility).")
    args = parser.parse_args()

    records = fetch(args.target)
    stamp = args.fetched_at or time.strftime("%Y-%m-%d", time.gmtime())
    for r in records:
        r["fetched_at"] = stamp
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source": REGISTRY,
        "fetched_at": stamp,
        "distinct_latest_servers": len(records),
        "servers": sorted(records, key=lambda r: r["name"]),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST} — {len(records)} distinct latest-version servers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
