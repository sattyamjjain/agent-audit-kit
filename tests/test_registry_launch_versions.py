"""The registry corpus launches the release each record names.

A registry package states one version (`packages[].version`). Up to report
v1.0 `fetch_registry._to_config` dropped it, so every npm and PyPI server in the
2026-07-26 snapshot (161 of them) was converted into an unpinned `npx -y pkg` or
`uvx pkg`, and the corpus measured the converter rather than the servers. The
conversion now carries the version, and `--from-cache` re-converts the cached
raw pages offline so the snapshot itself does not move.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
RESEARCH = REPO / "research" / "state-of-mcp-2026"
MANIFEST = RESEARCH / "corpus" / "registry-manifest.json"
FP_DIR = REPO / "benchmarks" / "false_positive"


def _fetch_registry() -> Any:
    spec = importlib.util.spec_from_file_location(
        "somcp_fetch_registry_versions", RESEARCH / "fetch_registry.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fp_corpus() -> Any:
    if str(FP_DIR) not in sys.path:
        sys.path.insert(0, str(FP_DIR))
    spec = importlib.util.spec_from_file_location("fp_corpus_versions", FP_DIR / "corpus.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _package_server(registry: str, ident: str, version: str | None) -> dict[str, Any]:
    package: dict[str, Any] = {"registryType": registry, "identifier": ident,
                               "transport": {"type": "stdio"}}
    if version is not None:
        package["version"] = version
    return {"name": "io.example/server", "version": "9.9.9", "packages": [package]}


def _entry(config: dict[str, Any]) -> dict[str, Any]:
    (entry,) = config["mcpServers"].values()
    return entry


# --- the conversion ----------------------------------------------------------


@pytest.mark.parametrize(("registry", "ident", "version", "command", "args"), [
    ("npm", "@scope/server", "1.7.1", "npx", ["-y", "@scope/server@1.7.1"]),
    ("npm", "server", "0.2.0-beta.1", "npx", ["-y", "server@0.2.0-beta.1"]),
    # uvx's own spelling: AAK-MCP-007 reads an argument without `@` as unpinned.
    ("pypi", "linkguard-mcp", "0.1.0", "uvx", ["linkguard-mcp@0.1.0"]),
    ("oci", "ghcr.io/org/image", "1.2.3", "docker", ["run", "-i", "--rm", "ghcr.io/org/image:1.2.3"]),
])
def test_conversion_launches_the_stated_version(registry, ident, version, command, args) -> None:
    entry = _entry(_fetch_registry()._to_config(_package_server(registry, ident, version)))
    assert entry["command"] == command
    assert entry["args"] == args


@pytest.mark.parametrize(("registry", "ident", "version", "expected"), [
    # an identifier that already names a version, tag or digest keeps it
    ("npm", "@scope/server@2.0.0", "1.0.0", "@scope/server@2.0.0"),
    ("pypi", "pkg==2.0.0", "1.0.0", "pkg==2.0.0"),
    ("oci", "docker.io/org/image:0.1.0", "9.9.9", "docker.io/org/image:0.1.0"),
    ("oci", "ghcr.io/org/image@sha256:" + "a" * 64, "1.0.0", "ghcr.io/org/image@sha256:" + "a" * 64),
    # a registry port is not a tag
    ("oci", "localhost:5000/image", "1.0.0", "localhost:5000/image:1.0.0"),
    # no stated version, nothing to pin
    ("npm", "@scope/server", None, "@scope/server"),
    ("pypi", "pkg", "", "pkg"),
    # a registry the conversion does not launch through a package manager
    ("nuget", "anythink-mcp", "0.2.21", "anythink-mcp"),
])
def test_launch_spec_edges(registry, ident, version, expected) -> None:
    assert _fetch_registry()._launch_spec(registry, ident, version) == expected


def test_remote_servers_are_untouched() -> None:
    fr = _fetch_registry()
    server = {"name": "io.example/remote", "version": "1.0.0",
              "remotes": [{"type": "streamable-http", "url": "https://example.test/mcp"}],
              "packages": [{"registryType": "npm", "identifier": "pkg", "version": "1.0.0"}]}
    assert fr._to_config(server) == {
        "mcpServers": {"remote": {"type": "http", "url": "https://example.test/mcp"}}
    }


# --- the offline rebuild -------------------------------------------------------


def _page(entries: list[dict[str, Any]], cursor: str | None) -> dict[str, Any]:
    return {"servers": entries, "metadata": {"nextCursor": cursor, "count": len(entries)}}


def _listing(server: dict[str, Any], *, latest: bool = True, status: str = "active") -> dict[str, Any]:
    return {"server": server, "_meta": {"io.modelcontextprotocol.registry/official": {
        "status": status, "isLatest": latest, "publishedAt": "2026-07-20T00:00:00Z"}}}


def _write_cache(cache: Path) -> None:
    cache.mkdir()
    old = _package_server("npm", "pkg", "1.0.0")
    new = _package_server("npm", "pkg", "1.1.0")
    other = {**_package_server("pypi", "tool", "0.3.0"), "name": "io.example/tool"}
    gone = {**_package_server("npm", "dead", "1.0.0"), "name": "io.example/dead"}
    (cache / "page-000.json").write_text(json.dumps(_page(
        [_listing(old, latest=False), _listing(other), _listing(gone, status="deleted")], "c1")))
    # A later page re-lists the same server: the walk keeps the last record it saw.
    (cache / "page-001.json").write_text(json.dumps(_page([_listing(new)], None)))


def test_from_cache_rebuilds_the_records_offline(tmp_path: Path) -> None:
    fr = _fetch_registry()
    _write_cache(tmp_path / "cache")
    records = {r["name"]: r for r in fr.from_cache(tmp_path / "cache")}
    assert set(records) == {"io.example/server", "io.example/tool"}
    assert _entry(records["io.example/server"]["config"])["args"] == ["-y", "pkg@1.1.0"]
    assert _entry(records["io.example/tool"]["config"])["args"] == ["tool@0.3.0"]
    assert records["io.example/tool"]["published_at"] == "2026-07-20T00:00:00Z"


def test_from_cache_cli_keeps_the_snapshot_date(tmp_path: Path) -> None:
    _write_cache(tmp_path / "cache")
    out = tmp_path / "manifest.json"
    script = str(RESEARCH / "fetch_registry.py")
    refused = subprocess.run(
        [sys.executable, script, "--from-cache", str(tmp_path / "cache"), "--out", str(out)],
        capture_output=True, text=True,
    )
    assert refused.returncode != 0 and "--fetched-at" in refused.stderr
    assert not out.exists()
    subprocess.run(
        [sys.executable, script, "--from-cache", str(tmp_path / "cache"),
         "--fetched-at", "2026-07-26", "--out", str(out)],
        check=True, capture_output=True, text=True,
    )
    manifest = json.loads(out.read_text(encoding="utf-8"))
    assert manifest["fetched_at"] == "2026-07-26"
    assert manifest["distinct_latest_servers"] == 2
    assert {s["fetched_at"] for s in manifest["servers"]} == {"2026-07-26"}


def test_from_cache_refuses_an_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        _fetch_registry().from_cache(tmp_path)


# --- the committed manifest -----------------------------------------------------


def test_committed_registry_configs_launch_a_versioned_package() -> None:
    """Every npm and PyPI launch in the committed manifest names its release."""
    unversioned = []
    for server in json.loads(MANIFEST.read_text(encoding="utf-8"))["servers"]:
        for entry in (server.get("config") or {}).get("mcpServers", {}).values():
            command, args = entry.get("command"), entry.get("args") or []
            if command == "npx":
                spec = args[-1]
            elif command == "uvx":
                spec = args[0]
            else:
                continue
            if "@" not in spec[1:]:
                unversioned.append((server["name"], spec))
    assert not unversioned, (
        f"{len(unversioned)} registry config(s) launch an unversioned package, the "
        f"v1.0 conversion bug: {unversioned[:5]}. Rebuild the manifest with "
        "`fetch_registry.py --from-cache --fetched-at <snapshot date>`."
    )


# --- the benign slice stays the pre-registered one --------------------------------


@pytest.mark.parametrize(("arg", "name"), [
    ("@scope/mcp@0.0.3", "@scope/mcp"),
    ("pkg@1.2.3", "pkg"),
    ("pkg==1.2.3", "pkg"),
    ("@scope/pkg", "@scope/pkg"),
    ("pkg", "pkg"),
])
def test_fp_slice_matches_launch_arguments_by_package_name(arg: str, name: str) -> None:
    assert _fp_corpus()._package_name(arg) == name


def test_a_version_does_not_move_a_server_into_the_benign_slice() -> None:
    """`@scope/mcp` matches the feed's `mcp` with or without its version.

    Without the version strip, 8 servers of the 2026-07-26 snapshot entered the
    slice the day their configs gained a version, though nothing about them did.
    """
    corpus = _fp_corpus()
    ids = corpus.cve_feed_identifiers()
    assert "mcp" in ids
    server = {"name": "ai.example/server", "registry_status": "active",
              "auth_mode": "local-stdio",
              "config": {"mcpServers": {"s": {"command": "npx", "args": ["-y", "@example/mcp"]}}}}
    versioned = json.loads(json.dumps(server))
    versioned["config"]["mcpServers"]["s"]["args"] = ["-y", "@example/mcp@0.0.3"]
    assert corpus._server_identifiers(server) == corpus._server_identifiers(versioned)
    assert not corpus.is_benign(versioned, ids)
