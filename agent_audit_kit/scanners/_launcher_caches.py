"""What the package launchers keep on this host: npm's npx cache and uv's tool environments.

An MCP config that launches a package without pinning a release
(`npx -y pkg`, `uvx pkg`) runs whatever the launcher resolves or already has,
and both keep what they fetched:

* npx (npm 7+) installs a launched package and its dependencies into
  `<npm cache>/_npx/<hash>/node_modules/` and runs it from there. The npm cache is
  the `cache` setting from an `npm_config_cache` environment variable (npm reads
  its variables in any case), else `~/.npm`, or `%LocalAppData%\\npm-cache` on
  Windows (npm's own config definitions). An `.npmrc` `cache=` line is not read.
* uvx runs a tool in a venv it keeps at `<uv cache>/environments-v*/<hash>/<hash>`,
  a link into the cache's `archive-v0/` on uv 0.9. The uv cache is `UV_CACHE_DIR`,
  else `$XDG_CACHE_HOME/uv` or `~/.cache/uv`, or `%LOCALAPPDATA%\\uv\\cache` on
  Windows, as uv documents it; `--cache-dir` and `tool.uv.cache-dir` are not read.

AAK-MALICIOUS-RELEASE-001 and AAK-KNOWN-VULN-001 read these, and only when a scan
asks (`include_user_config`, `aak scan --include-user-config`): they are the
user's home, not the project. The walkers here yield what is cached; each rule
decides what a cached release means against its own feed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import AbstractSet, Iterator

from agent_audit_kit.malicious_feed import canonical_name

from ._dependency_pins import read_text
from ._helpers import loads_json
from ._site_packages import site_entries, site_package_dirs

_PACKAGE_JSON_BYTES = 1_000_000
_VERSION_KEY_RE = re.compile(r'^\s*"version"\s*:')


@dataclass(frozen=True)
class Cached:
    """One release a launcher keeps on this host."""

    launcher: str       # "npx" or "uvx"
    ecosystem: str      # "npm" or "PyPI"
    name: str           # as the cache writes it
    version: str
    directory: Path     # the package's folder or dist-info directory, as reached
    where: Path         # the file a finding points at: package.json or METADATA
    line: int | None    # its `version` / `Version:` line
    real: Path          # `directory` with links resolved, to tell one copy from another


def npm_cache_dir() -> Path:
    """npm's cache directory, as npm 7+ picks it: the `cache` setting from an
    `npm_config_cache` environment variable (any case), else `~/.npm`, or
    `%LocalAppData%\\npm-cache` on Windows. An `.npmrc` `cache=` line is not read."""
    for key, value in os.environ.items():
        if key.lower() == "npm_config_cache" and value:
            return Path(value).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home()) / "npm-cache"
    return Path.home() / ".npm"


def uv_cache_dir() -> Path:
    """uv's cache directory, as uv documents it: `UV_CACHE_DIR`, else
    `$XDG_CACHE_HOME/uv` or `~/.cache/uv`, or `%LOCALAPPDATA%\\uv\\cache` on Windows.
    `--cache-dir` and a `tool.uv.cache-dir` setting are not read."""
    value = os.environ.get("UV_CACHE_DIR")
    if value:
        return Path(value).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "uv" / "cache"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".cache") / "uv"


def resolved(path: Path) -> Path:
    """`path` with links resolved, or as given when it cannot be."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def subdirs(directory: Path) -> list[os.DirEntry[str]]:
    """The directories directly inside one, sorted, symlinks left out; none when unreadable."""
    try:
        with os.scandir(directory) as it:
            return sorted((e for e in it if e.is_dir(follow_symlinks=False)), key=lambda e: e.name)
    except OSError:
        return []


def metadata_version_line(metadata: Path) -> int | None:
    """The line of a dist-info METADATA's `Version:` header, or None."""
    text = read_text(metadata, 1_000_000)
    if text is None:
        return None
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("Version:"):
            return number
        if not line.strip():
            break  # the headers end at the first blank line
    return None


def _npx_packages(modules: Path) -> Iterator[tuple[str, Path]]:
    """(name, directory) for every package at the top of one node_modules, scoped ones included."""
    for entry in subdirs(modules):
        if entry.name.startswith("@"):
            for scoped in subdirs(Path(entry.path)):
                yield f"{entry.name}/{scoped.name}", Path(scoped.path)
        elif not entry.name.startswith("."):
            yield entry.name, Path(entry.path)


def _package_version(package_json: Path) -> tuple[str, int | None] | None:
    """A package.json's `version` and the line it is on, or None."""
    text = read_text(package_json, _PACKAGE_JSON_BYTES)
    if text is None:
        return None
    try:
        data = loads_json(text, package_json)
    except ValueError:
        return None
    version = data.get("version") if isinstance(data, dict) else None
    if not isinstance(version, str) or not version.strip():
        return None
    line = next((n for n, row in enumerate(text.splitlines(), 1) if _VERSION_KEY_RE.match(row)), None)
    return version.strip(), line


def npx_cached(wanted: AbstractSet[str]) -> Iterator[Cached]:
    """Every package in npm's npx cache whose name (lower case) is in `wanted`."""
    npx = npm_cache_dir() / "_npx"
    if not wanted or not npx.is_dir():
        return
    for install in subdirs(npx):
        for name, directory in _npx_packages(Path(install.path) / "node_modules"):
            if canonical_name("npm", name) not in wanted:
                continue
            package_json = directory / "package.json"
            found = _package_version(package_json)
            if found is not None:
                yield Cached("npx", "npm", name, found[0], directory, package_json, found[1], resolved(directory))


def uv_cached(wanted: AbstractSet[str]) -> Iterator[Cached]:
    """Every `<name>-<version>.dist-info` in uv's cached tool environments whose
    name (PEP 503) is in `wanted`. Each environment is read once, however many
    entries link to it."""
    root = uv_cache_dir()
    if not wanted or not root.is_dir():
        return
    seen: set[Path] = set()
    for bucket in subdirs(root):
        if not bucket.name.startswith("environments-v"):
            continue
        for interpreter in subdirs(Path(bucket.path)):
            try:
                with os.scandir(interpreter.path) as it:
                    links = sorted(Path(e.path) for e in it)
            except OSError:
                continue
            for link in links:
                target = resolved(link)
                if target in seen or not target.is_dir():
                    continue
                seen.add(target)
                for site_dir in site_package_dirs(target):
                    for entry in site_entries(site_dir):
                        if not entry.name.endswith(".dist-info") or not entry.is_dir(follow_symlinks=False):
                            continue
                        name, sep, version = entry.name[: -len(".dist-info")].rpartition("-")
                        if not sep or not name or not version or canonical_name("PyPI", name) not in wanted:
                            continue
                        directory = Path(entry.path)
                        shown = link / directory.relative_to(target)
                        metadata = directory / "METADATA"
                        has_metadata = metadata.is_file()
                        yield Cached(
                            "uvx", "PyPI", name, version, shown, shown / "METADATA" if has_metadata else shown,
                            metadata_version_line(metadata) if has_metadata else None, resolved(directory),
                        )


__all__ = [
    "Cached", "metadata_version_line", "npm_cache_dir", "npx_cached", "resolved", "subdirs", "uv_cache_dir",
    "uv_cached",
]
