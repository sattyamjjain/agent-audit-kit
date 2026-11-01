"""AAK-MALICIOUS-RELEASE-001 and -002: releases published as malware.

litellm 1.107.0 was uploaded to PyPI on 21 Oct 2026 with a credential stealer
and a remote loader that ran at every Python start (OSV MAL-2026-2144), and the
same build went out as a Docker image. It passed every rule AAK had: the pins
judge ranges against a fix, and 1.107.0 sat above every floor. This module asks
the other question: is what the project declares, resolves, installs or runs a
release a source has listed as malicious? The list is the offline feed in
`agent_audit_kit.malicious_feed`; a scan never touches the network.

What it reads (outside `SKIP_DIRS`, anywhere under the root):

* A declaration that pins one version: requirements*.txt, pyproject.toml,
  Pipfile and package.json (its dependency maps and overrides, not its
  scripts), read by `_dependency_pins` as the version pins read them, and MCP
  configs, whose launches (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`) `_manifest_deps`
  reads. A range, or no version, matches only an entry that lists
  every release of the package (a typosquat): a range does not say which
  release was installed, and the vendor's own advice after 1.107.0 was a range
  that excluded it.
* A lockfile's resolved versions: uv.lock, poetry.lock, Pipfile.lock,
  package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml and yarn.lock (v1),
  through the pin table's lockfile reader, compared whole, so 1.107.0rc1 is not
  1.107.0.
* An installed `<name>-<version>.dist-info` directory in a site-packages or
  dist-packages directory the `_site_packages` walk reaches, the venvs and an
  unpacked image root filesystem included.
* An image reference by digest (`repo@sha256:<64 hex>`) in a Dockerfile, a YAML
  file (compose, Kubernetes, Helm, workflows) or an MCP config. A tag alone
  (`latest`, `main-stable`, `v1.107.0`) never matches: a tag moves, a digest does
  not.
* With `include_user_config` (`aak scan --include-user-config`), what the
  launchers have on disk on this host: the packages in npm's npx cache
  (`<npm cache>/_npx/<hash>/node_modules/<name>/package.json`) and the
  `<name>-<version>.dist-info` directories of uv's cached tool environments
  (`<uv cache>/environments-v*/`, the venvs `uvx` runs in). A cached release the
  feed lists is reported as an installed one: it is what the launcher ran.

AAK-MALICIOUS-RELEASE-002 asks what -001 cannot. Most MCP configs launch a
package with no version (`npx -y local-commander-agent`), and a launch without
one runs whichever release the registry, or the launcher's cache, hands it. On
31 Oct 2026 GitHub and OSV listed local-commander-agent 0.3.52, an MCP bridge,
as malware (GHSA-7j62-5j84-72fv, MAL-2026-18425), and such a launch passed with
a LOW "no version pin". -001 cannot report it, since nothing says which release
ran; -002 reports the launch of a package that has any version-specific entry
(an every-version entry is -001's), unless its range admits none of the listed
releases. The engine then stands AAK-SUPPLY-001 and AAK-MCP-007 down on the same
launch, so it is reported once.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable, Iterator

from agent_audit_kit.malicious_feed import Feed, Release, canonical_name, load_feed, version_order
from agent_audit_kit.models import Finding

from ._dependency_pins import read_manifest, read_text
from ._helpers import MCP_SERVER_KEYS, SKIP_DIRS, loads_json, make_finding, read_text_capped, strip_jsonc
from ._launchers import launch_head, npm_spec, py_spec
from ._manifest_deps import (
    MAX_LOCKFILE_BYTES,
    MAX_MANIFEST_BYTES,
    Declaration,
    declaration_lines,
    declarations,
)
from ._site_packages import site_entries, site_package_dirs
from ._versions import exact_version, interval_spans, intersect, parse_range, parse_version
from .container_image_pins import _COMMENT_RE, _kind
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries

_RULE = "AAK-MALICIOUS-RELEASE-001"
_RULE_UNPINNED = "AAK-MALICIOUS-RELEASE-002"
# How many listed versions an AAK-MALICIOUS-RELEASE-002 finding names per entry.
_SHOWN_VERSIONS = 10
_PACKAGE_JSON_BYTES = 1_000_000
_VERSION_KEY_RE = re.compile(r'^\s*"version"\s*:')

_MANIFEST_NAMES = frozenset({"pyproject.toml", "pipfile", "package.json", ".mcp.json", "mcp.json",
                             "claude_desktop_config.json"})
# Lockfile name -> (registry, the name `_lockfile_raw_entries` reads it under).
_LOCKFILES = {
    "uv.lock": ("PyPI", "uv.lock"),
    "poetry.lock": ("PyPI", "poetry.lock"),
    "pipfile.lock": ("PyPI", "pipfile.lock"),
    "package-lock.json": ("npm", "package-lock.json"),
    "npm-shrinkwrap.json": ("npm", "package-lock.json"),
    "pnpm-lock.yaml": ("npm", "pnpm-lock.yaml"),
    "yarn.lock": ("npm", "yarn.lock"),
}
_REGISTRY = {"py": "PyPI", "js": "npm"}
_IMAGE_FILE_BYTES = 2_000_000
_DIGEST_RE = re.compile(r"@(sha256:[0-9a-f]{64})(?![0-9a-f])", re.I)
# `_COMMENT_RE` with `^` at every line start, so a search begun at one finds a `#` there.
_LINE_COMMENT_RE = re.compile(_COMMENT_RE.pattern, re.M)
# How far before a digest the reference it ends is looked for, and quoted from.
_REF_WINDOW = 256
_OPERATOR_RE = re.compile(r"^\s*(?:===|==|=)?\s*")


def _is_manifest(name: str) -> bool:
    low = name.lower()
    return (
        low in _MANIFEST_NAMES
        or (low.startswith("requirements") and low.endswith(".txt"))
        or low.endswith((".mcp.yaml", ".mcp.yml", ".mcp.json"))
    )


def _files(project_root: Path) -> Iterator[tuple[Path, str]]:
    """(file, kind) for every manifest, lockfile and image-reference file."""
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name.lower() in _LOCKFILES:
                yield path, "lockfile"
            elif _is_manifest(name):
                yield path, "manifest"
            if _kind(name) is not None:
                yield path, "image"


def exact_pin(declaration: Declaration) -> str | None:
    """The one version a declaration pins, as written, or None for a range or
    no version. Exactness is judged by the pin table's range reader."""
    spans = parse_range(declaration.version, declaration.dialect)
    if spans is None or exact_version(spans) is None:
        return None
    return _OPERATOR_RE.sub("", declaration.version).strip() or None


def _feed_note(feed: Feed, release_url: str) -> str:
    where = f" ({release_url})" if release_url else ""
    return (
        f"{where}. Feed: the {feed.origin} copy generated {feed.generated_at}. Treat an "
        "environment that installed it as compromised."
    )


def _declared(path: Path) -> tuple[tuple[Declaration, ...], Callable[[Declaration], int | None]] | None:
    """A file's declarations and where each is written.

    A dependency manifest is read through `_dependency_pins.read_manifest`,
    shared with the version pins, which leaves out a package.json's `scripts`.
    An MCP config is read whole, so its launches (`npx -y pkg@1.2.3`) count.
    """
    name = path.name.lower()
    if name.endswith((".json", ".yaml", ".yml")) and name != "package.json":
        text = read_text(path, MAX_MANIFEST_BYTES)
        if text is None:
            return None
        return tuple(declarations(path, text)), declaration_lines(path, text)
    manifest = read_manifest(path)
    if manifest is None:
        return None
    return manifest.declarations, manifest.line_of


def _manifest_findings(path: Path, rel: str, feed: Feed) -> list[Finding]:
    declared = _declared(path)
    if declared is None:
        return []
    found, line_of = declared
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for declaration in found:
        ecosystem = _REGISTRY.get(declaration.ecosystem or "")
        if ecosystem is None:
            continue  # a program run by name names no registry
        version = exact_pin(declaration)
        matched = feed.match(ecosystem, declaration.name, version)
        for release in matched:
            key = (release.id, declaration.text)
            if key in seen:
                continue
            seen.add(key)
            findings.append(make_finding(
                _RULE, rel,
                f"`{declaration.text}` in {path.name} installs a malicious release: "
                f"{release.describe(version)}{_feed_note(feed, release.url)}",
                line_of(declaration),
            ))
        if matched or version is not None or declaration.kind != "launch":
            continue
        listed = _unpinned_risk(declaration, feed.releases(ecosystem, declaration.name))
        # One finding per launch: two servers launching one package are two launches,
        # and each is the launch AAK-SUPPLY-001 reports under its own server name.
        key = (_RULE_UNPINNED, repr((declaration.text, declaration.spec, declaration.path[:2])))
        if listed and key not in seen:
            seen.add(key)
            findings.append(make_finding(
                _RULE_UNPINNED, rel, _unpinned_evidence(declaration, path.name, listed, feed),
                line_of(declaration),
            ))
    return findings


def _is_registry_launch(declaration: Declaration) -> bool:
    """Does the launch fetch from the registry, not a git URL or a path?"""
    if not declaration.spec:
        return True
    if declaration.ecosystem == "js":
        return npm_spec(declaration.spec).kind == "registry"
    return py_spec(declaration.spec).kind == "registry"


def _unpinned_risk(declaration: Declaration, releases: tuple[Release, ...]) -> list[Release]:
    """The version-specific entries an unpinned launch could install a release of.

    An every-version entry is AAK-MALICIOUS-RELEASE-001's and is not counted.
    A launch with no version, a tag (`@latest`) or a range the version reader
    cannot read could install any release; a readable range only those it
    admits, read on release triples as the pin table reads ranges. A listed
    version that is not a release triple counts as admitted.
    """
    specific = [r for r in releases if not r.all_versions]
    if not specific or not _is_registry_launch(declaration):
        return []
    spans = parse_range(declaration.version, declaration.dialect) if declaration.version.strip() else None
    if spans is None:
        return specific
    admitted: list[Release] = []
    for release in specific:
        listed = release.listed or tuple(release.versions)
        unreadable = any(parse_version(v) is None for v in listed)
        bad = interval_spans(((r.introduced, r.fixed, r.last_affected) for r in release.ranges), listed)
        if unreadable or intersect(spans, bad):
            admitted.append(release)
    return admitted


def _shown_versions(release: Release) -> str:
    listed = sorted(release.listed or tuple(release.versions),
                    key=lambda v: (version_order(release.ecosystem, v) is None,
                                   version_order(release.ecosystem, v) or (), v))
    ranges = [
        ">= " + r.introduced + (f", < {r.fixed}" if r.fixed else f", <= {r.last_affected}" if r.last_affected else "")
        for r in release.ranges
    ]
    shown = listed[:_SHOWN_VERSIONS] + ranges
    more = len(listed) - _SHOWN_VERSIONS
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def _unpinned_evidence(declaration: Declaration, file_name: str, releases: list[Release], feed: Feed) -> str:
    """The evidence of AAK-MALICIOUS-RELEASE-002. It opens with the launch's
    `launch_head` when the launch belongs to a server of a top-level server map,
    the key `engine.run_scan` stands AAK-SUPPLY-001 and AAK-MCP-007 down by."""
    path = declaration.path
    # A server of a top-level map, the servers AAK-SUPPLY-001 reads and names.
    if len(path) >= 2 and path[0] in MCP_SERVER_KEYS and isinstance(path[1], str) and declaration.spec:
        head = f"{launch_head(path[1], declaration.spec)} is launched by `{declaration.text}` in {file_name}"
    else:
        head = f"`{declaration.text}` in {file_name} is a launch"
    listing = "; ".join(
        f"{r.id}{' (' + ', '.join(r.aliases) + ')' if r.aliases else ''} lists {r.name} {_shown_versions(r)}"
        f"{' (' + r.url + ')' if r.url else ''}"
        for r in releases
    )
    state = "with no version pinned" if not declaration.version.strip() else (
        f"pinned only to `{declaration.version}`, which admits a listed release")
    return (
        f"{head} {state}, and the malicious-release feed lists releases of {declaration.name}: {listing}. "
        "An unpinned launch runs whichever release the registry or the launcher's cache hands it. "
        "Pin a release outside the list, and check the launcher cache "
        "(`aak scan --include-user-config` reads npx's and uv's). "
        f"Feed: the {feed.origin} copy generated {feed.generated_at}."
    )


def _lockfile_findings(path: Path, rel: str, feed: Feed) -> list[Finding]:
    ecosystem, reader_name = _LOCKFILES[path.name.lower()]
    text = read_text(path, MAX_LOCKFILE_BYTES)
    if text is None:
        return []
    wanted = feed.names(ecosystem)
    if not wanted:
        return []
    findings: list[Finding] = []
    for name, rows in sorted(_lockfile_raw_entries(text, reader_name, wanted).items()):
        reported: set[str] = set()
        for line, version in rows:
            # One finding per release the lockfile resolves, at its first entry: a
            # lockfile repeating one entry 300,000 times made 300,000 findings.
            if version in reported:
                continue
            reported.add(version)
            for release in feed.match(ecosystem, name, version or None):
                findings.append(make_finding(
                    _RULE, rel,
                    f"{path.name} resolves {name} {version}, a malicious release: "
                    f"{release.describe(version)}{_feed_note(feed, release.url)}",
                    line,
                ))
    return findings


def _version_line(metadata: Path) -> int | None:
    text = read_text(metadata, 1_000_000)
    if text is None:
        return None
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("Version:"):
            return number
        if not line.strip():
            break  # the headers end at the first blank line
    return None


def _listed_dist_infos(site_dir: Path, feed: Feed) -> Iterator[tuple[Path, str, str, list[Release]]]:
    """(dist-info directory, name, version, entries) for each installed release
    in one site-packages directory that the feed lists."""
    for entry in site_entries(site_dir):
        if not entry.name.endswith(".dist-info") or not entry.is_dir(follow_symlinks=False):
            continue
        name, sep, version = entry.name[: -len(".dist-info")].rpartition("-")
        if not sep or not name or not version:
            continue
        releases = feed.match("PyPI", name, version)
        if releases:
            yield Path(entry.path), name, version, releases


def _installed_findings(project_root: Path, feed: Feed, scanned: set[str], reported: set[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for site_dir in site_package_dirs(project_root):
        for directory, name, version, releases in _listed_dist_infos(site_dir, feed):
            reported.add(_resolved(directory))
            metadata = directory / "METADATA"
            where = metadata if metadata.is_file() else directory
            rel = where.relative_to(project_root).as_posix()
            scanned.add(rel)
            line = _version_line(metadata) if where is metadata else None
            for release in releases:
                findings.append(make_finding(
                    _RULE, rel,
                    f"`{directory.relative_to(project_root).as_posix()}` is an installed "
                    f"{name} {version}, a malicious release: {release.describe(version)}"
                    f"{_feed_note(feed, release.url)}",
                    line,
                ))
    return findings


# ---- the launchers' caches on this host (include_user_config) --------------------------


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


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


def _subdirs(directory: Path) -> list[os.DirEntry[str]]:
    """The directories directly inside one, sorted, symlinks left out; none when unreadable."""
    try:
        with os.scandir(directory) as it:
            return sorted((e for e in it if e.is_dir(follow_symlinks=False)), key=lambda e: e.name)
    except OSError:
        return []


def _npx_packages(modules: Path) -> Iterator[tuple[str, Path]]:
    """(name, directory) for every package at the top of one node_modules, scoped ones included."""
    for entry in _subdirs(modules):
        if entry.name.startswith("@"):
            for scoped in _subdirs(Path(entry.path)):
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


def _npx_cache_findings(feed: Feed, scanned: set[str]) -> list[Finding]:
    """Releases the feed lists in npm's npx cache: npx installs a launched package
    and its dependencies into `<cache>/_npx/<hash>/node_modules/` and runs it from there."""
    wanted = feed.names("npm")
    npx = npm_cache_dir() / "_npx"
    if not wanted or not npx.is_dir():
        return []
    findings: list[Finding] = []
    for install in _subdirs(npx):
        for name, directory in _npx_packages(Path(install.path) / "node_modules"):
            if canonical_name("npm", name) not in wanted:
                continue
            package_json = directory / "package.json"
            found = _package_version(package_json)
            if found is None:
                continue
            version, line = found
            releases = feed.match("npm", name, version)
            if not releases:
                continue
            shown = package_json.as_posix()
            scanned.add(shown)
            for release in releases:
                findings.append(make_finding(
                    _RULE, shown,
                    f"npx cache at {directory.as_posix()} holds {name} {version}, a malicious "
                    f"release: {release.describe(version)}{_feed_note(feed, release.url)}",
                    line,
                ))
    return findings


def _uv_cache_findings(feed: Feed, scanned: set[str], reported: set[Path]) -> list[Finding]:
    """Releases the feed lists in uv's cached tool environments: `uvx` runs a tool
    in a venv it keeps at `<cache>/environments-v*/<hash>/<hash>`, a link into
    the cache's `archive-v0/` on uv 0.9."""
    root = uv_cache_dir()
    if not feed.names("PyPI") or not root.is_dir():
        return []
    findings: list[Finding] = []
    seen: set[Path] = set()
    for bucket in _subdirs(root):
        if not bucket.name.startswith("environments-v"):
            continue
        for interpreter in _subdirs(Path(bucket.path)):
            try:
                with os.scandir(interpreter.path) as it:
                    links = sorted(Path(e.path) for e in it)
            except OSError:
                continue
            for link in links:
                target = _resolved(link)
                if target in seen or not target.is_dir():
                    continue
                seen.add(target)
                for site_dir in site_package_dirs(target):
                    for directory, name, version, releases in _listed_dist_infos(site_dir, feed):
                        if _resolved(directory) in reported:
                            continue  # the scan root holds this environment, and reported it
                        shown_dir = link / directory.relative_to(target)
                        metadata = directory / "METADATA"
                        where = (shown_dir / "METADATA") if metadata.is_file() else shown_dir
                        scanned.add(where.as_posix())
                        line = _version_line(metadata) if metadata.is_file() else None
                        for release in releases:
                            findings.append(make_finding(
                                _RULE, where.as_posix(),
                                f"uvx cache at {shown_dir.as_posix()} holds {name} {version}, a "
                                f"malicious release: {release.describe(version)}"
                                f"{_feed_note(feed, release.url)}",
                                line,
                            ))
    return findings


def _image_findings(path: Path, rel: str, feed: Feed) -> list[Finding]:
    try:
        text = read_text_capped(path, _IMAGE_FILE_BYTES, errors="replace")
    except OSError:
        return []
    is_json = path.name.lower().endswith(".json")
    if is_json:
        try:
            text = strip_jsonc(text)
        except ValueError:
            return []
    findings: list[Finding] = []
    # One pass: the line, its start and its first comment marker are carried from one
    # listed digest to the next. Each used to look back to the start of its line and of
    # the file and quote everything before it on the line: 27,000 of them on one 2 MB
    # line ran past two minutes, and 108 KB of them made 82 MB of evidence.
    line, last, line_start = 1, 0, 0
    comment_for, comment_at = -1, -1  # the line start the marker was read for, and where it ends
    for m in _DIGEST_RE.finditer(text):
        image = feed.image(m.group(1))
        if image is None:
            continue
        start = m.start()
        newlines = text.count("\n", last, start)
        if newlines:
            line += newlines
            line_start = text.rfind("\n", last, start) + 1
        last = start
        if not is_json:
            if comment_for != line_start:
                line_end = text.find("\n", line_start)
                marker = _LINE_COMMENT_RE.search(text, line_start, len(text) if line_end < 0 else line_end)
                comment_for, comment_at = line_start, -1 if marker is None else marker.end()
            if 0 <= comment_at <= start:
                continue
        lo = max(line_start, start - _REF_WINDOW)
        stop = max(text.rfind(c, lo, start) for c in " \t\"'=")
        ref_start = lo if stop < 0 else stop + 1
        shown = ("…" if stop < 0 and lo > line_start else "") + text[ref_start:start] + m.group(0)
        findings.append(make_finding(
            _RULE, rel,
            f"`{shown}` runs image {m.group(1)}, which {image.id} lists as a malicious "
            f"{image.image} build (tags it was published under: {', '.join(image.tags)})"
            f"{f' ({image.url})' if image.url else ''}. Feed: the {feed.origin} copy generated "
            f"{feed.generated_at}. Treat a host or cluster that ran it as compromised.",
            line,
        ))
    return findings


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    """Report declared, resolved, installed, cached or referenced malicious
    releases, and unpinned launches of packages that have any.

    Args:
        project_root: The root directory of the project, or an unpacked image
            root filesystem.
        include_user_config: Also read this host's npx and uv caches, outside the
            project (`aak scan --include-user-config`). Off by default: a scan
            reads the user's home only when asked.

    Returns:
        A tuple of (list of findings, set of scanned file paths: relative to the
        root, absolute for a cache outside it).
    """
    feed = load_feed()
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path, kind in _files(project_root):
        rel = path.relative_to(project_root).as_posix()
        if kind == "manifest":
            found = _manifest_findings(path, rel, feed)
        elif kind == "lockfile":
            found = _lockfile_findings(path, rel, feed)
        else:
            found = _image_findings(path, rel, feed)
        scanned.add(rel)
        findings.extend(found)
    reported: set[Path] = set()
    findings.extend(_installed_findings(project_root, feed, scanned, reported))
    if include_user_config:
        findings.extend(_npx_cache_findings(feed, scanned))
        findings.extend(_uv_cache_findings(feed, scanned, reported))
    return findings, scanned


__all__ = ["scan", "exact_pin", "npm_cache_dir", "uv_cache_dir"]
