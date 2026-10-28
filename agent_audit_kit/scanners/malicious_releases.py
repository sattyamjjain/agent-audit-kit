"""AAK-MALICIOUS-RELEASE-001: a project that installs a release published as malware.

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
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable, Iterator

from agent_audit_kit.malicious_feed import Feed, load_feed
from agent_audit_kit.models import Finding

from ._dependency_pins import read_manifest, read_text
from ._helpers import SKIP_DIRS, make_finding, read_text_capped, strip_jsonc
from ._manifest_deps import (
    MAX_LOCKFILE_BYTES,
    MAX_MANIFEST_BYTES,
    Declaration,
    declaration_lines,
    declarations,
)
from ._site_packages import site_entries, site_package_dirs
from ._versions import exact_version, parse_range
from .container_image_pins import _COMMENT_RE, _kind
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries

_RULE = "AAK-MALICIOUS-RELEASE-001"

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
        for release in feed.match(ecosystem, declaration.name, version):
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
    return findings


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


def _installed_findings(project_root: Path, feed: Feed, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for site_dir in site_package_dirs(project_root):
        for entry in site_entries(site_dir):
            if not entry.name.endswith(".dist-info") or not entry.is_dir(follow_symlinks=False):
                continue
            name, sep, version = entry.name[: -len(".dist-info")].rpartition("-")
            if not sep or not name or not version:
                continue
            releases = feed.match("PyPI", name, version)
            if not releases:
                continue
            directory = Path(entry.path)
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


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report declared, resolved, installed or referenced malicious releases.

    Args:
        project_root: The root directory of the project, or an unpacked image
            root filesystem.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
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
    findings.extend(_installed_findings(project_root, feed, scanned))
    return findings, scanned


__all__ = ["scan", "exact_pin"]
