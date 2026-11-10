"""AAK-KNOWN-VULN-001 and -003: packages a published advisory lists as affected.

Four critical advisories published on 26 and 27 Oct 2026, for packages agent and
MCP hosts install (vLLM, MLflow, the OpenHands SDK and NVIDIA's NeMo Agent
Toolkit), passed every rule on 0.6.28: AAK knew a vulnerable release only
through a hand-written pin. This module checks every release a scan already
resolves against the offline advisory feed (`agent_audit_kit.advisory_feed`),
OSV's advisory records for PyPI, npm, Go and crates.io, which `aak update` keeps from
the exports it downloads. A scan never touches the network; without `aak update`
the feed is the few records bundled with AAK.

What it reads (outside `SKIP_DIRS`, anywhere under the root), as
AAK-MALICIOUS-RELEASE-001 reads it:

* A lockfile's resolved versions: uv.lock, poetry.lock, Pipfile.lock,
  package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock (v1), Cargo.lock
  and go.mod, through the pin table's lockfile reader. A Cargo.lock block counts
  only with a `source` line: the root crate, path dependencies and workspace members
  have none and are the project's own code. A go.mod counts every `require`, direct
  or `// indirect`, as its `replace` lines leave it, and go.sum is not read: it lists
  modules outside the build list. A lockfile is read for its first
  `MAX_RELEASES_PER_PACKAGE` distinct releases of a package, which bounds the
  work a crafted lockfile can ask for.
* A declaration in requirements*.txt, pyproject.toml, Pipfile, package.json
  (not its `scripts`) or an MCP config's launches. One that pins one release
  is judged as an install of it. A range is reported at the advisory's
  severity only when every release it admits is affected (`<0.32`); one that
  admits affected and unaffected releases (`vllm>=0.30`) is reported once, at
  INFO, naming the advisories, and not at all when a lockfile in the same
  directory resolves the package, since the lockfile says what is installed.
  Ranges are read on release triples, as the pin table reads them. A
  declaration without a version is not judged, except an MCP config's launch.
* An installed `<name>-<version>.dist-info` directory in a site-packages or
  dist-packages directory the `_site_packages` walk reaches.
* With `include_user_config` (`aak scan --include-user-config`), what the
  launchers keep on this host (`_launcher_caches`): the packages in npm's npx
  cache and the dist-info directories of uv's tool environments. A cached
  release an advisory lists is an installed one, reported at the advisory's
  severity with the cache path.

AAK-KNOWN-VULN-003 is the launch the pins cannot judge. DBHub (`@bytebase/dbhub`),
a database MCP server, is started straight from an MCP config as
`npx -y @bytebase/dbhub`, and below 0.22.6 MySQL comment syntax slipped past its
read-only SQL validation (GHSA-j656-3hf2-fvjc, 2 Nov 2026). Such a launch names
no release, so -001 had nothing to judge: it runs whatever npx resolves or finds
in its cache. -003 reports a registry launch (not a git URL or a path) that
pins no release, with no version, a tag (`@latest`) or a range, for every
advisory of the package whose affected releases it admits, read as
AAK-MALICIOUS-RELEASE-002 reads a launch. It carries the advisory's severity
when every release the launch can fetch is affected (the advisory names no end,
or a range admits only affected releases), and MEDIUM otherwise: the release
that runs is the one the launcher picks, which the config does not say. A launch
pinned to one release stays -001's.

A release matches as its registry orders versions (`malicious_feed.Range`):
PEP 440 for PyPI, so MLflow's `>=3.12.0rc0, <3.17.0` takes 3.12.0rc0 and
3.17.0rc1 and leaves 3.17.0, and semver for npm, Go and crates.io. A finding names the advisory,
its CVE ids, the release and the fix, and carries the advisory's severity:
CRITICAL from CVSS 9.0, HIGH from 7.0, MEDIUM otherwise (see
`advisory_feed.record_severity`), INFO for a range. One finding per file,
package and advisory, at the first entry that resolves an affected release. Where
a uv.lock or poetry.lock shows a package pinning that release exactly, the finding says
the fix needs an override, or, for the project's own pin, says to raise it. A fix
on a date line npm has deprecated says so, for the packages the reviewed list
`data/date_line_packages.json` names.

Where a version-pin rule reports the advisory's CVEs on the same line of the same
file (the declaration or lockfile entry both point at) at or above this
finding's severity, that finding stands and this one is dropped
(`engine._drop_known_vulns_a_rule_reports`): 82 of the 134 pin-table rows name
a CVE OSV also lists for the package. The comparison needs the assembled
finding list, so it runs in the engine, and it reads this rule's CVE ids back
from its evidence (`evidence_cves`), the only place they are written.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.advisory_feed import Advisory, AdvisoryFeed, load_feed
from agent_audit_kit.malicious_feed import canonical_name, version_order
from agent_audit_kit.models import Finding, Severity

from ._dependency_pins import read_text
from ._helpers import MCP_SERVER_KEYS, SKIP_DIRS, loads_json, make_finding
from ._launcher_caches import npx_cached, resolved, uv_cached
from ._launchers import is_registry_spec, launch_head
from ._manifest_deps import MAX_LOCKFILE_BYTES, Declaration
from ._site_packages import site_entries, site_package_dirs
from ._versions import TOP, ZERO, Spans, intersect, interval_spans, parse_range
from .malicious_releases import _LOCKFILES, _REGISTRY, _declared, _is_manifest, _version_line, exact_pin
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries, go_mod_incomplete_note

RULE = "AAK-KNOWN-VULN-001"
RULE_LAUNCH = "AAK-KNOWN-VULN-003"
_EVERY_RELEASE: Spans = ((ZERO, TOP),)
#: How many distinct releases of one package a lockfile is read for. An npm
#: lockfile nests a few copies of a package at most; 64 bounds a crafted one.
MAX_RELEASES_PER_PACKAGE = 64
#: How many advisories an INFO finding names before "and N more".
_NAMED = 5
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
# How an INFO finding counts the advisories it does not name.
_UNNAMED_RE = re.compile(r"; and \d+ more\. ")
_LEVEL = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "INFO": Severity.INFO}


def evidence_cves(evidence: str) -> frozenset[str]:
    """The CVE ids a finding of this rule names: its advisories', the only CVE
    ids its evidence holds. Empty for a finding that counts advisories it does not
    name, whose CVE ids are not all written down, so the engine never drops it."""
    if _UNNAMED_RE.search(evidence):
        return frozenset()
    return frozenset(_CVE_RE.findall(evidence))


def _files(project_root: Path) -> tuple[list[Path], list[Path]]:
    """(lockfiles, manifests) under the root, in walk order."""
    lockfiles: list[Path] = []
    manifests: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.lower() in _LOCKFILES:
                lockfiles.append(Path(dirpath) / name)
            elif _is_manifest(name):
                manifests.append(Path(dirpath) / name)
    return lockfiles, manifests


def _finding(rel: str, evidence: str, line: int | None, level: str, rule: str = RULE) -> Finding:
    finding = make_finding(rule, rel, evidence, line)
    severity = _LEVEL[level]
    return finding if finding.severity is severity else dataclasses.replace(finding, severity=severity)


_TOML_PACKAGE_RE = re.compile(r"^\[\[package\]\][ \t]*$", re.M)
_TOML_NAME_RE = re.compile(r'^name\s*=\s*"([^"\n]+)"', re.M)
_UV_ROOT_RE = re.compile(r'^source\s*=\s*\{\s*(?:virtual|editable)\s*=', re.M)
_UV_EXACT_RE = re.compile(r'\{\s*name\s*=\s*"([^"\n]+)"[^}\n]{0,200}?\bspecifier\s*=\s*"==\s*([^",\s]+)"')
_POETRY_DEPS_RE = re.compile(r"^\[package\.dependencies\][ \t]*$", re.M)
_POETRY_EXACT_RE = re.compile(
    r'^([A-Za-z0-9._-]+)\s*=\s*(?:"(?:==)?\s*(\d[^"*,<>=~^ \n]*)"|\{[^}\n]{0,200}?\bversion\s*=\s*"(?:==)?\s*(\d[^"*,<>=~^ \n]*)")',
    re.M,
)


def _exact_parents(text: str, reader_name: str) -> dict[tuple[str, str], tuple[str, bool]]:
    """(package, version) -> (the package that pins exactly that, is it this project).

    A uv.lock holds requirements for its workspace members only, under
    `[package.metadata]`; a poetry.lock holds them for every package under
    `[package.dependencies]`. One pass over the file, whatever the number of findings.
    """
    parents: dict[tuple[str, str], tuple[str, bool]] = {}
    if reader_name not in ("uv.lock", "poetry.lock"):
        return parents
    starts = [m.start() for m in _TOML_PACKAGE_RE.finditer(text)] + [len(text)]
    for start, stop in zip(starts, starts[1:]):
        block = text[start:stop]
        name = _TOML_NAME_RE.search(block)
        if name is None:
            continue
        if reader_name == "uv.lock":
            own = _UV_ROOT_RE.search(block) is not None
            pins = [(m.group(1), m.group(2)) for m in _UV_EXACT_RE.finditer(block)]
        else:
            own = False
            deps = _POETRY_DEPS_RE.search(block)
            body = block[deps.end():].split("\n[", 1)[0] if deps else ""
            pins = [(m.group(1), m.group(2) or m.group(3)) for m in _POETRY_EXACT_RE.finditer(body)]
        for package, version in pins:
            parents.setdefault((canonical_name("PyPI", package), version), (name.group(1), own))
    return parents


def _override_note(parents: dict[tuple[str, str], tuple[str, bool]], name: str, version: str) -> str:
    """What a lockfile says about why the release is held where it is. A fix cannot
    land while a parent pins the affected release exactly."""
    found = parents.get((canonical_name("PyPI", name), version))
    if found is None:
        return ""
    parent, own = found
    if own:
        return f"; {parent}, this project, pins {name} =={version} exactly, so raise that pin"
    return (f"; {parent} pins {name} =={version} exactly, so the upgrade needs an override "
            "(`[tool.uv] override-dependencies` or a pip constraint)")


@functools.lru_cache(maxsize=1)
def _date_line_packages() -> dict[tuple[str, str], dict[str, Any]]:
    """The reviewed list of packages that left a deprecated date line for SemVer."""
    path = Path(__file__).parent.parent / "data" / "date_line_packages.json"
    try:
        rows = loads_json(path.read_text(encoding="utf-8"), path)["packages"]
    except (OSError, ValueError, KeyError):
        return {}
    return {(row["ecosystem"], canonical_name(row["ecosystem"], row["name"])): row for row in rows}


def _touches_semver_line(advisory: Advisory, first: tuple[Any, ...], line: tuple[Any, ...]) -> bool:
    """Does the advisory place any bound or listed version between the first SemVer
    release and the start of the date line, the releases current installs resolve to?"""
    bounds = [key for row in advisory.ranges for key in (row.bounds or ())]
    listed = [version_order(advisory.ecosystem, version) for version in advisory.versions]
    return any(key is not None and first <= key < line for key in bounds + listed)


def _left_date_line(advisory: Advisory, fixed: str) -> str:
    """What to add when the fix an advisory names is on a date line npm deprecated.

    Four npm reference servers published date versions (2025.1.14 to 2026.8.31), then
    went back to SemVer at 1.0.0 in October 2026, and npm now marks the date line
    deprecated. An advisory written before that names 2025.7.1 as the fix, so a project
    on 0.6.2 was sent to a deprecated release when any SemVer one is outside the
    advisory. This says so only for an advisory that leaves the SemVer line alone; a
    later one that lists 1.x, or fixes in it, keeps its own wording.
    """
    row = _date_line_packages().get((advisory.ecosystem, canonical_name(advisory.ecosystem, advisory.name)))
    if row is None:
        return ""
    fixed_key = version_order(advisory.ecosystem, fixed)
    first = version_order(advisory.ecosystem, row["semver_from"])
    line = version_order(advisory.ecosystem, row["date_line_from"])
    if fixed_key is None or first is None or line is None or fixed_key < line:
        return ""
    if _touches_semver_line(advisory, first, line):
        return ""
    return (f", on the date line npm has since deprecated: {row['name']} went back to semantic versioning at "
            f"{row['semver_from']} on {row['semver_published']}, and this advisory lists none of those releases")


def _fix(advisory: Advisory, version: str) -> str:
    fixed = advisory.fix_for(version)
    if fixed:
        return f"; it is fixed in {fixed}{_left_date_line(advisory, fixed)}"
    last = advisory.last_affected_for(version)
    if last:  # a CNA's `lessThanOrEqual`: IBM's Langflow records end at 1.12.8 and name no fix
        return f"; the advisory lists no fixed release, and {last} as the last affected one"
    return "; the advisory lists no fixed release"


def _feed_note(feed: AdvisoryFeed, advisory: Advisory) -> str:
    where = f" ({advisory.url})" if advisory.url else ""
    return f"{where}. Feed: the {feed.origin} copy generated {feed.generated_at}."


def _lockfile_findings(
    path: Path, rel: str, feed: AdvisoryFeed, resolved: dict[tuple[Path, str], set[str]]
) -> list[Finding]:
    ecosystem, reader_name = _LOCKFILES[path.name.lower()]
    text = read_text(path, MAX_LOCKFILE_BYTES)
    if text is None:
        return []
    wanted = feed.names(ecosystem)
    if not wanted:
        return []
    findings: list[Finding] = []
    # A `require` states a minimum, so a go.mod requires a release where a lockfile resolves one.
    verb, note = ("requires", go_mod_incomplete_note(text)) if reader_name == "go.mod" else ("resolves", "")
    parents: dict[tuple[str, str], tuple[str, bool]] | None = None
    for name, rows in sorted(_lockfile_raw_entries(text, reader_name, wanted).items()):
        resolved.setdefault((path.parent, ecosystem), set()).add(name)
        releases: dict[str, int] = {}  # release -> its first line, in file order
        for line, version in rows:
            if not version or version in releases:
                continue
            if len(releases) == MAX_RELEASES_PER_PACKAGE:
                break
            releases[version] = line
        for advisory in feed.advisories(ecosystem, name):
            hit = [(version, line) for version, line in releases.items() if advisory.matches(version)]
            if not hit:
                continue
            version, line = hit[0]
            if parents is None:
                parents = _exact_parents(text, reader_name)
            more = ""
            if len(hit) > 1:
                shown = ", ".join(v for v, _ in hit[1:4]) + (", ..." if len(hit) > 4 else "")
                more = f" (and {len(hit) - 1} more affected release{'s' if len(hit) > 2 else ''}: {shown})"
            findings.append(_finding(
                rel,
                f"{path.name} {verb} {name} {version}{more}, which {advisory.label()} lists as "
                f"affected{_fix(advisory, version)}{_override_note(parents, name, version)}"
                f"{_feed_note(feed, advisory)}{note}",
                line,
                advisory.severity,
            ))
    return findings


def _affected_spans(advisory: Advisory) -> Spans:
    """The releases an advisory lists, on release triples (`_versions`), the
    form a declaration's range is read in."""
    return interval_spans(((row.introduced, row.fixed, row.last_affected) for row in advisory.ranges),
                          advisory.versions)


def _below(advisory: Advisory) -> str:
    if advisory.fixed:
        return f", fixed in {', '.join(advisory.fixed)}{_left_date_line(advisory, advisory.fixed[-1])}"
    last = sorted({row.last_affected for row in advisory.ranges if row.last_affected is not None})
    return f", no fixed release listed, last affected {', '.join(last)}" if last else ", no fixed release listed"


def _manifest_findings(
    path: Path, rel: str, feed: AdvisoryFeed, resolved: dict[tuple[Path, str], set[str]]
) -> list[Finding]:
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
        advisories = feed.advisories(ecosystem, declaration.name)
        if advisories:
            findings.extend(_declaration_findings(path, rel, feed, resolved, declaration, ecosystem,
                                                  advisories, line_of(declaration), seen))
    return findings


def _declaration_findings(
    path: Path, rel: str, feed: AdvisoryFeed, resolved: dict[tuple[Path, str], set[str]],
    declaration: Declaration, ecosystem: str, advisories: tuple[Advisory, ...], line: int | None,
    seen: set[tuple[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    pinned = exact_pin(declaration)
    if pinned is None and declaration.kind == "launch":
        return _launch_findings(path, rel, feed, declaration, ecosystem, advisories, line, seen)
    spans = None if pinned is not None else parse_range(declaration.version, declaration.dialect)
    partial: list[Advisory] = []
    for advisory in advisories:
        if (advisory.id, declaration.text) in seen:
            continue
        if pinned is not None:
            if not advisory.matches(pinned):
                continue
            evidence = (f"`{declaration.text}` in {path.name} installs {declaration.name} {pinned}, which "
                        f"{advisory.label()} lists as affected{_fix(advisory, pinned)}")
        else:
            if not spans:
                continue  # no readable version, or a range that admits nothing
            overlap = intersect(spans, _affected_spans(advisory))
            if not overlap:
                continue
            if overlap != spans:
                partial.append(advisory)
                continue
            evidence = (f"every release `{declaration.text}` in {path.name} admits is one "
                        f"{advisory.label()} lists as affected{_below(advisory)}")
        seen.add((advisory.id, declaration.text))
        findings.append(_finding(rel, evidence + _feed_note(feed, advisory), line, advisory.severity))
    name = canonical_name(ecosystem, declaration.name)
    if partial and name not in resolved.get((path.parent, ecosystem), ()) and ("", declaration.text) not in seen:
        seen.add(("", declaration.text))
        listed = "; ".join(f"{advisory.label()}{_below(advisory)}" for advisory in partial[:_NAMED])
        rest = f"; and {len(partial) - _NAMED} more" if len(partial) > _NAMED else ""
        lists = "an advisory lists" if len(partial) == 1 else f"{len(partial)} advisories list"
        findings.append(_finding(
            rel,
            f"`{declaration.text}` in {path.name} admits releases {lists} as affected, and releases "
            f"it does not: {listed}{rest}. No lockfile beside it says which release is installed. "
            f"Feed: the {feed.origin} copy generated {feed.generated_at}.",
            line,
            "INFO",
        ))
    return findings


# ---- AAK-KNOWN-VULN-003: a launch that pins no release ------------------------------------


def _affected_text(advisory: Advisory) -> str:
    """Which releases an advisory lists, as a finding says it: `below 0.22.6`."""
    parts: list[str] = []
    for row in advisory.ranges:
        start = "" if row.introduced in ("0", "") else f"from {row.introduced} "
        if row.fixed is not None:
            parts.append(f"{start}below {row.fixed}")
        elif row.last_affected is not None:
            parts.append(f"{start}through {row.last_affected}")
        else:
            parts.append(f"{start}onward" if start else "every release")
    if advisory.versions:
        listed = sorted(advisory.versions, key=lambda v: (version_order(advisory.ecosystem, v) or (), v))
        shown = ", ".join(listed[:5]) + (f" and {len(listed) - 5} more" if len(listed) > 5 else "")
        parts.append(f"{shown} (listed)")
    return "; ".join(parts) or "releases it lists"


def _open_ended(advisory: Advisory) -> bool:
    """Does the advisory list releases with no end, so the newest release is affected too?"""
    return any(row.fixed is None and row.last_affected is None for row in advisory.ranges)


def _launch_fix(declaration: Declaration, ecosystem: str, advisory: Advisory) -> str:
    if not advisory.fixed:
        return ("The advisory names no fixed release, so every release the launch can fetch past its "
                "start is affected: stop launching the package, or keep the flawed component unreachable.")
    fixed = max(advisory.fixed, key=lambda v: (version_order(ecosystem, v) or (), v))
    launcher = declaration.text[: -len(declaration.spec)].strip() if declaration.spec else declaration.text.split(" ")[0]
    if ecosystem == "npm":
        example = f"{launcher} -y {declaration.name}@{fixed}" if launcher == "npx" else f"{launcher} {declaration.name}@{fixed}"
    else:
        example = f"{launcher} {declaration.name}=={fixed}"
    return (f"The release that runs is whichever {launcher} resolves or finds in its cache, which this config "
            f"does not control. Pin a release outside the advisory's range: `{example}` or later.")


def _launch_findings(
    path: Path, rel: str, feed: AdvisoryFeed, declaration: Declaration, ecosystem: str,
    advisories: tuple[Advisory, ...], line: int | None, seen: set[tuple[str, str]],
) -> list[Finding]:
    """AAK-KNOWN-VULN-003 for one launch that pins no release.

    A launch with no version or a tag (`@latest`) can fetch any release, and one
    with a range only those it admits, read on release triples as the pin table
    reads ranges; a git URL or a local path fetches nothing from the registry
    and is not judged. One finding per launch (a server of a top-level server map,
    or the launch text) and advisory. The evidence opens with the launch's
    `launch_head`, as AAK-MALICIOUS-RELEASE-002's does, so the engine stands
    AAK-SUPPLY-001 and AAK-MCP-007 down on the same launch.
    """
    if not is_registry_spec(declaration.ecosystem, declaration.spec):
        return []
    text = declaration.version.strip()
    spans = parse_range(text, declaration.dialect) if text else None
    admitted = spans if spans is not None else _EVERY_RELEASE
    where = declaration.path[:2]
    server = where[1] if len(where) == 2 and where[0] in MCP_SERVER_KEYS and isinstance(where[1], str) else None
    head = (f"{launch_head(server, declaration.spec)} is launched by `{declaration.text}` in {path.name}"
            if server is not None and declaration.spec else f"`{declaration.text}` in {path.name} is a launch")
    state = "with no version pinned" if not text else (
        f"pinned only to `{text}`, which admits affected releases")
    findings: list[Finding] = []
    for advisory in advisories:
        key = (RULE_LAUNCH + "\0" + advisory.id, repr((declaration.text, declaration.spec, where)))
        if key in seen:
            continue
        overlap = intersect(admitted, _affected_spans(advisory))
        if not overlap:
            continue  # the range admits no release the advisory lists
        seen.add(key)
        level = advisory.severity if _open_ended(advisory) or (spans is not None and overlap == spans) else "MEDIUM"
        findings.append(_finding(
            rel,
            f"{head} {state}, and {advisory.label()} lists {declaration.name} {_affected_text(advisory)} "
            f"as affected{_below(advisory)}. {_launch_fix(declaration, ecosystem, advisory)} "
            "`aak scan --include-user-config` reads npx's and uv's caches for an affected release "
            f"already fetched{_feed_note(feed, advisory)}",
            line,
            level,
            RULE_LAUNCH,
        ))
    return findings


def _installed_findings(project_root: Path, feed: AdvisoryFeed, scanned: set[str],
                        reported: set[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for site_dir in site_package_dirs(project_root):
        for entry in site_entries(site_dir):
            if not entry.name.endswith(".dist-info") or not entry.is_dir(follow_symlinks=False):
                continue
            name, sep, version = entry.name[: -len(".dist-info")].rpartition("-")
            if not sep or not name or not version:
                continue
            advisories = feed.match("PyPI", name, version)
            if not advisories:
                continue
            directory = Path(entry.path)
            reported.add(resolved(directory))
            metadata = directory / "METADATA"
            where = metadata if metadata.is_file() else directory
            rel = where.relative_to(project_root).as_posix()
            scanned.add(rel)
            line = _version_line(metadata) if where is metadata else None
            for advisory in advisories:
                findings.append(_finding(
                    rel,
                    f"`{directory.relative_to(project_root).as_posix()}` is an installed {name} {version}, "
                    f"which {advisory.label()} lists as affected{_fix(advisory, version)}"
                    f"{_feed_note(feed, advisory)}",
                    line,
                    advisory.severity,
                ))
    return findings


def _cache_findings(feed: AdvisoryFeed, scanned: set[str], reported: set[Path]) -> list[Finding]:
    """Releases an advisory lists in the launchers' caches on this host: one finding
    per cache path, package and advisory, at the advisory's severity."""
    findings: list[Finding] = []
    for cached in [*npx_cached(feed.names("npm")), *uv_cached(feed.names("PyPI"))]:
        if cached.real in reported:
            continue  # the scan root holds this copy, and reported it
        advisories = feed.match(cached.ecosystem, cached.name, cached.version)
        if not advisories:
            continue
        shown = cached.where.as_posix()
        scanned.add(shown)
        for advisory in advisories:
            findings.append(_finding(
                shown,
                f"{cached.launcher} cache at {cached.directory.as_posix()} holds {cached.name} {cached.version}, "
                f"which {advisory.label()} lists as affected{_fix(advisory, cached.version)}; a launch that pins no "
                f"release can run it{_feed_note(feed, advisory)}",
                cached.line,
                advisory.severity,
            ))
    return findings


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    """Report locked, pinned, installed or cached releases an advisory lists as
    affected, and launches that pin no release of a package with an advisory.

    Args:
        project_root: The root directory of the project, or an unpacked image
            root filesystem.
        include_user_config: Also read this host's npx and uv caches, outside the
            project (`aak scan --include-user-config`). Off by default.

    Returns:
        A tuple of (list of findings, set of scanned file paths: relative to the
        root, absolute for a cache outside it).
    """
    feed = load_feed()
    findings: list[Finding] = []
    scanned: set[str] = set()
    resolved: dict[tuple[Path, str], set[str]] = {}  # (directory, registry) -> packages a lockfile there resolves
    lockfiles, manifests = _files(project_root)
    for path in lockfiles:
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        findings.extend(_lockfile_findings(path, rel, feed, resolved))
    for path in manifests:
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        findings.extend(_manifest_findings(path, rel, feed, resolved))
    reported: set[Path] = set()
    findings.extend(_installed_findings(project_root, feed, scanned, reported))
    if include_user_config:
        findings.extend(_cache_findings(feed, scanned, reported))
    return findings, scanned


__all__ = ["MAX_RELEASES_PER_PACKAGE", "RULE", "RULE_LAUNCH", "evidence_cves", "scan"]
