"""AAK-KNOWN-VULN-001: a locked, pinned or installed package an OSV advisory lists as affected.

Four critical advisories published on 26 and 27 Oct 2026, for packages agent and
MCP hosts install (vLLM, MLflow, the OpenHands SDK and NVIDIA's NeMo Agent
Toolkit), passed every rule on 0.6.28: AAK knew a vulnerable release only
through a hand-written pin. This module checks every release a scan already
resolves against the offline advisory feed (`agent_audit_kit.advisory_feed`),
OSV's advisory records for PyPI and npm, which `aak update` keeps from the
exports it downloads for the malicious-release feed. A scan never touches the
network; without `aak update` the feed is the few records bundled with AAK.

What it reads (outside `SKIP_DIRS`, anywhere under the root), as
AAK-MALICIOUS-RELEASE-001 reads it:

* A lockfile's resolved versions: uv.lock, poetry.lock, Pipfile.lock,
  package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml and yarn.lock (v1),
  through the pin table's lockfile reader. A lockfile is read for its first
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
  declaration without a version is not judged.
* An installed `<name>-<version>.dist-info` directory in a site-packages or
  dist-packages directory the `_site_packages` walk reaches.

A release matches as its registry orders versions (`malicious_feed.Range`):
PEP 440 for PyPI, so MLflow's `>=3.12.0rc0, <3.17.0` takes 3.12.0rc0 and
3.17.0rc1 and leaves 3.17.0, and semver for npm. A finding names the advisory,
its CVE ids, the release and the fix, and carries the advisory's severity:
CRITICAL from CVSS 9.0, HIGH from 7.0, MEDIUM otherwise (see
`advisory_feed.record_severity`), INFO for a range. One finding per file,
package and advisory, at the first entry that resolves an affected release.

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
import os
import re
from pathlib import Path

from agent_audit_kit.advisory_feed import Advisory, AdvisoryFeed, load_feed
from agent_audit_kit.malicious_feed import canonical_name
from agent_audit_kit.models import Finding, Severity

from ._dependency_pins import read_text
from ._helpers import SKIP_DIRS, make_finding
from ._manifest_deps import MAX_LOCKFILE_BYTES, Declaration
from ._site_packages import site_entries, site_package_dirs
from ._versions import TOP, ZERO, Spans, intersect, next_patch, parse_range, parse_version, union
from .malicious_releases import _LOCKFILES, _REGISTRY, _declared, _is_manifest, _version_line, exact_pin
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries

RULE = "AAK-KNOWN-VULN-001"
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


def _finding(rel: str, evidence: str, line: int | None, level: str) -> Finding:
    finding = make_finding(RULE, rel, evidence, line)
    severity = _LEVEL[level]
    return finding if finding.severity is severity else dataclasses.replace(finding, severity=severity)


def _fix(advisory: Advisory, version: str) -> str:
    fixed = advisory.fix_for(version)
    return f"; it is fixed in {fixed}" if fixed else "; the advisory lists no fixed release"


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
            more = ""
            if len(hit) > 1:
                shown = ", ".join(v for v, _ in hit[1:4]) + (", ..." if len(hit) > 4 else "")
                more = f" (and {len(hit) - 1} more affected release{'s' if len(hit) > 2 else ''}: {shown})"
            findings.append(_finding(
                rel,
                f"{path.name} resolves {name} {version}{more}, which {advisory.label()} lists as "
                f"affected{_fix(advisory, version)}{_feed_note(feed, advisory)}",
                line,
                advisory.severity,
            ))
    return findings


def _affected_spans(advisory: Advisory) -> Spans:
    """The releases an advisory lists, on release triples (`_versions`), the
    form a declaration's range is read in."""
    pieces: list[tuple[tuple[int, int, int], tuple[int, int, int]]] = []
    for row in advisory.ranges:
        low = ZERO if row.introduced == "0" else parse_version(row.introduced)
        if low is None:
            continue
        if row.fixed is not None:
            high = parse_version(row.fixed)
        elif row.last_affected is not None:
            last = parse_version(row.last_affected)
            high = None if last is None else next_patch(last)
        else:
            high = TOP
        if high is not None and low < high:
            pieces.append((low, high))
    for listed in advisory.versions:
        exact = parse_version(listed)
        if exact is not None:
            pieces.append((exact, next_patch(exact)))
    return union(pieces)


def _below(advisory: Advisory) -> str:
    return f", fixed in {', '.join(advisory.fixed)}" if advisory.fixed else ", no fixed release listed"


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


def _installed_findings(project_root: Path, feed: AdvisoryFeed, scanned: set[str]) -> list[Finding]:
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


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report locked, pinned or installed releases an advisory lists as affected.

    Args:
        project_root: The root directory of the project, or an unpacked image
            root filesystem.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
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
    findings.extend(_installed_findings(project_root, feed, scanned))
    return findings, scanned


__all__ = ["MAX_RELEASES_PER_PACKAGE", "RULE", "evidence_cves", "scan"]
