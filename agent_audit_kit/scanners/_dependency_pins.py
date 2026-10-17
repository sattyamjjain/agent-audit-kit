"""How a version pin outside the CVE pin table reads a dependency.

Six modules keep a version pin of their own beside a code check:
langchain_vuln (AAK-LANGCHAIN-001 and -003), neo4j_cve (AAK-NEO4J-001),
ssrf_redirect (AAK-LANGCHAIN-SSRF-REDIR-001), ssrf_toctou (AAK-SSRF-TOCTOU-001),
transport_limits (AAK-MCPFRAME-001 and AAK-NEXT-AI-DRAW-001) and dns_rebind
(AAK-DNS-REBIND-002). A seventh, log_token_leak's pin on `splunk-mcp-server`,
is gone: it could only match the wrong package (see that module). Each read its
manifests with a regex of its own and took the first number after the package
name as the version in use, the flaw `_versions` retired from the pin table:

- An upper bound read as the version. `langchain-core<1.2.22` admits only
  releases CVE-2026-34070 affects, and it read as 1.2.22, the fix, so it was
  silent; `pkg<2.0.0,>=1.0.0` read as 2.0.0 while `pkg>=1.0.0,<2.0.0` read as
  1.0.0; and `mcp>=1.0` fired in pyproject.toml and not in requirements.txt,
  whose pattern acted on `==`, `<` and `<=` only.
- Other text sat where the version was looked for. Extras
  (`mcp[cli]==1.22.0`, the MCP SDK's own install line) hid it from a pattern
  with no place for them, and one that took any number after the name read
  `langchain-text-splitters[x]==1.1.2` as a name with no version.
- A format went unread. langchain_vuln listed every pyproject.toml and never
  matched one, because its pattern was anchored at the start of a requirement
  line and a TOML string starts with a quote; neo4j_cve's docstring promised
  pyproject.toml and read four requirements files; and a Poetry table entry
  (`mcp = "1.22.0"`) matched no module's pattern.

A module now parses each manifest into the declarations it makes, with the
reader the pin table uses (`_manifest_deps`): requirement lines with comments,
markers, extras and continuations handled, the PEP 621, dependency-group and
Poetry tables of pyproject.toml, and package.json's dependency maps and
overrides. The commands a package.json script runs are dropped, because none
of these rules ever read them. What the declarations allow is judged with the
pin table's own policy (`mcp_cve_pins_2026_07._deciding_declaration`), so the
two cannot drift apart:

- A range is reported when it admits an affected version, however its bounds
  are written: `<1.2.22`, `>=1.0,<2` and `<2,>=1.0` read alike, and so does a
  lower bound below the fix (`mcp>=1.2.0`), which a resolver may satisfy with
  an affected release. AAK-MCP-SDK-CVE-2026-52869-001 already reports that line.
- The declarations of one install (a requirements file, a PEP 621 list, an
  extra, a dependency group, a package.json section) are intersected, as pip
  merges them; an override (npm `overrides`, uv `override-dependencies`)
  replaces the regular entries; and a patched pin in another section does not
  clear a range in this one.
- A git reference, an archive (a URL or a local `file:` tarball) and a
  workspace spec are judged by the release their tag, file name or range
  names (`_with_referenced_version`). Releases compare on their first three
  numbers, as in the pin table, so a pre-release of the fix reads as the fix.
- A declaration that states no version AAK can read (a bare name, `*`,
  `latest`, a local directory, a git reference to a commit or a branch) is
  reported only by a rule that always reported one (`report_unversioned`).

One finding per rule per file, on the line of the declaration that decided it.

The six modules read their manifests, lockfiles and Python sources through
`_regular_bytes`, which reads only a regular file and never waits on a FIFO
named like one of them.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path

from agent_audit_kit.scanners._helpers import collecting_refusals, loads_json, loads_toml, refuse
from agent_audit_kit.scanners._manifest_deps import (
    MAX_LOCKFILE_BYTES,
    MAX_MANIFEST_BYTES,
    Declaration,
    declaration_lines,
    declarations,
    package_json_declarations,
    pyproject_declarations,
    requirements_declarations,
)
from agent_audit_kit.scanners._versions import (
    NONE,
    TOP,
    Ver,
    exact_version,
    intersect,
    parse_range,
    parse_version,
)
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import (
    _admits_affected,
    _deciding_declaration,
    _declaration_index,
    _names_match,
    _Pin,
    _pin_applies,
    _pin_candidates,
)
from agent_audit_kit.scanners.supply_chain import _lockfile_index, _lockfile_lookup


@dataclass(frozen=True)
class DependencyPin:
    """One package and the first release that fixes it."""

    names: tuple[str, ...]          # the package as its registry names it
    fixed: Ver                      # every release below this one is affected
    ecosystem: str | None = None    # "py", "js", or None for either registry
    # Report a declaration that states no readable version. Off for most of
    # these rules: their old patterns needed a number, and an unpinned
    # reference usually installs a fixed release.
    report_unversioned: bool = False

    def as_table_pin(self) -> _Pin:
        """The same pin as the CVE table states one, for its policy to judge."""
        return _Pin("", self.names[0], self.names, self.fixed, ecosystem=self.ecosystem,
                    requires_version=not self.report_unversioned)


@dataclass(frozen=True)
class PinnedDependency:
    """The declaration that puts a project on an affected release."""

    declaration: Declaration
    line: int | None
    fixed: Ver

    @property
    def quoted(self) -> str:
        """The declaration as written, and what it admits, for evidence."""
        return self.quote()

    def quote(self, where: str = "") -> str:
        """The declaration as written, then `where` (" in devDependencies"), then
        what it admits.

        An exact pin needs no gloss. A range says that it admits releases below
        the fix: a lower bound such as `mcp>=1.2.0` pins nothing, and is reported
        because a resolver may still pick an affected release. A declaration
        whose version AAK cannot read says so.
        """
        declaration = self.declaration
        spans = parse_range(declaration.version, declaration.dialect)
        if spans is None:
            how = ", which states no version AAK can read"
        elif exact_version(spans) is not None:
            how = ""
        else:
            how = f", which admits releases below {_dotted(self.fixed)}"
        return f"{declaration.text!r}{where}{how}"


def _parsed(path: Path, text: str) -> tuple[list[Declaration], object]:
    """The dependencies `path` declares as parsed, and the parsed document.

    Every requirements file is read as one, whatever its name, so
    `dev-requirements.txt` counts though it does not start with "requirements".

    A package.json loses its `scripts` before it is read, not after. None of
    these rules reads the commands a script runs, and tokenising them was the
    costly part of reading the file: with shlex, quadratic in the length of one
    word, a 300 KB script word took 3.5 s to read for launches that were then
    thrown away. A file that does not parse declares nothing, as in
    `declarations`.
    """
    name = path.name.lower()
    if name.endswith(".txt"):
        return requirements_declarations(text), None
    try:
        if name == "package.json":
            data = loads_json(text, path)
            if not isinstance(data, dict):
                return [], None
            return package_json_declarations({k: v for k, v in data.items() if k != "scripts"}), data
        if name == "pyproject.toml":
            document = loads_toml(text, path)
            return pyproject_declarations(document), document
    except ValueError:
        # TOMLDecodeError and JSONDecodeError are ValueErrors, and so is what
        # `loads_json` and `loads_toml` raise for a text nested deeper than the
        # parser recurses (a 3,000-deep inline table), which they refuse.
        return [], None
    except RecursionError:
        # A dependency table nested past the recursion limit, refused as
        # `declarations` refuses one.
        refuse(path, "dependency table nested too deep to read (RecursionError)")
        return [], None
    return [d for d in declarations(path, text) if d.kind != "launch"], None


def manifest_declarations(path: Path, text: str) -> list[Declaration]:
    """The dependencies `path` declares, each with the version a reference names.

    See `_with_referenced_version`: a git reference, an archive URL or a
    workspace spec is judged by the release it names.
    """
    found, document = _parsed(path, text)
    return [_with_referenced_version(d, document) for d in found]


# What a git reference or archive names a release with. A tag counts only as
# digits, a dot and a digit after an optional `v`, so a commit hash, a branch
# and `HEAD` name none.
_VCS_SCHEMES = ("git+", "hg+", "svn+", "bzr+")
_ARCHIVES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".whl")


def _digits(text: str) -> bool:
    return bool(text) and all("0" <= c <= "9" for c in text)


def _names_a_release(token: str) -> bool:
    text = token[1:] if token[:1] in ("v", "V") else token
    dot = text.find(".")
    return dot > 0 and _digits(text[:dot]) and _digits(text[dot + 1:dot + 2])


def _tag_release(tag: str) -> Ver | None:
    """The release a tag names: `v1.2.3`, `1.2.3`, `name==1.2.3`, `release-1.2.3`.

    A name holding a `/` names none, whatever it looks like: `release/1.1.14`,
    `feature/v2.0.0` and `refs/heads/1.1.14` are branches, and reading the last
    segment took a branch named after the fix as the fix. `refs/tags/<tag>` is
    the one exception, and names what `<tag>` does.
    """
    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/"):]
    if "/" in tag:
        return None
    for candidate in (tag.rsplit("==", 1)[-1], tag.rsplit("-", 1)[-1]):
        if _names_a_release(candidate):
            return parse_version(candidate)
    return None


def _archive_release(url: str) -> Ver | None:
    """The release an archive's file name states: `sdk-1.20.0.tgz`,
    `pkg-1.2.3.tar.gz`, `pkg-1.2.3-py3-none-any.whl`, GitHub's `v1.2.3.tar.gz`."""
    name = url.split("#", 1)[0].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    lowered = name.lower()
    for suffix in _ARCHIVES:
        if lowered.endswith(suffix):
            for part in name[:-len(suffix)].split("-"):
                if _names_a_release(part):
                    return parse_version(part)
    return None


def _npm_reference(spec: str) -> str | None:
    """The version an npm git, tarball or workspace spec names, as an npm range."""
    if spec.startswith("workspace:"):
        rest = spec[len("workspace:"):]
        return rest if rest not in ("", "*", "^", "~") else None
    if "#" in spec:  # github:o/r#v1.2.3, git+https://...#1.2.3, o/r#semver:^1.2.0
        fragment = spec.rsplit("#", 1)[1]
        if fragment.startswith("semver:"):
            return fragment[len("semver:"):] or None
        release = _tag_release(fragment)
        return _dotted(release) if release else None
    if spec.startswith(("http://", "https://", "file:")):  # a tarball, local or not
        release = _archive_release(spec)
        return _dotted(release) if release else None
    return None


def _pip_reference(text: str) -> str | None:
    """The version a pip VCS or URL requirement names, as an exact pin: its tag
    (`git+https://host/o/r@v1.2.3`, `@name==1.2.3`) or its archive's file name.
    The tag is read after the repository path's last `@`, never from the
    userinfo before the host."""
    at = text.find("://")
    if at == -1:
        return None
    start = at
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "+-."):
        start -= 1
    end = at + 3
    while end < len(text) and not text[end].isspace():
        end += 1
    url = text[start:end]
    if url.startswith(_VCS_SCHEMES):
        location = url.split("#", 1)[0][url.find("://") + 3:]
        slash = location.find("/")
        repository = location[slash:] if slash != -1 else ""
        release = _tag_release(repository.rsplit("@", 1)[1]) if "@" in repository else None
    else:
        release = _archive_release(url)
    return f"=={_dotted(release)}" if release else None


def _poetry_reference(declaration: Declaration, document: object) -> str | None:
    """The release a Poetry git table's `tag` or `rev`, or a url table's archive,
    names, as an exact pin."""
    node = document
    for key in declaration.path:
        if isinstance(node, dict):
            node = node.get(key)
        elif isinstance(node, list) and isinstance(key, int) and 0 <= key < len(node):
            node = node[key]
        else:
            return None
    if not isinstance(node, dict):
        return None
    for key in ("tag", "rev"):
        value = node.get(key)
        release = _tag_release(value) if isinstance(value, str) else None
        if release:
            return f"=={_dotted(release)}"
    url = node.get("url")
    release = _archive_release(url) if isinstance(url, str) else None
    return f"=={_dotted(release)}" if release else None


def _with_referenced_version(declaration: Declaration, document: object) -> Declaration:
    """`declaration`, with the version the reference it names states, if it names one.

    A git reference, an archive and a workspace spec state a release: in the
    tag (`github:o/r#v1.20.0`, `git+https://host/o/r@v1.1.13`, the LangChain
    monorepo's `@langchain-openai==1.1.14`, a Poetry `tag`), in the file name
    (`sdk-1.20.0.tgz` at a URL or behind `file:`, a Poetry `url`), or in the
    range after `workspace:`. The first-number readers took the version from
    there, and read as stating none, AAK-DNS-REBIND-002 (HIGH) lost every one,
    while the two langchain SSRF pins, which report an unversioned reference,
    reported a git requirement at the patched release as stating no version,
    which no upgrade could clear. A reference that names no release (a commit,
    a branch or any name holding a `/` but `refs/tags/<tag>`, `workspace:*`, a
    local directory) still states no version. The text stays as written, for
    the evidence and the line.
    """
    if declaration.dialect == "npm":
        version = _npm_reference(declaration.version)
    elif declaration.version:
        return declaration
    elif declaration.dialect == "poetry":
        version = _poetry_reference(declaration, document)
    else:
        version = _pip_reference(declaration.text)
    return declaration if version is None else replace(declaration, version=version)


@dataclass(frozen=True)
class Manifest:
    """One manifest as the version pins read it: its text and its declarations."""

    path: Path
    text: str
    declarations: tuple[Declaration, ...]

    @cached_property
    def line_of(self) -> Callable[[Declaration], int | None]:
        """The line each declaration is written on, its positions read once."""
        return declaration_lines(self.path, self.text)

    @cached_property
    def _found(self) -> list[Declaration]:
        return list(self.declarations)

    @cached_property
    def _index(self) -> dict[str, list[int]]:
        """Where each package is declared, filed once per file by the pin table's index."""
        return _declaration_index(self._found)

    def naming(self, pin: _Pin) -> list[Declaration]:
        """The declarations that may name `pin`'s packages, in file order.

        Each pin used to filter every declaration of the file, so on a 1.9 MB
        pyproject.toml of 100,000 dependencies the six pins cost more than the
        parse. This is the pin table's own candidate list, a superset of what
        `_deciding_declaration` keeps, so no verdict changes.
        """
        return _pin_candidates(pin, self._found, self._index)


# Parsed manifests are kept, keyed by path and content, so the modules that
# read one root pyproject.toml (and a package.json, and a requirements file)
# share one parse in a scan. Each used to parse it alone: a 1.9 MB
# pyproject.toml cost 3.6 s of CPU across them, where one parse costs about
# 0.6 s. The content digest, not the modification time, says a file is
# unchanged: a coarse filesystem clock leaves two writes of one size with the
# same time, which `aak fix` rewriting a pin can produce. The least recently
# used entries go once more than 32 are kept or their text passes 8 MB, so a
# repository of many large manifests cannot hold them all in memory.
_MANIFESTS: OrderedDict[tuple[str, bytes], Manifest] = OrderedDict()
_MANIFESTS_KEPT = 32
_MANIFESTS_TEXT_BUDGET = 8_000_000
_MANIFESTS_LOCK = threading.Lock()


# Opened without waiting: a FIFO opens at once, with no writer, and is then refused.
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_READ_CHUNK = 1 << 16


def _regular_bytes(path: Path, limit: int | None) -> bytes | None:
    """`path`'s bytes, or None when it is missing, unreadable, not a regular file, or
    holds more than `limit` bytes (None: any size).

    A repository chooses what sits at each name these modules read. A FIFO blocks
    the read that opens it until a writer comes, and reports a size of 0, so a size
    check lets it through. The modules found requirements files, every
    pyproject.toml and their Python sources by glob and read whatever matched, so a
    FIFO named requirements.txt, pyproject.toml or app.py stopped `aak scan` for
    good. A link is followed, and what it names must be a regular file: one to a
    FIFO or a device is refused before it is opened, and the file is opened without
    waiting and its descriptor checked again, so one swapped for a FIFO after that
    look is refused too. At most `limit` + 1 bytes are read, so a file that holds
    more than the size it reported is refused, not read whole. Anything refused
    reads as a missing file.
    """
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return None
        fd = os.open(path, _READ_FLAGS)
    except OSError:
        return None
    chunks: list[bytes] = []
    held = 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (limit is not None and info.st_size > limit):
            return None
        want = info.st_size + 1  # a file as large as it says ends on the first read
        while limit is None or held <= limit:
            chunk = os.read(fd, want if limit is None else min(want, limit + 1 - held))
            if not chunk:
                break
            chunks.append(chunk)
            held += len(chunk)
            want = _READ_CHUNK
    except OSError:
        return None
    finally:
        os.close(fd)
    return None if limit is not None and held > limit else b"".join(chunks)


def _read(path: Path, limit: int) -> tuple[tuple[str, bytes], bytes] | None:
    """`path`'s bytes and their cache key, or None when it is missing, unreadable,
    not a regular file or over `limit` bytes (`_regular_bytes`). The key is the
    absolute path and a digest of the bytes."""
    raw = _regular_bytes(path, limit)
    if raw is None:
        return None
    return (str(path.absolute()), hashlib.blake2b(raw, digest_size=16).digest()), raw


def _decoded(raw: bytes) -> str:
    """The text as the modules always read a file: UTF-8 with replacement, universal newlines."""
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def read_text(path: Path, limit: int | None = None) -> str | None:
    """`path` decoded as `Path.read_text(encoding="utf-8", errors="replace")` decodes
    it, or None when it is missing, unreadable, not a regular file or over `limit`
    bytes. The modules read their source files through this, so a FIFO named
    `app.py` is skipped like a missing file (`_regular_bytes`)."""
    raw = _regular_bytes(path, limit)
    return None if raw is None else _decoded(raw)


def read_manifest(path: Path) -> Manifest | None:
    """`path` read and parsed, or None when it is missing, unreadable, not a regular
    file or too large.

    A manifest over MAX_MANIFEST_BYTES (2 MB), the CVE pin table's limit, is not
    read, so a crafted file costs no rule more than one bounded parse. The text
    is decoded as the modules always read it (UTF-8 with replacement, universal
    newlines), so evidence and lines are unchanged.

    Args:
        path: The manifest; its name selects the format.

    Returns:
        The manifest, shared with every other caller that reads the same file
        content during the process unless reading it refused a file, or None.
    """
    read = _read(path, MAX_MANIFEST_BYTES)
    if read is None:
        return None
    key, raw = read
    with _MANIFESTS_LOCK:
        cached = _MANIFESTS.get(key)
        if cached is not None:
            _MANIFESTS.move_to_end(key)
            return cached
    text = _decoded(raw)
    with collecting_refusals() as refused:
        manifest = Manifest(path, text, tuple(manifest_declarations(path, text)))
    if refused:
        # Not kept: each reader of a file refused here records the refusal
        # itself, as AAK-INTERNAL-SCANNER-FAIL names the scanner that skipped it.
        for where, reason in refused.items():
            refuse(where, reason)
        return manifest
    with _MANIFESTS_LOCK:
        _MANIFESTS[key] = manifest
        held = sum(len(m.text) for m in _MANIFESTS.values())
        while len(_MANIFESTS) > 1 and (len(_MANIFESTS) > _MANIFESTS_KEPT or held > _MANIFESTS_TEXT_BUDGET):
            _, dropped = _MANIFESTS.popitem(last=False)
            held -= len(dropped.text)
    return manifest


def pinned_dependency(manifest: Manifest, pin: DependencyPin) -> PinnedDependency | None:
    """The declaration in `manifest` that admits an affected release, or None.

    Args:
        manifest: The file, from `read_manifest`.
        pin: The package and its fix.

    Returns:
        The deciding declaration and its line, or None when the file declares
        no affected release of the package.
    """
    table_pin = pin.as_table_pin()
    declaration = _deciding_declaration(table_pin, manifest.naming(table_pin))
    if declaration is None:
        return None
    return PinnedDependency(declaration, manifest.line_of(declaration), pin.fixed)


@dataclass(frozen=True)
class Lockfile:
    """One lockfile as the version pins read it: every package it resolves, by name."""

    path: Path
    index: dict[str, list[Ver]]
    size: int  # its bytes, which the cache's budget counts


# Lockfile indexes are kept the same way, by path and content. Each SSRF pin
# used to index every lockfile again, so a 31 MiB uv.lock cost 2.4 s of CPU
# across the two where one index costs 1.2 s, and the line search it replaced
# took 1.0 s. An index holds every package the file resolves, about 80 MB for
# that uv.lock, so the least recently used go once more than 4 are kept or
# their files pass 64 MiB: room for a root's three lockfiles at ordinary sizes,
# and for two at the 32 MiB limit.
_LOCKFILES: OrderedDict[tuple[str, bytes], Lockfile] = OrderedDict()
_LOCKFILES_KEPT = 4
_LOCKFILES_BYTE_BUDGET = 2 * MAX_LOCKFILE_BYTES
_LOCKFILES_LOCK = threading.Lock()


def read_lockfile(path: Path, limit: int = MAX_LOCKFILE_BYTES) -> Lockfile | None:
    """`path` read and indexed, or None when it is missing, unreadable, not a regular
    file or too large.

    A lockfile over MAX_LOCKFILE_BYTES (32 MiB), the CVE pin table's limit, is
    not read. The index is the pin table's (`supply_chain._lockfile_index`), so
    Pipfile.lock's JSON, the `[[package]]` blocks of poetry.lock and uv.lock,
    and a PEP 503 spelling of a name all read as the pins read them.

    Args:
        path: The lockfile; its name selects the format.
        limit: The largest file read, in bytes. The size is checked before the
            cache is, so a cached index never outlives a lower limit.

    Returns:
        The lockfile, shared with every other caller that reads the same file
        content during the process unless reading it refused the file, or None.
    """
    read = _read(path, limit)
    if read is None:
        return None
    key, raw = read
    with _LOCKFILES_LOCK:
        cached = _LOCKFILES.get(key)
        if cached is not None:
            _LOCKFILES.move_to_end(key)
            return cached
    with collecting_refusals() as refused:
        lockfile = Lockfile(path, _lockfile_index(_decoded(raw), path.name.lower(), path), len(raw))
    if refused:
        # Not kept, as in `read_manifest`.
        for where, reason in refused.items():
            refuse(where, reason)
        return lockfile
    with _LOCKFILES_LOCK:
        _LOCKFILES[key] = lockfile
        held = sum(entry.size for entry in _LOCKFILES.values())
        while len(_LOCKFILES) > 1 and (len(_LOCKFILES) > _LOCKFILES_KEPT or held > _LOCKFILES_BYTE_BUDGET):
            _, dropped = _LOCKFILES.popitem(last=False)
            held -= dropped.size
    return lockfile


def locked_affected_versions(lockfile: Lockfile, pin: DependencyPin) -> list[Ver]:
    """The affected versions a lockfile resolves the package to, lowest first.

    The pattern this replaced wanted a TOML `name =` line followed by a
    `version =` line, so it never matched a Pipfile.lock, though both modules
    listed one.
    """
    filename = lockfile.path.name.lower()
    resolved = _lockfile_lookup(lockfile.index, filename, pin.names)
    return [v for v in resolved if v < pin.fixed]


def _dotted(version: Ver) -> str:
    return ".".join(str(n) for n in version)


@dataclass(frozen=True)
class Raised:
    """What raising one package's declarations in one manifest came to."""

    text: str      # the manifest to write: the input, unchanged, when anything was refused
    raised: int    # declarations rewritten; 0 when anything was refused
    # (line, why) for each declaration that admits an affected release and cannot
    # be rewritten where it is written.
    refused: tuple[tuple[int | None, str], ...] = ()


def raise_to_fix(path: Path, text: str, pin: DependencyPin) -> Raised:
    """`text` with every declaration that admits an affected release raised to the fix.

    `aak fix` uses this, so a fix reads the manifest exactly as the rule does
    and rewrites what the rule reports and nothing else. Its bumps used to match
    `name op version` at the start of a requirement line and judge the first
    number, so they left `langchain-core<1.2.22` alone (the first number is the
    fix), could not see a pin with extras, and refused pyproject.toml, all of
    which the rules report.

    Each declaration that admits an affected release keeps what it admitted
    from the fix up: `>=1.0,<2` becomes `>=1.2.22,<2.0.0`, and `~=1.2.0` becomes
    `>=1.2.22,<1.3.0`. One that admitted nothing at or above the fix
    (`<1.2.22`, `==1.2.21`), or several ranges, becomes `>=<fix>`. Extras,
    markers, comments and the file's line endings stay as they were. The
    result is read again with the rule's policy before it is returned.

    A manifest is rewritten whole or not at all. A declaration that spans
    several lines, keeps its version on a line of its own (a Poetry sub-table)
    or carries a `--hash` (which pip checks against the pinned release, so a
    range would fail the install) is refused, and then nothing is rewritten:
    raising the other lines alone could leave a file that no resolver can
    satisfy, such as `>=1.2.22` beside a hashed `==1.2.21`.
    """
    table_pin = pin.as_table_pin()
    found, document = _parsed(path, text)
    targets = [
        (d, judged) for d, judged in ((d, _with_referenced_version(d, document)) for d in found)
        if _pin_applies(table_pin, judged.ecosystem) and _names_match(table_pin, judged)
        and _admits_affected(table_pin, judged)
    ]
    if not targets:
        return Raised(text, 0)
    # Lines are counted in `\n`s, as `declaration_lines` counts them; splitlines()
    # also breaks on rarer separators. The positions are read once for the file.
    line_of = declaration_lines(path, text)
    lines = text.split("\n")
    refused: list[tuple[int | None, str]] = []
    for declaration, judged in targets:
        number = line_of(declaration)
        if number is None:
            refused.append((None, f"{declaration.text!r} is not written where AAK read it"))
            continue
        if judged is not declaration:
            refused.append((number, "names its release in a git reference or URL; point that at a fixed release"))
            continue
        line, why = _raised_line(lines, number - 1, declaration, _raised_spec(declaration, pin.fixed))
        if why:
            refused.append((number, why))
        else:
            lines[number - 1] = line
    if refused:
        return Raised(text, 0, tuple(refused))
    raised = "\n".join(lines)
    if pinned_dependency(Manifest(path, raised, tuple(manifest_declarations(path, raised))), pin) is not None:
        return Raised(text, 0, ((None, "the rewritten file would still admit a release below the fix"),))
    return Raised(raised, len(targets))


def _raised_spec(declaration: Declaration, fixed: Ver) -> str:
    """What `declaration` admitted from `fixed` up, as a specifier, or `>=fixed`."""
    spans = parse_range(declaration.version, declaration.dialect)
    kept = intersect(spans, ((fixed, TOP),)) if spans is not None else NONE
    if len(kept) == 1:
        lo, hi = kept[0]
        joiner = " " if declaration.dialect == "npm" else ","
        return f">={_dotted(lo)}" + ("" if hi == TOP else f"{joiner}<{_dotted(hi)}")
    return f">={_dotted(fixed)}"


def _raised_line(lines: list[str], index: int, declaration: Declaration, spec: str) -> tuple[str, str]:
    """`lines[index]` with the declaration's version replaced by `spec`, and "".

    Or the line unchanged and why it cannot be rewritten. A requirement string
    as written (a requirements line, a PEP 621 entry) is found on the line and
    its version replaced inside it; a TOML value (`name = "^1.2"`, `{ version =
    "<1.2" }`) is found as the quoted version.
    """
    line = lines[index]
    if declaration.section == "requirements":
        logical = [line]
        while logical[-1].rstrip("\r").endswith("\\") and index + len(logical) < len(lines):
            logical.append(lines[index + len(logical)])
        if any("--hash" in part for part in logical):
            return line, "has a --hash, which pip checks against the pinned release; re-lock it instead"
    at = line.find(declaration.text)
    if at != -1:
        start = declaration.text.find(declaration.version, len(declaration.name))
        if start == -1:
            return line, "states its version in a form AAK does not rewrite"
        requirement = declaration.text[:start] + spec + declaration.text[start + len(declaration.version):]
        return line[:at] + requirement + line[at + len(declaration.text):], ""
    for quote in ('"', "'"):
        token = quote + declaration.version + quote
        at = line.find(token)
        if at != -1:
            return line[:at] + quote + spec + quote + line[at + len(token):], ""
    if declaration.section == "requirements":
        return line, "continues onto the next line"
    return line, "keeps its version on another line"
