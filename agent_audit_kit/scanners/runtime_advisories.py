"""Runtime advisories: a declared language runtime, or a bundled codec, below its fix.

Two critical runtime flaws landed in one week and nothing in AAK read a runtime
version. PHP2Shell (CVE-2026-109618, CVE-2026-109619, fixed in PHP 8.2.35,
8.3.36, 8.4.27 and 8.5.12, in CISA KEV from 26 Oct 2026) is in the interpreter
an MCP server's PHP backend runs on, and CVE-2026-111497, an out-of-bounds write
in Google's Brotli decoder, is in the copy Node.js bundles (fixed in 22.23.4,
24.22.1 and 26.12.1, no other line) and in the Brotli and brotlicffi wheels on
PyPI (fixed in 1.2.1 and 1.2.1.0). A dependency pin never sees either: the
version that matters is the runtime the image, the version file or the MCP
launcher names. This module reads those against a bundled advisory file
(`data/runtime_advisories.json`, or a copy at
`~/.agent-audit-kit/runtime_advisories.json`, read first, as `vuln_db` reads its
cache). A scan never fetches it.

* AAK-RUNTIME-ADV-001: a declared runtime below the fixed release on its line,
  or on a line no fixed release exists for (an end-of-life line).
* AAK-RUNTIME-ADV-002 (INFO): a runtime named by a floating tag (`node:24`,
  `php:8`, `latest`, a managed runtime such as App Engine's `nodejs22`) on a line
  that has a fix: whether it already runs the fix cannot be told from the file.
* AAK-RUNTIME-ADV-003: a lockfile, or an exact pin in a manifest, that puts a
  library bundling an affected codec (Brotli, brotlicffi) below its fixed release.

What it reads, outside `SKIP_DIRS`:

* the `FROM` of every Dockerfile and Containerfile naming an official `node`,
  `php` or `python` image, through `startup_hooks`' Dockerfile reader, with
  global `ARG` defaults filled in;
* `.nvmrc`, `.node-version`, `.python-version` and `.tool-versions`;
* `engines.node` in package.json, judged at the lowest version the range admits;
* `runtime:` in App Engine `app.yaml` and Serverless `serverless.yml`;
* MCP configs whose `command` (or an argument) is a runtime under a versioned
  install path: nvm, asdf, mise, Volta, fnm, n, pyenv and Homebrew's Cellar;
* uv.lock, poetry.lock, Pipfile.lock, package-lock.json, pnpm-lock.yaml and
  yarn.lock, and exact pins in requirements*.txt, pyproject.toml and Pipfile,
  for the libraries an advisory names (`pypi:<name>`, `npm:<name>`).
"""

from __future__ import annotations

import dataclasses
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from agent_audit_kit.models import Finding, Severity

from ._dependency_pins import read_manifest, read_text
from ._helpers import (
    CONFIG_MAX_BYTES,
    SKIP_DIRS,
    find_line_number,
    find_line_numbers,
    iter_mcp_servers,
    load_yaml,
    loads_json,
    loads_jsonc,
    make_finding,
    read_text_capped,
)
from ._manifest_deps import MAX_LOCKFILE_BYTES
from ._versions import parse_range
from .malicious_releases import exact_pin
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries
from .startup_hooks import _dockerfile_kind, _words, instructions

_ADV_001, _ADV_002, _ADV_003 = "AAK-RUNTIME-ADV-001", "AAK-RUNTIME-ADV-002", "AAK-RUNTIME-ADV-003"

BUNDLED: Path = Path(__file__).resolve().parent.parent / "data" / "runtime_advisories.json"
FILE_NAME = "runtime_advisories.json"
_RUNTIMES = ("node", "php", "python")
_DISPLAY = {"node": "Node.js", "php": "PHP", "python": "Python"}


def cache_path() -> Path:
    """A local copy of the advisory file, read before the bundled one."""
    return Path.home() / ".agent-audit-kit" / FILE_NAME


# ---- versions and lines -------------------------------------------------------------

Version = tuple[int, ...]
_VERSION_RE = re.compile(r"v?(\d{1,6}(?:\.\d{1,6}){0,3})")


def parse_version(text: str) -> Version | None:
    """The dotted numbers a version text opens with (`v24.22.0-slim` is 24.22.0)."""
    m = _VERSION_RE.match(text.strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def _pad(v: Version, n: int) -> Version:
    return v + (0,) * (n - len(v))


def _lt(a: Version, b: Version) -> bool:
    n = max(len(a), len(b))
    return _pad(a, n) < _pad(b, n)


def _line_width(subject: str) -> int:
    """How many numbers name a release line: Node.js lines are majors (24),
    PHP, Python and the libraries major.minor (8.4, 1.2)."""
    return 1 if subject == "node" else 2


def line_key(subject: str, version: Version) -> str | None:
    width = _line_width(subject)
    return ".".join(str(n) for n in version[:width]) if len(version) >= width else None


def _dotted(v: Version) -> str:
    return ".".join(str(n) for n in v)


# ---- the advisory file -----------------------------------------------------------------


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: tuple[str, ...]
    subject: str
    title: str
    fixed_by_line: dict[str, str]
    unfixed_lines_affected: bool
    affected_from: str | None
    affected_from_by_line: dict[str, str]
    kev_added: str | None
    kev_due: str | None
    severity: Severity
    url: str

    @property
    def label(self) -> str:
        kev = (
            f"; CISA KEV, added {self.kev_added}" + (f", due {self.kev_due}" if self.kev_due else "")
            if self.kev_added else ""
        )
        return f"{self.id} ({self.title}{kev})"


@dataclass(frozen=True)
class Advisories:
    generated_at: str
    source: str
    origin: str
    by_subject: dict[str, tuple[Advisory, ...]]
    eol: dict[str, dict[str, str]]
    eol_source: dict[str, tuple[str, str]]

    def summary(self) -> dict[str, str]:
        return {"generatedAt": self.generated_at, "source": self.source, "origin": self.origin}

    def eol_note(self, subject: str, line: str) -> str:
        date = self.eol.get(subject, {}).get(line)
        if date is None:
            return ""
        url, read_at = self.eol_source.get(subject, ("endoflife.date", ""))
        return f"; the {line} line reached end of life on {date} ({url}, read {read_at})"


def _strings(value: object) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _str_map(value: object) -> dict[str, str]:
    return {str(k): v for k, v in value.items() if isinstance(v, str)} if isinstance(value, dict) else {}


def parse_advisories(data: object, origin: str) -> Advisories:
    """The advisory file, parsed; ValueError when it is not one."""
    if not isinstance(data, dict) or not isinstance(data.get("advisories"), list):
        raise ValueError("no `advisories` list")
    by_subject: dict[str, list[Advisory]] = {}
    for raw in data["advisories"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not isinstance(raw.get("subject"), str):
            continue
        try:
            severity = Severity[str(raw.get("severity", "HIGH")).upper()]
        except KeyError:
            continue
        if raw.get("kev_added"):
            severity = Severity.CRITICAL
        advisory = Advisory(
            id=raw["id"],
            aliases=_strings(raw.get("aliases")),
            subject=raw["subject"],
            title=str(raw.get("title") or raw["id"]),
            fixed_by_line=_str_map(raw.get("fixed_by_line")),
            unfixed_lines_affected=raw.get("unfixed_lines_affected") is True,
            affected_from=raw.get("affected_from") if isinstance(raw.get("affected_from"), str) else None,
            affected_from_by_line=_str_map(raw.get("affected_from_by_line")),
            kev_added=raw.get("kev_added") if isinstance(raw.get("kev_added"), str) else None,
            kev_due=raw.get("kev_due") if isinstance(raw.get("kev_due"), str) else None,
            severity=severity,
            url=str(raw.get("url") or ""),
        )
        by_subject.setdefault(_subject_key(advisory.subject), []).append(advisory)
    eol: dict[str, dict[str, str]] = {}
    eol_source: dict[str, tuple[str, str]] = {}
    for subject, table in (data.get("eol") or {}).items():
        if isinstance(table, dict):
            eol[subject] = _str_map(table.get("lines"))
            eol_source[subject] = (str(table.get("url") or ""), str(table.get("read_at") or ""))
    return Advisories(
        generated_at=str(data.get("generated_at") or ""),
        source=str(data.get("source") or ""),
        origin=origin,
        by_subject={k: tuple(v) for k, v in by_subject.items()},
        eol=eol,
        eol_source=eol_source,
    )


def _subject_key(subject: str) -> str:
    """`pypi:Brotli` and `pypi:brotli` are one subject: PyPI names compare PEP 503."""
    if subject.startswith("pypi:"):
        return "pypi:" + re.sub(r"[-_.]+", "-", subject[5:]).lower()
    if subject.startswith("npm:"):
        return "npm:" + subject[4:].lower()
    return subject


_LOADED: dict[tuple[str, int, int], Advisories] = {}


def _load(path: Path, origin: str) -> Advisories:
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    if key not in _LOADED:
        text = read_text_capped(path, 8_000_000)
        _LOADED.clear()
        _LOADED[key] = parse_advisories(loads_json(text, path), origin)
    return _LOADED[key]


def load_advisories() -> Advisories:
    """The local copy when it exists and parses, else the bundled file."""
    cached = cache_path()
    if cached.is_file():
        try:
            return _load(cached, "cached")
        except (OSError, ValueError):
            pass
    return _load(BUNDLED, "bundled")


def advisories_summary() -> dict[str, str]:
    """`Advisories.summary()` for the file a scan reads."""
    return load_advisories().summary()


# ---- judging a version or a line ---------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    advisory: Advisory
    fixed: str | None  # the fixed release on the line, or None: the line has none


def _above_fixes(subject: str, line: str, advisory: Advisory) -> bool:
    """Is `line` newer than every line the advisory fixed? Such a line was
    released after the fix and is taken to carry it."""
    newest = max((parse_version(k) or () for k in advisory.fixed_by_line), default=())
    here = parse_version(line) or ()
    return bool(newest) and _lt(newest, here)


def judge(advisory: Advisory, subject: str, version: Version) -> Verdict | None:
    """Does a runtime or library at `version` carry the advisory's flaw?"""
    line = line_key(subject, version)
    if line is None:
        return None
    low = advisory.affected_from_by_line.get(line, advisory.affected_from)
    low_v = parse_version(low) if low else None
    if low_v is not None and _lt(version, low_v):
        return None
    fixed = advisory.fixed_by_line.get(line)
    if fixed is not None:
        fixed_v = parse_version(fixed)
        return Verdict(advisory, fixed) if fixed_v is not None and _lt(version, fixed_v) else None
    if not advisory.unfixed_lines_affected or _above_fixes(subject, line, advisory):
        return None
    return Verdict(advisory, None)


def judge_line(advisory: Advisory, subject: str, line: str) -> Verdict | None | str:
    """A declaration that names only a line (`node:20`, `nodejs20.x`, `php:8.1`).

    A line with a fixed release floats onto it or not, which a file cannot say:
    "floating". A line with no fixed release is affected whatever its patch,
    unless it is wholly below where the flaw arrived or newer than every fix.
    """
    if line in advisory.fixed_by_line:
        return "floating"
    if not advisory.unfixed_lines_affected or _above_fixes(subject, line, advisory):
        return None
    here = parse_version(line) or ()
    low = advisory.affected_from_by_line.get(line, advisory.affected_from)
    low_v = parse_version(low) if low else None
    if low_v is not None and _lt(here, _pad(low_v[: len(here)], len(here))):
        return None  # the whole line predates the flaw
    return Verdict(advisory, None)


# ---- declarations ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Declared:
    """One place a file names a runtime: a full version, a line, or nothing to go on."""

    subject: str
    shown: str              # the text as written, for the evidence
    where: str              # how it is used ("FROM", ".nvmrc", "engines.node", ...)
    line_no: int | None
    version: Version | None = None   # a full release
    line: str | None = None          # only a release line
    managed: bool = False            # a platform picks the patch (App Engine, Lambda)
    note: str = ""                   # appended to the evidence


_OFFICIAL_PREFIXES = (
    "docker.io/library/", "index.docker.io/library/", "registry-1.docker.io/library/",
    "docker.io/", "index.docker.io/", "library/", "mirror.gcr.io/library/",
    "public.ecr.aws/docker/library/",
)
_ARG_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
# Past this an expansion is no image reference (a repository name is at most 255
# characters, a tag 128): `FROM ${X}${X}...` of an ARG as long, in a 100 KB file, took
# 800 MB and would have reached tens of gigabytes at the 1 MB cap.
_MAX_REFERENCE = 1024


def _expand(word: str, args: dict[str, str]) -> str | None:
    """`word` with the global ARG defaults filled in, or None when one is unset or
    the result runs past `_MAX_REFERENCE` characters."""
    pieces: list[str] = []
    size = last = 0
    for m in _ARG_RE.finditer(word):
        value = args.get(m.group(1) or m.group(2))
        if value is None:
            return None
        size += m.start() - last + len(value)
        if size > _MAX_REFERENCE:
            return None
        pieces += (word[last:m.start()], value)
        last = m.end()
    if size + len(word) - last > _MAX_REFERENCE:
        return None
    pieces.append(word[last:])
    return "".join(pieces)
_TAG_RE = re.compile(r"^v?(\d{1,6})(?:\.(\d{1,6}))?(?:\.(\d{1,6}))?(?![\d])")


def _official(repository: str) -> str | None:
    name = repository.lower()
    for prefix in _OFFICIAL_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name if name in _RUNTIMES else None


def split_image(reference: str) -> tuple[str, str | None, str | None]:
    """(repository, tag, digest) of an image reference."""
    digest = None
    if "@" in reference:
        reference, digest = reference.split("@", 1)
    slash = reference.rfind("/")
    colon = reference.rfind(":")
    if colon > slash:
        return reference[:colon], reference[colon + 1:], digest
    return reference, None, digest


def tag_declared(subject: str, tag: str | None, shown: str, where: str, line_no: int | None) -> Declared:
    """What an image tag says about its runtime's release."""
    m = _TAG_RE.match(tag or "")
    if m is None:
        return Declared(subject, shown, where, line_no)
    parts = tuple(int(p) for p in m.groups() if p is not None)
    if len(parts) == 3:
        return Declared(subject, shown, where, line_no, version=parts)
    line = line_key(subject, parts)
    return Declared(subject, shown, where, line_no, line=line)


def _dockerfile_declared(path: Path, text: str) -> list[Declared]:
    steps = instructions(text)
    args: dict[str, str] = {}
    stages: set[str] = set()
    out: list[Declared] = []
    seen_from = False
    for step in steps:
        if step.keyword == "ARG" and not seen_from:
            for word in _words(step.args, path):
                name, eq, value = word.partition("=")
                if eq:
                    args[name] = value
        if step.keyword != "FROM":
            continue
        seen_from = True
        words = [w for w in _words(step.args, path) if not w.startswith("--")]
        if not words:
            continue
        reference = _expand(words[0], args)
        if len(words) >= 3 and words[1].upper() == "AS":
            stages.add(words[2].lower())
        if reference is None or "\0" in reference or reference.lower() in stages:
            continue  # an unresolved ARG, an expansion past any reference, or an earlier stage
        repository, tag, digest = split_image(reference)
        subject = _official(repository)
        if subject is None:
            continue
        if tag is None and digest is not None:
            continue  # pinned by digest alone: nothing to judge, nothing floating
        stage = f"base image of stage `{words[2]}`" if len(words) >= 3 and words[1].upper() == "AS" else "base image"
        out.append(tag_declared(subject, tag, f"FROM {words[0]}", stage, step.line))
    return out


_TOOL_NAMES = {"nodejs": "node", "node": "node", "php": "php", "python": "python"}
_FLOATING_WORDS = frozenset({"latest", "lts", "stable", "current", "node", "lts/*"})


def _version_file_declared(name: str, text: str) -> list[Declared]:
    out: list[Declared] = []
    if name in (".nvmrc", ".node-version", ".python-version"):
        subject = "python" if name == ".python-version" else "node"
        for number, raw in enumerate(text.splitlines(), 1):
            value = raw.split("#", 1)[0].strip()
            if not value:
                continue
            out.append(_value_declared(subject, value, name, number))
            if name != ".python-version":
                break  # nvm and fnm read the first line only
    elif name == ".tool-versions":
        for number, raw in enumerate(text.splitlines(), 1):
            words = raw.split("#", 1)[0].split()
            if len(words) < 2 or words[0] not in _TOOL_NAMES:
                continue
            subject = _TOOL_NAMES[words[0]]
            for value in dict.fromkeys(words[1:]):
                out.append(_value_declared(subject, value, f".tool-versions ({words[0]})", number))
    return [d for d in out if d is not None]


def _value_declared(subject: str, value: str, where: str, line_no: int) -> Declared:
    shown = value
    if value.lower() in _FLOATING_WORDS or value.lower().startswith("lts/"):
        return Declared(subject, shown, where, line_no)
    if subject == "python" and not value[:1].isdigit():
        return Declared(subject, shown, where, line_no, note="not CPython")  # pypy3.10, system
    version = parse_version(value)
    if version is None:
        return Declared(subject, shown, where, line_no, note="not judged")
    if len(version) >= 3:
        return Declared(subject, shown, where, line_no, version=version[:3])
    return Declared(subject, shown, where, line_no, line=line_key(subject, version))


def _engines_declared(path: Path, text: str) -> list[Declared]:
    try:
        data = loads_json(text, path)
    except ValueError:
        return []
    engines = data.get("engines") if isinstance(data, dict) else None
    spec = engines.get("node") if isinstance(engines, dict) else None
    if not isinstance(spec, str) or not spec.strip():
        return []
    spans = parse_range(spec, "npm")
    if not spans:
        return []
    lowest = min(lo for lo, _ in spans)
    return [Declared(
        "node", f'"engines": {{"node": "{spec}"}}', "engines.node",
        find_line_number(text, '"engines"'), version=tuple(lowest),
        note=f"the lowest release `{spec}` admits; engines says what the package supports, not what runs",
    )]




def _managed_runtime(value: str) -> tuple[str, str] | None:
    """(subject, line) for a managed runtime name: App Engine `nodejs22`, `php83`,
    `python312`; Lambda/Serverless `nodejs22.x`, `python3.12`."""
    low = value.strip().lower()
    m = re.fullmatch(r"nodejs(\d{1,2})(?:\.x)?", low)
    if m:
        return "node", m.group(1)
    m = re.fullmatch(r"php(\d)(\d{1,2})", low)
    if m:
        return "php", f"{m.group(1)}.{m.group(2)}"
    m = re.fullmatch(r"python(\d)\.?(\d{1,2})", low)
    if m:
        return "python", f"{m.group(1)}.{m.group(2)}"
    return None


def _runtime_key_declared(path: Path, text: str) -> list[Declared]:
    try:
        data = load_yaml(text, path)
    except yaml.YAMLError:
        return []
    values: list[str] = []
    if isinstance(data, dict):
        if isinstance(data.get("runtime"), str):
            values.append(data["runtime"])
        provider = data.get("provider")
        if isinstance(provider, dict) and isinstance(provider.get("runtime"), str):
            values.append(provider["runtime"])
        functions = data.get("functions")
        if isinstance(functions, dict):
            values.extend(f["runtime"] for f in functions.values()
                          if isinstance(f, dict) and isinstance(f.get("runtime"), str))
    managed = [(value, found) for value in dict.fromkeys(values) if (found := _managed_runtime(value))]
    # Every value's line in one pass: a search of the file per value cost 6.4 s for 30,000.
    lines = find_line_numbers(text, (value for value, _ in managed))
    return [Declared(subject, f"runtime: {value}", f"{path.name} runtime", lines.get(value), line=line, managed=True)
            for value, (subject, line) in managed]


# A runtime under a versioned install path, as an MCP config's `command` names it.
_INSTALL_PATHS = tuple(
    (re.compile(pattern), subject)
    for pattern, subject in (
        (r"\.nvm/versions/node/v?(\d+\.\d+\.\d+)/", "node"),
        (r"\.asdf/installs/nodejs/(\d+\.\d+\.\d+)/", "node"),
        (r"\.asdf/installs/php/(\d+\.\d+\.\d+)/", "php"),
        (r"\.asdf/installs/python/(\d+\.\d+\.\d+)/", "python"),
        (r"mise/installs/node(?:js)?/(\d+\.\d+\.\d+)/", "node"),
        (r"mise/installs/php/(\d+\.\d+\.\d+)/", "php"),
        (r"mise/installs/python/(\d+\.\d+\.\d+)/", "python"),
        (r"\.volta/tools/image/node/(\d+\.\d+\.\d+)/", "node"),
        (r"fnm/node-versions/v?(\d+\.\d+\.\d+)/", "node"),
        (r"/n/versions/node/(\d+\.\d+\.\d+)/", "node"),
        (r"\.pyenv/versions/(\d+\.\d+\.\d+)/", "python"),
        (r"Cellar/node(?:@\d+)?/(\d+\.\d+\.\d+)(?:_\d+)?/", "node"),
        (r"Cellar/php(?:@\d+\.\d+)?/(\d+\.\d+\.\d+)(?:_\d+)?/", "php"),
        (r"Cellar/python(?:@\d+\.\d+)?/(\d+\.\d+\.\d+)(?:_\d+)?/", "python"),
    )
)


def _mcp_declared(path: Path, text: str) -> list[Declared]:
    try:
        data = loads_jsonc(text, path)
    except ValueError:
        return []
    hits: list[tuple[str, str, str, re.Match[str]]] = []
    for name, server in iter_mcp_servers(data):
        args = server.get("args")
        words = [server.get("command"), *(args if isinstance(args, list) else ())]
        hit = next(
            ((word, subject, m) for word in words if isinstance(word, str)
             for pattern, subject in _INSTALL_PATHS
             if (m := pattern.search(word.replace("\\", "/")))),
            None,
        )
        if hit is not None:  # one runtime per server: the first versioned path it names
            hits.append((name, *hit))
    lines = find_line_numbers(text, (word for _, word, _, _ in hits))  # one pass, not one search a server
    return [Declared(subject, word, f"MCP server `{name}`", lines.get(word), version=parse_version(m.group(1)))
            for name, word, subject, m in hits]


# ---- libraries that bundle a codec ------------------------------------------------------

_LOCKFILES = {
    "uv.lock": ("pypi", "uv.lock"), "poetry.lock": ("pypi", "poetry.lock"), "pipfile.lock": ("pypi", "pipfile.lock"),
    "package-lock.json": ("npm", "package-lock.json"), "npm-shrinkwrap.json": ("npm", "package-lock.json"),
    "pnpm-lock.yaml": ("npm", "pnpm-lock.yaml"), "yarn.lock": ("npm", "yarn.lock"),
}
_PIN_MANIFESTS = ("pyproject.toml", "pipfile")
_REGISTRY = {"py": "pypi", "js": "npm"}


def _library_subject(registry: str, name: str) -> str:
    return _subject_key(f"{registry}:{name}")


def _library_findings(path: Path, rel: str, advisories: Advisories) -> list[Finding]:
    wanted: dict[str, set[str]] = {}
    for subject in advisories.by_subject:
        registry, _, name = subject.partition(":")
        if name:
            wanted.setdefault(registry, set()).add(name)
    low = path.name.lower()
    hits: list[tuple[str, str, Version, int | None, str]] = []  # subject, name, version, line, how
    if low in _LOCKFILES:
        registry, reader = _LOCKFILES[low]
        if registry not in wanted:
            return []
        text = read_text(path, MAX_LOCKFILE_BYTES)
        if text is None:
            return []
        for name, rows in sorted(_lockfile_raw_entries(text, reader, wanted[registry]).items()):
            seen_raw: set[str] = set()
            for line, raw in rows:
                if raw in seen_raw:  # one finding per release the lockfile resolves, at its first entry
                    continue
                seen_raw.add(raw)
                version = parse_version(raw)
                if version is not None:
                    hits.append((_library_subject(registry, name), name, version, line, f"{path.name} resolves {name} {raw}"))
    else:
        manifest = read_manifest(path)
        if manifest is None:
            return []
        for declaration in manifest.declarations:
            pinned_registry = _REGISTRY.get(declaration.ecosystem or "")
            if pinned_registry is None:
                continue
            pinned_subject = _library_subject(pinned_registry, declaration.name)
            pinned = exact_pin(declaration) if pinned_subject in advisories.by_subject else None
            pinned_version = parse_version(pinned) if pinned else None
            if pinned_version is not None:
                hits.append((pinned_subject, declaration.name, pinned_version,
                             manifest.line_of(declaration), f"`{declaration.text}` in {path.name}"))
    findings: list[Finding] = []
    for subject, name, version, at, how in hits:
        verdicts = [v for a in advisories.by_subject.get(subject, ()) if (v := judge(a, subject, version))]
        if verdicts:
            findings.append(_finding(_ADV_003, rel, f"{how}: {name} {_dotted(version)}", verdicts, at, subject,
                                     version, advisories))
    return findings


# ---- findings ------------------------------------------------------------------------------


def _finding(rule: str, rel: str, lead: str, verdicts: list[Verdict], line: int | None, subject: str,
             version: Version | None, advisories: Advisories, note: str = "") -> Finding:
    parts = []
    for verdict in verdicts:
        if verdict.fixed is not None:
            parts.append(f"below {verdict.fixed}, the fixed release on its line, for {verdict.advisory.label}")
        else:
            key = line_key(subject, version) if version else None
            eol = advisories.eol_note(subject, key) if key else ""
            parts.append(f"on a line with no fixed release for {verdict.advisory.label}{eol}")
    evidence = f"{lead} is " + "; and ".join(parts) + "."
    if note:
        evidence += f" ({note}.)"
    finding = make_finding(rule, rel, evidence, line)
    severity = max((v.advisory.severity for v in verdicts), key=lambda s: s.numeric())
    if severity is not finding.severity:
        # The advisory decides how severe its flaw is; a KEV entry is CRITICAL.
        finding = dataclasses.replace(finding, severity=severity)
    return finding


def _runtime_findings(rel: str, declared: Declared, advisories: Advisories) -> list[Finding]:
    found = advisories.by_subject.get(declared.subject, ())
    if not found:
        return []
    name = _DISPLAY.get(declared.subject, declared.subject)
    if declared.version is not None:
        verdicts = [v for a in found if (v := judge(a, declared.subject, declared.version))]
        if not verdicts:
            return []
        lead = f"`{declared.shown}` ({declared.where}): {name} {_dotted(declared.version)}"
        return [_finding(_ADV_001, rel, lead, verdicts, declared.line_no, declared.subject, declared.version,
                         advisories, declared.note)]
    if declared.note in ("not CPython", "not judged"):
        return []
    if declared.line is not None:
        results = [judge_line(a, declared.subject, declared.line) for a in found]
        verdicts = [r for r in results if isinstance(r, Verdict)]
        if verdicts:
            lead = f"`{declared.shown}` ({declared.where}): {name} {declared.line}.x, any patch release,"
            line_version = parse_version(declared.line)
            return [_finding(_ADV_001, rel, lead, verdicts, declared.line_no, declared.subject, line_version,
                             advisories)]
        floating = [a for a, r in zip(found, results) if r == "floating"]
        if not floating:
            return []
        fixes = ", ".join(f"{a.fixed_by_line[declared.line]} for {a.id}" for a in floating)
        if declared.managed:
            advice = (f"the platform picks the patch release of {name} {declared.line}; confirm it runs "
                      f"{fixes} or later")
        else:
            advice = (f"it floats over the {declared.line} line, so AAK cannot tell whether it has {fixes}; "
                      "pin a full version or a digest")
        return [make_finding(_ADV_002, rel, f"`{declared.shown}` ({declared.where}): {advice}.",
                             declared.line_no)]
    fixes = "; ".join(
        f"{a.id}: " + ", ".join(f"{fixed} on {line}" for line, fixed in sorted(a.fixed_by_line.items()))
        for a in found
    )
    return [make_finding(
        _ADV_002, rel,
        f"`{declared.shown}` ({declared.where}) names no {name} release, so AAK cannot tell whether it has "
        f"the fixes ({fixes}); pin a full version or a digest.",
        declared.line_no,
    )]


# ---- the scan -------------------------------------------------------------------------------

_VERSION_FILES = frozenset({".nvmrc", ".node-version", ".python-version", ".tool-versions"})
_RUNTIME_YAML = frozenset({"app.yaml", "app.yml", "serverless.yml", "serverless.yaml"})


def _is_mcp_config(name: str) -> bool:
    low = name.lower()
    return low in (".mcp.json", "mcp.json", "claude_desktop_config.json") or low.endswith(".mcp.json")


def _is_pin_manifest(name: str) -> bool:
    low = name.lower()
    return low in _PIN_MANIFESTS or (low.startswith("requirements") and low.endswith(".txt"))


def _files(project_root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            low = name.lower()
            if (_dockerfile_kind(name) or name in _VERSION_FILES or low in _RUNTIME_YAML or low == "package.json"
                    or _is_mcp_config(name) or low in _LOCKFILES or _is_pin_manifest(name)):
                yield Path(dirpath) / name


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report declared runtimes and bundled codecs below their fixed release.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    advisories = load_advisories()
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _files(project_root):
        rel = path.relative_to(project_root).as_posix()
        low = path.name.lower()
        if low in _LOCKFILES or _is_pin_manifest(path.name):
            scanned.add(rel)
            findings.extend(_library_findings(path, rel, advisories))
            continue
        try:
            text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
        except OSError:
            continue
        scanned.add(rel)
        declared: list[Declared] = []
        if _dockerfile_kind(path.name):
            declared = _dockerfile_declared(path, text)
        elif path.name in _VERSION_FILES:
            declared = _version_file_declared(path.name, text)
        elif low in _RUNTIME_YAML:
            declared = _runtime_key_declared(path, text)
        elif low == "package.json":
            declared = _engines_declared(path, text)
            findings.extend(_library_findings(path, rel, advisories))
        elif _is_mcp_config(path.name):
            declared = _mcp_declared(path, text)
        for one in declared:
            findings.extend(_runtime_findings(rel, one, advisories))
    return findings, scanned


__all__ = ["scan", "load_advisories", "advisories_summary", "judge", "judge_line", "parse_version"]

