"""Startup hooks: code Python, pytest or npm runs unasked.

litellm 1.107.0 (21 Oct 2026, OSV MAL-2026-2144) needed no import of litellm to
run. Every wheel carried `cook.pth`, `cook.py` and `sitecustomize.py`, which pip
installs at the top of site-packages, and Python runs both kinds of file at
every interpreter start, `pip` included. The pin rules judged the version and
passed it, because 1.107.0 was above every pinned floor. This module reports the
route, whatever package takes it, and the test runner's own route:

* AAK-STARTUP-HOOK-PTH-001: a `.pth` file at the top of a site-packages or
  dist-packages directory with a line Python runs as code, or a PEP 829
  `.start` file naming an entry point. `site.py` execs a `.pth` line that
  starts with `import ` or `import<TAB>`; CPython 3.9 to 3.14 test the raw line
  and 3.15 strips it first, so a line counts after optional whitespace. The text
  is split with `str.splitlines()`, as 3.12 and later split it (3.9 to 3.11 split
  at line ends only, a subset), and a leading BOM is dropped, as 3.12 and later
  drop it. Python 3.15 also calls each `pkg.mod:callable` line of a `.start`
  file. A line that only names a directory is not code and is not reported.
* AAK-STARTUP-HOOK-SITECUSTOMIZE-001: a `sitecustomize` or `usercustomize`
  module in site-packages, dist-packages, or a directory a Dockerfile puts on
  `PYTHONPATH`: a `.py`, a sourceless `.pyc`, an extension module, a package
  with an `__init__`, or a compiled copy in `__pycache__`, which Python loads
  only beside its source and so shows one was installed there.
* AAK-STARTUP-HOOK-DOCKERFILE-001: a Dockerfile or Containerfile that copies a
  `.pth`, `sitecustomize.py` or `usercustomize.py` into the image, a RUN that
  writes one (a redirect, `tee`, `cp`, `mv`, `install` or `ln` naming one), or
  `ENV PYTHONSTARTUP` in an image that runs an MCP server.
* AAK-STARTUP-HOOK-NPM-INSTALL-001: a package-lock.json (or
  npm-shrinkwrap.json) entry marked `hasInstallScript`, in a project that
  declares an MCP SDK or an `.mcp.json` server. npm runs those scripts on
  install. Only the lockfile is read: node_modules is never walked and npm is
  never run.
* AAK-STARTUP-HOOK-CONFTEST-001: a `conftest.py` that hands the environment,
  read whole or by a secret's name, to a network call (HIGH) or a file write
  (MEDIUM). pytest imports every conftest.py under its rootdir and the test
  paths before the first test, with the shell's environment, so a test run
  started by a person, a hook or a coding agent runs it. The file is parsed,
  never imported or run.

Where it looks
--------------
Site-packages directories are found by `_site_packages.site_package_dirs`,
which, unlike every other scanner, looks inside `.venv/`, `venv/`, `env/`,
`.tox/` and `vendor/`, so a project's own environment, an MCP server's
environment under the project, and a vendored site-packages are read. An image
is read as an unpacked root filesystem given as the scan path
(`docker create` then `docker export | tar -x`), with no registry pull and no
network: its `usr/local/lib/python3.X/site-packages` and
`usr/lib/python3/dist-packages` are directories like any other.

A file named in `data/startup_hook_allowlist.json` with the same normalised
content (setuptools' `distutils-precedence.pth`, the `_virtualenv.pth` that
virtualenv and uv write, coverage's `a1_coverage.pth`) is not reported. The
name alone never matches, because a malicious `.pth` can call itself
`distutils-precedence.pth`. Every startup file is read through
`read_bytes_capped` with `CONFIG_MAX_BYTES`; a FIFO or a device in its place is
skipped, as `_helpers` skips one, and a file over the cap is refused, so the
scan reports itself incomplete rather than passing a megabyte of startup code
unread.

Dockerfiles, npm lockfiles and `conftest.py` files are found by one walk of the
scan root that skips `SKIP_DIRS` (`node_modules`, `.venv` and the rest) and a
Claude Code worktree under `.claude/worktrees/`. A `conftest.py` is read with
the same cap as a startup file, and refused over it.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import os
import re
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Iterator, NamedTuple

from agent_audit_kit.models import Finding, Severity

from ._helpers import (
    CONFIG_MAX_BYTES,
    MCP_TS_SDK_NAMES,
    FileNotRead,
    declares_mcp_sdk,
    iter_mcp_servers,
    kept_dirs,
    loads_json,
    loads_jsonc,
    make_finding,
    parse_python,
    read_bytes_capped,
    read_text_capped,
    refuse,
    refusing_overflow,
)
from ._launchers import shell_words
from ._manifest_deps import MAX_LOCKFILE_BYTES, _json_positions
from ._site_packages import site_entries, site_package_dirs

_PTH = "AAK-STARTUP-HOOK-PTH-001"
_CUSTOMIZE = "AAK-STARTUP-HOOK-SITECUSTOMIZE-001"
_DOCKERFILE = "AAK-STARTUP-HOOK-DOCKERFILE-001"
_NPM = "AAK-STARTUP-HOOK-NPM-INSTALL-001"
_CONFTEST = "AAK-STARTUP-HOOK-CONFTEST-001"

_ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "startup_hook_allowlist.json"
_IMPORT_PREFIXES = ("import ", "import\t")
_CUSTOMIZE_STEMS = ("sitecustomize", "usercustomize")
_SNIPPET_CHARS = 80
_LOCKFILE_NAMES = ("package-lock.json", "npm-shrinkwrap.json")


# ---- the allowlist -------------------------------------------------------------


def normalised_text(raw: bytes) -> str:
    """A startup file's content as the allowlist compares it.

    UTF-8 with a leading BOM dropped and undecodable bytes replaced, split as
    `str.splitlines()` splits, each line stripped, blank and `#` lines dropped.
    """
    text = raw.decode("utf-8-sig", errors="replace")
    lines = (line.strip() for line in text.splitlines())
    return "\n".join(line for line in lines if line and not line.startswith("#"))


def normalised_sha256(raw: bytes) -> str:
    """The sha256 the allowlist keys a file's content by."""
    return hashlib.sha256(normalised_text(raw).encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _allowlist() -> frozenset[tuple[str, str]]:
    data = loads_json(_ALLOWLIST_PATH.read_text(encoding="utf-8"), _ALLOWLIST_PATH)
    return frozenset(
        (str(entry["name"]), str(entry["sha256"]).lower()) for entry in data.get("entries", ())
    )


def _allowlisted(name: str, raw: bytes) -> bool:
    return (name, normalised_sha256(raw)) in _allowlist()


# ---- reading -------------------------------------------------------------------


def _link_target(path: Path, root: Path) -> Path | None:
    """Where a symlinked startup file leads, read as the image reads it, or None.

    An absolute target is taken under the scan root, as in an unpacked image root
    filesystem, where Debian links `sitecustomize.py` to `/etc/python3.X/`;
    followed on the host, the same link named the host's own file. A link that
    still leads outside the root is not read.
    """
    try:
        link = os.readlink(path)
    except OSError:
        return None
    target = root.joinpath(link.lstrip("/")) if link.startswith("/") else path.parent / link
    try:
        resolved = target.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return None
    return resolved


def _read(path: Path, root: Path) -> bytes | None:
    """A startup file's bytes, or None when it is not a regular file inside the
    scan root (`root`, resolved).

    A file over CONFIG_MAX_BYTES is refused: Python reads every line of one, so
    skipping it in silence would pass whatever it holds.
    """
    target = _link_target(path, root) if path.is_symlink() else path
    if target is None:
        return None
    try:
        return read_bytes_capped(target, CONFIG_MAX_BYTES)
    except FileNotRead as exc:
        if exc.errno == errno.EFBIG:
            refuse(path, f"startup file larger than {CONFIG_MAX_BYTES:,} bytes, not read")
        return None
    except OSError:
        return None


def _snippet(text: str) -> str:
    shown = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text[:_SNIPPET_CHARS])
    return shown + ("…" if len(text) > _SNIPPET_CHARS else "")


def _rel(path: Path, project_root: Path) -> str:
    return path.relative_to(project_root).as_posix()


def startup_lines(raw: bytes, suffix: str) -> list[tuple[int, str]]:
    """(1-based line, stripped text) for each line Python runs at startup.

    For a `.pth`, a line that starts with `import ` or `import<TAB>` once
    leading whitespace is stripped (3.15 strips it; 3.9 to 3.14 test the raw
    line, a subset). For a `.start`, every line that is not blank or a comment
    is an entry point. Lines are numbered as `splitlines()` numbers them.
    """
    text = raw.decode("utf-8-sig", errors="replace")
    out: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if suffix == ".start" or stripped.startswith(_IMPORT_PREFIXES):
            out.append((number, stripped))
    return out


def _first_code_line(raw: bytes) -> int:
    """The first line of a source file that is not blank or a comment, else 1."""
    text = raw.decode("utf-8-sig", errors="replace")
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return number
    return 1


# ---- site-packages ---------------------------------------------------------------


def _startup_file_finding(
    path: Path, raw: bytes, project_root: Path, site_rel: str
) -> Finding | None:
    suffix = path.suffix.lower()
    lines = startup_lines(raw, suffix)
    if not lines or _allowlisted(path.name, raw):
        return None
    number, text = lines[0]
    more = f" and {len(lines) - 1} more line(s) like it" if len(lines) > 1 else ""
    if suffix == ".start":
        how = (
            f"`{path.name}` in `{site_rel}` names an entry point Python 3.15 and later "
            f"call at every interpreter start (PEP 829): line {number}, `{_snippet(text)}`{more}."
        )
    else:
        how = (
            f"`{path.name}` in `{site_rel}` has a line `site.py` runs as code at every "
            f"interpreter start: line {number}, `{_snippet(text)}`{more}."
        )
    if path.name.startswith("."):
        how += (
            " Its name starts with a dot, which the Python releases AAK checked "
            "(3.9.25 to 3.15.2) skip; an older patch release may still run it."
        )
    return make_finding(_PTH, _rel(path, project_root), how, number)


def _customize_modules(directory: Path) -> Iterator[tuple[Path, str]]:
    """(file, form) for each sitecustomize or usercustomize Python can import
    from `directory`, and each compiled copy of one in its `__pycache__`."""
    for entry in site_entries(directory):
        name = entry.name
        for stem in _CUSTOMIZE_STEMS:
            if name in (f"{stem}.py", f"{stem}.pyc"):
                yield Path(entry.path), "sourceless module" if name.endswith("c") else "module"
            elif name.startswith(f"{stem}.") and name.endswith((".so", ".pyd")):
                yield Path(entry.path), "extension module"
            elif name == stem and entry.is_dir(follow_symlinks=False):
                for init in ("__init__.py", "__init__.pyc"):
                    candidate = Path(entry.path) / init
                    if candidate.is_file():
                        yield candidate, "package"
                        break
        if name == "__pycache__" and entry.is_dir(follow_symlinks=False):
            for cached in site_entries(Path(entry.path)):
                if cached.name.endswith(".pyc") and cached.name.split(".", 1)[0] in _CUSTOMIZE_STEMS:
                    yield Path(cached.path), "compiled copy"


@dataclass
class _ScanState:
    """What one scan shares across files: the startup files already reported, the
    directories already listed, and each directory's MCP-SDK verdict."""

    project_root: Path
    root: Path = field(init=False)  # project_root, resolved
    seen: set[Path] = field(default_factory=set)
    scanned: set[str] = field(default_factory=set)
    listed: set[Path] = field(default_factory=set)
    sdk: dict[Path, tuple[bool, list[str]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.root = self.project_root.resolve()

    def inside(self, path: Path) -> Path | None:
        """`path` as a directory under the scan root, symlinks resolved, or None when
        it is not a directory or resolves outside the root."""
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(self.root)
        except (OSError, ValueError, RuntimeError):
            return None
        return self.project_root.joinpath(relative) if resolved.is_dir() else None

    def customize_findings(self, directory: Path, where: str) -> list[Finding]:
        """The customize modules of a directory `inside` returned, listed once a scan."""
        if directory in self.listed:
            return []
        self.listed.add(directory)
        return _customize_findings(directory, self, where)


def _customize_findings(directory: Path, state: _ScanState, where: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, form in _customize_modules(directory):
        if path in state.seen:
            continue
        state.seen.add(path)
        raw = _read(path, state.root)
        if raw is None:
            continue
        rel = _rel(path, state.project_root)
        state.scanned.add(rel)
        if _allowlisted(path.name, raw):
            continue
        stem = path.name.split(".", 1)[0] if form != "package" else path.parent.name
        if form == "compiled copy":
            what = (
                f"`{rel}` is a compiled copy of `{stem}` {where}. Python loads a "
                "`__pycache__` copy only beside its source, so this one shows the module "
                "was installed here; Python imports that module at every interpreter start."
            )
            line = 1
        else:
            what = (
                f"`{rel}` is a `{stem}` {form} {where}, and Python imports `{stem}` at every "
                "interpreter start."
            )
            line = 1 if form in ("sourceless module", "extension module") else _first_code_line(raw)
        findings.append(make_finding(_CUSTOMIZE, rel, what, line))
    return findings


def _site_dir_findings(site_dir: Path, state: _ScanState) -> list[Finding]:
    project_root = state.project_root
    findings: list[Finding] = []
    site_rel = _rel(site_dir, project_root) if site_dir != project_root else "."
    for entry in site_entries(site_dir):
        if not entry.name.lower().endswith((".pth", ".start")):
            continue
        path = Path(entry.path)
        raw = _read(path, state.root)
        if raw is None:
            continue
        state.scanned.add(_rel(path, project_root))
        finding = _startup_file_finding(path, raw, project_root, site_rel)
        if finding is not None:
            findings.append(finding)
    listed = state.inside(site_dir)
    if listed is not None:
        findings.extend(state.customize_findings(listed, f"in `{site_rel}`"))
    return findings


# ---- Dockerfiles -----------------------------------------------------------------


@dataclass(frozen=True)
class _Instruction:
    line: int     # 1-based line the instruction starts on
    keyword: str  # upper case
    args: str     # the rest, continuation lines joined


_HEREDOC_RE = re.compile(r"<<-?[ \t]*([\"']?)([A-Za-z_][A-Za-z0-9_]{0,63})\1")


def _dockerfile_kind(name: str) -> bool:
    low = name.lower()
    return (
        low in ("dockerfile", "containerfile")
        or low.startswith(("dockerfile.", "containerfile."))
        or low.endswith(".dockerfile")
    )


def instructions(text: str) -> list[_Instruction]:
    """The instructions of a Dockerfile, with continuations joined.

    A line ending in a backslash continues on the next; comment and blank lines
    inside a continuation are dropped, as the builder drops them. A heredoc's
    body (`RUN <<EOF` ... `EOF`) is skipped, so its lines are never read as
    instructions. A parser directive changing the escape character is not read.
    """
    lines = text.splitlines()
    out: list[_Instruction] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i
        parts = [stripped]
        while parts[-1].endswith("\\") and i + 1 < len(lines):
            parts[-1] = parts[-1][:-1]
            i += 1
            following = lines[i].strip()
            while (not following or following.startswith("#")) and i + 1 < len(lines):
                i += 1
                following = lines[i].strip()
            if following and not following.startswith("#"):
                parts.append(following)
        joined = " ".join(parts)
        keyword, _, args = joined.partition(" ")
        out.append(_Instruction(start + 1, keyword.upper(), args.strip()))
        i += 1
        for marker in (m.group(2) for m in _HEREDOC_RE.finditer(args)):
            while i < len(lines) and lines[i].strip() != marker:
                i += 1
            i += 1
    return out


def split_words(text: str) -> list[str]:
    """`shlex.split(text)`, falling back to `text.split()` where shlex raises.

    shlex grows each word one character at a time on an attribute, so one RUN
    word of 900,000 characters took 5.4 s; `_launchers.shell_words` reads the
    same grammar in runs.
    """
    return shell_words(text, punctuation="", whitespace=" \t\r\n", commenters="")


def _words(args: str, path: Path) -> list[str]:
    """An instruction's arguments as the shell form splits them, or its JSON array."""
    if args.startswith("["):
        try:
            value = loads_json(args, path)
        except ValueError:
            value = None
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return list(value)
    return split_words(args)


def _env_pairs(args: str, path: Path) -> list[tuple[str, str]]:
    words = _words(args, path)
    if not words:
        return []
    if "=" not in words[0]:
        return [(words[0], " ".join(words[1:]))]  # the legacy `ENV KEY value` form
    return [(k, v) for k, _, v in (w.partition("=") for w in words if "=" in w)]


def _is_hook_name(path_text: str) -> bool:
    """Does a path name a `.pth`, a `sitecustomize`/`usercustomize` module or,
    in a site-packages directory, a `.start` file?"""
    name = PurePosixPath(path_text.rstrip("/")).name
    low = path_text.lower()
    if name.lower().endswith(".pth"):
        return True
    if name in ("sitecustomize.py", "usercustomize.py", "sitecustomize.pyc", "usercustomize.pyc"):
        return True
    return name.lower().endswith(".start") and ("site-packages" in low or "dist-packages" in low)


_REDIRECT_RE = re.compile(r"(?<![<>])>{1,2}\|?[ \t]*[\"']?([^\s\"';|&<>()]{1,4096})")
_COMMAND_SPLIT_RE = re.compile(r"\|\||&&|[;|\n]")
_WRITERS = frozenset({"cp", "mv", "install", "ln", "tee"})


def _run_writes_hook(args: str) -> str | None:
    """The startup file a RUN command writes, or None."""
    for m in _REDIRECT_RE.finditer(args):
        if _is_hook_name(m.group(1)):
            return m.group(1)
    for command in _COMMAND_SPLIT_RE.split(args):
        argv = split_words(command)
        # Past leading VAR=value assignments and `sudo`, found by index: slicing the
        # list once per assignment cost 70 s for 245,000 of them.
        k = 0
        while k < len(argv) and "=" in argv[k] and not argv[k].startswith(("-", "/")):
            k += 1
        if k < len(argv) and argv[k] == "sudo":
            k += 1
        argv = argv[k:]
        if not argv or PurePosixPath(argv[0]).name not in _WRITERS:
            continue
        operands = [a for a in argv[1:] if not a.startswith("-")]
        if PurePosixPath(argv[0]).name == "tee":
            hit = next((a for a in operands if _is_hook_name(a)), None)
        else:
            hit = operands[-1] if operands and _is_hook_name(operands[-1]) else None
            if hit is None and len(operands) >= 2:
                hit = next((a for a in operands[:-1] if _is_hook_name(a)), None)
        if hit is not None:
            return hit
    return None


_MCP_WORD_RE = re.compile(r"(?<![A-Za-z0-9])mcp(?![A-Za-z0-9])|fastmcp|modelcontextprotocol", re.I)


def _declares_sdk(directory: Path, cache: dict[Path, tuple[bool, list[str]]]) -> tuple[bool, list[str]]:
    """`declares_mcp_sdk(directory)`, once per directory per scan. It lists the
    directory and parses the manifests there, so 10,000 Dockerfiles in one
    directory, each asking again, took 43 s."""
    if directory not in cache:
        cache[directory] = declares_mcp_sdk(directory)
    return cache[directory]


def _runs_mcp_server(
    steps: list[_Instruction], context: Path, sdk: dict[Path, tuple[bool, list[str]]]
) -> str | None:
    """Why the image is taken to run an MCP server, or None.

    An `mcp` word (`mcp-server-git`, `python -m mcp`, `@scope/mcp`), `fastmcp`
    or `modelcontextprotocol` in a CMD, ENTRYPOINT, RUN or LABEL, an MCP SDK
    declared beside the Dockerfile, or an `.mcp.json` there.
    """
    for step in steps:
        if step.keyword in ("CMD", "ENTRYPOINT", "RUN", "LABEL") and _MCP_WORD_RE.search(step.args):
            return f"line {step.line}: `{step.keyword} {_snippet(step.args)}`"
    declared, manifests = _declares_sdk(context, sdk)
    if declared:
        return f"`{manifests[0]}` beside it declares an MCP SDK"
    # One file beside a Dockerfile at any depth, a hint the image is an MCP project, not the root list.
    if (context / ".mcp.json").is_file():
        return "an `.mcp.json` sits beside it"
    return None


def _dest(workdir: PurePosixPath, dest: str) -> PurePosixPath:
    path = PurePosixPath(dest)
    return path if path.is_absolute() else workdir / path


def _dockerfile_findings(
    path: Path, text: str, project_root: Path, state: _ScanState
) -> list[Finding]:
    """AAK-STARTUP-HOOK-DOCKERFILE-001, and SITECUSTOMIZE-001 for a directory the
    Dockerfile puts on PYTHONPATH (the root read as an unpacked image, or a
    directory of the build context copied there).

    Each part is read once: whether the image runs an MCP server is decided once,
    not per `ENV PYTHONSTARTUP` (49,000 of them took 66 s), each PYTHONPATH
    directory is matched once against the copies indexed by destination (10,000
    entries against 10,000 copies took 11 s), and a directory's customize modules
    are listed once per scan. A directory is read only inside the scanned root,
    resolved: `ENV PYTHONPATH=/../../usr/lib/python3.12`, or a path through a
    symlinked directory, named the host's own files.
    """
    rel = _rel(path, project_root)
    context = path.parent
    steps = instructions(text)
    findings: list[Finding] = []
    pythonpath: dict[PurePosixPath, int] = {}  # directory -> the first line naming it
    copies: dict[PurePosixPath, list[tuple[list[str], int]]] = {}
    workdir = PurePosixPath("/")
    mcp_why: list[str | None] = []  # decided at the first `ENV PYTHONSTARTUP`, then kept
    for step in steps:
        if step.keyword == "FROM":
            workdir = PurePosixPath("/")
        elif step.keyword == "WORKDIR" and step.args and "$" not in step.args:
            words = _words(step.args, path)
            workdir = _dest(workdir, words[0] if words else step.args)
        elif step.keyword in ("COPY", "ADD"):
            every = _words(step.args, path)
            words = [w for w in every if not w.startswith("--")]
            from_stage = any(w.startswith("--from") for w in every)
            if len(words) < 2:
                continue
            sources, dest = words[:-1], words[-1]
            hit = next((s for s in sources if _is_hook_name(s)), None)
            if hit is None and _is_hook_name(dest):
                hit = dest
            if hit is not None:
                findings.append(make_finding(
                    _DOCKERFILE, rel,
                    f"line {step.line}: `{step.keyword} {_snippet(step.args)}` puts `{hit}` "
                    "into the image, a file Python runs at every interpreter start.",
                    step.line,
                ))
            elif not from_stage and "$" not in dest:
                copies.setdefault(_dest(workdir, dest), []).append((sources, step.line))
        elif step.keyword == "RUN":
            written = _run_writes_hook(step.args)
            if written is not None:
                findings.append(make_finding(
                    _DOCKERFILE, rel,
                    f"line {step.line}: `RUN {_snippet(step.args)}` writes `{written}`, a file "
                    "Python runs at every interpreter start.",
                    step.line,
                ))
        elif step.keyword == "ENV":
            for key, value in _env_pairs(step.args, path):
                if key == "PYTHONPATH":
                    for part in value.split(":"):
                        if part.startswith("/") and "$" not in part:
                            pythonpath.setdefault(PurePosixPath(part), step.line)
                elif key == "PYTHONSTARTUP" and value:
                    if not mcp_why:
                        mcp_why.append(_runs_mcp_server(steps, context, state.sdk))
                    why = mcp_why[0]
                    if why is not None:
                        findings.append(make_finding(
                            _DOCKERFILE, rel,
                            f"line {step.line}: `ENV PYTHONSTARTUP={_snippet(value)}` in an image "
                            f"that runs an MCP server ({why}): every interactive Python in the "
                            "image (`python` with no script, or `python -i`) runs that file first.",
                            step.line,
                        ))
    for directory, line in pythonpath.items():
        where = f"on the PYTHONPATH `{rel}` sets (line {line})"
        in_root = state.inside(project_root.joinpath(*directory.parts[1:]))
        if in_root is not None:
            findings.extend(state.customize_findings(in_root, where))
        for sources, copy_line in copies.get(directory, ()):
            for source in sources:
                if any(c in source for c in "*?[") or source.startswith(("http://", "https://")):
                    continue
                local = state.inside(context / source)
                if local is not None:
                    findings.extend(state.customize_findings(
                        local,
                        f"in a directory `{rel}` copies onto its PYTHONPATH (lines {copy_line} and {line})",
                    ))
    return findings


# ---- npm lockfiles --------------------------------------------------------------


def _mcp_project(lock_dir: Path, packages: dict, sdk: dict[Path, tuple[bool, list[str]]]) -> str | None:
    for name in MCP_TS_SDK_NAMES:
        if f"node_modules/{name}" in packages:
            return f"the lockfile resolves `{name}`"
    declared, manifests = _declares_sdk(lock_dir, sdk)
    if declared:
        return f"`{manifests[0]}` declares an MCP SDK"
    # A hint beside a lockfile at any depth, as for a Dockerfile above, not the root list.
    config = lock_dir / ".mcp.json"
    if config.is_file():
        try:
            data = loads_jsonc(read_text_capped(config, CONFIG_MAX_BYTES, errors="replace"), config)
        except (OSError, ValueError):
            return None
        if any(True for _ in iter_mcp_servers(data)):
            return "`.mcp.json` beside it declares an MCP server"
    return None


_IGNORE_SCRIPTS_RE = re.compile(r"^[ \t]*ignore-scripts[ \t]*=[ \t]*true[ \t]*$", re.I | re.M)


def _ignores_scripts(lock_dir: Path) -> bool:
    """Does the `.npmrc` beside the lockfile set `ignore-scripts=true`?"""
    try:
        text = read_text_capped(lock_dir / ".npmrc", CONFIG_MAX_BYTES, errors="replace")
    except OSError:
        return False
    return _IGNORE_SCRIPTS_RE.search(text) is not None


def _lockfile_findings(path: Path, state: _ScanState) -> list[Finding]:
    try:
        text = read_text_capped(path, MAX_LOCKFILE_BYTES, errors="replace")
    except OSError:
        return []
    rel = _rel(path, state.project_root)
    state.scanned.add(rel)
    try:
        data = loads_json(text, path)
    except ValueError:
        return []
    if not isinstance(data, dict) or data.get("lockfileVersion") not in (2, 3):
        return []
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []
    marked = [
        (key, meta) for key, meta in packages.items()
        if key and isinstance(meta, dict) and meta.get("hasInstallScript") is True
    ]
    if not marked or _ignores_scripts(path.parent):
        return []
    why = _mcp_project(path.parent, packages, state.sdk)
    if why is None:
        return []
    positions = _json_positions(text)
    findings: list[Finding] = []
    for key, meta in marked:
        name = str(key).rsplit("node_modules/", 1)[-1]
        version = meta.get("version")
        shown = f"{name}@{version}" if isinstance(version, str) and version else name
        findings.append(make_finding(
            _NPM, rel,
            f"`{key}` ({shown}) is marked `hasInstallScript`: `npm install` and `npm ci` run "
            "its preinstall, install or postinstall script unless `--ignore-scripts` is set. "
            f"The project runs an MCP server ({why}).",
            positions.get(("packages", key)),
        ))
    return findings


# ---- conftest.py -----------------------------------------------------------------
#
# pytest imports every `conftest.py` under its rootdir and the test paths before
# the first test runs, in a process holding the environment of whatever started
# it: CI secrets, cloud credentials, AI API keys. A person typing `pytest`, a
# `make test`, a pre-commit hook and a coding agent asked to run the tests all
# run what a conftest.py holds, so whoever adds or changes one, in a pull request
# or as an agent writing tests, runs code on the next test run.
# AAK-STARTUP-HOOK-CONFTEST-001 reports a conftest.py that hands the environment
# to a network call (HIGH) or to a file it writes (MEDIUM).
#
# The file is parsed, never imported or run. A source is a bulk read of the
# environment (iterated, copied by one of its four copying methods or `dict`,
# unpacked into a display, put in an f-string, or passed whole to a call), or a
# read of one variable named like a secret, `*_KEY`, `*_TOKEN`, `*_SECRET` or
# `*_PASSWORD`, by a literal name. A sink is a call of urllib, http.client,
# socket, requests, httpx or aiohttp, a method of a client one of them built, a
# subprocess or shell command running curl, wget, nc, ncat or socat, or a write
# to a file opened for writing. The flow is one hop: a source inside the sink's
# arguments, or a name bound from a source (an assignment, a loop, or a
# comprehension's own variable inside that comprehension). A fixture reading one
# setting, a child process handed the environment through `env=`, and aak's own
# loop deleting a variable with monkeypatch are not flows.
#
# Every pass is iterative and touches each node a fixed number of times: the tree
# is listed once (`ast.walk`, parents before children), sources are marked from
# each node's own fields, lines are carried up the list in reverse (children
# before parents), names are looked up in dicts, and each sink reads only its own
# arguments' entries. A file of many reads, many names or many sinks costs what
# its size does, and an attribute chain is read to `_DOTTED_PARTS` parts at most.

_CONFTEST_NAME = "conftest.py"
_ENV_WORDS = (b"environ", b"getenv")
_SECRET_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
_ENVIRON = "os.environ"
_COPYING_METHODS = frozenset({"items", "keys", "values", "copy"})
_NAMED_READS = frozenset({"os.environ.get", "os.getenv"})
_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")
_NET_CLIENTS = frozenset({
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.socket", "socket.create_connection",
    "aiohttp.ClientSession", "requests.Session", "requests.session",
    "httpx.Client", "httpx.AsyncClient",
})
_NET_CALLS = _NET_CLIENTS | frozenset(
    {"urllib.request.urlopen", "urllib.request.Request", "aiohttp.request"}
    | {f"{module}.{verb}" for module in ("requests", "httpx") for verb in _HTTP_VERBS}
)
_PROCESS_CALLS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "os.system", "os.popen",
})
_NET_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "socat"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# A network tool as a word of a shell command: at the start, or after a blank or
# a shell separator, with an optional directory before it.
_NET_TOOL_RE = re.compile(r"(?:^|[\s;&|(`])(?:[\w.~/-]*/)?(curl|wget|nc|ncat|socat)(?=[\s;&|)`]|$)")
_OPEN_CALLS = frozenset({"open", "io.open", "codecs.open"})
_HANDLE_WRITES = frozenset({"write", "writelines"})
_PATH_WRITES = frozenset({"write_text", "write_bytes"})
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_PY_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
_DOTTED_PARTS = 4
_SHOWN_NAMES = 5

# name -> (line the environment is read on, the expression the name is bound from)
_Bindings = dict[str, tuple[int, ast.AST]]


class _Sink(NamedTuple):
    call: ast.Call
    network: bool
    reads: tuple[ast.AST, ...]  # the parts of the call a flow is looked for in
    what: str                   # how the evidence names the call


def _dotted(node: ast.AST | None, aliases: dict[str, str]) -> str | None:
    """`node` as a dotted name with its first part resolved through the file's
    imports (`o.environ` is `os.environ` after `import os as o`), or None. At
    most `_DOTTED_PARTS` parts are read, so a long attribute chain costs what a
    short one does."""
    parts: list[str] = []
    for _ in range(_DOTTED_PARTS):
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(aliases.get(node.id, node.id))
            return ".".join(reversed(parts))
        else:
            return None
    return None


def _import_aliases(nodes: list[ast.AST]) -> dict[str, str]:
    """Local name -> the module or attribute it was imported as."""
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.partition(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _secret_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value.upper().endswith(_SECRET_SUFFIXES):
            return node.value
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _arguments(call: ast.Call) -> tuple[ast.AST, ...]:
    return (*call.args, *(k.value for k in call.keywords))


def _env_sources(nodes: list[ast.AST], aliases: dict[str, str]) -> dict[ast.AST, str | None]:
    """Each source node, mapped to the variable it reads by name, or None for a
    read of the whole environment."""
    sources: dict[ast.AST, str | None] = {}
    for node in nodes:
        whole: tuple[ast.AST, ...] = ()
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            whole = (node.iter,)
        elif isinstance(node, ast.Call):
            whole = tuple(a.value if isinstance(a, ast.Starred) else a for a in _arguments(node))
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _COPYING_METHODS:
                if _dotted(func.value, aliases) == _ENVIRON:
                    sources[node] = None
            elif node.args and _dotted(func, aliases) in _NAMED_READS:
                name = _secret_name(node.args[0])
                if name is not None:
                    sources[node] = name
        elif isinstance(node, ast.Dict):
            whole = tuple(v for k, v in zip(node.keys, node.values) if k is None)
        elif isinstance(node, (ast.Starred, ast.FormattedValue)):
            whole = (node.value,)
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            name = _secret_name(node.slice)
            if name is not None and _dotted(node.value, aliases) == _ENVIRON:
                sources[node] = name
        for part in whole:
            if _dotted(part, aliases) == _ENVIRON:
                sources[part] = None
    return sources


def _first_lines(nodes: list[ast.AST], seeds: dict[ast.AST, int]) -> dict[ast.AST, int]:
    """For each node with a seed in its subtree, the first line of one.

    `nodes` is `ast.walk` order, which lists every parent before its children, so
    read in reverse each child is settled before its parent.
    """
    lines: dict[ast.AST, int] = {}
    for node in reversed(nodes):
        best = seeds.get(node)
        for child in ast.iter_child_nodes(node):
            line = lines.get(child)
            if line is not None and (best is None or line < best):
                best = line
        if best is not None:
            lines[node] = best
    return lines


def _bound_names(target: ast.AST) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)]


def _env_bindings(
    nodes: list[ast.AST], source_lines: dict[ast.AST, int]
) -> tuple[_Bindings, dict[ast.AST, _Bindings]]:
    """The names bound from a source: file-wide for an assignment or a loop, and
    per comprehension for a comprehension's own variables, which Python keeps
    inside it. A name bound twice keeps the binding whose source comes first."""
    file_wide: _Bindings = {}
    per_comprehension: dict[ast.AST, _Bindings] = {}
    for node in nodes:
        pairs: list[tuple[ast.AST, ast.AST]] = []
        if isinstance(node, ast.Assign):
            pairs = [(target, node.value) for target in node.targets]
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and node.value is not None:
            pairs = [(node.target, node.value)]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            pairs = [(node.target, node.iter)]
        elif isinstance(node, _COMPREHENSIONS):
            own: _Bindings = {}
            for generator in node.generators:
                line = source_lines.get(generator.iter)
                if line is not None:
                    for name in _bound_names(generator.target):
                        own.setdefault(name, (line, generator.iter))
            if own:
                per_comprehension[node] = own
        for target, value in pairs:
            line = source_lines.get(value)
            if line is None:
                continue
            for name in _bound_names(target):
                if name not in file_wide or line < file_wide[name][0]:
                    file_wide[name] = (line, value)
    return file_wide, per_comprehension


def _flow_seeds(
    nodes: list[ast.AST],
    sources: dict[ast.AST, str | None],
    file_wide: _Bindings,
    per_comprehension: dict[ast.AST, _Bindings],
) -> tuple[dict[ast.AST, int], dict[ast.AST, tuple[int, ast.AST]]]:
    """Seeds for the flow lines: every source, and every read of a bound name.

    A comprehension's variables are handed down to the nodes inside it, parents
    first, so a read finds them in one lookup; a name the comprehension binds
    hides a file-wide one of the same spelling, as Python's scoping does.
    Returns the seeds and, for each name read that is one, its binding.
    """
    seeds: dict[ast.AST, int] = {node: getattr(node, "lineno", 1) for node in sources}
    via: dict[ast.AST, tuple[int, ast.AST]] = {}
    visible: dict[ast.AST, _Bindings] = {}
    for node in nodes:
        scope = visible.get(node)
        own = per_comprehension.get(node)
        if own:
            scope = {**scope, **own} if scope else own
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            hit = (scope.get(node.id) if scope else None) or file_wide.get(node.id)
            if hit is not None:
                seeds[node] = hit[0]
                via[node] = hit
        if scope:
            for child in ast.iter_child_nodes(node):
                visible[child] = scope
    return seeds, via


def _text_of(node: ast.AST | None) -> str | None:
    """A string literal's text, or an f-string's literal parts with a NUL where
    each field goes."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "\0"
            for v in node.values
        )
    return None


def _shell_text(node: ast.AST | None) -> str | None:
    """The literal text of a shell command string: a string or an f-string, or
    the one a `+` or `%` expression, or a `.format` call, starts from. The walk
    down the left of an expression is the length of that expression, read once."""
    while True:
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            node = node.left
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            node = node.func.value
        else:
            return _text_of(node)


def _network_tool(command: ast.AST | None) -> str | None:
    """The network tool a subprocess command runs: the program of an argument
    list, a word of a shell string, or a word of a `sh -c` string."""
    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        program = (_text_of(command.elts[0]) or "").rsplit("/", 1)[-1]
        if program in _NET_TOOLS:
            return program
        if program not in _SHELLS:
            return None
        texts = [_shell_text(element) for element in command.elts[1:]]
    else:
        texts = [_shell_text(command)]
    for text in texts:
        match = _NET_TOOL_RE.search(text) if text else None
        if match:
            return match.group(1)
    return None


def _opens_for_writing(node: ast.AST | None, aliases: dict[str, str]) -> bool:
    """Is `node` an `open` call, or a path's `.open`, with a mode that writes?"""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if _dotted(func, aliases) in _OPEN_CALLS:
        mode = node.args[1] if len(node.args) > 1 else _keyword(node, "mode")
    elif isinstance(func, ast.Attribute) and func.attr == "open" and not (
        isinstance(func.value, ast.Name) and func.value.id in aliases
    ):
        mode = node.args[0] if node.args else _keyword(node, "mode")
    else:
        return False
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+")


class _Objects(NamedTuple):
    clients: frozenset[str]  # names bound to a network client
    handles: frozenset[str]  # names bound to a file opened for writing


def _bound_objects(nodes: list[ast.AST], aliases: dict[str, str]) -> _Objects:
    clients: set[str] = set()
    handles: set[str] = set()
    target: ast.AST | None
    value: ast.AST
    for node in nodes:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.withitem):
            target, value = node.optional_vars, node.context_expr
        else:
            continue
        if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
            continue
        if _dotted(value.func, aliases) in _NET_CLIENTS:
            clients.add(target.id)
        elif _opens_for_writing(value, aliases):
            handles.add(target.id)
    return _Objects(frozenset(clients), frozenset(handles))


def _is_object(node: ast.AST | None, names: frozenset[str], made: bool) -> bool:
    return isinstance(node, ast.Name) and node.id in names or made


def _sink(call: ast.Call, aliases: dict[str, str], objects: _Objects) -> _Sink | None:
    func = call.func
    name = _dotted(func, aliases)
    every = _arguments(call)
    if name in _NET_CALLS:
        return _Sink(call, True, every, f"`{name}`")
    if isinstance(func, ast.Attribute):
        receiver = func.value
        built = isinstance(receiver, ast.Call) and _dotted(receiver.func, aliases) in _NET_CLIENTS
        if _is_object(receiver, objects.clients, built):
            return _Sink(call, True, every, f"`.{func.attr}` of a network client")
        if func.attr in _PATH_WRITES:
            return _Sink(call, False, every, f"`.{func.attr}`")
        opened = _opens_for_writing(receiver, aliases)
        if func.attr in _HANDLE_WRITES and _is_object(receiver, objects.handles, opened):
            return _Sink(call, False, every, f"`.{func.attr}` of a file opened for writing")
    if name in _PROCESS_CALLS:
        command = call.args[0] if call.args else _keyword(call, "args")
        tool = _network_tool(command)
        if tool is None:
            return None
        reads = tuple(part for part in (command, _keyword(call, "input")) if part is not None)
        return _Sink(call, True, reads, f"`{name}` running `{tool}`")
    if name == "print":
        handle = _keyword(call, "file")
    elif name == "json.dump":
        handle = call.args[1] if len(call.args) > 1 else _keyword(call, "fp")
    else:
        return None
    if _is_object(handle, objects.handles, _opens_for_writing(handle, aliases)):
        return _Sink(call, False, every, f"`{name}` to a file opened for writing")
    return None


def _first_sink(
    nodes: list[ast.AST], aliases: dict[str, str], flow_lines: dict[ast.AST, int]
) -> tuple[_Sink, int] | None:
    """The sink to report and the first line its flow reads the environment on:
    the first network sink a flow reaches, else the first file write."""
    objects = _bound_objects(nodes, aliases)
    best: tuple[tuple[bool, int, int], _Sink, int] | None = None
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        sink = _sink(node, aliases, objects)
        if sink is None:
            continue
        lines = [flow_lines[part] for part in sink.reads if part in flow_lines]
        if not lines:
            continue
        key = (not sink.network, node.lineno, node.col_offset)
        if best is None or key < best[0]:
            best = (key, sink, min(lines))
    return (best[1], best[2]) if best else None


def _what_flows(
    sink: _Sink, sources: dict[ast.AST, str | None], via: dict[ast.AST, tuple[int, ast.AST]]
) -> tuple[list[str], bool, str | None]:
    """The variables a sink's flow reads by name, whether it reads the whole
    environment, and the bound name it goes through first, if any."""
    read: list[str | None] = []
    through: tuple[int, str] | None = None
    values: dict[int, ast.AST] = {}  # each binding's expression once, however often its name is read
    for part in sink.reads:
        for node in ast.walk(part):
            if node in sources:
                read.append(sources[node])
            elif isinstance(node, ast.Name) and node in via:
                line, value = via[node]
                values.setdefault(id(value), value)
                if through is None or (line, node.id) < through:
                    through = (line, node.id)
    for value in values.values():
        read.extend(sources[node] for node in ast.walk(value) if node in sources)
    names = sorted({name for name in read if name is not None})
    return names, None in read, through[1] if through else None


def _conftest_evidence(text: str, sink: _Sink, source_line: int, flows: tuple[list[str], bool, str | None]) -> str:
    names, whole, through = flows
    shown = ", ".join(f"`{n}`" for n in names[:_SHOWN_NAMES])
    if len(names) > _SHOWN_NAMES:
        shown += f" and {len(names) - _SHOWN_NAMES} more"
    if whole or not shown:
        what = "the environment, read whole" + (f" with {shown}" if shown else "")
    else:
        what = f"{shown}, read"
    route = f", through `{through}`," if through else ","
    lines = _PY_LINE_BREAK_RE.split(text)
    line = sink.call.lineno
    quoted = lines[line - 1].strip() if line <= len(lines) else ""
    verb, where = ("sends", "a network call") if sink.network else ("writes", "a file")
    return (
        f"Line {line} {verb} {what} on line {source_line}{route} to {where} "
        f"({sink.what}): `{_snippet(quoted)}`. pytest imports every conftest.py under its "
        "rootdir and test paths before the first test, so any test run, a coding agent's "
        "included, runs this with the environment of the shell that started it."
    )


def _conftest_flow(tree: ast.AST, text: str, rel: str) -> Finding | None:
    nodes = list(ast.walk(tree))
    aliases = _import_aliases(nodes)
    sources = _env_sources(nodes, aliases)
    if not sources:
        return None
    source_lines = _first_lines(nodes, {node: getattr(node, "lineno", 1) for node in sources})
    file_wide, per_comprehension = _env_bindings(nodes, source_lines)
    seeds, via = _flow_seeds(nodes, sources, file_wide, per_comprehension)
    found = _first_sink(nodes, aliases, _first_lines(nodes, seeds))
    if found is None:
        return None
    sink, source_line = found
    evidence = _conftest_evidence(text, sink, source_line, _what_flows(sink, sources, via))
    finding = make_finding(_CONFTEST, rel, evidence, sink.call.lineno)
    return finding if sink.network else replace(finding, severity=Severity.MEDIUM)


def _conftest_findings(path: Path, state: _ScanState) -> list[Finding]:
    """AAK-STARTUP-HOOK-CONFTEST-001 for one conftest.py: parsed, never imported.

    The bytes are parsed as Python parses a source file (a BOM or a coding line
    honoured). A file with neither `environ` nor `getenv` in it holds no source
    and is not parsed; one that does not parse is not reported.
    """
    try:
        raw = read_bytes_capped(path, CONFIG_MAX_BYTES)
    except FileNotRead as exc:
        if exc.errno == errno.EFBIG:
            refuse(path, f"conftest.py larger than {CONFIG_MAX_BYTES:,} bytes, not read")
        return []
    except OSError:
        return []
    rel = _rel(path, state.project_root)
    state.scanned.add(rel)
    if not any(word in raw for word in _ENV_WORDS):
        return []
    try:
        tree = parse_python(raw, path)
    except (SyntaxError, ValueError):
        return []
    with refusing_overflow(path):
        finding = _conftest_flow(tree, raw.decode("utf-8-sig", errors="replace"), rel)
        return [finding] if finding is not None else []
    return []


# ---- the scan --------------------------------------------------------------------


def _project_files(project_root: Path) -> Iterator[Path]:
    """Dockerfiles, npm lockfiles and conftest.py files under the root, outside
    `SKIP_DIRS`."""
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = kept_dirs(dirpath, dirnames, project_root)
        for name in sorted(filenames):
            if _dockerfile_kind(name) or name in _LOCKFILE_NAMES or name == _CONFTEST_NAME:
                yield Path(dirpath) / name


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report Python startup files and npm install scripts that run unasked.

    Args:
        project_root: The root directory of the project, or an unpacked image
            root filesystem.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    state = _ScanState(project_root)
    for site_dir in site_package_dirs(project_root):
        findings.extend(_site_dir_findings(site_dir, state))
    for path in _project_files(project_root):
        if path.name in _LOCKFILE_NAMES:
            findings.extend(_lockfile_findings(path, state))
            continue
        if path.name == _CONFTEST_NAME:
            findings.extend(_conftest_findings(path, state))
            continue
        try:
            text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
        except OSError:
            continue
        state.scanned.add(_rel(path, project_root))
        findings.extend(_dockerfile_findings(path, text, project_root, state))
    return findings, state.scanned
