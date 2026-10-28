"""Startup hooks: code an install puts where Python or npm runs it unasked.

litellm 1.107.0 (21 Oct 2026, OSV MAL-2026-2144) needed no import of litellm to
run. Every wheel carried `cook.pth`, `cook.py` and `sitecustomize.py`, which pip
installs at the top of site-packages, and Python runs both kinds of file at
every interpreter start, `pip` included. The pin rules judged the version and
passed it, because 1.107.0 was above every pinned floor. This module reports the
route, whatever package takes it:

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
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Iterator

from agent_audit_kit.models import Finding

from ._helpers import (
    CONFIG_MAX_BYTES,
    MCP_TS_SDK_NAMES,
    SKIP_DIRS,
    FileNotRead,
    declares_mcp_sdk,
    iter_mcp_servers,
    loads_json,
    loads_jsonc,
    make_finding,
    read_bytes_capped,
    read_text_capped,
    refuse,
)
from ._launchers import shell_words
from ._manifest_deps import MAX_LOCKFILE_BYTES, _json_positions
from ._site_packages import site_entries, site_package_dirs

_PTH = "AAK-STARTUP-HOOK-PTH-001"
_CUSTOMIZE = "AAK-STARTUP-HOOK-SITECUSTOMIZE-001"
_DOCKERFILE = "AAK-STARTUP-HOOK-DOCKERFILE-001"
_NPM = "AAK-STARTUP-HOOK-NPM-INSTALL-001"

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


# ---- the scan --------------------------------------------------------------------


def _project_files(project_root: Path) -> Iterator[Path]:
    """Dockerfiles and npm lockfiles under the root, outside `SKIP_DIRS`."""
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if _dockerfile_kind(name) or name in _LOCKFILE_NAMES:
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
        try:
            text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
        except OSError:
            continue
        state.scanned.add(_rel(path, project_root))
        findings.extend(_dockerfile_findings(path, text, project_root, state))
    return findings, state.scanned
