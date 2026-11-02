"""AAK-MCP-CODEEXEC-SANDBOX-001 and -002: code-execution tools whose sandbox runtime has open permissions.

FastMCP's Generative UI provider (`mcp.add_provider(GenerativeUI())`, from
`fastmcp.apps.generative`) adds a `generate_prefab_ui` tool that takes Python
code from its caller and runs it in prefab-ui's sandbox: Pyodide inside a Deno
subprocess. prefab-ui 0.14.0 up to 0.21.0 started that subprocess with
`deno run --allow-read --allow-write --allow-net` and never took the
permissions back, and Python in Pyodide can reach Deno's API, so whoever could
call the tool could read and write files as the server's user and leave a
`.pth` file in its environment (CVE-2026-120338, JFrog, CVSS 10.0; fixed in
0.21.0, PrefectHQ/prefab PR 538). 0.21.0 scopes the network permission to the
Pyodide CDN, adds `--no-prompt`, and revokes read, write and net in its runner
(`Deno.permissions.revoke`) before it accepts generated code.

-001 is the FastMCP shape of it: Python source that registers `GenerativeUI`,
in a project whose lockfiles or installed packages give prefab-ui 0.14.0 up to
0.21.0, or that pins it nowhere (fastmcp's `apps` extra asks only for
`prefab-ui>=0.18.0`). It reads versions with the readers AAK-KNOWN-VULN-001 uses.

-002 is the class: a Deno launch with an open permission (`-A`, `--allow-all`,
or `--allow-read`, `--allow-write`, `--allow-net`, `--allow-run`,
`--allow-env`, `--allow-ffi`, `--allow-sys` or `--allow-import` with no value),
in Python or JS/TS source, where code a caller supplies reaches the runtime: a
Pyodide `runPython`/`runPythonAsync`, an `eval` or a `new Function` whose
argument is not a plain literal, in the launching file or in a script it names
beside it (prefab-ui's `_pyodide.py` starts `runner.js`). A permission the
script revokes with `Deno.permissions.revoke` counts as closed. This is pattern
matching, not data flow; the limitations say where it stops.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path

from agent_audit_kit.malicious_feed import canonical_name, version_order
from agent_audit_kit.models import Finding

from ._dependency_pins import read_text
from ._helpers import SKIP_DIRS, SOURCE_MAX_BYTES, make_finding, parse_python
from ._manifest_deps import MAX_LOCKFILE_BYTES
from ._site_packages import site_entries, site_package_dirs
from ._versions import interval_spans, intersect, parse_range
from .malicious_releases import _LOCKFILES, _declared, _is_manifest, _version_line, exact_pin
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries

RULE_GENUI = "AAK-MCP-CODEEXEC-SANDBOX-001"
RULE_DENO = "AAK-MCP-CODEEXEC-SANDBOX-002"
CVE = "CVE-2026-120338"
PACKAGE = "prefab-ui"
INTRODUCED, FIXED = "0.14.0", "0.21.0"

_GENUI_MODULE = "fastmcp.apps.generative"
_GENUI_CLASS = "GenerativeUI"
_PY_EXTS = frozenset({".py"})
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"})
#: How many releases of prefab-ui one lockfile is read for, as AAK-KNOWN-VULN-001 reads them.
_RELEASES_PER_LOCKFILE = 64

# A Deno launch: the `deno` executable (a word, a path ending in it, `Deno.execPath()`)
# and then its `run` subcommand, as an argument list (`[deno, "run"`, `spawn("deno",
# ["run"`, `{ args: ["run"`) or a command string (`"deno run`).
_LAUNCH_RE = re.compile(
    r"""(?:\bdeno(?:\.exe)?\b|\bDeno\.execPath\(\))["'`]?\s*"""
    r"""(?:,\s*(?:\{\s*args\s*:\s*)?\[?\s*)?["'`]?run\b"""
)
#: How far past `run` a launch's arguments are read, up to the first `]` or `)`.
LAUNCH_WINDOW = 1_500
_LAUNCH_END_RE = re.compile(r"[\])]")
# A permission flag with no value: `-A`, `--allow-all`, `--allow-read`. A scoped one
# (`--allow-read=/srv/assets`) is followed by `=` and is not read.
_FLAG_RE = re.compile(r"(?<![\w-])(-A|--allow-all|--allow-(read|write|net|run|env|ffi|sys|import))(?![\w=-])")
_ALL = ("read", "write", "net", "run", "env", "ffi", "sys")
# Code handed to the runtime: Pyodide's runners, `eval`, `new Function`.
_HANDOFF_RE = re.compile(r"\b(runPythonAsync|runPython|eval)\s*\(|\bnew\s+Function\s*\(")
_REVOKE_RE = re.compile(r"\bDeno\.permissions\.revoke(?:Sync)?\s*\(")
_PERMISSION_NAME_RE = re.compile(r"""["'`](read|write|net|run|env|ffi|sys|import)["'`]""")
#: How much text before and after a revoke call its permission names are read from:
#: `revoke({ name: "read" })`, or a loop over `["read", "write", "net"]` just above it.
_REVOKE_BEFORE, _REVOKE_AFTER = 300, 120
_SCRIPT_RE = re.compile(r"""["']([\w./-]{1,200}\.(?:js|mjs|cjs|ts|mts|cts))["']""")
#: How many script names one launching file is followed to.
_SCRIPTS_PER_FILE = 32
_LITERAL_END = {'"': re.compile(r'(?:[^"\\\n]|\\.)*"'), "'": re.compile(r"(?:[^'\\\n]|\\.)*'")}
_TEMPLATE_END = re.compile(r"(?:[^`\\]|\\.)*`", re.S)
# After a literal first argument: the call ends, or (Pyodide's options) goes on to another.
_CLOSE_RE = re.compile(r"\s*[),]")
# `new Function(a, b, body)` takes its code last, so only a lone literal is constant.
_LONE_RE = re.compile(r"\s*\)")
_TEMPLATE_WINDOW = 20_000


# ---- the walk ---------------------------------------------------------------------------------


@dataclass
class _Tree:
    python: list[Path]
    js: list[Path]
    lockfiles: list[Path]
    manifests: list[Path]


def _walk(project_root: Path) -> _Tree:
    tree = _Tree([], [], [], [])
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            low = name.lower()
            suffix = path.suffix.lower()
            if suffix in _PY_EXTS:
                tree.python.append(path)
            elif suffix in _JS_EXTS:
                tree.js.append(path)
            if low in _LOCKFILES:
                tree.lockfiles.append(path)
            elif _is_manifest(name):
                tree.manifests.append(path)
    return tree


def _source(path: Path) -> str | None:
    return read_text(path, SOURCE_MAX_BYTES)


# ---- AAK-MCP-CODEEXEC-SANDBOX-001: GenerativeUI on an affected prefab-ui ---------------------


def _dotted(expr: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return None
    parts.append(expr.id)
    return ".".join(reversed(parts))


def genui_registrations(tree: ast.Module) -> list[int]:
    """Lines of the `add_provider(...)` calls that register FastMCP's `GenerativeUI`.

    The class is recognised by its import (`from fastmcp.apps.generative import
    GenerativeUI`, any alias, or the module imported and the class named on it),
    and the registration as `add_provider(GenerativeUI(...))` or
    `add_provider(x)` with `x = GenerativeUI(...)` in the same module.
    """
    classes: set[str] = set()
    modules: set[str] = {_GENUI_MODULE}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _GENUI_MODULE:
            classes.update(a.asname or a.name for a in node.names if a.name == _GENUI_CLASS)
        elif isinstance(node, ast.ImportFrom) and node.module == "fastmcp.apps":
            modules.update(a.asname or a.name for a in node.names if a.name == "generative")
        elif isinstance(node, ast.Import):
            modules.update(a.asname for a in node.names if a.name == _GENUI_MODULE and a.asname)

    def constructs(expr: ast.expr | None) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if isinstance(func, ast.Name):
            return func.id in classes
        return isinstance(func, ast.Attribute) and func.attr == _GENUI_CLASS and _dotted(func.value) in modules

    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and constructs(node.value):
            bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and constructs(node.value) and isinstance(node.target, ast.Name):
            bound.add(node.target.id)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_provider"):
            continue
        for arg in [*node.args, *(k.value for k in node.keywords)]:
            if constructs(arg) or (isinstance(arg, ast.Name) and arg.id in bound):
                lines.add(node.lineno)
    return sorted(lines)


def _affected(version: str) -> bool:
    key = version_order("PyPI", version)
    low, high = version_order("PyPI", INTRODUCED), version_order("PyPI", FIXED)
    return key is not None and low is not None and high is not None and low <= key < high


@dataclass(frozen=True)
class _Seen:
    where: str        # the file, relative to the root
    line: int | None
    version: str      # a release, or a manifest range


def _prefab_versions(project_root: Path, tree: _Tree) -> tuple[list[_Seen], list[_Seen]]:
    """(releases the project resolves or has installed, ranges its manifests declare)."""
    resolved: list[_Seen] = []
    declared: list[_Seen] = []
    wanted = frozenset({PACKAGE})
    for path in tree.lockfiles:
        ecosystem, reader = _LOCKFILES[path.name.lower()]
        if ecosystem != "PyPI":
            continue
        text = read_text(path, MAX_LOCKFILE_BYTES)
        if text is None:
            continue
        rel = path.relative_to(project_root).as_posix()
        for rows in _lockfile_raw_entries(text, reader, wanted).values():
            seen: set[str] = set()
            for line, version in rows:
                if version and version not in seen and len(seen) < _RELEASES_PER_LOCKFILE:
                    seen.add(version)
                    resolved.append(_Seen(rel, line, version))
    for site_dir in site_package_dirs(project_root):
        for entry in site_entries(site_dir):
            if not entry.name.endswith(".dist-info") or not entry.is_dir(follow_symlinks=False):
                continue
            name, sep, version = entry.name[: -len(".dist-info")].rpartition("-")
            if sep and canonical_name("PyPI", name) == PACKAGE and version:
                metadata = Path(entry.path) / "METADATA"
                where = metadata if metadata.is_file() else Path(entry.path)
                at = _version_line(metadata) if where is metadata else None
                resolved.append(_Seen(where.relative_to(project_root).as_posix(), at, version))
    for path in tree.manifests:
        found = _declared(path)
        if found is None:
            continue
        declarations, line_of = found
        rel = path.relative_to(project_root).as_posix()
        for declaration in declarations:
            if declaration.ecosystem not in ("py", None) or canonical_name("PyPI", declaration.name) != PACKAGE:
                continue
            pinned = exact_pin(declaration)
            target = resolved if pinned is not None else declared
            target.append(_Seen(rel, line_of(declaration), pinned or declaration.version))
    return resolved, declared


def _admits_affected(declared: _Seen) -> bool:
    spans = parse_range(declared.version, "pep440") if declared.version.strip() else None
    return spans is None or bool(intersect(spans, interval_spans([(INTRODUCED, FIXED, None)])))


def _genui_state(resolved: list[_Seen], declared: list[_Seen]) -> str | None:
    """What makes the project's prefab-ui affected, or None when it is not."""
    if resolved:
        hits = [seen for seen in resolved if _affected(seen.version)]
        if not hits:
            return None
        first = hits[0]
        where = f"{first.where}:{first.line}" if first.line else first.where
        more = f" (and {len(hits) - 1} more)" if len(hits) > 1 else ""
        return f"{where} gives prefab-ui {first.version}{more}"
    if declared and not any(_admits_affected(seen) for seen in declared):
        return None
    if declared:
        seen = declared[0]
        return (f"no lockfile or installed copy says which prefab-ui it runs, and {seen.where} "
                f"declares `{seen.version or 'prefab-ui'}`, which admits an affected release")
    return ("no lockfile or installed copy says which prefab-ui it runs, and nothing pins it "
            "(fastmcp's `apps` extra asks only for prefab-ui>=0.18.0)")


def _genui_findings(project_root: Path, tree: _Tree, scanned: set[str]) -> list[Finding]:
    registrations: list[tuple[str, int]] = []
    for path in tree.python:
        text = _source(path)
        if text is None or _GENUI_CLASS not in text:
            continue
        try:
            parsed = parse_python(text, path)
        except (SyntaxError, ValueError):
            continue
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        registrations.extend((rel, line) for line in genui_registrations(parsed))
    if not registrations:
        return []
    resolved, declared = _prefab_versions(project_root, tree)
    state = _genui_state(resolved, declared)
    if state is None:
        return []
    return [
        make_finding(
            RULE_GENUI, rel,
            f"`{rel}:{line}` registers FastMCP's GenerativeUI provider, whose `generate_prefab_ui` "
            f"tool runs Python its caller supplies in prefab-ui's Pyodide sandbox, and {state}. "
            f"prefab-ui {INTRODUCED} up to {FIXED} starts that sandbox's Deno runtime with unscoped "
            f"read, write and network permissions the code can reach ({CVE}, CVSS 10.0); it is "
            f"fixed in {FIXED}. Upgrade prefab-ui to {FIXED} or later and re-lock (fastmcp's "
            "`apps` extra does not require it), and check the server's environment for "
            "unexpected .pth files, which AAK-STARTUP-HOOK-PTH-001 reads. The finding says the "
            "tool is exposed, not that it was used.",
            line,
        )
        for rel, line in registrations
    ]


# ---- AAK-MCP-CODEEXEC-SANDBOX-002: Deno with open permissions and caller code -----------------


def _literal_end(text: str, start: int) -> int | None:
    """The offset just past a string literal opening at `start`, or None."""
    quote = text[start]
    if quote == "`":
        m = _TEMPLATE_END.match(text, start + 1, min(len(text), start + 1 + _TEMPLATE_WINDOW))
        return m.end() if m else None
    m = _LITERAL_END[quote].match(text, start + 1)
    return m.end() if m else None


def _handoffs(text: str) -> list[tuple[int, str]]:
    """(offset, call) of each call that hands the runtime code which is not a plain literal."""
    out: list[tuple[int, str]] = []
    for m in _HANDOFF_RE.finditer(text):
        at = m.end()
        while at < len(text) and text[at] in " \t\r\n":
            at += 1
        call = m.group(1) or "new Function"
        if at < len(text) and text[at] in "\"'`":
            end = _literal_end(text, at)
            if end is not None:
                literal = text[at:end]
                closes = (_LONE_RE if call == "new Function" else _CLOSE_RE).match(text, end)
                if not (literal.startswith("`") and "${" in literal) and closes:
                    continue  # a constant string: nothing a caller wrote
        out.append((m.start(), call))
    return out


def _revoked(text: str) -> set[str]:
    names: set[str] = set()
    for m in _REVOKE_RE.finditer(text):
        window = text[max(0, m.start() - _REVOKE_BEFORE): m.end() + _REVOKE_AFTER]
        names.update(n.group(1) for n in _PERMISSION_NAME_RE.finditer(window))
    return names


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


@dataclass(frozen=True)
class _Runner:
    rel: str
    handoff: tuple[int, str] | None   # (line, call)
    revoked: frozenset[str]


def _runner(path: Path, project_root: Path, cache: dict[Path, _Runner | None]) -> _Runner | None:
    """How one JS/TS file hands a runtime code and which permissions it revokes."""
    if path in cache:
        return cache[path]
    result: _Runner | None = None
    text = _source(path) if path.suffix.lower() in _JS_EXTS else None
    if text is not None:
        found = _handoffs(text)
        first = (_line(text, found[0][0]), found[0][1]) if found else None
        result = _Runner(path.relative_to(project_root).as_posix(), first, frozenset(_revoked(text)))
    cache[path] = result
    return result


def _scripts(text: str, path: Path, project_root: Path) -> list[Path]:
    """The JS/TS scripts a launching file names, resolved beside it, inside the root."""
    out: list[Path] = []
    root = project_root.resolve()
    for m in _SCRIPT_RE.finditer(text):
        if len(out) >= _SCRIPTS_PER_FILE:
            break
        candidate = (path.parent / m.group(1)).resolve()
        if candidate.is_file() and candidate.is_relative_to(root) and candidate not in out:
            out.append(candidate)
    return out


def _granted(window: str) -> tuple[list[str], set[str]]:
    flags: list[str] = []
    names: set[str] = set()
    for m in _FLAG_RE.finditer(window):
        if m.group(1) not in flags:
            flags.append(m.group(1))
        names.update(_ALL if m.group(2) is None else (m.group(2),))
    return flags, names


def _deno_findings(project_root: Path, tree: _Tree, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    cache: dict[Path, _Runner | None] = {}
    root = project_root.resolve()
    for path in tree.python + tree.js:
        text = _source(path)
        if text is None or "deno" not in text.lower():
            continue
        rel = path.relative_to(project_root).as_posix()
        launches = []
        at = 0
        while True:
            m = _LAUNCH_RE.search(text, at)
            if m is None:
                break
            limit = min(len(text), m.end() + LAUNCH_WINDOW)
            close = _LAUNCH_END_RE.search(text, m.end(), limit)
            end = close.start() if close else limit
            launches.append((m.start(), text[m.end():end]))
            at = max(end, m.end())
        if not launches:
            continue
        scanned.add(rel)
        runners: list[_Runner] = []
        for candidate in ([path.resolve()] if path.suffix.lower() in _JS_EXTS else []) + _scripts(text, path, root):
            found = _runner(candidate, root, cache)
            if found is not None and found.handoff is not None and found not in runners:
                runners.append(found)
        if not runners:
            continue
        line, counted = 1, 0  # launches come in file order: count lines once, forward
        for offset, window in launches:
            line += text.count("\n", counted, offset)
            counted = offset
            flags, names = _granted(window)
            if not flags:
                continue
            for runner in runners:
                still_open = sorted(names - runner.revoked)
                if not still_open or runner.handoff is None:
                    continue
                handoff_line, call = runner.handoff
                revoked = (f"; it revokes only {', '.join(sorted(runner.revoked))}" if runner.revoked
                           else ", and nothing revokes them")
                findings.append(make_finding(
                    RULE_DENO, rel,
                    f"`{rel}:{line}` starts Deno with {' '.join(flags)}, which leaves "
                    f"{', '.join(still_open)} open, and `{runner.rel}:{handoff_line}` hands that "
                    f"runtime code to run (`{call}(...)` of text that is not a fixed literal){revoked}. "
                    "Code a caller supplies then has the server's own access to files, network or "
                    "processes, as prefab-ui's Generative UI sandbox had below 0.21.0 "
                    f"({CVE}). Start the runtime with no permissions or scoped ones "
                    "(`--allow-read=<dir>`, `--allow-net=<host>`), revoke what bootstrap needed "
                    "with `Deno.permissions.revoke` before taking code and pass `--no-prompt`, as "
                    "prefab-ui 0.21.0 does, and check the server's environment for unexpected .pth "
                    "files, which AAK-STARTUP-HOOK-PTH-001 reads. The finding reads the launch, not "
                    "whether the sandbox was escaped.",
                    line,
                ))
                break  # one finding per launch
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report GenerativeUI on an affected prefab-ui, and Deno sandboxes with open permissions.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    tree = _walk(project_root)
    scanned: set[str] = set()
    findings = _genui_findings(project_root, tree, scanned)
    findings.extend(_deno_findings(project_root, tree, scanned))
    return findings, scanned


__all__ = ["RULE_GENUI", "RULE_DENO", "CVE", "scan", "genui_registrations", "LAUNCH_WINDOW"]
