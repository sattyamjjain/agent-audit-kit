"""Ox MCP STDIO command-injection scanner (AAK-STDIO-001).

Fires when user-controlled input flows into a shell-style executor
inside an MCP server implementation. This is the architectural shape
the Ox Security April-16 2026 disclosure traced through **10 CVEs and
200,000+ exposed servers**:

    ┌──────────────┐      ┌────────────────────────────┐      ┌─────────┐
    │  MCP tool    │─────▶│ StdioServerParameters /    │─────▶│  shell  │
    │  caller      │ args │ subprocess.*(shell=True)   │      │  exec   │
    └──────────────┘      └────────────────────────────┘      └─────────┘

References:
- Ox disclosure (Apr 16 2026):
  https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/
- Windsurf RCE (2026-04-15): https://nvd.nist.gov/vuln/detail/CVE-2026-30615
- Associated CVEs: CVE-2025-65720, CVE-2026-30617, CVE-2026-30618,
  CVE-2026-30623, CVE-2026-30624, CVE-2026-30625, CVE-2026-33224,
  CVE-2026-26015.

Python side: AST walk. We look for MCP-server hint files (modules that
register @tool or import StdioServerParameters) and flag every
`subprocess.*` / `os.system` / `os.popen` / `exec` / `eval` call whose
args reference a taint source: `request.params`, `stdin`, `sys.stdin`,
`json.loads(...)` wrapped around stdin, `StdioServerParameters`
construction, or a parameter of a `@tool`-decorated function.

TS/JS side: regex on `.ts` / `.tsx` / `.js` / `.mjs` files that hint at
MCP server code; matches on `child_process.spawn` / `execa` / `exec`
with `shell: true` plus a request-body interpolation.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, in_skip_dir
from agent_audit_kit.scanners._versions import ZERO, admits, parse_range


_PY_EXTS = {".py"}
_JS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs"}
_MAX_FILE_BYTES = 512_000


_PY_MCP_HINT_RE = re.compile(
    r"\b(?:StdioServerParameters|FastMCP|@tool|McpServer|Server\.run_streamable_http|mcp\.server)\b"
)

# Taint sources: things that make an argument "attacker-controlled" in the
# Ox threat model.
_TAINT_NAME = frozenset({
    "stdin", "request", "req", "event", "params", "tool_input",
    "input_data", "args", "payload",
})
_TAINT_ATTR_CHAINS = {
    ("request", "params"),
    ("request", "body"),
    ("request", "json"),
    ("req", "body"),
    ("req", "json"),
    ("req", "query"),
    ("event", "body"),
    ("sys", "stdin"),
    ("process", "stdin"),
}

_DANGEROUS_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
    "os.system", "os.popen", "os.exec", "os.execv", "os.execvp",
    "commands.getoutput", "commands.getstatusoutput",
    "eval", "exec",
}

# Any call whose last name is one of these is a candidate sink...
_LOOSE_SINK_NAMES = frozenset({
    "system", "popen", "exec", "eval", "run", "Popen", "call", "check_call", "check_output",
})
# ...but one that is not a `_DANGEROUS_CALLS` name after the file's imports are
# resolved counts only on a receiver that names an executor. Matching the last
# name alone reported `asyncio.run(main(args))`, a Cozo or LLM-tool
# `client.run(...)`, a `registry.call(name, arguments)` dispatcher and a file's
# own `run(...)` helper as command injection: on 1,713 real Python MCP repos 88
# judged findings had that shape and none was real. The cost is an executor
# behind a short name, such as Fabric's `c.run(cmd)`.
_EXEC_RECEIVER_RE = re.compile(
    r"(?i)(subprocess|popen|shell|interpreter|process|proc|sandbox|executor|terminal|cmd|command|spawn|runner)"
)
# Modules a file may import an executor from, bare or under an alias. Not
# asyncio: `from asyncio import run` binds a coroutine runner, not a process.
_EXEC_MODULES = frozenset({"subprocess", "os", "commands"})


def _exec_import_names(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    """The names a file binds to an executor module, and to a function of one.

    `import subprocess as sp` maps `sp` to `subprocess`, and `from subprocess
    import run` maps `run` to `subprocess.run`, so `sp.run(...)` and a bare
    `run(...)` resolve to the call they make.
    """
    modules: dict[str, str] = {}
    functions: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _EXEC_MODULES:
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in _EXEC_MODULES:
            for alias in node.names:
                functions[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return modules, functions


def _resolve_call(fqn: str, modules: dict[str, str], functions: dict[str, str]) -> str:
    """`fqn` with an imported alias replaced by the name it binds."""
    head, _, rest = fqn.partition(".")
    if rest and head in modules:
        return f"{modules[head]}.{rest}"
    if not rest and fqn in functions:
        return functions[fqn]
    return fqn


def _is_executor_call(fqn: str, resolved: str) -> bool:
    """Whether a call whose last name is a candidate sink runs a command."""
    if resolved in _DANGEROUS_CALLS:
        return True
    receiver = fqn.rpartition(".")[0]
    return bool(receiver) and bool(_EXEC_RECEIVER_RE.search(receiver))


def _iter_python_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*.py"):
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _iter_js_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _JS_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _call_fqn(func: ast.expr) -> str:
    """Resolve `foo.bar.baz(...)` → 'foo.bar.baz' (best-effort)."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _node_references_taint(node: ast.AST) -> bool:
    """Return True if an AST subtree references any known taint source."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in _TAINT_NAME:
            return True
        if isinstance(sub, ast.Attribute):
            chain = []
            cur: ast.expr = sub
            while isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                chain.append(cur.id)
                chain = list(reversed(chain))
                for length in range(2, len(chain) + 1):
                    if tuple(chain[: length][-2:]) in _TAINT_ATTR_CHAINS:
                        return True
                    # Match (prefix[-2], prefix[-1]) windows.
                # fall through
            # check "sys.stdin.read()" etc.
            if isinstance(cur, ast.Name) and len(chain) >= 2:
                if (chain[-2], chain[-1]) in _TAINT_ATTR_CHAINS:
                    return True
        if isinstance(sub, ast.Call):
            fqn = _call_fqn(sub.func)
            if fqn == "json.loads":
                # json.loads(stdin.read()) — tainted.
                for arg in sub.args:
                    if _node_references_taint(arg):
                        return True
    return False


def _python_hint_match(text: str) -> bool:
    return bool(_PY_MCP_HINT_RE.search(text))


def _check_python_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not _python_hint_match(text):
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []

    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    # Track parameters of @tool-decorated functions as taint sources. A
    # decorator written with parentheses (`@mcp.tool()`, `@server.call_tool()`)
    # is a Call, which `_call_fqn` cannot name, so it is named by its `func`.
    # Both arms used to pass the node itself, which left every parenthesised
    # tool, the usual FastMCP spelling and the only low-level one, with no
    # caller input.
    tool_params: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = [
                (_call_fqn(d.func) if isinstance(d, ast.Call) else _call_fqn(d))
                for d in node.decorator_list
            ]
            if any(dec.endswith("tool") or dec.endswith(".tool") for dec in decorators):
                tool_params.update(arg.arg for arg in node.args.args)
                tool_params.update(arg.arg for arg in node.args.kwonlyargs)

    taint_names_in_file = set(_TAINT_NAME) | tool_params
    exec_modules, exec_functions = _exec_import_names(tree)

    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        fqn = _call_fqn(call.func)
        if not fqn:
            continue
        if fqn not in _DANGEROUS_CALLS and fqn.split(".")[-1] not in _LOOSE_SINK_NAMES:
            continue
        resolved = _resolve_call(fqn, exec_modules, exec_functions)
        if not _is_executor_call(fqn, resolved):
            continue

        # For subprocess.*, only fire if shell=True OR the first arg is a
        # dynamic expression. For os.system / os.popen / exec / eval we
        # always fire when tainted.
        is_subprocess = resolved.startswith("subprocess.")
        shell_true = False
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                shell_true = True

        def _args_reference_taint() -> bool:
            for arg in call.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in taint_names_in_file:
                        return True
                    if _node_references_taint(sub):
                        return True
            return False

        # An argv-list `subprocess.*(["cmd", arg], shell=False)` is the SAFE
        # form: the elements are handed to execve() directly, so a tainted
        # element is an argument, not a shell-injection vector. Only
        # shell=True (or a string / dynamic command expression) is the
        # AAK-STDIO-001 sink. Skip argv-list calls that aren't shell=True.
        if is_subprocess and not shell_true:
            first_arg = call.args[0] if call.args else None
            if isinstance(first_arg, (ast.List, ast.Tuple)):
                continue
            # `["git"] + args` is an argv list too: a list on the left of `+`.
            if (isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add)
                    and isinstance(first_arg.left, (ast.List, ast.Tuple))):
                continue
        if not _args_reference_taint():
            continue

        snippet = ast.unparse(call) if hasattr(ast, "unparse") else fqn
        findings.append(
            make_finding(
                "AAK-STDIO-001",
                rel,
                f"STDIO command injection path: {snippet[:200]!r}"
                + (" (shell=True)" if shell_true else ""),
                line_number=call.lineno,
            )
        )

    return findings


# ---- TS / JS side ----

_JS_MCP_HINT_RE = re.compile(
    r"\b(?:StdioServerParameters|createServer|McpServer|@tool|stdio\s*:|mcp\.server)\b",
    re.IGNORECASE,
)

# Both patterns keep each scan inside one call and one object or interpolation,
# so a crafted file is read in linear time. They were super-linear: the
# argument scan of every `exec(` ran on to the next `)` across later calls, the
# object scan of every `{` ran on to the next `}` across later objects, and an
# extra `\s*` beside another one split each whitespace run every possible way.
# 3,600 characters of `exec({` took 1.6 seconds and doubling it took eight times
# as long. Now the argument scan stops at the next call, the object scan stops at
# the next brace of either kind (the walk over the arguments still tries every
# `{`, so `shell: true` directly in the options object matches exactly as
# before), and the interpolation scan stops at the next `$`, `}` or backtick,
# with the closing backtick checked once, up front.
_JS_SHELL_TRUE_RE = re.compile(
    r"""(?:child_process\.)?(?:spawn|exec|execFile|execa)\s*\(
        (?:(?!(?:spawn|exec|execFile|execa)\s*\()[^)])*?
        \{[^{}]*?\bshell\s*:\s*true\b
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

_JS_DYNAMIC_CMD_RE = re.compile(
    r"""(?:child_process\.)?(?:spawn|exec|execFile|execa)\s*\(\s*
        (?:`(?=[^`]*`)[^`]*\$\{[^$}`]*(?:req|request|body|params|event|stdin|tool_input)[^`]*`
         |[\"'][^\"']*[\"']\s*\+\s*\w*(?:req|request|body|params|event|stdin|tool_input)
         |\w+(?:\.\w+)*(?:req|request|body|params|event|stdin|tool_input)
         )""",
    re.IGNORECASE | re.VERBOSE,
)


def _check_js_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not _JS_MCP_HINT_RE.search(text):
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    for match in _JS_SHELL_TRUE_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-STDIO-001",
                rel,
                f"child_process spawn/exec/execa with {{shell: true}} in MCP server: {match.group(0)[:200]!r}",
                line_number=find_line_number(text, match.group(0).splitlines()[0]),
            )
        )

    for match in _JS_DYNAMIC_CMD_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-STDIO-001",
                rel,
                f"child_process invocation with request-derived command: {match.group(0)[:200]!r}",
                line_number=find_line_number(text, match.group(0).splitlines()[0]),
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_python_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_python_file(path, project_root))
    for path in _iter_js_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_js_file(path, project_root))
    findings.extend(_check_flowise(project_root, scanned))
    return findings, scanned


# ---------------------------------------------------------------------------
# AAK-FLOWISE-001 — Flowise Custom-MCP RCE cluster. CVE-2026-40933 (< 3.1.0,
# CVSS 10.0), CVE-2025-71336 (< 3.0.6 unsandboxed RCE), CVE-2026-56274
# (< 3.1.2 OS command injection / regex bypass), and CVE-2026-58057 (< 3.1.3
# case-sensitive NODE_OPTIONS denylist bypass → `node_options` on Windows →
# NODE_OPTIONS --require RCE) — pin floor is the highest fixed version so
# 3.1.0/3.1.1/3.1.2 are still flagged for the CVE they remain exposed to.
# ---------------------------------------------------------------------------


_FLOWISE_PATCHED_VERSION = (3, 1, 3)


def _admits_vulnerable_flowise(spec: str) -> bool:
    """Does an npm range admit a Flowise release below the 3.1.3 floor?

    The version arm used to skip the operator and read the first number, so
    `"<3.1.3"`, which admits nothing but affected releases, read as 3.1.3 and
    passed, while `">=3.0.0"` and `"^3.0.6"` read their lower bound. A range is
    now judged by every version it admits. A spec that states no version
    (`latest`, a VCS or `workspace:` reference) is reported, as before.
    """
    spans = parse_range(spec, "npm")
    return spans is None or admits(spans, ZERO, _FLOWISE_PATCHED_VERSION)


def _check_flowise(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    vulnerable = False
    pkg = project_root / "package.json"
    if pkg.is_file():
        import json as _json

        rel = str(pkg.relative_to(project_root))
        scanned.add(rel)
        try:
            data = _json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except _json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section) or {}
                if not isinstance(deps, dict):
                    continue
                for name, spec in deps.items():
                    if name not in ("flowise", "flowise-components"):
                        continue
                    if _admits_vulnerable_flowise(str(spec)):
                        findings.append(make_finding(
                            "AAK-FLOWISE-001",
                            rel,
                            f"{name} pinned at {spec!r}, which admits a release below "
                            "3.1.3 — CVE-2026-40933 (CVSS 10.0) is patched in 3.1.0 "
                            "and the rest of the Custom-MCP cluster in 3.1.3.",
                        ))
                        vulnerable = True

    # Whether or not the version was pinned, any flow config with an
    # MCP adapter sink is worth flagging — the same primitive appears
    # in Flowise Enterprise where the version lives outside package.json.
    flow_globs = (".flowise/*.json", "flows/*.json", "flows/**/*.json")
    sink_re_src = r'"(?:customFunction|runCode|executeCommand)"\s*:\s*(?:"|{)'
    import re as _re

    for pattern in flow_globs:
        for path in project_root.glob(pattern):
            if not path.is_file():
                continue
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "mcp" not in text.lower():
                continue
            if _re.search(sink_re_src, text):
                findings.append(make_finding(
                    "AAK-FLOWISE-001",
                    rel,
                    "Flowise flow config declares an MCP adapter with a "
                    "customFunction / runCode / executeCommand sink — "
                    "CVE-2026-40933 shape.",
                    line_number=find_line_number(text, "customFunction"),
                ))
                vulnerable = True

    return findings if vulnerable else findings
