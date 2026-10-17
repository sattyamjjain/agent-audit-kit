"""TypeScript / JavaScript dangerous-sink pattern scanner.

This is a **regex pattern scan**, not a real taint analyzer. It looks for
dangerous sinks (eval, child_process.exec, fs.writeFile, SQL template
literals, etc.) in files that appear to implement an MCP server. It does
NOT track flow from user-controlled sources to those sinks.

The module used to be named `typescript_scan.py` and documented as
"TypeScript taint analysis". That overstated what the scanner does; a
real taint tracer would walk the TypeScript AST (via tree-sitter or the
`tsc` compiler API) and model source/sink reachability. A true AST-based
analyzer may ship in a later release in a separate module.

For the Python taint analyzer — which IS AST-based — see
`scanners/taint_analysis.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, in_skip_dir

# ---- Patterns that indicate an MCP server implementation ----
_MCP_SERVER_RE = re.compile(
    r"\b(createServer|McpServer|@tool)\b",
    re.IGNORECASE,
)

# ---- Dangerous sink patterns mapped to AAK-TAINT rules ----
#
# Each entry: (compiled regex, rule_id, description)
# These are pattern matches on file contents. A positive finding means
# "a dangerous sink was called somewhere in a file that looks like an MCP
# server" — NOT "user input reaches this sink".

_DANGEROUS_SINKS: list[tuple[re.Pattern[str], str, str]] = [
    # AAK-TAINT-002: eval() usage
    (
        re.compile(r"\beval\s*\("),
        "AAK-TAINT-002",
        "eval() call detected in MCP server file",
    ),
    # AAK-TAINT-001: child_process exec/spawn. This is the module-qualified
    # call; `_scan_file` swaps in `_child_process_sink`, which adds the names
    # the file binds to the module or imports from it.
    (
        re.compile(
            r"(?<![\w$.])child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(",
        ),
        "AAK-TAINT-001",
        "child_process exec/spawn call detected in MCP server file",
    ),
    # AAK-TAINT-003: fs.writeFileSync / fs.writeFile with potential user input
    (
        re.compile(
            r"\b(?:fs\s*\.\s*)?(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\(",
        ),
        "AAK-TAINT-003",
        "fs write call detected in MCP server file",
    ),
    # AAK-TAINT-005: raw / interpolated SQL execution sink.
    #
    # Parity with the Python taint engine (cursor/connection/session.execute)
    # and the Rust scanner (sql!/query! with format!). The OX Security MCP
    # disclosure class includes Node/TS MCP servers with SQL injection
    # (e.g. astro-mcp-server, CVE-2026-7591), so the TS/JS scanner must
    # flag the same shape: SQL built by string interpolation/concatenation
    # reaching a query/execute call, plus the explicitly-unsafe raw APIs.
    #
    # Tight by design to avoid flagging parameterized queries
    # (`db.query("SELECT ... WHERE id = $1", [id])`), which use placeholder
    # args, not template interpolation. Matches:
    #   - Prisma  $queryRawUnsafe(...) / $executeRawUnsafe(...)
    #   - knex    .raw(`...${...}...`)  (raw SQL with interpolation)
    #   - any     .query(`...${...}`) / .execute(`...${...}`)  (interpolated)
    #   - any     .query("..." + x) / .execute('...' + x)      (concatenated)
    (
        re.compile(
            # Prisma explicitly-unsafe raw APIs
            r"\$(?:query|execute)RawUnsafe\s*\("
            # knex / driver .raw() with an interpolated template literal
            r"|\.\s*raw\s*\(\s*`[^`]*\$\{"
            # .query()/.execute() with an interpolated template literal
            r"|\.\s*(?:query|execute)\s*\(\s*`[^`]*\$\{"
            # .query()/.execute() with string concatenation
            r"|\.\s*(?:query|execute)\s*\(\s*['\"][^'\"]*['\"]\s*\+"
        ),
        "AAK-TAINT-005",
        "raw/interpolated SQL execution sink detected in MCP server file",
    ),
]


# ---- AAK-MCP-TOOL-ARG-OSCMD-001 (CVE-2026-78430) ---------------------------
#
# Narrower than AAK-TAINT-001 above, deliberately. That rule fires on ANY
# child_process call in a file that mentions an MCP server, which says nothing
# about how the command was built -- `execFile(bin, argv)` trips it just as
# readily as `exec(`${bin} ${arg}`)`. Two further conditions have to hold here:
#
#   1. the file handles tool CALLS, not merely defines a server, and
#   2. the command is COMPOSED at the call site -- a template literal carrying
#      an interpolation, or a string concatenation -- or the call explicitly
#      opts into a shell with `shell: true`.
#
# `execFile('ffmpeg', ['-i', input, '-f', format])` satisfies neither and stays
# quiet. That is the negative fixture, and it is exactly the shape the rule's
# remediation asks for, so the rule going quiet on it is the point rather than
# a coverage gap.
#
# Still a pattern scan, not taint: it proves the command was composed at a
# process boundary inside a tool handler, not that the interpolated value
# reached it from the arguments object. The rule text says so.

_TOOL_HANDLER_RE = re.compile(
    r"\b(?:handleToolCall|CallToolRequestSchema|setRequestHandler"
    r"|server\s*\.\s*tool|@tool)\b"
    r"|['\"]tools/call['\"]"
)

# exec()/execSync() whose FIRST argument is built on the spot.
_EXEC_COMPOSED_RE = re.compile(
    r"\b(?:child_process\s*\.\s*)?exec(?:Sync)?\s*\(\s*"
    r"(?:`[^`]*\$\{"                      # exec(`ffmpeg -f ${format}`)
    r"|['\"][^'\"]*['\"]\s*\+"            # exec("ffmpeg -f " + format)
    r"|[A-Za-z_$][\w$]*\s*\+)"            # exec(base + format)
)

# Any process API that opts into a shell. Split in two so the `shell: true`
# may sit on a later line of the same call without the call itself drifting:
# matching them jointly over a window would also fire on the line ABOVE the
# call, whose window happens to contain both tokens.
_PROC_CALL_OPEN_RE = re.compile(
    r"\b(?:child_process\s*\.\s*)?"
    r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("
)
_SHELL_TRUE_RE = re.compile(r"\bshell\s*:\s*true\b")

_SHELL_OPT_LOOKAHEAD_LINES = 2

_ARG_OSCMD_RULE = "AAK-MCP-TOOL-ARG-OSCMD-001"
# The generic sink rule this one supersedes when both would fire on one line.
_SUPERSEDED_RULE = "AAK-TAINT-001"


def _is_mcp_server_file(source: str) -> bool:
    """Return True if the file contains MCP server patterns."""
    return bool(_MCP_SERVER_RE.search(source))


def _is_tool_handler_file(source: str) -> bool:
    """Return True if the file dispatches tool CALLS, not just defines a server.

    A handler module (``src/tools/handlers.ts`` in CVE-2026-78430) need not
    mention ``McpServer`` at all, so this is checked alongside
    ``_is_mcp_server_file`` rather than after it.
    """
    return bool(_TOOL_HANDLER_RE.search(source))


def _composes_shell_command(line: str, window: str) -> bool:
    """Whether this line hands a shell-composed command to a process API."""
    if _EXEC_COMPOSED_RE.search(line):
        return True
    return bool(_PROC_CALL_OPEN_RE.search(line) and _SHELL_TRUE_RE.search(window))


# JavaScript is gated on an MCP server itself. When `.js` began to be read, the
# gate above put ordinary Node files in scope: its `createServer` is also Node's
# `http.createServer`, so a static dev server, a test helper and an Electron main
# process all read as MCP servers. Naming the SDK was not enough either: on
# 2,016 JavaScript files from code search, a gate of `McpServer`,
# `@modelcontextprotocol/sdk`, `server.tool(` or `CallToolRequestSchema` gave
# 500 findings, and a third were not in a server or tool handler (MCP clients,
# hosts with a `class McpServer` of their own, build, eval and test scripts).
# So a JavaScript file is a server when it imports the SDK's server modules,
# registers a tool, or handles `CallToolRequestSchema`; and it handles tool
# calls when it names a handler marker other than `'tools/call'`, the method a
# client sends. Fixed before a second sample of 1,428 files was drawn, these
# gates gave 337 findings there, 86.1% in a server or handler and naming their
# sink (87.6% of 330 without AAK-TAINT-002, below). TypeScript keeps the gates
# above, which neither sample measured.
_JS_MCP_SERVER_RE = re.compile(
    r"""(?:\bfrom\s*|\b(?:require|import)\s*\(\s*)[`'"][^`'"\n]*@modelcontextprotocol/sdk/(?:dist/(?:cjs|esm)/)?server\b"""
    r"|\bserver\s*\.\s*(?:tool|registerTool)\s*\("
    r"|setRequestHandler\s*\(\s*CallToolRequestSchema"
)
_JS_TOOL_HANDLER_RE = re.compile(
    r"\b(?:handleToolCall|CallToolRequestSchema|setRequestHandler|server\s*\.\s*tool)\b|@tool\b"
)
# AAK-TAINT-002 stays TypeScript-only. In JavaScript MCP servers from code
# search, 1 of 12 `eval(` matches was an eval call; the rest sat in strings or
# regular expressions, or named a method `eval` (`async eval({ js })`,
# `pw.eval(...)`). The other rules cleared 80% there.
_TS_ONLY_RULES = frozenset({"AAK-TAINT-002"})
_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs"})

_CP_MODULE = r"""['"](?:node:)?child_process['"]"""
# `require('child_process')` or a dynamic `await import('child_process')`.
_CP_LOAD = rf"(?:require|(?:await\s+)?import)\s*\(\s*{_CP_MODULE}\s*\)"
_CP_METHODS = ("exec", "execSync", "spawn", "spawnSync")
# A name bound to the module: `const cp = require('child_process')` (not
# `require(...).exec`), `const cp = await import(...)`, `import cp from ...`,
# `import * as cp from ...`.
_CP_ALIAS_RE = re.compile(
    rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*{_CP_LOAD}(?!\s*\.)"
    rf"|\bimport\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{{[^}}]*\}}\s*)?from\s*{_CP_MODULE}"
)
# Names imported from it: `const { exec, spawn: run } = require(...)` or
# `= await import(...)`, `import { execSync as sh } from ...`,
# `import cp, { exec } from ...`.
_CP_NAMED_RE = re.compile(
    rf"\b(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*{_CP_LOAD}"
    rf"|\bimport\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?\{{([^}}]*)\}}\s*from\s*{_CP_MODULE}"
)
_CP_MEMBER_RE = re.compile(
    rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*{_CP_LOAD}"
    r"\s*\.\s*(?:exec|execSync|spawn|spawnSync)\b"
)
_IMPORT_ITEM_RE = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*(?:(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?\s*")


def _child_process_sink(source: str) -> re.Pattern[str]:
    """AAK-TAINT-001's sink in this file: `exec`, `execSync`, `spawn` or `spawnSync`
    called on `child_process`, on a name the file binds to that module, on
    `require('child_process')` itself, or under a name imported from it.

    The pattern was any `exec(`, `.exec(` or `spawn(`, so a regular expression's
    `exec` (`/^\\/files\\/(.+)$/.exec(req.url)`) or a database's read as a
    child process, CRITICAL. A wrapper such as `promisify(exec)`, execa or
    cross-spawn, and process APIs outside child_process (`Bun.spawn`, node-pty,
    an SSH client's `exec`), are not followed.
    """
    receivers = {"child_process"}
    names: set[str] = set()
    for m in _CP_ALIAS_RE.finditer(source):
        receivers.add(m.group(1) or m.group(2))
    for m in _CP_NAMED_RE.finditer(source):
        for item in (m.group(1) or m.group(2)).split(","):
            parts = _IMPORT_ITEM_RE.fullmatch(item)
            if parts and parts.group(1) in _CP_METHODS:
                names.add(parts.group(2) or parts.group(1))
    names.update(m.group(1) for m in _CP_MEMBER_RE.finditer(source))
    methods = "|".join(_CP_METHODS)
    alternatives = [
        rf"(?<![\w$.])(?:{'|'.join(map(re.escape, sorted(receivers)))})\s*\.\s*(?:{methods})\s*\(",
        rf"\brequire\s*\(\s*{_CP_MODULE}\s*\)\s*\.\s*(?:{methods})\s*\(",
    ]
    if names:
        alternatives.append(rf"(?<![\w$.])(?:{'|'.join(map(re.escape, sorted(names)))})\s*\(")
    return re.compile("|".join(alternatives))


def _is_bundle(name: str, source: str) -> bool:
    """A minified file or a bundler's output, which no one wrote and no finding
    in it can point anyone at: `*.min.js` and the like, or more than 10 KB with
    lines over 500 characters long on average. `dist/`, `build/` and `out/` are
    skipped already, but `public/js/server.bundle.min.js` was read, and its one
    line gave AAK-TAINT-001 and -002."""
    if ".min." in name.lower():
        return True
    return len(source) > 10_000 and len(source) > 500 * (source.count("\n") + 1)


def _scan_file(
    source: str,
    rel_path: str,
) -> list[Finding]:
    """Scan a single TypeScript or JavaScript file for dangerous sink patterns.

    Only files that contain MCP server or tool-handler patterns are scanned,
    with the JavaScript gates for a JavaScript file.

    Args:
        source: The raw source text of the file.
        rel_path: The relative file path for reporting.

    Returns:
        A list of findings for dangerous patterns found in the file.
    """
    is_js = Path(rel_path).suffix.lower() in _JS_SUFFIXES
    if is_js:
        is_server = bool(_JS_MCP_SERVER_RE.search(source))
        is_handler = bool(_JS_TOOL_HANDLER_RE.search(source))
    else:
        is_server = _is_mcp_server_file(source)
        is_handler = _is_tool_handler_file(source)
    if not (is_server or is_handler):
        return []

    findings: list[Finding] = []
    lines = source.splitlines()

    def _code_lines() -> list[tuple[int, str]]:
        out = []
        for line_no, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            out.append((line_no, line))
        return out

    code = _code_lines()

    # Pass 1 -- the specific rule, so pass 2 knows which lines it already owns.
    owned: set[int] = set()
    if is_handler:
        for line_no, line in code:
            window = "\n".join(lines[line_no - 1: line_no + _SHELL_OPT_LOOKAHEAD_LINES])
            if _composes_shell_command(line, window):
                owned.add(line_no)
                findings.append(make_finding(
                    _ARG_OSCMD_RULE,
                    rel_path,
                    "tool handler composes a shell command at the process "
                    f"boundary (line {line_no}): {line.strip()[:120]}",
                    line_no,
                ))

    # Pass 2 -- the generic sinks. AAK-TAINT-001 is dropped where the specific
    # rule already reported: two findings on one line is the same defect twice.
    if not is_server:
        return findings

    cp_sink = _child_process_sink(source)
    sinks = [
        (cp_sink if rule_id == "AAK-TAINT-001" else pattern, rule_id, description)
        for pattern, rule_id, description in _DANGEROUS_SINKS
        if not (is_js and rule_id in _TS_ONLY_RULES)
    ]
    for line_no, line in code:
        for pattern, rule_id, description in sinks:
            if rule_id == _SUPERSEDED_RULE and line_no in owned:
                continue
            if pattern.search(line):
                findings.append(make_finding(
                    rule_id,
                    rel_path,
                    f"{description} (line {line_no}): {line.strip()[:120]}",
                    line_no,
                ))

    return findings


# TypeScript and JavaScript, as the rules this module emits describe. Only the
# first two were globbed, so a JavaScript MCP server had no file read at all.
_SOURCE_GLOBS = ("*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan TypeScript and JavaScript files for dangerous sinks in MCP server implementations.

    Uses regex-based pattern matching (not AST) to detect dangerous sinks
    in files that contain MCP server patterns (createServer, McpServer, @tool
    in TypeScript; the SDK's server modules, a registered tool or a
    CallToolRequestSchema handler in JavaScript). Minified JavaScript and
    one-line bundles are skipped.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for suffix in _SOURCE_GLOBS:
        for ts_path in project_root.rglob(suffix):
            # Skip excluded directories
            if in_skip_dir(ts_path, project_root):
                continue
            if not ts_path.is_file():
                continue

            # Skip large files (> 1 MB)
            try:
                if ts_path.stat().st_size > 1_000_000:
                    continue
                source = ts_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if ts_path.suffix.lower() in _JS_SUFFIXES and _is_bundle(ts_path.name, source):
                continue

            rel_path = str(ts_path.relative_to(project_root))
            scanned_files.add(rel_path)

            findings.extend(_scan_file(source, rel_path))

    return findings, scanned_files
