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
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

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
    # AAK-TAINT-001: child_process.exec() / execSync() usage
    (
        re.compile(
            r"\b(?:child_process\s*\.\s*)?(?:exec|execSync|spawn|spawnSync)\s*\(",
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


def _scan_file(
    source: str,
    rel_path: str,
) -> list[Finding]:
    """Scan a single TypeScript file for dangerous sink patterns.

    Only files that contain MCP server or tool-handler patterns are scanned.

    Args:
        source: The raw source text of the file.
        rel_path: The relative file path for reporting.

    Returns:
        A list of findings for dangerous patterns found in the file.
    """
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

    for line_no, line in code:
        for pattern, rule_id, description in _DANGEROUS_SINKS:
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


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan TypeScript/TSX files for taint flows in MCP server implementations.

    Uses regex-based pattern matching (not AST) to detect dangerous sinks
    in files that contain MCP server patterns (createServer, McpServer, @tool).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for suffix in ("*.ts", "*.tsx"):
        for ts_path in project_root.rglob(suffix):
            # Skip excluded directories
            try:
                rel_parts = ts_path.relative_to(project_root).parts
            except ValueError:
                continue
            if any(part in SKIP_DIRS for part in rel_parts):
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

            rel_path = str(ts_path.relative_to(project_root))
            scanned_files.add(rel_path)

            findings.extend(_scan_file(source, rel_path))

    return findings, scanned_files
