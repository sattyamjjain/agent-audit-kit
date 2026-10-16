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

import os
import re
from collections.abc import Iterator
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, make_finding

# ---- Patterns that indicate an MCP server implementation ----
# `@tool` sits outside the leading `\b` here and in `_TOOL_HANDLER_RE`: a
# boundary before `@` needs a word character in front, so inside it a `@tool`
# decorator at the start of a line never matched, and a file whose only marker
# it was went unread.
_MCP_SERVER_RE = re.compile(
    r"(?:\b(?:createServer|McpServer)|@tool)\b",
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
            r"(?<![\w$.])child_process\s*\??\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(",
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
    r"(?:\b(?:handleToolCall|CallToolRequestSchema|setRequestHandler"
    r"|server\s*\.\s*tool)|@tool)\b"
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
#
# The handler gate took a bare `setRequestHandler` or `CallToolRequestSchema`
# as well, but a client registers handlers with the same method (an
# elicitation handler that opens the URL a server sent got a CRITICAL) and a
# script imports the schema to build a request. It takes the registration
# itself now, `setRequestHandler(CallToolRequestSchema, ...)`. The six files of
# the second sample with an AAK-MCP-TOOL-ARG-OSCMD-001 finding all pass it,
# five through that registration and one through `server.tool`.
_JS_MCP_SERVER_RE = re.compile(
    r"""(?:\bfrom\s*|\b(?:require|import)\s*\(\s*)[`'"][^`'"\n]*@modelcontextprotocol/sdk/(?:dist/(?:cjs|esm)/)?server\b"""
    r"|\bserver\s*\.\s*(?:tool|registerTool)\s*\("
    r"|setRequestHandler\s*\(\s*CallToolRequestSchema"
)
_JS_TOOL_HANDLER_RE = re.compile(
    r"\b(?:handleToolCall|server\s*\.\s*tool)\b|@tool\b"
    r"|\bsetRequestHandler\s*\(\s*CallToolRequestSchema\b"
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
# The same, or the same in parentheses: `(await import('child_process'))`.
_CP_LOAD_P = rf"(?:\(\s*{_CP_LOAD}\s*\)|{_CP_LOAD})"
_CP_METHODS = frozenset({"exec", "execSync", "spawn", "spawnSync"})
# An import or destructuring list, its body bounded. `[^}]*` read to the end of
# the file from every unclosed `let {` or `import a, {`, so 80,000 of them
# (0.48 MB) took 183 s and a 0.24 MB server.ts 34 s. A brace ends the list, and
# no real one comes near 2,000 characters.
_CP_LIST = r"\{([^{}]{0,2000})\}"
# A dynamic import's promise and the callback it hands the module to:
# `import('child_process').then(cp => ...)`, `.then((cp) => ...)`,
# `.then(async function (cp) {...})`. Every `\s*` follows a token that must be
# there. With `function\b\s*` and an optional name before a `\s*` of its own,
# and the alias pattern's `\(?\s*` after that, two or three `\s*` stood side by
# side wherever the optional tokens were absent, and a match failing after a run
# of blanks split the run every way: 160,000 blanks took 224 s, and
# `.then(function` followed by 4,000 blanks, a 4 KB file, 177 s.
_CP_THEN = rf"\bimport\s*\(\s*{_CP_MODULE}\s*\)\s*\.\s*then\s*\(\s*(?:async\b\s*)?"
# A function callback's head, up to and with the `(` of its parameter list.
# The `(` was optional after an optional name, so a callback naming no parameter
# had its name cut short and its last letter read as one:
# `.then(function load() {...})` bound `d`.
_CP_FUNCTION_HEAD = r"(?:function\b\s*(?:[A-Za-z_$][\w$]*\s*)?)?\(\s*"
# A name bound to the module. Any assignment of the module to a name binds it
# (`require(...).exec` is a member, below): `const cp = require('child_process')`,
# a second declarator (`const fs = require('fs'), cp = require(...)`), a name
# declared first and assigned later (`let cp; cp = require(...)`), `await
# import(...)` in parentheses or not, and TypeScript's `import cp = require(...)`.
# Only a `const`, `let` or `var` declaration used to count. `==` and `=>` are not
# assignments, and a property (`obj.cp = ...`) binds no name. Then `import cp
# from ...`, `import * as cp from ...` and the parameter of a `.then` callback.
_CP_ALIAS_RE = re.compile(
    rf"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*{_CP_LOAD_P}(?!\s*\??\.)"
    rf"|\bimport\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{{[^{{}}]{{0,2000}}\}}\s*)?from\s*{_CP_MODULE}"
    rf"|{_CP_THEN}(?:{_CP_FUNCTION_HEAD})?(?!(?:async|function)\b)([A-Za-z_$][\w$]*)"
)
# `this.cp = require('child_process')`, called as `this.cp.exec(...)`. Another
# object's property is not followed.
_CP_THIS_ALIAS_RE = re.compile(
    rf"\bthis\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?![=>])\s*{_CP_LOAD_P}(?!\s*\??\.)"
)
# Names imported from it: `const { exec, spawn: run } = require(...)` or
# `= await import(...)`, `import { execSync as sh } from ...`,
# `import cp, { exec } from ...`, and `.then(({ exec }) => ...)`. A `default`
# item binds the module itself: `.then(({ default: cp }) => ...)`.
_CP_NAMED_RE = re.compile(
    rf"\b(?:const|let|var)\s*{_CP_LIST}\s*=\s*{_CP_LOAD_P}"
    rf"|\bimport\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?{_CP_LIST}\s*from\s*{_CP_MODULE}"
    rf"|{_CP_THEN}{_CP_FUNCTION_HEAD}{_CP_LIST}"
)
# A list destructured from a plain name, `const { exec } = cp`, read once the
# names bound to the module are known.
_CP_DESTRUCTURE_RE = re.compile(
    rf"\b(?:const|let|var)\s*{_CP_LIST}\s*=\s*([A-Za-z_$][\w$]*)(?![\w$])(?!\s*(?:\??\.|\(|\[))"
)
_CP_MEMBER_RE = re.compile(
    rf"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*{_CP_LOAD_P}"
    r"\s*\??\.\s*(?:exec|execSync|spawn|spawnSync)\b"
)
# One item of such a list, matched stripped (`exec`, `spawn: run`,
# `execSync as sh`): with a `\s*` at either end as well as around the separator,
# two adjacent ones split a run of blanks every way.
_CP_ITEM_RE = re.compile(r"([A-Za-z_$][\w$]*)(?:\s*(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?")
# A call: a bare name, or a method on a name through `.` or `?.`.
_CALL_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\??\.\s*([A-Za-z_$][\w$]*)\s*)?\(")
# A method called on `this.<name>`.
_THIS_CALL_RE = re.compile(r"\bthis\s*\.\s*([A-Za-z_$][\w$]*)\s*\??\.\s*([A-Za-z_$][\w$]*)\s*\(")
# A call on the module itself, `require('child_process').exec(...)`, or on the
# module in parentheses, `(await import('child_process')).exec(...)`.
_CP_REQUIRE_CALL_RE = re.compile(
    rf"(?:\brequire\s*\(\s*{_CP_MODULE}\s*\)|\(\s*{_CP_LOAD}\s*\))"
    r"\s*\??\.\s*(?:exec|execSync|spawn|spawnSync)\s*\("
)
# A call split across two lines at its dot: the receiver ends one line and
# `.exec(cmd)` starts the next (the layout formatters give a long chain), or
# `cp.` ends one and `exec(cmd)` starts the next.
_LEADING_DOT_CALL_RE = re.compile(r"\s*\??\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(")
_LEADING_CALL_RE = re.compile(r"\s*(?:exec|execSync|spawn|spawnSync)\s*\(")
_TRAILING_RECEIVER_RE = re.compile(
    rf"(?:(?<![\w$.])([A-Za-z_$][\w$]*)|\bthis\s*\.\s*([A-Za-z_$][\w$]*)"
    rf"|\brequire\s*\(\s*{_CP_MODULE}\s*\))\Z"
)


class _ChildProcessSink:
    """AAK-TAINT-001's sink in one file: `exec`, `execSync`, `spawn` or `spawnSync`
    called on `child_process`, on a name the file binds to that module (or on
    `this.<name>` it assigns the module to), on `require('child_process')`
    itself, or under a name imported from it.

    The pattern was any `exec(`, `.exec(` or `spawn(`, so a regular expression's
    `exec` (`/^\\/files\\/(.+)$/.exec(req.url)`) or a database's read as a
    child process, CRITICAL. A wrapper such as `promisify(exec)`, execa or
    cross-spawn, and process APIs outside child_process (`Bun.spawn`, node-pty,
    an SSH client's `exec`), are not followed.

    Each call's names are looked up in a set. They used to be joined into one
    alternation that every position of every line tried in turn, so 10,000
    bound names took 37 times as long as 1,000.
    """

    def __init__(self, receivers: frozenset[str], names: frozenset[str], this_receivers: frozenset[str]) -> None:
        self.receivers = receivers
        self.names = names
        self.this_receivers = this_receivers

    def search(self, line: str) -> bool:
        if _CP_REQUIRE_CALL_RE.search(line):
            return True
        for m in _CALL_RE.finditer(line):
            name, method = m.group(1), m.group(2)
            if method is None:
                if name in self.names:
                    return True
            elif method in _CP_METHODS and name in self.receivers:
                return True
        if self.this_receivers:
            for m in _THIS_CALL_RE.finditer(line):
                if m.group(2) in _CP_METHODS and m.group(1) in self.this_receivers:
                    return True
        return False

    def continues(self, before: str, line: str) -> bool:
        """Whether `line` finishes a call the code line `before` began on a receiver:
        `cp` then `.exec(cmd)`, or `cp.` then `exec(cmd)`."""
        tail = before.rstrip()
        if tail.endswith("."):
            if not _LEADING_CALL_RE.match(line):
                return False
            tail = tail[:-1].rstrip("?").rstrip()
        elif not _LEADING_DOT_CALL_RE.match(line):
            return False
        m = _TRAILING_RECEIVER_RE.search(tail)
        if m is None:
            return False
        if m.group(1) is not None:
            return m.group(1) in self.receivers
        if m.group(2) is not None:
            return m.group(2) in self.this_receivers
        return True


def _child_process_sink(source: str) -> _ChildProcessSink:
    """The names `source` binds to child_process, and to its exec and spawn calls."""
    receivers = {"child_process"}
    names: set[str] = set()

    def take(body: str) -> None:
        for item in body.split(","):
            parts = _CP_ITEM_RE.fullmatch(item.strip())
            if parts is None:
                continue
            name, alias = parts.group(1), parts.group(2)
            if name in _CP_METHODS:
                names.add(alias or name)
            elif name == "default" and alias:
                receivers.add(alias)

    for m in _CP_ALIAS_RE.finditer(source):
        receivers.add(next(g for g in m.groups() if g is not None))
    for m in _CP_NAMED_RE.finditer(source):
        take(next(g for g in m.groups() if g is not None))
    names.update(m.group(1) for m in _CP_MEMBER_RE.finditer(source))
    for m in _CP_DESTRUCTURE_RE.finditer(source):
        if m.group(2) in receivers:
            take(m.group(1))
    this_receivers = frozenset(m.group(1) for m in _CP_THIS_ALIAS_RE.finditer(source))
    return _ChildProcessSink(frozenset(receivers), frozenset(names), this_receivers)


def _is_bundle(name: str, source: str) -> bool:
    """A minified file or a bundler's output, which no one wrote and no finding
    in it can point anyone at. `dist/`, `build/` and `out/` are skipped already,
    but `public/js/server.bundle.min.js` was read, and its one line gave
    AAK-TAINT-001 and -002. A file is a bundle when its name says so
    (`*.min.js` and the like), or when it is over 10 KB and either its median
    non-blank line (the longer middle one, for an even count) is over 500
    characters long or most of it is minified code: lines over 5,000
    characters, in which `(` and `;` make up at least 1%.

    The check took the mean line length, so one inlined 150 KB base64 image in
    a 190-line hand-written server averaged about 800 characters a line, and the
    file lost its `exec(cmd)` finding. The median alone would miss a bundle whose
    minifier kept the newlines inside template literals: 77 lines, median 40
    characters, 98% of its 340 KB in seven lines of code. In the 4,971 files of
    the JavaScript measurement, long lines of code ran 2.5% to 6% `(` and `;`,
    and long lines of data at most 0.2%.
    """
    if ".min." in name.lower():
        return True
    if len(source) <= 10_000:
        return False
    lines = [line for line in source.splitlines() if line.strip()]
    lengths = sorted(map(len, lines))
    if lengths and lengths[len(lengths) // 2] > 500:
        return True
    long_lines = [line for line in lines if len(line) > 5_000]
    long_size = sum(map(len, long_lines))
    if long_size * 2 <= len(source):
        return False
    punctuation = sum(line.count("(") + line.count(";") for line in long_lines)
    return punctuation * 100 >= long_size


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
    sinks: list[tuple[re.Pattern[str] | _ChildProcessSink, str, str]] = [
        (cp_sink if rule_id == "AAK-TAINT-001" else pattern, rule_id, description)
        for pattern, rule_id, description in _DANGEROUS_SINKS
        if not (is_js and rule_id in _TS_ONLY_RULES)
    ]
    # Lines that finish a child_process call the code line before them began.
    continued: set[int] = set()
    before = ""
    for line_no, line in code:
        if before and cp_sink.continues(before, line):
            continued.add(line_no)
        if line.strip():
            before = line
    for line_no, line in code:
        for pattern, rule_id, description in sinks:
            if rule_id == _SUPERSEDED_RULE and line_no in owned:
                continue
            if pattern.search(line) or (pattern is cp_sink and line_no in continued):
                findings.append(make_finding(
                    rule_id,
                    rel_path,
                    f"{description} (line {line_no}): {line.strip()[:120]}",
                    line_no,
                ))

    return findings


# TypeScript and JavaScript, as the rules this module emits describe. Only the
# first two were read, so a JavaScript MCP server had no file read at all.
# `.mts` and `.cts`, TypeScript's module files, are TypeScript to the gates.
_SOURCE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")


def _source_files(project_root: Path) -> Iterator[Path]:
    """Every file under the root whose name ends in one of the suffixes, in one
    walk that does not enter a skipped directory. One `rglob` per suffix walked
    the tree eight times, into `node_modules` too (2.55 s for 50,000 files;
    main, with two suffixes, 0.82 s)."""
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith(_SOURCE_SUFFIXES):
                yield Path(dirpath) / name


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

    for ts_path in _source_files(project_root):
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
