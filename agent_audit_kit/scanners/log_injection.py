"""Log-injection scanner for MCP tool handlers (AAK-LOGINJ-001 / CVE-2026-6494).

A `@tool`-decorated function parameter flows into `logger.*` / `logging.*` /
`print` / `sys.stdout.write` / `sys.stderr.write` / `console.log` without
stripping CRLF or ANSI escape sequences. Attackers can forge log entries +
inject escape sequences to social-engineer an operator into running
dangerous commands.

Detection is pragmatic:
- locate functions decorated with anything ending in `tool`
- for each, check the body for the calls `_log_target` reads (logger.*,
  logging.*, print, sys.stdout / sys.stderr) whose args reference a
  parameter name
- fire unless the function has obvious sanitization:
    * `.replace('\\r', '').replace('\\n', '')`, or
    * `.encode('ascii', 'ignore').decode()`, or
    * a call to `re.sub` with a control-character class, or
    * a call to a function whose name contains `sanitize`, `strip_control`
      or `escape_controls`.

References:
- CVE-2026-6494: https://nvd.nist.gov/vuln/detail/CVE-2026-6494
- CWE-117: Improper Output Neutralization for Logs.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    PatternSpans,
    in_skip_dir,
    make_finding,
    parse_python,
    read_text_capped,
)


# Every level method of a stdlib logger. `logger` lacked `exception`, `warn`
# and `fatal`, and `log` also `critical` and `log`, so the `logger.exception`
# in an `except` block, the commonest way a tool logs a failure, was not read.
_LOG_LEVELS = frozenset({
    "debug", "info", "warning", "warn", "error", "critical", "exception", "fatal", "log",
})
_LOGGER_NAMES = frozenset({"logger", "log"})
_STD_STREAMS = frozenset({"sys.stdout", "sys.stderr", "stdout", "stderr"})
_CONSOLE_METHODS = frozenset({"log", "info", "warn", "error"})
# What sanitising code looks like where it is written in the function, one
# pattern per form so that every match of each is found.
_SANITIZERS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"""re\.sub\s*\(\s*r?['"]\\?\\[rn\\x1b\\x7f]""",
        r"""\.replace\s*\(\s*['"]\\r['"]""",
        r"""\.replace\s*\(\s*['"]\\n['"]""",
        r"""\.encode\s*\(\s*['"]ascii['"]\s*,\s*['"]ignore['"]""",
    )
)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
# The name of a sanitising function, read from what a call calls. These words
# were matched as text anywhere in the function, in any case, so a docstring
# saying "Logs the unsanitized note." cleared a raw `print(note)`.
_SANITIZER_NAME_RE = re.compile(r"sanitize|strip_control|escape_controls", re.IGNORECASE)


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _is_tool_decorated(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if name.endswith("tool") or name.endswith(".tool"):
            return True
    return False


def _log_target(call: ast.Call) -> tuple[str, str] | None:
    """The (receiver, method) of a call that writes its arguments to a log or a console, else None.

    The sinks are `print`, a level method of `logger`, `log` or the `logging`
    module, any method of `sys.stdout` or `sys.stderr`, and
    `console.<log|info|warn|error>`. The rule text named `print` and this
    returned a pair for it, but the table it was checked against had none, so
    `print` was never a sink; nor were `sys.stderr` (only `sys.stdout` was
    peeled) or the `logging` module's own functions.

    Each was measured before it was added, on 9,137 Python files from GitHub
    code searches for MCP servers, reading every finding it added. What was
    counted is the rule's condition, a tool parameter reaching the call as a
    raw string, not whether a log line can be forged: on a STDIO server a
    `print` to stdout writes into the protocol stream instead (see the rule
    text). In 82.7% of the 371 `print` findings a tool parameter reaches print
    as a raw string; the `logging` functions, 100 findings, 84.0%;
    `sys.stderr`, 43, 95.3%; the levels `logger` and `log` lacked (`exception`
    above all), 373, 92.8%. A logger held as an attribute (`self.logger.info`)
    is left out: 69 findings, 63.8%, most of the rest an int, a list or a `!r`
    value in a class-based server's debug logging. `print` with `file=` set to
    anything but a standard stream or `None` is not read.
    """
    func = call.func
    if isinstance(func, ast.Name):
        if func.id != "print":
            return None
        # `print(..., file=fh)` writes wherever fh goes. Only the standard
        # streams are a log or, on a STDIO server, the protocol channel:
        # `print(query, file=out)` writing a CSV is neither. `file=None` is
        # print's default, stdout.
        stream = next((kw.value for kw in call.keywords if kw.arg == "file"), None)
        if isinstance(stream, ast.Constant) and stream.value is None:
            stream = None
        if stream is not None and _decorator_name(stream) not in _STD_STREAMS:
            return None
        return ("", "print")
    if not isinstance(func, ast.Attribute):
        return None
    node = func.value
    if isinstance(node, ast.Name):
        if node.id in _LOGGER_NAMES or node.id == "logging":
            return (node.id, func.attr) if func.attr in _LOG_LEVELS else None
        if node.id == "console" and func.attr in _CONSOLE_METHODS:
            return (node.id, func.attr)
        return None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "sys":
        # `sys.stdout.write` → (sys, stdout) after peeling the method.
        return ("sys", node.attr) if node.attr in ("stdout", "stderr") else None
    return None


def _names_a_param(node: ast.AST, param_names: set[str], known: dict[ast.AST, bool]) -> bool:
    """Whether the subtree under `node` names one of `param_names`.

    Each node is decided once, bottom up, and kept in `known` for the tool
    function's other calls. Each log call's arguments were walked whole, so a
    call nested in another's arguments was walked again for every call around
    it: lines of `print(` 190 deep took 14.6 s at 479 KB.
    """
    stack: list[tuple[ast.AST, bool]] = [(node, False)]
    while stack:
        current, children_known = stack.pop()
        if current in known:
            continue
        if children_known:
            known[current] = (isinstance(current, ast.Name) and current.id in param_names) or any(
                known[child] for child in ast.iter_child_nodes(current)
            )
        else:
            stack.append((current, True))
            stack.extend((child, False) for child in ast.iter_child_nodes(current) if child not in known)
    return known[node]


def _callee_name(func: ast.expr) -> str:
    """The last name of what a call calls: `sanitize` for `utils.sanitize(...)`."""
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _own_calls(
    func: ast.FunctionDef | ast.AsyncFunctionDef, nested_tools: list[ast.FunctionDef | ast.AsyncFunctionDef]
) -> list[ast.Call]:
    """The calls a tool function reads: those in its body and in the functions
    nested in it, in the order `ast.walk` meets them, up to a nested tool
    function, which reads its own and is added to `nested_tools`.

    Every tool function walked its whole subtree, nested tool functions
    included, so a call inside 99 nested tools was read 99 times and reported
    once for each tool around it: 68.5 s at 494 KB, and 99 findings for one
    `print`. Each call is read once now, for the innermost tool function
    around it.
    """
    calls: list[ast.Call] = []
    queue: deque[ast.AST] = deque(ast.iter_child_nodes(func))
    while queue:
        node = queue.popleft()
        if isinstance(node, _FUNCTIONS) and _is_tool_decorated(node):
            nested_tools.append(node)
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        queue.extend(ast.iter_child_nodes(node))
    return calls


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = read_text_capped(path, 512_000, errors="replace")
    except OSError:
        return []
    try:
        tree = parse_python(text, path)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))
    # A function's source is its lines joined with newlines; the file is split
    # once. Each tool function used to split it again, so 6,000 of them took
    # 3.1 s, growing with the square of their number.
    lines = text.splitlines()
    joined = "\n".join(lines)
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)
    tools = [node for node in ast.walk(tree) if isinstance(node, _FUNCTIONS) and _is_tool_decorated(node)]
    own_calls: dict[ast.AST, list[ast.Call]] = {}
    nested: dict[ast.AST, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for node in tools:
        nested[node] = []
        own_calls[node] = _own_calls(node, nested[node])
    # A tool function calls a sanitiser when it, or a function nested in it, does
    # by name: `ast.walk` meets a nested tool after the one around it, so the
    # nested ones are settled first walking back.
    calls_sanitiser: dict[ast.AST, bool] = {}
    for node in reversed(tools):
        calls_sanitiser[node] = any(
            _SANITIZER_NAME_RE.search(_callee_name(call.func)) for call in own_calls[node]
        ) or any(calls_sanitiser[inner] for inner in nested[node])
    # Sanitising code is found once per file, and a tool function's source holds
    # it as a search of the function's lines alone would find it.
    sanitising_code = PatternSpans(_SANITIZERS, joined)
    for node in tools:
        params = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
        if not params:
            continue
        first = min(node.lineno - 1, len(lines))
        last = min(node.end_lineno or node.lineno, len(lines))
        start = line_starts[first]
        if calls_sanitiser[node] or sanitising_code.within(start, max(start, line_starts[last] - 1)):
            continue
        known: dict[ast.AST, bool] = {}
        for call in own_calls[node]:
            target = _log_target(call)
            if target is None:
                continue
            for arg in list(call.args) + [kw.value for kw in call.keywords]:
                if _names_a_param(arg, params, known):
                    findings.append(make_finding(
                        "AAK-LOGINJ-001",
                        rel,
                        f"Tool function {node.name!r} logs caller-controlled parameter "
                        f"via {'.'.join(filter(None, target))}(...) without CRLF/ANSI sanitization",
                        line_number=call.lineno,
                    ))
                    break
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in project_root.rglob("*.py"):
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
