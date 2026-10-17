"""AAK-MCP-STDIO-CMD-INJ-001..004 — config-to-spawn taint for the OX class.

The April 2026 OX MCP advisory hub aggregated 8 CVEs (CVE-2026-30615,
30617, 30623, 22252, 22688, 33224, 40933, 6980) under a single
architectural class: the upstream MCP SDK exposes a
`StdioServerParameters(command=, args=)` API that *executes whatever
you pass*. Downstream agents that build the params from
network-controlled input (a request body, a fetched marketplace
manifest, an env var fed by an HTTP webhook) inherit the bug.

This scanner is the SDK-named-API counterpart to the broader
AAK-STDIO-001 sink-pattern detector. Where AAK-STDIO-001 fires on any
`subprocess.run(shell=True, ..., tainted)` shape, this scanner fires
*specifically* on `StdioServerParameters(command=tainted)` (Python) and on a
hand-rolled Python launcher that spawns `shlex.split()` of a stored MCP
server's command with no executable allowlist (CVE-2026-93965),
`new StdioClientTransport({command, args})` (TS),
`StdioServerParameters.Builder().command(tainted)` (Java), and
`tokio::process::Command::new(tainted)` adjacent to MCP imports
(Rust). Cross-link the two from descriptions; do not collapse.

Rules emitted:

- AAK-MCP-STDIO-CMD-INJ-001 — language=python (AST)
- AAK-MCP-STDIO-CMD-INJ-002 — language=typescript (regex+AST hybrid)
- AAK-MCP-STDIO-CMD-INJ-003 — language=java (regex)
- AAK-MCP-STDIO-CMD-INJ-004 — language=rust (regex; ~10% FP rate on
  heavy macro use). No tree-sitter-rust grammar, and none is pending:
  #22 closed 2026-08-15 having shipped a TypeScript slice only.
"""

from __future__ import annotations

import ast
import re
import sys
from bisect import bisect_left, bisect_right
from collections import deque
from pathlib import Path
from typing import Iterator

from agent_audit_kit.models import Finding

from . import _ts_stdio_taint
from ._helpers import (
    SOURCE_MAX_BYTES,
    _JS_IDENT_CHARS,
    _JS_OPERAND,
    _js_regex_allowed,
    _js_skip_regex,
    blank_js_comments,
    in_skip_dir,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    unparse,
)


# ---------------------------------------------------------------------------
# Python — AAK-MCP-STDIO-CMD-INJ-001
# ---------------------------------------------------------------------------


_PY_TAINT_MODULES_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|form|args|data|values|headers|files)\b
      | \bflask\.request\.\w+\b
      | \bfastapi\.Request\.\w+
      | \bstarlette\.requests\.Request\.\w+
      | \brequests\.(?:get|post|put|delete)\([^)]*\)\s*\.(?:json|text)\(\)
      | \bhttpx\.(?:get|post|put|delete)\([^)]*\)\s*\.(?:json|text)\(\)
      | \burllib\.request\.urlopen\(
      | \bos\.environ\b
      | \bjson\.loads\b
      | \byaml\.safe_load\b
      | \byaml\.load\b
    )
    """,
    re.VERBOSE,
)


def _attr_chain(node: ast.AST) -> str:
    """Return a dotted form of an Attribute / Name chain ('a.b.c')."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return ".".join(reversed(parts))


def _under_calls(call: ast.Call, below: dict[int, ast.AST]) -> ast.AST:
    """The first node under `call`, following each call's `func`, that is not a
    call: `f` for `f()()()`. `below` keeps it for every call a walk passed, by
    `id`, for the one file being analysed, so a walk stops at the first call it
    has seen before."""
    passed: list[ast.Call] = []
    cur: ast.AST = call
    while isinstance(cur, ast.Call):
        known = below.get(id(cur))
        if known is not None:
            cur = known
            break
        passed.append(cur)
        cur = cur.func
    for seen in passed:
        below[id(seen)] = cur
    return cur


def _outer_parts(node: ast.AST, limit: int, below: dict[int, ast.AST]) -> list[str]:
    """The first `limit` parts `_attr_chain(node)` collects, outermost first.

    `_attr_chain` reads a chain down to its root, so asking it about every call of
    a chain such as `x.join(a).join(a)...` or `f()()()...` read the chain below each
    call again, N * N / 2 steps for N calls: 1 MB of 480-call `f()()()` chains took
    18.6 s. The checks below compare a call's chain with a name of at most two
    parts, which its outermost three parts decide: fewer than three are the whole
    chain, and three, joined, match no such name.
    """
    parts: list[str] = []
    cur: ast.AST = node
    while len(parts) < limit:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        elif isinstance(cur, ast.Call):
            cur = _under_calls(cur, below)
        else:
            break
    return parts


def _is_stdio_server_params_call(call: ast.Call, below: dict[int, ast.AST]) -> bool:
    # Match `StdioServerParameters(...)` directly or as `mcp.client.stdio.StdioServerParameters`:
    # the last part of the call's chain.
    return _outer_parts(call.func, 1, below) == ["StdioServerParameters"]


# Function parameters whose *name* strongly implies untrusted, network-shaped
# input. Deliberately excludes generic names like `config`/`data` (a config
# object is normally trusted) so we don't fire on every builder function.
_SUSPICIOUS_PARAMS = frozenset(
    {"body", "payload", "req", "request", "event", "untrusted", "user_input"}
)


class _FileMemo:
    """What one file's checks have worked out about its nodes, by `id`, while its tree
    is alive: `_under_calls`'s first non-call node, and the answers of `_is_static`
    and `_reads_stored_command` for every node they read.

    The launcher arm reads a spawn's split source, and many spawns can reach one
    source through a name (`cmd = shlex.split(...)` and then `Popen(cmd)` a thousand
    times) or nest in each other. Reading it again for each made 1,000 spawns of
    one 75,000-name tuple take 122 s on main.
    """

    def __init__(self) -> None:
        self.below: dict[int, ast.AST] = {}
        self.static: dict[int, bool] = {}
        self.stored: dict[int, bool] = {}


def _is_static(node: ast.AST, memo: dict[int, bool] | None = None) -> bool:
    """True if the expression is a compile-time-constant literal. With `memo`, every
    node read keeps its answer there."""
    if memo is not None and id(node) in memo:
        return memo[id(node)]
    if isinstance(node, ast.Constant):
        static = True
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        static = all(_is_static(e, memo) for e in node.elts)
    elif isinstance(node, ast.Dict):
        static = all(
            (k is None or _is_static(k, memo)) and _is_static(v, memo)
            for k, v in zip(node.keys, node.values)
        )
    else:
        static = False
    if memo is not None:
        memo[id(node)] = static
    return static


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _unparse(node: ast.AST) -> str:
    return unparse(node)


def _command_arg_exprs(call: ast.Call) -> list[ast.expr]:
    """The `command=` / `args=` expressions of a StdioServerParameters call.

    Positionally, StdioServerParameters(command, args, env, ...) — so arg 0 is
    command and arg 1 is args.
    """
    exprs: list[ast.expr] = []
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    if "command" in kw:
        exprs.append(kw["command"])
    elif call.args:
        exprs.append(call.args[0])
    if "args" in kw:
        exprs.append(kw["args"])
    elif len(call.args) > 1:
        exprs.append(call.args[1])
    return exprs


# Before 3.12 `ast.unparse` writes an f-string's expressions with its own rules for
# quotes and escapes, which depend on how deep the f-string sits, so text inside an
# f-string is not written as it is written alone.
_FSTRING_REWRITTEN = sys.version_info < (3, 12)


def _taint_flows_to_command(call: ast.Call, facts: _FunctionFacts) -> bool:
    """True only when the `command`/`args` fed to StdioServerParameters is a
    dynamic value that traces back to a network-controlled source — a real
    source→sink path, not merely 'a taint marker appears somewhere in the
    function'. Constant command/args (allow-lists, literals) never fire.

    A StdioServerParameters call can sit inside another's `command` or `args`, and
    reading each nested call's whole argument again cost up to 200 times the
    argument: 190 nested `StdioServerParameters(command=` around a tuple of names
    took 7.1 s at 100 KB on main. So a call judged clean marks every node under
    its `command` and `args`:
    - in `facts.names_clean`, when no name there is a suspicious parameter or a
      tainted local. A call inside names fewer names, so none of its can be.
    - in `facts.judged`, when `ast.unparse` could also write them, except, before
      Python 3.12, the nodes inside an f-string. `_walk_python` judges a call
      there clean without reading it: `ast.unparse` writes a subexpression inside
      its parent as it writes it alone, give or take brackets around it, so the
      pattern finds no taint source in the call's text that it misses in its
      parent's. Before 3.12 that is not so inside an f-string, whose strings
      `ast.unparse` writes with or without escapes depending on the quotes left
      to it: a tab before `request.json` written as a tab matches, written as
      `\t` does not, as a built f-string three deep shows. Checked on Python 3.9
      to 3.12 for every expression the pattern matches in 100,336 files, about
      18,000 of them inside another expression, and on generated nests and
      f-strings built as trees.
    `ast.unparse` cannot write a nest deeper than its recursion allows, about 160
    calls, and the calls it fails on are then read for their names only once.
    """
    exprs = _command_arg_exprs(call)
    if not exprs or all(_is_static(e, facts.memo.static) for e in exprs):
        return False
    texts = [_unparse(expr) for expr in exprs]
    if any(_PY_TAINT_MODULES_RE.search(text) for text in texts):
        return True  # e.g. command=request.json()["cmd"] / os.environ[...]
    names_clean = id(call) in facts.names_clean
    written = all(texts)
    if names_clean and not written:
        return False

    referenced: set[str] = set()
    read: list[int] = []
    outside: list[int] = []  # the nodes of `read` outside an f-string, before 3.12
    for expr in exprs:
        stack: list[tuple[ast.AST, bool]] = [(expr, False)]
        while stack:
            sub, in_fstring = stack.pop()
            read.append(id(sub))
            if not in_fstring:
                outside.append(id(sub))
            if isinstance(sub, ast.Name):
                referenced.add(sub.id)
            in_fstring = in_fstring or (_FSTRING_REWRITTEN and isinstance(sub, ast.JoinedStr))
            stack.extend((child, in_fstring) for child in ast.iter_child_nodes(sub))
    if not names_clean:
        # A referenced name that is a suspicious *parameter* of this function.
        func = facts.func
        params = {a.arg for a in func.args.args}
        params |= {a.arg for a in func.args.posonlyargs}
        params |= {a.arg for a in func.args.kwonlyargs}
        if referenced & (params & _SUSPICIOUS_PARAMS):
            return True
        # A referenced name that is locally assigned from a taint expression
        # (`cmd = os.environ[...]` / `body = await request.json()`).
        if referenced & facts.tainted_targets():
            return True
        facts.names_clean.update(read)
    if written:
        facts.judged.update(outside)
    return False


# Hand-rolled launcher arm (CVE-2026-93965, SxDevOps). An application that
# stores the MCP servers its users register and starts a STDIO one itself, with
# `subprocess.Popen(shlex.split(server.endpoint_or_command))`, never touches the
# SDK names above, so the SDK arm cannot see it. Same class, same function-local
# posture: the split and the spawn sit in one function, the split reads a stored
# server's `command` field, the function manages MCP STDIO servers (its class,
# its name or its own strings say "MCP" and "stdio"), and nothing between the
# split and the spawn checks the executable against an allowlist.
_PY_SPAWN_CHAINS = frozenset({
    "subprocess.Popen", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "asyncio.create_subprocess_exec", "Popen", "create_subprocess_exec",
})
_ALLOWLIST_NAME_RE = re.compile(r"allow|permit|whitelist|approved", re.IGNORECASE)


def _spawn_argv(call: ast.Call, below: dict[int, ast.AST]) -> ast.expr | None:
    """The argv a process-spawn call runs, or None if it is not one."""
    if ".".join(reversed(_outer_parts(call.func, 3, below))) not in _PY_SPAWN_CHAINS:
        return None
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    if "args" in kw:
        return kw["args"]
    if not call.args:
        return None
    first = call.args[0]
    return first.value if isinstance(first, ast.Starred) else first


def _is_shlex_split(node: ast.AST, below: dict[int, ast.AST]) -> bool:
    return isinstance(node, ast.Call) and _outer_parts(node.func, 3, below) == ["split", "shlex"] and bool(node.args)


def _names_a_command(node: ast.AST) -> bool:
    """`node` itself reads a field named for a command: `.command`, `["command"]`."""
    if isinstance(node, ast.Attribute):
        return "command" in node.attr.lower()
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and "command" in node.slice.value.lower()
    )


def _reads_stored_command(node: ast.AST, memo: dict[int, bool] | None = None) -> bool:
    """A server record's command field: `server.endpoint_or_command`, `cfg["command"]`,
    anywhere in `node`.

    Each node's answer is its own or one of its children's, worked out once, from
    the leaves up, and kept in `memo` for the file when given.
    """
    memo = {} if memo is None else memo
    stack: list[tuple[ast.AST, bool]] = [(node, False)]
    while stack:
        cur, children_done = stack.pop()
        if id(cur) in memo:
            continue
        if _names_a_command(cur):
            memo[id(cur)] = True
        elif not children_done:
            stack.append((cur, True))
            stack.extend((child, False) for child in ast.iter_child_nodes(cur) if id(child) not in memo)
        else:
            memo[id(cur)] = any(memo[id(child)] for child in ast.iter_child_nodes(cur))
    return memo[id(node)]


def _split_source(call: ast.Call, facts: _FunctionFacts) -> ast.expr | None:
    """What `shlex.split` was applied to, when a spawn's argv is its result.

    Either directly (`Popen(shlex.split(x))`) or through the last local
    assignment before the spawn (`command = shlex.split(x); Popen(command)`). An
    argv assigned from anything else, such as a validator, is not followed:
    that is exactly what the upstream fix looks like.
    """
    memo = facts.memo
    argv = _spawn_argv(call, memo.below)
    if argv is None:
        return None
    if isinstance(argv, ast.Name):
        argv = facts.assigned_value(argv.id, call.lineno)
    if not isinstance(argv, ast.Call) or not _is_shlex_split(argv, memo.below):
        return None
    source = argv.args[0]
    if _is_static(source, memo.static) or not _reads_stored_command(source, memo.stored):
        return None
    return source


def _manages_mcp_stdio(func: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str) -> bool:
    words = [class_name, func.name]
    words += [
        n.value for n in ast.walk(func)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    blob = " ".join(words).lower()
    return "mcp" in blob and "stdio" in blob


def _checks_an_allowlist(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """`if command[0] not in ALLOWED_EXECUTABLES:` and its kin, inside the function."""
    for node in ast.walk(func):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            continue
        for side in (node.left, *node.comparators):
            if _ALLOWLIST_NAME_RE.search(_attr_chain(side)):
                return True
    return False


class _Assignments:
    """Every assignment to one name in a function, for `_split_source`'s question.

    The question is which assigned value a spawn on line L runs, answered the
    way `_split_source` always answered it: walk the function's statements in
    `ast.walk` order and, among assignments that start before L, keep a value
    until a later statement starts past the line the kept value starts on.
    Walking the function for every spawn made one function of 1,000 spawns take
    14 seconds; this answers each spawn in time logarithmic in the number of
    assignments.

    `ast.walk` visits statements one depth at a time, and at one depth in source
    order. Within a depth, then, the walk keeps the first assignment of each
    line it reaches, except a line whose first statement begins where the kept
    value begins, which happens only when it follows a `;` on the line the kept
    value's statement ends on; that line is skipped and the next one is not. So
    in a depth's lines below L, from the first line past the value carried in
    from the depths above, the walk ends on the last line's first assignment,
    or on the line before it when an odd run of such skips ends at the last
    line. A function where that shape does not hold, which Python's grammar
    should not allow, is answered by the walk itself.
    """

    def __init__(self, found: list[tuple[int, int, ast.expr]]) -> None:
        # (depth, statement line, value), in `ast.walk` order.
        self._walk_order = [(line, value) for _, line, value in found]
        by_depth: dict[int, list[tuple[int, ast.expr]]] = {}
        for depth, line, value in found:
            by_depth.setdefault(depth, []).append((line, value))
        runs = [_depth_run(by_depth[depth]) for depth in sorted(by_depth)]
        self._runs = None if None in runs else [run for run in runs if run is not None]

    def value_at(self, line: int) -> ast.expr | None:
        if self._runs is None:
            return self._walked_value(line)
        value: ast.expr | None = None
        for lines, values, since in self._runs:
            below = bisect_left(lines, line)
            start = 0 if value is None else bisect_right(lines, getattr(value, "lineno", 0))
            if start >= below:
                continue
            last = below - 1
            if (last - max(start, since[last])) % 2:
                last -= 1
            value = values[last]
        return value

    def _walked_value(self, line: int) -> ast.expr | None:
        value: ast.expr | None = None
        for stmt_line, candidate in self._walk_order:
            if stmt_line < line and (value is None or stmt_line > getattr(value, "lineno", 0)):
                value = candidate
        return value


def _depth_run(found: list[tuple[int, ast.expr]]) -> tuple[list[int], list[ast.expr], list[int]] | None:
    """One depth's assignment lines, each line's first value, and where each line's
    run of skips began; None when the depth is not in source order."""
    lines: list[int] = []
    values: list[ast.expr] = []
    for line, value in found:
        if lines and line <= lines[-1]:
            if line < lines[-1]:
                return None
            continue
        if getattr(value, "lineno", 0) < line:
            return None
        lines.append(line)
        values.append(value)
    since: list[int] = []
    for i, line in enumerate(lines):
        skipped = i > 0 and getattr(values[i - 1], "lineno", 0) == line
        if i > 0 and getattr(values[i - 1], "lineno", 0) > line:
            return None
        since.append(since[i - 1] if skipped else i)
    return lines, values, since


class _FunctionFacts:
    """What the checks ask about one function, each worked out once for all its calls.

    Every call in a function used to put the same questions to the whole function
    again: `_split_source` walked it for where a spawn's argv was assigned,
    `_taint_flows_to_command` for tainted assignments, and the launcher arm for
    its MCP words and its allowlist checks.
    """

    def __init__(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str, memo: _FileMemo | None = None
    ) -> None:
        self.func = func
        self.class_name = class_name
        # Shared by every function of one file.
        self.memo = _FileMemo() if memo is None else memo
        # Nodes under the `command` and `args` of StdioServerParameters calls this
        # function's scan judged clean (see `_taint_flows_to_command`).
        self.names_clean: set[int] = set()
        self.judged: set[int] = set()
        self._assignments: dict[str, _Assignments] | None = None
        self._tainted: set[str] | None = None
        self._manages: bool | None = None
        self._allowlisted: bool | None = None

    def assigned_value(self, name: str, line: int) -> ast.expr | None:
        """The value `name` was last assigned before `line`, as `_Assignments` reads it."""
        if self._assignments is None:
            found: dict[str, list[tuple[int, int, ast.expr]]] = {}
            todo: deque[tuple[ast.AST, int]] = deque([(self.func, 0)])
            while todo:  # `ast.walk`'s order, with each node's depth
                node, depth = todo.popleft()
                todo.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
                if isinstance(node, ast.Assign):
                    for target in dict.fromkeys(t.id for t in node.targets if isinstance(t, ast.Name)):
                        found.setdefault(target, []).append((depth, node.lineno, node.value))
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                    found.setdefault(node.target.id, []).append((depth, node.lineno, node.value))
            self._assignments = {target: _Assignments(items) for target, items in found.items()}
        assignments = self._assignments.get(name)
        return assignments.value_at(line) if assignments is not None else None

    def tainted_targets(self) -> set[str]:
        """Every name in the target of an assignment whose value reads a taint source."""
        if self._tainted is None:
            tainted: set[str] = set()
            for stmt in ast.walk(self.func):
                if isinstance(stmt, ast.Assign) and _PY_TAINT_MODULES_RE.search(_unparse(stmt.value)):
                    for target in stmt.targets:
                        tainted |= _names_in(target)
            self._tainted = tainted
        return self._tainted

    def manages_mcp_stdio(self) -> bool:
        if self._manages is None:
            self._manages = _manages_mcp_stdio(self.func, self.class_name)
        return self._manages

    def checks_an_allowlist(self) -> bool:
        if self._allowlisted is None:
            self._allowlisted = _checks_an_allowlist(self.func)
        return self._allowlisted


def _functions_in(tree: ast.AST) -> Iterator[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]]:
    """Every function definition in `tree`, with the name of the class it sits in.

    In the order the recursive `ast.NodeVisitor` this replaces reached them: a
    function before anything inside it, children in field order, and the class
    the innermost enclosing `class` statement names ("" outside one), even
    across functions defined between the two. That visitor took two frames per
    level of nesting, and every `elif` sits one level below the branch before
    it, so a function dispatching on more than about 480 branches raised
    RecursionError and the scanner lost its findings in every file. This walk
    keeps its own stack.
    """
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, class_name = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node, class_name
        elif isinstance(node, ast.ClassDef):
            class_name = node.name
        stack.extend((child, class_name) for child in reversed(list(ast.iter_child_nodes(node))))


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    try:
        tree = parse_python(text, path)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    memo = _FileMemo()

    def _launcher_finding(call: ast.Call, facts: _FunctionFacts) -> Finding | None:
        source = _split_source(call, facts)
        if source is None:
            return None
        if not facts.manages_mcp_stdio():
            return None
        if facts.checks_an_allowlist():
            return None
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        return make_finding(
            "AAK-MCP-STDIO-CMD-INJ-001",
            rel,
            f"{_attr_chain(call.func)}(...) at line {call.lineno} launches "
            f"`shlex.split({_unparse(source)})`, a stored MCP STDIO server's "
            "command, with no executable allowlist between the split and the "
            "spawn. Whoever can register or edit that server record chooses "
            "the program this host runs (the CVE-2026-93965 launcher shape).",
            line_number=call.lineno,
        )

    def _scan(func: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str) -> None:
        calls = sorted(
            (n for n in ast.walk(func) if isinstance(n, ast.Call)),
            key=lambda c: (c.lineno, c.col_offset),
        )
        facts = _FunctionFacts(func, class_name, memo)
        for call in calls:
            if not _is_stdio_server_params_call(call, memo.below):
                launcher = _launcher_finding(call, facts)
                if launcher is not None:
                    findings.append(launcher)
                    return  # one finding per function
                continue
            if id(call) in facts.judged:
                continue  # inside a call judged clean, so clean too
            # We have StdioServerParameters(command=X, args=Y). Fire only
            # when a network-controlled value actually flows into the
            # command/args sink — not merely because a taint marker or a
            # generically-named arg (`config`, `data`) exists somewhere in
            # the function. Constant command/args never fire.
            if not _taint_flows_to_command(call, facts):
                continue
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-MCP-STDIO-CMD-INJ-001",
                rel,
                f"StdioServerParameters(...) at line {call.lineno} "
                "is built inside a function that reads from a "
                "network-controlled source (request body, fetched "
                "JSON, env var, or untrusted YAML). The OX MCP "
                "Apr-2026 class lets the resulting `command`/`args` "
                "be executed verbatim by the SDK.",
                line_number=call.lineno,
            ))
            return  # one finding per function

    for func, class_name in _functions_in(tree):
        _scan(func, class_name)
    return findings


# ---------------------------------------------------------------------------
# TypeScript — AAK-MCP-STDIO-CMD-INJ-002
# ---------------------------------------------------------------------------


_TS_STDIO_TRANSPORT_RE = re.compile(
    r"""
    new\s+(?:StdioClientTransport|StdioServerTransport)\s*\(
    """,
    re.VERBOSE,
)
_TS_TAINT_RE = re.compile(
    r"""
    (?:
        req\.(?:body|query|params|headers)\b
      | request\.(?:body|query|params|headers)\b
      | await\s+fetch\s*\([^)]*\)\s*\.(?:then|catch|finally)
      | await\s+axios\s*\.\s*\w+\s*\(
      | process\.env\.[A-Z_][A-Z0-9_]*
      | JSON\.parse\s*\(
    )
    """,
    re.VERBOSE,
)


# A `command:` or `args:` member of a transport's options object, quoted or not.
_TS_SINK_KEY_RE = re.compile(r"""\s*["']?(?:command|args)["']?\s*:""")
_TS_SINK_SPAN = 1024


def _ts_sink_members(text: str, start: int, stop: int) -> list[str]:
    """The top-level members of the options object a transport call opens.

    Reads from `start`, just after `new StdioClientTransport(`, to the `)` that
    closes the call, and never past `stop`. Strings, template literals and regex
    literals are skipped whole and brackets nest, so a `,` inside `args: [a, b]`
    does not end the member. A regex literal is told from a division the way
    `_helpers.blank_js_comments` tells them apart, by the token before the `/`:
    a quote inside one (`u.replace(/'/g, '')`) used to open a string that hid
    every member after it. So a slash after a postfix `i++` or `i--` divides,
    and so does one after any `}`: a block's brace and an object's are the same
    token, and `if (a) {} /'/.test(s)` is read as a division. A quoted string
    ends at an unescaped newline, as `_helpers._js_skip_quoted` ends it, so a
    quote opened by such a misread hides only the rest of its line.
    """
    members: list[str] = []
    depth = 0
    member_start = -1
    quote = ""
    # The last significant character, where it is, and where the word it ends
    # starts (-1: it ends none). The word is sliced only at a `/`, so a long
    # identifier is not rebuilt character by character.
    prev, last, word_start = "", -1, -1
    i = start
    while i < stop:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote or (ch == "\n" and quote != "`"):
                quote = ""
                prev, word_start = _JS_OPERAND, -1
            i += 1
            continue
        postfix = prev in "+-" and last > start and text[last - 1] == prev
        if ch == "/" and not postfix and _js_regex_allowed(prev, text[word_start:last + 1] if word_start >= 0 else ""):
            i = _js_skip_regex(text, i, stop)
            prev, word_start = _JS_OPERAND, -1
            continue
        if not ch.isspace():
            if ch not in _JS_IDENT_CHARS:
                word_start = -1
            elif not (last == i - 1 and prev in _JS_IDENT_CHARS and word_start >= 0):
                word_start = i
            prev, last = ch, i
        if ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
            if depth == 1 and ch == "{":
                member_start = i + 1
        elif ch in ")]}":
            if depth == 1 and member_start >= 0:
                members.append(text[member_start:i])
                member_start = -1
            depth -= 1
            if depth < 0:
                break
        elif ch == "," and depth == 1 and member_start >= 0:
            members.append(text[member_start:i])
            member_start = i + 1
        i += 1
    return members


def _walk_ts_proximity(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Original heuristic: a taint marker within 1024 chars before the sink,
    or in the sink's own `command` / `args`.

    Retained as the fallback for when the tree-sitter grammar is unavailable, so
    the package keeps working with no new hard dependency. It both over-fires
    (an unrelated source that happens to sit nearby) and under-fires (a real
    source that reaches the sink from beyond the window).

    It used to read only the 1024 characters before `new
    StdioClientTransport(`, so the most direct shape, `{ command:
    req.body.command }` in the transport's own options, was CRITICAL with
    tree-sitter and silent without it, and a default install has no
    tree-sitter. The options are read up to the next transport at most, so a
    file of transports that never close is read once.

    The transports and their options are read with comments blanked, as the
    data-flow path parses them away: a comment before a key hid the member, an
    apostrophe in one opened a string that ran on, a source named in one
    counted as a value, and a commented-out transport took the next line's
    code as its options. A member's value is judged by the data-flow path's
    own source test, so Koa's `ctx.query` and a lower-case `process.env` name
    count on both paths. The look-back window still reads the source as
    written.
    """
    findings: list[Finding] = []
    code = blank_js_comments(text)
    sinks = list(_TS_STDIO_TRANSPORT_RE.finditer(code))
    for n, m in enumerate(sinks):
        stop = min(len(code), m.end() + _TS_SINK_SPAN)
        if n + 1 < len(sinks):
            stop = min(stop, sinks[n + 1].start())
        own = any(
            _TS_SINK_KEY_RE.match(member) and _ts_stdio_taint._is_taint_source(member)
            for member in _ts_sink_members(code, m.end(), stop)
        )
        if not own:
            window_start = max(0, m.start() - 1024)
            window = text[window_start : m.start()]
            if not _TS_TAINT_RE.search(window):
                continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        where = (
            "has a network-controlled source (req.body / fetch / axios / "
            "process.env / JSON.parse) written in its own command or args."
            if own else
            "is built shortly after a network-controlled source (req.body / "
            "fetch / axios / process.env / JSON.parse)."
        )
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-002",
            rel,
            f"new StdioClientTransport({{...}}) {where} OX MCP Apr-2026 class. "
            "[proximity heuristic — install tree-sitter for data-flow analysis]",
            line_number=line,
        ))
        return findings  # one per file is plenty
    return findings


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Data-flow when the grammar is present, proximity when it is not.

    What the rule reports is identical either way — same rule_id, severity and
    framework mappings. Only the decision changed: reachability from a
    caller-controlled source to the `command`/`args` of a StdioTransport,
    instead of "a marker appeared somewhere in the preceding 1024 characters".
    """
    if not _ts_stdio_taint.available():
        return _walk_ts_proximity(text, path, project_root, scanned)

    line = _ts_stdio_taint.find_tainted_sink(text)
    if line is None:
        return []

    rel = str(path.relative_to(project_root))
    scanned.add(rel)
    return [make_finding(
        "AAK-MCP-STDIO-CMD-INJ-002",
        rel,
        "new StdioClientTransport({...}) receives a command/args value that "
        "data-flow analysis traces back to a network-controlled source "
        "(req.body / fetch / axios / process.env / JSON.parse). OX MCP "
        "Apr-2026 class.",
        line_number=line,
    )]


# ---------------------------------------------------------------------------
# Java — AAK-MCP-STDIO-CMD-INJ-003 (regex pass)
# ---------------------------------------------------------------------------


# Match `StdioServerParameters.Builder()` — context window then proves the
# chain calls `.command(...)`/`.args(...)`/`.build()` and is fed by
# tainted input. Avoids regex fighting with nested parens in the chain.
_JAVA_STDIO_BUILDER_RE = re.compile(
    r"StdioServerParameters\s*\.\s*Builder\s*\(\s*\)",
    re.DOTALL,
)
_JAVA_STDIO_TERMINATOR_RE = re.compile(r"\.\s*build\s*\(\s*\)")
_JAVA_TAINT_RE = re.compile(
    r"""
    (?:
        request\s*\.\s*getParameter\s*\(
      | HttpServletRequest\b
      | RestTemplate\s*\.\s*getForObject\s*\(
      | WebClient\s*\.\s*\w+\s*\(\s*\)\s*\.\s*\w+
      | ObjectMapper\s*\.\s*\w+\s*\(\s*[^)]*Network
      | new\s+ObjectMapper\s*\(\s*\)\s*\.\s*readValue\s*\(
      | System\s*\.\s*getenv\s*\(
    )
    """,
    re.VERBOSE,
)


def _walk_java(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for m in _JAVA_STDIO_BUILDER_RE.finditer(text):
        # Require `.build()` somewhere in the next 4KB to confirm chain.
        forward = text[m.end() : m.end() + 4096]
        if not _JAVA_STDIO_TERMINATOR_RE.search(forward):
            continue
        # Look for taint marker either before the Builder() or in the
        # chain itself (e.g. `.args(request.getParameter("args"))`).
        window_start = max(0, m.start() - 2048)
        window = text[window_start : m.start()] + forward
        if not _JAVA_TAINT_RE.search(window):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-003",
            rel,
            "StdioServerParameters.Builder().command(...).build() is "
            "built after a network-controlled source (request param, "
            "RestTemplate/WebClient response, ObjectMapper.readValue, "
            "or System.getenv). OX MCP Apr-2026 class.",
            line_number=line,
        ))
        return findings
    return findings


# ---------------------------------------------------------------------------
# Rust — AAK-MCP-STDIO-CMD-INJ-004 (regex pass; FP-prone on macros)
# ---------------------------------------------------------------------------


_RUST_PROCESS_NEW_RE = re.compile(
    r"""
    (?:
        (?:tokio::process|std::process)\s*::\s*Command\s*::\s*new\s*\(
      | \bCommand\s*::\s*new\s*\(           # bare Command::new (when imported via `use`)
    )
    """,
    re.VERBOSE,
)
_RUST_USE_COMMAND_RE = re.compile(
    r"use\s+(?:tokio::process|std::process)::Command\b"
)
_RUST_TAINT_RE = re.compile(
    r"""
    (?:
        reqwest\s*::\s*get\s*\(
      | reqwest\s*::\s*Client
      | serde_json\s*::\s*from_str\s*\(
      | serde_json\s*::\s*from_slice\s*\(
      | std\s*::\s*env\s*::\s*var\s*\(
      | hyper\s*::\s*body
      | actix_web\s*::\s*web\s*::\s*Json
      | axum\s*::\s*extract\s*::\s*Json
    )
    """,
    re.VERBOSE,
)
_RUST_MCP_HINT_RE = re.compile(r"\b(?:mcp_sdk|modelcontextprotocol|mcp::client::stdio)\b")


def _walk_rust(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _RUST_MCP_HINT_RE.search(text):
        return []
    has_use_command = bool(_RUST_USE_COMMAND_RE.search(text))
    findings: list[Finding] = []
    for m in _RUST_PROCESS_NEW_RE.finditer(text):
        # If the match is the bare `Command::new`, require a matching
        # `use ...::process::Command;` somewhere in the file.
        matched_text = m.group(0)
        if matched_text.lstrip().startswith("Command") and not has_use_command:
            continue
        window_start = max(0, m.start() - 2048)
        window = text[window_start : m.start()]
        if not _RUST_TAINT_RE.search(window):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-004",
            rel,
            "tokio::process::Command::new(...) is invoked in a file "
            "that imports `mcp_sdk` / `modelcontextprotocol` after a "
            "network-controlled source (reqwest, serde_json, env::var, "
            "hyper/actix/axum body extractors). OX MCP Apr-2026 class. "
            "Note: regex-only pass; expect ~10% FP on macro-heavy code. "
            "There is no tree-sitter-rust grammar and none is pending.",
            line_number=line,
        ))
        return findings
    return findings


# ---------------------------------------------------------------------------
# Go - AAK-MCP-STDIO-CMD-INJ-005 (regex + proximity; same posture as Rust)
# ---------------------------------------------------------------------------
#
# Modelled on _walk_rust deliberately, including its limits. This is not a
# go/ast pass and does not model flow; it reports that a spawn sink sits
# downstream of a network-shaped source in an MCP-shaped file.
#
# The MCP hint cannot be an SDK import the way Rust's is. CVE-2026-90898's
# handler imports `encoding/json`, `net/http` and `os/exec` and nothing else --
# the MCP identity lives in the type name (`MCPClientRequest`), the route
# (`/api/mcp/client`) and the field names (`stdio_command`). A hint gated on an
# SDK import would miss the exemplar this rule exists for.

_GO_EXEC_RE = re.compile(r"\bexec\s*\.\s*Command(?:Context)?\s*\(")
# A quoted literal in argv[0] position, optionally after a ctx argument.
_GO_LITERAL_ARGV0_RE = re.compile(r'\s*(?:\w+\s*,\s*)?["`]')
_GO_TAINT_RE = re.compile(
    r"""
    (?:
        json\s*\.\s*NewDecoder\s*\(\s*r\s*\.\s*Body\s*\)
      | json\s*\.\s*NewDecoder\s*\(\s*\w+\s*\.\s*Body\s*\)
      | \*\s*http\s*\.\s*Request\b
      | \bShouldBindJSON\s*\(
      | \bBindJSON\s*\(
      | io\s*\.\s*ReadAll\s*\(\s*\w+\s*\.\s*Body\s*\)
      | mux\s*\.\s*Vars\s*\(
      | r\s*\.\s*URL\s*\.\s*Query\s*\(\s*\)
    )
    """,
    re.VERBOSE,
)
# MCP identity in Go: an SDK path, a protocol name, an `MCPFoo` identifier, an
# /mcp route, or an mcp-prefixed JSON field.
_GO_MCP_HINT_RE = re.compile(
    r"""
    (?:
        modelcontextprotocol
      | \bmcp-go\b
      | \bMCP[A-Z]\w*
      | ["'`][^"'`]*/mcp(?:/|["'`])
      | \bmcpServers?\b
      | \bstdio_?[Cc]ommand\b
    )
    """,
    re.VERBOSE,
)


def _walk_go(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _GO_MCP_HINT_RE.search(text):
        return []
    findings: list[Finding] = []
    for m in _GO_EXEC_RE.finditer(text):
        window = text[max(0, m.start() - 2048) : m.start()]
        if not _GO_TAINT_RE.search(window):
            continue
        # argv[0] is a string literal => the binary is chosen server-side and
        # the caller cannot pick it. This is what a patched handler looks like
        # (an allowlist resolves a constant, request data rides as later args),
        # and without this guard a proximity rule reports every server that
        # decoded a body anywhere in the preceding 2 KB. Narrow on purpose: a
        # literal first argument is decidable without parsing Go.
        if _GO_LITERAL_ARGV0_RE.match(text, m.end()):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-005",
            rel,
            "exec.Command(...) is invoked in an MCP-shaped Go file downstream "
            "of a network-controlled source (json.NewDecoder(r.Body), an "
            "*http.Request handler, or ShouldBindJSON). CVE-2026-90898 "
            "(Bifrost) class: an unauthenticated client-registration route "
            "that spawns the registered command. Note: regex and proximity "
            "only, not Go data-flow analysis, so a handler that decodes a body "
            "and separately shells out to a constant will also match.",
            line_number=line,
        ))
        return findings
    return findings


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root):
            continue
        suffix = path.suffix
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            with refusing_overflow(path):
                findings.extend(_walk_python(text, path, project_root, scanned))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            findings.extend(_walk_ts(text, path, project_root, scanned))
        elif suffix == ".java":
            findings.extend(_walk_java(text, path, project_root, scanned))
        elif suffix == ".rs":
            findings.extend(_walk_rust(text, path, project_root, scanned))
        elif suffix == ".go":
            findings.extend(_walk_go(text, path, project_root, scanned))
    return findings, scanned
