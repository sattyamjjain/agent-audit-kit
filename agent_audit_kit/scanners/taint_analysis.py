from __future__ import annotations

import ast
import string
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import in_skip_dir, make_finding, parse_python, refusing_overflow, walk_tree

# ---- Tool decorator names to recognise ----
_TOOL_DECORATORS: frozenset[str] = frozenset({
    "tool",
    "mcp.tool",
    "server.tool",
    "langchain.tools.tool",
    "crewai.tool",
    "autogen.tool",
})

# ---- Dangerous sink categories, keyed by rule ID ----
#
# Each entry maps a rule ID to a set of (module_or_none, function_name) tuples.
# module_or_none is ``None`` for builtins, otherwise the dotted module prefix.
_SINKS: dict[str, set[tuple[str | None, str]]] = {
    "AAK-TAINT-001": {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
        # Shell-executing primitives the rule's own description already claims
        # ("os.system(), subprocess, or similar shell execution functions")
        # but the set omitted. `asyncio.create_subprocess_shell` is the sink in
        # CVE-2026-90617: PentestAgent's `run_task` tool hands a caller-supplied
        # string to it through LocalRuntime, and the rule stayed silent on the
        # real shape because only the blocking `subprocess` spellings were here.
        # `asyncio.create_subprocess_exec` is deliberately absent: it takes an
        # argv list and never reaches a shell, so it is the fixed form, not a
        # sink. Same split as `subprocess.run(..., shell=True)` vs a list.
        ("asyncio", "create_subprocess_shell"),
        ("subprocess", "getoutput"),
        ("subprocess", "getstatusoutput"),
        # `os.exec*` replaces the process with the program its first argument
        # names. A caller-chosen program is run as surely as by
        # `subprocess.run(param)`, which this set has always counted, and
        # `os.execvp(cmd, [cmd])` in a tool scanned clean while it was absent.
        ("os", "execl"),
        ("os", "execle"),
        ("os", "execlp"),
        ("os", "execlpe"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "execvp"),
        ("os", "execvpe"),
    },
    "AAK-TAINT-002": {
        (None, "eval"),
        (None, "exec"),
        (None, "compile"),
    },
    "AAK-TAINT-003": {
        (None, "open"),
        ("pathlib", "Path"),
    },
    "AAK-TAINT-004": {
        ("requests", "get"),
        ("requests", "post"),
        ("requests", "put"),
        ("requests", "delete"),
        ("urllib.request", "urlopen"),
        ("httpx", "get"),
        ("httpx", "post"),
    },
    "AAK-TAINT-005": {
        ("cursor", "execute"),
        ("connection", "execute"),
        ("session", "execute"),
    },
    "AAK-TAINT-006": {
        ("pickle", "loads"),
        ("pickle", "load"),
        ("yaml", "load"),
        ("yaml", "unsafe_load"),
        ("marshal", "loads"),
    },
}

# Flat lookup: (module_or_none, func_name) -> rule_id
_SINK_LOOKUP: dict[tuple[str | None, str], str] = {}
for _rule_id, _sink_set in _SINKS.items():
    for _sink in _sink_set:
        _SINK_LOOKUP[_sink] = _rule_id


def _get_decorator_name(decorator: ast.expr) -> str:
    """Extract the full dotted name from a decorator node.

    Handles:
      - ``@tool``                -> "tool"
      - ``@mcp.tool``           -> "mcp.tool"
      - ``@server.tool()``      -> "server.tool"
      - ``@langchain.tools.tool`` -> "langchain.tools.tool"
    """
    node = decorator
    # Unwrap Call nodes: @tool() -> tool, @server.tool() -> server.tool
    if isinstance(node, ast.Call):
        node = node.func

    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return ".".join(parts)


def _is_tool_function(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function is decorated with a recognised tool decorator."""
    for deco in func_def.decorator_list:
        name = _get_decorator_name(deco)
        if name in _TOOL_DECORATORS:
            return True
    return False


def _is_call_tool_handler(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True for the low-level MCP SDK's tool handler, ``@<server>.call_tool()``.

    `mcp.server.lowlevel.Server` registers no function per tool. It calls one
    handler with the requested tool's name and the caller's `arguments` dict,
    so that handler is where every tool's input arrives. It was not an entry
    point here, and `subprocess.run(arguments["cmd"], shell=True)` inside it
    scanned clean.

    Any receiver counts. The SDK's own examples name the server `server` and
    `app`, and unlike `.tool`, a decorator name other agent frameworks use too,
    `call_tool` as a decorator belongs to this API.
    """
    for deco in func_def.decorator_list:
        if _get_decorator_name(deco).endswith(".call_tool"):
            return True
    return False


def _get_param_names(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all parameter names from a function definition (excluding ``self`` / ``cls``)."""
    names: set[str] = set()
    args = func_def.args
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        if arg.arg not in ("self", "cls"):
            names.add(arg.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _resolve_callee(node: ast.Call) -> tuple[str | None, str] | None:
    """Resolve a Call node to (module_or_none, func_name).

    Returns None if the callee cannot be resolved to a known pattern.
    Handles:
      - eval(...)                 -> (None, "eval")
      - os.system(...)            -> ("os", "system")
      - subprocess.run(...)       -> ("subprocess", "run")
      - cursor.execute(...)       -> ("cursor", "execute")
      - pathlib.Path(...)         -> ("pathlib", "Path")
    """
    func = node.func

    if isinstance(func, ast.Name):
        # Simple name: eval, exec, compile, open
        return (None, func.id)

    if isinstance(func, ast.Attribute):
        # Single-level attribute: os.system, cursor.execute
        if isinstance(func.value, ast.Name):
            return (func.value.id, func.attr)
        # Two-level attribute: urllib.request.urlopen, langchain.tools.tool
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            module = f"{func.value.value.id}.{func.value.attr}"
            return (module, func.attr)

    return None


# ---- Sinks imported under another name ----
#
# A sink is listed by its module and function (`("subprocess", "run")`), and was
# matched by its spelling at the call site, so `from subprocess import run` then
# `run(cmd, shell=True)`, `from pathlib import Path` then `Path(p)`, and `import
# subprocess as sp` then `sp.run(...)` were no sinks. A file's imports now say
# what such a name stands for. A name counts only when every binding the file
# makes of it is an import of the same thing, anywhere in the file: a `def`, a
# class, an assignment, a parameter or a second import that names something else
# leaves it read by its spelling, and a relative import names no module this
# list knows. The spelling also wins when it is a sink itself or the import names
# none, so the builtin `open` stays a sink whatever the file imports.


def _import_names(tree: ast.Module) -> dict[str, str]:
    """What each name the file binds only by importing it stands for, as a dotted path.

    A star import may bind any name, so a file with one reads no name through
    its imports: `from helpers import *` after `from subprocess import run`
    can define its own `run`, and `from subprocess import *` binds names this
    map never learns. Every call is then matched by its spelling, as before.
    """
    targets: dict[str, set[str]] = {}
    rebound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    targets.setdefault(alias.asname, set()).add(alias.name)
                else:
                    top = alias.name.split(".")[0]
                    targets.setdefault(top, set()).add(top)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return {}
                bound = alias.asname or alias.name
                if node.level or not node.module:
                    rebound.add(bound)
                else:
                    targets.setdefault(bound, set()).add(f"{node.module}.{alias.name}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            rebound.add(node.name)
        elif type(node).__name__ in ("MatchAs", "MatchStar", "MatchMapping"):
            # Read by name: the `match` nodes are 3.10, and this runs on 3.9.
            for captured in (getattr(node, "name", None), getattr(node, "rest", None)):
                if isinstance(captured, str):
                    rebound.add(captured)
    return {
        name: next(iter(paths)) for name, paths in targets.items() if len(paths) == 1 and name not in rebound
    }


def _resolve_sink(node: ast.Call, imported: dict[str, str]) -> tuple[str | None, str] | None:
    """`_resolve_callee`, with a name the file imports read as what it stands for.

    `run(...)` after `from subprocess import run` is `("subprocess", "run")`, and
    `sp.run(...)` after `import subprocess as sp` is too. The spelling is kept
    when it is a sink already, or when what the import names is not one.
    """
    callee = _resolve_callee(node)
    if callee is None or callee in _SINK_LOOKUP or not imported:
        return callee
    module, name = callee
    if module is None:
        path = imported.get(name)
        if path is None or "." not in path:
            return callee
        owner, _, attr = path.rpartition(".")
        resolved: tuple[str | None, str] = (owner, attr)
    else:
        head, dot, rest = module.partition(".")
        path = imported.get(head)
        if path is None:
            return callee
        resolved = (path + dot + rest, name)
    return resolved if resolved in _SINK_LOOKUP else callee


#: What a `pathlib.Path` gives without touching a file: the parts of its name.
#: `Path(p).suffix` reads the caller's string and opens nothing, so a `Path` call
#: whose result is read only for one of these is no file-access sink. Of 100
#: sampled AAK-TAINT-003 findings the import map above added on the corpus, 7
#: had that shape (`Path(name).stem`, `Path(file_name).suffix.lower()`).
_PATH_NAME_PARTS = frozenset({"name", "stem", "suffix", "suffixes", "parts", "anchor", "drive", "root"})
_NAME_ONLY_SINKS: frozenset[tuple[str | None, str]] = frozenset({("pathlib", "Path")})


def _name_only_calls(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> set[int]:
    """The calls in `func_def` whose result is read only for a part of its name."""
    return {
        id(node.value) for node in ast.walk(func_def)
        if isinstance(node, ast.Attribute) and node.attr in _PATH_NAME_PARTS and isinstance(node.value, ast.Call)
    }


def _reads_param(node: ast.expr, param_names: set[str]) -> bool:
    """True when ``node`` is a parameter, or an item read out of one.

    A bare name is the parameter itself. `arguments["cmd"]`, `arguments.get("cmd")`
    (with or without a default) and chains of them (`arguments["opts"]["cmd"]`)
    are the caller's data as surely: the parameter only holds it. A low-level
    `call_tool` handler receives every input as one `arguments` dict, so without
    item reads its entry point would see nothing. Anything else built on the
    value (`arguments["expr"].strip()`, an f-string, a concatenation) is not
    followed, the same as for a bare parameter.
    """
    if isinstance(node, ast.Name):
        return node.id in param_names
    if isinstance(node, ast.Subscript):
        return _reads_param(node.value, param_names)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        return _reads_param(node.func.value, param_names)
    return False


def _call_uses_param(call_node: ast.Call, param_names: set[str]) -> bool:
    """True if any positional or keyword argument is a parameter or an item read from one."""
    for arg in call_node.args:
        if _reads_param(arg, param_names):
            return True
        # Also check starred args: *args
        if isinstance(arg, ast.Starred) and isinstance(arg.value, ast.Name) and arg.value.id in param_names:
            return True
    for kw in call_node.keywords:
        if _reads_param(kw.value, param_names):
            return True
    return False


def _has_any_type_hints(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if at least one parameter (excluding self/cls) has a type annotation."""
    args = func_def.args
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        if arg.arg in ("self", "cls"):
            continue
        if arg.annotation is not None:
            return True
    return False


def _is_literal(node: ast.expr) -> bool:
    """A literal operand: a constant, an f-string with no placeholders, or a list/tuple of literals (a fixed argv)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    return False


#: Sinks whose later positional arguments are operands as much as the first, so a
#: literal first argument proves nothing about them: `os.exec*` hands them to the
#: new program as its argv (`os.execl("/bin/sh", "sh", "-c", cmd)`), and
#: `pathlib.Path` joins them all into one path (`pathlib.Path("/srv", name)`).
_LATER_ARGS_ARE_OPERANDS: frozenset[tuple[str | None, str]] = frozenset(
    {("os", name) for name in ("execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe")}
    | {("pathlib", "Path")}
)


def _fixed_target(node: ast.Call, callee: tuple[str | None, str]) -> bool:
    """True when the call's target, its first positional argument, is a literal.

    A constant URL, a fixed argv or a constant SQL string decides what the call
    does, and a parameter elsewhere in it (`json=`, `params=`, `input=`, `cwd=`,
    a bound SQL value) is data for that fixed target. Forwarding the whole
    `arguments` dict to a constant URL (`requests.post(URL, json=arguments)`)
    is no SSRF, and a bound value is how SQL injection is avoided. Measured on
    1,713 public Python MCP server repositories, this skip removed 12 findings
    of that shape (10 of them the `call_tool` handler's whole-dict forwards) and
    no true positive.

    It gives up one shape, stated in AAK-TAINT-001's limitation: a fixed
    interpreter fed the caller's text on stdin
    (`subprocess.run(["python3"], input=code)`) reads as a fixed command. The
    sinks in `_LATER_ARGS_ARE_OPERANDS` are exempt.
    """
    if callee in _LATER_ARGS_ARE_OPERANDS:
        return False
    return bool(node.args) and _is_literal(node.args[0])


# AAK-TAINT-005 and a query built from the caller's value. Only a parameter
# passed as the whole query is reported, so `cursor.execute(f"... WHERE title =
# '{title}'")` scans clean, as the rule's limitation says. An arm that also read
# the values formatted into the query (an f-string, `.format()`, `%` or `+`
# with a parameter or a followed local in it) was measured on the same 7,915
# tool and handler files as the allow-list skip below: 22 of its 66 findings
# were true, 33% (17 of 40 for a parameter, 5 of 26 for a handler local), under
# the 80% bar it had to clear. Of the 44 others, 32 put the value where it
# cannot extend the statement (a sqlite PRAGMA argument, or DESCRIBE, SHOW or
# USE on a driver that runs one statement per call), 10 format a number that
# FastMCP or the tool's inputSchema has already validated, and 2 check or
# escape it first. So it was left off; the arm and its tests are kept on the
# local, unpushed branch `wip/taint-locals-formatted`.


# ---- A `call_tool` handler's locals ----
#
# Real handlers copy the caller's input into a local before using it,
# `cmd = arguments["cmd"]` and then `subprocess.run(cmd, shell=True)`, and the
# rules above see only a parameter or an item read straight from one. Of the
# sink calls the `arguments` dict reaches inside handlers on 1,713 public Python
# MCP server repositories, 106 go through such a local and 15 read the item
# directly, so the handler entry point found about one in eight on its own.
#
# This pass follows the locals that hold a parameter or an item read from one
# (`x = arguments`, `x = arguments["k"]`, `x = arguments.get("k", default)`,
# annotated or bound with `:=`), and one link further (`y = x["k"]`). Any other
# binding clears the name: a call, an f-string, a concatenation, `x or default`,
# unpacking, an augmented assignment, a `for`, `with`, `except` or `case`
# target, an import, a nested `def` or `class`, `del`. A nested function, class
# or lambda is its own scope and is not entered, and inside a comprehension its
# own variable hides a local of the same name. The literal-target skip applies
# to a local as to a parameter.
#
# Paths are read as the direct rules read a sink, any one is enough: after an
# `if`, a loop, a `try` or a `match`, a local holds the input when some branch
# that gets there leaves it holding it. A branch that returns or raises gets
# nowhere, and a loop body may run no times. So `cmd = arguments["cmd"]` in an
# `if` with `cmd = "ls"` in its `else` is followed whichever branch comes first,
# and a local bound in a branch that returns does not reach the code after it.
#
# What it reports was judged on the same repositories, by a first version that
# read an `if`'s branches one after the other, so the later one's assignment
# won. AAK-TAINT-001, -003 and -004 gained 43 true positives in 44 additions
# (12/13, 26/26, 5/5; the other was unclear); AAK-TAINT-006 had no addition
# either way and is included with them. AAK-TAINT-002 (24 of 38, 14 false
# positives from calculator tools that allowlist the expression before `eval`)
# and AAK-TAINT-005 (32 of 44, the rest read-only SQL tools and SELECT-prefix
# checks) were left out. `@tool` functions keep the behaviour they had: across
# those repositories the pass added a single finding in one, and it was unclear.
#
# Both were measured again on 7,915 tool and handler files, and both stay out.
# AAK-TAINT-002 added 27 findings and 16 were true (59%). Of the 11 false
# positives, 7 are calculator handlers that allow-list the expression before
# `eval`, which the allow-list skip below does not read in a handler, and 3 are
# `compile()` calls that only check syntax: not following a local to
# `compile()`, which runs nothing, gives 16 of 24 (67%). AAK-TAINT-005 added 36
# and 26 were true (72%), the rest tools that run only reads (a SELECT prefix on
# a driver that runs one statement, a read-only connection or transaction) and
# a REPL whose `session.execute` is not SQL. Following both, and the `compile()`
# exclusion, are kept with their tests on the local, unpushed branch
# `wip/taint-locals-formatted`.
_ALIAS_FOLLOWED_RULES: frozenset[str] = frozenset(
    {"AAK-TAINT-001", "AAK-TAINT-003", "AAK-TAINT-004", "AAK-TAINT-006"}
)
_MAX_ALIAS_DEPTH = 2
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _item_root(node: ast.expr) -> ast.expr:
    """What an item read reads from: `x["a"]["b"]` and `x.get("a").get("b")` both give `x`."""
    while True:
        if isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            node = node.func.value
        else:
            return node


def _alias_depth(node: ast.expr | None, depths: dict[str, int], param_names: set[str]) -> int | None:
    """0 for a parameter or an item read of one, n for a local n links away from one, None otherwise."""
    if node is None:
        return None
    root = _item_root(node)
    if isinstance(root, ast.Name):
        if root.id in param_names:
            return 0
        return depths.get(root.id)
    return None


def _evaluated(expr: ast.AST) -> list[tuple[ast.AST, frozenset[str]]]:
    """The nodes an expression evaluates, in source order, each with the names a
    comprehension around it binds for itself. A lambda is not entered."""
    out: list[tuple[ast.AST, frozenset[str]]] = []
    stack: list[tuple[ast.AST, frozenset[str]]] = [(expr, frozenset())]
    # A comprehension's first iterable is evaluated outside the comprehension.
    outside: dict[int, frozenset[str]] = {}
    while stack:
        node, hidden = stack.pop()
        hidden = outside.pop(id(node), hidden)
        if isinstance(node, ast.Lambda):
            continue
        out.append((node, hidden))
        if isinstance(node, _COMPREHENSIONS):
            outside[id(node.generators[0].iter)] = hidden
            hidden = hidden | {
                n.id for gen in node.generators for n in ast.walk(gen.target) if isinstance(n, ast.Name)
            }
        stack.extend((child, hidden) for child in reversed(list(ast.iter_child_nodes(node))))
    return out


class _Locals:
    """The handler's locals that hold the caller's input, each with its depth.

    A branch is explored from the state it opens in, keeping an undo log of the
    names it writes. Closing it hands back what it left on those names and puts
    their opening values back, so a join costs the names its branches wrote, not
    the whole map, and a crafted handler with many locals and branches stays
    linear.
    """

    def __init__(self) -> None:
        self.depths: dict[str, int] = {}
        self._logs: list[dict[str, int | None]] = []

    def set(self, name: str, depth: int | None) -> None:
        for log in self._logs:
            if name not in log:
                log[name] = self.depths.get(name)
        if depth is None:
            self.depths.pop(name, None)
        else:
            self.depths[name] = depth

    def open(self) -> None:
        self._logs.append({})

    def close(self) -> dict[str, int | None]:
        log = self._logs.pop()
        left = {name: self.depths.get(name) for name in log}
        for name, before in log.items():
            if before is None:
                self.depths.pop(name, None)
            else:
                self.depths[name] = before
        return left

    def join(self, outcomes: list[dict[str, int | None] | None]) -> bool:
        """Merge the branches that get here, from the state they opened in.

        A branch's outcome is what it left on the names it wrote, or None when it
        returned or raised. After the join a local holds the input if any branch
        left it holding it, at the shortest depth any did. False when no branch
        gets here.
        """
        live = [left for left in outcomes if left is not None]
        for name in {name for left in live for name in left}:
            held = [d for d in (left.get(name, self.depths.get(name)) for left in live) if d is not None]
            self.set(name, min(held) if held else None)
        return bool(live)


class _HandlerFlow:
    """Follow one `call_tool` handler's locals to the sinks they reach (see above)."""

    def __init__(
        self,
        func_def: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
        param_names: set[str],
        imported: dict[str, str] | None = None,
        name_only: set[int] | None = None,
    ) -> None:
        self.func_def = func_def
        self.rel_path = rel_path
        self.params = param_names
        self.imported = imported or {}
        self.name_only = name_only or set()
        self.locals = _Locals()
        self.findings: list[Finding] = []

    def scan(self, expr: ast.AST | None) -> None:
        """Report the sinks `expr` calls on a local, then bind its `:=` targets."""
        if expr is None:
            return
        nodes = _evaluated(expr)
        for node, hidden in nodes:
            if isinstance(node, ast.Call):
                self._check(node, hidden)
        for node, _hidden in nodes:
            if isinstance(node, ast.NamedExpr):
                self._bind(node.target, self._depth(node.value))

    def _check(self, call: ast.Call, hidden: frozenset[str]) -> None:
        callee = _resolve_sink(call, self.imported)
        rule_id = _SINK_LOOKUP.get(callee) if callee is not None else None
        if callee is None or rule_id is None or rule_id not in _ALIAS_FOLLOWED_RULES:
            return
        if callee in _NAME_ONLY_SINKS and id(call) in self.name_only:
            return
        # A call the direct rules consider, because a parameter or an item read
        # from one is among its arguments, is theirs: they report it, or the
        # literal-target skip silences it, and neither should happen twice.
        if _call_uses_param(call, self.params) or _fixed_target(call, callee):
            return
        name = self._local_arg(call, hidden)
        if name is None:
            return
        sink_label = f"{callee[0]}.{callee[1]}" if callee[0] else callee[1]
        self.findings.append(make_finding(
            rule_id,
            self.rel_path,
            f"Function '{self.func_def.name}': param flows to {sink_label}() via local '{name}'",
            getattr(call, "lineno", self.func_def.lineno),
        ))

    def _local_arg(self, call: ast.Call, hidden: frozenset[str]) -> str | None:
        """The local among the call's arguments that holds the input, if one does."""
        for arg in [*call.args, *(kw.value for kw in call.keywords)]:
            if isinstance(arg, ast.Starred):
                arg = arg.value
            root = _item_root(arg)
            if isinstance(root, ast.Name) and root.id in self.locals.depths and root.id not in hidden:
                return root.id
        return None

    def _depth(self, value: ast.expr | None) -> int | None:
        return _alias_depth(value, self.locals.depths, self.params)

    def _bind(self, target: ast.expr, depth: int | None) -> None:
        """Record what `target` holds now: the input `depth` links away, or not.

        A parameter stays tainted by name, as in the direct rules.
        """
        if isinstance(target, ast.Name):
            if target.id in self.params:
                return
            if depth is not None and depth < _MAX_ALIAS_DEPTH:
                self.locals.set(target.id, depth + 1)
            else:
                self.locals.set(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt, None)
        elif isinstance(target, ast.Starred):
            self._bind(target.value, None)

    def visit(self, stmts: list[ast.stmt]) -> bool:
        """Follow `stmts` in order; False when they cannot complete (they return or raise)."""
        for st in stmts:
            if isinstance(st, (ast.Break, ast.Continue)):
                # The rest of the block does not run; the loop's merge covers
                # where control goes instead.
                return True
            if not self._statement(st):
                return False
        return True

    def _statement(self, st: ast.stmt) -> bool:
        """Follow one statement; False when control cannot continue past it."""
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.locals.set(st.name, None)
        elif isinstance(st, ast.Assign):
            self.scan(st.value)
            depth = self._depth(st.value)
            for target in st.targets:
                self._bind(target, depth)
        elif isinstance(st, ast.AnnAssign):
            self.scan(st.value)
            if st.value is not None:
                self._bind(st.target, self._depth(st.value))
        elif isinstance(st, ast.AugAssign):
            self.scan(st.value)
            self._bind(st.target, None)
        elif isinstance(st, ast.Delete):
            for target in st.targets:
                self._bind(target, None)
        elif isinstance(st, (ast.Import, ast.ImportFrom)):
            for alias in st.names:
                if alias.name != "*":
                    self.locals.set(alias.asname or alias.name.split(".")[0], None)
        elif isinstance(st, (ast.Return, ast.Raise)):
            for child in ast.iter_child_nodes(st):
                self.scan(child)
            return False
        elif isinstance(st, ast.If):
            self.scan(st.test)
            return self.locals.join([self._branch(st.body), self._branch(st.orelse)])
        elif isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
            return self._loop(st)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                self.scan(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, None)
            return self.visit(st.body)
        elif type(st).__name__ in ("Try", "TryStar"):
            # Read by name: `ast.TryStar` is 3.11 and `ast.Match` 3.10, and this runs on 3.9.
            return self._try(st)
        elif type(st).__name__ == "Match":
            return self._match(st)
        else:
            for child in ast.iter_child_nodes(st):
                if isinstance(child, ast.expr):
                    self.scan(child)
        return True

    def _branch(self, stmts: list[ast.stmt]) -> dict[str, int | None] | None:
        """Explore `stmts` from the current state, then put the state back."""
        self.locals.open()
        completes = self.visit(stmts)
        left = self.locals.close()
        return left if completes else None

    def _loop(self, st: ast.For | ast.AsyncFor | ast.While) -> bool:
        """The body may run any number of times, none included: it is followed once
        and merged with the state the loop started in. `else` runs after that."""
        self.scan(st.test if isinstance(st, ast.While) else st.iter)
        self.locals.open()
        if not isinstance(st, ast.While):
            self._bind(st.target, None)
        completes = self.visit(st.body)
        left = self.locals.close()
        self.locals.join([{}, left if completes else None])
        return self.visit(st.orelse)

    def _try(self, st: ast.stmt) -> bool:
        """`else` starts where the body ended. A handler can start anywhere in the
        body, so from the state before it merged with the state after it, and
        `finally` runs on every way out."""
        self.locals.open()
        body_completes = self.visit(getattr(st, "body", []))
        body_left = self.locals.close()
        self.locals.join([{}, body_left])
        outcomes: list[dict[str, int | None] | None] = []
        if body_completes:
            self.locals.open()
            for name, depth in body_left.items():
                self.locals.set(name, depth)
            outcomes.append(self.locals.close() if self.visit(getattr(st, "orelse", [])) else None)
        for handler in getattr(st, "handlers", []):
            self.locals.open()
            self.scan(handler.type)
            if handler.name:
                self.locals.set(handler.name, None)
            outcomes.append(self.locals.close() if self.visit(handler.body) else None)
        completes = self.locals.join(outcomes)
        return self.visit(getattr(st, "finalbody", [])) and completes

    def _match(self, st: ast.stmt) -> bool:
        """Each case starts after the subject with its captures cleared, and
        matching no case is a way through too."""
        self.scan(getattr(st, "subject", None))
        outcomes: list[dict[str, int | None] | None] = [{}]
        for case in getattr(st, "cases", []):
            self.locals.open()
            for node in ast.walk(case.pattern):
                for captured in (getattr(node, "name", None), getattr(node, "rest", None)):
                    if isinstance(captured, str):
                        self.locals.set(captured, None)
            self.scan(case.guard)
            outcomes.append(self.locals.close() if self.visit(case.body) else None)
        return self.locals.join(outcomes)


# ---- An `eval` behind an allow-list check (AAK-TAINT-002) ----
#
# A calculator tool that admits only digits and operators before `eval` hands
# the sink nothing it can run: Python source needs a letter or an underscore to
# name anything, and without a name it can call nothing. So in a `@tool`
# function (not a `call_tool` handler) an `eval`, `exec` or `compile` call is
# not reported when all of the following hold, and is reported as before when
# any one does not:
#
# - Its first argument is a parameter, by name, and no other argument reads a
#   parameter. That parameter is bound nowhere else in the function: not
#   assigned, augmented or deleted, not a `for`, `with`, `except`, `:=`,
#   import, comprehension or `match` target, not declared global or nonlocal,
#   and not a parameter of a nested function or lambda. It is never assigned
#   to another name, and no attribute or item of it is read or written.
# - Earlier in the same straight-line code, a check on that parameter guards
#   the call: `if not <check>:` whose body ends in `raise` or `return`, before
#   the call in the same block, or `if <check>:` with the call in its body. The
#   check is `all(c in A for c in x)`, `set(x) <= A` or `re.fullmatch(P, x)`,
#   on the parameter itself, so a check on a copy (`x.strip()`) does not count.
# - The block may be the function's body, the branch the check guards, or the
#   body of a `try` (a raise in the check leaves the body, so the call runs
#   only after the check passed). No loop, `with`, `try`, comprehension,
#   generator, lambda, `def`, `class`, `match`, `await` or `yield` may sit
#   between the check and the call, and none may hold the call: in a loop, an
#   `except`, `else` or `finally`, or a comprehension, generator or lambda, it
#   is reported. A check inside a `try` or `with` guards nothing after it.
# - The allow-list A is a string literal, a list, tuple or set of them, or
#   `set()` or `frozenset()` of one, written inline or bound to a name: a local
#   bound once, earlier in the same straight-line code, or a module-level
#   assignment. The name is bound nowhere else, in the function for a local and
#   anywhere in the file for a module name (so an enclosing function cannot
#   shadow it), and it is only ever read as an operand of a comparison, so no
#   call can add to it. A local is read in no nested scope either: not by a
#   nested `def`, lambda or class, and by no comprehension or generator but the
#   check's own (`all(c in allowed for c in x)` reads it from its generator). The pattern P is a string literal of one character
#   class repeated (`[0-9+*/() -]+`), with no flags and no escape class (`\d`,
#   `\w`, `\s`).
# - Every character A or P admits is an ASCII digit, punctuation other than
#   `_`, or whitespace. An allow-list that admits a letter or an underscore,
#   however tightly, leaves the call reported.
# - `all`, `set`, `frozenset`, `eval`, `exec` and `compile` are bound nowhere
#   in the file, `re` only by a module-level `import re`, nothing assigns an
#   attribute of `re`, and the file has no star import.
#
# Each piece is read in one pass over the function and the file, so the cost
# is linear, and a function too deep to read leaves every call reported.

#: What an allow-list may admit. A name needs a letter or an underscore.
_ARITHMETIC_CHARS: frozenset[str] = frozenset(
    string.digits + string.punctuation.replace("_", "") + " \t\n\r\x0b\x0c"
)
#: The escapes a pattern's character class may use besides escaped punctuation.
_CLASS_ESCAPES: dict[str, str] = {"t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v"}
#: `try`, and from 3.11 `try`/`except*`, which has the same fields.
_TRY_STATEMENTS: tuple[type[ast.Try], ...] = (ast.Try,) + tuple(
    getattr(ast, name) for name in ("TryStar",) if hasattr(ast, name)
)
#: Statements whose bodies are not read, and that guard nothing after them.
_OPAQUE_STATEMENTS: tuple[type[ast.stmt], ...] = (
    ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
) + tuple(getattr(ast, name) for name in ("Match",) if hasattr(ast, name))
#: Expressions that run their body later, or not where they are written.
_DEFERRED: tuple[type[ast.expr], ...] = (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
#: Nodes whose body is a scope of its own inside the function.
_NESTED_SCOPES: tuple[type[ast.AST], ...] = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef) + _DEFERRED
#: What may not sit between a check and the call it guards.
_BARRIERS: tuple[type[ast.AST], ...] = (
    _TRY_STATEMENTS + _OPAQUE_STATEMENTS + _DEFERRED + (ast.Await, ast.Yield, ast.YieldFrom)
)
_CAPTURES: tuple[type[ast.AST], ...] = (ast.ExceptHandler,) + tuple(
    getattr(ast, name) for name in ("MatchAs", "MatchStar", "TypeVar", "ParamSpec", "TypeVarTuple") if hasattr(ast, name)
)


def _names_bound(node: ast.AST) -> list[str]:
    """The names `node` binds or declares: a store or `del` target, a
    parameter, an import (`*` for a star import), a `def` or `class`, an
    `except` or `match` capture, a type parameter, a `global` or `nonlocal`."""
    if isinstance(node, ast.Name):
        return [node.id] if isinstance(node.ctx, (ast.Store, ast.Del)) else []
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.alias):
        return [node.asname or node.name.split(".")[0]]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    if isinstance(node, _CAPTURES):
        captured = getattr(node, "name", None)
    else:
        captured = getattr(node, "rest", None)  # a mapping pattern's `**rest`
    return [captured] if isinstance(captured, str) else []


class _NameUses:
    """How each name is bound and used in a subtree, from one walk."""

    def __init__(self, root: ast.AST) -> None:
        self.bindings: dict[str, int] = {}
        self.loads: dict[str, int] = {}
        #: Loads inside a nested scope below `root`: a `def`, lambda, class,
        #: comprehension or generator.
        self.nested_loads: dict[str, int] = {}
        #: Loads that are an operand of a comparison, which reads a builtin
        #: collection without changing it.
        self.compared: dict[str, int] = {}
        #: Names with an attribute or item read or written (`x.y`, `x[0]`).
        self.subscripted: set[str] = set()
        #: Names with an attribute or item written or deleted.
        self.stored_into: set[str] = set()
        #: Names assigned to another name (`y = x`, `a, b = x, 1`, `with x as y`).
        self.aliased: set[str] = set()
        stack: list[tuple[ast.AST, bool]] = [(root, False)]
        while stack:
            node, nested = stack.pop()
            inner = nested or (node is not root and isinstance(node, _NESTED_SCOPES))
            stack.extend((child, inner) for child in ast.iter_child_nodes(node))
            for name in _names_bound(node):
                self.bindings[name] = self.bindings.get(name, 0) + 1
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.loads[node.id] = self.loads.get(node.id, 0) + 1
                if nested:
                    self.nested_loads[node.id] = self.nested_loads.get(node.id, 0) + 1
            elif isinstance(node, ast.Compare):
                for operand in (node.left, *node.comparators):
                    if isinstance(operand, ast.Name):
                        self.compared[operand.id] = self.compared.get(operand.id, 0) + 1
            elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.value, ast.Name):
                self.subscripted.add(node.value.id)
                if not isinstance(node.ctx, ast.Load):
                    self.stored_into.add(node.value.id)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
                self._alias(node.value)
            elif isinstance(node, ast.withitem):
                self._alias(node.context_expr)

    def _alias(self, value: ast.expr) -> None:
        for part in value.elts if isinstance(value, (ast.Tuple, ast.List)) else [value]:
            if isinstance(part, ast.Name):
                self.aliased.add(part.id)


class _FileFacts:
    """What the allow-list skip needs from a whole file. Read on first use,
    when a `@tool` function first reaches an `eval`, `exec` or `compile`."""

    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree
        self._uses: _NameUses | None = None
        self._module_values: dict[str, ast.expr] = {}
        self._re_imported = False
        self._constants: dict[str, bool] = {}
        self._patterns: dict[str, bool] = {}

    @property
    def uses(self) -> _NameUses:
        if self._uses is None:
            self._uses = _NameUses(self._tree)
            for st in self._tree.body:
                bound = _single_target(st)
                if bound is not None:
                    self._module_values[bound[0]] = bound[1]
                elif isinstance(st, ast.Import) and any(a.name == "re" and a.asname in (None, "re") for a in st.names):
                    self._re_imported = True
        return self._uses

    def unbound(self, name: str) -> bool:
        """True when nothing in the file binds `name`, so it is the builtin."""
        uses = self.uses
        return name not in uses.bindings and "*" not in uses.bindings

    @property
    def re_module(self) -> bool:
        """True when `re` is the standard module and nothing replaces its functions."""
        uses = self.uses
        return self._re_imported and uses.bindings.get("re") == 1 and "re" not in uses.stored_into

    def constant(self, name: str) -> bool:
        """True when `name` is a module-level allow-list that nothing in the file can change."""
        if name not in self._constants:
            uses, value = self.uses, self._module_values.get(name)
            self._constants[name] = (
                value is not None and uses.bindings.get(name) == 1
                and uses.loads.get(name, 0) == uses.compared.get(name, 0)
                and _arithmetic_allow_list(value, self)
            )
        return self._constants[name]

    def pattern(self, pattern: str) -> bool:
        if pattern not in self._patterns:
            self._patterns[pattern] = _arithmetic_pattern(pattern)
        return self._patterns[pattern]


def _single_target(st: ast.stmt) -> tuple[str, ast.expr] | None:
    """(name, value) for `name = value` or `name: T = value`."""
    if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
        return st.targets[0].id, st.value
    if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
        return st.target.id, st.value
    return None


def _arithmetic_allow_list(value: ast.expr, facts: _FileFacts) -> bool:
    """A string literal, a list, tuple or set of them, or `set()` / `frozenset()`
    of one, admitting only `_ARITHMETIC_CHARS`."""
    if (
        isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in ("set", "frozenset")
        and len(value.args) == 1 and not value.keywords and facts.unbound(value.func.id)
    ):
        value = value.args[0]
    parts = value.elts if isinstance(value, (ast.List, ast.Tuple, ast.Set)) else [value]
    return all(
        isinstance(part, ast.Constant) and isinstance(part.value, str) and _ARITHMETIC_CHARS.issuperset(part.value)
        for part in parts
    )


def _class_item(body: str, index: int) -> tuple[str | None, int]:
    """The character a pattern's class names at `index`, and where the next
    item starts. None for an escape class or code (`\\d`, `\\x41`) or a bracket."""
    char = body[index]
    if char == "\\":
        escaped = body[index + 1:index + 2]
        if escaped in _CLASS_ESCAPES:
            return _CLASS_ESCAPES[escaped], index + 2
        return (escaped if escaped and escaped in string.punctuation else None), index + 2
    return (None if char in "[]" else char), index + 1


def _arithmetic_pattern(pattern: str) -> bool:
    """True for one character class repeated, `[...]+` or `[...]*`, optionally
    between `^` and `$`, that names only `_ARITHMETIC_CHARS`: literal
    characters, ranges between them, and escaped punctuation or `\\t`, `\\n`,
    `\\r`, `\\f`, `\\v`. One pass, so a crafted pattern costs its length."""
    start = 1 if pattern.startswith("^") else 0
    end = len(pattern) - 1 if pattern.endswith("$") else len(pattern)
    if end - start < 4 or pattern[start] != "[" or pattern[end - 2:end] not in ("]+", "]*"):
        return False
    body = pattern[start + 1:end - 2]
    if body.startswith("^"):
        return False
    index = 0
    while index < len(body):
        first, index = _class_item(body, index)
        if first is None or first not in _ARITHMETIC_CHARS:
            return False
        if index + 1 < len(body) and body[index] == "-":
            last, index = _class_item(body, index + 1)
            if last is None or last not in _ARITHMETIC_CHARS or last < first:
                return False
            if not _ARITHMETIC_CHARS.issuperset(map(chr, range(ord(first), ord(last) + 1))):
                return False
    return True


def _allow_list(
    node: ast.expr, facts: _FileFacts, uses: _NameUses, bound: set[str], own_generator: bool = False
) -> bool:
    """True for an allow-list nothing can change (see the block comment above).

    `own_generator` is True when `node` is read from the check's generator,
    the one nested read a local may have.
    """
    if not isinstance(node, ast.Name):
        return _arithmetic_allow_list(node, facts)
    if node.id in bound:
        return (
            uses.bindings.get(node.id) == 1 and uses.loads.get(node.id, 0) == uses.compared.get(node.id, 0)
            and uses.nested_loads.get(node.id, 0) == (1 if own_generator else 0)
        )
    return facts.constant(node.id)


def _checked_name(test: ast.expr, facts: _FileFacts, uses: _NameUses, bound: set[str]) -> str | None:
    """The name `test` proves holds only allow-listed characters when it is true."""
    if isinstance(test, ast.Call) and not test.keywords:
        func, args = test.func, test.args
        if (
            isinstance(func, ast.Name) and func.id == "all" and len(args) == 1
            and isinstance(args[0], ast.GeneratorExp) and len(args[0].generators) == 1 and facts.unbound("all")
        ):
            elt, comp = args[0].elt, args[0].generators[0]
            if (
                not comp.ifs and not comp.is_async and isinstance(comp.target, ast.Name)
                and isinstance(comp.iter, ast.Name) and isinstance(elt, ast.Compare) and len(elt.ops) == 1
                and isinstance(elt.ops[0], ast.In) and isinstance(elt.left, ast.Name)
                and elt.left.id == comp.target.id
                and _allow_list(elt.comparators[0], facts, uses, bound, own_generator=True)
            ):
                return comp.iter.id
            return None
        if (
            isinstance(func, ast.Attribute) and func.attr == "fullmatch" and isinstance(func.value, ast.Name)
            and func.value.id == "re" and len(args) == 2 and isinstance(args[0], ast.Constant)
            and isinstance(args[0].value, str) and isinstance(args[1], ast.Name)
            and facts.re_module and facts.pattern(args[0].value)
        ):
            return args[1].id
        return None
    if (
        isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.LtE)
        and isinstance(test.left, ast.Call) and isinstance(test.left.func, ast.Name)
        and test.left.func.id == "set" and len(test.left.args) == 1 and not test.left.keywords
        and isinstance(test.left.args[0], ast.Name) and facts.unbound("set")
        and _allow_list(test.comparators[0], facts, uses, bound)
    ):
        return test.left.args[0].id
    return None


def _barrier_statements(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> set[int]:
    """The statements in `func_def` that are or hold one of `_BARRIERS`.

    Each barrier climbs to the function through its ancestors, and a climb
    stops at a node an earlier one passed, so every node is climbed once.
    """
    parents: dict[int, ast.AST] = {}
    barriers: list[ast.AST] = []
    for node in ast.walk(func_def):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
        if node is not func_def and isinstance(node, _BARRIERS):
            barriers.append(node)
    held: set[int] = set()
    climbed: set[int] = set()
    for barrier in barriers:
        current: ast.AST | None = barrier
        while current is not None and current is not func_def and id(current) not in climbed:
            climbed.add(id(current))
            if isinstance(current, ast.stmt):
                held.add(id(current))
            current = parents.get(id(current))
    return held


def _mark_guarded_calls(expr: ast.expr, guarded: set[str], param_names: set[str], marked: set[int]) -> None:
    """Add to `marked` each call in `expr`, outside a lambda or comprehension,
    whose first argument is a name in `guarded` and whose other arguments read
    no parameter. The caller applies it to `eval`, `exec` and `compile` only."""
    stack: list[ast.AST] = [expr]
    while stack:
        node = stack.pop()
        if isinstance(node, _DEFERRED):
            continue
        stack.extend(ast.iter_child_nodes(node))
        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if not isinstance(first, ast.Name) or first.id not in guarded:
            continue
        rest = [*node.args[1:], *(keyword.value for keyword in node.keywords)]
        if not any(isinstance(n, ast.Name) and n.id in param_names for part in rest for n in ast.walk(part)):
            marked.add(id(node))


def _allow_listed_sinks(func_def: ast.FunctionDef | ast.AsyncFunctionDef, facts: _FileFacts) -> frozenset[int]:
    """The `eval`, `exec` and `compile` calls in a `@tool` function that an
    allow-list check guards (see the block comment above), by node id.

    A function too deep to read gives none, so every call is reported as
    before and the rest of the file is still scanned.
    """
    try:
        return _read_allow_listed_sinks(func_def, facts)
    except RecursionError:
        return frozenset()


def _read_allow_listed_sinks(func_def: ast.FunctionDef | ast.AsyncFunctionDef, facts: _FileFacts) -> frozenset[int]:
    if not all(facts.unbound(name) for name in ("eval", "exec", "compile")):
        return frozenset()
    uses = _NameUses(func_def)
    args = func_def.args
    candidates = {
        arg.arg for arg in args.posonlyargs + args.args + args.kwonlyargs
        if uses.bindings.get(arg.arg) == 1 and arg.arg not in uses.subscripted and arg.arg not in uses.aliased
    }
    if not candidates:
        return frozenset()
    param_names = _get_param_names(func_def)
    barriers = _barrier_statements(func_def)
    marked: set[int] = set()
    # Each block is read once, in order, with the parameters a check has
    # guarded and the allow-list locals bound so far on the way to it.
    work: list[tuple[list[ast.stmt], frozenset[str], frozenset[str]]] = [(func_def.body, frozenset(), frozenset())]
    while work:
        block, guarded_before, bound_before = work.pop()
        guarded, bound = set(guarded_before), set(bound_before)
        for st in block:
            if isinstance(st, _TRY_STATEMENTS):
                work.append((st.body, frozenset(guarded), frozenset(bound)))
                guarded.clear()
                bound.clear()
                continue
            if isinstance(st, _OPAQUE_STATEMENTS):
                guarded.clear()
                bound.clear()
                continue
            if isinstance(st, ast.If):
                test, negated = st.test, False
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    test, negated = test.operand, True
                checked = _checked_name(test, facts, uses, bound)
                if checked is not None and checked in candidates:
                    exits = isinstance(st.body[-1], (ast.Return, ast.Raise))
                    if not negated:
                        work.append((st.body, frozenset(guarded | {checked}), frozenset(bound)))
                    elif exits:
                        work.append((st.orelse, frozenset(guarded | {checked}), frozenset(bound)))
                        guarded.add(checked)
                    # What reaches the statements after the `if`: both branches,
                    # or only `else` when the body of an `if not` exits.
                    reaching = st.orelse if negated and exits else st.body + st.orelse
                    if any(id(inner) in barriers for inner in reaching):
                        guarded.clear()
                        bound.clear()
                    continue
                _mark_guarded_calls(st.test, guarded, param_names, marked)
            else:
                for child in ast.iter_child_nodes(st):
                    if isinstance(child, ast.expr):
                        _mark_guarded_calls(child, guarded, param_names, marked)
                local = _single_target(st)
                if local is not None and _arithmetic_allow_list(local[1], facts):
                    bound.add(local[0])
            if id(st) in barriers:
                guarded.clear()
                bound.clear()
    return frozenset(marked)


def _alias_flow_findings(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    param_names: set[str],
    imported: dict[str, str] | None = None,
    name_only: set[int] | None = None,
) -> list[Finding]:
    """Findings for sink calls a handler's locals reach (see the block comment above)."""
    flow = _HandlerFlow(func_def, rel_path, param_names, imported, name_only)
    flow.visit(func_def.body)
    return flow.findings


def _analyse_tool_function(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    call_tool_handler: bool = False,
    file_facts: _FileFacts | None = None,
    imported: dict[str, str] | None = None,
) -> list[Finding]:
    """Perform taint analysis on a single @tool function.

    Args:
        func_def: The decorated function.
        rel_path: Its file, relative to the project root.
        call_tool_handler: The function is a low-level `call_tool` handler. Its
            locals are followed for AAK-TAINT-001, -003, -004 and -006 (see
            `_alias_flow_findings`), and AAK-TAINT-007 and -008 do not apply.
            Those two describe one tool (its parameters carry no type hints; its
            body reaches three kinds of sink), and the handler is every tool's
            dispatcher: its signature is the SDK's and its schema comes from
            `list_tools`, so on it they would report the SDK's shape, not a
            tool's. The flow rules, 001 to 006, apply to it as to any tool.
        file_facts: The file's facts for the allow-list skip, given for a
            `@tool` function only: it leaves out an AAK-TAINT-002 call an
            allow-list check guards (see `_allow_listed_sinks`). None, as for a
            `call_tool` handler, reads no checks.
        imported: What the names the file binds by import stand for (see
            `_import_names`), so a sink imported under another name is found.
    """
    findings: list[Finding] = []
    param_names = _get_param_names(func_def)
    func_name = func_def.name
    name_only = _name_only_calls(func_def)

    # Track which rule categories have dangerous sinks (for AAK-TAINT-008)
    triggered_categories: set[str] = set()
    guarded: frozenset[int] | None = None

    # Walk function body for Call nodes
    for node in ast.walk(func_def):
        if not isinstance(node, ast.Call):
            continue

        callee = _resolve_sink(node, imported or {})
        if callee is None:
            continue

        rule_id = _SINK_LOOKUP.get(callee)
        if rule_id is None or (callee in _NAME_ONLY_SINKS and id(node) in name_only):
            continue

        # Track category regardless of param taint
        triggered_categories.add(rule_id)

        # Check if any argument is a tainted parameter, unless the call's
        # target is a literal (see `_fixed_target`)
        if param_names and _call_uses_param(node, param_names) and not _fixed_target(node, callee):
            if rule_id == "AAK-TAINT-002" and file_facts is not None:
                if guarded is None:
                    guarded = _allow_listed_sinks(func_def, file_facts)
                if id(node) in guarded:
                    continue
            sink_label = f"{callee[0]}.{callee[1]}" if callee[0] else callee[1]
            line = getattr(node, "lineno", func_def.lineno)
            findings.append(make_finding(
                rule_id,
                rel_path,
                f"Function '{func_name}': param flows to {sink_label}()",
                line,
            ))

    if call_tool_handler:
        findings.extend(_alias_flow_findings(func_def, rel_path, param_names, imported, name_only))
        return findings

    # AAK-TAINT-007: No type hints on any parameter
    if param_names and not _has_any_type_hints(func_def):
        findings.append(make_finding(
            "AAK-TAINT-007",
            rel_path,
            f"Function '{func_name}': no type hints on any parameter",
            func_def.lineno,
        ))

    # AAK-TAINT-008: >= 3 different dangerous sink categories in the body
    if len(triggered_categories) >= 3:
        cats = ", ".join(sorted(triggered_categories))
        findings.append(make_finding(
            "AAK-TAINT-008",
            rel_path,
            f"Function '{func_name}': {len(triggered_categories)} dangerous sink categories ({cats})",
            func_def.lineno,
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan Python files for taint flows in @tool functions.

    Algorithm:
        1. Recursively find .py files (skip SKIP_DIRS, skip files > 1 MB).
        2. Parse each file with ``ast.parse``.
        3. Walk AST for FunctionDef / AsyncFunctionDef with tool decorators.
        4. For each tool function, collect parameter names and walk the body
           for calls to dangerous sinks that receive a parameter directly.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for py_path in project_root.rglob("*.py"):
        # Skip excluded directories
        if in_skip_dir(py_path, project_root):
            continue
        if not py_path.is_file():
            continue

        # Skip large files
        try:
            if py_path.stat().st_size > 1_000_000:
                continue
            source = py_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(py_path.relative_to(project_root))

        # Parse AST
        try:
            tree = parse_python(source, py_path)
        except SyntaxError:
            continue

        scanned_files.add(rel_path)
        file_facts = _FileFacts(tree)

        # Item reads and a handler's branches are followed recursively, so a
        # file's tool functions and handlers are analysed in one `walk_tree`
        # (one hand-over to the worker before 3.11, not one per function, and
        # none for a file with neither), and a file too deep even for that is
        # refused alone, its findings with it.
        with refusing_overflow(py_path):
            targets: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]] = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if _is_tool_function(node):
                        targets.append((node, False))
                    elif _is_call_tool_handler(node):
                        targets.append((node, True))
            if targets:
                findings.extend(walk_tree(_analyse_functions, targets, rel_path, file_facts, _import_names(tree)))

    return findings, scanned_files


def _analyse_functions(
    targets: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]],
    rel_path: str,
    file_facts: _FileFacts,
    imported: dict[str, str],
) -> list[Finding]:
    """`_analyse_tool_function` on each (function, is a `call_tool` handler).
    A tool function is given the file's facts for the allow-list skip, and a
    handler is not, as each was analysed before."""
    file_findings: list[Finding] = []
    for node, call_tool_handler in targets:
        if call_tool_handler:
            file_findings.extend(_analyse_tool_function(node, rel_path, call_tool_handler=True, imported=imported))
        else:
            file_findings.extend(_analyse_tool_function(node, rel_path, file_facts=file_facts, imported=imported))
    return file_findings
