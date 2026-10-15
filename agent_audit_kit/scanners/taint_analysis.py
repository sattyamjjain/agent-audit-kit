from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, in_skip_dir

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
# checks) are left out pending a decision. `@tool` functions keep the behaviour
# they had: across those repositories the pass added a single finding in one,
# and it was unclear.
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
        self, func_def: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str, param_names: set[str]
    ) -> None:
        self.func_def = func_def
        self.rel_path = rel_path
        self.params = param_names
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
        callee = _resolve_callee(call)
        rule_id = _SINK_LOOKUP.get(callee) if callee is not None else None
        if callee is None or rule_id is None or rule_id not in _ALIAS_FOLLOWED_RULES:
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


def _alias_flow_findings(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str, param_names: set[str]
) -> list[Finding]:
    """Findings for sink calls a handler's locals reach (see the block comment above)."""
    flow = _HandlerFlow(func_def, rel_path, param_names)
    flow.visit(func_def.body)
    return flow.findings


def _analyse_tool_function(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    call_tool_handler: bool = False,
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
    """
    findings: list[Finding] = []
    param_names = _get_param_names(func_def)
    func_name = func_def.name

    # Track which rule categories have dangerous sinks (for AAK-TAINT-008)
    triggered_categories: set[str] = set()

    # Walk function body for Call nodes
    for node in ast.walk(func_def):
        if not isinstance(node, ast.Call):
            continue

        callee = _resolve_callee(node)
        if callee is None:
            continue

        rule_id = _SINK_LOOKUP.get(callee)
        if rule_id is None:
            continue

        # Track category regardless of param taint
        triggered_categories.add(rule_id)

        # Check if any argument is a tainted parameter, unless the call's
        # target is a literal (see `_fixed_target`)
        if param_names and _call_uses_param(node, param_names) and not _fixed_target(node, callee):
            sink_label = f"{callee[0]}.{callee[1]}" if callee[0] else callee[1]
            line = getattr(node, "lineno", func_def.lineno)
            findings.append(make_finding(
                rule_id,
                rel_path,
                f"Function '{func_name}': param flows to {sink_label}()",
                line,
            ))

    if call_tool_handler:
        findings.extend(_alias_flow_findings(func_def, rel_path, param_names))
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
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            continue

        scanned_files.add(rel_path)

        # Walk top-level and nested function definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_tool_function(node):
                    findings.extend(_analyse_tool_function(node, rel_path))
                elif _is_call_tool_handler(node):
                    findings.extend(_analyse_tool_function(node, rel_path, call_tool_handler=True))

    return findings, scanned_files
