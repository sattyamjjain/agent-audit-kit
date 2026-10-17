"""The walks a raised recursion limit lets reach the bottom of a deep tree stay
linear on the way down.

Seven scanners did work proportional to the tree below every call or operator
they visited. Where the walk recursed, the default limit used to stop it a few
hundred levels down (main crashed there), and with `walk_tree`'s room it ran to
the bottom: a nested call chain cost the square of its depth, about 1 to 7 s a
chain at 3,000 levels, and a file holds dozens. Two did it in loops the limit
never stopped, so main paid in full: stdio_injection's search of a sink's
argument (four calls on a 3,000-level argument took 33 s) and
mcp_auth_pathtraversal's of a `+` chain (four chains of 1,500 took 4.1 s); and
CrewAI's search for the function around a call was quadratic on a flat file
too (3,000 calls at module level, 18 s). Each now reads every node once, and
answers as it did, checked against the old code on thousands of generated
shapes.
"""

from __future__ import annotations

import ast
import random
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Callable

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


_LINEAR = """
    import sys, time
    from pathlib import Path
    module = __import__("agent_audit_kit.scanners." + sys.argv[1], fromlist=["scan"])
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        findings, _ = module.scan(Path(sys.argv[2]))
        best = min(best, time.process_time() - started)
    print(best, len(findings))
"""


def _child_scan_seconds(scanner: str, root: Path) -> tuple[float, int]:
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_LINEAR), scanner, str(root)], capture_output=True, text=True,
        timeout=300, cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PATH": "", "HOME": tempfile.mkdtemp(prefix="aak-home-")},
    )
    assert out.returncode == 0, out.stderr[-1000:]
    seconds, count = out.stdout.split()
    return float(seconds), int(count)


def _assert_linear(tmp_path: Path, scanner: str, shape: Callable[[int], str], small: int) -> None:
    """The scanner's time at two sizes ten times apart, in a child: linear grows
    about ten times, the old work about a hundred."""
    times = []
    for n in (small, 10 * small):
        root = tmp_path / f"n{n}"
        _write(root, "server.py", shape(n))
        seconds, _ = _child_scan_seconds(scanner, root)
        times.append(seconds)
    small_seconds, large_seconds = times
    assert large_seconds < 3.0 and large_seconds < 40 * small_seconds + 0.25, (small_seconds, large_seconds)


# ---------------------------------------------------------------------------
# CrewAI: the function around each call, found in one pass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("shape", "small"), [
    # Every call searched the whole file for its function: calls outside every
    # function, and a nested call chain in one.
    (lambda n: "import crewai\n" + "f()\n" * n, 300),
    (lambda n: "import crewai\n\n\ndef build():\n    return f" + "()" * n + "\n", 300),
    # Every tool call searched the body around it, the whole file outside every
    # function, for its guard, and some for taint hints too.
    (lambda n: "import crewai\n" + "CodeInterpreterTool(unsafe_mode=True)\n" * n, 500),
    (lambda n: "import crewai\n" + "JSONSearchTool(file_path=request.args)\n" * n, 500),
    (lambda n: "import crewai\n" + "RagTool(url=request.args)\n" * n, 500),
], ids=["calls at module level", "a nested call chain", "code interpreters", "JSON search tools", "RAG tools"])
def test_crewai_finds_each_calls_function_in_linear_time(
    tmp_path: Path, shape: Callable[[int], str], small: int
) -> None:
    """At 3,000 calls the old search took about 3 s for the chain and 18 s for
    the calls at module level, and the guard searches 4.5, 2.3 and 1.6 s for
    the three tools; each grew with the square of their number."""
    _assert_linear(tmp_path, "crewai_rce_chain", shape, small)


def _old_outermost(tree: ast.AST, call: ast.Call) -> ast.AST | None:
    """The function CrewAI's search found for `call` before `_outermost_functions`."""
    for parent in ast.walk(tree):
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(c is call for c in ast.walk(parent) if isinstance(c, ast.Call)):
                return parent
    return None


def test_crewai_finds_the_function_it_did_for_every_call() -> None:
    from agent_audit_kit.scanners import crewai_rce_chain

    rng = random.Random(1019)
    fixtures = sorted((ROOT / "tests" / "fixtures").rglob("*.py"))
    sources = [p.read_text(encoding="utf-8", errors="replace") for p in fixtures]

    def module(depth: int) -> str:
        out = []
        for _ in range(rng.randrange(1, 4)):
            kind = rng.randrange(4)
            if kind == 0 and depth > 0:
                deco = rng.choice(["", "@d(f())\n", "@tool\n"])
                kw = rng.choice(["async def", "def"])
                out.append(f"{deco}{kw} g(a=h()):\n" + textwrap.indent(module(depth - 1) or "pass\n", "    "))
            elif kind == 1 and depth > 0:
                out.append("class C:\n" + textwrap.indent(module(depth - 1) or "pass\n", "    "))
            elif kind == 2:
                out.append("x = (lambda: k())()\n")
            else:
                out.append("f(g(h()))\n")
        return "".join(out)

    sources += [module(3) for _ in range(300)]
    checked = 0
    for source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        found = crewai_rce_chain._outermost_functions(tree)
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            assert found.get(id(call)) is _old_outermost(tree, call), source[:300]
            checked += 1
    assert checked > 5_000


# ---------------------------------------------------------------------------
# stdio_injection: a sink's argument, searched once
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("shape", "small"), [
    # Every node of a sink's argument searched the argument below it again,
    # whether or not it found a taint source in the end: four calls on a
    # 3,000-level argument took 33 s.
    (lambda n: "from mcp.server.fastmcp import FastMCP\nimport os\n\n\n@mcp.tool()\ndef run(arg):\n"
     + "".join(f"    os.system(x{'[0]' * n})\n" for _ in range(4)), 300),
    # Every one of 190 nested sinks searched the whole argument for taint and
    # unparsed it whole for 200 characters of evidence: 4.0 s at 20,000 names.
    (lambda n: "from mcp.server.fastmcp import FastMCP\nimport os\n\n\n@mcp.tool()\ndef run(cmd):\n    "
     + "os.system(" * 190 + "(" + ", ".join(["cmd"] * n) + ")" + ")" * 190 + "\n", 3_000),
], ids=["a deep argument", "nested sinks"])
def test_stdio_injection_searches_a_sink_argument_in_linear_time(
    tmp_path: Path, shape: Callable[[int], str], small: int
) -> None:
    _assert_linear(tmp_path, "stdio_injection", shape, small)


def test_a_sink_snippet_is_the_start_of_its_unparsed_source_on_every_shape() -> None:
    """The evidence keeps the first 200 characters of `ast.unparse(call)`, now
    built from each inner call's own start: the same text on calls nested in
    calls, keywords, starred arguments, lambdas, comprehensions and f-strings."""
    from agent_audit_kit.scanners import stdio_injection

    rng = random.Random(1021)
    names = ["cmd", "x", "'a b'", "1.5", "b'\\x00'", "None"]

    def expr(depth: int) -> str:
        if depth <= 0 or rng.random() < 0.2:
            return rng.choice(names)
        inner = expr(depth - 1)
        return rng.choice([
            f"os.system({inner}, {expr(depth - 2)})", f"f({inner}, k={expr(depth - 2)})", f"g(*{inner})",
            f"h(**{inner})", f"{inner}()", f"(lambda a={inner}: a)()", f"[{inner} for _ in {expr(depth - 2)}]",
            f"f'{{{inner}!r}} {{{expr(depth - 2)}:>4}}'", f"{{{inner}: {expr(depth - 2)}}}", f"({inner}, {inner})",
            f"{inner} + {expr(depth - 2)}", f"{inner}.attr", f"{inner}[0]", f"q({inner} for _ in y)",
            "'" + "x" * rng.randrange(150, 260) + "'",
        ])

    checked = 0
    for _ in range(3_000):
        source = expr(7)
        try:
            tree = ast.parse(source)
        except SyntaxError:  # an f-string nested in its own quotes, before 3.12
            continue
        heads: dict[int, str] = {}
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            assert stdio_injection._call_head(call, heads)[:200] == ast.unparse(call)[:200], source
            checked += 1
    assert checked > 5_000


def _old_node_references_taint(node: ast.AST) -> bool:
    """`stdio_injection._node_references_taint` before it read each chain once."""
    from agent_audit_kit.scanners import stdio_injection as m

    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in m._TAINT_NAME:
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
                    if tuple(chain[:length][-2:]) in m._TAINT_ATTR_CHAINS:
                        return True
            if isinstance(cur, ast.Name) and len(chain) >= 2:
                if (chain[-2], chain[-1]) in m._TAINT_ATTR_CHAINS:
                    return True
        if isinstance(sub, ast.Call) and m._call_fqn(sub.func) == "json.loads":
            for arg in sub.args:
                if _old_node_references_taint(arg):
                    return True
    return False


def _old_args_reference_taint(call: ast.Call, taint_names: set[str]) -> bool:
    for arg in call.args:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Name) and sub.id in taint_names:
                return True
            if _old_node_references_taint(sub):
                return True
    return False


def test_the_stdio_taint_search_answers_as_it_did_on_every_shape() -> None:
    from agent_audit_kit.scanners import stdio_injection

    rng = random.Random(1020)
    words = ["sys", "stdin", "process", "request", "req", "event", "body", "json", "query", "params", "read",
             "x", "cmd", "os", "environ", "loads", "data", "arg"]

    def expr(depth: int) -> str:
        if depth <= 0 or rng.random() < 0.2:
            return rng.choice(words)
        inner = expr(depth - 1)
        kind = rng.randrange(6)
        if kind < 3:
            return f"{inner}.{rng.choice(words)}"
        if kind == 3:
            return f"json.loads({inner})"
        if kind == 4:
            return f"{inner}({expr(depth - 2)})"
        return f"{inner} + {expr(depth - 2)}"

    differing = []
    for _ in range(6_000):
        source = f"os.system({expr(6)}, {expr(4)})"
        call = ast.parse(source).body[0].value
        assert isinstance(call, ast.Call)
        names = set(rng.sample(words, 2)) | set(stdio_injection._TAINT_NAME)
        if (stdio_injection._node_references_taint(call) != _old_node_references_taint(call)
                or stdio_injection._args_reference_taint(call, names) != _old_args_reference_taint(call, names)):
            differing.append(source)
        # One memo for the file answers every call in it, outer and inner, in walk order.
        holds = stdio_injection._taint_memo(names)
        for inner in (n for n in ast.walk(call) if isinstance(n, ast.Call)):
            if stdio_injection._args_reference_taint(inner, names, holds) != _old_args_reference_taint(inner, names):
                differing.append(source)
    assert not differing, differing[:3]


# ---------------------------------------------------------------------------
# Callees and `/` chains, read once, in the walks a raised limit lets reach the
# bottom
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("scanner", "shape", "small"), [
    # Every call's callee was unparsed, the whole chain below it, and every
    # `.error` call's receiver.
    ("mcp_noauth_default", lambda n: (
        "from mcp.server.fastmcp import FastMCP\nHOST = '0.0.0.0'\nAPI_KEY = ''\n"
        "if not API_KEY:\n    warn" + "()" * n + "\n"), 300),
    ("mcp_noauth_default", lambda n: (
        "from mcp.server.fastmcp import FastMCP\nHOST = '0.0.0.0'\nAPI_KEY = ''\n"
        "if not API_KEY:\n    x" + "().error" * n + "()\n"), 120),
    # A callee that is neither a name nor an attribute ends as its last operand
    # does, here `sys.exit` in brackets: 150 such callees nested around a call
    # of n arguments. Reading each whole source re-read the arguments 150 times,
    # 5.7 s at the larger size (the tokenizer nests no more than 200 brackets).
    ("mcp_noauth_default", lambda n: (
        "from mcp.server.fastmcp import FastMCP\nHOST = '0.0.0.0'\nAPI_KEY = ''\n"
        "if not API_KEY:\n    warn()\n    " + "(" * 150 + "x(" + "a, " * n + "a)"
        + " + (y if z else sys.exit))()" * 150 + "\n"), 10_000),
    ("project_deal_drift", lambda n: "import stripe\n\n\ndef set_price(item):\n    return f" + "()" * n + "\n", 300),
    # Every call built its callee's dotted name down to the bottom of the chain.
    ("mcp_stdio_params", lambda n: "import subprocess\n\n\n" + "".join(
        f"def launch{i}(cmd):\n    return run" + "()" * n + "\n\n\n" for i in range(4)), 300),
    ("mcp_marketplace_fetch", lambda n: "import requests\n\n\n" + "".join(
        f"def refresh{i}(url):\n    return requests.get" + "()" * n + "\n\n\n" for i in range(4)), 300),
    # Every `+` of a chain searched and unparsed the chain below it.
    ("mcp_auth_pathtraversal", lambda n: (
        "from mcp.server.fastmcp import FastMCP\nimport os\n\n\n" + "".join(
            f"def load{i}(token):\n    p = base + {' + '.join(['token'] * n)}\n    return os.path.exists(p)\n\n\n"
            for i in range(4))), 150),
])
def test_a_walk_that_reaches_the_bottom_of_a_call_chain_stays_linear(
    tmp_path: Path, scanner: str, shape: Callable[[int], str], small: int
) -> None:
    """At the larger size the old work took 1.3 s to 7.7 s, and it grew with
    the square of the chain."""
    _assert_linear(tmp_path, scanner, shape, small)


def _old_body_is_warn_only(body: list[ast.stmt]) -> bool:
    """`mcp_noauth_default._body_is_warn_only` before it read each source once."""
    from agent_audit_kit.scanners import mcp_noauth_default as m

    saw_warn = False
    for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(stmt, (ast.Raise, ast.Return)):
            return False
        if isinstance(stmt, ast.Call):
            name = ast.unparse(stmt.func)
            if m._call_stops(name):
                return False
            if m._WARN_CALL_RE.search(name):
                saw_warn = True
    return saw_warn


_NAMES = ["warn", "print", "exit", "quit", "_exit", "abort", "foo", "logger", "parser", "arg_parser", "ctx",
          "context", "atexit", "log_equity", "getLogger", "console", "sys", "click", "x", "Warning"]
_ATTRS = ["warning", "warn", "error", "fail", "exit", "abort", "register", "info", "getLogger", "run",
          "get_current_context", "on_exit", "messages", "create", "chat", "completions", "client"]


# Expressions a callee can be that end as their last operand does, or in a
# bracket the unparser adds: `{0}` is the operand at the end, `{1}` another.
_ENDING_AS_AN_OPERAND = [
    "({1} if {1} else {0})", "({0} if {1} else {1})", "({1} or {0})", "({1} and {0})", "(lambda: {0})",
    "({1} + {0})", "({1} ** {0})", "({1} + ({1} if {1} else {0}))", "(-{0})", "(not {0})", "({1} < {0})",
    "({1} < {1} in {0})", "(await {0})", "(y := {0})", "(yield {0})", "(lambda x=1: {1} or {0})",
]


def _random_expr(rng: random.Random, depth: int) -> str:
    if depth <= 0 or rng.random() < 0.25:
        return rng.choice(_NAMES)
    inner = _random_expr(rng, depth - 1)
    kind = rng.randrange(11)
    if kind < 3:
        return f"{inner}.{rng.choice(_ATTRS)}"
    if kind < 5:
        args = ", ".join(_random_expr(rng, depth - 2) for _ in range(rng.randrange(3)))
        return f"{inner}({args})"
    if kind == 5:
        return f"{inner}[{rng.choice(['0', repr(rng.choice(_NAMES))])}]"
    if kind == 6:
        return "f'{" + inner + "} " + rng.choice(_NAMES) + "'"
    if kind == 7:
        return repr(rng.choice(_NAMES) + "." + rng.choice(_ATTRS))
    return rng.choice(_ENDING_AS_AN_OPERAND).format(inner, _random_expr(rng, depth - 2))


def _random_body(rng: random.Random, depth: int = 3) -> str:
    lines = []
    for _ in range(rng.randrange(1, 5)):
        kind = rng.randrange(10)
        if kind < 6:
            lines.append(_random_expr(rng, 5) + "()" * rng.randrange(1, 3))
        elif kind == 6 and depth > 0:
            nested = textwrap.indent(_random_body(rng, depth - 1), "    ")
            lines.append("if x:\n" + nested)
        elif kind == 7:
            lines.append(rng.choice(["raise SystemExit(1)", "return None"]))
        else:
            lines.append(f"y = {_random_expr(rng, 4)}()")
    return "\n".join(lines) + "\n"


def test_the_warn_only_test_answers_as_it_did_on_every_shape() -> None:
    from agent_audit_kit.scanners import mcp_noauth_default

    rng = random.Random(1017)
    differing, checked = [], 0
    for _ in range(4_000):
        source = "def f():\n" + textwrap.indent(_random_body(rng), "    ")
        try:
            body = ast.parse(source).body[0].body
        except SyntaxError:  # an f-string nested in its own quotes, before 3.12
            continue
        checked += 1
        if mcp_noauth_default._body_is_warn_only(body) != _old_body_is_warn_only(body):
            differing.append(source)
    assert not differing, differing[:3]
    assert checked > 2_000


def _old_llm_sink_call(func: ast.FunctionDef) -> ast.Call | None:
    """`project_deal_drift`'s sink search before it read each source once."""
    from agent_audit_kit.scanners import project_deal_drift as m

    for child in ast.walk(func):
        if not isinstance(child, ast.Call):
            continue
        if not m._LLM_SINK_RE.search(ast.unparse(child.func)):
            continue
        if m._has_templated_model_kwarg(child):
            return child
    return None


def test_the_llm_sink_search_finds_the_call_it_did_on_every_shape() -> None:
    from agent_audit_kit.scanners import project_deal_drift

    rng = random.Random(1018)
    vocabulary = ["anthropic", "openai", "litellm", "client", "messages", "chat", "completions", "create",
                  "completion", "ChatCompletion", "beta", "x"]
    differing = []
    for _ in range(4_000):
        calls = []
        for _ in range(rng.randrange(1, 5)):
            dotted = ".".join(rng.choice(vocabulary) for _ in range(rng.randrange(1, 6)))
            model = rng.choice(["", "model=m", "model='opus'", "model=cfg.m"])
            callee = dotted
            for _ in range(rng.randrange(3)):
                callee = f"{callee}({rng.choice(['', 'model=m', 'q'])}).{rng.choice(vocabulary)}"
            calls.append(f"    r = {callee}({model})\n")
        source = "def set_price(item):\n" + "".join(calls)
        func = ast.parse(source).body[0]
        assert isinstance(func, ast.FunctionDef)
        new, old = project_deal_drift._llm_sink_call(func), _old_llm_sink_call(func)
        if new is not old:
            differing.append(source)
    assert not differing, differing[:3]


def _old_attr_chain(node: ast.AST) -> str:
    """The `_attr_chain` both modules keep, which built the whole name."""
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


def test_each_callee_check_answers_as_the_whole_dotted_name_did() -> None:
    from agent_audit_kit.scanners import mcp_marketplace_fetch as fetch
    from agent_audit_kit.scanners import mcp_stdio_params as stdio
    from agent_audit_kit.scanners._helpers import chain_ends, chain_is

    rng = random.Random(1021)
    words = ["subprocess", "Popen", "run", "shlex", "split", "requests", "httpx", "urllib", "get", "post",
             "urlopen", "StdioServerParameters", "StdioClientTransport", "mcp", "client", "stdio", "x",
             "asyncio", "create_subprocess_exec", "check_output"]

    def callee(depth: int) -> str:
        if depth <= 0 or rng.random() < 0.3:
            return rng.choice(words + ["x[0]", "(a + b)", "'s'", "f()"])
        inner = callee(depth - 1)
        return rng.choice([f"{inner}.{rng.choice(words)}", f"{inner}()", f"{inner}[0]", f"{inner}(y)"])

    differing = []
    for _ in range(8_000):
        source = callee(6) + "(arg)"
        call = ast.parse(source).body[0].value
        assert isinstance(call, ast.Call)
        name = _old_attr_chain(call.func)
        parts = name.split(".") if name else []
        expected = (len(parts), parts[0], parts[-1]) if parts else (0, "", "")
        names = set(rng.sample(sorted(stdio._PY_SPAWN_CHAINS) + ["x", "shlex.split", "requests.get"], 3))
        checks = [
            chain_ends(call.func) == expected,
            chain_is(call.func, names) == (name in names),
            stdio._is_stdio_server_params_call(call, {}) == (
                bool(name) and name.split(".")[-1] == "StdioServerParameters"),
            (stdio._spawn_argv(call, {}) is None) == (name not in stdio._PY_SPAWN_CHAINS),
            stdio._is_shlex_split(call, {}) == (name == "shlex.split" and bool(call.args)),
            fetch._is_fetch_call(call) == (bool(name) and name.split(".")[-1] in fetch._PY_FETCH_NAMES and (
                (name.split(".")[0] if "." in name else "") in {"requests", "httpx", "urllib"} or name == "urlopen")),
            fetch._is_stdio_call(call) == (bool(name) and name.split(".")[-1] in fetch._PY_STDIO_TARGETS),
        ]
        if not all(checks):
            differing.append((source, checks))
    assert not differing, differing[:3]


def _old_builds_path_from_token(node: ast.AST, tainted: set[str]) -> bool:
    """`mcp_auth_pathtraversal._builds_path_from_token` before it judged each
    chain once, with the unparse the scanner used then."""
    import re

    from agent_audit_kit.scanners import mcp_auth_pathtraversal as m

    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = m._attr_chain(sub.func)
            short = name.split(".")[-1]
            if (name in m._PATH_JOIN or short == "join" or name in m._PATH_CTORS
                    or short in {"Path", "PurePath"}):
                if any(m._expr_uses_tainted(a, tainted) for a in sub.args):
                    return True
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Div, ast.Add)):
            if m._expr_uses_tainted(sub, tainted):
                blob = ""
                try:
                    blob = ast.unparse(sub)
                except Exception:
                    pass
                if isinstance(sub.op, ast.Div) or re.search(r"path|dir|Path|\.session|/", blob):
                    return True
        if isinstance(sub, ast.JoinedStr):
            has_tokq = any(
                isinstance(v, ast.FormattedValue) and m._expr_uses_tainted(v.value, tainted) for v in sub.values
            )
            has_sep = any(
                isinstance(v, ast.Constant) and isinstance(v.value, str) and ("/" in v.value or "\\" in v.value)
                for v in sub.values
            )
            if has_tokq and has_sep:
                return True
    return False


def test_the_path_build_check_answers_as_it_did_on_every_shape() -> None:
    from agent_audit_kit.scanners import mcp_auth_pathtraversal

    rng = random.Random(1022)
    names = ["token", "session_id", "base", "root", "cfg", "x", "dir_name", "paths", "Path", "data"]

    def expr(depth: int) -> str:
        if depth <= 0 or rng.random() < 0.2:
            return rng.choice(names + ["'/srv'", "'a'", "'.session'", "'dir'"])
        a, b = expr(depth - 1), expr(depth - 2)
        return rng.choice([f"{a} + {b}", f"{a} / {b}", f"({a}) + ({b})", f"os.path.join({a}, {b})",
                           f"Path({a}) / {b}", f"f'{{{a}}}/{{{b}}}'", f"{a}.{rng.choice(['sessions', 'x'])}",
                           f"str({a})", f"{a} * {b}"])

    differing, checked = [], 0
    for _ in range(6_000):
        source = expr(7)
        try:
            node = ast.parse(source).body[0].value
        except SyntaxError:  # an f-string nested in its own quotes, before 3.12
            continue
        checked += 1
        tainted = set(rng.sample(names, 2))
        if mcp_auth_pathtraversal._builds_path_from_token(node, tainted) != _old_builds_path_from_token(node, tainted):
            differing.append((source, tainted))
    assert not differing, differing[:3]
    assert checked > 2_000
