"""The walks a raised recursion limit lets reach the bottom of a deep tree stay
linear on the way down.

Seven scanners did work proportional to the tree below every call or operator
they visited. Where the walk recursed, the default limit used to stop it a few
hundred levels down (main crashed there), and with `walk_tree`'s room it ran to
the bottom: a nested call chain cost the square of its depth, about 1 to 7 s a
chain at 3,000 levels, and a file holds dozens. Two did it in loops the limit
never stopped, so main paid in full: stdio_injection's search of a sink's
argument (four calls on a 3,000-level argument took 33 s) and
mcp_auth_pathtraversal's of a `+` chain (four chains of 1,500 took 7.6 s); and
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


@pytest.mark.parametrize("shape", [
    # Every call searched the whole file for its function: calls outside every
    # function, and a nested call chain in one.
    lambda n: "import crewai\n" + "f()\n" * n,
    lambda n: "import crewai\n\n\ndef build():\n    return f" + "()" * n + "\n",
], ids=["calls at module level", "a nested call chain"])
def test_crewai_finds_each_calls_function_in_linear_time(tmp_path: Path, shape: Callable[[int], str]) -> None:
    """At 3,000 calls the old search took about 3 s for the chain and 18 s for
    the calls at module level, and it grew with the square of their number."""
    _assert_linear(tmp_path, "crewai_rce_chain", shape, 300)


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


def test_stdio_injection_searches_a_sink_argument_in_linear_time(tmp_path: Path) -> None:
    """Every node of a sink's argument searched the argument below it again,
    whether or not it found a taint source in the end: four calls on a
    3,000-level argument took 33 s."""
    _assert_linear(tmp_path, "stdio_injection", lambda n: (
        "from mcp.server.fastmcp import FastMCP\nimport os\n\n\n@mcp.tool()\ndef run(arg):\n"
        + "".join(f"    os.system(x{'[0]' * n})\n" for _ in range(4))), 300)


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
    assert not differing, differing[:3]
