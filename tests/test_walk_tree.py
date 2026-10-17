"""`walk_tree` and `unparse`: a recursive walk of a parsed tree, with room to
recurse.

A recursive walk takes a frame or more for each level of the tree, and the
interpreter stops at 1,000 frames, which real code reaches (sympy's generated
table of Galois resolvents is 569 levels deep). `walk_tree` runs a walk with the
limit raised to `WALK_RECURSION_LIMIT` for the walk alone, before 3.11 on the
256 MB worker, and `unparse` is `ast.unparse` run that way.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from agent_audit_kit.scanners import _helpers
from agent_audit_kit.scanners._helpers import (
    WALK_RECURSION_LIMIT,
    collecting_refusals,
    refuse,
    refusing_overflow,
    unparse,
    walk_tree,
)

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# walk_tree and unparse
# ---------------------------------------------------------------------------


def _recurse(n: int) -> int:
    return 0 if n == 0 else 1 + _recurse(n - 1)


@pytest.fixture(params=[False, True], ids=["in place", "on the worker"])
def walk_on_worker(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Both ways a walk runs: in place, as from 3.11, and on the large-stack
    worker, as before 3.11. Before 3.11 a walk in place would take the main
    thread's stack, which is the reason for the worker, so only the worker runs."""
    if not request.param and sys.version_info < (3, 11):
        pytest.skip("before 3.11 a walk runs on the worker")
    monkeypatch.setattr(_helpers, "_WALK_ON_WORKER", request.param)
    return bool(request.param)


def test_a_walk_recurses_past_the_default_limit_and_the_limit_is_put_back(walk_on_worker: bool) -> None:
    limit = sys.getrecursionlimit()
    with pytest.raises(RecursionError):
        _recurse(limit + 100)
    assert walk_tree(_recurse, WALK_RECURSION_LIMIT - 500) == WALK_RECURSION_LIMIT - 500
    assert sys.getrecursionlimit() == limit
    with pytest.raises(RecursionError):
        walk_tree(_recurse, WALK_RECURSION_LIMIT + 100)
    assert sys.getrecursionlimit() == limit


def test_a_walk_runs_where_its_version_needs_and_raises_in_the_caller(walk_on_worker: bool) -> None:
    def where() -> int:
        return threading.get_ident()

    ran_on = walk_tree(where)
    assert (ran_on != threading.get_ident()) is walk_on_worker
    with pytest.raises(KeyError, match="raised in the walk"):
        walk_tree(lambda: {}["raised in the walk"])


def test_a_refusal_made_inside_a_walk_reaches_the_callers_collector(walk_on_worker: bool) -> None:
    def deep_walk() -> None:
        with refusing_overflow("deep.py"):
            _recurse(WALK_RECURSION_LIMIT + 100)
        refuse("noted.py", "refused inside the walk")

    with collecting_refusals() as refused:
        walk_tree(deep_walk)
    assert set(refused) == {"deep.py", "noted.py"}
    assert refused["deep.py"] == "syntax tree too deep for this scanner to walk (RecursionError)"


def test_the_raised_limit_is_never_lowered_by_the_limit_already_set(walk_on_worker: bool) -> None:
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(WALK_RECURSION_LIMIT + 5_000)
    try:
        assert walk_tree(sys.getrecursionlimit) == WALK_RECURSION_LIMIT + 5_000
        assert sys.getrecursionlimit() == WALK_RECURSION_LIMIT + 5_000
    finally:
        sys.setrecursionlimit(previous)


def test_walks_on_two_threads_share_one_raise() -> None:
    """The first walk to finish must not put the limit back under the other,
    and the limit goes back once both are done."""
    limit = sys.getrecursionlimit()
    first_in, second_done = threading.Event(), threading.Event()
    seen: list[int] = []

    def first() -> None:
        first_in.set()
        assert second_done.wait(30)
        seen.append(sys.getrecursionlimit())
        seen.append(_recurse(WALK_RECURSION_LIMIT - 500))

    def second() -> None:
        assert first_in.wait(30)
        walk_tree(_recurse, 10)
        second_done.set()

    if _helpers._WALK_ON_WORKER:
        pytest.skip("before 3.11 every walk runs on the one worker, one after another")
    threads = [threading.Thread(target=walk_tree, args=(first,)), threading.Thread(target=second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert seen == [max(limit, WALK_RECURSION_LIMIT), WALK_RECURSION_LIMIT - 500]
    assert sys.getrecursionlimit() == limit


_NESTED = """
    import sys
    from agent_audit_kit.scanners import _helpers
    _helpers._WALK_ON_WORKER = _helpers._PARSE_ON_WORKER = True
    print(_helpers.walk_tree(lambda: _helpers.walk_tree(lambda: _helpers.parse_python("x = 1", None).body[0].lineno)))
"""


def test_a_walk_inside_a_walk_and_a_parse_inside_a_walk_run_in_place() -> None:
    """Handed to the worker from the worker, either would wait behind the walk
    that handed it over, for ever: in a child, with a timeout."""
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_NESTED)], capture_output=True, text=True, timeout=60,
        cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PATH": ""},
    )
    assert out.returncode == 0, out.stderr[-500:]
    assert out.stdout.strip() == "1"


def test_unparse_reads_a_deep_expression_and_refuses_one_past_the_limit(walk_on_worker: bool) -> None:
    deep = ast.parse("x = " + " + ".join(["a"] * 700)).body[0]
    assert unparse(deep).count("+") == 699
    with pytest.raises(RecursionError):
        unparse(_nested_calls(WALK_RECURSION_LIMIT))


def test_unparse_reads_what_the_unparser_cannot_rebuild_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(node: ast.AST) -> str:
        raise ValueError("Unable to avoid backslash in f-string expression part")

    monkeypatch.setattr(_helpers.ast, "unparse", broken)
    assert unparse(ast.parse("x = 1")) == ""


def _nested_calls(n: int) -> ast.expr:
    """`f()()...()`, n calls deep, built without a parse (3.12 would refuse it)."""
    node: ast.expr = ast.Name(id="f", ctx=ast.Load())
    for _ in range(n):
        node = ast.Call(func=node, args=[], keywords=[])
    return node
