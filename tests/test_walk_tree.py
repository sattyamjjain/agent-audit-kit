"""A scanner walks a syntax tree as deep as real code gets.

A recursive walk takes a frame or more for each level of the tree, and the
interpreter stops at 1,000 frames. sympy's generated table of Galois resolvents
(sympy/polys/numberfields/resolvent_lookup.py) holds a 562-term polynomial whose
tree is 569 levels deep: five scanners that walk every Python file could not walk
it, nine once a header opened their gates, and DeepSeek's walker, which had no
containment, took its scanner down with it. Of 100,303 real files it is the
deepest. Every recursive walk now goes through `walk_tree`, which raises the
limit to `WALK_RECURSION_LIMIT` for the walk alone (before 3.11, on the 256 MB
worker); a tree deeper than even that is refused per file, as before.
"""

from __future__ import annotations

import ast
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import ScanResult
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
SCANNERS = ROOT / "agent_audit_kit" / "scanners"


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


def test_before_3_11_unparse_hands_only_an_expression_too_deep_in_place_to_the_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hand-over to the worker cost more than unparsing the small expressions
    scanners mostly ask about, once for every callee they judged. The unparse
    is tried in place first, and only one the default limit stops goes over;
    on 3.9.6 the retry after that RecursionError must not abort."""
    monkeypatch.setattr(_helpers, "_WALK_ON_WORKER", True)
    handed: list[object] = []
    real = _helpers.walk_tree

    def counting(walk: Any, *args: Any, **kwargs: Any) -> Any:
        handed.append(args[0])
        return real(walk, *args, **kwargs)

    monkeypatch.setattr(_helpers, "walk_tree", counting)
    small = ast.parse("x = y.z").body[0].value
    assert unparse(small) == "y.z" and handed == []
    deep = ast.parse("x = " + " + ".join(["a"] * 700)).body[0].value
    assert unparse(deep).count("+") == 699 and handed == [deep]


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


# ---------------------------------------------------------------------------
# The large-stack worker
# ---------------------------------------------------------------------------


class _NoThreads(ThreadPoolExecutor):
    def submit(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("can't start new thread")


def test_a_worker_that_cannot_start_leaves_parses_and_walks_in_place(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Under an address-space or process limit the 256 MB thread cannot start,
    and before 3.11 that RuntimeError came out of every parse, with every
    Python scanner. The parse and the walk now run in place, the walk under
    the default recursion limit, and the stack size is put back."""
    monkeypatch.setattr(_helpers, "_parse_worker", None)
    monkeypatch.setattr(_helpers, "ThreadPoolExecutor", _NoThreads)
    monkeypatch.setattr(_helpers, "_PARSE_ON_WORKER", True)
    monkeypatch.setattr(_helpers, "_WALK_ON_WORKER", True)
    size = threading.stack_size()
    assert _helpers._large_stack_worker() is None
    assert threading.stack_size() == size
    assert _helpers.parse_python("x = 1", "x.py").body[0].lineno == 1
    assert walk_tree(_recurse, 100) == 100
    with pytest.raises(RecursionError):
        walk_tree(_recurse, sys.getrecursionlimit() + 100)
    (tmp_path / "server.py").write_text(
        "import requests\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n"
        "@mcp.tool()\ndef fetch(url):\n    return requests.get(url).text\n"
    )
    assert run_scan(tmp_path).scanner_failures == []


def test_threads_parsing_for_the_first_time_at_once_start_one_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stack size is the process's while it is set. Without a lock, threads
    starting the worker at once each started one, the one kept could have
    started under the size another had already put back, and 256 MB stayed the
    size of every later thread. Setting the size is slowed here, so that all
    eight threads are inside the start at once."""
    real = threading.stack_size

    def slow_stack_size(*size: int) -> int:
        previous = real(*size)
        if size:
            time.sleep(0.02)
        return previous

    monkeypatch.setattr(_helpers, "_parse_worker", None)
    monkeypatch.setattr(threading, "stack_size", slow_stack_size)
    before = {thread.ident for thread in threading.enumerate() if thread.name.startswith("aak-parse")}
    size = real()
    gate = threading.Barrier(8)
    got: list[ThreadPoolExecutor | None] = []

    def first_use() -> None:
        gate.wait()
        got.append(_helpers._large_stack_worker())

    threads = [threading.Thread(target=first_use) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    started = [t for t in threading.enumerate() if t.name.startswith("aak-parse") and t.ident not in before]
    try:
        assert len(got) == 8 and got[0] is not None and all(worker is got[0] for worker in got)
        assert len(started) == 1
        assert real() == size
    finally:
        for worker in {id(worker): worker for worker in got if worker is not None}.values():
            worker.shutdown(wait=False)


def _in_forked_child(body: Callable[[], str]) -> str:
    """`body()` in a forked child, or what went wrong there; a child that hangs
    is ended after 10 s."""
    read_end, write_end = os.pipe()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # 3.12 warns of fork with threads running
        pid = os.fork()
    if pid == 0:
        try:
            signal.alarm(10)
            out = body()
        except BaseException as exc:  # noqa: BLE001 - reported to the parent
            out = f"raised {type(exc).__name__}: {exc}"
        os.write(write_end, out.encode())
        os._exit(0)
    os.close(write_end)
    _, status = os.waitpid(pid, 0)
    with os.fdopen(read_end, "rb") as pipe:
        out = pipe.read().decode()
    return f"killed by signal {os.WTERMSIG(status)}" if os.WIFSIGNALED(status) else out


_FORK = pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")


@_FORK
def test_a_child_forked_during_another_threads_walk_gets_the_limit_back() -> None:
    """Only the forking thread runs in the child, so the other thread's walk
    never ends there and nothing put the raised limit back: the child kept
    10,000 frames for good."""
    limit = sys.getrecursionlimit()
    started, release = threading.Event(), threading.Event()

    def waits() -> None:
        started.set()
        release.wait(30)

    thread = threading.Thread(target=walk_tree, args=(waits,))
    thread.start()
    try:
        assert started.wait(30)
        assert sys.getrecursionlimit() == max(limit, WALK_RECURSION_LIMIT)

        def child() -> str:
            before = sys.getrecursionlimit()
            walk_tree(lambda: None)
            return f"{before} {sys.getrecursionlimit()} {_helpers._headroom_walks}"

        assert _in_forked_child(child) == f"{limit} {limit} {{}}"
    finally:
        release.set()
        thread.join(30)
    assert sys.getrecursionlimit() == limit


@_FORK
def test_a_child_forked_while_another_thread_holds_the_headroom_lock_can_walk() -> None:
    """A lock another thread held at the fork is never released in the child,
    so its first walk waited on it for ever."""
    holding, let_go = threading.Event(), threading.Event()

    def hold() -> None:
        with _helpers._headroom_lock:
            holding.set()
            let_go.wait(30)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert holding.wait(30)
        assert _in_forked_child(lambda: repr(walk_tree(lambda: "ok"))) == "'ok'"
    finally:
        let_go.set()
        thread.join(30)


@_FORK
def test_a_child_forked_inside_its_own_walk_keeps_that_walk() -> None:
    """Checked from inside the walk, which holds on every version. Before 3.11
    the walk runs on the parse worker, so the child is a copy of that thread
    and the walk never returns to its caller there (the review's
    fork_cases_r3.py, case (d)); from 3.11 it returns and puts the limit back."""
    limit = sys.getrecursionlimit()

    def forks() -> str:
        return _in_forked_child(
            lambda: f"{sys.getrecursionlimit()} {_helpers._headroom_walks == {threading.get_ident(): 1}}"
        )

    assert walk_tree(forks) == f"{max(limit, WALK_RECURSION_LIMIT)} True"
    assert sys.getrecursionlimit() == limit


# ---------------------------------------------------------------------------
# A file as deep as real code gets, read by every scanner that walks it
# ---------------------------------------------------------------------------

# Opens the gates of the scanners that parse Python: MCP, tool, LLM, agent,
# framework and commerce markers, a non-loopback bind and a DeepSeek base URL.
GATES = textwrap.dedent('''\
    import os
    import sqlite3
    import subprocess
    import sys

    import crewai
    import requests
    import stripe
    from crewai import Agent
    from langchain.prompts import PromptTemplate, load_prompt
    from langgraph.prebuilt import ToolNode
    from mcp import StdioServerParameters
    from mcp.server.fastmcp import FastMCP
    from openai import OpenAI

    client = OpenAI(base_url="https://api.deepseek.com/v1")
    mcp = FastMCP("probe")
    HOST = "0.0.0.0"
    # @mcp.tool skill agent llm session token Bearer Authorization
    # github.event.pull_request.title client.messages.create
''')


def resolvent_table(terms: int) -> str:
    """The shape of sympy's resolvent table: a dict of lambda lists, one lambda a
    polynomial of `terms` terms, as deep as `terms` plus seven."""
    lines = "".join(f"            {'-' if i % 2 else '+'} {i + 2}*s1**{i % 6}*s2*s3\n" for i in range(terms - 1))
    return (
        "resolvent_coeff_lambdas = {\n"
        "    (6, 1): [\n"
        "        lambda s1, s2, s3: (s1**6\n" + lines + "        ),\n"
        "    ],\n"
        "}\n"
    )


def _depth(tree: ast.AST) -> int:
    best, stack = 0, [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        best = max(best, depth)
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return best


def _refusals(result: ScanResult) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in result.scanner_failures:
        out.setdefault(f.file_path, set()).add(f.evidence.split("'")[1])
    return out


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# The scanners that walk every Python file, and those that walk it once the
# header opens their gate. Each refused the table without the raised limit.
# mcp_stdio_params and DeepSeek's scanner walk a file's functions with a stack
# of their own, so neither needs the raised limit.
_WALK_EVERY_FILE = {
    "SSRF: validate-then-fetch with redirects (CVE-2026-41481)",
    "SSRF: validate-then-fetch DNS-rebind / TOCTOU (CVE-2026-41488)",
    "MCP marketplace-fetch → StdioServerParameters",
}
_WALK_BEHIND_A_GATE = {
    "Project Deal economic-drift (Anthropic 2026-04-26)",
    "LangGraph ToolNode positional-list regression (1.0.11)",
    "PR-title indirect prompt injection (Comment-and-Control 2026-04-25)",
    "CrewAI four-CVE chain (CERT/CC VU#221883)",
    "LangChain load_prompt path traversal (CVE-2026-34070)",
}


@pytest.mark.parametrize("header", ["", GATES], ids=["as shipped", "gates open"])
def test_a_file_as_deep_as_sympys_resolvent_table_is_walked_by_every_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, header: str
) -> None:
    """600 terms, 607 levels: a little deeper than sympy's 569. Without the raised
    limit each walking scanner refuses the file; with it, none does."""
    source = header + resolvent_table(600)
    assert _depth(ast.parse(source)) > 600
    _write(tmp_path, "pkg/resolvent_lookup.py", source)
    with monkeypatch.context() as patched:
        patched.setattr(_helpers, "WALK_RECURSION_LIMIT", sys.getrecursionlimit())
        without = _refusals(run_scan(tmp_path, strict_loading=True))
    expected = _WALK_EVERY_FILE | (_WALK_BEHIND_A_GATE if header else set())
    assert set(without) == {"pkg/resolvent_lookup.py"}
    assert expected <= without["pkg/resolvent_lookup.py"], sorted(expected - without["pkg/resolvent_lookup.py"])
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []


def test_a_2000_part_attribute_chain_is_read_by_every_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`a.b.b...`, 2,000 parts at module level, the stall sweep's dotted run.
    The five scanners that walk every Python file raised RecursionError on it
    as shipped; without the raised limit each refuses it, and with it none does."""
    _write(tmp_path, "server.py", "import x\na" + ".b" * 2000 + "\n")
    with monkeypatch.context() as patched:
        patched.setattr(_helpers, "WALK_RECURSION_LIMIT", sys.getrecursionlimit())
        without = _refusals(run_scan(tmp_path, strict_loading=True))
    assert _WALK_EVERY_FILE <= without.get("server.py", set()), without
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []


# ---------------------------------------------------------------------------
# A deep expression where each scanner's own recursion reads it
# ---------------------------------------------------------------------------


def _deep_positions(n: int) -> dict[str, str]:
    """An n-level expression in each place a scanner recurses over, one file a
    place so that one the parser refuses cannot hide another, each under the
    header that opens every gate."""
    chain = " + ".join(["arg"] * n)
    items = "[0]" * n
    calls = "()" * n
    ladder = "".join(f"    elif name == 'n{i}':\n        os.system(arguments['cmd'])\n" for i in range(n))
    places = {
        # An assignment's value: argv_toctou and llm_sql_rce unparse it.
        "assign.py": f"PAYLOAD = {chain}\n",
        # A tool's body: the visitors walk it, mcp_auth_pathtraversal and
        # mcp_ssrf_toolarg unparse the whole function, quoted_shell_interp
        # rebuilds the shell command, and a sink's argument reaches
        # stdio_injection's unparse and taint_analysis's item reads.
        "tool.py": textwrap.dedent(f'''\
            @mcp.tool()
            def run(arg: str, url: str, token: str, session_dir: str) -> str:
                command = "ls " + {chain}
                subprocess.run(command, shell=True)
                os.system(arg{items})
                eval(arg{items})
                path = os.path.join(session_dir, token)
                if os.path.exists(path):
                    return requests.get(url + {chain}).text
                return ""
        '''),
        # A call chain as a decorator: skill_lifecycle_attribution and
        # mcp_tool_unsafe_eval follow it down.
        "decorators.py": textwrap.dedent(f'''\
            @skill{calls}
            def execute(store):
                store.save()


            @mcp.tool{calls}
            def evaluate(expr):
                return eval(expr)
        '''),
        # An empty secret checked with a warning: mcp_noauth_default unparses
        # the callee of each call.
        "noauth.py": textwrap.dedent(f'''\
            API_KEY = os.getenv("API_KEY", "")
            API_TOKEN = os.getenv{calls}
            if not API_KEY:
                warn{calls}
        '''),
        # A pricing function: project_deal_drift reads each call's callee.
        "pricing.py": textwrap.dedent(f'''\
            def set_price(item):
                quote = f{calls}
                return client.messages.create(model=item.tier, messages=[quote])
        '''),
        # An `elif` ladder in a `call_tool` handler: taint_analysis follows its
        # branches.
        "handler.py": textwrap.dedent('''\
            @server.call_tool()
            async def handle(name, arguments):
                if name == "start":
                    os.system(arguments["cmd"])
        ''') + ladder,
    }
    return {rel: GATES + "\n\n" + text for rel, text in places.items()}


def _scan_positions(root: Path, n: int) -> ScanResult:
    for rel, text in _deep_positions(n).items():
        _write(root, rel, text)
    return run_scan(root, strict_loading=True)


# The scanners whose own recursion reads one of the places above, besides the
# visitors. Each refused its file without the raised limit.
_RECURSE_OVER_A_PLACE = {
    "Argv rebuilt after allowlist approval before spawn (CVE-2026-53822)",
    "LLM-generated SQL on an RCE-capable DB role (CVE-2026-25879)",
    "MCP bearer-token joined into session file path (CVE-2026-52830)",
    "MCP server unauthenticated-by-default / fail-open auth (CVE-2026-48814)",
    "MCP tool-arg URL SSRF (CVE-2026-14748)",
    "Ox MCP STDIO command-injection",
    "Taint analysis",
    "Tool argument interpolated into a shell command despite quoting (CVE-2026-55157 class)",
    "Skill lifecycle outcome-attribution (SkillsVote, arXiv:2605.18401)",
    "Unsafe eval/exec inside @mcp.tool handler (CVE-2026-44717 class)",
}


def test_an_expression_past_the_default_limit_is_read_wherever_a_scanner_recurses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """1,500 levels in each place: past the default limit for a walk of one frame
    a level, inside the raised one for a walk of three. Without the raised limit
    every scanner that recurses over a place refuses its file; with it, none
    does."""
    with monkeypatch.context() as patched:
        patched.setattr(_helpers, "WALK_RECURSION_LIMIT", sys.getrecursionlimit())
        without = _refusals(_scan_positions(tmp_path, 1500))
    refusing = set().union(*without.values()) if without else set()
    expected = _WALK_EVERY_FILE | _WALK_BEHIND_A_GATE | _RECURSE_OVER_A_PLACE
    assert expected <= refusing, sorted(expected - refusing)
    assert "<scanner>" not in without
    assert _scan_positions(tmp_path, 1500).scanner_failures == []


_PAST_THE_LIMIT = """
    import json, sys
    from pathlib import Path
    sys.path.insert(0, "tests")
    from test_walk_tree import _scan_positions
    result = _scan_positions(Path(sys.argv[1]), int(sys.argv[2]))
    print(json.dumps([[f.file_path, f.evidence] for f in result.scanner_failures]))
"""


def test_an_expression_past_the_raised_limit_is_refused_per_file_never_a_crash(tmp_path: Path) -> None:
    """9,000 levels: past what any walk takes under the raised limit. In a child,
    because before 3.11 a walk that ran on the main thread's stack would segfault
    instead of raising, and the suite would die with it."""
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_PAST_THE_LIMIT), str(tmp_path), "9000"],
        capture_output=True, text=True, timeout=600, cwd=ROOT,
        env={"PYTHONPATH": str(ROOT), "PATH": "", "HOME": tempfile.mkdtemp(prefix="aak-home-")},
    )
    assert out.returncode == 0, (out.returncode, out.stderr[-1000:])
    failures = json.loads(out.stdout)
    assert {path for path, _ in failures} == set(_deep_positions(1)), failures


# ---------------------------------------------------------------------------
# Every scanner walks through the helpers
# ---------------------------------------------------------------------------


def test_no_scanner_unparses_or_starts_a_visitor_outside_the_walk_helper() -> None:
    """A direct `ast.unparse` or `SomeVisitor().visit(tree)` walks with the
    default limit, so real code as deep as sympy's table is refused again."""
    offenders: list[str] = []
    for path in sorted(SCANNERS.glob("*.py")):
        if path.name == "_helpers.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            func = node.func
            if isinstance(func.value, ast.Name) and func.value.id == "ast" and func.attr == "unparse":
                offenders.append(f"{path.name}:{node.lineno} ast.unparse")
            elif func.attr == "visit" and isinstance(func.value, ast.Call):
                offenders.append(f"{path.name}:{node.lineno} a visitor started outside walk_tree")
    assert not offenders, offenders

