"""The pin table reads a deep document in linear time and memory.

The pin table finds every MCP server in a config by walking the parsed document
breadth first, and it gave every container the container's whole path, one
level longer at each level, which cost the square of the depth on a chain.
JSON's parser reads about 10,000 levels on Python 3.12 and later, and more on
3.14, so a 1.9 MB root .mcp.json of 105 chains of 9,000 lists took 10.8 s in
the pin table on 3.12 (9 chains of 100,000 took 110 s on 3.14), and servers
nested in servers held 1.75 GB for 1.4 MB. The walk now keeps each container's
parent instead of its path and builds a path only for a server, and none
longer than 64 keys: a server nested deeper is still reported, without a line.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
import textwrap
from collections import deque
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.scanners import _manifest_deps as m
from agent_audit_kit.scanners._manifest_deps import declaration_lines, declarations

ROOT = Path(__file__).resolve().parent.parent


def _old_command_entries(data: object) -> list[tuple[dict, tuple[str | int, ...]]]:
    """`_command_entries` as it was, copying the path at every level."""
    entries: list[tuple[dict, tuple[str | int, ...]]] = []
    queue: deque[tuple[object, tuple[str | int, ...]]] = deque([(data, ())])
    seen: set[int] = set()
    while queue:
        node, where = queue.popleft()
        if isinstance(node, (dict, list)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, dict):
            if isinstance(node.get("command"), (str, list)):
                entries.append((node, where))
            queue.extend((value, where + (key,)) for key, value in node.items())
        elif isinstance(node, list):
            queue.extend((value, where + (index,)) for index, value in enumerate(node))
    return entries


def _random_config(rng: random.Random, depth: int, made: list[Any]) -> Any:
    """A config of objects, lists and servers, some containers shared and a few
    holding themselves, the shapes a YAML alias makes."""
    roll = rng.random()
    if made and roll < 0.08:
        return rng.choice(made)
    if depth <= 0 or roll < 0.3:
        return rng.choice(["npx", "-y", "c@3.0.0", 7, None, True])
    if roll < 0.45:
        server: dict[str, Any] = {"command": rng.choice(["npx", ["uvx", "x==1.0"], "node s.js"])}
        made.append(server)
        server["args"] = [_random_config(rng, depth - 1, made) for _ in range(rng.randint(0, 3))]
        return server
    if roll < 0.75:
        obj: dict[str, Any] = {}
        made.append(obj)
        for _ in range(rng.randint(0, 4)):
            obj[rng.choice(["mcpServers", "servers", "s", "x", "command"])] = _random_config(rng, depth - 1, made)
        return obj
    items: list[Any] = []
    made.append(items)
    items.extend(_random_config(rng, depth - 1, made) for _ in range(rng.randint(0, 4)))
    if rng.random() < 0.02:
        items.append(items)
    return items


def test_the_server_walk_finds_the_servers_and_paths_it_did_on_every_shape() -> None:
    rng = random.Random(11)
    found = 0
    for _ in range(3_000):
        doc = _random_config(rng, rng.randint(0, 8), [])
        got = [(id(entry), where) for entry, where in m._command_entries(doc)]
        assert got == [(id(entry), where) for entry, where in _old_command_entries(doc)]
        found += len(got)
    assert found > 2_000


def _server_at(depth: int) -> str:
    server: Any = {"command": "npx", "args": ["-y", "c@3.0.0"]}
    for _ in range(depth):
        server = {"k": server}
    return json.dumps(server, indent=1)


def test_a_server_past_the_bound_is_read_and_reported_without_a_line() -> None:
    """The deepest server with a path keeps two keys for a word of its command
    line (`"args", 1`), so the word's path is at the bound; one level deeper,
    the server is read and its declaration has no line."""
    deepest = m._MAX_PATH_DEPTH - 2
    for depth, has_line in ((deepest, True), (deepest + 1, False)):
        text = _server_at(depth)
        found = declarations(Path(".mcp.json"), text)
        assert [(d.name, d.version) for d in found] == [("c", "3.0.0")]
        line = declaration_lines(Path(".mcp.json"), text)(found[0])
        expected = text.splitlines().index(" " * (depth + 2) + '"c@3.0.0"') + 1 if has_line else None
        assert line == expected, depth


_TIMED = """
    import sys, time
    from agent_audit_kit.scanners._manifest_deps import mcp_config_declarations
    k, d = int(sys.argv[1]), int(sys.argv[2])
    chains = []
    for _ in range(k):
        v = []
        for _ in range(d):
            v = [v]
        chains.append(v)
    doc = {"mcpServers": {"s": {"command": "npx", "args": ["-y", "c@3.0.0"]}}, "x": chains}
    started = time.process_time()
    found = mcp_config_declarations(doc)
    print(time.process_time() - started, len(found))
"""

_TRACED = """
    import sys, tracemalloc
    from agent_audit_kit.scanners import _manifest_deps as m
    case, n = sys.argv[1], int(sys.argv[2])
    if case == "servers":
        v = {}
        for _ in range(n):
            v = {"command": "npx", "args": ["-y", "c@3.0.0"], "a": v}
        run = lambda: len(m.mcp_config_declarations({"mcpServers": {"s": v}}))
    tracemalloc.start()
    count = run()
    print(tracemalloc.get_traced_memory()[1] / 1e6, count)
"""


def _child(script: str, *args: str) -> tuple[float, int]:
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script), *args], capture_output=True, text=True, timeout=120,
        cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PATH": "", "HOME": tempfile.mkdtemp(prefix="aak-home-")},
    )
    assert out.returncode == 0, out.stderr[-1000:]
    value, count = out.stdout.split()
    return float(value), int(count)


def test_a_config_of_deep_chains_is_walked_in_linear_time() -> None:
    """32 chains of 20,000 lists, built in Python so that every version can
    hold them: 11.7 s of CPU for the old walk on 3.12, 0.5 s now."""
    seconds, found = _child(_TIMED, "32", "20000")
    assert found == 1
    assert seconds < 3.0


@pytest.mark.parametrize(("case", "size", "old_mb"), [
    ("servers", "12000", 1159),  # 12,000 servers, each inside the last
])
def test_a_deep_document_is_read_in_linear_memory(case: str, size: str, old_mb: int) -> None:
    """Peak traced memory, measured in a child: `old_mb` before, a few MB now
    (6 on 3.12). tracemalloc rather than the peak RSS, which on Linux counts
    the pytest worker that started the child."""
    peak_mb, count = _child(_TRACED, case, size)
    assert count > 0
    assert peak_mb < 60, (peak_mb, old_mb)
