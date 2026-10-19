"""The pin table reads a deep document in linear time and memory.

The pin table finds every MCP server in a config by walking the parsed document
breadth first, and it gave every container the container's whole path, one
level longer at each level; the passes that find a declaration's line recorded
the path of every node the same way. Each cost the sum of all those lengths,
the square of the depth on a chain. JSON's parser reads about 10,000 levels on
Python 3.12 and later, and more on 3.14, so a 1.9 MB root .mcp.json of 105
chains of 9,000 lists took 10.8 s in the pin table on 3.12 (9 chains of 100,000
took 110 s on 3.14), servers nested in servers held 1.75 GB for 1.4 MB, and four
chains of 6,000 lists held 579 MB in the JSON position pass. The walk now keeps
each container's parent instead of its path and builds a path only for a
server, and no path longer than 64 keys is built or recorded: a declaration
nested deeper is still reported, without a line.
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


@pytest.mark.parametrize("depth", [m._MAX_PATH_DEPTH - 2, m._MAX_PATH_DEPTH - 1])
def test_a_pinned_server_at_the_bound_keeps_its_line_and_one_past_it_is_still_reported(
    tmp_path: Path, depth: int
) -> None:
    """The pin table's finding for a vulnerable server at the deepest level
    with a path carries the line of the word that names it; one level deeper
    the server is still read and judged, and the finding has no line."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

    server: Any = {"command": "npx", "args": ["@adenot/mcp-google-search"]}
    for _ in range(depth):
        server = {"k": server}
    text = json.dumps(server, indent=1)
    (tmp_path / ".mcp.json").write_text(text)
    findings = [f for f in pins.scan(tmp_path)[0] if f.rule_id == "AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001"]
    word = text.splitlines().index(" " * (depth + 2) + '"@adenot/mcp-google-search"') + 1
    assert [f.line_number for f in findings] == [word if depth <= m._MAX_PATH_DEPTH - 2 else None]


def test_a_lockfile_entry_keeps_its_line_past_the_bound(tmp_path: Path) -> None:
    """A lockfile's lines are read off the text by their own patterns, not the
    position passes, so a lockfileVersion 1 entry 70 `dependencies` deep is
    reported on its own line, as the rule text says."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

    package = "@adenot/mcp-google-search"
    deps: Any = {package: {"version": "1.0.0"}}
    for i in range(70):
        deps = {f"p{i}": {"version": "1.0.0", "dependencies": deps}}
    text = json.dumps({"name": "x", "lockfileVersion": 1, "dependencies": deps}, indent=1)
    (tmp_path / "package-lock.json").write_text(text)
    findings = [f for f in pins.scan(tmp_path)[0] if f.rule_id == "AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001"]
    word = next(i for i, line in enumerate(text.splitlines(), 1) if package in line)
    assert [f.line_number for f in findings] == [word]


def test_every_pin_table_rule_states_how_deep_a_declaration_keeps_its_line() -> None:
    from agent_audit_kit.rules.builtin import RULES
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

    stated = (
        f"A declaration nested more than {m._MAX_PATH_DEPTH} levels deep in package.json, a TOML manifest "
        f"or an MCP config (an MCP server more than {m._MAX_PATH_DEPTH - 2}) is still judged, and reported "
        "without a line; a lockfile entry keeps its line at any depth."
    )
    ids = sorted({pin.rule_id for pin in pins._PINS})
    assert len(ids) > 100
    assert [rule_id for rule_id in ids if stated not in (RULES[rule_id].limitations or "")] == []


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
    elif case == "json":
        text = '{"a": [' + ",".join(["[" * n + "]" * n] * 4) + "]}"
        run = lambda: len(m._json_positions(text))
    elif case == "toml":
        text = "".join("x%d = " % i + "[" * n + "]" * n + "\\n" for i in range(400))
        run = lambda: len(m._toml_positions(text))
    else:
        import tempfile
        from pathlib import Path
        from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins
        root = Path(tempfile.mkdtemp())
        chains = ",".join(["[" * n + "]" * n] * 1000)
        (root / ".mcp.json").write_text(
            '{"mcpServers": {"gs": {"command": "npx", "args": ["@adenot/mcp-google-search"]}},\\n"x": ['
            + chains + "]}")
        run = lambda: int([(f.rule_id, f.line_number) for f in pins.scan(root)[0]] == [
            ("AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001", 1)])
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


@pytest.mark.parametrize(("case", "size", "old_mb", "bound_mb"), [
    ("servers", "12000", 1159, 60),  # 12,000 servers, each inside the last
    ("json", "6000", 579, 60),       # four JSON chains of 6,000 lists, 48 KB
    ("toml", "300", 155, 60),        # 400 TOML arrays nested 300 deep, 243 KB
    # A pinned server beside 1,000 JSON chains of 480 lists (961 KB, inside the
    # JSON depth limit), and the line of its finding. The parsed lists alone
    # take most of the 109 MB it now peaks at.
    ("pins", "480", 969, 300),
])
def test_a_deep_document_is_read_in_linear_memory(case: str, size: str, old_mb: int, bound_mb: int) -> None:
    """Peak traced memory, measured in a child: `old_mb` before, a few MB now
    (6, 1 and 9 on 3.12, and 109 for the whole pin-table scan). tracemalloc
    rather than the peak RSS, which on Linux counts the pytest worker that
    started the child."""
    peak_mb, count = _child(_TRACED, case, size)
    assert count > 0  # for "pins", the finding with its line
    assert peak_mb < bound_mb, (peak_mb, old_mb)


def _positions_capped_and_full(monkeypatch: pytest.MonkeyPatch, read: Any, text: str) -> tuple[dict, dict]:
    capped = read(text)
    monkeypatch.setattr(m, "_MAX_PATH_DEPTH", 10**9)
    full = read(text)
    monkeypatch.undo()
    return capped, full


@pytest.mark.parametrize("fmt", ["json", "toml", "yaml"])
def test_each_position_pass_records_every_path_up_to_the_bound_and_none_past_it(
    monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    depth = 90  # under the YAML loader's 100 levels
    if fmt == "json":
        read, text = m._json_positions, '{"a":' * depth + '["x", {"b": "y"}]' + "}" * depth
    elif fmt == "toml":
        read, text = m._toml_positions, 'a = "x"\nb = ' + "[" * depth + '"y"' + "]" * depth + "\n"
    else:
        read = m._yaml_positions
        text = "".join("  " * i + "a:\n" for i in range(depth)) + "  " * depth + "- x\n"
    capped, full = _positions_capped_and_full(monkeypatch, read, text)
    assert capped == {path: line for path, line in full.items() if len(path) <= m._MAX_PATH_DEPTH}
    assert max(map(len, capped)) == m._MAX_PATH_DEPTH < max(map(len, full))


def _old_json_positions(text: str) -> dict[tuple[str | int, ...], int]:
    """`_json_positions` as it was, recording every path."""
    try:
        text = m.strip_jsonc(text)
    except ValueError:
        return {}
    positions: dict[tuple[str | int, ...], int] = {}
    stack: list[list] = []
    line, last = 1, 0
    for match in m._JSON_TOKEN_RE.finditer(text):
        token, start = match.group(), match.start()
        line += text.count("\n", last, start)
        last = start
        frame = stack[-1] if stack else None
        if token[0] == '"':
            if frame is None:
                positions[()] = line
            elif frame[0] and frame[3] == "key":
                frame[2], frame[3] = m._json_key(token), "colon"
            elif frame[3] == "value":
                positions[frame[1] + (frame[2],)] = line
                frame[3] = "done"
        elif token in "{[":
            if frame is None:
                child: tuple[str | int, ...] = ()
            elif frame[3] == "value":
                child = frame[1] + (frame[2],)
                frame[3] = "done"
            else:
                break
            positions[child] = line
            stack.append([True, child, "", "key"] if token == "{" else [False, child, 0, "value"])
        elif token in "}]":
            if stack:
                stack.pop()
        elif token == ":":
            if frame is not None and frame[0] and frame[3] == "colon":
                frame[3] = "value"
        elif frame is not None:
            if frame[0]:
                frame[3] = "key"
            else:
                frame[2] += 1
                frame[3] = "value"
    return positions


def test_the_json_position_pass_records_what_it_did_on_every_shape() -> None:
    rng = random.Random(13)
    recorded = 0
    for _ in range(2_000):
        doc = _random_config(rng, rng.randint(0, 8), [])
        try:
            text = json.dumps(doc, indent=rng.choice([None, 1, 2]))
        except ValueError:  # a list that holds itself
            continue
        got = m._json_positions(text)
        assert got == _old_json_positions(text), text
        recorded += len(got)
    assert recorded > 4_000
