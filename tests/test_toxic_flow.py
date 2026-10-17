"""AAK-TOXICFLOW-001 — Snyk-parity source/sink pair scoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners.toxic_flow import scan


@pytest.fixture
def enable_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AAK_TOXIC_FLOW", "1")


def _write_mcp(root: Path, servers: dict) -> None:
    import json

    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": servers}), encoding="utf-8"
    )


def test_disabled_by_default(tmp_path: Path) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    # No AAK_TOXIC_FLOW env → no findings.
    findings, _ = scan(tmp_path)
    assert findings == []


def test_fs_read_paired_with_http_post_fires(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_only_source_no_sink_passes(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_trust_allowlist_suppresses(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    (tmp_path / ".aak-toxic-flow-trust.yml").write_text(
        """
trust:
  - source: fs_read
    sink: http_post
    justification: "Documented data-export feature; sink is allow-listed in egress proxy."
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_trust_without_justification_does_not_suppress(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    (tmp_path / ".aak-toxic-flow-trust.yml").write_text(
        """
trust:
  - source: fs_read
    sink: http_post
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_secrets_paired_with_email_fires(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "vault": {"command": "node", "args": ["mcp__vault__read_secret"]},
        "smtp": {"command": "node", "args": ["mcp__email__send"]},
    })
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


# VS Code keeps servers under `servers`, not `mcpServers`, so a VS Code project
# exposed no MCP tools to this rule at all.


def _write_vscode(root: Path, servers: dict) -> None:
    import json

    (root / ".vscode").mkdir(exist_ok=True)
    (root / ".vscode" / "mcp.json").write_text(json.dumps({"servers": servers}), encoding="utf-8")


def test_vscode_servers_pair_fires(tmp_path: Path, enable_flag: None) -> None:
    _write_vscode(tmp_path, {
        "fs": {"type": "stdio", "command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"type": "stdio", "command": "node", "args": ["mcp__fetch__post"]},
    })
    findings, scanned = scan(tmp_path)
    flows = [f for f in findings if f.rule_id == "AAK-TOXICFLOW-001"]
    assert flows, "a source/sink pair declared under VS Code's `servers` must be reported"
    # Reported against the file the pair came from, not a `.mcp.json` the
    # project does not have.
    assert {f.file_path for f in flows} == {".vscode/mcp.json"}
    assert scanned == {".vscode/mcp.json"}


def test_vscode_source_without_sink_passes(tmp_path: Path, enable_flag: None) -> None:
    _write_vscode(tmp_path, {
        "fs": {"type": "stdio", "command": "node", "args": ["mcp__filesystem__read_text_file"]},
    })
    findings, _ = scan(tmp_path)
    assert findings == []


def test_mcp_json_pair_is_still_reported_against_mcp_json(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    findings, scanned = scan(tmp_path)
    assert {f.file_path for f in findings} == {".mcp.json"}
    assert scanned == {".mcp.json"}


@pytest.mark.parametrize(("line", "decorator"), [
    # Bare, the form LangChain documents. The scanner reads `splitlines()`
    # output, which carries no newline, so a bare `@tool` never matched.
    ("@tool", True),
    ("@mcp.tool", True),
    ("@tool   ", True),
    ("@tool  # exposed to the agent", True),
    ("@tool()", True),
    ("@mcp.tool( )", True),
    ("@tool\n", True),
    ("@tool )", True),
    ("    @mcp.tool()", True),
    # Arguments, on the line or on the lines below, are not read.
    ("@tool(name='x')", False),
    ("@tool(", False),
    ("@toolkit", False),
    ("@tools.register", False),
    # A decorator starts its line: a comment or code that ends in `@tool` is not one.
    ("# Internal helpers; the public ones are wrapped with @tool", False),
    ("x = 1  # see @tool", False),
    ("emails = ['ops@tool']", False),
])
def test_tool_decorator_keeps_its_shape(line: str, decorator: bool) -> None:
    from agent_audit_kit.scanners.toxic_flow import _TOOL_DECORATOR_RE

    assert bool(_TOOL_DECORATOR_RE.search(line)) is decorator


# A pair made only of `@tool` functions in the repo used to be filed against
# `.mcp.json`, a file the project may not have.

_REPO_TOOLS = (
    "from mcp.server.fastmcp import FastMCP\n"
    "\n"
    "mcp = FastMCP('notes')\n"
    "\n"
    "\n"
    "@mcp.tool()\n"
    "def read_file(path: str) -> str:\n"
    "    return open(path).read()\n"
    "\n"
    "\n"
    "@mcp.tool()\n"
    "def fetch(url: str) -> str:\n"
    "    return ''\n"
)


def test_repo_tool_pair_is_filed_against_the_file_that_declares_it(
    tmp_path: Path, enable_flag: None
) -> None:
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "tools.py").write_text(_REPO_TOOLS, encoding="utf-8")
    findings, scanned = scan(tmp_path)
    flows = [f for f in findings if f.rule_id == "AAK-TOXICFLOW-001"]
    assert len(flows) == 1
    # The pair's first tool is its first source, `read_file`, on line 7.
    assert (flows[0].file_path, flows[0].line_number) == ("srv/tools.py", 7)
    assert not (tmp_path / ".mcp.json").exists()
    assert scanned == {"srv/tools.py"}


def test_repo_tool_pair_names_the_first_source_whatever_the_file_order(
    tmp_path: Path, enable_flag: None
) -> None:
    """Two files each declare one side. The finding names the source's file,
    and the same one on every run, whatever order the directory lists them in."""
    (tmp_path / "a_sink.py").write_text(
        "from langchain.tools import tool\n\n\n@tool\ndef fetch(url: str) -> str:\n    return ''\n",
        encoding="utf-8",
    )
    (tmp_path / "b_source.py").write_text(
        "from langchain.tools import tool\n\n\n@tool\ndef read_file(path: str) -> str:\n"
        "    return open(path).read()\n",
        encoding="utf-8",
    )
    findings, scanned = scan(tmp_path)
    assert [(f.file_path, f.line_number) for f in findings] == [("b_source.py", 5)]
    assert scanned == {"a_sink.py", "b_source.py"}


def test_a_tool_declared_twice_is_filed_against_the_first_file_in_path_order(
    tmp_path: Path, enable_flag: None
) -> None:
    for name in ("z_copy.py", "a_copy.py"):
        (tmp_path / name).write_text(_REPO_TOOLS, encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert [(f.file_path, f.line_number) for f in findings] == [("a_copy.py", 7)]


def test_a_pair_with_a_configured_tool_is_still_filed_against_the_config(
    tmp_path: Path, enable_flag: None
) -> None:
    """The source is a repo function, the sink an MCP server: the config wins,
    as it did before, and carries no line."""
    _write_mcp(tmp_path, {"fetch": {"command": "node", "args": ["mcp__fetch__post"]}})
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n\n\n@tool\ndef read_file(path: str) -> str:\n"
        "    return open(path).read()\n",
        encoding="utf-8",
    )
    findings, scanned = scan(tmp_path)
    assert [(f.file_path, f.line_number) for f in findings] == [(".mcp.json", None)]
    assert scanned == {".mcp.json", "tools.py"}


def test_bare_langchain_tools_form_a_pair(tmp_path: Path, enable_flag: None) -> None:
    """`@tool` with no parentheses is the form LangChain documents."""
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def read_file(path: str) -> str:\n"
        "    return open(path).read()\n"
        "\n"
        "\n"
        "@tool  # posts the report\n"
        "def fetch(url: str) -> str:\n"
        "    return ''\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert [(f.file_path, f.line_number) for f in findings] == [("agent.py", 5)]
    assert "(read_file)" in findings[0].evidence and "(fetch)" in findings[0].evidence


def test_a_comment_ending_in_tool_declares_no_tool(tmp_path: Path, enable_flag: None) -> None:
    """The bare-decorator arm read `@tool` at the end of any line, so a comment
    such as this one made the undecorated `def` below it a tool."""
    (tmp_path / "helpers.py").write_text(
        "# Internal helpers; the public ones are wrapped with @tool\n"
        "def read_file(path):\n"
        "    return open(path).read()\n",
        encoding="utf-8",
    )
    (tmp_path / "net.py").write_text(
        "from langchain.tools import tool\n\n\n@tool()\ndef fetch(url: str) -> str:\n    return url\n",
        encoding="utf-8",
    )
    assert scan(tmp_path)[0] == []


def test_a_decorator_with_arguments_declares_no_tool(tmp_path: Path, enable_flag: None) -> None:
    """Stated in the limitation: `@tool("name")` and `@mcp.tool(name=...)` are not read."""
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n\n"
        "@tool(\"read_file\")\ndef read_file(path: str) -> str:\n    return open(path).read()\n\n\n"
        "@tool(\"fetch\")\ndef fetch(url: str) -> str:\n    return ''\n",
        encoding="utf-8",
    )
    assert scan(tmp_path) == ([], set())


def test_a_long_decorator_line_reads_in_linear_time() -> None:
    """`@tool` and 1 MB of blanks. The two `\\s*` around an optional `(`
    split the run every way: 40,000 blanks took 4 seconds and the time grew
    with the square. The bound is loose for slow CI runners."""
    import time

    from agent_audit_kit.scanners.toxic_flow import _TOOL_DECORATOR_RE

    started = time.perf_counter()
    _TOOL_DECORATOR_RE.search("@tool" + " " * 1_000_000 + "x")
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize("line", [
    "@tool(" + " " * 1_000_000 + "x",
    "@tool" + " " * 1_000_000 + "#" + " " * 1_000_000 + "x\nx",
    "@tool" * 200_000,
])
def test_the_bare_decorator_forms_read_in_linear_time(line: str) -> None:
    """The end-of-line and comment arms added for a bare `@tool`: 1 MB of
    blanks after `(` or `#`, and 200,000 decorators on one line."""
    import time

    from agent_audit_kit.scanners.toxic_flow import _TOOL_DECORATOR_RE

    started = time.perf_counter()
    _TOOL_DECORATOR_RE.search(line)
    assert time.perf_counter() - started < 5.0
