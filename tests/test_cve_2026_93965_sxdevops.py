"""CVE-2026-93965 (aiyiyi121/sxdevops, CVSS 6.6) - closing the #810 deferral.

SxDevOps is a DevOps web application whose AIOps module stores the MCP servers
its users register. For a STDIO server it splits the stored
``endpoint_or_command`` with ``shlex.split`` and starts it with
``subprocess.Popen``, so whoever can register a server record chooses the program
the host runs. The fix (``2b4bf858``) routes the split through
``_validate_mcp_stdio_command``, which rejects shell metacharacters and allows only
``npx`` with an audited package and ``swmcp``.

#810 was deferred on 2026-09-27 with a measured gap: a full ``run_scan`` of the
upstream file reported nothing on the launcher, because every STDIO
command-injection arm followed a configured command into the MCP SDKs' own
launchers (``StdioServerParameters``, ``StdioClientTransport``), and a hand-rolled
``subprocess.Popen`` over a stored command string is neither. The arm added to
``AAK-MCP-STDIO-CMD-INJ-001`` is that launcher shape, cut from the upstream file.

Its posture is the rule's: AST within one function, not data flow across
functions. The split and the spawn must sit in the same function, and the
command must come from a stored server's ``command`` field inside a class or
function that manages MCP STDIO servers.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_stdio_params import scan as stdio_scan

RULE = "AAK-MCP-STDIO-CMD-INJ-001"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-93965-sxdevops"


def _py(src: str) -> list[tuple[str, int | None]]:
    d = Path(tempfile.mkdtemp())
    (d / "launcher.py").write_text(src, encoding="utf-8")
    return [(f.rule_id, f.line_number) for f in stdio_scan(d)[0]]


def test_the_rule_carries_the_cve_and_names_both_launchers() -> None:
    rule = RULES[RULE]
    assert "CVE-2026-93965" in rule.cve_references
    text = rule.description
    assert "StdioServerParameters" in text and "subprocess.Popen" in text
    assert "not data flow across functions" in text


def test_the_upstream_launcher_now_produces_a_finding_on_the_spawn() -> None:
    result = run_scan(FIXTURES / "vulnerable")
    hits = [f for f in result.findings if f.rule_id == RULE]
    assert hits, "the launcher at 1d707ff8 must fire"
    assert hits[0].file_path == "backend/aiops/services.py"
    assert hits[0].line_number == 38, "report the subprocess.Popen call, not the split"
    assert "endpoint_or_command" in hits[0].evidence
    assert result.scanner_failures == []


def test_the_upstream_fix_is_silent() -> None:
    """2b4bf858: argv comes from the allowlisting validator, not from shlex.split."""
    result = run_scan(FIXTURES / "negative")
    assert RULE not in {f.rule_id for f in result.findings}
    assert result.scanner_failures == []


def test_the_direct_form_fires() -> None:
    src = (
        "import shlex, subprocess\n"
        "def start_mcp_stdio_server(server_cfg):\n"
        "    return subprocess.run(shlex.split(server_cfg['command']), check=True)\n"
    )
    assert (RULE, 3) in _py(src)


def test_asyncio_exec_over_a_split_command_fires() -> None:
    src = (
        "import asyncio, shlex\n"
        "class McpStdioLauncher:\n"
        "    async def start(self, record):\n"
        "        argv = shlex.split(record.command)\n"
        "        return await asyncio.create_subprocess_exec(*argv)\n"
    )
    assert (RULE, 5) in _py(src)


def test_an_inline_allowlist_check_is_silent() -> None:
    src = (
        "import shlex, subprocess\n"
        "ALLOWED_MCP_EXECUTABLES = {'npx', 'uvx'}\n"
        "class StdioMcpSession:\n"
        "    def __init__(self, server):\n"
        "        command = shlex.split(server.endpoint_or_command)\n"
        "        if command[0] not in ALLOWED_MCP_EXECUTABLES:\n"
        "            raise ValueError('MCP STDIO executable is not allowed')\n"
        "        self.process = subprocess.Popen(command)\n"
    )
    assert RULE not in {rid for rid, _ in _py(src)}


def test_a_constant_argv_is_silent() -> None:
    src = (
        "import subprocess\n"
        "class StdioMcpSession:\n"
        "    def __init__(self, server):\n"
        "        self.process = subprocess.Popen(['npx', '-y', '@n9e/n9e-mcp-server'])\n"
    )
    assert RULE not in {rid for rid, _ in _py(src)}


def test_the_same_spawn_outside_mcp_stdio_code_is_silent() -> None:
    """A host-command runner is a different product surface; this arm is about
    applications that launch MCP STDIO servers."""
    src = (
        "import shlex, subprocess\n"
        "class HostTaskRunner:\n"
        "    def run(self, task):\n"
        "        return subprocess.Popen(shlex.split(task.command))\n"
    )
    assert RULE not in {rid for rid, _ in _py(src)}
