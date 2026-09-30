"""CVE-2026-94031 (0-Gaurav-0/nexus-mcp, CVSS 6.3) - closing the #816 deferral.

The ``nexus_reauth`` tool's handler, ``src/tools/reauth.ts``, takes its ``url``
argument and calls ``sessionManager.reauth(provider, loginUrl)``.
``BrowserSessionManager.reauth()`` is defined in another file,
``src/auth/browser.ts``: it builds ``open "${loginUrl}"`` into a local ``cmd`` and
hands that to ``exec``. Double quotes do not stop ``$(...)`` or backticks.

#816 was deferred on 2026-09-27 with a measured gap: nothing fired in
``browser.ts``. ``AAK-SHELL-QUOTED-INTERP-001`` said so itself in its
limitations ("a value routed through a helper function in another module is not
followed"), and its JavaScript arm also read a command template only when it
was written inline in the ``exec(...)`` call, not through a local variable as
the rule text claimed. Both hops are added here.

The cross-file hop is matched by method name, not by type, and it follows one
call: a tool-handler file passes a tool-argument value to ``x.method(...)``, and
``method`` interpolates the parameter at that position into a shell command. A
value looked up in a table keyed by a tool argument
(``PROVIDER_LOGIN_URLS[provider]``) is the table's value, not the argument, so it
does not count.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.quoted_shell_interp import INTERP_RULE, scan

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-94031-nexus-mcp"

_SINK = """\
import { exec } from 'child_process';

export class BrowserSessionManager {
  async reauth(
    provider: string,
    loginUrl: string,
  ): Promise<void> {
    let cmd: string;
    cmd = `open "${loginUrl}"`;
    exec(cmd, () => undefined);
  }
}
"""


def _interp(root: Path) -> list[tuple[str, int | None]]:
    return [(f.file_path, f.line_number) for f in scan(root)[0] if f.rule_id == INTERP_RULE]


def _project(tmp_path: Path, handler: str) -> Path:
    (tmp_path / "src" / "auth").mkdir(parents=True)
    (tmp_path / "src" / "tools").mkdir(parents=True)
    (tmp_path / "src" / "auth" / "browser.ts").write_text(_SINK, encoding="utf-8")
    (tmp_path / "src" / "tools" / "reauth.ts").write_text(handler, encoding="utf-8")
    return tmp_path


def test_the_rule_carries_the_cve_and_states_the_hop() -> None:
    rule = RULES[INTERP_RULE]
    assert "CVE-2026-94031" in rule.cve_references
    assert "another file" in rule.description
    assert "by name, not type" in (rule.limitations or "")


def test_the_upstream_tree_now_reports_the_sink_in_browser_ts() -> None:
    result = run_scan(FIXTURES / "vulnerable")
    hits = [f for f in result.findings if f.rule_id == INTERP_RULE]
    assert [(f.file_path, f.line_number) for f in hits] == [("src/auth/browser.ts", 38)]
    evidence = hits[0].evidence
    assert "loginUrl" in evidence and "double quotes" in evidence
    assert "src/tools/reauth.ts" in evidence, "say which handler the argument comes from"
    assert result.scanner_failures == []


def test_execfile_with_an_argv_list_is_silent() -> None:
    result = run_scan(FIXTURES / "negative")
    assert INTERP_RULE not in {f.rule_id for f in result.findings}


def test_a_table_lookup_keyed_by_a_tool_argument_is_silent(tmp_path: Path) -> None:
    handler = (
        "import { PROVIDER_LOGIN_URLS } from '../auth/browser.js';\n"
        "export async function handleReauth(args: Record<string, unknown>, sessionManager: any) {\n"
        "  const provider = args.provider as string;\n"
        "  const loginUrl = PROVIDER_LOGIN_URLS[provider];\n"
        "  return sessionManager.reauth(provider, loginUrl);\n"
        "}\n"
    )
    assert _interp(_project(tmp_path, handler)) == []


def test_a_method_no_tool_handler_calls_is_silent(tmp_path: Path) -> None:
    handler = (
        "export async function handleStatus(args: Record<string, unknown>) {\n"
        "  return { ok: true, provider: args.provider };\n"
        "}\n"
    )
    assert _interp(_project(tmp_path, handler)) == []


def test_the_argument_position_matters(tmp_path: Path) -> None:
    """The tool argument lands in `provider`, which the command never uses."""
    handler = (
        "export async function handleReauth(args: Record<string, unknown>, sessionManager: any) {\n"
        "  const provider = args.provider as string;\n"
        "  return sessionManager.reauth(provider, 'https://claude.ai/login');\n"
        "}\n"
    )
    assert _interp(_project(tmp_path, handler)) == []


def test_a_local_variable_in_the_handler_file_itself_fires(tmp_path: Path) -> None:
    """The one-hop form the rule text always claimed, now in JavaScript too."""
    (tmp_path / "tool.ts").write_text(
        "import { exec } from 'child_process';\n"
        "export async function handle(args: Record<string, unknown>) {\n"
        "  const username = args.username as string;\n"
        "  const cmd = `getent passwd \"${username}\"`;\n"
        "  exec(cmd);\n"
        "}\n",
        encoding="utf-8",
    )
    assert _interp(tmp_path) == [("tool.ts", 5)]
