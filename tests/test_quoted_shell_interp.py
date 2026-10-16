"""Tests for the quoted-shell-interpolation family (2026-08 wave).

Two advisories, both CVSS 3.1 8.4, both of which a rule that only fires on
*unquoted* interpolation would walk straight past:

  - CVE-2026-55157 / GHSA-49mq-fc6q-3h46 (npm @ooples/token-optimizer-mcp
    < 5.1.0): `getent passwd "${username}" || grep "^${username}:" /etc/passwd`
    through execAsync. Both sites are double-quoted. Double quotes do not stop
    $(...) or backticks, so the quoting buys nothing.
  - CVE-2026-55071 / GHSA-49m4-vp58-wgc9 (PyPI stata-mcp < 1.19.0): an
    unsanitized package name concatenated into a Stata command and handed over
    as an argv element. The list form stops shell metacharacters and does
    nothing about newline injection into Stata's own command language, which
    has a shell escape.

The negatives pin the two claims that make the rule safe to ship: `shlex.quote`
clears it, and a plain argv list with no interpreter flag clears it.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.quoted_shell_interp import INTERP_RULE, PROFILE_RULE, scan


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _ids(tmp_path: Path) -> list[str]:
    findings, _ = scan(tmp_path)
    return sorted(f.rule_id for f in findings)


def _interp(tmp_path: Path) -> list:
    findings, _ = scan(tmp_path)
    return [f for f in findings if f.rule_id == INTERP_RULE]


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_rules_are_registered() -> None:
    for rule_id in (INTERP_RULE, PROFILE_RULE):
        assert rule_id in RULES
        assert RULES[rule_id].severity.value == "high"
        assert "CVE-2026-55157" in RULES[rule_id].cve_references
        assert "CVE-2026-55071" in RULES[rule_id].cve_references
        assert RULES[rule_id].limitations

    assert RULES[INTERP_RULE].category.value == "taint-analysis"
    assert RULES[PROFILE_RULE].category.value == "mcp-config"


# --------------------------------------------------------------------------
# The quoting nuance — the whole point of the rule.
# --------------------------------------------------------------------------


def test_double_quoted_interpolation_is_flagged(tmp_path: Path) -> None:
    """CVE-2026-55157. The value is quoted; it is still command execution."""
    _write(tmp_path, "smart_user.ts", """
import { exec } from "child_process";
const execAsync = promisify(exec);

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const username = request.params.arguments.username as string;
  const { stdout } = await execAsync(
    `getent passwd "${username}" || grep "^${username}:" /etc/passwd`
  );
  return { content: [{ type: "text", text: stdout }] };
});
""")
    findings = _interp(tmp_path)
    assert len(findings) == 1, "one defect, not one per interpolation site"
    assert "inside double quotes" in findings[0].evidence
    assert "$(...)" in findings[0].evidence


def test_quoting_context_is_reported_distinctly(tmp_path: Path) -> None:
    """Bare, double-quoted and single-quoted sites get different explanations."""
    _write(tmp_path, "variants.py", """
import subprocess

@mcp.tool()
def bare(name: str) -> str:
    return subprocess.run(f"lookup {name}", shell=True, capture_output=True).stdout

@mcp.tool()
def double(name: str) -> str:
    return subprocess.run(f'lookup "{name}"', shell=True, capture_output=True).stdout

@mcp.tool()
def single(name: str) -> str:
    return subprocess.run(f"lookup '{name}'", shell=True, capture_output=True).stdout
""")
    evidence = {f.evidence.split("'")[1]: f.evidence for f in _interp(tmp_path)}
    assert "unquoted" in evidence["bare"]
    assert "do not stop" in evidence["double"]
    assert "literal '" in evidence["single"]


def test_argv_behind_an_eval_flag_is_flagged(tmp_path: Path) -> None:
    """CVE-2026-55071. An argv list is not a defence when an element is a program.

    `-b` precedes `-e` here, which is exactly the layout that defeats a scanner
    that stops at the first flag it recognises.
    """
    _write(tmp_path, "stata_tools.py", """
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("stata")

@mcp.tool()
def ado_package_install(package: str) -> str:
    cmd = 'ssc install "%s", replace' % package
    return subprocess.run(
        ["stata-mp", "-b", "-e", cmd], capture_output=True
    ).stdout.decode()
""")
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "interpreter eval flag" in findings[0].evidence
    assert "package" in findings[0].evidence


def test_taint_propagates_one_hop_through_a_local(tmp_path: Path) -> None:
    """The command is built into a local first — as every real advisory does.

    AAK-TAINT-001 only matches a bare parameter handed straight to the sink,
    which is why it saw neither CVE.
    """
    _write(tmp_path, "tools.py", """
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    command = "ping -c 1 " + host
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
""")
    assert INTERP_RULE in _ids(tmp_path)


# --------------------------------------------------------------------------
# True negatives.
# --------------------------------------------------------------------------


def test_shlex_quote_clears_the_finding(tmp_path: Path) -> None:
    _write(tmp_path, "safe.py", """
import shlex
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    command = "ping -c 1 " + shlex.quote(host)
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
""")
    assert _ids(tmp_path) == []


def test_plain_argv_list_is_not_flagged(tmp_path: Path) -> None:
    """No shell, no interpreter flag, no finding. This is the correct fix."""
    _write(tmp_path, "safe.py", """
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    return subprocess.run(
        ["ping", "-c", "1", host], capture_output=True
    ).stdout.decode()
""")
    assert _ids(tmp_path) == []


def test_constant_command_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "safe.py", """
import subprocess

@mcp.tool()
def uptime(unused: str) -> str:
    return subprocess.run("uptime", shell=True, capture_output=True).stdout.decode()
""")
    assert _ids(tmp_path) == []


def test_execfile_with_plain_argv_is_not_flagged(tmp_path: Path) -> None:
    """execFile does not spawn a shell, and no element here is a program."""
    _write(tmp_path, "safe.ts", """
import { execFile } from "child_process";

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const host = request.params.arguments.host as string;
  return execFile("ping", ["-c", "1", host]);
});
""")
    assert _ids(tmp_path) == []


def test_non_tool_function_is_not_flagged(tmp_path: Path) -> None:
    """An internal helper is not an agent-reachable surface."""
    _write(tmp_path, "internal.py", """
import subprocess

def rebuild(target: str) -> str:
    return subprocess.run(f"make {target}", shell=True, capture_output=True).stdout
""")
    assert _ids(tmp_path) == []


# --------------------------------------------------------------------------
# Default-profile reachability.
# --------------------------------------------------------------------------


def test_default_profile_fires_alongside_the_interp_finding(tmp_path: Path) -> None:
    _write(tmp_path, "tools.py", """
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout
""")
    assert _ids(tmp_path) == sorted([INTERP_RULE, PROFILE_RULE])


def test_env_gated_tool_clears_the_profile_rule(tmp_path: Path) -> None:
    """An opt-in gate is the remediation, so it has to clear the rule."""
    _write(tmp_path, "tools.py", """
import os
import subprocess

if os.environ.get("AAK_ENABLE_SHELL_TOOLS") == "1":

    @mcp.tool()
    def probe(host: str) -> str:
        return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout
""")
    ids = _ids(tmp_path)
    assert INTERP_RULE in ids, "the injection is still real"
    assert PROFILE_RULE not in ids, "but it is no longer reachable by default"


def test_profile_rule_does_not_fire_without_an_injection(tmp_path: Path) -> None:
    """It qualifies a real finding; it is not a complaint about running commands."""
    _write(tmp_path, "safe.py", """
import subprocess

@mcp.tool()
def uptime(unused: str) -> str:
    return subprocess.run(["uptime"], capture_output=True).stdout.decode()
""")
    assert PROFILE_RULE not in _ids(tmp_path)


# --------------------------------------------------------------------------
# Linear time.
# --------------------------------------------------------------------------

_HANDLER = """
import {{ exec }} from "child_process";

server.setRequestHandler(CallToolRequestSchema, async (request) => {{
  const username = request.params.arguments.username as string;
  exec(`{command}`);
}});
"""


def test_unclosed_interpolations_after_the_last_brace_add_nothing(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", _HANDLER.format(command='id "${username}" ${host ${port'))
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "parameter 'username'" in findings[0].evidence


def test_a_template_with_no_closing_brace_has_no_interpolation(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", _HANDLER.format(command="id ${username"))
    assert _interp(tmp_path) == []


def test_a_template_of_unclosed_interpolations_scans_in_linear_time(tmp_path: Path) -> None:
    """300 KB of `${` that never closes, after one that does. `[^}]*` read from
    each to the end of the template: 40,000 characters took 1.5 seconds, and
    the time grew with the square of the template. The bound is loose for slow
    CI runners; the scan takes milliseconds."""
    _write(tmp_path, "tool.ts", _HANDLER.format(command='id "${username}" ' + "${" * 150_000))
    started = time.perf_counter()
    findings = _interp(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert len(findings) == 1


_TYPED_LOCAL = """import { exec } from "child_process";

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const host = request.params.arguments.host as string;
  const cmd: Array<string> | string = `ping -c 1 ${host}`;
  exec(cmd);
});
"""


def test_a_typed_local_template_is_followed(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", _TYPED_LOCAL)
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "parameter 'host'" in findings[0].evidence


@pytest.mark.parametrize("typed", [True, False], ids=["typed", "untyped"])
def test_a_local_template_is_followed_in_a_file_that_starts_with_a_newline(
    tmp_path: Path, typed: bool
) -> None:
    """The look-back for the local's assignment walks up to sixty lines. When it
    reached the newline at offset 0 it asked for the last newline before offset
    -1, which counts from the end of the file, so the window jumped past the
    sink and the template was lost whenever a file's first line was blank."""
    source = _TYPED_LOCAL if typed else _TYPED_LOCAL.replace("const cmd: Array<string> | string = ", "const cmd = ")
    _write(tmp_path, "tool.ts", "\n" + source)
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "parameter 'host'" in findings[0].evidence


def test_a_long_blank_type_scans_in_linear_time(tmp_path: Path) -> None:
    """300 KB of blanks after `cmd :` and no type. The type's class and the
    `\\s*` around it split the run every way: 2,000 blanks took 2.1 seconds and
    the time grew with the cube of the run. The bound is loose for slow CI
    runners; the scan takes milliseconds."""
    crafted = _TYPED_LOCAL.replace("const cmd:", "let cmd :" + " " * 300_000 + "\t\nconst cmd:")
    _write(tmp_path, "tool.ts", crafted)
    started = time.perf_counter()
    findings = _interp(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert len(findings) == 1


# --------------------------------------------------------------------------
# One pass per file.
# --------------------------------------------------------------------------
#
# Both passes read a file again for every place they looked at: the Python
# pass split the whole source into lines for every tool function, and the
# TS/JS passes read the template, its quoting, sixty lines back for a local,
# and the prefix for the line number at every sink, and the cross-file hop ran
# the header pattern from the top of the file to every sink and worked out the
# handler's tool-derived names and call arguments for every question. Each test
# below runs a crafted project at two sizes, best of three, and allows the
# larger 40 times the smaller's time for 10 times the text (the old passes
# needed 100 times or more) plus a fixed slack, under an absolute bound that is
# loose for slow CI runners.


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


# shape -> (project for k units, k for the smaller size)
_PYTHON_SHAPES: dict[str, tuple[Callable[[int], dict[str, str]], int]] = {
    # `ast.get_source_segment` split the file into lines for every tool
    # function: 227 KB of them took 7.6 seconds.
    "python-tool-functions": (
        lambda k: {"tools.py": "".join(f"@mcp.tool()\ndef f{i}(name: str) -> str:\n    return name\n" for i in range(k))},
        200,
    ),
}


_CRAFTED = dict(_PYTHON_SHAPES)


@pytest.mark.parametrize("shape", sorted(_CRAFTED))
def test_a_crafted_project_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    build, count = _CRAFTED[shape]
    roots = []
    for name, k in (("small", count), ("large", 10 * count)):
        root = tmp_path / name
        root.mkdir()
        for rel, text in build(k).items():
            assert len(text) < 400_000, "under the scanner's file cap"
            (root / rel).write_text(text, encoding="utf-8")
        roots.append(root)
    t_small, t_large = _seconds(lambda: scan(roots[0])), _seconds(lambda: scan(roots[1]))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)
