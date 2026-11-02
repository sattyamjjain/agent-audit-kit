"""AAK-MCP-CODEEXEC-SANDBOX-001 and -002: code-execution sandboxes with open runtime permissions.

prefab-ui 0.14.0 up to 0.21.0 ran the Python FastMCP's `generate_prefab_ui` tool
receives in Pyodide under `deno run --allow-read --allow-write --allow-net`
(CVE-2026-120338, CVSS 10.0); 0.21.0 scopes the network flag and revokes read,
write and net before it takes code. These tests pin the GenerativeUI
registration against the prefab-ui release a project resolves, and the Deno
launch against the code its script runs, on the order's fixtures and on two
short snippets shaped like prefab-ui's own launcher and runner at 0.20.2 and
0.21.0. Every fixture is a config file or a few lines of source; none runs.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_codeexec_sandbox import (
    CVE,
    RULE_DENO,
    RULE_GENUI,
    genui_registrations,
    scan,
)

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_codeexec_sandbox"


def _found(root: Path) -> list[tuple[str, str, int | None]]:
    findings, _ = scan(root)
    return [(f.rule_id, f.file_path, f.line_number) for f in findings]


# ---- the order's fixtures ------------------------------------------------------------------


def test_genui_on_prefab_ui_0_20_2_is_critical() -> None:
    findings, _ = scan(FIXTURES / "genui-vulnerable")
    assert [(f.rule_id, f.severity, f.file_path, f.line_number) for f in findings] == [
        (RULE_GENUI, Severity.CRITICAL, "server.py", 5)]
    evidence = findings[0].evidence
    for part in ("`server.py:5` registers FastMCP's GenerativeUI provider", "uv.lock:10 gives prefab-ui 0.20.2",
                 CVE, "fixed in 0.21.0", "Upgrade prefab-ui to 0.21.0 or later", ".pth",
                 "AAK-STARTUP-HOOK-PTH-001", "not that it was used"):
        assert part in evidence, part


def test_genui_on_prefab_ui_0_21_0_is_quiet() -> None:
    assert _found(FIXTURES / "genui-fixed") == []


def test_prefab_ui_0_20_2_without_genui_is_known_vuln_s_alone() -> None:
    root = FIXTURES / "genui-unused"
    assert _found(root) == []
    result = run_scan(project_root=root)
    known = [f for f in result.findings if f.rule_id == "AAK-KNOWN-VULN-001" and CVE in f.evidence]
    assert [(f.file_path, f.severity) for f in known] == [("uv.lock", Severity.CRITICAL)]


def test_genui_vulnerable_reports_the_registration_and_the_release() -> None:
    """The footer's check: both fire without `aak update`, on different files, so the
    engine's pass that drops a feed finding a pin repeats keeps both."""
    result = run_scan(project_root=FIXTURES / "genui-vulnerable")
    got = sorted((f.rule_id, f.file_path) for f in result.findings
                 if f.rule_id == RULE_GENUI or (f.rule_id == "AAK-KNOWN-VULN-001" and CVE in f.evidence))
    assert got == [("AAK-KNOWN-VULN-001", "uv.lock"), (RULE_GENUI, "server.py")]


def test_deno_run_dash_a_handed_caller_python_is_high() -> None:
    findings, _ = scan(FIXTURES / "deno-open")
    assert [(f.rule_id, f.severity, f.file_path, f.line_number) for f in findings] == [
        (RULE_DENO, Severity.HIGH, "runner.js", 5)]
    evidence = findings[0].evidence
    for part in ("starts Deno with -A", "env, ffi, net, read, run, sys, write open", "`runner.js:10` hands",
                 "runPythonAsync", "nothing revokes them", "Deno.permissions.revoke", "--no-prompt", ".pth"):
        assert part in evidence, part


def test_a_scoped_flag_is_quiet() -> None:
    assert _found(FIXTURES / "deno-scoped") == []


def test_deno_with_every_permission_and_no_code_hand_off_is_quiet() -> None:
    assert _found(FIXTURES / "deno-no-code") == []


# ---- prefab-ui's own shape --------------------------------------------------------------------


def test_prefab_s_0_20_2_launcher_and_runner_are_reported_at_the_launch() -> None:
    """The launch is in Python and the hand-off in the runner it starts (runner.js),
    as in prefab-ui's `_pyodide.py`."""
    findings, _ = scan(FIXTURES / "prefab-0.20.2-shape")
    assert [(f.rule_id, f.file_path, f.line_number) for f in findings] == [(RULE_DENO, "_pyodide.py", 12)]
    assert "--allow-read --allow-write --allow-net" in findings[0].evidence
    assert "net, read, write open" in findings[0].evidence and "`runner.js:9` hands" in findings[0].evidence


def test_prefab_s_0_21_0_revokes_what_bootstrap_needed_and_is_quiet() -> None:
    """0.21.0 still passes unscoped --allow-read and --allow-write, for bootstrap, and
    revokes them with net before it takes code."""
    root = FIXTURES / "prefab-0.21.0-shape"
    assert "--allow-read\"," in (root / "_pyodide.py").read_text()
    assert _found(root) == []


def test_a_revocation_that_misses_one_permission_leaves_it_open(tmp_path: Path) -> None:
    src = FIXTURES / "prefab-0.21.0-shape"
    (tmp_path / "_pyodide.py").write_text((src / "_pyodide.py").read_text().replace(
        '"--allow-net=cdn.jsdelivr.net:443"', '"--allow-net"'))
    (tmp_path / "runner.js").write_text((src / "runner.js").read_text().replace(
        '["read", "write", "net"]', '["read", "write"]'))
    findings, _ = scan(tmp_path)
    assert [f.rule_id for f in findings] == [RULE_DENO]
    assert "leaves net open" in findings[0].evidence and "it revokes only read, write" in findings[0].evidence


# ---- launches and hand-offs ---------------------------------------------------------------------


@pytest.mark.parametrize("launch, fires", [
    ('spawn("deno", ["run", "-A", script]);', True),
    ('new Deno.Command(Deno.execPath(), { args: ["run", "--allow-all", script] });', True),
    ('execSync("deno run --allow-run --allow-env " + script);', True),
    ('spawn("/usr/local/bin/deno", ["run", "--allow-write", script]);', True),
    ('spawn("deno", ["run", "--allow-read=/srv", "--allow-net=api.example:443", script]);', False),
    ('spawn("deno", ["run", "--no-prompt", script]);', False),
    ('spawn("deno", ["fmt", "-A", script]);', False),  # not `run`
    ('spawn("denoise", ["run", "-A", script]);', False),
])
def test_what_counts_as_an_open_launch(tmp_path: Path, launch: str, fires: bool) -> None:
    (tmp_path / "worker.js").write_text(
        f"import {{ spawn, execSync }} from 'node:child_process';\nconst script = 'w.ts';\n{launch}\n"
        "export const run = (pyodide, code) => pyodide.runPython(code);\n")
    assert bool(_found(tmp_path)) is fires


@pytest.mark.parametrize("handoff, fires", [
    ("pyodide.runPython(code)", True),
    ("pyodide.runPythonAsync(`print(${JSON.stringify(code)})`)", True),
    ("eval(request.body)", True),
    ("new Function('a', body)", True),
    ("pyodide.runPython('import sys')", False),
    ("pyodide.runPythonAsync(\"import prefab_ui\")", False),
    ("pyodide.runPython(`import sys`)", False),
    ("pyodide.evaluate(code)", False),
])
def test_what_counts_as_handing_the_runtime_code(tmp_path: Path, handoff: str, fires: bool) -> None:
    (tmp_path / "worker.js").write_text(
        "import { spawn } from 'node:child_process';\n"
        f"spawn('deno', ['run', '-A', 'w.ts']);\nexport const go = (pyodide, code, request, body) => {handoff};\n")
    assert bool(_found(tmp_path)) is fires


def test_a_script_outside_the_root_or_missing_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "runner.js").write_text("export const go = (p, code) => p.runPython(code);\n")
    project = tmp_path / "project"
    project.mkdir()
    (project / "launch.py").write_text(
        'import subprocess\nsubprocess.Popen(["deno", "run", "-A", "../outside/runner.js", "missing.js"])\n')
    assert _found(project) == []


# ---- the GenerativeUI registration -----------------------------------------------------------


@pytest.mark.parametrize("source, lines", [
    ("from fastmcp.apps.generative import GenerativeUI\nmcp.add_provider(GenerativeUI())\n", [2]),
    ("from fastmcp.apps.generative import GenerativeUI as G\nmcp.add_provider(G(tool_name='x'))\n", [2]),
    ("import fastmcp.apps.generative as gen\nmcp.add_provider(gen.GenerativeUI())\n", [2]),
    ("from fastmcp.apps import generative\nmcp.add_provider(generative.GenerativeUI())\n", [2]),
    ("import fastmcp.apps.generative\nmcp.add_provider(fastmcp.apps.generative.GenerativeUI())\n", [2]),
    ("from fastmcp.apps.generative import GenerativeUI\nui = GenerativeUI()\n\nmcp.add_provider(ui)\n", [4]),
    ("from fastmcp.apps.generative import GenerativeUI\nui: GenerativeUI = GenerativeUI()\nmcp.add_provider(ui)\n", [3]),
    ("from fastmcp.apps.generative import GenerativeUI\nGenerativeUI()\n", []),          # never registered
    ("from elsewhere import GenerativeUI\nmcp.add_provider(GenerativeUI())\n", []),        # another class
    ("from fastmcp.apps.generative import GenerativeUI\nmcp.add_provider(other())\n", []),
])
def test_a_registration_is_recognised_by_its_import(source: str, lines: list[int]) -> None:
    assert genui_registrations(ast.parse(source)) == lines


@pytest.mark.parametrize("files, fires", [
    ({"uv.lock": '[[package]]\nname = "prefab-ui"\nversion = "0.14.0"\n'}, True),
    ({"uv.lock": '[[package]]\nname = "prefab-ui"\nversion = "0.21.0rc1"\n'}, True),   # PEP 440: before 0.21.0
    ({"uv.lock": '[[package]]\nname = "prefab-ui"\nversion = "0.13.9"\n'}, False),
    ({"poetry.lock": '[[package]]\nname = "prefab_ui"\nversion = "0.20.0"\n'}, True),
    ({"requirements.txt": "fastmcp[apps]==3.2.0\nprefab-ui==0.20.2\n"}, True),
    ({"requirements.txt": "fastmcp[apps]==3.2.0\nprefab-ui==0.21.1\n"}, False),
    ({"requirements.txt": "fastmcp[apps]==3.2.0\nprefab-ui>=0.21.0\n"}, False),        # a range past the fix
    ({"requirements.txt": "fastmcp[apps]==3.2.0\nprefab-ui>=0.18.0\n"}, True),         # admits 0.18.0
    ({"requirements.txt": "fastmcp[apps]==3.2.0\n"}, True),                            # nothing pins it
    ({".venv/lib/python3.12/site-packages/prefab_ui-0.20.2.dist-info/METADATA":
      "Metadata-Version: 2.1\nName: prefab-ui\nVersion: 0.20.2\n"}, True),
    ({".venv/lib/python3.12/site-packages/prefab_ui-0.21.0.dist-info/METADATA":
      "Metadata-Version: 2.1\nName: prefab-ui\nVersion: 0.21.0\n"}, False),
])
def test_the_release_decides(tmp_path: Path, files: dict[str, str], fires: bool) -> None:
    (tmp_path / "server.py").write_text((FIXTURES / "genui-vulnerable" / "server.py").read_text())
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    assert bool(_found(tmp_path)) is fires


def test_an_unpinned_project_says_why(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text((FIXTURES / "genui-vulnerable" / "server.py").read_text())
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["fastmcp[apps]>=3.2"]\n')
    (finding,), _ = scan(tmp_path)
    assert "no lockfile or installed copy says which prefab-ui it runs, and nothing pins it" in finding.evidence


def test_one_affected_lock_is_enough_and_the_others_are_counted(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text((FIXTURES / "genui-vulnerable" / "server.py").read_text())
    for name, version in (("a", "0.21.0"), ("b", "0.19.0"), ("c", "0.20.2")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "uv.lock").write_text(f'[[package]]\nname = "prefab-ui"\nversion = "{version}"\n')
    (finding,), _ = scan(tmp_path)
    assert "b/uv.lock:2 gives prefab-ui 0.19.0 (and 1 more)" in finding.evidence  # the entry's name line


# ---- the registry ---------------------------------------------------------------------------------


def test_the_rules_carry_the_cve_and_the_severities_the_order_asks_for() -> None:
    assert RULES[RULE_GENUI].severity is Severity.CRITICAL and RULES[RULE_DENO].severity is Severity.HIGH
    assert RULES[RULE_GENUI].cve_references == [CVE] == RULES[RULE_DENO].cve_references
    assert "MCP05:2025" in RULES[RULE_DENO].owasp_mcp_references
