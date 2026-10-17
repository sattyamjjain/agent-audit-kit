"""AAK-ANTHROPIC-SDK-001 — OX-MCP-2026-04-15 inheritance check tests."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_sdk_hardening

FIXTURES = Path(__file__).parent / "fixtures" / "incidents" / "ox-mcp-2026-04-15"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


def test_python_unsanitized_stdio_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "python" / "vulnerable", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_python_sanitizer_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "python" / "sanitized", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_typescript_unsanitized_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "typescript" / "vulnerable", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_typescript_sanitizer_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "typescript" / "sanitized", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_documented_risk_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented-risk", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_no_sdk_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "class StdioServerTransport: pass\n", encoding="utf-8"
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    # No SDK declared → we should NOT fire even though the marker exists.
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_sdk_without_stdio_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "# HTTP-only server\nclass HttpServer: pass\n", encoding="utf-8"
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_http_opt_out_in_server_suppresses(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        'class StdioServerTransport: pass\n'
        'transport = StdioServerTransport()\n'
        'transports = ["http"]\n',
        encoding="utf-8",
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


# --------------------------------------------------------------------------
# The SDK gate. This scanner kept its own copy of the gate after #989 fixed
# the stateless one: pyproject.toml counted only as the bare quoted "mcp", and
# a requirements line was cut at its first `=`. So "mcp[cli]>=1.2.0", Poetry's
# `mcp = "^1.2.0"` and `mcp~=1.2.0` never opened it, and an unsanitized STDIO
# server declared the usual way was never reported.
# --------------------------------------------------------------------------

_STDIO_SERVER = (
    "from mcp.server.stdio import stdio_server\n\n\n"
    "async def main(server):\n"
    "    async with stdio_server() as (read, write):\n"
    "        await server.run(read, write)\n"
)


def _gate_fires(root: Path, manifest: str, text: str) -> bool:
    (root / manifest).write_text(text, encoding="utf-8")
    (root / "server.py").write_text(_STDIO_SERVER, encoding="utf-8")
    findings, _ = mcp_sdk_hardening.scan(root)
    return any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


@pytest.mark.parametrize(("manifest", "text"), [
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n'),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["MCP>=1.2"]\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.10"\nmcp = "^1.2.0"\n'),
    ("pyproject.toml", '[dependency-groups]\nserver = ["mcp>=1.2"]\n'),
    ("requirements.txt", "mcp~=1.2.0\n"),
    ("requirements.txt", 'mcp[cli]>=1.2 ; python_version >= "3.10"\n'),
    ("requirements-dev.txt", "MCP==1.2.0  # pinned\n"),
])
def test_the_sdk_gate_reads_real_manifests(tmp_path: Path, manifest: str, text: str) -> None:
    assert _gate_fires(tmp_path, manifest, text)


@pytest.mark.parametrize(("manifest", "text"), [
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp-proxy>=0.3"]\n'),
    ("requirements.txt", "mcp-server-git==0.6.2\n"),
    ("requirements.txt", "# mcp>=1.2\nclick>=8.1\n"),
])
def test_the_sdk_gate_stays_shut_for_other_distributions(
    tmp_path: Path, manifest: str, text: str
) -> None:
    assert not _gate_fires(tmp_path, manifest, text)


def test_the_sdk_gate_is_the_one_the_stateless_rules_use(tmp_path: Path) -> None:
    from agent_audit_kit.scanners import _helpers

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n', encoding="utf-8"
    )
    (tmp_path / "server.py").write_text(_STDIO_SERVER, encoding="utf-8")
    _, scanned = mcp_sdk_hardening.scan(tmp_path)
    assert {"pyproject.toml", "server.py"} <= scanned
    assert mcp_sdk_hardening.declares_mcp_sdk is _helpers.declares_mcp_sdk


@pytest.mark.parametrize(("source", "hinted"), [
    ("execFile(cmd, [arg])", True),
    ("execFile(execFile(x), [y])", True),
    ("execFile(, [x])", False),
    ("execFile(cmd,\n  [arg])", True),
    ("execFile(cmd, arg)", False),
])
def test_execfile_argv_hint_keeps_its_shape(source: str, hinted: bool) -> None:
    assert bool(mcp_sdk_hardening._SANITIZER_HINTS[1].search(source)) is hinted


def test_the_execfile_hint_reads_a_crafted_file_in_linear_time() -> None:
    """1 MB of `execFile(` and no comma. Each call read the rest of the file:
    80 KB took 0.22 seconds and the time grew with the square. The bound is
    loose for slow CI runners."""
    started = time.perf_counter()
    mcp_sdk_hardening._SANITIZER_HINTS[1].search("execFile(" * 110_000)
    assert time.perf_counter() - started < 5.0


# --------------------------------------------------------------------------
# A sanitizer or opt-out guards its own file. The evidence of every STDIO
# file in the project used to be pooled, so one `ALLOWED_*` name or HTTP
# setting anywhere cleared an unguarded STDIO transport in another file.
# --------------------------------------------------------------------------

_UNGUARDED_PY = (
    "from mcp.client.stdio import stdio_client, StdioServerParameters\n\n\n"
    "async def connect(command, args):\n"
    "    params = StdioServerParameters(command=command, args=args)\n"
    "    async with stdio_client(params) as (read, write):\n"
    "        return read, write\n"
)
_GUARDED_PY = (
    "from mcp.client.stdio import stdio_client, StdioServerParameters\n\n"
    'ALLOWED_COMMANDS = {"uvx", "npx"}\n\n\n'
    "async def connect_safe(command, args):\n"
    "    if command not in ALLOWED_COMMANDS:\n"
    "        raise ValueError(command)\n"
    "    params = StdioServerParameters(command=command, args=args)\n"
    "    async with stdio_client(params) as (read, write):\n"
    "        return read, write\n"
)


def _reported(root: Path, files: dict[str, str]) -> list[str]:
    (root / "requirements.txt").write_text("mcp==1.25.0\n", encoding="utf-8")
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    findings, _ = mcp_sdk_hardening.scan(root)
    return sorted(f.file_path for f in findings if f.rule_id == "AAK-ANTHROPIC-SDK-001")


def test_an_allow_list_in_another_stdio_file_does_not_clear_this_one(tmp_path: Path) -> None:
    files = {"svc1/server_a.py": _UNGUARDED_PY, "svc2/server_b.py": _GUARDED_PY}
    assert _reported(tmp_path, files) == ["svc1/server_a.py"]


def test_an_unrelated_allow_list_in_another_file_does_not_clear_this_one(tmp_path: Path) -> None:
    """The limitation's old blind spot: `ALLOWED_ORIGINS` in src/cors.ts."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}', encoding="utf-8"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "cors.ts").write_text(
        "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';\n\n"
        "export const ALLOWED_ORIGINS = ['https://example.test'];\n"
        "export const child = new StdioClientTransport({ command: 'node', args: ['child.js'] });\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "server.ts").write_text(
        "import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';\n\n"
        "await server.connect(new StdioServerTransport());\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert sorted(f.file_path for f in findings) == ["src/server.ts"]


def test_an_http_setting_in_another_stdio_file_does_not_clear_this_one(tmp_path: Path) -> None:
    files = {
        "http_server.py": 'class StdioServerTransport: pass\nt = StdioServerTransport()\ntransports = ["http"]\n',
        "stdio_server.py": _UNGUARDED_PY,
    }
    assert _reported(tmp_path, files) == ["stdio_server.py"]


def test_each_guarded_stdio_file_is_cleared_by_its_own_guard(tmp_path: Path) -> None:
    files = {
        "a.py": _GUARDED_PY,
        "b.py": _UNGUARDED_PY.replace("    params", "    command = shlex.quote(command)\n    params"),
        "c.py": 'class StdioServerTransport: pass\nt = StdioServerTransport()\ntransports = ["sse"]\n',
    }
    assert _reported(tmp_path, files) == []


# --------------------------------------------------------------------------
# Only a file that builds a transport is judged. Every file holding a STDIO
# marker used to be, so with guards scoped to their file, a guarded server's
# test mock, re-export barrel and type-only import were each reported HIGH.
# --------------------------------------------------------------------------

_GUARDED_TS = (
    "import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'\n"
    "const ALLOWED_COMMANDS = ['git', 'ls']\n"
    "export const transport = new StdioServerTransport()\n"
)


@pytest.mark.parametrize(("rel", "text"), [
    ("tests/server.test.ts",
     "jest.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({ StdioServerTransport: jest.fn() }))\n"),
    ("src/index.ts", "export { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'\n"),
    ("src/types.ts",
     "import type { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'\n"
     "export type T = StdioClientTransport\n"),
    ("src/transport.py", "class StdioServerTransport(BaseTransport):\n    pass\n"),
    ("src/helpers.py", "def stdio_server(read, write):\n    return read, write\n"),
])
def test_a_file_that_only_names_a_transport_is_not_judged(tmp_path: Path, rel: str, text: str) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "^1.20.0"}}', encoding="utf-8"
    )
    for name, content in (("src/server.ts", _GUARDED_TS), (rel, text)):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(content, encoding="utf-8")
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert [f.file_path for f in findings] == []


@pytest.mark.parametrize("text", [
    "val transport = StdioServerTransport(System.in.asSource(), System.out.asSink())\n",
    "StdioServerTransportProvider provider = new StdioServerTransportProvider(mapper);\n",
    "let transport = StdioTransport::new();\n",
    "async with stdio_client(params) as (read, write):\n    pass\n",
])
def test_a_file_that_builds_a_transport_is_judged(tmp_path: Path, text: str) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.kt").write_text("// StdioServerTransport\n" + text, encoding="utf-8")
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert [f.file_path for f in findings] == ["server.kt"]


@pytest.mark.parametrize(("rel", "builder", "tail", "call", "judged"), [
    # `ServerTransport` is 15 characters and `Transport` 9, so these names run
    # 48 and 49 past `Stdio`.
    ("src/server.ts", "const t = new StdioServerTransport", 33, "()", True),
    ("src/server.ts", "const t = new StdioServerTransport", 34, "()", False),
    ("server.py", "t = StdioServerTransport", 16, "()", True),
    ("server.py", "t = StdioServerTransport", 17, "()", False),
    ("src/main.rs", "let t = StdioTransport", 39, "::new();", True),
    ("src/main.rs", "let t = StdioTransport", 40, "::new();", False),
])
def test_a_builder_name_past_its_bounded_tail_is_not_read(
    tmp_path: Path, rel: str, builder: str, tail: int, call: str, judged: bool
) -> None:
    """The builder names are read with a bounded tail, so a crafted identifier
    stays linear, and a longer name is not recognised: its file is not read,
    and the limitation says so."""
    assert _reported(tmp_path, {rel: builder + "X" * tail + call + "\n"}) == ([rel] if judged else [])
    limitation = RULES["AAK-ANTHROPIC-SDK-001"].limitations
    assert "more than 48 characters past `Stdio`" in limitation
    assert "more than 16 past `Transport`" in limitation
    assert "`StdioTransport::new(`" in limitation


def test_the_construction_pattern_reads_a_crafted_name_in_linear_time() -> None:
    """A long identifier that keeps restarting `Transport`: a `\\w*Transport\\w*`
    pattern would read it once for every `Transport` in it."""
    started = time.perf_counter()
    mcp_sdk_hardening._STDIO_CONSTRUCT_RE.search("new Stdio" + "Transport" * 100_000 + " x")
    mcp_sdk_hardening._STDIO_CONSTRUCT_RE.search("Stdio" + "Transport" * 100_000 + " x")
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize(("guard", "line", "reported"), [
    ("export const ALLOWED_COMMANDS = ['git']\n", "import { ALLOWED_COMMANDS } from './allow'\n", []),
    ("export function safeArgv(a) { return a }\n", "import { safeArgv } from './allow'\n", ["src/server.ts"]),
])
def test_a_guard_in_another_module_counts_only_by_its_name(
    tmp_path: Path, guard: str, line: str, reported: list[str]
) -> None:
    """What the limitation says: an import names the guard, or it is not seen."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "^1.20.0"}}', encoding="utf-8"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "allow.ts").write_text(guard, encoding="utf-8")
    (tmp_path / "src" / "server.ts").write_text(
        line + "import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'\n"
        "const t = new StdioServerTransport()\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert sorted(f.file_path for f in findings) == reported
