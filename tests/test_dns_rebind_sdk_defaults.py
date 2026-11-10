"""AAK-DNS-REBIND-001 against what the Python SDK actually does.

`mcp` 1.23.0 (CVE-2025-66416, GHSA-9h52-p55h-vw2f) made FastMCP default to host
127.0.0.1 and turn the protection on for a loopback host when no `transport_security`
is passed; the SDK's maintainer gave that as the reason for closing python-sdk issue
3562 on 2026-10-06. On 0.6.30 the rule fired at CRITICAL on that shape, and fired
nothing on protection switched off beside an allow-list or on an allow-list of `*`
alone. Code that builds the transport directly never goes through the
auto-enable, so it stays reported on any host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners.dns_rebind import scan

RULE = "AAK-DNS-REBIND-001"
SDK = "from mcp.server.fastmcp import FastMCP\n"
RUN = 'mcp.run(transport="streamable-http")\n'
DEFAULT_HOST = SDK + 'mcp = FastMCP("x")\n' + RUN
UV_LOCK = 'version = 1\n\n[[package]]\nname = "mcp"\nversion = "%s"\n'
# Built here so this file reads as neither shape to AAK's own self-scan.
ANY_HOST = ".".join("0" * 4)
PROTECTION_OFF = "enable_dns_rebinding_protection" + "=False"
TS_PROTECTION_OFF = "enableDnsRebindingProtection" + ": false"


def _evidence(root: Path) -> list[str]:
    return [f.evidence for f in scan(root)[0] if f.rule_id == RULE]


def _project(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


LOCK_FIXED = {"uv.lock": UV_LOCK % "1.23.0"}


# ---- what stands down ------------------------------------------------------------


@pytest.mark.parametrize("files", [
    {"uv.lock": UV_LOCK % "1.23.0"},
    {"uv.lock": UV_LOCK % "2.3.0"},
    {"poetry.lock": '[[package]]\nname = "mcp"\nversion = "1.23.0"\n'},
    {"Pipfile.lock": '{"default": {"mcp": {"version": "==1.23.0"}}, "develop": {}}'},
    {"requirements.txt": "mcp==1.23.0\n"},
    {"requirements.txt": "mcp[cli]>=1.25\n"},
    {"pyproject.toml": '[project]\nname = "x"\nversion = "1"\ndependencies = ["mcp>=1.23.0,<3"]\n'},
], ids=["uv", "uv-2x", "poetry", "pipfile", "pin", "floor", "pyproject"])
def test_the_sdk_server_on_its_default_host_stands_down(tmp_path: Path, files: dict[str, str]) -> None:
    assert _evidence(_project(tmp_path, {"server.py": DEFAULT_HOST, **files})) == []


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_a_literal_loopback_host_stands_down(tmp_path: Path, host: str) -> None:
    server = SDK + f'mcp = FastMCP("x", host="{host}")\n' + RUN
    assert _evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED})) == []


def test_2x_mcpserver_stands_down_on_its_default_host(tmp_path: Path) -> None:
    server = 'from mcp.server.mcpserver import MCPServer\nmcp = MCPServer("x")\napp = mcp.streamable_http_app()\n'
    assert _evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED})) == []


def test_a_multi_line_import_counts(tmp_path: Path) -> None:
    server = 'from mcp.server.fastmcp import (\n    Context,\n    FastMCP,\n)\nmcp = FastMCP("x")\n' + RUN
    assert _evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED})) == []


def test_the_nearest_directory_decides(tmp_path: Path) -> None:
    root = _project(tmp_path, {"uv.lock": UV_LOCK % "1.22.0", "svc/uv.lock": UV_LOCK % "1.23.0",
                               "svc/app/server.py": DEFAULT_HOST})
    assert _evidence(root) == []
    (root / "svc" / "uv.lock").unlink()
    assert len(_evidence(root)) == 1


def test_a_real_allow_list_with_protection_on_clears_a_public_bind(tmp_path: Path) -> None:
    server = (SDK + "from mcp.server.transport_security import TransportSecuritySettings\n"
              f'mcp = FastMCP("x", host="{ANY_HOST}", transport_security=TransportSecuritySettings('
              'allowed_hosts=["mcp.example.com"]))\n' + RUN)
    assert _evidence(_project(tmp_path, {"server.py": server})) == []


# ---- what still fires, and what it says ------------------------------------------


@pytest.mark.parametrize("files", [
    {"uv.lock": UV_LOCK % "1.22.0"},
    {"requirements.txt": "mcp==1.22.0\n"},
    {"uv.lock": 'version = 1\n\n[[package]]\nname = "mcp"\nversion = "1.22.0"\n\n'
                '[[package]]\nname = "mcp"\nversion = "1.23.0"\n'},
], ids=["lock", "pin", "lock-holds-both"])
def test_below_the_fix_it_fires_and_says_so(tmp_path: Path, files: dict[str, str]) -> None:
    (evidence,) = _evidence(_project(tmp_path, {"server.py": DEFAULT_HOST, **files}))
    assert "resolves `mcp` below 1.23.0" in evidence and "CVE-2025-66416" in evidence


@pytest.mark.parametrize("files", [
    {},
    {"requirements.txt": "mcp\n"},
    {"requirements.txt": "mcp>=1.0\n"},
    {"uv.lock": 'version = 1\n\n[[package]]\nname = "httpx"\nversion = "1.0.0"\n'},
], ids=["nothing", "no-version", "range-admits-below", "lock-without-it"])
def test_with_no_readable_version_it_fires_and_says_what_would_clear_it(tmp_path: Path, files: dict[str, str]) -> None:
    (evidence,) = _evidence(_project(tmp_path, {"server.py": DEFAULT_HOST, **files}))
    assert "No `mcp` version could be read" in evidence
    assert "from 1.23.0 the SDK turns the protection on" in evidence


@pytest.mark.parametrize("server", [
    SDK + f'mcp = FastMCP("x", host="{ANY_HOST}")\n' + RUN,
    SDK + 'mcp = FastMCP("x", host=HOST)\n' + RUN,
    SDK + 'mcp = FastMCP("x", host=os.environ["HOST"])\n' + RUN,
    SDK + f'mcp = FastMCP("x")\nmcp.settings.host = "{ANY_HOST}"\n' + RUN,
    SDK + f'mcp = FastMCP("x")\napp = mcp.streamable_http_app()\nuvicorn.run(app, host="{ANY_HOST}")\n',
    SDK + 'mcp = FastMCP("x", transport_security=SETTINGS)\n' + RUN,
    f'from mcp.server.mcpserver import MCPServer\nmcp = MCPServer("x")\nmcp.run(transport="sse", host="{ANY_HOST}")\n',
], ids=["public", "variable", "environ", "settings-assignment", "uvicorn", "own-settings", "mcpserver-public"])
def test_a_host_or_settings_the_auto_enable_does_not_cover_still_fires(tmp_path: Path, server: str) -> None:
    (evidence,) = _evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED}))
    assert "without a Host-header allow-list" in evidence
    assert "`mcp`" not in evidence, "this is not a question of the SDK's version"


@pytest.mark.parametrize("server", [
    'from mcp.server.streamable_http_manager import StreamableHTTPSessionManager\n'
    'manager = StreamableHTTPSessionManager(app=server)\nuvicorn.run(app, host="127.0.0.1")\n',
    'from mcp.server.streamable_http import StreamableHTTPServerTransport\n'
    'transport = StreamableHTTPServerTransport(mcp_session_id=None)\n',
    'from mcp.server.sse import SseServerTransport\ntransport = SseServerTransport("/messages/")\n',
    SDK + 'mcp = FastMCP("x")\nmanager = StreamableHTTPSessionManager(app=mcp._mcp_server)\n',
], ids=["session-manager", "server-transport", "sse", "beside-fastmcp"])
def test_a_transport_built_directly_fires_on_any_host(tmp_path: Path, server: str) -> None:
    assert len(_evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED}))) == 1


def test_the_standalone_fastmcp_package_never_stands_down(tmp_path: Path) -> None:
    server = 'from fastmcp import FastMCP\nmcp = FastMCP("x")\n' + RUN
    assert len(_evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED}))) == 1


def test_another_librarys_mcpserver_is_no_candidate(tmp_path: Path) -> None:
    server = 'from agents.mcp import MCPServer\nserver = MCPServer("x")\nserver.run(transport="sse")\n'
    assert _evidence(_project(tmp_path, {"client.py": server})) == []


# ---- protection switched off ------------------------------------------------------


OFF = (SDK + "from mcp.server.transport_security import TransportSecuritySettings\n"
       f'mcp = FastMCP("x", host="{ANY_HOST}", transport_security=TransportSecuritySettings('
       f'{PROTECTION_OFF}, allowed_hosts=["example.com"]))\n' + RUN)


def test_protection_off_fires_beside_an_allow_list(tmp_path: Path) -> None:
    (finding,) = [f for f in scan(_project(tmp_path, {"server.py": OFF}))[0] if f.rule_id == RULE]
    assert "protection switched off" in finding.evidence and finding.line_number == 3


def test_protection_off_fires_on_a_fixed_loopback_server_and_past_another_files_list(tmp_path: Path) -> None:
    server = SDK + f'mcp = FastMCP("x", transport_security=TransportSecuritySettings({PROTECTION_OFF}))\n' + RUN
    root = _project(tmp_path, {"server.py": server, "other/settings.py": 'ALLOWED_HOSTS = ["a.example.com"]\n',
                               **LOCK_FIXED})
    assert len(_evidence(root)) == 1


def test_typescript_protection_off_fires(tmp_path: Path) -> None:
    server = f"const t = new StreamableHTTPServerTransport({{ {TS_PROTECTION_OFF}, allowedHosts: ['example.com'] }});\n"
    (evidence,) = _evidence(_project(tmp_path, {"server.ts": server}))
    assert "protection switched off" in evidence


def test_a_comment_does_not_switch_it_off(tmp_path: Path) -> None:
    server = f"# {PROTECTION_OFF}\n" + DEFAULT_HOST
    assert _evidence(_project(tmp_path, {"server.py": server, **LOCK_FIXED})) == []


def test_the_setting_in_another_file_is_not_read(tmp_path: Path) -> None:
    """The stated limitation: `allowed_hosts` beside it clears the project as any list does."""
    settings = f'S = TransportSecuritySettings({PROTECTION_OFF}, allowed_hosts=["a.example.com"])\n'
    server = SDK + f'mcp = FastMCP("x", host="{ANY_HOST}", transport_security=S)\n' + RUN
    assert _evidence(_project(tmp_path, {"server.py": server, "settings.py": settings})) == []


# ---- what is not an allow-list ----------------------------------------------------


@pytest.mark.parametrize("line", [
    'S = TransportSecuritySettings(allowed_hosts=["*"])\n',
    "S = TransportSecuritySettings(allowed_hosts=['*'])\n",
    'S = TransportSecuritySettings(allowed_hosts = ( "*", ))\n',
    'ALLOWED_HOSTS = ["*"]\n',
    'app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])\n',
    'app = TrustedHostMiddleware(inner, allowed_hosts=["*"])\n',
], ids=["sdk", "single-quotes", "tuple", "django", "add-middleware", "wrapped"])
def test_a_wildcard_alone_does_not_count(tmp_path: Path, line: str) -> None:
    server = SDK + f'mcp = FastMCP("x", host="{ANY_HOST}")\n' + line + RUN
    assert len(_evidence(_project(tmp_path, {"server.py": server}))) == 1


def test_a_typescript_wildcard_alone_does_not_count(tmp_path: Path) -> None:
    server = "const t = new StreamableHTTPServerTransport({ allowedHosts: ['*'] });\n"
    assert len(_evidence(_project(tmp_path, {"server.ts": server}))) == 1


def test_a_list_holding_a_real_name_beside_the_wildcard_counts(tmp_path: Path) -> None:
    """The stated limitation."""
    server = SDK + f'mcp = FastMCP("x", host="{ANY_HOST}", allowed_hosts=["*", "a.example.com"])\n' + RUN
    assert _evidence(_project(tmp_path, {"server.py": server})) == []
