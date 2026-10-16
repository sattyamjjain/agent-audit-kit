from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.scanners._helpers import iter_mcp_servers, mcp_server_maps
from agent_audit_kit.scanners.mcp_config import scan


def test_vulnerable_mcp_triggers_expected_rules(vulnerable_mcp_project: Path) -> None:
    findings, _ = scan(vulnerable_mcp_project)
    rule_ids = {f.rule_id for f in findings}

    # Must trigger these rules
    assert "AAK-MCP-001" in rule_ids, "Should detect remote server without auth"
    assert "AAK-MCP-002" in rule_ids, "Should detect shell injection in command"
    assert "AAK-MCP-003" in rule_ids, "Should detect hardcoded secrets in env"
    assert "AAK-MCP-004" in rule_ids, "Should detect excessive server count (13 servers)"
    assert "AAK-MCP-005" in rule_ids, "Should detect npx/uvx usage"
    assert "AAK-MCP-006" in rule_ids, "Should detect relative path command"
    assert "AAK-MCP-007" in rule_ids, "Should detect unpinned package version"
    assert "AAK-MCP-008" in rule_ids, "Should detect headersHelper"
    assert "AAK-MCP-009" in rule_ids, "Should detect internal network URL"


def test_clean_mcp_produces_zero_findings(clean_mcp_project: Path) -> None:
    findings, _ = scan(clean_mcp_project)
    assert len(findings) == 0, f"Clean MCP config should produce zero findings, got: {[f.rule_id for f in findings]}"


def test_empty_file(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_malformed_json(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{not valid json!!!")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_missing_keys(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}')
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_env_variable_references_not_flagged(tmp_path: Path) -> None:
    """Env values that are ${VAR} references should NOT be flagged."""
    import json
    config = {
        "mcpServers": {
            "safe-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "${MY_API_KEY}",
                    "SECRET_TOKEN": "${SECRET_FROM_VAULT}"
                }
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    secret_findings = [f for f in findings if f.rule_id == "AAK-MCP-003"]
    assert len(secret_findings) == 0, "Variable references should not be flagged as hardcoded secrets"


def test_authenticated_remote_server_not_flagged(tmp_path: Path) -> None:
    """Remote server WITH auth headers should not trigger AAK-MCP-001."""
    import json
    config = {
        "mcpServers": {
            "authed-remote": {
                "url": "https://mcp.example.com/api",
                "headers": {
                    "Authorization": "Bearer sk-abc123"
                }
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    no_auth_findings = [f for f in findings if f.rule_id == "AAK-MCP-001"]
    assert len(no_auth_findings) == 0


# ---------------------------------------------------------------------------
# #475 — AAK-MCP-001 must recognize custom API-key auth headers (X-*-Key family)
# ---------------------------------------------------------------------------


def test_custom_apikey_header_via_env_not_flagged(tmp_path: Path) -> None:
    """#475 benign case: a vendor-prefixed API-key header whose value is an env
    reference IS the server's declared auth scheme — AAK-MCP-001 must not fire.
    (These were the 2 confirmed benign-slice false positives.)"""
    import json
    config = {
        "mcpServers": {
            "nefesh": {"type": "http", "url": "https://mcp.nefesh.ai/mcp",
                       "headers": {"X-Nefesh-Key": "${SECRET}"}},
            "satoshidata": {"type": "http", "url": "https://satoshidata.ai/mcp/v1/",
                            "headers": {"X-WR-API-Key": "${SECRET}"}},
            "google": {"type": "http", "url": "https://mcp.example.com/mcp",
                       "headers": {"X-Goog-Api-Key": "${GOOGLE_API_KEY}"}},
            "generic": {"type": "http", "url": "https://api.acme.dev/mcp",
                        "headers": {"X-Api-Key": "${ACME_API_KEY}"}},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    assert not [f for f in findings if f.rule_id == "AAK-MCP-001"], (
        "custom X-*-Key auth headers with env values must not fire AAK-MCP-001"
    )


def test_apikey_placeholder_value_not_flagged(tmp_path: Path) -> None:
    """A placeholder value (YOUR_..._HERE) is a declared-but-unfilled scheme."""
    import json
    config = {"mcpServers": {"s": {"type": "http", "url": "https://x/mcp",
              "headers": {"X-Goog-Api-Key": "YOUR_STITCH_API_KEY_HERE"}}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    assert not [f for f in findings if f.rule_id == "AAK-MCP-001"]


def test_x402_payment_header_not_flagged(tmp_path: Path) -> None:
    """x402 X-PAYMENT gates access (pay-to-access); the endpoint is not openly
    reachable, so AAK-MCP-001 does not fire. Explicit decision for #475."""
    import json
    config = {"mcpServers": {"x402": {"type": "http", "url": "https://api.lattiq.ai/mcp",
              "headers": {"X-PAYMENT": "${SECRET}"}}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    assert not [f for f in findings if f.rule_id == "AAK-MCP-001"]


def test_hardcoded_custom_apikey_literal_still_flagged(tmp_path: Path) -> None:
    """True positive: a custom auth header carrying a HARDCODED literal secret
    exposes the credential in the config, so AAK-MCP-001 still fires."""
    import json
    config = {"mcpServers": {"leaky": {"type": "http", "url": "https://api.acme.dev/mcp",
              "headers": {"X-Acme-Key": "sk-live-9f8e7d6c5b4a3210deadbeefcafef00d"}}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    assert [f for f in findings if f.rule_id == "AAK-MCP-001"], (
        "a hardcoded literal in a custom auth header must still fire AAK-MCP-001"
    )


def test_non_auth_header_only_still_flagged(tmp_path: Path) -> None:
    """Preserved true positive: a remote server whose only header is a non-auth
    header (Accept) has no credential and must still fire (the ai.spala shape)."""
    import json
    config = {"mcpServers": {"public": {"type": "http", "url": "https://mcp.spala.ai/mcp",
              "headers": {"Accept": "application/json"}}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    assert [f for f in findings if f.rule_id == "AAK-MCP-001"], (
        "a non-auth header (Accept) must not suppress AAK-MCP-001"
    )


def test_absolute_path_command_not_flagged(tmp_path: Path) -> None:
    """Commands with absolute paths should not trigger AAK-MCP-006."""
    import json
    config = {
        "mcpServers": {
            "absolute-path": {
                "command": "/usr/local/bin/mcp-server",
                "args": ["--port", "3000"]
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    relative_findings = [f for f in findings if f.rule_id == "AAK-MCP-006"]
    assert len(relative_findings) == 0


# ---------------------------------------------------------------------------
# VS Code's `.vscode/mcp.json` keeps its servers under `servers`, not
# `mcpServers`. Until mcp_server_maps this scanner read only `mcpServers`, so
# every rule below passed a VS Code server unread.
# ---------------------------------------------------------------------------


def _write_vscode(root: Path, servers: Any) -> None:
    vscode = root / ".vscode"
    vscode.mkdir(exist_ok=True)
    (vscode / "mcp.json").write_text(json.dumps({"servers": servers}, indent=2), encoding="utf-8")


@pytest.mark.parametrize(("rule_id", "server"), [
    ("AAK-MCP-001", {"type": "http", "url": "https://mcp.example.com/mcp"}),
    ("AAK-MCP-002", {"type": "stdio", "command": "bash -c 'node server.js'"}),
    ("AAK-MCP-003", {"type": "stdio", "command": "node", "args": ["s.js"],
                     "env": {"GITHUB_TOKEN": "k9f2Lq7XvN3mR8tW1zP5bY6cH0dJ4sA2"}}),
    ("AAK-MCP-005", {"type": "stdio", "command": "npx", "args": ["-y", "@acme/mcp-server@1.0.0"]}),
    ("AAK-MCP-006", {"type": "stdio", "command": "my-mcp-server"}),
    ("AAK-MCP-007", {"type": "stdio", "command": "npx", "args": ["-y", "@acme/mcp-server"]}),
    ("AAK-MCP-008", {"type": "http", "url": "https://mcp.example.com/mcp", "headersHelper": "./h.sh"}),
    ("AAK-MCP-009", {"type": "http", "url": "http://192.168.1.20:8080/mcp"}),
    ("AAK-MCP-010", {"type": "stdio", "command": "npx",
                     "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/"]}),
    ("AAK-MCP-ATTEST-001", {"type": "stdio", "command": "node", "args": ["docs-server.js"]}),
    ("AAK-MCP-CONFIG-MALFORMED-001", {"type": "stdio", "command": "node", "args": "server.js"}),
])
def test_a_vscode_server_is_read(tmp_path: Path, rule_id: str, server: dict[str, Any]) -> None:
    _write_vscode(tmp_path, {"srv": server})
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == rule_id]
    assert [f.file_path for f in hits] == [".vscode/mcp.json"]


def test_mcp_004_counts_a_vscode_map(tmp_path: Path) -> None:
    _write_vscode(tmp_path, {f"s{i}": {"command": "node", "args": [f"s{i}.js"]} for i in range(11)})
    raw = (tmp_path / ".vscode" / "mcp.json").read_text(encoding="utf-8")
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-MCP-004"]
    assert [f.evidence for f in hits] == ["11 MCP servers declared (threshold: 10)"]
    assert hits[0].line_number is not None
    assert raw.splitlines()[hits[0].line_number - 1].strip() == '"servers": {'


def test_both_maps_in_one_file_are_read_and_counted_apart(tmp_path: Path) -> None:
    """A client loads one map of a file, so six and six is not twelve."""
    config = {
        "mcpServers": {f"a{i}": {"url": f"https://a{i}.example/mcp"} for i in range(6)},
        "servers": {f"b{i}": {"url": f"https://b{i}.example/mcp"} for i in range(6)},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    ids = [f.rule_id for f in scan(tmp_path)[0]]
    assert ids.count("AAK-MCP-001") == 12
    assert "AAK-MCP-004" not in ids


def test_vscode_input_variables_count_as_references(tmp_path: Path) -> None:
    """`${input:id}` is VS Code's prompt-for-a-value reference: not a literal
    secret for AAK-MCP-003, and a declared credential for AAK-MCP-001."""
    _write_vscode(tmp_path, {
        "local": {"type": "stdio", "command": "/usr/local/bin/srv", "attestation": "x",
                  "env": {"PERPLEXITY_API_KEY": "${input:perplexity-key}"}},
        "remote": {"type": "http", "url": "https://mcp.example.com/mcp", "attestation": "x",
                   "headers": {"Authorization": "Bearer ${input:api-token}"}},
    })
    assert scan(tmp_path)[0] == []


def test_a_servers_array_is_not_a_server_map(tmp_path: Path) -> None:
    """An MCP Registry listing keeps `servers` as an array of records."""
    listing = {"servers": [{"name": "x", "url": "http://x.example/mcp"}]}
    (tmp_path / "registry-mcp.json").write_text(json.dumps(listing), encoding="utf-8")
    assert scan(tmp_path)[0] == []


def test_a_nested_server_map_is_not_read(tmp_path: Path) -> None:
    nested = {"config": {"servers": {"x": {"url": "https://x.example/mcp"}}}}
    (tmp_path / "tool-mcp.json").write_text(json.dumps(nested), encoding="utf-8")
    assert scan(tmp_path)[0] == []


def test_a_windsurf_config_is_still_read_by_the_server_rules(tmp_path: Path) -> None:
    """AAK-WINDSURF-001 is retired, and with it the auto-approve and SHA-256 checks
    that only ran on `.windsurf/mcp.json`. The file itself stays on the list every
    server rule reads, so an unpinned package there is still reported, and an
    auto-approve key there is not."""
    windsurf = tmp_path / ".windsurf"
    windsurf.mkdir(mode=0o700)
    (windsurf / "mcp.json").write_text(json.dumps({
        "auto_approve": True,
        "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}},
    }), encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert scanned == {".windsurf/mcp.json"}
    assert {"AAK-MCP-005", "AAK-MCP-007"} <= {f.rule_id for f in findings}
    assert not [f for f in findings if "auto" in f.evidence.lower() or "sha-256" in f.evidence.lower()]


def test_a_top_level_array_is_skipped_not_a_crash(tmp_path: Path) -> None:
    """`data.get` on a JSON array raised AttributeError and failed the scanner."""
    (tmp_path / ".mcp.json").write_text("[1, 2]", encoding="utf-8")
    assert scan(tmp_path) == ([], {".mcp.json"})


@pytest.mark.parametrize("command", [" ", "\t\n", "　"])
def test_a_command_of_only_whitespace_names_no_program_and_is_not_a_crash(
    tmp_path: Path, command: str
) -> None:
    """`command.strip().split()[0]` raised IndexError on a command with no word in
    it, and this is a core scanner, so a 39-byte `.mcp.json` lost every finding
    it makes, in that file and every other. Such a command runs no program, so
    AAK-MCP-005, 006 and 007 have nothing to report on it; the server beside it
    and the config in the next file are read as before."""
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "blank": {"command": command},
        "fetch": {"command": "npx", "args": ["some-package"]},
    }}), encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "relative": {"command": "./run-server"},
    }}), encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert scanned == {".mcp.json", ".cursor/mcp.json"}
    by_server = {(f.rule_id, f.file_path, f.evidence.split("'")[1]) for f in findings}
    assert {("AAK-MCP-005", ".mcp.json", "fetch"), ("AAK-MCP-007", ".mcp.json", "fetch"),
            ("AAK-MCP-006", ".cursor/mcp.json", "relative")} <= by_server
    assert not [f for f in findings if "'blank'" in f.evidence and f.rule_id in {
        "AAK-MCP-005", "AAK-MCP-006", "AAK-MCP-007"}]


def test_mcp_server_maps_reads_both_keys_at_the_top_only() -> None:
    data = {
        "mcpServers": {"a": {}},
        "servers": {"b": {}, "c": "not an object"},
        "config": {"mcpServers": {"d": {}}},
    }
    assert [key for key, _ in mcp_server_maps(data)] == ["mcpServers", "servers"]
    assert [name for name, _ in iter_mcp_servers(data)] == ["a", "b"]
    assert mcp_server_maps({"servers": [{"name": "x"}]}) == []
    assert mcp_server_maps(["not", "a", "config"]) == []


def test_iter_mcp_servers_keeps_the_semantics_of_the_readers_it_replaced() -> None:
    """pinning, toxic_flow, supply_chain, tool_poisoning and mcp_stdio_launcher
    each kept a copy of this loop; this is what all of them did."""
    both = {
        "mcpServers": {"a": {"command": "x"}, "dup": {"command": "1"}, "str": "npx thing"},
        "servers": {"dup": {"command": "2"}, "b": {"type": "http", "url": "https://h.example/mcp"}, "nil": None},
    }
    # Keys in order, each map's entries on their own, non-object entries skipped.
    assert list(iter_mcp_servers(both)) == [
        ("a", {"command": "x"}),
        ("dup", {"command": "1"}),
        ("dup", {"command": "2"}),
        ("b", {"type": "http", "url": "https://h.example/mcp"}),
    ]
    # A name is always a string.
    assert list(iter_mcp_servers({"servers": {1: {"command": "x"}}})) == [("1", {"command": "x"})]
    # A registry-style array is not a map, and neither is a nested one.
    assert list(iter_mcp_servers({"servers": [{"name": "listing", "command": "x"}]})) == []
    assert list(iter_mcp_servers({"config": {"mcpServers": {"a": {"command": "x"}}}})) == []
    # A top level that is not an object yields nothing and does not raise.
    for top in ([], "mcpServers", 3, None, True):
        assert list(iter_mcp_servers(top)) == []


# A tuple, list or argument list naming both server-map keys, either order.
_BOTH_SERVER_KEYS = re.compile(
    r"""["']mcpServers["']\s*,\s*["']servers["']|["']servers["']\s*,\s*["']mcpServers["']"""
)


def test_no_module_reads_both_server_maps_by_hand() -> None:
    """Five modules kept their own copy of the two-key loop, each pinned to the
    shared semantics by a comment. One reader means one place to change when a
    client adds a key; read the maps with `iter_mcp_servers` or `mcp_server_maps`."""
    repo = Path(__file__).resolve().parent.parent
    offenders: list[str] = []
    for py in sorted((repo / "agent_audit_kit").rglob("*.py")):
        if py.name == "_helpers.py" and py.parent.name == "scanners":
            continue
        text = py.read_text(encoding="utf-8")
        for m in _BOTH_SERVER_KEYS.finditer(text):
            offenders.append(f"{py.relative_to(repo)}:{text.count(chr(10), 0, m.start()) + 1}")
    assert not offenders, f"read the server maps with _helpers.iter_mcp_servers: {offenders}"


# ---------------------------------------------------------------------------
# A loopback server is the developer's own process. AAK-MCP-001 reported it as a
# remote server without authentication (CRITICAL) and AAK-MCP-009 again as an
# internal network address: 51 findings on 190 real `.vscode/mcp.json` files,
# none a true positive.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://localhost:8001/mcp",
    "https://localhost/mcp",
    "http://127.0.0.1:3000/mcp",
    "http://127.0.0.2/mcp",
    "http://[::1]:9000/mcp",
    "http://0.0.0.0:8080/mcp",
    "http://LOCALHOST.:8001/mcp",
    # Read as the client reads them: each of these is 127.0.0.1 to Node and to
    # the resolver behind curl and httpx.
    "http://127.1:8001/mcp",
    "http://0x7f.1/mcp",
    "http://2130706433/mcp",
    "http://[::ffff:127.0.0.1]/mcp",
    "http://%6c%6f%63%61%6c%68%6f%73%74:8001/mcp",
    # A State of MCP corpus config has this shape: the port is a template
    # Claude Code expands, so it is still the developer's own machine.
    "http://localhost:${JETBRAINS_MCP_PORT:-64342}/sse",
])
def test_a_loopback_server_is_not_remote_or_internal(tmp_path: Path, url: str) -> None:
    _write_vscode(tmp_path, {"local": {"type": "http", "url": url}})
    ids = {f.rule_id for f in scan(tmp_path)[0]}
    assert not ids & {"AAK-MCP-001", "AAK-MCP-009"}


@pytest.mark.parametrize(("url", "rules"), [
    ("http://localhost.evil.example/mcp", {"AAK-MCP-001", "AAK-MCP-009"}),
    ("http://evil.example\\@localhost/mcp", {"AAK-MCP-001", "AAK-MCP-009"}),  # evil.example to Node
    # localhost to Node, evil.example to curl, httpx and urlsplit, which keep the
    # backslash in the authority and take the host after the last `@`. This was
    # exempt as loopback, so a Python MCP client went to evil.example unreported.
    ("http://localhost\\@evil.example/mcp", {"AAK-MCP-001"}),
    ("http://127.0.0.1.nip.io/mcp", {"AAK-MCP-001", "AAK-MCP-009"}),
    ("http://192.168.1.20:8080/mcp", {"AAK-MCP-001", "AAK-MCP-009"}),
])
def test_a_host_that_only_looks_local_still_fires(tmp_path: Path, url: str, rules: set[str]) -> None:
    _write_vscode(tmp_path, {"remote": {"type": "http", "url": url}})
    assert rules <= {f.rule_id for f in scan(tmp_path)[0]}


_IDEOGRAPHIC_STOP = chr(0x3002)


@pytest.mark.parametrize("url", [
    "http://10.1/mcp",            # 10.0.0.1
    "http://0xa.0.0.5/mcp",       # 10.0.0.5
    "http://167772165/mcp",       # 10.0.0.5
    "http://012.0.0.5/mcp",       # octal 012 is 10
    "http://%31%30.0.0.5/mcp",    # percent-escaped digits
    "http://192.168.1/mcp",       # 192.168.0.1
    "http://0xc0a80101/mcp",      # 192.168.1.1
    "http://172.16.1/mcp",        # 172.16.0.1
    "http://[::ffff:a00:5]/mcp",  # IPv4-mapped 10.0.0.5
    "http://10" + _IDEOGRAPHIC_STOP + "0" + _IDEOGRAPHIC_STOP + "0" + _IDEOGRAPHIC_STOP + "5/mcp",
])
def test_mcp_009_reads_an_internal_address_as_the_client_does(tmp_path: Path, url: str) -> None:
    """The regex read the URL's text, so every other spelling of an RFC 1918
    address passed. Node reads each of these as one, and so does the resolver
    (`inet_aton`) behind curl and httpx for the numeric forms."""
    _write_vscode(tmp_path, {"internal": {"type": "http", "url": url}})
    assert "AAK-MCP-009" in {f.rule_id for f in scan(tmp_path)[0]}


@pytest.mark.parametrize("url", ["http://0x08080808/mcp", "http://8.8.2056/mcp", "https://public.example/mcp"])
def test_mcp_009_a_public_address_in_another_spelling_is_not_internal(tmp_path: Path, url: str) -> None:
    _write_vscode(tmp_path, {"public": {"type": "http", "url": url}})
    assert "AAK-MCP-009" not in {f.rule_id for f in scan(tmp_path)[0]}


@pytest.mark.parametrize("command", [
    "${workspaceFolder}/run.sh",
    "${userHome}/go/bin/tool",
    "${env:LOCALAPPDATA}/tools/server.exe",
    "${workspaceFolder:api}/bin/server",
])
def test_mcp_002_a_vscode_variable_is_not_shell_expansion(tmp_path: Path, command: str) -> None:
    """VS Code substitutes these itself and spawns without a shell; both MCP-002
    findings on 190 real `.vscode/mcp.json` files were exactly this shape."""
    _write_vscode(tmp_path, {"s": {"type": "stdio", "command": command}})
    assert "AAK-MCP-002" not in {f.rule_id for f in scan(tmp_path)[0]}


@pytest.mark.parametrize("command", [
    "${workspaceFolder}/run.sh; curl https://evil.example",
    "$(cat ${workspaceFolder}/cmd)",
    "${HOME}/bin/server",  # not a VS Code variable: still read as shell expansion
    "bash -c ${workspaceFolder}/run.sh",
])
def test_mcp_002_shell_syntax_beside_a_vscode_variable_still_fires(tmp_path: Path, command: str) -> None:
    _write_vscode(tmp_path, {"s": {"type": "stdio", "command": command}})
    assert "AAK-MCP-002" in {f.rule_id for f in scan(tmp_path)[0]}


# The scanner skips a config over 1,000,000 characters, so the crafted values
# below are as large as a config it reads can hold.
_LARGEST_VALUE = 999_000


@pytest.mark.parametrize("unit", ["${env:", "${file:", "${input:"])
def test_mcp_002_a_crafted_command_scans_in_linear_time(tmp_path: Path, unit: str) -> None:
    """A 1 MB command of VS Code variable openers with no closer. With `[^}]*`
    every opener rescanned to the end of the command, and 56,000 characters of
    `${file:` already took 1.6 seconds. The bound is loose for slow CI runners;
    the linear strip takes milliseconds."""
    import time

    _write_vscode(tmp_path, {"s": {"type": "stdio", "command": unit * (_LARGEST_VALUE // len(unit))}})
    started = time.perf_counter()
    rule_ids = {f.rule_id for f in scan(tmp_path)[0]}
    assert time.perf_counter() - started < 5.0
    assert "AAK-MCP-002" in rule_ids  # nothing closed, so nothing was stripped


@pytest.mark.parametrize("opener", ["{{", "${", "<"])
def test_mcp_001_a_hostile_header_value_scans_in_linear_time(tmp_path: Path, opener: str) -> None:
    """A credential header whose value is 1 MB of an opener with no closer. With
    `[^}]*` every opener rescanned to the end of the value: 200,000 characters of
    `{{` took 25 seconds, and a 1 MB value about ten minutes. The bound is loose
    for slow CI runners; the linear search takes a fraction of a second."""
    import time

    value = opener * (_LARGEST_VALUE // len(opener))
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"api": {
            "url": "https://mcp.example.com/mcp", "headers": {"X-Service-Token": value},
        }}}),
        encoding="utf-8",
    )
    started = time.perf_counter()
    rule_ids = {f.rule_id for f in scan(tmp_path)[0]}
    assert time.perf_counter() - started < 5.0
    assert "AAK-MCP-001" in rule_ids  # a literal, not a reference, so no declared scheme


@pytest.mark.parametrize(("value", "declared"), [
    ("${API_TOKEN}", True),
    ("{{ secrets.token }}", True),
    ("<your-token>", True),
    ("$API_TOKEN", True),
    # A brace or bracket inside a reference keeps it a reference.
    ("${env:{TOKEN}}", True),
    ("<token<>", True),
    ("k9f2Lq7XvN3mR8tW1zP5bY6cH0dJ4sA2", False),
])
def test_mcp_001_reads_a_custom_header_value_as_a_reference_or_a_literal(
    tmp_path: Path, value: str, declared: bool
) -> None:
    import json

    server = {"url": "https://mcp.example.com/mcp", "headers": {"X-Service-Token": value}}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"api": server}}), encoding="utf-8")
    rule_ids = {f.rule_id for f in scan(tmp_path)[0]}
    assert ("AAK-MCP-001" not in rule_ids) is declared


# ---------------------------------------------------------------------------
# AAK-MCP-003 asks whether a literal under a secret-looking name is a secret.
# On 190 real `.vscode/mcp.json` files it reported settings and demo literals
# as hardcoded secrets; its three true positives were 44 to 139 characters.
# ---------------------------------------------------------------------------

_TOKEN_SHAPED = "k9f2Lq7XvN3mR8tW1zP5bY6cH0dJ4sA2nE8uG3iT7oV1"


def _mcp_003(root: Path, env: dict[str, str]) -> list[str]:
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "node", "args": ["s.js"], "env": env}}}),
        encoding="utf-8",
    )
    return [f.evidence for f in scan(root)[0] if f.rule_id == "AAK-MCP-003"]


@pytest.mark.parametrize("env", [
    {"API_KEY": _TOKEN_SHAPED},
    {"SERVICE_ACCESS_TOKEN": "pat-" + _TOKEN_SHAPED},
    {"SERVICE_SECRET_KEY": "live-test-" + _TOKEN_SHAPED},  # a marker in a long value does not count
    {"DB_PASSWORD": "S3cr$tValue!9"},                      # a `$` in a literal is not a reference
    {"SERVICE_API_KEY": "9b2d6c1e-7f3a-4e0b-9c5d-2a8f1e6b3c4d"},  # a UUID key stays reported
])
def test_mcp_003_a_credential_shaped_literal_fires(tmp_path: Path, env: dict[str, str]) -> None:
    assert _mcp_003(tmp_path, env) == [f"Server 's' env.{next(iter(env))} = (hardcoded value)"]


@pytest.mark.parametrize("env", [
    {"AWS_DOCUMENTATION_PARTITION": "aws"},          # too short to be a credential
    {"PROXMOX_TOKEN_NAME": "automation"},            # the key names a setting
    {"ROBOTMCP_MAX_INLINE_TOKENS": "2000"},
    {"ROBOTMCP_TOKENIZER": "tiktoken"},
    {"KEY_VAULT_ID": "vault-prod-weu-01"},
    {"SAP_PASSWORD": "MyPassword12"},                # a demo string
    {"AZURE_AI_FOUNDRY_KEY": "test-foundry-key-1234"},
    {"OPENAI_API_KEY": "<your-openai-key>"},          # placeholders and references
    {"GITHUB_TOKEN": "your_token_here"},
    {"API_TOKEN": "Bearer ${API_TOKEN}"},
    {"ANTHROPIC_API_KEY": "sk-ant-xxxxxxxxxxxx"},
])
def test_mcp_003_a_setting_dummy_or_placeholder_is_quiet(tmp_path: Path, env: dict[str, str]) -> None:
    assert _mcp_003(tmp_path, env) == []


@pytest.mark.parametrize("opener", ["{{", "${", "<"])
def test_mcp_003_a_crafted_value_scans_in_linear_time(tmp_path: Path, opener: str) -> None:
    """Openers with no closer must not make the placeholder search quadratic. With
    `[^}]*` every opener rescanned to the end of the value: 40,000 `{{` took two
    seconds, and this size took between half a minute and two minutes per case.
    The bound is loose for slow CI runners; the linear search takes milliseconds."""
    import time

    started = time.perf_counter()
    evidence = _mcp_003(tmp_path, {"API_KEY": opener * 300_000})
    assert time.perf_counter() - started < 10.0
    assert evidence == ["Server 's' env.API_KEY = (hardcoded value)"]


@pytest.mark.parametrize(("url", "loopback"), [
    ("http://localhost:8001/mcp", True),
    ("http://127.10.20.30/", True),
    ("http://[::1]/", True),
    ("http://0.0.0.0:80/", True),
    ("localhost:8080", True),
    ("http://localhost.evil.example/", False),
    ("http://10.0.0.5/", False),
    ("http://[::ffff:10.0.0.5]/", False),
    ("http://[::1/", False),
    ("${input:host}", False),
    # Every reading has to be local. The first is evil.example to Node, the
    # second evil.example to curl and httpx.
    ("http://evil.example\\@localhost/", False),
    ("http://localhost\\@evil.example/", False),
    ("http://evil.example\\.localhost/", False),
    ("http://127.0.0.1\\@localhost/", True),
    # IPv4 numbers, escapes and mapped addresses, read as Node reads them.
    ("http://127.1/", True),
    ("http://0x7f.1/", True),
    ("http://127.0.0.010/", True),   # 127.0.0.8 to Node, 127.0.0.10 to macOS: local either way
    ("http://0177.0.0.1/", False),   # 127.0.0.1 to Node, 177.0.0.1 to macOS's resolver
    ("http://[::ffff:127.0.0.1]/", True),
    ("http://%31%32%37.0.0.1/", True),
    ("http:/localhost:8080/", True),
    # A templated port: Claude Code fills it in, and the host is localhost.
    ("http://localhost:${JETBRAINS_MCP_PORT:-64342}/sse", True),
    # No client opens these, so nothing exempts them.
    ("http://[::1]evil.example/", False),
    ("http://evil.example[::1]/", False),
    ("http://[::1%25eth0]/", False),
])
def test_is_loopback_url(url: str, loopback: bool) -> None:
    from agent_audit_kit.scanners._helpers import is_loopback_url

    assert is_loopback_url(url) is loopback
