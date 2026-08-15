"""Reachability tests for ssrf_patterns (#593).

The rule used to decide file-wide: the word `fetch` anywhere plus a user-input
marker anywhere meant CRITICAL, with no requirement that either be code, be
related, or be near the other. Against AAK's own source that produced three
findings, all of them prose — a scanner description, a rule title, and the SSRF
scanner's own detection regex.

Each rule now hangs off a real outbound call site whose URL argument is traced.
The tests below are split into the two things that matter: prose must not fire,
and genuine data flow must still fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners._ssrf_reach import analyze_js, analyze_python
from agent_audit_kit.scanners.ssrf_patterns import scan

# Every file must carry an MCP tool hint or the scanner skips it entirely.
_HINT = "from mcp.server.fastmcp import FastMCP\n"


def _ids(tmp_path: Path, name: str, body: str) -> set[str]:
    (tmp_path / name).write_text(_HINT + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


# --- the #593 reproduction --------------------------------------------------


def test_scanner_does_not_flag_its_own_source() -> None:
    """The regression that motivated this: AAK flagging its own detection patterns."""
    findings = scan(Path("agent_audit_kit"))[0]
    assert findings == [], (
        "ssrf_patterns fires on AAK's own source: "
        + ", ".join(f"{f.rule_id} {f.file_path}:{f.line_number}" for f in findings)
    )


def test_private_address_in_a_regex_literal_does_not_fire(tmp_path: Path) -> None:
    """The exact shape from ssrf_patterns.py:36 — a detection pattern, not a call."""
    body = (
        'import re\n'
        '_ADDR = re.compile(r"127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254")\n'
        'def check(text):\n'
        '    return bool(_ADDR.search(text))\n'
    )
    assert _ids(tmp_path, "patterns.py", body) == set()


def test_private_address_in_a_description_string_does_not_fire(tmp_path: Path) -> None:
    """The shape from engine.py:99 and builtin.py:451 — prose in a data structure."""
    body = (
        'SCANNERS = [\n'
        '    ("noauth", "Unauthenticated MCP server on 0.0.0.0 / wildcard CORS", []),\n'
        '    ("url", "MCP server URL points to localhost/internal network", []),\n'
        ']\n'
    )
    assert _ids(tmp_path, "registry.py", body) == set()


def test_user_input_and_fetch_in_the_same_file_but_unconnected(tmp_path: Path) -> None:
    """Both markers present, no flow between them — the old rule fired here."""
    body = (
        'import requests\n'
        'def log_request(request):\n'
        '    print(request.json)\n'
        'def health():\n'
        '    return requests.get("https://status.example.com/健康".encode().decode())\n'
    )
    ids = _ids(tmp_path, "svc.py", body)
    assert "AAK-SSRF-001" not in ids
    assert "AAK-SSRF-005" not in ids


# --- genuine flow must still fire ------------------------------------------


def test_direct_user_input_to_fetch_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def tool(request):\n'
        '    return requests.get(request.json["url"])\n'
    )
    ids = _ids(tmp_path, "tool.py", body)
    assert "AAK-SSRF-001" in ids
    assert "AAK-SSRF-005" in ids


def test_user_input_through_a_variable_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def tool(params):\n'
        '    target = params["endpoint"]\n'
        '    return requests.get(target)\n'
    )
    assert "AAK-SSRF-001" in _ids(tmp_path, "tool.py", body)


def test_user_input_through_an_fstring_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def tool(args):\n'
        '    host = args["host"]\n'
        '    return requests.get(f"https://{host}/v1/data")\n'
    )
    assert "AAK-SSRF-001" in _ids(tmp_path, "tool.py", body)


def test_metadata_address_reaching_a_call_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def creds():\n'
        '    return requests.get("http://169.254.169.254/latest/meta-data/iam/")\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


def test_metadata_address_via_a_variable_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'METADATA = "http://169.254.169.254/latest/meta-data/"\n'
        'def creds():\n'
        '    return requests.get(METADATA)\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


def test_allowlist_guard_clears_the_tainted_finding(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'ALLOWED_HOSTS = {"api.example.com"}\n'
        'def tool(params):\n'
        '    return requests.get(params["url"])\n'
    )
    assert "AAK-SSRF-005" not in _ids(tmp_path, "tool.py", body)


# --- backend units ----------------------------------------------------------


def test_python_backend_ignores_calls_that_are_not_fetches() -> None:
    sites = analyze_python('import os\ndef f(request):\n    os.getenv(request.json["k"])\n')
    assert sites == []


def test_python_backend_survives_a_syntax_error() -> None:
    """A file that does not parse must yield nothing, not raise."""
    assert analyze_python("def broken(:\n  pass\n") == []


def test_js_backend_resolves_a_single_hop() -> None:
    sites = analyze_js('const target = req.query.url;\nfetch(target);\n')
    assert sites and sites[0].tainted


def test_js_backend_ignores_a_commented_call() -> None:
    sites = analyze_js('// fetch(req.query.url)\nconst x = 1;\n')
    assert all(not s.tainted for s in sites)


@pytest.mark.parametrize("addr", ["127.0.0.1", "169.254.169.254", "192.168.1.5"])
def test_python_backend_finds_private_addresses_in_the_url_arg(addr: str) -> None:
    sites = analyze_python(f'import requests\nrequests.get("http://{addr}/x")\n')
    assert sites and sites[0].private_addr == addr


def test_python_backend_does_not_find_addresses_outside_a_call() -> None:
    sites = analyze_python('import requests\nDOC = "use 127.0.0.1 for local"\nrequests.get("https://a.example")\n')
    assert sites and sites[0].private_addr is None
