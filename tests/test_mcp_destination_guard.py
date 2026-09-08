"""AAK-MCP-DEST-UNVALIDATED-001 — the rule #693 and #699 were deferred for.

Both CVEs are reproduced from their NVD text, and the two negatives that decide
whether the rule is worth shipping are here too: a module that guards every
destination must stay silent (or the asymmetry arm is just an absence arm with
extra steps), and a caller-supplied *tool argument* must stay silent (that is
AAK-MCP-SSRF-001's surface, and two rules reporting one finding is noise).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_destination_guard as dg

RULE = "AAK-MCP-DEST-UNVALIDATED-001"


def _scan(tmp_path: Path, src: str, name: str = "server.py") -> list:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return dg.scan(tmp_path)[0]


def _ids(tmp_path: Path, src: str) -> set[str]:
    return {f.rule_id for f in _scan(tmp_path, src)}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_rule_is_registered() -> None:
    assert RULE in RULES


def test_rule_cites_both_cves() -> None:
    assert set(RULES[RULE].cve_references) == {"CVE-2026-85666", "CVE-2026-86122"}


def test_rule_states_its_boundary_against_the_tool_argument_rule() -> None:
    """Ten AAK-SSRF-* rules already exist. If this one does not say where it stops,
    the coverage story gains a rule and loses precision."""
    assert "AAK-MCP-SSRF-001" in RULES[RULE].limitations


# ---------------------------------------------------------------------------
# Arm A — asymmetry (CVE-2026-85666, OGX)
# ---------------------------------------------------------------------------

OGX = '''
import httpx

def validate_url_not_private(u):
    import socket, ipaddress
    ip = socket.gethostbyname(u)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("blocked")
    return u

async def create_response(body):
    """OpenAI-compatible POST /v1/responses — MCP tool definitions."""
    callback_url = validate_url_not_private(body["callback_url"])
    await httpx.AsyncClient().post(callback_url, json={})
    # The guard exists, is called above, and is not applied here:
    server_url = body["server_url"]
    return await httpx.AsyncClient().get(server_url, headers=body["headers"])
'''


def test_asymmetry_arm_fires_on_the_ogx_shape(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, OGX)


def test_asymmetry_evidence_names_the_guard_that_was_skipped(tmp_path: Path) -> None:
    """The finding has to say *why* this is worse than a missing guard, or a reader
    cannot tell it apart from Arm B."""
    f = [x for x in _scan(tmp_path, OGX) if x.rule_id == RULE][0]
    assert "does guard other URL inputs" in f.evidence
    assert "CVE-2026-85666" in f.evidence


def test_asymmetry_arm_reports_the_unguarded_name_not_the_guarded_one(tmp_path: Path) -> None:
    ev = " ".join(f.evidence for f in _scan(tmp_path, OGX) if f.rule_id == RULE)
    assert "`server_url`" in ev
    assert "`callback_url` reaches" not in ev


# ---------------------------------------------------------------------------
# Arm B — absence (CVE-2026-86122, Rowboat)
# ---------------------------------------------------------------------------

ROWBOAT = '''
import requests

def call_mcp_tool(project_config):
    server_url = project_config["mcp_server_url"]
    return requests.post(server_url, json={"method": "tools/call"})
'''


def test_absence_arm_fires_on_the_rowboat_shape(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, ROWBOAT)


def test_absence_evidence_says_nothing_guards_anything(tmp_path: Path) -> None:
    f = [x for x in _scan(tmp_path, ROWBOAT) if x.rule_id == RULE][0]
    assert "nothing in this module resolves or range-checks" in f.evidence
    assert "CVE-2026-86122" in f.evidence


def test_webhook_destination_also_fires(tmp_path: Path) -> None:
    src = '''
import requests
def deliver(cfg):
    """mcp webhook delivery"""
    webhook_url = cfg.get("webhook_url")
    requests.post(webhook_url, json={})
'''
    assert RULE in _ids(tmp_path, src)


# ---------------------------------------------------------------------------
# The negatives that decide whether this rule earns its place
# ---------------------------------------------------------------------------

def test_a_module_that_guards_every_destination_is_silent(tmp_path: Path) -> None:
    """The whole claim of the asymmetry arm is that guarding everything passes.
    If this fires, the arm is an absence check wearing a better name."""
    src = '''
import httpx

def validate_url_not_private(u):
    import socket, ipaddress
    ip = socket.gethostbyname(u)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("blocked")
    return u

async def call(body):
    """mcp tools/call"""
    server_url = validate_url_not_private(body["server_url"])
    callback_url = validate_url_not_private(body["callback_url"])
    await httpx.AsyncClient().get(server_url)
    await httpx.AsyncClient().post(callback_url, json={})
'''
    assert RULE not in _ids(tmp_path, src)


def test_a_caller_supplied_tool_argument_is_not_this_rule(tmp_path: Path) -> None:
    """`AAK-MCP-SSRF-001` owns a URL that arrives as a tool argument. Firing here
    too would report one finding twice."""
    src = '''
import requests
def fetch_page(url):
    """An mcp tool that fetches a caller-supplied url."""
    return requests.get(url)
'''
    assert RULE not in _ids(tmp_path, src)


def test_a_non_mcp_webhook_client_is_silent(tmp_path: Path) -> None:
    """A generic webhook sender is not this bug, and there are a lot of them."""
    src = '''
import requests
def notify(cfg):
    webhook_url = cfg["webhook_url"]
    requests.post(webhook_url, json={"event": "deploy"})
'''
    assert RULE not in _ids(tmp_path, src)


def test_a_dict_get_is_not_a_fetch(tmp_path: Path) -> None:
    """`.get()` on a mapping is the most common false-positive source for any
    fetch matcher. The receiver has to look like an HTTP client."""
    src = '''
def build(cfg):
    """mcp config loader"""
    server_url = cfg.get("server_url")
    other = cfg.get(server_url)
    return server_url, other
'''
    assert RULE not in _ids(tmp_path, src)


def test_a_literal_destination_is_silent(tmp_path: Path) -> None:
    src = '''
import requests
def ping():
    """mcp health check"""
    return requests.get("https://status.example.com/health")
'''
    assert RULE not in _ids(tmp_path, src)


def test_base_url_is_not_a_steerable_destination(tmp_path: Path) -> None:
    """Caught by the first self-scan, on a `negative/` fixture. `base_url` in an
    API client is the service's own address — configured once, not caller-chosen —
    and every client in the corpus has one."""
    src = '''
import requests
def upload(config, data):
    """mcp attachment upload"""
    base_url = config["base_url"]
    return requests.post(base_url + "/attachments", data=data)
'''
    assert RULE not in _ids(tmp_path, src)


def test_bare_url_identifier_is_not_matched(tmp_path: Path) -> None:
    assert dg._is_dest_name("url") is False
    assert dg._is_dest_name("server_url") is True
    assert dg._is_dest_name("mcp_server_url") is True


def test_syntax_error_does_not_crash_the_scan(tmp_path: Path) -> None:
    assert _ids(tmp_path, "def broken(:\n    mcp\n") == set()


@pytest.mark.parametrize("name,expected", [
    ("server_url", True), ("webhook_url", True), ("base_url", False),
    ("sse_url", True), ("url", False), ("curl", False), ("urls", False),
])
def test_destination_vocabulary(name: str, expected: bool) -> None:
    assert dg._is_dest_name(name) is expected
