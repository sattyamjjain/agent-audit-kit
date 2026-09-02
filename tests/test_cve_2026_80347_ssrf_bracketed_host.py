"""`AAK-SSRF-BRACKETED-HOST-001` — CVE-2026-80347 (mcp-fetch).

The guard is present, which is exactly why the missing-allow-list rules cannot
see this. The benign fixture is the same guard with the brackets stripped: one
call different, and it must go silent. Without that fixture the rule could not
appear in the published false-positive rate honestly, because nothing would have
watched it decline to fire.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.ssrf_bracketed_host import scan

RULE = "AAK-SSRF-BRACKETED-HOST-001"
CVE = "CVE-2026-80347"

# `new URL(raw).hostname` keeps the brackets; `net.isIP` rejects them and returns
# 0, so the private-address branch never runs and the tail allows.
POSITIVE = """\
import net from "node:net";

function isSafeUrl(raw: string): boolean {
  const u = new URL(raw);
  const host = u.hostname;
  if (net.isIP(host)) {
    if (host.startsWith("127.") || host === "::1") return false;
    return true;
  }
  return true;
}

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { url } = req.params.arguments as { url: string };
  if (!isSafeUrl(url)) throw new Error("blocked by ssrf allowlist");
  return fetch(url);
});
"""

# The same guard, unbracketing before it classifies.
BENIGN = POSITIVE.replace(
    "  const host = u.hostname;",
    '  const host = u.hostname.replace(/^\\[|\\]$/g, "");',
)


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def test_positive_fires(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, "src/fetch.ts", POSITIVE)


def test_benign_is_silent(tmp_path: Path) -> None:
    """One call different from the positive, and the finding must go away."""
    assert RULE not in _ids(tmp_path, "src/fetch.ts", BENIGN)


def test_the_two_fixtures_differ_only_in_the_unbracketing() -> None:
    """Guards the guard: if they drift apart the benign case stops testing the
    thing it claims to."""
    assert BENIGN != POSITIVE
    assert BENIGN.replace(
        '  const host = u.hostname.replace(/^\\[|\\]$/g, "");',
        "  const host = u.hostname;",
    ) == POSITIVE


def test_a_guardless_fetch_is_left_to_the_existing_rule(tmp_path: Path) -> None:
    """This rule is about a guard that is present and wrong. A handler with no
    guard at all belongs to `AAK-MCP-SSRF-001`, and claiming it here would report
    one defect twice."""
    no_guard = """\
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { url } = req.params.arguments as { url: string };
  return fetch(url);
});
"""
    assert RULE not in _ids(tmp_path, "src/plain.ts", no_guard)


def test_python_is_not_flagged(tmp_path: Path) -> None:
    """urlsplit().hostname strips the brackets before you see them, so the same
    shape in Python is not vulnerable. Flagging it would invent a finding."""
    py = """\
from urllib.parse import urlsplit
import ipaddress, httpx

def is_safe_url(raw):
    host = urlsplit(raw).hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_loopback or ip.is_private)

def tool(url):
    if not is_safe_url(url):
        raise ValueError("blocked by ssrf allowlist")
    return httpx.get(url)
"""
    assert RULE not in _ids(tmp_path, "guard.py", py)


def test_rule_metadata() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.TRANSPORT_SECURITY
    assert rule.cve_references == [CVE]
    assert rule.limitations
    assert rule.owasp_mcp_references and rule.owasp_agentic_references


def test_rule_is_a_class_not_a_package_signature() -> None:
    rule = RULES[RULE]
    text = f"{rule.title} {rule.description} {rule.remediation}".lower()
    assert "mcp-fetch" not in text
