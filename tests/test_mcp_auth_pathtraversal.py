"""Tests for AAK-MCP-AUTH-PATHTRAVERSAL-001 (CVE-2026-52830, CWE-22).

MCP auth code that joins an untrusted bearer token into a session file path used
for an existence/read check — with no separator rejection or resolve-and-contain
guard — is a path traversal: the caller controls the token, so they control the
path. fast-mcp-telegram < 0.19.1 is the anchor (CVSS 9.4).

Fixtures pin the contract: a token joined into a session path FLAGS; a
separator-rejected + resolved-and-contained variant PASSES (guards the FP-rate
claim). SARIF output carries the fingerprint, the fix (remediation), and the
security-severity.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_auth_pathtraversal import scan

RULE_ID = "AAK-MCP-AUTH-PATHTRAVERSAL-001"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "critical"
    assert "CVE-2026-52830" in rule.cve_references
    assert "CWE-22" in rule.description
    assert "MCP07:2025" in rule.owasp_mcp_references


# ---------------------------------------------------------------------------
# Vulnerable — must FLAG
# ---------------------------------------------------------------------------


def test_token_joined_into_session_path_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-52830 shape: bearer token joined into the session file path
    used for an existence check, no guard."""
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

SESSION_DIR = "/var/lib/mcp/sessions"
server = Server("telegram")

def load_session(request):
    token = request.headers.get("Authorization").removeprefix("Bearer ")
    session_path = os.path.join(SESSION_DIR, token + ".session")
    if os.path.exists(session_path):
        return open(session_path).read()
    return None
''')
    findings, scanned = scan(tmp_path)
    assert "server.py" in scanned
    assert _hits(findings), f"token-in-session-path must fire {RULE_ID}"


def test_pathlib_division_with_token_param_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "auth.py", '''
from pathlib import Path
from mcp.server.fastmcp import FastMCP

def _session_exists(bearer_token):
    p = Path("/sessions") / f"{bearer_token}.session"
    return p.exists()
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "Path()/token then .exists() must fire"


def test_typescript_token_join_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "session.ts", '''
import { existsSync } from "fs";
import path from "path";

// MCP session server
export function loadSession(req: any) {
  const token = req.headers["authorization"].replace("Bearer ", "");
  const p = path.join(SESSION_DIR, `${token}.session`);
  return existsSync(p);
}
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "TS token-join into path + existsSync must fire"


# ---------------------------------------------------------------------------
# Safe — must PASS (FP-rate guard)
# ---------------------------------------------------------------------------


def test_separator_rejected_and_contained_passes(tmp_path: Path) -> None:
    """Reject separators + resolve-and-contain -> not exploitable, must pass."""
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

SESSION_DIR = "/var/lib/mcp/sessions"

def load_session(request):
    token = request.headers.get("Authorization").removeprefix("Bearer ")
    if "/" in token or "\\\\" in token or ".." in token:
        raise ValueError("invalid token")
    session_path = os.path.realpath(os.path.join(SESSION_DIR, token + ".session"))
    if not session_path.startswith(SESSION_DIR):
        raise ValueError("path traversal")
    if os.path.exists(session_path):
        return open(session_path).read()
    return None
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "separator-rejected + contained flow must pass"


def test_constant_path_with_token_elsewhere_passes(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

def check(request):
    token = request.headers.get("Authorization")
    if os.path.exists("/etc/mcp/config.json"):
        return token
    return None
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "constant path (token not in path) must pass"


def test_typescript_guarded_passes(tmp_path: Path) -> None:
    _write(tmp_path, "session.ts", '''
import { existsSync } from "fs";
import path from "path";

export function loadSession(req: any) {
  const token = req.headers["authorization"].replace("Bearer ", "");
  if (token.includes("/") || token.includes("..")) throw new Error("bad token");
  const p = path.resolve(path.join(SESSION_DIR, `${token}.session`));
  return existsSync(p);
}
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "TS guarded (reject + resolve) must pass"


def test_non_mcp_file_passes(tmp_path: Path) -> None:
    _write(tmp_path, "util.py", '''
import os
def read_thing(name):
    p = os.path.join("/data", name + ".txt")
    return os.path.exists(p)
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no MCP/auth context -> must not fire"


# ---------------------------------------------------------------------------
# SARIF: fingerprint + fix + security-severity
# ---------------------------------------------------------------------------


def test_sarif_carries_fingerprint_fix_and_severity(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server
SESSION_DIR = "/var/lib/mcp/sessions"
def load_session(request):
    token = request.headers.get("Authorization").removeprefix("Bearer ")
    session_path = os.path.join(SESSION_DIR, token + ".session")
    if os.path.exists(session_path):
        return open(session_path).read()
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings)
    result = ScanResult()
    result.findings.extend(_hits(findings))
    sarif = json.loads(format_results(result))
    run = sarif["runs"][0]
    res = next(r for r in run["results"] if r["ruleId"] == RULE_ID)
    rule_obj = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == RULE_ID)
    # security-severity on the rule (critical band)
    assert "security-severity" in rule_obj["properties"]
    assert float(rule_obj["properties"]["security-severity"]) >= 9.0
    # partial fingerprint on the result
    assert "partialFingerprints" in res
    # remediation carried in a valid property bag, not an invalid SARIF `fixes`
    assert "fixes" not in res
    assert res["properties"]["remediation"]
    assert "resolve" in rule_obj["help"]["text"].lower()
    # CVE tag carried
    assert "CVE-2026-52830" in rule_obj["properties"]["tags"]
