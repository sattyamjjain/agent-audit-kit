"""Tests for the MCP sidecar HTTP surface family (2026-08 wave).

Three advisories in one week share one shape: an MCP server that also binds a
local HTTP dashboard with no auth, reachable by DNS rebinding or a co-located
SSRF even when bound to loopback.

  - GHSA-76pc-mqxp-3rq5 / CVE-2026-55156 (npm @ooples/token-optimizer-mcp < 5.1.0)
  - GHSA-rm43-82j9-r4mj (PyPI atomic-agents-stack <= 1.0.0)
  - GHSA-9hgc-g3w5-67cm / CVE-2026-53708 (PyPI mcp-contextforge-gateway < 1.0.3)

The negatives carry more weight than the positives here: "binds HTTP" on its own
is not a finding, and a rule that cannot tell an authenticated dashboard from an
unauthenticated one is worse than no rule. Every FP guard below is pinned.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_sidecar_http import NOAUTH_RULE, REBIND_RULE, scan


def _write(tmp_path: Path, name: str, src: str) -> Path:
    path = tmp_path / name
    path.write_text(src, encoding="utf-8")
    return path


def _ids(tmp_path: Path) -> list[str]:
    findings, _ = scan(tmp_path)
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_rules_are_registered() -> None:
    for rule_id in (NOAUTH_RULE, REBIND_RULE):
        assert rule_id in RULES
        assert RULES[rule_id].severity.value == "high"
        assert RULES[rule_id].limitations, "every rule states its blind spot"

    assert RULES[NOAUTH_RULE].category.value == "mcp-config"
    assert RULES[REBIND_RULE].category.value == "transport-security"
    assert "CVE-2026-55156" in RULES[NOAUTH_RULE].cve_references
    assert "GHSA-76pc-mqxp-3rq5" in RULES[NOAUTH_RULE].incident_references


def test_scan_reports_both_rules_as_evaluated(tmp_path: Path) -> None:
    _, evaluated = scan(tmp_path)
    assert evaluated == {NOAUTH_RULE, REBIND_RULE}


# --------------------------------------------------------------------------
# True positives
# --------------------------------------------------------------------------


def test_token_optimizer_shape_is_flagged(tmp_path: Path) -> None:
    """CVE-2026-55156: MCP tools + express dashboard, no auth, loopback bind."""
    _write(tmp_path, "dashboard.ts", """
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "token-optimizer", version: "5.0.0" });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

const app = express();

app.get("/api/session-summary", (req, res) => {
  const sessionId = req.query.sessionId as string;
  res.send(fs.readFileSync(path.join(SESSION_DIR, sessionId + ".json"), "utf-8"));
});

app.get("/api/session-events", (req, res) => {
  res.send(fs.readFileSync(path.join(LOG_DIR, req.query.file as string), "utf-8"));
});

app.listen(3000, "127.0.0.1");
""")
    assert _ids(tmp_path) == [NOAUTH_RULE, REBIND_RULE]


def test_atomic_agents_shape_is_flagged(tmp_path: Path) -> None:
    """GHSA-rm43-82j9-r4mj: FastMCP tools + FastAPI dashboard on loopback."""
    _write(tmp_path, "dashboard.py", """
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
import os, uvicorn

mcp = FastMCP("atomic-agents-stack")

@mcp.tool()
def run_agent(name: str) -> str:
    return dispatch(name)

app = FastAPI()

@app.get("/api/logs")
def read_log(path: str):
    with open(os.path.join(LOG_ROOT, path)) as fh:
        return fh.read()

uvicorn.run(app, host="127.0.0.1", port=8100)
""")
    assert _ids(tmp_path) == [NOAUTH_RULE, REBIND_RULE]


def test_session_auth_clears_noauth_but_not_rebind(tmp_path: Path) -> None:
    """The nuance the two rules exist to separate.

    A session cookie stops an anonymous request, so the dashboard is not
    unauthenticated. It does nothing against DNS rebinding, because the browser
    attaches the cookie on the attacker's behalf — so the rebind rule still
    fires, and says so in the evidence.
    """
    _write(tmp_path, "app.py", """
from flask import Flask, session
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")

@mcp.tool()
def list_notes() -> list:
    return NOTES

app = Flask(__name__)

@app.route("/admin/export")
def export():
    if not session["user"]:
        return "forbidden", 403
    return dump_all()

app.run(host="127.0.0.1", port=5000)
""")
    findings, _ = scan(tmp_path)
    assert [f.rule_id for f in findings] == [REBIND_RULE]
    assert "browser attaches it" in findings[0].evidence


# --------------------------------------------------------------------------
# True negatives — these matter more than the positives.
# --------------------------------------------------------------------------


def test_plain_web_app_without_mcp_is_not_flagged(tmp_path: Path) -> None:
    """Binding an unauthenticated HTTP listener is not, by itself, a finding.

    This is an ordinary internal Flask app. AAK is an MCP scanner; without MCP
    identity there is no agent trust boundary to cross, and firing here would
    make the rule unusable in any repo that also contains a web service.
    """
    _write(tmp_path, "web.py", """
from flask import Flask
app = Flask(__name__)

@app.route("/api/reports")
def reports():
    return render_reports()

app.run(host="127.0.0.1", port=5000)
""")
    assert _ids(tmp_path) == []


def test_bearer_auth_clears_both_rules(tmp_path: Path) -> None:
    """Request-borne credentials defeat both anonymous access and rebinding."""
    _write(tmp_path, "app.py", """
from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("notes")

@mcp.tool()
def list_notes() -> list:
    return NOTES

app = FastAPI()
bearer = HTTPBearer()

@app.get("/api/logs", dependencies=[Depends(verify_token)])
def read_log(name: str):
    return LOGS[name]

uvicorn.run(app, host="127.0.0.1", port=8100)
""")
    assert _ids(tmp_path) == []


def test_host_allowlist_clears_the_rebind_rule(tmp_path: Path) -> None:
    """The actual fix: keep the loopback bind, stop treating it as the control."""
    _write(tmp_path, "app.py", """
from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("notes")

@mcp.tool()
def list_notes() -> list:
    return NOTES

app = FastAPI()
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

@app.get("/api/logs")
def read_log(name: str):
    return LOGS[name]

uvicorn.run(app, host="127.0.0.1", port=8100)
""")
    # Still unauthenticated, so NOAUTH stands; rebinding is now blocked.
    assert _ids(tmp_path) == [NOAUTH_RULE]


def test_health_only_routes_are_not_flagged(tmp_path: Path) -> None:
    """A liveness probe is not a dashboard."""
    _write(tmp_path, "app.py", """
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("notes")

@mcp.tool()
def list_notes() -> list:
    return NOTES

app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/metrics")
def metrics():
    return PROM.render()

uvicorn.run(app, host="127.0.0.1", port=8100)
""")
    assert _ids(tmp_path) == []


def test_stdio_only_server_is_not_flagged(tmp_path: Path) -> None:
    """No HTTP listener, no sidecar."""
    _write(tmp_path, "server.py", """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")

@mcp.tool()
def list_notes() -> list:
    return NOTES

mcp.run(transport="stdio")
""")
    assert _ids(tmp_path) == []


def test_streamable_http_defers_to_dns_rebind_rule(tmp_path: Path) -> None:
    """AAK-DNS-REBIND-001 owns the SDK's own transport; do not double-report."""
    _write(tmp_path, "server.py", """
from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http import StreamableHTTPServerTransport
import uvicorn

mcp = FastMCP("notes")

@mcp.tool()
def list_notes() -> list:
    return NOTES

app = StreamableHTTPServerTransport(mcp)

@app.get("/mcp")
def handle():
    return app.dispatch()

uvicorn.run(app, host="127.0.0.1", port=8100)
""")
    assert _ids(tmp_path) == []


def test_vendored_dependency_is_skipped(tmp_path: Path) -> None:
    """SKIP_DIRS keeps third-party trees out of the result."""
    vendored = tmp_path / "node_modules" / "some-mcp"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("""
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const app = require("express")();
app.get("/api/debug", (req, res) => res.send(dumpState()));
app.listen(3000, "127.0.0.1");
""", encoding="utf-8")
    assert _ids(tmp_path) == []
